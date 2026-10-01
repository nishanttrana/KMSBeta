package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route/routetest"
)

func edgeFixture(t *testing.T) (mtlsFixture, RuntimeCertMaterializerConfig) {
	t.Helper()
	f := newMTLSFixture(t)
	cfg := f.cfg
	cfg.Enabled, cfg.TenantID, cfg.RootCAName = true, "root", "vecta-runtime-root"
	f.svc.runtimeCfg = cfg
	if err := f.svc.MaterializeRuntimeCerts(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	return f, cfg
}

func installedIssuer(t *testing.T, f mtlsFixture) string {
	t.Helper()
	leaf, _, err := installedLeaf(f.svc.edgeDir())
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Issuer.CommonName
}

// A PKI CA as the edge certificate source: certs issues and installs the
// edge certificate from it, renews it from it, and refuses CAs that can't
// serve (unknown, the internal-services Sub CA, an unattended HSM CA).
func TestEdgeCertificateFromPKICA(t *testing.T) {
	f, cfg := edgeFixture(t)
	ctx := context.Background()
	if got := installedIssuer(t, f); got != "vecta-runtime-root" {
		t.Fatalf("default edge certificate issuer: %q", got)
	}
	ca, err := f.svc.CreateCA(ctx, CreateCARequest{TenantID: "root", Name: "corp-edge", CALevel: "root",
		Algorithm: "ECDSA-P256", KeyBackend: "software", Subject: "CN=Corp Edge CA"})
	if err != nil {
		t.Fatal(err)
	}
	_, sub, _ := f.svc.EnsureInternalPKI(ctx, "root")
	for _, tc := range []struct {
		choice edgeCertChoice
		reason string
	}{
		{edgeCertChoice{Source: "acme"}, "invalid_source"},
		{edgeCertChoice{Source: edgeSourceCA, CAID: "ca_missing"}, "unknown_ca"},
		{edgeCertChoice{Source: edgeSourceCA, CAID: sub.ID}, "internal_services_ca"},
		{edgeCertChoice{Source: edgeSourceCA, CAID: ca.ID, KeyAlgorithm: "ML-DSA-65"}, "invalid_key_algorithm"},
		{edgeCertChoice{Source: edgeSourceRuntime}, "unchanged"},
	} {
		_, _, err := f.svc.SetEdgeCertificateSource(ctx, "root", "", tc.choice)
		var r mtlsRefusal
		if !errors.As(err, &r) || r.reason != tc.reason {
			t.Fatalf("%+v: %v, want %s", tc.choice, err, tc.reason)
		}
	}
	if got := installedIssuer(t, f); got != "vecta-runtime-root" {
		t.Fatalf("a refused change must leave the edge alone: %q", got)
	}

	if _, _, err := f.svc.SetEdgeCertificateSource(ctx, "root", "", edgeCertChoice{Source: edgeSourceCA, CAID: ca.ID, KeyAlgorithm: "ECDSA-P384", UpdatedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	if got := installedIssuer(t, f); got != "Corp Edge CA" {
		t.Fatalf("the edge must be issued by the chosen CA: %q", got)
	}
	v := f.svc.edgeCertificateView(ctx, "root", listenerHTTPS, "")
	if v.Installed == nil || !v.Installed.FromChoice || v.Installed.KeyAlgorithm != "ECDSA-P384" || v.Choice.UpdatedBy != "admin" {
		t.Fatalf("view: %+v %+v", v.Choice, v.Installed)
	}
	// A materializer pass keeps it (not due); it is served through Envoy's SDS
	// files, which the probe pins.
	serial := v.Installed.Serial
	if err := f.svc.MaterializeRuntimeCerts(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if v := f.svc.edgeCertificateView(ctx, "root", listenerHTTPS, ""); v.Installed.Serial != serial {
		t.Fatal("a materializer pass must not reissue a current certificate")
	}

	if _, _, err := f.svc.SetEdgeCertificateSource(ctx, "root", "", edgeCertChoice{Source: edgeSourceRuntime}); err != nil {
		t.Fatal(err)
	}
	if got := installedIssuer(t, f); got != "vecta-runtime-root" {
		t.Fatalf("back to the runtime root: %q", got)
	}
}

// External: the node makes its own key and CSR; only a certificate for that
// key, valid now, for TLS server use and signed by the given chain is
// installed. Until then the edge keeps a runtime-root certificate.
func TestEdgeExternalCertificateFlow(t *testing.T) {
	f, cfg := edgeFixture(t)
	ctx := context.Background()
	if _, err := f.svc.CreateEdgeCSR(ctx, "", "kms.example.com", nil, "", "admin"); !isRefusal(err, "source_not_external") {
		t.Fatalf("a CSR before choosing external: %v", err)
	}
	if _, _, err := f.svc.SetEdgeCertificateSource(ctx, "root", "", edgeCertChoice{Source: edgeSourceExternal}); err != nil {
		t.Fatal(err)
	}
	if got := installedIssuer(t, f); got != "vecta-runtime-root" {
		t.Fatalf("until an external certificate is installed the edge keeps serving: %q", got)
	}
	if _, err := f.svc.InstallEdgeCertificate(ctx, "", "x", ""); !isRefusal(err, "no_pending_key") {
		t.Fatalf("install without a CSR: %v", err)
	}
	p, err := f.svc.CreateEdgeCSR(ctx, "", "kms.example.com", []string{"kms.example.com", "10.0.0.5"}, "", "admin")
	if err != nil || !strings.Contains(p.CSRPEM, "CERTIFICATE REQUEST") {
		t.Fatalf("csr: %+v %v", p, err)
	}
	// The customer's CA (another tenant's CA here: nothing on the edge trusts it).
	ext, err := f.svc.CreateCA(ctx, CreateCARequest{TenantID: "customer", Name: "Customer Issuing CA", CALevel: "root",
		Algorithm: "ECDSA-P256", KeyBackend: "software", Subject: "CN=Customer Issuing CA"})
	if err != nil {
		t.Fatal(err)
	}
	signed, _, err := f.svc.IssueCertificate(ctx, IssueCertificateRequest{TenantID: "customer", CAID: ext.ID, CertType: "tls-server",
		SubjectCN: "kms.example.com", SANs: []string{"kms.example.com"}, CSRPem: p.CSRPEM, ValidityDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.svc.CreateCA(ctx, CreateCARequest{TenantID: "customer", Name: "Other CA", CALevel: "root",
		Algorithm: "ECDSA-P256", KeyBackend: "software", Subject: "CN=Other CA"})
	if err != nil {
		t.Fatal(err)
	}
	otherLeaf, _, err := f.svc.IssueCertificate(ctx, IssueCertificateRequest{TenantID: "customer", CAID: other.ID, CertType: "tls-server",
		SubjectCN: "kms.example.com", ServerKeygen: true, ValidityDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ cert, chain, reason string }{
		{otherLeaf.CertPEM, other.CertPEM, "key_mismatch"},
		{signed.CertPEM, other.CertPEM, "bad_chain"},
		{signed.CertPEM, "", "chain_required"},
		{"not a certificate", "", "invalid_certificate"},
	} {
		if _, err := f.svc.InstallEdgeCertificate(ctx, "", tc.cert, tc.chain); !isRefusal(err, tc.reason) {
			t.Fatalf("%s: %v", tc.reason, err)
		}
	}
	leaf, err := f.svc.InstallEdgeCertificate(ctx, "", signed.CertPEM, ext.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got := installedIssuer(t, f); got != "Customer Issuing CA" {
		t.Fatalf("installed issuer: %q", got)
	}
	v := f.svc.edgeCertificateView(ctx, "root", listenerHTTPS, leaf.SerialNumber.Text(16))
	if v.Installed == nil || !v.Installed.FromChoice || !v.Served || v.Pending != nil {
		t.Fatalf("view after install: %+v", v)
	}
	if _, err := f.svc.InstallEdgeCertificate(ctx, "", signed.CertPEM, ext.CertPEM); !isRefusal(err, "no_pending_key") {
		t.Fatalf("the pending key is consumed: %v", err)
	}
	// The materializer keeps the external certificate.
	if err := f.svc.MaterializeRuntimeCerts(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if got := installedIssuer(t, f); got != "Customer Issuing CA" {
		t.Fatalf("the materializer must keep the external certificate: %q", got)
	}
	// The edge serves it: the probe pins it through a real handshake.
	cert, err := tls.LoadX509KeyPair(filepath.Join(f.svc.edgeDir(), "tls.crt"), filepath.Join(f.svc.edgeDir(), "tls.key"))
	if err != nil {
		t.Fatalf("installed key and certificate must pair: %v", err)
	}
	addr := edgeServer(t, f.svc.edgeDir(), func(b *tls.Config) *tls.Config { c := b.Clone(); c.Certificates = []tls.Certificate{cert}; return c })
	t.Setenv("CERTS_EDGE_PROBE_TARGETS", "envoy="+addr)
	if err := f.svc.ProbeEdge(ctx); err != nil {
		t.Fatal(err)
	}
	if inv, _ := f.svc.EdgeInventory(ctx); !inv.Certificate.Served {
		t.Fatalf("the probe must see the installed certificate served: %+v", inv.Certificate)
	}
}

// The runtime directory is tmpfs, so a restart empties it. An installed
// external certificate and the key of a pending CSR come back from this
// node's kept copy, and the restore is audited. A kept copy that isn't an
// installed external certificate, has expired, or was ended by leaving the
// external source does not come back.
func TestEdgeExternalCertificateSurvivesRestart(t *testing.T) {
	f, cfg := edgeFixture(t)
	ctx := context.Background()
	rec := &subjectRecorder{}
	f.svc.events = rec
	const restored = "audit.certs.edge_tls_certificate_restored"
	kept := f.svc.edgeKept(listenerHTTPS)
	restart := func() {
		t.Helper()
		if err := os.RemoveAll(cfg.MaterializeDir); err != nil {
			t.Fatal(err)
		}
		if err := f.svc.MaterializeRuntimeCerts(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	ext, err := f.svc.CreateCA(ctx, CreateCARequest{TenantID: "customer", Name: "Customer Issuing CA", CALevel: "root",
		Algorithm: "ECDSA-P256", KeyBackend: "software", Subject: "CN=Customer Issuing CA"})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(csr string) string {
		t.Helper()
		signed, _, err := f.svc.IssueCertificate(ctx, IssueCertificateRequest{TenantID: "customer", CAID: ext.ID, CertType: "tls-server",
			SubjectCN: "kms.example.com", SANs: []string{"kms.example.com"}, CSRPem: csr, ValidityDays: 30})
		if err != nil {
			t.Fatal(err)
		}
		return signed.CertPEM
	}
	if _, _, err := f.svc.SetEdgeCertificateSource(ctx, "root", "", edgeCertChoice{Source: edgeSourceExternal}); err != nil {
		t.Fatal(err)
	}
	p, err := f.svc.CreateEdgeCSR(ctx, "", "kms.example.com", []string{"kms.example.com"}, "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.svc.edgeFiles(listenerHTTPS).pending()); !os.IsNotExist(err) {
		t.Fatalf("the pending key must not be on the runtime volume: %v", err)
	}

	// A restart between the CSR and the install keeps the pending key.
	restart()
	if got := installedIssuer(t, f); got != "vecta-runtime-root" || rec.count(restored) != 0 {
		t.Fatalf("nothing is installed yet: issuer %q, restores %d", got, rec.count(restored))
	}
	leaf, err := f.svc.InstallEdgeCertificate(ctx, "", sign(p.CSRPEM), ext.CertPEM)
	if err != nil {
		t.Fatalf("install after a restart: %v", err)
	}

	// A restart after the install serves the same certificate and key again.
	restart()
	if got := installedIssuer(t, f); got != "Customer Issuing CA" {
		t.Fatalf("the external certificate must survive a restart: %q", got)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(f.svc.edgeDir(), "tls.crt"), filepath.Join(f.svc.edgeDir(), "tls.key")); err != nil {
		t.Fatalf("restored key and certificate must pair: %v", err)
	}
	if v := f.svc.edgeCertificateView(ctx, "root", listenerHTTPS, ""); v.Installed == nil || !v.Installed.FromChoice {
		t.Fatalf("view after the restore: %+v", v.Installed)
	}
	if rec.count(restored) != 1 || rec.last(t, restored)["serial"] != leaf.SerialNumber.Text(16) || rec.last(t, restored)["listener"] != listenerHTTPS {
		t.Fatalf("the restore must be audited once with the serial: %d %v", rec.count(restored), rec.last(t, restored))
	}
	if err := f.svc.MaterializeRuntimeCerts(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if rec.count(restored) != 1 {
		t.Fatalf("a pass that restores nothing must audit nothing: %d", rec.count(restored))
	}

	// Refused: each of these falls back to a runtime-root certificate, and
	// the kept key is gone.
	notRestored := func(why string) {
		t.Helper()
		restart()
		if got := installedIssuer(t, f); got != "vecta-runtime-root" {
			t.Fatalf("%s: served %q", why, got)
		}
		if _, err := os.Stat(kept.dir()); !os.IsNotExist(err) {
			t.Fatalf("%s: the kept key must be discarded: %v", why, err)
		}
		if rec.count(restored) != 1 {
			t.Fatalf("%s: audited as restored", why)
		}
	}
	if err := os.WriteFile(kept.marker(), []byte("deadbeef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	notRestored("a kept certificate the marker doesn't name")

	signer, keyPEM, err := generateLeafKey(pkgcrypto.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "kms.example.com"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour)}
	der, err := x509.CreateCertificate(pkgcrypto.Reader, tpl, tpl, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	expired, _ := x509.ParseCertificate(der)
	if err := kept.writeExternal([]byte(keyPEM), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), expired); err != nil {
		t.Fatal(err)
	}
	notRestored("an expired kept certificate")

	if p, err = f.svc.CreateEdgeCSR(ctx, "", "kms.example.com", []string{"kms.example.com"}, "", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.InstallEdgeCertificate(ctx, "", sign(p.CSRPEM), ext.CertPEM); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{edgeSourceRuntime, edgeSourceExternal} {
		if _, _, err := f.svc.SetEdgeCertificateSource(ctx, "root", "", edgeCertChoice{Source: src}); err != nil {
			t.Fatal(err)
		}
	}
	notRestored("a certificate ended by leaving the external source")
}

// Every edge certificate action and refusal is audited; the measurement is
// readable by any verified caller (the pqc service's token), not anonymously.
func TestEdgeCertificateRoutesAudited(t *testing.T) {
	f, _ := edgeFixture(t)
	rec := &routetest.Recorder{}
	router := mtlsRouter(t, f.svc, rec)
	w := mtlsCall(router, http.MethodPut, "/certs/edge-tls/certificate", "acme", map[string]string{"source": "external"})
	if last := rec.Last(t); w.Code != http.StatusForbidden || last.Event.Details["reason"] != "not_root_tenant" {
		t.Fatalf("tenant admin: %d %+v", w.Code, last.Event)
	}
	w = mtlsCall(router, http.MethodPost, "/certs/edge-tls/csr", "root", map[string]string{"subject_cn": "kms.example.com"})
	if last := rec.Last(t); w.Code != http.StatusBadRequest || last.Action != "edge_tls_csr_created" || last.Event.Details["reason"] != "source_not_external" {
		t.Fatalf("csr before external: %d %+v", w.Code, last.Event)
	}
	w = mtlsCall(router, http.MethodPut, "/certs/edge-tls/certificate", "root", map[string]string{"source": "external", "reason": "public CA"})
	if last := rec.Last(t); w.Code != http.StatusOK || last.Action != "edge_tls_certificate_source_updated" || last.Event.Result != "success" ||
		last.Event.Details["source"] != "external" || last.Event.Details["previous_source"] != "runtime" {
		t.Fatalf("source change: %d %s %+v", w.Code, w.Body, last.Event)
	}
	w = mtlsCall(router, http.MethodPost, "/certs/edge-tls/csr", "root", map[string]string{"subject_cn": "kms.example.com"})
	if last := rec.Last(t); w.Code != http.StatusOK || last.Event.Result != "success" || last.Event.Details["key_algorithm"] != "ECDSA-P256" {
		t.Fatalf("csr: %d %+v", w.Code, last.Event)
	}
	w = mtlsCall(router, http.MethodPost, "/certs/edge-tls/certificate/install", "root", map[string]string{"certificate_pem": "junk"})
	if last := rec.Last(t); w.Code != http.StatusBadRequest || last.Action != "edge_tls_certificate_installed" || last.Event.Details["reason"] != "invalid_certificate" {
		t.Fatalf("bad install: %d %+v", w.Code, last.Event)
	}

	w = mtlsCall(router, http.MethodGet, "/certs/edge-tls/measurement", "acme", nil)
	if last := rec.Last(t); w.Code != http.StatusOK || last.Action != "edge_tls_measurement_read" || !strings.Contains(w.Body.String(), `"listeners"`) {
		t.Fatalf("measurement for a tenant user: %d %s", w.Code, w.Body)
	}
	req := httptest.NewRequest(http.MethodGet, "/certs/edge-tls/measurement?tenant_id=acme", nil)
	anon := httptest.NewRecorder()
	router.ServeHTTP(anon, req)
	if anon.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous measurement read: %d", anon.Code)
	}
}

func isRefusal(err error, reason string) bool {
	var r mtlsRefusal
	return errors.As(err, &r) && r.reason == reason
}

// KMIP's certificate has its own source, independent of the HTTPS edge's;
// an unknown listener is refused and audited.
func TestKMIPCertificateSource(t *testing.T) {
	f, cfg := edgeFixture(t)
	ctx := context.Background()
	kmipIssuer := func() string {
		leaf, _, err := installedLeaf(f.svc.edgeFiles(listenerKMIP).dir())
		if err != nil {
			t.Fatal(err)
		}
		return leaf.Issuer.CommonName
	}
	if got := kmipIssuer(); got != "vecta-runtime-root" {
		t.Fatalf("default KMIP issuer: %q", got)
	}
	ca, err := f.svc.CreateCA(ctx, CreateCARequest{TenantID: "root", Name: "kmip-ca", CALevel: "root",
		Algorithm: "ECDSA-P256", KeyBackend: "software", Subject: "CN=KMIP Server CA"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.SetEdgeCertificateSource(ctx, "root", "ftp", edgeCertChoice{Source: edgeSourceRuntime}); !isRefusal(err, "invalid_listener") {
		t.Fatalf("unknown listener: %v", err)
	}
	if _, _, err := f.svc.SetEdgeCertificateSource(ctx, "root", listenerKMIP, edgeCertChoice{Source: edgeSourceCA, CAID: ca.ID}); err != nil {
		t.Fatal(err)
	}
	if got := kmipIssuer(); got != "KMIP Server CA" {
		t.Fatalf("KMIP issuer after the change: %q", got)
	}
	if got := installedIssuer(t, f); got != "vecta-runtime-root" {
		t.Fatalf("the HTTPS edge must not change: %q", got)
	}
	leaf, _, _ := installedLeaf(f.svc.edgeFiles(listenerKMIP).dir())
	if !strings.Contains(strings.Join(leaf.DNSNames, ","), "kmip") {
		t.Fatalf("the KMIP certificate names kmip: %v", leaf.DNSNames)
	}
	// Kept on a materializer pass; the view reports it per listener.
	if err := f.svc.MaterializeRuntimeCerts(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	inv, err := f.svc.EdgeInventory(ctx)
	if err != nil || inv.KMIPCertificate.Choice.Source != edgeSourceCA || inv.KMIPCertificate.Installed == nil ||
		!inv.KMIPCertificate.Installed.FromChoice || inv.Certificate.Choice.Source != edgeSourceRuntime {
		t.Fatalf("inventory: %+v %+v %v", inv.KMIPCertificate, inv.Certificate.Choice, err)
	}

	rec := &routetest.Recorder{}
	router := mtlsRouter(t, f.svc, rec)
	w := mtlsCall(router, http.MethodPut, "/certs/edge-tls/certificate", "root", map[string]string{"listener": "ftp", "source": "runtime"})
	if last := rec.Last(t); w.Code != http.StatusBadRequest || last.Event.Details["reason"] != "invalid_listener" || last.Event.Details["listener"] != "ftp" {
		t.Fatalf("unknown listener route: %d %+v", w.Code, last.Event)
	}
	w = mtlsCall(router, http.MethodPut, "/certs/edge-tls/certificate", "root", map[string]string{"listener": "kmip", "source": "runtime"})
	if last := rec.Last(t); w.Code != http.StatusOK || last.Event.Details["listener"] != "kmip" || last.Event.Details["previous_source"] != "ca" {
		t.Fatalf("kmip route: %d %s %+v", w.Code, w.Body, last.Event)
	}
	if got := kmipIssuer(); got != "vecta-runtime-root" {
		t.Fatalf("back to the runtime root: %q", got)
	}
}
