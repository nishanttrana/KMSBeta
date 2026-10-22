package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	pkgauth "vecta-kms/pkg/auth"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/route/routetest"
)

// The platform's list is exactly the CA keys the Go toolchain refuses: it
// fails when a toolchain update changes distrustedSPKIHashes.
func TestBuiltinDistrustMatchesGoToolchain(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "crypto", "x509", "verify.go"))
	if err != nil {
		t.Fatalf("the toolchain's crypto/x509 source must be readable: %v", err)
	}
	block := regexp.MustCompile(`(?s)var distrustedSPKIHashes = map\[string\]struct\{\}\{(.*?)\n\}`).FindSubmatch(src)
	if block == nil {
		t.Fatal("crypto/x509 no longer has distrustedSPKIHashes: revisit builtinDistrusted")
	}
	goList := regexp.MustCompile(`"([0-9a-f]{64})"`).FindAllStringSubmatch(string(block[1]), -1)
	var want, got []string
	for _, m := range goList {
		want = append(want, m[1])
	}
	for h := range builtinDistrusted {
		got = append(got, h)
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(want, ",") != strings.Join(got, ",") || len(want) == 0 {
		t.Fatalf("builtinDistrusted %v, the toolchain distrusts %v", got, want)
	}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCert(t *testing.T, cn string, parent *testCA, isCA bool, ocspURL string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: isCA, BasicConstraintsValid: true, DNSNames: []string{cn}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if ocspURL != "" {
		tmpl.OCSPServer = []string{ocspURL}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert: cert, key: key}
}

// serveChain is a TLS endpoint presenting leaf and intermediate.
func serveChain(t *testing.T, leaf, inter testCA) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{
		Certificate: [][]byte{leaf.cert.Raw, inter.cert.Raw}, PrivateKey: leaf.key, Leaf: leaf.cert}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// A certificate under a CA the tenant distrusts is found without
// rescanning, announced once, counted over the inventory and listed with
// the CA it runs through; the platform's own entries can't be removed.
func TestDistrustedCAFindings(t *testing.T) {
	svc, store, _ := newDiscoveryService(t)
	checkDistrust(t, svc, store, "t1")
}

// The same on real Postgres (CI integration-postgres): the IN lists, the
// distinct counts and the NOT EXISTS of the findings.
func TestDistrustedCAFindingsPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{PostgresDSN: dsn, MaxOpen: 2, MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(context.Background(), "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	store := NewSQLStore(conn)
	checkDistrust(t, NewService(store, nil, nil, nil), store, "t-dist-pg-"+strconv.FormatInt(time.Now().UnixNano(), 36))
}

func checkDistrust(t *testing.T, svc *Service, store *SQLStore, tenant string) {
	t.Helper()
	rec := &routetest.Recorder{}
	svc.audit = rec
	ctx := context.Background()
	root := newCert(t, "Test Root", nil, true, "")
	inter := newCert(t, "Shady Intermediate", &root, true, "")
	leaf := newCert(t, "api.example.test", &inter, false, "")
	addr := serveChain(t, leaf, inter)

	scan := func(scanID string) {
		t.Helper()
		p, err := probeTLS(ctx, addr, 3*time.Second, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.chain) != 2 || p.trusted || p.chainErr == "" {
			t.Fatalf("the probe must keep the presented chain and why it failed: %d trusted=%v err=%q", len(p.chain), p.trusted, p.chainErr)
		}
		p.revocation = svc.checkRevocation(ctx, p.chain)
		svc.storeAssets(ctx, tenant, svc.tlsAssets(tenant, scanID, addr, p), map[string]bool{})
	}
	scan("scan-1")
	found := func() int {
		n := 0
		for _, ev := range rec.Events() {
			if ev.Action == "distrusted_ca_found" {
				n++
			}
		}
		return n
	}
	if total, _, _, _ := svc.DistrustFindings(ctx, tenant, "", 0, 0); total != 0 || found() != 0 {
		t.Fatalf("nothing is distrusted yet: %d findings, %d events", total, found())
	}

	pemInter := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.cert.Raw}))
	d, err := svc.AddDistrustedCA(ctx, tenant, DistrustInput{CertificatePEM: pemInter}, "admin-1")
	if err != nil {
		t.Fatal(err)
	}
	if d.SPKISHA256 != spkiSHA256(inter.cert) || d.Affected != 1 || !strings.Contains(d.Label, "Shady Intermediate") || found() != 1 {
		t.Fatalf("distrusting a CA finds what it already affects: %+v, %d events", d, found())
	}
	ev := rec.Last(t)
	if ev.Event.Details["distrusted_spki_sha256"] != d.SPKISHA256 || ev.Event.Details["location"] != addr {
		t.Fatalf("event %+v", ev.Event)
	}

	scan("scan-2") // a rescan finds it again but doesn't announce it again
	if found() != 1 {
		t.Fatalf("a certificate is announced once per distrusted CA, got %d", found())
	}
	total, unrecorded, items, err := svc.DistrustFindings(ctx, tenant, d.SPKISHA256, 0, 0)
	if err != nil || total != 1 || unrecorded != 0 || len(items) != 1 || items[0].Matches[0].Source != "tenant" {
		t.Fatalf("findings %d %d %+v %v", total, unrecorded, items, err)
	}
	list, _ := svc.ListDistrustedCAs(ctx, tenant)
	if len(list) != len(builtinDistrusted)+1 || list[0].SPKISHA256 != d.SPKISHA256 || list[0].Affected != 1 {
		t.Fatalf("the list puts affected CAs first with their counts: %+v", list[0])
	}
	if other, _, _, _ := svc.DistrustFindings(ctx, tenant+"-other", "", 0, 0); other != 0 {
		t.Fatal("another tenant sees nothing")
	}

	// A certificate found before chains were recorded is counted apart.
	if err := store.UpsertAsset(ctx, CryptoAsset{TenantID: tenant, ID: "old-cert", ScanID: "s0", AssetType: "tls_certificate", Name: "old", Location: "old:443", Source: "network", Metadata: map[string]interface{}{}}); err != nil {
		t.Fatal(err)
	}
	if _, unrecorded, _, _ = svc.DistrustFindings(ctx, tenant, "", 0, 0); unrecorded != 1 {
		t.Fatalf("unrecorded %d", unrecorded)
	}

	for name, in := range map[string]DistrustInput{
		"platform's own": {SPKISHA256: "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105", Label: "x"},
		"not a hash":     {SPKISHA256: "abc", Label: "x"},
		"no label":       {SPKISHA256: strings.Repeat("a", 64)},
		"hash mismatch":  {CertificatePEM: pemInter, SPKISHA256: strings.Repeat("b", 64)},
	} {
		if _, err := svc.AddDistrustedCA(ctx, tenant, in, "admin-1"); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
	if err := svc.RemoveDistrustedCA(ctx, tenant, "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105"); err == nil {
		t.Fatal("the platform's list can't be changed per tenant")
	}
	if err := svc.RemoveDistrustedCA(ctx, tenant, d.SPKISHA256); err != nil {
		t.Fatal(err)
	}
	if total, _, _, _ := svc.DistrustFindings(ctx, tenant, "", 0, 0); total != 0 {
		t.Fatalf("after removal %d findings", total)
	}
	// Deleting the certificate deletes its chain.
	assetID := items[0].Asset.ID
	if err := store.DeleteAsset(ctx, tenant, assetID); err != nil {
		t.Fatal(err)
	}
	if m, _ := store.ChainSPKIsOf(ctx, tenant, []string{assetID}); len(m[assetID]) != 0 {
		t.Fatal("a deleted certificate's chain must go with it")
	}
}

// The leaf's OCSP responder is asked, and its answer counts only when it is
// signed for the issuer and current. A revocation is announced once.
func TestOCSPRevocation(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	rec := &routetest.Recorder{}
	svc.audit = rec
	ctx := context.Background()
	root := newCert(t, "Root", nil, true, "")
	inter := newCert(t, "Issuing CA", &root, true, "")
	stranger := newCert(t, "Not the issuer", &root, true, "")
	answer := struct {
		status int
		signer testCA
		next   time.Time
	}{status: ocsp.Good, signer: inter}
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(raw)
		req, err := ocsp.ParseRequest(raw)
		if err != nil || r.Header.Get("Content-Type") != "application/ocsp-request" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp, err := ocsp.CreateResponse(answer.signer.cert, answer.signer.cert, ocsp.Response{
			Status: answer.status, SerialNumber: req.SerialNumber, ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: answer.next,
			RevokedAt: time.Now().Add(-time.Hour), RevocationReason: ocsp.KeyCompromise, IssuerHash: crypto.SHA256,
		}, answer.signer.key)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_, _ = w.Write(resp)
	}))
	defer responder.Close()
	svc.ocsp = responder.Client() // loopback; production dials through ssrfguard
	leaf := newCert(t, "web.example.test", &inter, false, responder.URL)
	chain := []*x509.Certificate{leaf.cert, inter.cert}

	check := func(want string) map[string]interface{} {
		t.Helper()
		got := svc.checkRevocation(ctx, chain)
		if got["status"] != want {
			t.Fatalf("status %v, want %s (%v)", got["status"], want, got["error"])
		}
		return got
	}
	answer.next = time.Now().Add(time.Hour)
	check("good")
	answer.status = ocsp.Revoked
	if got := check("revoked"); got["reason"] != "key_compromise" || got["revoked_at"] == "" {
		t.Fatalf("revocation details %v", got)
	}
	answer.signer = stranger
	check("unavailable") // signed by someone other than the issuer
	answer.signer, answer.next = inter, time.Now().Add(-time.Minute)
	check("unavailable") // out of date
	if got := svc.checkRevocation(ctx, []*x509.Certificate{leaf.cert}); got["status"] != "unavailable" {
		t.Fatal("no issuer presented: no answer can be checked")
	}
	if got := svc.checkRevocation(ctx, []*x509.Certificate{inter.cert, root.cert}); got["status"] != "not_offered" {
		t.Fatal("a certificate without an OCSP address is not_offered")
	}

	// Stored twice while revoked: announced once.
	answer.next, answer.status = time.Now().Add(time.Hour), ocsp.Revoked
	p := tlsProbe{version: "TLS 1.3", cipher: "TLS_AES_128_GCM_SHA256", kex: "X25519", leaf: leaf.cert, chain: chain, chainErr: "x509: unknown authority"}
	for i := 0; i < 2; i++ {
		p.revocation = svc.checkRevocation(ctx, chain)
		svc.storeAssets(ctx, "t1", svc.tlsAssets("t1", "scan", "web.example.test:443", p), map[string]bool{})
	}
	n := 0
	for _, ev := range rec.Events() {
		if ev.Action == "revoked_certificate_found" {
			n++
			if ev.Event.Details["reason"] != "key_compromise" {
				t.Fatalf("event %+v", ev.Event)
			}
		}
	}
	if n != 1 {
		t.Fatalf("a revoked certificate is announced once, got %d", n)
	}
}

// The distrust routes through the kernel: a malformed entry is refused and
// audited with its reason, an added one is audited with how many
// certificates it affects, and the findings answer counts the whole set.
func TestDistrustRoutes(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)
	admin := &pkgauth.Claims{UserID: "admin-1", TenantID: "t1", Permissions: []string{"discovery.read", "discovery.write"}}

	if rr := serveAs(h, admin, http.MethodPost, "/discovery/distrusted-cas?tenant_id=t1", `{"label":"x","spki_sha256":"nothex"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad hash: %d %s", rr.Code, rr.Body)
	}
	if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "invalid_distrusted_ca" {
		t.Fatalf("refusal event %+v", ev.Event)
	}
	hash := strings.Repeat("ab", 32)
	if rr := serveAs(h, admin, http.MethodPost, "/discovery/distrusted-cas?tenant_id=t1", `{"label":"Old partner CA","spki_sha256":"`+hash+`"}`); rr.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rr.Code, rr.Body)
	}
	if ev := rec.Last(t); ev.Action != "distrusted_ca_add" || ev.Event.TargetID != hash || ev.Event.Details["affected"] != int64(0) {
		t.Fatalf("add event %s %+v", ev.Action, ev.Event)
	}
	rr := serveAs(h, admin, http.MethodGet, "/discovery/distrusted?tenant_id=t1", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"total":0`) {
		t.Fatalf("findings: %d %s", rr.Code, rr.Body)
	}
	if rr := serveAs(h, admin, http.MethodDelete, "/discovery/distrusted-cas/"+hash+"?tenant_id=t1", ""); rr.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", rr.Code, rr.Body)
	}
}
