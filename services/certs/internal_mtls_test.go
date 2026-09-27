package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgconfig "vecta-kms/pkg/config"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
	"vecta-kms/pkg/svctls"
)

type mtlsFixture struct {
	svc   *Service
	store *SQLStore
	trust string
	cfg   RuntimeCertMaterializerConfig
}

func newMTLSFixture(t *testing.T) mtlsFixture {
	t.Helper()
	svc, store := newCertsService(t)
	dir := t.TempDir()
	cfg := RuntimeCertMaterializerConfig{
		MaterializeDir: filepath.Join(dir, "runtime"), DashboardTLSDir: filepath.Join(dir, "dashboard-tls"),
		InfraTLSDir: filepath.Join(dir, "infra-tls"),
	}
	trust := filepath.Join(dir, "trust")
	svc.SetInternalMTLSDirs(trust, cfg)
	if _, _, err := svc.EnsureInternalPKI(context.Background(), "root"); err != nil {
		t.Fatal(err)
	}
	return mtlsFixture{svc: svc, store: store, trust: trust, cfg: cfg}
}

func (f mtlsFixture) certStatus(t *testing.T, id string) string {
	t.Helper()
	c, err := f.store.GetCertificate(context.Background(), "root", id)
	if err != nil {
		t.Fatal(err)
	}
	return c.Status
}

func (f mtlsFixture) published(t *testing.T, identity string) svctls.ServicePolicy {
	t.Helper()
	p, err := svctls.ReadPolicy(filepath.Join(f.trust, svctls.PolicyFileName), identity)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Rotating a service revokes its certificate and publishes a new generation,
// which the service applies by restarting (pkg/svctls TestPolicyChangeTriggersRestart).
func TestMTLSRotateServiceRevokesAndPublishes(t *testing.T) {
	f := newMTLSFixture(t)
	ctx := context.Background()
	enrolled, err := f.svc.EnrollInternal(ctx, "root", "kms-keycore", csrFor(t, "kms-keycore"))
	if err != nil {
		t.Fatal(err)
	}
	active, _ := f.svc.activeInternalCerts(ctx, "root", mustSub(t, f).ID)
	certID := active["kms-keycore"][0].ID
	if active["kms-keycore"][0].SerialNumber != enrolled.Serial {
		t.Fatal("setup: the enrolled certificate must be active")
	}

	res, err := f.svc.ApplyMTLSChange(ctx, "root", mtlsChange{Identity: "kms-keycore", Rotate: true, RestartMode: svctls.RestartGraceful, Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Revoked != 1 || f.certStatus(t, certID) != CertStatusRevoked || res.Policy.Generation != 1 {
		t.Fatalf("rotation must revoke the current certificate and bump the generation: %+v", res)
	}
	if p := f.published(t, "kms-keycore"); p.Generation != 1 || p.RestartMode != svctls.RestartGraceful {
		t.Fatalf("the rotation must be published for the service: %+v", p)
	}

	res, err = f.svc.ApplyMTLSChange(ctx, "root", mtlsChange{Identity: "kms-keycore", Rotate: true, RestartMode: svctls.RestartForce})
	if err != nil || res.Policy.Generation != 2 || f.published(t, "kms-keycore").RestartMode != svctls.RestartForce {
		t.Fatalf("a forced rotation must be published as force: %+v %v", res, err)
	}
}

func mustSub(t *testing.T, f mtlsFixture) CA {
	t.Helper()
	_, sub, err := f.svc.EnsureInternalPKI(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	return sub
}

func TestMTLSPolicyChangesAndRefusals(t *testing.T) {
	f := newMTLSFixture(t)
	ctx := context.Background()
	res, err := f.svc.ApplyMTLSChange(ctx, "root", mtlsChange{Identity: "kms-auth", KeyAlgorithm: pkgcrypto.AlgECDSAP384, KXProfile: svctls.KXPQCRequired})
	if err != nil {
		t.Fatal(err)
	}
	if p := f.published(t, "kms-auth"); p.KeyAlgorithm != pkgcrypto.AlgECDSAP384 || p.KXProfile != svctls.KXPQCRequired || p.Generation != res.Policy.Generation {
		t.Fatalf("the policy must be published: %+v", p)
	}
	for name, tc := range map[string]struct {
		ch     mtlsChange
		reason string
	}{
		"same policy again":       {mtlsChange{Identity: "kms-auth", KeyAlgorithm: pkgcrypto.AlgECDSAP384, KXProfile: svctls.KXPQCRequired}, "unchanged"},
		"ML-DSA certificate":      {mtlsChange{Identity: "kms-auth", KeyAlgorithm: "ML-DSA-65"}, "invalid_policy"},
		"unknown profile":         {mtlsChange{Identity: "kms-auth", KXProfile: "x25519-only"}, "invalid_policy"},
		"groups of a daemon":      {mtlsChange{Identity: "vecta-postgres", KXProfile: svctls.KXPQCRequired}, "kx_profile_not_applicable"},
		"forced daemon restart":   {mtlsChange{Identity: "vecta-postgres", Rotate: true, RestartMode: svctls.RestartForce}, "force_not_available"},
		"not a platform identity": {mtlsChange{Identity: "kms-evil", Rotate: true}, "unknown_identity"},
	} {
		_, err := f.svc.ApplyMTLSChange(ctx, "root", tc.ch)
		r, ok := err.(mtlsRefusal)
		if !ok || r.reason != tc.reason {
			t.Fatalf("%s: want refusal %s, got %v", name, tc.reason, err)
		}
	}
}

// A file identity is reissued at once under the policy's key, the certificate
// it replaces is revoked, and a certificate from another CA with the same
// subject (the edge certificate of vecta-envoy) is untouched.
func TestMTLSFileIdentityReissueSparesOtherCAs(t *testing.T) {
	f := newMTLSFixture(t)
	ctx := context.Background()
	root, _, _ := f.svc.EnsureInternalPKI(ctx, "root")
	edge, _, err := f.svc.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID: "root", CAID: root.ID, CertType: "tls-server", Algorithm: pkgcrypto.AlgECDSAP256, CertClass: "internal-mtls",
		SubjectCN: "vecta-envoy", SANs: []string{"localhost"}, ServerKeygen: true, ValidityDays: 30, Protocol: "internal-mtls",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ApplyMTLSChange(ctx, "root", mtlsChange{Identity: "vecta-envoy", KeyAlgorithm: pkgcrypto.AlgECDSAP384}); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(f.cfg.MaterializeDir, "envoy-client", "tls.crt")
	if got := fileKeyAlgorithm(certPath); got != pkgcrypto.AlgECDSAP384 {
		t.Fatalf("the reissued certificate must use the policy key, got %q", got)
	}
	first, _ := f.svc.activeInternalCerts(ctx, "root", mustSub(t, f).ID)
	firstID := first["vecta-envoy"][0].ID

	res, err := f.svc.ApplyMTLSChange(ctx, "root", mtlsChange{Identity: "vecta-envoy", Rotate: true})
	if err != nil || !res.Reissued {
		t.Fatalf("rotate: %+v %v", res, err)
	}
	if f.certStatus(t, firstID) != CertStatusRevoked {
		t.Fatal("the replaced client certificate must be revoked")
	}
	if f.certStatus(t, edge.ID) != CertStatusActive {
		t.Fatal("the edge certificate (another CA, same subject) must not be revoked")
	}
	inv, _, err := f.svc.MTLSInventory(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range inv {
		if v.Identity == "vecta-envoy" && (!v.Applied || v.ServedFile == nil || v.ServedFile.Generation != 2) {
			t.Fatalf("the written file must show as applied: %+v", v)
		}
	}
}

// A policy counts as applied only when the instances report running it, and
// audit.certs.internal_mtls_applied is emitted once per generation.
func TestMTLSAppliedOnlyWhenReportedAndAuditedOnce(t *testing.T) {
	f := newMTLSFixture(t)
	ctx := context.Background()
	if _, err := f.svc.ApplyMTLSChange(ctx, "root", mtlsChange{Identity: "kms-keycore", KXProfile: svctls.KXPQCRequired}); err != nil {
		t.Fatal(err)
	}
	applied := func() bool {
		inv, _, err := f.svc.MTLSInventory(ctx, "root")
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range inv {
			if v.Identity == "kms-keycore" {
				return v.Applied
			}
		}
		t.Fatal("kms-keycore missing from the inventory")
		return false
	}
	rec := &routetest.Recorder{}
	if applied() {
		t.Fatal("nothing reported yet: not applied")
	}
	report := func(gen int64) {
		if err := f.store.UpsertMTLSObserved(ctx, mtlsObservedRow{Identity: "kms-keycore", Instance: "node-a", Serial: "01",
			KeyAlgorithm: pkgcrypto.AlgECDSAP256, KXProfile: svctls.KXPQCRequired, Generation: gen, StartedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	report(0) // the old process, before its restart
	if applied() {
		t.Fatal("an instance on the previous generation: not applied")
	}
	_ = f.svc.AuditAppliedMTLS(ctx, rec)
	if len(rec.Events()) != 0 {
		t.Fatal("no applied event before the service runs the policy")
	}
	report(1)
	if !applied() {
		t.Fatal("reported on the new generation: applied")
	}
	if err := f.svc.AuditAppliedMTLS(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.AuditAppliedMTLS(ctx, rec); err != nil {
		t.Fatal(err)
	}
	ev := rec.Events()
	if len(ev) != 1 || ev[0].Action != "internal_mtls_applied" || ev[0].Event.TargetID != "kms-keycore" || ev[0].Event.Details["kx_profile"] != svctls.KXPQCRequired {
		t.Fatalf("exactly one applied event: %+v", ev)
	}
}

func mtlsRouter(t *testing.T, svc *Service, rec *routetest.Recorder) *route.Router {
	t.Helper()
	k := route.New("cert", rec, log.New(io.Discard, "", 0))
	svc.RegisterInternalMTLSRoutes(k)
	return k
}

func TestMTLSRoutesRefusalsAudited(t *testing.T) {
	f := newMTLSFixture(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, mtlsRouter(t, f.svc, rec), rec)
}

func mtlsCall(router http.Handler, method, path, tenant string, body interface{}) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path+"?tenant_id="+tenant, bytes.NewReader(raw))
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{UserID: "admin-1", TenantID: tenant, Role: "admin", Permissions: []string{"*"}}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// Only the root tenant manages the platform's mTLS; every change and refusal
// is audited with its details.
func TestMTLSRoutesRootOnlyAndAudited(t *testing.T) {
	f := newMTLSFixture(t)
	rec := &routetest.Recorder{}
	router := mtlsRouter(t, f.svc, rec)

	w := mtlsCall(router, http.MethodPost, "/certs/internal-mtls/kms-keycore/rotate", "acme", map[string]string{"mode": "graceful"})
	if w.Code != http.StatusForbidden || rec.Last(t).Event.Details["reason"] != "not_root_tenant" {
		t.Fatalf("a tenant admin must be refused and audited: %d %+v", w.Code, rec.Last(t))
	}

	w = mtlsCall(router, http.MethodPut, "/certs/internal-mtls/kms-keycore/policy", "root", map[string]string{"key_algorithm": pkgcrypto.AlgECDSAP384, "kx_profile": svctls.KXPQCRequired, "reason": "test"})
	last := rec.Last(t)
	if w.Code != http.StatusOK || last.Action != "internal_mtls_policy_updated" || last.Event.Result != "success" ||
		last.Event.Details["kx_profile"] != svctls.KXPQCRequired || last.Event.Details["previous_kx_profile"] != svctls.KXPQCPreferred {
		t.Fatalf("a policy change must be audited with old and new values: %d %s %+v", w.Code, w.Body, last)
	}

	w = mtlsCall(router, http.MethodPost, "/certs/internal-mtls/kms-keycore/rotate", "root", map[string]string{"mode": "graceful"})
	if last := rec.Last(t); w.Code != http.StatusOK || last.Action != "internal_mtls_rotated" || last.Event.Result != "success" || last.Event.Details["restart_mode"] != "graceful" {
		t.Fatalf("a rotation must be audited with its restart mode: %d %s %+v", w.Code, w.Body, last)
	}

	w = mtlsCall(router, http.MethodPost, "/certs/internal-mtls/rotate-all", "root", map[string]string{"mode": "graceful"})
	if w.Code != http.StatusBadRequest || rec.Last(t).Event.Details["reason"] != "confirmation_required" {
		t.Fatalf("rotate-all needs a typed confirmation: %d", w.Code)
	}
	w = mtlsCall(router, http.MethodPost, "/certs/internal-mtls/rotate-all", "root", map[string]string{"mode": "graceful", "confirm": "rotate-all"})
	if w.Code != http.StatusOK || rec.Last(t).Action != "internal_mtls_rotated_all" {
		t.Fatalf("rotate-all: %d %s", w.Code, w.Body)
	}
	certs := f.published(t, "kms-certs")
	keycore := f.published(t, "kms-keycore")
	if !certs.ApplyAfter.After(keycore.ApplyAfter) {
		t.Fatalf("rotate-all must stagger restarts, certs last: certs %v keycore %v", certs.ApplyAfter, keycore.ApplyAfter)
	}

	w = mtlsCall(router, http.MethodGet, "/certs/internal-mtls", "root", nil)
	var out struct {
		Items []mtlsIdentityView `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != http.StatusOK || len(out.Items) != len(svctls.Services)+len(svctls.Materialized)+len(svctls.Infrastructure) {
		t.Fatalf("the inventory must list every internal identity: %d, %d items", w.Code, len(out.Items))
	}
	if last := rec.Last(t); last.Action != "internal_mtls_inventory_read" || last.Event.Result != "success" {
		t.Fatalf("reading the inventory must be audited: %+v", last)
	}
}

// Storage on real Postgres: the policy and observed tables from the
// migration, the upserts, timestamp handling, and the exact statement every
// service uses to report (pkg/config.MTLSObservedUpsertSQL).
func TestMTLSStorePostgres(t *testing.T) {
	ctx := context.Background()
	conn := postgresTestDB(t)
	st := NewSQLStore(conn)
	after := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	for gen := int64(1); gen <= 2; gen++ {
		if err := st.UpsertMTLSPolicy(ctx, mtlsPolicyRow{Identity: "kms-keycore", KeyAlgorithm: pkgcrypto.AlgECDSAP384, KXProfile: svctls.KXPQCRequired, Generation: gen, RestartMode: svctls.RestartForce, ApplyAfter: after, UpdatedBy: "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := st.ListMTLSPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r := rows["kms-keycore"]; r.Generation != 2 || r.RestartMode != svctls.RestartForce || !r.ApplyAfter.Equal(after) || r.AuditedGeneration != 0 {
		t.Fatalf("upsert must replace the row: %+v", r)
	}
	if err := st.MarkMTLSPolicyAudited(ctx, "kms-keycore", 2); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkMTLSPolicyAudited(ctx, "kms-keycore", 1); err != nil { // never goes back
		t.Fatal(err)
	}
	if rows, _ = st.ListMTLSPolicies(ctx); rows["kms-keycore"].AuditedGeneration != 2 {
		t.Fatalf("audited generation: %d", rows["kms-keycore"].AuditedGeneration)
	}

	started := time.Now().UTC().Truncate(time.Second)
	for _, serial := range []string{"0a", "0b"} {
		if _, err := conn.SQL().ExecContext(ctx, pkgconfig.MTLSObservedUpsertSQL, "kms-keycore", "node-a", serial, started.Add(7*24*time.Hour),
			pkgcrypto.AlgECDSAP384, svctls.KXPQCRequired, `["X25519MLKEM768"]`, int64(2), "X25519MLKEM768", started, started); err != nil {
			t.Fatalf("the services' report statement: %v", err)
		}
	}
	if _, err := conn.SQL().ExecContext(ctx, pkgconfig.MTLSObservedUpsertSQL, "kms-auth", "node-a", "0c", started, pkgcrypto.AlgECDSAP256,
		svctls.KXPQCPreferred, `[]`, int64(0), "", nil, started); err != nil {
		t.Fatalf("a report before any handshake (NULL time): %v", err)
	}
	obs, err := st.ListMTLSObserved(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 || obs[1].Serial != "0b" || obs[1].Generation != 2 || obs[1].LastHandshakeGroup != "X25519MLKEM768" ||
		!obs[1].LastHandshakeAt.Equal(started) || len(obs[1].ServerGroups) != 1 || !obs[0].LastHandshakeAt.IsZero() {
		t.Fatalf("observed rows: %+v", obs)
	}
}
