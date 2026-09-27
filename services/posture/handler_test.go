package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
	"vecta-kms/pkg/tenantcheck"
)

type recordedPublish struct {
	mu       sync.Mutex
	subjects []string
}

func (p *recordedPublish) Publish(_ context.Context, subject string, _ []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	return nil
}

// newPostureHandler serves posture over the real 001 schema on SQLite, with
// the audit sink recorded.
func newPostureHandler(t *testing.T, event EventPublisher) (*Handler, *SQLStore, *routetest.Recorder) {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{UseSQLite: true, SQLitePath: ":memory:", MaxOpen: 1, MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	schema, err := os.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range strings.Split(string(schema), ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := conn.SQL().Exec(stmt); err != nil {
			t.Fatalf("%v: %s", err, stmt)
		}
	}
	store := NewSQLStore(conn)
	h := NewHandler(NewService(store, nil, event))
	rec := &routetest.Recorder{}
	h.audit = rec
	return h, store, rec
}

func userClaims(user, tenant string) *pkgauth.Claims {
	c := &pkgauth.Claims{UserID: user, TenantID: tenant, Role: "admin", Permissions: []string{"*"}}
	c.Subject = user
	return c
}

// reportingPrincipal is the kms-reporting service identity auth bootstraps.
func reportingPrincipal() *pkgauth.Claims {
	return &pkgauth.Claims{Role: "client-service", ClientID: "kms-reporting", TenantID: tenantcheck.InternalServiceTenant(), Permissions: []string{tenantcheck.ServicePermission}}
}

func postureCall(h http.Handler, claims *pkgauth.Claims, method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	if claims != nil {
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func expectRefused(t *testing.T, rec *routetest.Recorder, rr *httptest.ResponseRecorder, status int, action, reason string) {
	t.Helper()
	if rr.Code != status {
		t.Fatalf("status %d, want %d: %s", rr.Code, status, rr.Body)
	}
	e := rec.Last(t)
	if e.Action != action || e.Event.Result != route.ResultRefused || e.Event.Details["reason"] != reason {
		t.Fatalf("audited %s result=%s reason=%v, want %s refused %s", e.Action, e.Event.Result, e.Event.Details["reason"], action, reason)
	}
}

// Every posture route, engine and leak scanner, refuses and audits an
// unauthenticated caller, a caller without the permission and a caller
// naming another tenant.
func TestPostureRoutesRefusalsAudited(t *testing.T) {
	h, _, rec := newPostureHandler(t, nil)
	routetest.RefusalsAudited(t, h.newRouter(rec), rec)
}

// In the served chain, a missing or forged token reaches the kernel without
// claims and is refused and audited there; nothing defaults to all tenants.
func TestPostureUnauthenticatedRefusedThroughMiddleware(t *testing.T) {
	h, _, rec := newPostureHandler(t, nil)
	served := claimsMiddleware(h, func(string) (*pkgauth.Claims, error) { return nil, errors.New("bad signature") })
	for _, tc := range []struct{ method, path, action string }{
		{http.MethodGet, "/posture/dashboard", "dashboard_viewed"},
		{http.MethodGet, "/posture/risk", "risk_read"},
		{http.MethodGet, "/posture/risk/history", "risk_history_read"},
		{http.MethodPost, "/posture/scan?tenant_id=*", "scan_run"},
		{http.MethodPost, "/posture/events", "events_ingested"},
		{http.MethodPost, "/posture/actions/a1/execute", "action_executed"},
	} {
		expectRefused(t, rec, postureCall(served, nil, tc.method, tc.path, ""), http.StatusUnauthorized, tc.action, route.ReasonUnauthenticated)
		rr := postureCall(served, nil, tc.method, tc.path, "", "Authorization", "Bearer forged")
		expectRefused(t, rec, rr, http.StatusUnauthorized, tc.action, route.ReasonUnauthenticated)
	}
}

// A tenant-t1 caller can't reach t2 through the query, the header or a body
// tenant_id, including one inside a batch item.
func TestPostureCrossTenantRefused(t *testing.T) {
	h, store, rec := newPostureHandler(t, nil)
	alice := userClaims("alice", "t1")
	for _, tc := range []struct{ method, path, body, action string }{
		{http.MethodGet, "/posture/dashboard?tenant_id=t2", "", "dashboard_viewed"},
		{http.MethodGet, "/posture/risk?tenant_id=t2", "", "risk_read"},
		{http.MethodGet, "/posture/risk/history?tenant_id=t2", "", "risk_history_read"},
		{http.MethodPost, "/posture/scan?tenant_id=t2", "", "scan_run"},
		{http.MethodPost, "/posture/events", `{"tenant_id":"t2","service":"keycore","action":"key.export"}`, "events_ingested"},
	} {
		expectRefused(t, rec, postureCall(h, alice, tc.method, tc.path, tc.body), http.StatusForbidden, tc.action, route.ReasonTenantMismatch)
	}
	rr := postureCall(h, alice, http.MethodGet, "/posture/findings", "", "X-Tenant-ID", "t2")
	expectRefused(t, rec, rr, http.StatusForbidden, "findings_listed", route.ReasonTenantMismatch)

	batch := `{"items":[{"service":"keycore","action":"key.read"},{"tenant_id":"t2","service":"keycore","action":"key.export"}]}`
	rr = postureCall(h, alice, http.MethodPost, "/posture/events/batch", batch)
	expectRefused(t, rec, rr, http.StatusForbidden, "events_ingested", route.ReasonTenantMismatch)
	if got := rec.Last(t).Event; got.TenantID != "t1" || got.Details["requested_tenant"] != "t2" {
		t.Fatalf("refusal recorded as %s, requested %v", got.TenantID, got.Details["requested_tenant"])
	}
	var stored int
	if err := store.db.SQL().QueryRow(`SELECT COUNT(*) FROM posture_events_hot`).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("refused requests stored %d events (%v)", stored, err)
	}
}

// Events land in the caller's tenant, and the kernel event says how many.
func TestPostureIngestBindsTokenTenant(t *testing.T) {
	h, store, rec := newPostureHandler(t, nil)
	rr := postureCall(h, userClaims("alice", "t1"), http.MethodPost, "/posture/events/batch", `{"items":[{"service":"keycore","action":"key.export","result":"denied"}]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", rr.Code, rr.Body)
	}
	if tenants, _ := store.ListTenants(context.Background()); len(tenants) != 1 || tenants[0] != "t1" {
		t.Fatalf("events stored under %v, want [t1]", tenants)
	}
	if e := rec.Last(t); e.Action != "events_ingested" || e.Event.TenantID != "t1" || e.Event.Details["inserted"] != 1 || e.Event.ActorID != "alice" {
		t.Fatalf("ingest event %+v", e)
	}
}

// "*" and "all" no longer mean every tenant: an absent tenant is the token's,
// and a tenant-less root token or service principal naming a wildcard is
// refused.
func TestPostureWildcardTenantRefused(t *testing.T) {
	h, _, rec := newPostureHandler(t, nil)
	rr := postureCall(h, userClaims("alice", "t1"), http.MethodGet, "/posture/risk", "")
	var out struct {
		Risk RiskSnapshot `json:"risk"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &out) != nil || out.Risk.TenantID != "t1" {
		t.Fatalf("risk without tenant_id: %d %s, want t1's", rr.Code, rr.Body)
	}
	root := userClaims("root-admin", "")
	for _, path := range []string{"/posture/dashboard?tenant_id=*", "/posture/risk?tenant_id=all", "/posture/risk/history?tenant_id=*"} {
		action := map[string]string{"/posture/dashboard": "dashboard_viewed", "/posture/risk": "risk_read", "/posture/risk/history": "risk_history_read"}[strings.Split(path, "?")[0]]
		expectRefused(t, rec, postureCall(h, root, http.MethodGet, path, ""), http.StatusForbidden, action, reasonTenantWildcard)
	}
	expectRefused(t, rec, postureCall(h, reportingPrincipal(), http.MethodPost, "/posture/scan?tenant_id=all", ""), http.StatusForbidden, "scan_run", reasonTenantWildcard)
	if rr := postureCall(h, reportingPrincipal(), http.MethodPost, "/posture/scan", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("service principal scan without tenant: %d, want 400 tenant_required", rr.Code)
	}
}

// Reporting's verified service identity reads a tenant's findings and
// actions; the event records it as a service actor in that tenant.
func TestPostureServicePrincipalReadsTenant(t *testing.T) {
	h, _, rec := newPostureHandler(t, nil)
	for _, tc := range []struct{ path, action string }{
		{"/posture/findings?tenant_id=t1&limit=5", "findings_listed"},
		{"/posture/actions?tenant_id=t1&limit=5", "actions_listed"},
	} {
		if rr := postureCall(h, reportingPrincipal(), http.MethodGet, tc.path, ""); rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", tc.path, rr.Code, rr.Body)
		}
		if e := rec.Last(t); e.Action != tc.action || e.Event.TenantID != "t1" || e.Event.ActorType != "service" || e.Event.ActorID != "kms-reporting" {
			t.Fatalf("%s audited %+v", tc.path, e)
		}
	}
	// The same client_id without the reserved permission is an ordinary
	// client, held to its own tenant.
	forged := reportingPrincipal()
	forged.TenantID, forged.Permissions = "t2", []string{"*"}
	expectRefused(t, rec, postureCall(h, forged, http.MethodGet, "/posture/findings?tenant_id=t1", ""), http.StatusForbidden, "findings_listed", route.ReasonTenantMismatch)
}

// The dashboard read is audited once, by the kernel, with its counts.
func TestDashboardViewedAuditedOnce(t *testing.T) {
	bus := &recordedPublish{}
	h, _, rec := newPostureHandler(t, bus)
	if rr := postureCall(h, userClaims("alice", "t1"), http.MethodGet, "/posture/dashboard", ""); rr.Code != http.StatusOK {
		t.Fatalf("dashboard: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "dashboard_viewed" || e.Event.TenantID != "t1" || e.Event.Details["open_findings"] != 0 {
		t.Fatalf("dashboard event %+v", e)
	}
	if len(bus.subjects) != 0 {
		t.Fatalf("service layer still publishes %v", bus.subjects)
	}
}
