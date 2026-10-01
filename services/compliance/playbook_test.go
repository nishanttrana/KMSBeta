package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/clusterstate"
	"vecta-kms/pkg/mek/mektest"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
	"vecta-kms/pkg/servicetoken"
)

var (
	pbAdmin  = &pkgauth.Claims{UserID: "u-admin", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	pbWriter = &pkgauth.Claims{UserID: "u-writer", TenantID: "t1", Role: "ops", Permissions: []string{permPlaybookRead, permPlaybookWrite, permPlaybookRun}}
	pbClient = &pkgauth.Claims{ClientID: "ci-bot", TenantID: "t1", Role: "client-service", Permissions: []string{"*"}}
)

// platformCall is one request a platform stand-in received.
type platformCall struct {
	Method, Path, Tenant, Correlation, Auth string
	Body                                    map[string]interface{}
}

// platformRecorder stands in for keycore, certs, auth, governance, reporting
// and posture: it records each call and answers with the configured status.
type platformRecorder struct {
	mu     sync.Mutex
	calls  []platformCall
	status int
	body   string
}

func (p *platformRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]interface{}
	_ = json.Unmarshal(raw, &body)
	p.mu.Lock()
	p.calls = append(p.calls, platformCall{Method: r.Method, Path: r.URL.Path, Tenant: r.Header.Get("X-Tenant-ID"), Correlation: r.Header.Get("X-Correlation-ID"), Auth: r.Header.Get("Authorization"), Body: body})
	status, resp := p.status, p.body
	p.mu.Unlock()
	if status == 0 {
		status, resp = http.StatusOK, `{"status":"ok"}`
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(resp))
}

func (p *platformRecorder) reset(status int, body string) {
	p.mu.Lock()
	p.calls, p.status, p.body = nil, status, body
	p.mu.Unlock()
}

func (p *platformRecorder) all() []platformCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]platformCall(nil), p.calls...)
}

func (p *platformRecorder) writes() []platformCall {
	var out []platformCall
	for _, c := range p.all() {
		if c.Method != http.MethodGet {
			out = append(out, c)
		}
	}
	return out
}

type fakeAuthority struct {
	mu      sync.Mutex
	active  bool
	missing []string
	err     error
	calls   int
}

func (f *fakeAuthority) Authority(_ context.Context, _, _ string, _ []string) (Authority, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return Authority{Active: f.active, Missing: f.missing}, f.err
}

type fakeApprovals struct {
	mu        sync.Mutex
	requests  map[string]ApprovalRequestInput
	status    map[string]string
	cancelled []string
	err       error
}

func (f *fakeApprovals) RequestApproval(_ context.Context, in ApprovalRequestInput) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	id := fmt.Sprintf("apr_%d", len(f.requests)+1)
	f.requests[id] = in
	return id, nil
}

func (f *fakeApprovals) GetApproval(_ context.Context, _, id string) (GovernanceApproval, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	in, ok := f.requests[id]
	if !ok {
		return GovernanceApproval{}, errors.New("not found")
	}
	return GovernanceApproval{ID: id, Action: in.Action, TargetType: in.TargetType, TargetID: in.TargetID, TargetDetails: in.TargetDetails, RequesterID: in.RequesterID, Status: firstNonEmpty(f.status[id], "approved")}, nil
}

func (f *fakeApprovals) CancelApproval(_ context.Context, _, id, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelled = append(f.cancelled, id)
	return nil
}

type playbookHarness struct {
	h         *Handler
	store     *SQLStore
	rec       *routetest.Recorder
	exec      *PlaybookExecutor
	tl        *TriggerListener
	platform  *platformRecorder
	authority *fakeAuthority
	approvals *fakeApprovals
	vault     *connVault
	now       time.Time
}

func newPlaybookHarness(t *testing.T) *playbookHarness {
	t.Helper()
	svc, store, _, _, _, _, _ := newComplianceService(t)
	mektest.ApplySchema(t, store.db.SQL(), "compliance")
	vault := &connVault{}
	vault.set(mektest.Open(t, store.db.SQL(), "compliance", mektest.NewKeycore(t)))
	rec := &routetest.Recorder{}
	logger := log.New(io.Discard, "", 0)
	platform := &platformRecorder{}
	srv := httptest.NewServer(platform)
	t.Cleanup(srv.Close)
	urls := platformURLs{Keycore: srv.URL, Certs: srv.URL, Auth: srv.URL, Governance: srv.URL, Reporting: srv.URL, Posture: srv.URL}
	exec := NewPlaybookExecutor(store, urls, rec, vault, logger)
	exec.ops = svc
	authority := &fakeAuthority{active: true}
	approvals := &fakeApprovals{requests: map[string]ApprovalRequestInput{}, status: map[string]string{}}
	exec.authority, exec.approvals = authority, approvals
	h := NewHandler(svc, rec, logger, vault)
	h.dispatch = func(f func()) { f() }
	h.SetExecutor(exec)
	hs := &playbookHarness{h: h, store: store, rec: rec, exec: exec, platform: platform, authority: authority, approvals: approvals, vault: vault,
		now: time.Now().UTC()}
	tl := NewTriggerListener(store, exec, logger)
	tl.now = func() time.Time { return hs.now }
	tl.dispatch = func(f func()) { f() }
	h.triggers, hs.tl = tl, tl
	return hs
}

func (hs *playbookHarness) do(t *testing.T, method, path string, claims *pkgauth.Claims, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader = http.NoBody
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, r)
	if claims != nil {
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	}
	w := httptest.NewRecorder()
	hs.h.ServeHTTP(w, req)
	return w
}

// conn stores a sealed connection directly (the API refuses private
// addresses such as a test server's).
func (hs *playbookHarness) conn(t *testing.T, typ string, fields map[string]string) string {
	t.Helper()
	c := Connection{ID: newID("pbconn"), TenantID: "t1", Name: typ + " test", Type: typ, Fields: fields, Endpoint: "test"}
	if err := hs.vault.Seal(&c); err != nil {
		t.Fatal(err)
	}
	if _, err := hs.store.CreateConnection(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c.ID
}

// resetCooldown lets every playbook fire again.
func (hs *playbookHarness) resetCooldown(t *testing.T) {
	t.Helper()
	if _, err := hs.store.db.SQL().Exec(`UPDATE compliance_playbooks SET last_fired_ms=0`); err != nil {
		t.Fatal(err)
	}
}

func (hs *playbookHarness) event(tenant, result, target string, at time.Time, extra map[string]interface{}) []byte {
	m := map[string]interface{}{"tenant_id": tenant, "result": result, "target_id": target, "timestamp": at.Format(time.RFC3339Nano)}
	for k, v := range extra {
		m[k] = v
	}
	raw, _ := json.Marshal(m)
	return raw
}

func events(rec *routetest.Recorder, action string) []routetest.Recorded {
	var out []routetest.Recorded
	for _, e := range rec.Events() {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func lastEvent(t *testing.T, rec *routetest.Recorder, action string) routetest.Recorded {
	t.Helper()
	ev := events(rec, action)
	if len(ev) == 0 {
		t.Fatalf("no %s event", action)
	}
	return ev[len(ev)-1]
}

func wantRefused(t *testing.T, ev routetest.Recorded, reason string) {
	t.Helper()
	if ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != reason {
		t.Fatalf("%s: result=%s reason=%v, want refused %s (%v)", ev.Action, ev.Event.Result, ev.Event.Details["reason"], reason, ev.Event.Details)
	}
}

func playbookBody(trigger string, enabled bool, actions ...map[string]any) map[string]any {
	return map[string]any{"name": "pb " + trigger, "trigger": map[string]any{"type": trigger}, "enabled": enabled, "actions": actions}
}

func act(typ string, params map[string]string) map[string]any {
	return map[string]any{"type": typ, "parameters": params}
}

func createdID(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Data Playbook `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out.Data.ID
}

func runOf(t *testing.T, hs *playbookHarness, runID string) PlaybookRun {
	t.Helper()
	run, err := hs.store.GetPlaybookRun(context.Background(), "t1", runID)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func startedRun(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != http.StatusAccepted {
		t.Fatalf("run: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Data struct {
			RunID string `json:"run_id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out.Data.RunID
}

var rotate = act("rotate_key", map[string]string{"key_id": "k1"})

// Every playbook, run and connection route refuses an anonymous caller, a
// caller without the route permission and a caller naming another tenant,
// and audits each.
func TestPlaybookRoutesRefusalsAudited(t *testing.T) {
	hs := newPlaybookHarness(t)
	routetest.RefusalsAudited(t, hs.h.router, hs.rec)
}

// Before 2.4.0-beta the tenant came from the request body.
func TestPlaybookCreateTakesTenantFromToken(t *testing.T) {
	hs := newPlaybookHarness(t)
	body := playbookBody("canary_tripped", true, rotate)
	body["tenant_id"] = "victim"
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, body); w.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant create: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_created"), route.ReasonTenantMismatch)
	if pbs, _ := hs.store.ListPlaybooks(context.Background(), "victim"); len(pbs) != 0 {
		t.Fatal("playbook written into another tenant")
	}
}

// Saving an enabled playbook needs every action permission and a person.
func TestPlaybookSaveRequiresActionPermissions(t *testing.T) {
	hs := newPlaybookHarness(t)
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks", pbWriter, playbookBody("canary_tripped", true, rotate)); w.Code != http.StatusForbidden {
		t.Fatalf("writer without key.rotate: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_created"), reasonActionPermission)

	id := createdID(t, hs.do(t, http.MethodPost, "/compliance/playbooks", pbWriter, playbookBody("canary_tripped", false, rotate)))
	if pb, _ := hs.store.GetPlaybook(context.Background(), "t1", id); pb.AuthorizedBy != "" || pb.Enabled {
		t.Fatalf("disabled save by writer: %+v", pb)
	}
	if w := hs.do(t, http.MethodPut, "/compliance/playbooks/"+id, pbWriter, playbookBody("canary_tripped", true, rotate)); w.Code != http.StatusForbidden {
		t.Fatalf("writer enabling: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_updated"), reasonActionPermission)

	// An API client holds the permissions but is not a person.
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks", pbClient, playbookBody("canary_tripped", true, rotate)); w.Code != http.StatusForbidden {
		t.Fatalf("client enabling: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_created"), reasonUserRequired)

	if w := hs.do(t, http.MethodPut, "/compliance/playbooks/"+id, pbAdmin, playbookBody("canary_tripped", true, rotate)); w.Code != http.StatusOK {
		t.Fatalf("admin enabling: %d %s", w.Code, w.Body.String())
	}
	if pb, _ := hs.store.GetPlaybook(context.Background(), "t1", id); pb.AuthorizedBy != "u-admin" || !pb.Enabled {
		t.Fatalf("admin save: %+v", pb)
	}
	// Bad definitions are rejected, not stored.
	for name, body := range map[string]map[string]any{
		"custom without subject":    playbookBody(customTrigger, true, rotate),
		"custom on playbook events": {"name": "x", "enabled": true, "trigger": map[string]any{"type": customTrigger, "subject": "audit.compliance.playbook_triggered"}, "actions": []any{rotate}},
		"threshold without window":  {"name": "x", "enabled": true, "trigger": map[string]any{"type": "login_failed", "threshold": 5}, "actions": []any{rotate}},
		"unknown filter field":      {"name": "x", "enabled": true, "trigger": map[string]any{"type": "login_failed", "filters": []any{map[string]string{"field": "password", "op": "eq", "value": "x"}}}, "actions": []any{rotate}},
		"unknown template":          playbookBody("canary_tripped", true, act("rotate_key", map[string]string{"key_id": "{{secret.value}}"})),
		"email outside tenant form": playbookBody("canary_tripped", true, act("send_email", map[string]string{"to": "not an address", "subject": "x"})),
		"bad incident status":       playbookBody("incident_opened", true, act("set_incident_status", map[string]string{"incident_id": "i1", "status": "deleted"})),
		"connection of other type":  playbookBody("canary_tripped", true, act("send_slack", map[string]string{"connection_id": hs.conn(t, "teams", map[string]string{"webhook_url": "https://1.1.1.1/x"})})),
	} {
		if w := hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d %s", name, w.Code, w.Body.String())
		}
	}
}

// A manual run acts on the runner's authority and is audited per action.
func TestPlaybookRunRequiresActionPermissionsAndAuditsEachAction(t *testing.T) {
	hs := newPlaybookHarness(t)
	id := createdID(t, hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, playbookBody("canary_tripped", true, rotate)))
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/"+id+"/run", pbWriter, nil); w.Code != http.StatusForbidden {
		t.Fatalf("writer run: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_run_requested"), reasonActionPermission)
	if len(hs.platform.all()) != 0 {
		t.Fatal("refused run reached keycore")
	}
	runID := startedRun(t, hs.do(t, http.MethodPost, "/compliance/playbooks/"+id+"/run", pbAdmin, nil))
	calls := hs.platform.all()
	if len(calls) != 1 || calls[0].Path != "/keys/k1/rotate" || calls[0].Tenant != "t1" || calls[0].Correlation != runID {
		t.Fatalf("keycore calls = %+v", calls)
	}
	act := lastEvent(t, hs.rec, "playbook_action_executed")
	if act.Event.Result != route.ResultSuccess || act.Event.Details["action"] != "rotate_key" || act.Event.Details["target"] != "key_id=k1" || act.Event.ActorID != "u-admin" {
		t.Fatalf("playbook_action_executed: %+v", act.Event)
	}
	if done := lastEvent(t, hs.rec, "playbook_run_completed"); done.Event.Result != route.ResultSuccess || done.Event.Details["status"] != runCompleted {
		t.Fatalf("playbook_run_completed: %+v", done.Event)
	}
	if run := runOf(t, hs, runID); run.Status != runCompleted || run.Actor != "u-admin" || len(run.Results) != 1 || !run.Context.Supplied {
		t.Fatalf("run = %+v", run)
	}
}

// A platform call that opens an approval is pending, never done.
func TestPlaybookPendingApprovalIsNotSuccess(t *testing.T) {
	hs := newPlaybookHarness(t)
	hs.platform.reset(http.StatusAccepted, `{"status":"pending_approval"}`)
	id := createdID(t, hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, playbookBody("canary_tripped", true, rotate)))
	runID := startedRun(t, hs.do(t, http.MethodPost, "/compliance/playbooks/"+id+"/run", pbAdmin, nil))
	if a := lastEvent(t, hs.rec, "playbook_action_executed"); a.Event.Result != "pending" || a.Event.Details["outcome"] != outcomePendingApproval {
		t.Fatalf("pending action audited as %s", a.Event.Result)
	}
	if run := runOf(t, hs, runID); run.Status != runPendingApproval {
		t.Fatalf("run status %s", run.Status)
	}
}

// Every platform action calls the endpoint that exists, as the compliance
// service for the run's tenant; delegated actions name the person.
func TestPlaybookPlatformActionsCallRealEndpoints(t *testing.T) {
	hs := newPlaybookHarness(t)
	p := map[string]string{
		"key_id": "k1", "cert_id": "c1", "policy_id": "rp1", "user_id": "u9", "api_key_id": "ak1", "client_id": "cl1",
		"alert_id": "al1", "incident_id": "in1", "status": "investigating", "assigned_to": "u-oncall", "template_id": "evidence_pack",
		"to": "soc@example.com,role:admin", "subject": "canary",
	}
	want := map[string]string{
		"rotate_key": "POST /keys/k1/rotate", "disable_key": "POST /keys/k1/disable", "deactivate_key": "POST /keys/k1/deactivate",
		"activate_key": "POST /keys/k1/activate", "trigger_rotation_policy": "POST /rotation/policies/rp1/trigger",
		"renew_certificate": "POST /certs/c1/renew", "revoke_certificate": "POST /certs/c1/revoke",
		"disable_user": "POST /auth/delegated/users/u9/disable", "revoke_api_key": "POST /auth/delegated/api-keys/ak1/revoke",
		"revoke_client": "POST /auth/delegated/clients/cl1/revoke", "acknowledge_alert": "PUT /alerts/al1/acknowledge",
		"resolve_alert": "PUT /alerts/al1/resolve", "set_incident_status": "PUT /incidents/in1/status",
		"assign_incident": "PUT /incidents/in1/assign", "generate_report": "POST /reports/generate",
		"run_posture_scan": "POST /posture/scan", "send_email": "POST /governance/notify/email",
	}
	for _, spec := range playbookActions {
		w, ok := want[spec.Type]
		if !ok {
			continue
		}
		hs.platform.reset(0, "")
		outcome, err := hs.exec.executeAction(context.Background(), spec.Type, p, RunContext{TenantID: "t1", RunID: "pbrun_1", Actor: "u-admin", PlaybookID: "pb1"})
		calls := hs.platform.all()
		if err != nil || outcome != outcomeDone || len(calls) != 1 || calls[0].Method+" "+calls[0].Path != w || calls[0].Tenant != "t1" {
			t.Fatalf("%s: %s %v called %+v, want %s", spec.Type, outcome, err, calls, w)
		}
		if spec.Delegated && calls[0].Body["on_behalf_of"] != "u-admin" {
			t.Fatalf("%s: delegation %v", spec.Type, calls[0].Body)
		}
		delete(want, spec.Type)
	}
	if len(want) != 0 {
		t.Fatalf("not in the catalogue: %v", want)
	}
	hs.platform.reset(http.StatusNotFound, `{"error":{"code":"not_found","message":"key not found"}}`)
	if _, err := hs.exec.executeAction(context.Background(), "rotate_key", map[string]string{"key_id": "gone"}, RunContext{TenantID: "t1"}); err == nil || !strings.Contains(err.Error(), "not_found") {
		t.Fatalf("missing key: %v", err)
	}
}

// Keycore refuses anonymous callers, so platform actions carry the
// compliance service token; outbound notifications never do.
func TestPlaybookSendsServiceTokenOnlyToPlatformServices(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "svc-jwt", "expires_at": "2099-01-01T00:00:00Z"})
	}))
	defer auth.Close()
	t.Setenv("AUTH_URL", auth.URL)
	t.Setenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET", "3f9c2a7d5e1b8c4f6a0d2e9b7c5a3f1e8d6b4c2a0f9e7d5c3b1a8f6e4d2c0b9a")
	servicetoken.SetDefault(servicetoken.FromEnv("kms-compliance"))
	t.Cleanup(func() { servicetoken.SetDefault(nil) })

	hs := newPlaybookHarness(t)
	if _, err := hs.exec.executeAction(context.Background(), "rotate_key", map[string]string{"key_id": "k1"}, RunContext{TenantID: "t1"}); err != nil {
		t.Fatal(err)
	}
	if got := hs.platform.all()[0].Auth; got != "Bearer svc-jwt" {
		t.Fatalf("keycore call carried %q", got)
	}
	var mu sync.Mutex
	seen := map[string]string{}
	ext := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
	}))
	defer ext.Close()
	hs.exec.outbound = ext.Client()
	rc := RunContext{TenantID: "t1"}
	for typ, fields := range map[string]map[string]string{
		"send_webhook":               {"url": ext.URL + "/hook"},
		"create_servicenow_incident": {"instance_url": ext.URL},
		"create_jira_ticket":         {"base_url": ext.URL, "api_token": "dG9rZW4="},
	} {
		connID := hs.conn(t, actionConnectionType[typ], fields)
		p := map[string]string{"connection_id": connID, "project": "SEC", "summary": "x", "short_description": "x"}
		if _, err := hs.exec.executeAction(context.Background(), typ, p, rc); err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if seen["/hook"] != "" || seen["/api/now/table/incident"] != "" || seen["/rest/api/2/issue"] != "Basic dG9rZW4=" {
		t.Fatalf("outbound auth: %v", seen)
	}
}

// A connection can't point at a platform service or a private address: the
// executor's mTLS identity would be presented to it (SSRF).
func TestPlaybookOutboundCannotReachPlatformOrPrivateHosts(t *testing.T) {
	hs := newPlaybookHarness(t)
	for _, u := range []string{"https://keycore:8010/keys/k1/destroy", "http://1.1.1.1/hook", "https://127.0.0.1/hook", "https://169.254.169.254/latest"} {
		body := map[string]any{"name": "exfil", "type": "webhook", "fields": map[string]string{"url": u}}
		if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections", pbAdmin, body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d", u, w.Code)
		}
		wantRefused(t, lastEvent(t, hs.rec, "connection_created"), reasonURLBlocked)
	}
	if _, err := hs.exec.outboundCall(context.Background(), http.MethodPost, "https://keycore:8010/keys/k1/destroy", map[string]string{}, nil); err == nil {
		t.Fatal("outbound call reached a platform host")
	}
	ext := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ext.Close()
	if _, err := hs.exec.outboundCall(context.Background(), http.MethodPost, ext.URL+"/services/T0/B0/sekret", map[string]string{}, nil); err == nil || strings.Contains(err.Error(), "sekret") {
		t.Fatalf("private address: %v", err)
	}
}

// Connection credentials are sealed at rest, never returned, kept with the
// marker on update, and a connection in use can't be deleted.
func TestPlaybookConnectionsSealedAndNeverReturned(t *testing.T) {
	hs := newPlaybookHarness(t)
	secret := "https://1.1.1.1/services/T0/B0/sekret"
	w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections", pbAdmin, map[string]any{"name": "soc", "type": "slack", "fields": map[string]string{"webhook_url": secret}})
	if w.Code != http.StatusCreated {
		t.Fatalf("create connection: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Data Connection `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	id := out.Data.ID
	for _, resp := range []*httptest.ResponseRecorder{w, hs.do(t, http.MethodGet, "/compliance/playbooks/connections", pbAdmin, nil)} {
		if strings.Contains(resp.Body.String(), "sekret") || !strings.Contains(resp.Body.String(), "1.1.1.1") {
			t.Fatalf("connection response: %s", resp.Body.String())
		}
	}
	var dump bytes.Buffer
	rows, _ := hs.store.db.SQL().Query(`SELECT name, type, endpoint, fields_set, creds_ciphertext FROM compliance_playbook_connections`)
	for rows.Next() {
		var a, b, c, d string
		var e []byte
		_ = rows.Scan(&a, &b, &c, &d, &e)
		dump.WriteString(a + b + c + d + string(e))
	}
	_ = rows.Close()
	if strings.Contains(dump.String(), "sekret") {
		t.Fatal("credential stored in plaintext")
	}
	for _, e := range hs.rec.Events() {
		if raw, _ := json.Marshal(e.Event); strings.Contains(string(raw), "sekret") {
			t.Fatalf("secret in audit event %s", e.Action)
		}
	}
	if w := hs.do(t, http.MethodPut, "/compliance/playbooks/connections/"+id, pbAdmin, map[string]any{"name": "soc2", "type": "slack", "fields": map[string]string{"webhook_url": keepField}}); w.Code != http.StatusOK {
		t.Fatalf("update with marker: %d %s", w.Code, w.Body.String())
	}
	stored, _ := hs.store.GetConnection(context.Background(), "t1", id)
	if opened, err := hs.vault.Open(stored); err != nil || opened.Fields["webhook_url"] != secret || opened.Name != "soc2" {
		t.Fatalf("stored connection: %+v %v", opened, err)
	}
	createdID(t, hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, playbookBody("canary_tripped", true, act("send_slack", map[string]string{"connection_id": id}))))
	if w := hs.do(t, http.MethodDelete, "/compliance/playbooks/connections/"+id, pbAdmin, nil); w.Code != http.StatusConflict {
		t.Fatalf("delete in use: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_deleted"), "connection_in_use")

	// The test call is real: it reaches the endpoint.
	hit := make(chan string, 1)
	ext := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { hit <- r.URL.Path }))
	defer ext.Close()
	hs.exec.outbound = ext.Client()
	testID := hs.conn(t, "slack", map[string]string{"webhook_url": ext.URL + "/services/test"})
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections/"+testID+"/test", pbAdmin, nil); w.Code != http.StatusOK || <-hit != "/services/test" {
		t.Fatalf("connection test: %d %s", w.Code, w.Body.String())
	}
	if ev := lastEvent(t, hs.rec, "connection_tested"); ev.Event.Result != route.ResultSuccess {
		t.Fatalf("connection_tested: %+v", ev.Event)
	}
}

// Credentials earlier releases kept inline in actions move into sealed
// connections, recorded in the exposure register; the API hides them until
// then.
func TestPlaybookInlineSecretsMigrated(t *testing.T) {
	hs := newPlaybookHarness(t)
	ctx := context.Background()
	secret := "https://1.1.1.1/services/T0/B0/legacy"
	if _, err := hs.store.CreatePlaybook(ctx, Playbook{ID: "pb-old", TenantID: "t1", Name: "old", Category: "incident_response", Enabled: true, AuthorizedBy: "u-admin",
		Trigger: PlaybookTrigger{Type: "canary_tripped"}, Actions: []PlaybookAction{{Type: "send_slack", Parameters: map[string]string{"webhook_url": secret, "message": "hi"}}}}); err != nil {
		t.Fatal(err)
	}
	if w := hs.do(t, http.MethodGet, "/compliance/playbooks/pb-old", pbAdmin, nil); strings.Contains(w.Body.String(), "legacy") {
		t.Fatalf("inline secret returned: %s", w.Body.String())
	}
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/pb-old/run", pbAdmin, nil); w.Code != http.StatusConflict {
		t.Fatalf("run before migration: %d", w.Code)
	}
	var emitted []map[string]interface{}
	n, err := hs.h.svc.migrateInlineSecrets(ctx, hs.vault, func(context.Context) bool { return true }, func(_ string, d map[string]interface{}, _ string) { emitted = append(emitted, d) })
	if err != nil || n != 1 || len(emitted) != 1 {
		t.Fatalf("migrate: %d %v %v", n, err, emitted)
	}
	pb, _ := hs.store.GetPlaybook(ctx, "t1", "pb-old")
	connID := pb.Actions[0].Parameters["connection_id"]
	if connID == "" || pb.Actions[0].Parameters["webhook_url"] != "" || pb.Actions[0].Parameters["message"] != "hi" || pb.AuthorizedBy != "u-admin" {
		t.Fatalf("migrated action: %+v", pb.Actions[0])
	}
	stored, _ := hs.store.GetConnection(ctx, "t1", connID)
	if opened, err := hs.vault.Open(stored); err != nil || opened.Fields["webhook_url"] != secret {
		t.Fatalf("migrated connection: %v", err)
	}
	k, _ := hs.vault.current()
	if ex, err := k.Exposures(ctx, "t1", true); err != nil || len(ex) != 1 || ex[0].ItemID != connID {
		t.Fatalf("exposure register: %+v %v", ex, err)
	}
	if n, _ := hs.h.svc.migrateInlineSecrets(ctx, hs.vault, func(context.Context) bool { return true }, func(string, map[string]interface{}, string) {}); n != 0 {
		t.Fatal("migration is not idempotent")
	}
	if n, _ := hs.h.svc.migrateInlineSecrets(ctx, hs.vault, func(context.Context) bool { return false }, func(string, map[string]interface{}, string) {}); n != 0 {
		t.Fatal("a member migrated")
	}
}

// Actions that never worked are gone and refused, audited, at run time.
func TestPlaybookRemovedActionsRefused(t *testing.T) {
	hs := newPlaybookHarness(t)
	for _, a := range []string{"destroy_key", "notify_soc", "quarantine_tenant"} {
		if _, ok := actionByType[a]; ok {
			t.Fatalf("%s is in the catalogue", a)
		}
		var removed actionRemovedError
		if _, err := hs.exec.executeAction(context.Background(), a, map[string]string{}, RunContext{TenantID: "t1"}); !errors.As(err, &removed) {
			t.Fatalf("%s: %v", a, err)
		}
	}
	ctx := context.Background()
	stored, err := hs.store.CreatePlaybook(ctx, Playbook{ID: "pb-legacy", TenantID: "t1", Name: "legacy", Category: "incident_response", Enabled: true, AuthorizedBy: "u-admin",
		Trigger: PlaybookTrigger{Type: "canary_tripped"},
		Actions: []PlaybookAction{{Type: "suspend_key", Parameters: map[string]string{"key_id": "k1"}}, {Type: "destroy_key", Parameters: map[string]string{"key_id": "k1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if stored.Actions[0].Type != "disable_key" {
		t.Fatalf("legacy suspend_key read as %s", stored.Actions[0].Type)
	}
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/pb-legacy/run", pbAdmin, nil); w.Code != http.StatusConflict {
		t.Fatalf("run with removed action: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_run_requested"), reasonPlaybookInvalid)
	run, _ := hs.exec.Start(ctx, stored, runSource{Trigger: "canary_tripped", Actor: "u-admin"})
	if got := hs.exec.Execute(ctx, stored, run); got.Status != runPartialFailure {
		t.Fatalf("run status %s", got.Status)
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_action_executed"), reasonActionRemoved)
}

func TestPlaybookCatalogServedFromBackend(t *testing.T) {
	hs := newPlaybookHarness(t)
	w := hs.do(t, http.MethodGet, "/compliance/playbooks/catalog", pbWriter, nil)
	var out struct {
		Data struct {
			Triggers    []TriggerSpec    `json:"triggers"`
			Actions     []ActionSpec     `json:"actions"`
			Connections []ConnectionSpec `json:"connection_types"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != http.StatusOK || len(out.Data.Triggers) != len(playbookTriggers) || len(out.Data.Actions) != len(playbookActions) || len(out.Data.Connections) != len(connectionTypes) {
		t.Fatalf("catalog: %d %s", w.Code, w.Body.String())
	}
	if ev := lastEvent(t, hs.rec, "playbook_catalog_read"); ev.Event.Result != route.ResultSuccess {
		t.Fatalf("catalog event %+v", ev.Event)
	}
}

// Parameters template from the event; conditions skip steps; a template
// that resolves empty fails the step rather than calling with nothing.
func TestPlaybookTemplatesAndConditions(t *testing.T) {
	hs := newPlaybookHarness(t)
	body := playbookBody("canary_tripped", true,
		map[string]any{"type": "rotate_key", "parameters": map[string]string{"key_id": "{{event.target_id}}"}},
		map[string]any{"type": "disable_key", "parameters": map[string]string{"key_id": "{{event.details.key_id}}"}, "condition": []map[string]string{{"field": "severity", "op": "eq", "value": "critical"}}},
		map[string]any{"type": "activate_key", "parameters": map[string]string{"key_id": "{{event.details.missing}}"}},
	)
	id := createdID(t, hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, body))
	runID := startedRun(t, hs.do(t, http.MethodPost, "/compliance/playbooks/"+id+"/run", pbAdmin, map[string]any{"event": map[string]any{"target_id": "key-9", "severity": "high", "details": map[string]string{"key_id": "key-7"}}}))
	calls := hs.platform.writes()
	if len(calls) != 1 || calls[0].Path != "/keys/key-9/rotate" {
		t.Fatalf("templated calls: %+v", calls)
	}
	run := runOf(t, hs, runID)
	if len(run.Results) != 3 || run.Results[1].Status != resultSkipped || run.Results[2].Status != resultFailed || !strings.Contains(run.Results[2].Error, "resolved empty") {
		t.Fatalf("results: %+v", run.Results)
	}
	if ev := events(hs.rec, "playbook_action_executed"); ev[1].Event.Result != "skipped" {
		t.Fatalf("skipped step audited as %s", ev[1].Event.Result)
	}
}

// A gated action pauses the run for a governance approval bound to the
// resolved action; the run resumes only on a verified approval, with the
// authorizing person's authority re-checked.
func TestPlaybookApprovalGate(t *testing.T) {
	hs := newPlaybookHarness(t)
	ctx := context.Background()
	body := playbookBody("canary_tripped", true, act("deactivate_key", map[string]string{"key_id": "{{event.target_id}}"}), act("create_audit_event", map[string]string{"message": "done"}))
	id := createdID(t, hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, body))
	start := func() PlaybookRun {
		hs.resetCooldown(t)
		hs.tl.handle(ctx, "audit.keycore.canary_tripped", hs.event("t1", "success", "key-5", hs.now, nil))
		runID, _ := lastEvent(t, hs.rec, "playbook_triggered").Event.Details["run_id"].(string)
		return runOf(t, hs, runID)
	}
	decide := func(run PlaybookRun, subject string) {
		raw, _ := json.Marshal(map[string]interface{}{"tenant_id": "t1", "result": "success", "timestamp": hs.now.Format(time.RFC3339Nano), "data": map[string]string{"request_id": run.ApprovalRequestID}})
		hs.tl.handle(ctx, subject, raw)
	}

	run := start()
	if run.Status != runAwaitingApproval || run.ApprovalRequestID == "" || len(hs.platform.writes()) != 0 {
		t.Fatalf("gated run: %+v calls=%v", run, hs.platform.writes())
	}
	req := hs.approvals.requests[run.ApprovalRequestID]
	if req.Action != "playbook.deactivate_key" || req.RequesterID != "u-admin" || req.TargetID != run.ID+"#0" || req.TargetDetails["payload_hash"] == "" {
		t.Fatalf("approval request: %+v", req)
	}
	if ev := lastEvent(t, hs.rec, "playbook_approval_requested"); ev.Event.Details["approval_request_id"] != run.ApprovalRequestID {
		t.Fatalf("approval_requested: %+v", ev.Event)
	}
	decide(run, "audit.governance.quorum_reached")
	if calls := hs.platform.writes(); len(calls) != 1 || calls[0].Path != "/keys/key-5/deactivate" {
		t.Fatalf("after approval: %+v", calls)
	}
	if got := runOf(t, hs, run.ID); got.Status != runCompleted || len(got.Results) != 3 {
		t.Fatalf("resumed run: %+v", got)
	}
	lastEvent(t, hs.rec, "playbook_approval_granted")

	// Denied and expired requests end the run without acting.
	hs.platform.reset(0, "")
	run = start()
	decide(run, "audit.governance.quorum_denied")
	if got := runOf(t, hs, run.ID); got.Status != runApprovalDenied || len(hs.platform.writes()) != 0 {
		t.Fatalf("denied: %s %v", got.Status, hs.platform.writes())
	}
	run = start()
	decide(run, "audit.governance.request_expired")
	if got := runOf(t, hs, run.ID); got.Status != runApprovalExpired {
		t.Fatalf("expired: %s", got.Status)
	}

	// An event claiming approval is checked against governance.
	run = start()
	hs.approvals.status[run.ApprovalRequestID] = "pending"
	decide(run, "audit.governance.quorum_reached")
	if got := runOf(t, hs, run.ID); got.Status != runFailed || len(hs.platform.writes()) != 0 {
		t.Fatalf("unapproved resume: %s", got.Status)
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_action_executed"), "approval_mismatch")

	// Editing the action while it waits voids the approval.
	run = start()
	edited := playbookBody("canary_tripped", true, act("deactivate_key", map[string]string{"key_id": "other-key"}), act("create_audit_event", nil))
	if w := hs.do(t, http.MethodPut, "/compliance/playbooks/"+id, pbAdmin, edited); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	decide(run, "audit.governance.quorum_reached")
	wantRefused(t, lastEvent(t, hs.rec, "playbook_action_executed"), "definition_changed")

	// The authorizing person must still hold the permissions.
	if w := hs.do(t, http.MethodPut, "/compliance/playbooks/"+id, pbAdmin, body); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	run = start()
	hs.authority.missing = []string{"key.deactivate"}
	decide(run, "audit.governance.quorum_reached")
	wantRefused(t, lastEvent(t, hs.rec, "playbook_action_executed"), reasonAuthorityRevoked)
	if len(hs.platform.writes()) != 0 {
		t.Fatal("acted without authority")
	}
}

// Automatic runs: catalogue and custom triggers, filters, thresholds per
// group, cooldown, stale events, authority, platform events, cluster role,
// and no chains of playbooks.
func TestPlaybookTriggerListener(t *testing.T) {
	hs := newPlaybookHarness(t)
	ctx := context.Background()
	mk := func(id, tenant, authorizedBy string, trig PlaybookTrigger) {
		if _, err := hs.store.CreatePlaybook(ctx, Playbook{ID: id, TenantID: tenant, Name: id, Category: "incident_response", Enabled: true, AuthorizedBy: authorizedBy,
			Trigger: trig, Actions: []PlaybookAction{{Type: "create_audit_event", Parameters: map[string]string{}}}}); err != nil {
			t.Fatal(err)
		}
		hs.tl.Invalidate(tenant)
	}
	triggered := func(pb string) []routetest.Recorded {
		var out []routetest.Recorded
		for _, e := range events(hs.rec, "playbook_triggered") {
			if e.Event.TargetID == pb {
				out = append(out, e)
			}
		}
		return out
	}
	mk("pb-rotated", "t1", "u-admin", PlaybookTrigger{Type: "key_rotated"})
	hs.tl.handle(ctx, "audit.key.rotate", hs.event("t1", "success", "k9", hs.now, nil))
	if ev := triggered("pb-rotated"); len(ev) != 1 || ev[0].Event.Result != route.ResultSuccess || ev[0].Event.Details["run_id"] == "" {
		t.Fatalf("first trigger: %+v", ev)
	}
	hs.tl.handle(ctx, "audit.key.rotate", hs.event("t1", "success", "k9", hs.now, nil))
	wantRefused(t, triggered("pb-rotated")[1], reasonCooldown)
	hs.now = hs.now.Add(2 * triggerCooldown)
	hs.tl.handle(ctx, "audit.key.rotate", hs.event("t1", "refused", "k9", hs.now, nil))
	hs.tl.handle(ctx, "audit.key.rotate", hs.event("t1", "success", "k9", hs.now.Add(-time.Hour), nil))
	if ev := triggered("pb-rotated"); len(ev) != 3 {
		t.Fatalf("refused rotate fired, or stale not refused: %d", len(ev))
	} else {
		wantRefused(t, ev[2], reasonStaleEvent)
	}

	// Custom subject with a filter.
	mk("pb-custom", "t1", "u-admin", PlaybookTrigger{Type: customTrigger, Subject: "audit.cert.*", Filters: []EventFilter{{Field: "details.issuer", Op: "eq", Value: "corp-ca"}}})
	hs.tl.handle(ctx, "audit.cert.issued", hs.event("t1", "success", "c1", hs.now, map[string]interface{}{"details": map[string]string{"issuer": "other"}}))
	hs.tl.handle(ctx, "audit.cert.issued", hs.event("t1", "success", "c1", hs.now, map[string]interface{}{"details": map[string]string{"issuer": "corp-ca"}}))
	if ev := triggered("pb-custom"); len(ev) != 1 || ev[0].Event.Result != route.ResultSuccess {
		t.Fatalf("custom trigger: %+v", ev)
	}

	// Threshold per actor within a window.
	mk("pb-spike", "t1", "u-admin", PlaybookTrigger{Type: "login_failed", Threshold: 3, WindowSeconds: 60, GroupBy: "actor_id"})
	for i, actor := range []string{"mallory", "mallory", "alice", "mallory"} {
		hs.tl.handle(ctx, "audit.auth.login_failed", hs.event("t1", "failure", "", hs.now.Add(time.Duration(i)*time.Second), map[string]interface{}{"actor_id": actor}))
	}
	if ev := triggered("pb-spike"); len(ev) != 1 {
		t.Fatalf("threshold fired %d times", len(ev))
	}

	// Authority: revoked or unverifiable, the run doesn't start.
	mk("pb-canary", "t1", "u-admin", PlaybookTrigger{Type: "canary_tripped"})
	hs.authority.missing = []string{"x"}
	hs.tl.handle(ctx, "audit.keycore.canary_tripped", hs.event("t1", "success", "k1", hs.now, nil))
	wantRefused(t, triggered("pb-canary")[0], reasonAuthorityRevoked)
	hs.authority.missing, hs.authority.err = nil, errors.New("auth unreachable")
	hs.resetCooldown(t)
	hs.tl.handle(ctx, "audit.keycore.canary_tripped", hs.event("t1", "success", "k1", hs.now, nil))
	wantRefused(t, triggered("pb-canary")[1], reasonAuthorityUnknown)
	hs.authority.err = nil

	mk("pb-unauth", "t1", "", PlaybookTrigger{Type: "account_locked"})
	hs.tl.handle(ctx, "audit.auth.account_locked", hs.event("t1", "success", "u1", hs.now, nil))
	wantRefused(t, triggered("pb-unauth")[0], reasonNotAuthorized)

	// Watchdog incidents carry no tenant: the platform tenant's playbooks fire.
	mk("pb-health", "root", "u-root", PlaybookTrigger{Type: "service_health_degraded"})
	hs.tl.handle(ctx, "audit.health.incident", []byte(`{"result":"warning","target_id":"keycore","timestamp":"`+hs.now.Format(time.RFC3339Nano)+`"}`))
	if ev := triggered("pb-health"); len(ev) != 1 || ev[0].Event.TenantID != "root" {
		t.Fatalf("health incident: %+v", ev)
	}

	// Incidents link the run.
	mk("pb-incident", "t1", "u-admin", PlaybookTrigger{Type: "incident_opened"})
	hs.tl.handle(ctx, "audit.reporting.incident_opened", hs.event("t1", "success", "inc_1", hs.now, map[string]interface{}{"target_type": "incident"}))
	if w := hs.do(t, http.MethodGet, "/compliance/playbook-runs?incident_id=inc_1", pbAdmin, nil); !strings.Contains(w.Body.String(), "pb-incident") {
		t.Fatalf("runs by incident: %s", w.Body.String())
	}

	// No chains, no own events, no members.
	before := len(hs.rec.Events())
	hs.now = hs.now.Add(2 * triggerCooldown)
	for subject, extra := range map[string]map[string]interface{}{
		"audit.key.rotate":                    {"actor_id": "kms-compliance"},
		"audit.cert.revoked":                  {"correlation_id": "pbrun_123"},
		"audit.reporting.alert_created":       {"details": map[string]string{"source_actor_id": "kms-compliance"}},
		"audit.compliance.playbook_triggered": {},
		"audit.keycore.key_rotated":           {},
	} {
		hs.tl.handle(ctx, subject, hs.event("t1", "success", "k1", hs.now, extra))
	}
	clusterstate.SetDefault(clusterstate.Static(clusterstate.State{NodeID: "n2", Role: clusterstate.RoleFollower, PrimaryURL: "https://primary:8443", ForwardCredential: "cred"}))
	t.Cleanup(func() { clusterstate.SetDefault(nil) })
	hs.tl.handle(ctx, "audit.key.rotate", hs.event("t1", "success", "k9", hs.now, nil))
	if len(hs.rec.Events()) != before {
		t.Fatalf("fired: %v", hs.rec.Events()[before:])
	}
}

// Cancel stops a running or paused run; retry resumes from the first step
// that did not complete, on the caller's authority.
func TestPlaybookCancelAndRetry(t *testing.T) {
	hs := newPlaybookHarness(t)
	ctx := context.Background()

	// A paused run is cancelled at once and its approval withdrawn.
	gatedID := createdID(t, hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, playbookBody("canary_tripped", true, act("revoke_certificate", map[string]string{"cert_id": "c1"}))))
	runID := startedRun(t, hs.do(t, http.MethodPost, "/compliance/playbooks/"+gatedID+"/run", pbAdmin, nil))
	if w := hs.do(t, http.MethodPost, "/compliance/playbook-runs/"+runID+"/cancel", pbAdmin, nil); w.Code != http.StatusOK {
		t.Fatalf("cancel paused: %d %s", w.Code, w.Body.String())
	}
	if got := runOf(t, hs, runID); got.Status != runCancelled || len(hs.approvals.cancelled) != 1 {
		t.Fatalf("cancelled paused run: %s %v", got.Status, hs.approvals.cancelled)
	}
	if w := hs.do(t, http.MethodPost, "/compliance/playbook-runs/"+runID+"/cancel", pbAdmin, nil); w.Code != http.StatusConflict {
		t.Fatalf("cancel twice: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_run_cancelled"), reasonRunNotCancellable)

	// A running run stops at its next step.
	slowID := createdID(t, hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, playbookBody("canary_tripped", true, map[string]any{"type": "rotate_key", "delay_seconds": 30, "parameters": map[string]string{"key_id": "k1"}})))
	hs.h.dispatch = func(f func()) { go f() }
	runID = startedRun(t, hs.do(t, http.MethodPost, "/compliance/playbooks/"+slowID+"/run", pbAdmin, nil))
	deadline := time.Now().Add(2 * time.Second)
	for {
		hs.exec.mu.Lock()
		_, running := hs.exec.running[runID]
		hs.exec.mu.Unlock()
		if running || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if w := hs.do(t, http.MethodPost, "/compliance/playbook-runs/"+runID+"/cancel", pbAdmin, nil); w.Code != http.StatusOK {
		t.Fatalf("cancel running: %d %s", w.Code, w.Body.String())
	}
	for time.Now().Before(deadline.Add(2 * time.Second)) {
		if runOf(t, hs, runID).Status == runCancelled {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := runOf(t, hs, runID); got.Status != runCancelled || len(hs.platform.writes()) != 0 {
		t.Fatalf("cancelled running run: %s", got.Status)
	}
	hs.h.dispatch = func(f func()) { f() }

	// Retry from the failed step.
	hs.platform.reset(http.StatusInternalServerError, `{"error":{"code":"hsm_unavailable","message":"down"}}`)
	id := createdID(t, hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, playbookBody("canary_tripped", true, act("create_audit_event", nil), rotate)))
	runID = startedRun(t, hs.do(t, http.MethodPost, "/compliance/playbooks/"+id+"/run", pbAdmin, nil))
	if got := runOf(t, hs, runID); got.Status != runPartialFailure {
		t.Fatalf("first run: %s", got.Status)
	}
	hs.platform.reset(0, "")
	if w := hs.do(t, http.MethodPost, "/compliance/playbook-runs/"+runID+"/retry", pbWriter, nil); w.Code != http.StatusForbidden {
		t.Fatalf("retry without permission: %d", w.Code)
	}
	retryID := startedRun(t, hs.do(t, http.MethodPost, "/compliance/playbook-runs/"+runID+"/retry", pbAdmin, nil))
	got := runOf(t, hs, retryID)
	if got.RetryOf != runID || got.TriggerEvent != "retry" || got.Status != runCompleted || len(got.Results) != 1 || got.Results[0].Type != "rotate_key" {
		t.Fatalf("retry run: %+v", got)
	}
	if ev := lastEvent(t, hs.rec, "playbook_run_retried"); ev.Event.Details["resume_from"] != 2 {
		t.Fatalf("retry event: %+v", ev.Event.Details)
	}
	if w := hs.do(t, http.MethodPost, "/compliance/playbook-runs/"+retryID+"/retry", pbAdmin, nil); w.Code != http.StatusConflict {
		t.Fatalf("retry of a completed run: %d", w.Code)
	}
	_ = ctx
}

// A dry run resolves every step and reads each target from its owning
// service; it changes nothing.
func TestPlaybookDryRun(t *testing.T) {
	hs := newPlaybookHarness(t)
	id := createdID(t, hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, playbookBody("canary_tripped", true,
		act("rotate_key", map[string]string{"key_id": "{{event.target_id}}"}),
		map[string]any{"type": "resolve_alert", "parameters": map[string]string{"alert_id": "al1"}, "condition": []map[string]string{{"field": "severity", "op": "eq", "value": "critical"}}},
	)))
	hs.platform.reset(http.StatusNotFound, `{"error":{"code":"not_found","message":"no such key"}}`)
	w := hs.do(t, http.MethodPost, "/compliance/playbooks/"+id+"/dry-run", pbWriter, map[string]any{"event": map[string]any{"target_id": "key-3", "severity": "high"}})
	var out struct {
		Data struct {
			Steps []DryRunStep `json:"steps"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	s := out.Data.Steps
	if w.Code != http.StatusOK || len(s) != 2 || s[0].Parameters["key_id"] != "key-3" || s[0].HasPermission || !strings.HasPrefix(s[0].TargetCheck, "not found") || s[1].WouldRun {
		t.Fatalf("dry run: %d %s", w.Code, w.Body.String())
	}
	if len(hs.platform.writes()) != 0 {
		t.Fatalf("dry run wrote: %+v", hs.platform.writes())
	}
	lastEvent(t, hs.rec, "playbook_dry_run")
}

// Every trigger subject is emitted by a service. The table names where; it
// fails when an emitter is renamed or removed, and a new catalogue subject
// needs an entry.
func TestTriggerSubjectsAreEmitted(t *testing.T) {
	emitters := map[string][2]string{
		"audit.reporting.alert_created":             {"services/reporting/service.go", `Emit(ctx, "alert_created"`},
		"audit.reporting.incident_opened":           {"services/reporting/service.go", `Emit(ctx, "incident_opened"`},
		"audit.keycore.canary_tripped":              {"services/keycore/threat_detection.go", `"audit.keycore.canary_tripped"`},
		"audit.keycore.threat_signal_raised":        {"services/keycore/threat_detection.go", `"audit.keycore.threat_signal_raised"`},
		"audit.posture.threat_finding_raised":       {"services/posture/threat_findings.go", `"audit.posture.threat_finding_raised"`},
		"audit.security.sustained_risk_detected":    {"services/audit/sustained_risk.go", `"audit.security.sustained_risk_detected"`},
		"audit.key.compromise_detected":             {"services/keycore/enterprise_audit_service.go", `"audit.key.compromise_detected"`},
		"audit.audit.chain_broken":                  {"services/audit/service.go", `s.publisher.Publish(ctx, evt.Action, payload)`},
		"audit.discovery.secret_exposed":            {"services/discovery/service.go", `Emit(ctx, "secret_exposed"`},
		"audit.secrets.access_rule_created":         {"services/secrets/handler.go", `Action: "access_rule_created"`},
		"audit.secrets.access_rule_deleted":         {"services/secrets/handler.go", `Action: "access_rule_deleted"`},
		"audit.secrets.destroyed":                   {"services/secrets/handler.go", `Action: "destroyed"`},
		"audit.secrets.settings_updated":            {"services/secrets/handler.go", `Action: "settings_updated"`},
		"audit.secrets.version_cap_set":             {"services/secrets/handler.go", `Action: "version_cap_set"`},
		"audit.secrets.version_cap_deleted":         {"services/secrets/handler.go", `Action: "version_cap_deleted"`},
		"audit.secrets.retention_purged":            {"services/secrets/retention.go", `Emit(emitCtx, "retention_purged"`},
		"audit.key.create":                          {"services/keycore/keycore.go", `"audit.key.create"`},
		"audit.key.rotate":                          {"services/keycore/keycore.go", `"audit.key.rotate"`},
		"audit.key.destroyed":                       {"services/keycore/keycore.go", `"audit.key.destroyed"`},
		"audit.key.export":                          {"services/keycore/keycore.go", `"audit.key.export"`},
		"audit.key.access_refused":                  {"services/keycore/access_control.go", `"audit.key.access_refused"`},
		"audit.key.request_replay_detected":         {"services/keycore/handler.go", `"audit.key.request_replay_detected"`},
		"audit.key.hsm_refused":                     {"services/keycore/hsm.go", `"audit.key.hsm_refused"`},
		"audit.key.crypto_policy_refused":           {"services/keycore/agility_enforce.go", `"audit.key.crypto_policy_refused"`},
		"audit.key.caraf_decision_recorded":         {"services/keycore/handler_caraf.go", `Action: "caraf_decision_recorded"`},
		"audit.key.agility_policy_rule_created":     {"services/keycore/handler_agility.go", `Action: "agility_policy_rule_created"`},
		"audit.key.agility_policy_rule_updated":     {"services/keycore/handler_agility.go", `Action: "agility_policy_rule_updated"`},
		"audit.key.agility_policy_rule_deleted":     {"services/keycore/handler_agility.go", `Action: "agility_policy_rule_deleted"`},
		"audit.cert.revoked":                        {"services/certs/service.go", `"audit.cert.revoked"`},
		"audit.cert.renewal_window_missed":          {"services/certs/service_renewal.go", `"audit.cert.renewal_window_missed"`},
		"audit.cert.mass_renewal_risk_detected":     {"services/certs/service_renewal.go", `"audit.cert.mass_renewal_risk_detected"`},
		"audit.cert.crl_generation_failed":          {"services/certs/service.go", `"audit.cert.crl_generation_failed"`},
		"audit.auth.login_failed":                   {"services/auth/handler.go", `"audit.auth.login_failed"`},
		"audit.auth.account_locked":                 {"services/auth/handler.go", `"audit.auth.account_locked"`},
		"audit.auth.dpop_replay_detected":           {"services/auth/handler.go", `"audit.auth.dpop_replay_detected"`},
		"audit.workload.svid_issued":                {"services/workload/handler.go", `Action: "svid_issued"`},
		"audit.workload.settings_updated":           {"services/workload/handler.go", `Action: "settings_updated"`},
		"audit.workload.federation_bundle_upserted": {"services/workload/handler.go", `Action: "federation_bundle_upserted"`},
		"audit.workload.federation_bundle_deleted":  {"services/workload/handler.go", `Action: "federation_bundle_deleted"`},
		"audit.keyaccess.settings_updated":          {"services/keyaccess/handler.go", `Action: "settings_updated"`},
		"audit.keyaccess.code_upserted":             {"services/keyaccess/handler.go", `Action: "code_upserted"`},
		"audit.keyaccess.code_deleted":              {"services/keyaccess/handler.go", `Action: "code_deleted"`},
		"audit.confidential.policy_updated":         {"services/confidential/handler.go", `Action: "policy_updated"`},
		"audit.compliance.posture_changed":          {"services/compliance/service.go", `"audit.compliance.posture_changed"`},
		"audit.governance.fips_mode_changed":        {"services/governance/fips_mode.go", `"audit.governance.fips_mode_changed"`},
		"audit.governance.backup_restored":          {"services/governance/backup.go", `"audit.governance.backup_restored"`},
		"audit.cluster.member_joined":               {"services/cluster-manager/join.go", `"audit.cluster.member_joined"`},
		"audit.health.incident":                     {"services/watchdog/playbook.go", `Emit(ctx, "incident"`},
	}
	root := filepath.Join("..", "..")
	for _, spec := range playbookTriggers {
		for _, subject := range spec.Subjects {
			where, ok := emitters[subject]
			if !ok {
				t.Fatalf("trigger %s: subject %s has no known emitter", spec.Type, subject)
			}
			src, err := os.ReadFile(filepath.Join(root, where[0]))
			if err != nil || !bytes.Contains(src, []byte(where[1])) {
				t.Fatalf("trigger %s: %s no longer emits %s (%v)", spec.Type, where[0], subject, err)
			}
		}
	}
	for file, client := range map[string]string{
		"services/watchdog/playbook.go": `NewClient(js, "health")`,
		"services/reporting/main.go":    `"reporting"`,
	} {
		src, _ := os.ReadFile(filepath.Join(root, file))
		if !bytes.Contains(src, []byte(client)) {
			t.Fatalf("%s no longer emits under %s", file, client)
		}
	}
	// Governance decisions that resume paused runs.
	gov, _ := os.ReadFile(filepath.Join(root, "services/governance/service.go"))
	for subject := range governanceDecisions {
		if !bytes.Contains(gov, []byte(`"`+subject+`"`)) {
			t.Fatalf("governance no longer emits %s", subject)
		}
	}
}

// Threshold counts are stored, not held in memory: a new primary continues
// the count, events outside the window drop out, and editing the playbook
// starts it again.
func TestPlaybookThresholdSurvivesFailover(t *testing.T) {
	hs := newPlaybookHarness(t)
	ctx := context.Background()
	pb := Playbook{ID: "pb-spike", TenantID: "t1", Name: "spike", Category: "incident_response", Enabled: true, AuthorizedBy: "u-admin",
		Trigger: PlaybookTrigger{Type: "login_failed", Threshold: 3, WindowSeconds: 60, GroupBy: "actor_id"},
		Actions: []PlaybookAction{{Type: "create_audit_event", Parameters: map[string]string{}}}}
	if _, err := hs.store.CreatePlaybook(ctx, pb); err != nil {
		t.Fatal(err)
	}
	fired := func() int {
		n := 0
		for _, e := range events(hs.rec, "playbook_triggered") {
			if e.Event.TargetID == pb.ID && e.Event.Result == route.ResultSuccess {
				n++
			}
		}
		return n
	}
	fail := func(tl *TriggerListener, at time.Time) {
		tl.handle(ctx, "audit.auth.login_failed", hs.event("t1", "failure", "", at, map[string]interface{}{"actor_id": "mallory"}))
	}
	fail(hs.tl, hs.now)
	fail(hs.tl, hs.now.Add(time.Second))

	// Failover: a new listener on the same database.
	next := NewTriggerListener(hs.store, hs.tl.executor, hs.tl.logger)
	next.now = func() time.Time { return hs.now }
	next.dispatch = func(f func()) { f() }
	hs.now = hs.now.Add(2 * time.Second)
	fail(next, hs.now)
	if fired() != 1 {
		t.Fatalf("the new primary lost the count: fired %d", fired())
	}

	// Events that leave the window don't count.
	hs.now = hs.now.Add(2 * triggerCooldown)
	fail(next, hs.now)
	fail(next, hs.now.Add(time.Second))
	hs.now = hs.now.Add(2 * time.Minute)
	fail(next, hs.now)
	if fired() != 1 {
		t.Fatalf("events outside the window counted: fired %d", fired())
	}

	// An edit starts the count again.
	fail(next, hs.now.Add(time.Second))
	if w := hs.do(t, http.MethodPut, "/compliance/playbooks/"+pb.ID, pbAdmin, map[string]any{"name": "spike", "enabled": true,
		"trigger": map[string]any{"type": "login_failed", "threshold": 3, "window_seconds": 60, "group_by": "actor_id"},
		"actions": []any{map[string]any{"type": "create_audit_event", "parameters": map[string]string{}}}}); w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	hs.now = hs.now.Add(2 * time.Second)
	fail(next, hs.now)
	if fired() != 1 {
		t.Fatalf("counts survived an edit: fired %d", fired())
	}
}

// A broken audit chain starts the response playbook.
func TestPlaybookFiresOnChainBroken(t *testing.T) {
	hs := newPlaybookHarness(t)
	ctx := context.Background()
	if _, err := hs.store.CreatePlaybook(ctx, Playbook{ID: "pb-tamper", TenantID: "t1", Name: "tamper", Category: "incident_response", Enabled: true, AuthorizedBy: "u-admin",
		Trigger: PlaybookTrigger{Type: "audit_chain_broken"}, Actions: []PlaybookAction{{Type: "create_audit_event", Parameters: map[string]string{}}}}); err != nil {
		t.Fatal(err)
	}
	hs.tl.handle(ctx, "audit.audit.chain_broken", hs.event("t1", "failure", "", hs.now, map[string]interface{}{"details": map[string]interface{}{"scope": "chain", "break_count": 2}}))
	ev := events(hs.rec, "playbook_triggered")
	if len(ev) != 1 || ev[0].Event.TargetID != "pb-tamper" || ev[0].Event.Result != route.ResultSuccess {
		t.Fatalf("chain_broken: %+v", ev)
	}
}

// When the count can't be stored the playbook doesn't fire, and says why.
func TestPlaybookThresholdUnavailableRefused(t *testing.T) {
	hs := newPlaybookHarness(t)
	ctx := context.Background()
	if _, err := hs.store.CreatePlaybook(ctx, Playbook{ID: "pb-spike", TenantID: "t1", Name: "spike", Category: "incident_response", Enabled: true, AuthorizedBy: "u-admin",
		Trigger: PlaybookTrigger{Type: "login_failed", Threshold: 2, WindowSeconds: 60}, Actions: []PlaybookAction{{Type: "create_audit_event", Parameters: map[string]string{}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := hs.store.db.SQL().Exec(`DROP TABLE compliance_playbook_threshold_hits`); err != nil {
		t.Fatal(err)
	}
	hs.tl.handle(ctx, "audit.auth.login_failed", hs.event("t1", "failure", "", hs.now, nil))
	ev := events(hs.rec, "playbook_triggered")
	if len(ev) != 1 {
		t.Fatalf("events: %+v", ev)
	}
	wantRefused(t, ev[0], reasonThresholdUnavailable)
}

// The cooldown is stored with the playbook: a new primary still refuses a
// second firing inside it, and allows one after it.
func TestPlaybookCooldownSurvivesFailover(t *testing.T) {
	hs := newPlaybookHarness(t)
	ctx := context.Background()
	if _, err := hs.store.CreatePlaybook(ctx, Playbook{ID: "pb-rot", TenantID: "t1", Name: "rot", Category: "incident_response", Enabled: true, AuthorizedBy: "u-admin",
		Trigger: PlaybookTrigger{Type: "key_rotated"}, Actions: []PlaybookAction{{Type: "create_audit_event", Parameters: map[string]string{}}}}); err != nil {
		t.Fatal(err)
	}
	hs.tl.handle(ctx, "audit.key.rotate", hs.event("t1", "success", "k1", hs.now, nil))

	next := NewTriggerListener(hs.store, hs.tl.executor, hs.tl.logger)
	next.now = func() time.Time { return hs.now }
	next.dispatch = func(f func()) { f() }
	hs.now = hs.now.Add(triggerCooldown / 2)
	next.handle(ctx, "audit.key.rotate", hs.event("t1", "success", "k1", hs.now, nil))
	hs.now = hs.now.Add(triggerCooldown)
	next.handle(ctx, "audit.key.rotate", hs.event("t1", "success", "k1", hs.now, nil))

	ev := events(hs.rec, "playbook_triggered")
	if len(ev) != 3 || ev[0].Event.Result != route.ResultSuccess || ev[2].Event.Result != route.ResultSuccess {
		t.Fatalf("firings: %+v", ev)
	}
	wantRefused(t, ev[1], reasonCooldown)
}

// When the cooldown can't be checked the playbook doesn't fire, and says why.
func TestPlaybookCooldownUnavailableRefused(t *testing.T) {
	hs := newPlaybookHarness(t)
	ctx := context.Background()
	if _, err := hs.store.CreatePlaybook(ctx, Playbook{ID: "pb-rot", TenantID: "t1", Name: "rot", Category: "incident_response", Enabled: true, AuthorizedBy: "u-admin",
		Trigger: PlaybookTrigger{Type: "key_rotated"}, Actions: []PlaybookAction{{Type: "create_audit_event", Parameters: map[string]string{}}}}); err != nil {
		t.Fatal(err)
	}
	hs.tl.playbooks(ctx, "t1") // cache the playbook, then lose the column
	if _, err := hs.store.db.SQL().Exec(`ALTER TABLE compliance_playbooks DROP COLUMN last_fired_ms`); err != nil {
		t.Fatal(err)
	}
	hs.tl.handle(ctx, "audit.key.rotate", hs.event("t1", "success", "k1", hs.now, nil))
	ev := events(hs.rec, "playbook_triggered")
	if len(ev) != 1 {
		t.Fatalf("events: %+v", ev)
	}
	wantRefused(t, ev[0], reasonCooldownUnavailable)
}
