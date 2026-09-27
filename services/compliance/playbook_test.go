package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
	"vecta-kms/pkg/servicetoken"
)

var (
	pbAdmin  = &pkgauth.Claims{UserID: "u-admin", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	pbWriter = &pkgauth.Claims{UserID: "u-writer", TenantID: "t1", Role: "ops", Permissions: []string{permPlaybookRead, permPlaybookWrite, permPlaybookRun}}
)

// platformRecorder stands in for keycore and certs: it records each call and
// answers with the configured status and body.
type platformRecorder struct {
	mu     sync.Mutex
	calls  []*http.Request
	status int
	body   string
}

func (p *platformRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.calls = append(p.calls, r.Clone(context.Background()))
	status, body := p.status, p.body
	p.mu.Unlock()
	if status == 0 {
		status, body = http.StatusOK, `{"status":"ok"}`
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (p *platformRecorder) paths() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, r := range p.calls {
		out = append(out, r.URL.Path)
	}
	return out
}

type playbookHarness struct {
	h        *Handler
	store    *SQLStore
	rec      *routetest.Recorder
	exec     *PlaybookExecutor
	platform *platformRecorder
}

func newPlaybookHarness(t *testing.T) *playbookHarness {
	t.Helper()
	svc, store, _, _, _, _, _ := newComplianceService(t)
	rec := &routetest.Recorder{}
	logger := log.New(io.Discard, "", 0)
	platform := &platformRecorder{}
	srv := httptest.NewServer(platform)
	t.Cleanup(srv.Close)
	exec := NewPlaybookExecutor(store, srv.URL, srv.URL, rec, logger)
	exec.ops = svc
	h := NewHandler(svc, rec, logger)
	h.dispatch = func(f func()) { f() }
	h.SetExecutor(exec)
	return &playbookHarness{h: h, store: store, rec: rec, exec: exec, platform: platform}
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
		t.Fatalf("no %s event (have %v)", action, rec.Events())
	}
	return ev[len(ev)-1]
}

func wantRefused(t *testing.T, ev routetest.Recorded, reason string) {
	t.Helper()
	if ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != reason {
		t.Fatalf("%s: result=%s reason=%v, want refused %s", ev.Action, ev.Event.Result, ev.Event.Details["reason"], reason)
	}
}

func rotatePlaybook(enabled bool) map[string]any {
	return map[string]any{
		"name": "rotate on canary", "trigger": map[string]string{"type": "canary_tripped"}, "enabled": enabled,
		"actions": []map[string]any{{"type": "rotate_key", "parameters": map[string]string{"key_id": "k1"}}},
	}
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

// Every playbook route refuses an anonymous caller, a caller without the
// route permission and a caller naming another tenant, and audits each.
func TestPlaybookRoutesRefusalsAudited(t *testing.T) {
	hs := newPlaybookHarness(t)
	routetest.RefusalsAudited(t, hs.h.router, hs.rec)
}

// Before 2.4.0-beta the tenant came from the request body: any caller could
// plant a playbook in another tenant.
func TestPlaybookCreateTakesTenantFromToken(t *testing.T) {
	hs := newPlaybookHarness(t)
	body := rotatePlaybook(true)
	body["tenant_id"] = "victim"
	w := hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, body)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant create: %d %s", w.Code, w.Body.String())
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_created"), route.ReasonTenantMismatch)
	if pbs, _ := hs.store.ListPlaybooks(context.Background(), "victim"); len(pbs) != 0 {
		t.Fatalf("playbook written into another tenant: %+v", pbs)
	}
}

// Saving an enabled playbook needs every permission its actions use; the
// executor's service identity must not lend its reach to a playbook writer.
func TestPlaybookSaveRequiresActionPermissions(t *testing.T) {
	hs := newPlaybookHarness(t)
	w := hs.do(t, http.MethodPost, "/compliance/playbooks", pbWriter, rotatePlaybook(true))
	if w.Code != http.StatusForbidden {
		t.Fatalf("writer without key.rotate: %d %s", w.Code, w.Body.String())
	}
	ev := lastEvent(t, hs.rec, "playbook_created")
	wantRefused(t, ev, reasonActionPermission)
	if missing, _ := ev.Event.Details["missing_permissions"].([]string); len(missing) != 1 || missing[0] != "key.rotate" {
		t.Fatalf("missing_permissions = %v", ev.Event.Details["missing_permissions"])
	}

	// Disabled, it saves, unauthorized.
	id := createdID(t, hs.do(t, http.MethodPost, "/compliance/playbooks", pbWriter, rotatePlaybook(false)))
	pb, _ := hs.store.GetPlaybook(context.Background(), "t1", id)
	if pb.AuthorizedBy != "" || pb.Enabled {
		t.Fatalf("disabled save by writer: authorized_by=%q enabled=%v", pb.AuthorizedBy, pb.Enabled)
	}
	// The writer can't enable it.
	if w := hs.do(t, http.MethodPut, "/compliance/playbooks/"+id, pbWriter, rotatePlaybook(true)); w.Code != http.StatusForbidden {
		t.Fatalf("writer enabling: %d %s", w.Code, w.Body.String())
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_updated"), reasonActionPermission)
	// An admin can, and it runs on the admin's authority.
	if w := hs.do(t, http.MethodPut, "/compliance/playbooks/"+id, pbAdmin, rotatePlaybook(true)); w.Code != http.StatusOK {
		t.Fatalf("admin enabling: %d %s", w.Code, w.Body.String())
	}
	pb, _ = hs.store.GetPlaybook(context.Background(), "t1", id)
	if pb.AuthorizedBy != "u-admin" || !pb.Enabled {
		t.Fatalf("admin save: authorized_by=%q enabled=%v", pb.AuthorizedBy, pb.Enabled)
	}
	if ev := lastEvent(t, hs.rec, "playbook_updated"); ev.Event.Result != route.ResultSuccess || ev.Event.Details["authorized_by"] != "u-admin" {
		t.Fatalf("playbook_updated: %+v", ev.Event)
	}
	// Legacy fields are rejected, not ignored.
	legacy := rotatePlaybook(true)
	legacy["trigger"] = map[string]any{"type": "canary_tripped", "threshold": 5}
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, legacy); w.Code != http.StatusBadRequest {
		t.Fatalf("threshold accepted: %d", w.Code)
	}
}

// A manual run acts on the runner's authority and is audited per action.
func TestPlaybookRunRequiresActionPermissionsAndAuditsEachAction(t *testing.T) {
	hs := newPlaybookHarness(t)
	id := createdID(t, hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, rotatePlaybook(true)))

	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/"+id+"/run", pbWriter, nil); w.Code != http.StatusForbidden {
		t.Fatalf("writer run: %d %s", w.Code, w.Body.String())
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_run_requested"), reasonActionPermission)
	if len(hs.platform.paths()) != 0 {
		t.Fatal("refused run reached keycore")
	}

	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/"+id+"/run", pbAdmin, nil); w.Code != http.StatusAccepted {
		t.Fatalf("admin run: %d %s", w.Code, w.Body.String())
	}
	if got := hs.platform.paths(); len(got) != 1 || got[0] != "/keys/k1/rotate" {
		t.Fatalf("keycore calls = %v", got)
	}
	if tenant := hs.platform.calls[0].Header.Get("X-Tenant-ID"); tenant != "t1" {
		t.Fatalf("keycore tenant = %q", tenant)
	}
	act := lastEvent(t, hs.rec, "playbook_action_executed")
	if act.Event.Result != route.ResultSuccess || act.Event.Details["action"] != "rotate_key" || act.Event.Details["key_id"] != "k1" || act.Event.ActorID != "u-admin" {
		t.Fatalf("playbook_action_executed: %+v", act.Event)
	}
	done := lastEvent(t, hs.rec, "playbook_run_completed")
	if done.Event.Result != route.ResultSuccess || done.Event.Details["status"] != runCompleted || done.Event.Details["trigger"] != "manual" {
		t.Fatalf("playbook_run_completed: %+v", done.Event)
	}
	runs, _ := hs.store.ListPlaybookRuns(context.Background(), "t1", id, 10)
	if len(runs) != 1 || runs[0].Status != runCompleted || runs[0].Actor != "u-admin" {
		t.Fatalf("runs = %+v", runs)
	}
}

// A platform call that opens an approval is recorded as pending, never done.
func TestPlaybookPendingApprovalIsNotSuccess(t *testing.T) {
	hs := newPlaybookHarness(t)
	hs.platform.status, hs.platform.body = http.StatusAccepted, `{"status":"pending_approval","approval_request_id":"ap1"}`
	id := createdID(t, hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, rotatePlaybook(true)))
	hs.do(t, http.MethodPost, "/compliance/playbooks/"+id+"/run", pbAdmin, nil)
	act := lastEvent(t, hs.rec, "playbook_action_executed")
	if act.Event.Result != "pending" || act.Event.Details["outcome"] != outcomePendingApproval {
		t.Fatalf("pending action audited as %s/%v", act.Event.Result, act.Event.Details["outcome"])
	}
	if done := lastEvent(t, hs.rec, "playbook_run_completed"); done.Event.Details["status"] != runPendingApproval {
		t.Fatalf("run status %v", done.Event.Details["status"])
	}
}

// Each key and certificate action calls the endpoint that exists. Until
// 2.4.0-beta suspend/revoke/enable called PUT /keys/{id}/status and the
// certificate actions /certificates/..., none of which exist.
func TestPlaybookPlatformActionsCallRealEndpoints(t *testing.T) {
	hs := newPlaybookHarness(t)
	want := map[string]string{
		"rotate_key": "/keys/k1/rotate", "disable_key": "/keys/k1/disable", "deactivate_key": "/keys/k1/deactivate",
		"activate_key": "/keys/k1/activate", "renew_certificate": "/certs/c1/renew", "revoke_certificate": "/certs/c1/revoke",
	}
	for action, path := range want {
		hs.platform.calls = nil
		outcome, err := hs.exec.executeAction(context.Background(), PlaybookAction{Type: action, Parameters: map[string]string{"key_id": "k1", "cert_id": "c1"}}, RunContext{TenantID: "t1", RunID: "r1"})
		if err != nil || outcome != outcomeDone {
			t.Fatalf("%s: %s %v", action, outcome, err)
		}
		if got := hs.platform.paths(); len(got) != 1 || got[0] != path || hs.platform.calls[0].Method != http.MethodPost {
			t.Fatalf("%s called %v, want POST %s", action, got, path)
		}
	}
	hs.platform.status, hs.platform.body = http.StatusNotFound, `{"error":{"code":"not_found","message":"key not found"}}`
	if _, err := hs.exec.executeAction(context.Background(), PlaybookAction{Type: "rotate_key", Parameters: map[string]string{"key_id": "gone"}}, RunContext{TenantID: "t1"}); err == nil || !strings.Contains(err.Error(), "not_found") {
		t.Fatalf("missing key reported %v", err)
	}
}

// Keycore refuses anonymous callers, so key actions carry the compliance
// service token; outbound notifications never do.
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
	if _, err := hs.exec.executeAction(context.Background(), PlaybookAction{Type: "rotate_key", Parameters: map[string]string{"key_id": "k1"}}, RunContext{TenantID: "t1"}); err != nil {
		t.Fatal(err)
	}
	if got := hs.platform.calls[0].Header.Get("Authorization"); got != "Bearer svc-jwt" {
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
	for _, a := range []PlaybookAction{
		{Type: "send_webhook", Parameters: map[string]string{"url": ext.URL + "/hook"}},
		{Type: "create_servicenow_incident", Parameters: map[string]string{"instance_url": ext.URL, "short_description": "x"}},
		{Type: "create_jira_ticket", Parameters: map[string]string{"base_url": ext.URL, "project": "SEC", "summary": "x", "api_token": "dG9rZW4="}},
	} {
		if _, err := hs.exec.executeAction(context.Background(), a, RunContext{TenantID: "t1"}); err != nil {
			t.Fatalf("%s: %v", a.Type, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if seen["/hook"] != "" || seen["/api/now/table/incident"] != "" {
		t.Fatalf("service token reached an external endpoint: %v", seen)
	}
	if seen["/rest/api/2/issue"] != "Basic dG9rZW4=" {
		t.Fatalf("jira auth = %q", seen["/rest/api/2/issue"])
	}
}

// A playbook can't call a platform service or a private address: the
// executor's mTLS identity would be presented to it (SSRF).
func TestPlaybookOutboundCannotReachPlatformOrPrivateHosts(t *testing.T) {
	hs := newPlaybookHarness(t)
	for _, u := range []string{"https://keycore:8010/keys/k1/destroy", "http://1.1.1.1/hook", "https://127.0.0.1/hook", "https://169.254.169.254/latest"} {
		body := map[string]any{
			"name": "exfil", "trigger": map[string]string{"type": "canary_tripped"},
			"actions": []map[string]any{{"type": "send_webhook", "parameters": map[string]string{"url": u}}},
		}
		if w := hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d", u, w.Code)
		}
		wantRefused(t, lastEvent(t, hs.rec, "playbook_created"), reasonURLBlocked)
	}
	// At run time too: a stored row can't be pointed at the platform, and
	// the default client refuses private addresses at dial time. Errors name
	// the host, never the URL (a webhook URL is a credential).
	if _, err := hs.exec.notify(context.Background(), http.MethodPost, "https://keycore:8010/keys/k1/destroy", map[string]string{}, nil); err == nil {
		t.Fatal("notify reached a platform host")
	}
	ext := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ext.Close()
	_, err := hs.exec.notify(context.Background(), http.MethodPost, ext.URL+"/services/T0/B0/sekret", map[string]string{}, nil)
	if err == nil || strings.Contains(err.Error(), "sekret") {
		t.Fatalf("private address: err=%v", err)
	}
}

// Secret parameters never come back from the API; the redaction marker keeps
// the stored value on update.
func TestPlaybookSecretsNeverReturned(t *testing.T) {
	hs := newPlaybookHarness(t)
	secret := "https://1.1.1.1/services/T0/B0/sekret"
	body := map[string]any{
		"name": "notify", "trigger": map[string]string{"type": "canary_tripped"},
		"actions": []map[string]any{{"type": "send_slack", "parameters": map[string]string{"webhook_url": secret}}},
	}
	w := hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, body)
	id := createdID(t, w)
	for _, resp := range []*httptest.ResponseRecorder{w, hs.do(t, http.MethodGet, "/compliance/playbooks/"+id, pbAdmin, nil), hs.do(t, http.MethodGet, "/compliance/playbooks", pbAdmin, nil)} {
		if strings.Contains(resp.Body.String(), "sekret") || !strings.Contains(resp.Body.String(), redactedParam) {
			t.Fatalf("secret returned: %s", resp.Body.String())
		}
	}
	for _, e := range hs.rec.Events() {
		if raw, _ := json.Marshal(e.Event); strings.Contains(string(raw), "sekret") {
			t.Fatalf("secret in audit event %s", e.Action)
		}
	}
	body["actions"] = []map[string]any{{"type": "send_slack", "parameters": map[string]string{"webhook_url": redactedParam, "message": "hi"}}}
	if w := hs.do(t, http.MethodPut, "/compliance/playbooks/"+id, pbAdmin, body); w.Code != http.StatusOK {
		t.Fatalf("update with marker: %d %s", w.Code, w.Body.String())
	}
	pb, _ := hs.store.GetPlaybook(context.Background(), "t1", id)
	if pb.Actions[0].Parameters["webhook_url"] != secret || pb.Actions[0].Parameters["message"] != "hi" {
		t.Fatalf("stored params = %v", pb.Actions[0].Parameters)
	}
	// A marker with nothing stored behind it is refused.
	body["actions"] = []map[string]any{
		{"type": "send_slack", "parameters": map[string]string{"webhook_url": redactedParam}},
		{"type": "send_teams", "parameters": map[string]string{"webhook_url": redactedParam}},
	}
	if w := hs.do(t, http.MethodPut, "/compliance/playbooks/"+id, pbAdmin, body); w.Code != http.StatusBadRequest {
		t.Fatalf("unbacked marker: %d", w.Code)
	}
}

// Actions that never worked are gone from the catalogue, can't be saved, and
// a stored row that still names one is refused, audited, at run time.
func TestPlaybookRemovedActionsRefused(t *testing.T) {
	hs := newPlaybookHarness(t)
	for _, a := range []string{"destroy_key", "send_pagerduty", "disable_user", "revoke_api_key", "send_email", "notify_soc", "quarantine_tenant"} {
		if _, ok := actionByType[a]; ok {
			t.Fatalf("%s is still in the catalogue", a)
		}
		var removed actionRemovedError
		if _, err := hs.exec.executeAction(context.Background(), PlaybookAction{Type: a, Parameters: map[string]string{"key_id": "k1"}}, RunContext{TenantID: "t1"}); !asRemoved(err, &removed) {
			t.Fatalf("%s: %v", a, err)
		}
	}
	ctx := context.Background()
	stored, err := hs.store.CreatePlaybook(ctx, Playbook{
		ID: "pb-legacy", TenantID: "t1", Name: "legacy", Category: "incident_response", Enabled: true, AuthorizedBy: "u-admin",
		Trigger: PlaybookTrigger{Type: "canary_tripped"},
		Actions: []PlaybookAction{{Type: "suspend_key", Parameters: map[string]string{"key_id": "k1"}}, {Type: "destroy_key", Parameters: map[string]string{"key_id": "k1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stored.Actions[0].Type != "disable_key" {
		t.Fatalf("legacy suspend_key read as %s", stored.Actions[0].Type)
	}
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/pb-legacy/run", pbAdmin, nil); w.Code != http.StatusConflict {
		t.Fatalf("run with removed action: %d %s", w.Code, w.Body.String())
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_run_requested"), reasonPlaybookInvalid)
	// A triggered run still meets it: that action is refused and audited.
	run, _ := hs.exec.Start(ctx, stored, runSource{Trigger: "canary_tripped", Actor: "u-admin"})
	if got := hs.exec.Execute(ctx, stored, run, runSource{Trigger: "canary_tripped", Actor: "u-admin"}); got.Status != runPartialFailure {
		t.Fatalf("run status %s", got.Status)
	}
	wantRefused(t, lastEvent(t, hs.rec, "playbook_action_executed"), reasonActionRemoved)
}

func asRemoved(err error, target *actionRemovedError) bool {
	r, ok := err.(actionRemovedError)
	if ok {
		*target = r
	}
	return ok
}

func TestPlaybookCatalogServedFromBackend(t *testing.T) {
	hs := newPlaybookHarness(t)
	w := hs.do(t, http.MethodGet, "/compliance/playbooks/catalog", pbWriter, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("catalog: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Data struct {
			Triggers []TriggerSpec `json:"triggers"`
			Actions  []ActionSpec  `json:"actions"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out.Data.Triggers) != len(playbookTriggers) || len(out.Data.Actions) != len(playbookActions) {
		t.Fatalf("catalog: %d triggers, %d actions", len(out.Data.Triggers), len(out.Data.Actions))
	}
	if ev := lastEvent(t, hs.rec, "playbook_catalog_read"); ev.Event.Result != route.ResultSuccess {
		t.Fatalf("catalog event %+v", ev.Event)
	}
}

// Automatic runs: only authorized playbooks, only on the primary, one per
// cooldown, never for stale or refused events; every decision is audited.
func TestPlaybookTriggerListener(t *testing.T) {
	hs := newPlaybookHarness(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	tl := NewTriggerListener(hs.store, hs.exec, log.New(io.Discard, "", 0))
	tl.now = func() time.Time { return now }
	tl.dispatch = func(f func()) { f() }
	mk := func(id, tenant, trigger, authorizedBy string) {
		if _, err := hs.store.CreatePlaybook(ctx, Playbook{
			ID: id, TenantID: tenant, Name: id, Category: "incident_response", Enabled: true, AuthorizedBy: authorizedBy,
			Trigger: PlaybookTrigger{Type: trigger},
			Actions: []PlaybookAction{{Type: "rotate_key", Parameters: map[string]string{"key_id": "k1"}}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	mk("pb-rotated", "t1", "key_rotated", "u-admin")
	mk("pb-canary", "t1", "canary_tripped", "")
	mk("pb-health", "root", "service_health_degraded", "u-root")
	event := func(tenant, result string, at time.Time) []byte {
		raw, _ := json.Marshal(map[string]string{"tenant_id": tenant, "result": result, "target_id": "k9", "timestamp": at.Format(time.RFC3339Nano)})
		return raw
	}
	triggered := func() []routetest.Recorded { return events(hs.rec, "playbook_triggered") }

	tl.handle(ctx, "audit.key.rotate", event("t1", "success", now))
	if ev := triggered(); len(ev) != 1 || ev[0].Event.Result != route.ResultSuccess || ev[0].Event.TargetID != "pb-rotated" || ev[0].Event.Details["run_id"] == "" {
		t.Fatalf("first trigger: %+v", ev)
	}
	if got := hs.platform.paths(); len(got) != 1 || got[0] != "/keys/k1/rotate" {
		t.Fatalf("triggered run called %v", got)
	}
	if done := lastEvent(t, hs.rec, "playbook_run_completed"); done.Event.ActorID != "u-admin" || done.Event.Details["subject"] != "audit.key.rotate" {
		t.Fatalf("run completed: %+v", done.Event)
	}

	tl.handle(ctx, "audit.key.rotate", event("t1", "success", now))
	wantRefused(t, triggered()[1], reasonCooldown)

	now = now.Add(2 * triggerCooldown)
	tl.handle(ctx, "audit.key.rotate", event("t1", "refused", now))
	if len(triggered()) != 2 {
		t.Fatal("a refused rotate fired key_rotated")
	}
	tl.handle(ctx, "audit.key.rotate", event("t1", "success", now.Add(-time.Hour)))
	wantRefused(t, triggered()[2], reasonStaleEvent)

	tl.handle(ctx, "audit.keycore.canary_tripped", event("t1", "success", now))
	wantRefused(t, triggered()[3], reasonNotAuthorized)

	// Watchdog incidents carry no tenant: the platform tenant's playbooks fire.
	tl.handle(ctx, "audit.health.incident", []byte(`{"result":"warning","target_id":"keycore","timestamp":"`+now.Format(time.RFC3339Nano)+`"}`))
	if ev := triggered()[4]; ev.Event.TargetID != "pb-health" || ev.Event.TenantID != "root" || ev.Event.Result != route.ResultSuccess {
		t.Fatalf("health incident: %+v", ev.Event)
	}

	// Subjects nothing emits (the pre-2.4.0 map) fire nothing.
	before := len(hs.rec.Events())
	tl.handle(ctx, "audit.keycore.key_rotated", event("t1", "success", now))
	// Members never run playbooks; the primary sees their events by relay.
	clusterstate.SetDefault(clusterstate.Static(clusterstate.State{NodeID: "n2", Role: clusterstate.RoleFollower, PrimaryURL: "https://primary:8443", ForwardCredential: "cred"}))
	t.Cleanup(func() { clusterstate.SetDefault(nil) })
	now = now.Add(2 * triggerCooldown)
	tl.handle(ctx, "audit.key.rotate", event("t1", "success", now))
	if len(hs.rec.Events()) != before {
		t.Fatalf("dead subject or member fired: %v", hs.rec.Events()[before:])
	}
}

// Every trigger subject is emitted by a service. The table names where; it
// fails when an emitter is renamed or removed, and a new catalogue subject
// needs an entry.
func TestTriggerSubjectsAreEmitted(t *testing.T) {
	emitters := map[string][2]string{
		"audit.keycore.canary_tripped":          {"services/keycore/threat_detection.go", `"audit.keycore.canary_tripped"`},
		"audit.keycore.threat_signal_raised":    {"services/keycore/threat_detection.go", `"audit.keycore.threat_signal_raised"`},
		"audit.posture.threat_finding_raised":   {"services/posture/threat_findings.go", `"audit.posture.threat_finding_raised"`},
		"audit.key.compromise_detected":         {"services/keycore/enterprise_audit_service.go", `"audit.key.compromise_detected"`},
		"audit.key.create":                      {"services/keycore/keycore.go", `"audit.key.create"`},
		"audit.key.rotate":                      {"services/keycore/keycore.go", `"audit.key.rotate"`},
		"audit.key.destroyed":                   {"services/keycore/keycore.go", `"audit.key.destroyed"`},
		"audit.key.access_refused":              {"services/keycore/access_control.go", `"audit.key.access_refused"`},
		"audit.key.request_replay_detected":     {"services/keycore/handler.go", `"audit.key.request_replay_detected"`},
		"audit.cert.revoked":                    {"services/certs/service.go", `"audit.cert.revoked"`},
		"audit.cert.renewal_window_missed":      {"services/certs/service_renewal.go", `"audit.cert.renewal_window_missed"`},
		"audit.cert.mass_renewal_risk_detected": {"services/certs/service_renewal.go", `"audit.cert.mass_renewal_risk_detected"`},
		"audit.cert.crl_generation_failed":      {"services/certs/service.go", `"audit.cert.crl_generation_failed"`},
		"audit.auth.login_failed":               {"services/auth/handler.go", `"audit.auth.login_failed"`},
		"audit.auth.account_locked":             {"services/auth/handler.go", `"audit.auth.account_locked"`},
		"audit.auth.dpop_replay_detected":       {"services/auth/handler.go", `"audit.auth.dpop_replay_detected"`},
		"audit.compliance.posture_changed":      {"services/compliance/service.go", `"audit.compliance.posture_changed"`},
		"audit.health.incident":                 {"services/watchdog/playbook.go", `Emit(ctx, "incident"`},
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
	watchdog, _ := os.ReadFile(filepath.Join(root, "services/watchdog/playbook.go"))
	if !bytes.Contains(watchdog, []byte(`NewClient(js, "health")`)) {
		t.Fatal("watchdog incidents are no longer audit.health.*")
	}
}
