package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"vecta-kms/pkg/clusterstate"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/servicetoken"
)

// memApprovals stands in for governance's approval store in tests.
type memApprovals struct {
	mu    sync.Mutex
	items []GovernanceApproval
	fail  error
}

func (m *memApprovals) ListApprovals(_ context.Context, _ string, status, targetType, targetID string) ([]GovernanceApproval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return nil, m.fail
	}
	var out []GovernanceApproval
	for _, a := range m.items {
		if a.Status == status && a.TargetType == targetType && a.TargetID == targetID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *memApprovals) RequestApproval(_ context.Context, in ApprovalRequestInput) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := "apr_" + string(rune('a'+len(m.items)))
	m.items = append(m.items, GovernanceApproval{ID: id, Action: in.Action, TargetType: in.TargetType, TargetID: in.TargetID, TargetDetails: in.TargetDetails, RequesterID: in.RequesterID, Status: "pending"})
	return id, nil
}

func (m *memApprovals) approve(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.items {
		if m.items[i].ID == id {
			m.items[i].Status = "approved"
		}
	}
}

func (m *memApprovals) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}

// seedEscalation stores an overdue warning finding, its SLA-breach finding
// and the escalate action the corrective engine would propose for it.
func seedEscalation(t *testing.T, store *SQLStore) (source Finding, breach Finding, action RemediationAction) {
	t.Helper()
	ctx := context.Background()
	past := time.Now().UTC().Add(-7 * 24 * time.Hour)
	var err error
	source, err = store.UpsertFindingByFingerprint(ctx, "t1", FindingCandidate{Engine: "predictive", FindingType: "deletion_velocity_anomaly", Title: "delete spike", Severity: severityWarning, Fingerprint: "fp-src"}, past)
	if err != nil {
		t.Fatal(err)
	}
	breach, err = store.UpsertFindingByFingerprint(ctx, "t1", FindingCandidate{Engine: "corrective", FindingType: "remediation_sla_breached", Title: "SLA breached", Severity: severityHigh, Fingerprint: "fp-breach"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	action, err = store.CreateActionIfAbsent(ctx, "t1", breach.ID, ActionCandidate{
		FindingFingerprint: "fp-breach", ActionType: "escalate_remediation", SafetyGate: "manual", ApprovalRequired: true,
		Evidence: map[string]interface{}{"source_finding_id": source.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	return source, breach, action
}

// An escalation runs only on an approved governance request that is bound
// to this action and opened by the executor; then it really escalates.
func TestEscalationRunsOnlyOnBoundApproval(t *testing.T) {
	h, store, rec := newPostureHandler(t, nil)
	gov := &memApprovals{}
	h.svc.SetApprovalClient(gov)
	source, breach, action := seedEscalation(t, store)
	path := "/posture/actions/" + action.ID + "/execute"
	alice, bob := userClaims("alice", "t1"), userClaims("bob", "t1")
	ctx := context.Background()

	// No approval yet: posture opens one for alice and refuses.
	expectRefused(t, rec, postureCall(h, alice, http.MethodPost, path, ""), http.StatusConflict, "action_executed", "approval_pending")
	if gov.count() != 1 || gov.items[0].RequesterID != "alice" || gov.items[0].Action != "posture.escalate_remediation" || gov.items[0].TargetID != action.ID {
		t.Fatalf("approval request %+v", gov.items)
	}
	aprID := gov.items[0].ID
	if got, _ := store.GetAction(ctx, "t1", action.ID); got.Status != "awaiting_approval" || got.ApprovalRequestID != aprID {
		t.Fatalf("action %+v, want awaiting_approval with %s", got, aprID)
	}
	// Still pending: no second request, still refused.
	expectRefused(t, rec, postureCall(h, alice, http.MethodPost, path, ""), http.StatusConflict, "action_executed", "approval_pending")
	if gov.count() != 1 {
		t.Fatalf("duplicate approval requests: %d", gov.count())
	}
	// A made-up approval ID is not an approval.
	expectRefused(t, rec, postureCall(h, alice, http.MethodPost, path, `{"approval_request_id":"apr_forged"}`), http.StatusForbidden, "action_executed", "approval_invalid")

	gov.approve(aprID)
	// Bob can't run on alice's approval: he gets his own pending request.
	expectRefused(t, rec, postureCall(h, bob, http.MethodPost, path, ""), http.StatusConflict, "action_executed", "approval_pending")
	if src, _ := store.GetFinding(ctx, "t1", source.ID); src.Severity != severityWarning {
		t.Fatalf("finding escalated before an approved execution: %s", src.Severity)
	}

	rr := postureCall(h, alice, http.MethodPost, path, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("approved execute: %d %s", rr.Code, rr.Body)
	}
	src, _ := store.GetFinding(ctx, "t1", source.ID)
	if src.Severity != severityHigh || !src.SLADueAt.After(time.Now()) {
		t.Fatalf("source finding %s due %s, want high with a restarted SLA", src.Severity, src.SLADueAt)
	}
	if b, _ := store.GetFinding(ctx, "t1", breach.ID); b.Status != "resolved" {
		t.Fatalf("breach finding %s, want resolved", b.Status)
	}
	got, _ := store.GetAction(ctx, "t1", action.ID)
	if got.Status != "executed" || got.ExecutedBy != "alice" || got.ApprovalRequestID != aprID {
		t.Fatalf("action %+v", got)
	}
	e := rec.Last(t)
	if e.Action != "action_executed" || e.Event.Result != route.ResultSuccess || e.Event.Details["approval_request_id"] != aprID ||
		e.Event.Details["severity_from"] != severityWarning || e.Event.Details["severity_to"] != severityHigh || e.Event.Details["escalated_finding_id"] != source.ID {
		t.Fatalf("execute event %+v", e)
	}
	if rr := postureCall(h, alice, http.MethodPost, path, ""); rr.Code != http.StatusConflict {
		t.Fatalf("re-execute: %d", rr.Code)
	}
}

// An approval for another action, type, tenant or requester doesn't match.
func TestApprovalBindingRejectsMismatches(t *testing.T) {
	item := RemediationAction{ID: "a1", TenantID: "t1", ActionType: "escalate_remediation", FindingID: "f1"}
	good := GovernanceApproval{ID: "apr1", Action: "posture.escalate_remediation", TargetType: approvalTargetType, TargetID: "a1", RequesterID: "alice", Status: "approved",
		TargetDetails: map[string]interface{}{"payload_hash": approvalPayloadHash(item)}}
	if !approvalMatches(good, item, "alice") {
		t.Fatal("matching approval refused")
	}
	other := item
	other.TenantID = "t2"
	for name, a := range map[string]GovernanceApproval{
		"other action": func() GovernanceApproval { a := good; a.TargetID = "a2"; return a }(),
		"other type":   func() GovernanceApproval { a := good; a.Action = "posture.other"; return a }(),
		"other target": func() GovernanceApproval { a := good; a.TargetType = "key"; return a }(),
		"other tenant": func() GovernanceApproval {
			a := good
			a.TargetDetails = map[string]interface{}{"payload_hash": approvalPayloadHash(other)}
			return a
		}(),
		"no requester": func() GovernanceApproval { a := good; a.RequesterID = ""; return a }(),
	} {
		if approvalMatches(a, item, "alice") {
			t.Errorf("%s: matched", name)
		}
	}
	if approvalMatches(good, item, "bob") {
		t.Error("another executor matched alice's approval")
	}
}

// Without governance, or when it can't be reached, an approval-required
// action refuses; nothing changes.
func TestEscalationFailsClosedWithoutGovernance(t *testing.T) {
	h, store, rec := newPostureHandler(t, nil)
	source, _, action := seedEscalation(t, store)
	path := "/posture/actions/" + action.ID + "/execute"
	expectRefused(t, rec, postureCall(h, userClaims("alice", "t1"), http.MethodPost, path, ""), http.StatusServiceUnavailable, "action_executed", "approval_unavailable")
	h.svc.SetApprovalClient(&memApprovals{fail: context.DeadlineExceeded})
	expectRefused(t, rec, postureCall(h, userClaims("alice", "t1"), http.MethodPost, path, ""), http.StatusServiceUnavailable, "action_executed", "approval_unavailable")
	if src, _ := store.GetFinding(context.Background(), "t1", source.ID); src.Severity != severityWarning {
		t.Fatalf("finding changed without approval: %s", src.Severity)
	}
}

// A type posture has no executor for is refused, never marked executed.
func TestNonExecutableActionRefused(t *testing.T) {
	h, store, rec := newPostureHandler(t, nil)
	f, err := store.UpsertFindingByFingerprint(context.Background(), "t1", FindingCandidate{Engine: "predictive", FindingType: "connector_auth_flap", Title: "flap", Severity: severityHigh, Fingerprint: "fp-flap"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.CreateActionIfAbsent(context.Background(), "t1", f.ID, ActionCandidate{ActionType: "restart_degraded_connector", SafetyGate: "low-impact"})
	if err != nil {
		t.Fatal(err)
	}
	expectRefused(t, rec, postureCall(h, userClaims("alice", "t1"), http.MethodPost, "/posture/actions/"+a.ID+"/execute", ""), http.StatusConflict, "action_executed", "not_executable")
	if got, _ := store.GetAction(context.Background(), "t1", a.ID); got.Status != "suggested" {
		t.Fatalf("status %s", got.Status)
	}
}

// The corrective engine proposes only action types posture can execute;
// the other open findings still count toward the score.
func TestCorrectiveEngineProposesOnlyExecutableActions(t *testing.T) {
	h, store, _ := newPostureHandler(t, nil)
	seedEscalation(t, store)
	for _, ft := range []string{"connector_auth_flap", "hsm_latency_rising", "tenant_isolation_violation_pattern", "certificate_emergency_rotation_active"} {
		if _, err := store.UpsertFindingByFingerprint(context.Background(), "t1", FindingCandidate{Engine: "predictive", FindingType: ft, Title: ft, Severity: severityHigh, Fingerprint: "fp-" + ft}, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	_, actions, score, _ := h.svc.correctiveEngine(context.Background(), "t1", time.Now().UTC())
	if len(actions) == 0 {
		t.Fatal("overdue finding produced no escalation")
	}
	for _, a := range actions {
		if _, ok := actionExecutors[a.ActionType]; !ok {
			t.Errorf("engine proposed %s, which has no executor", a.ActionType)
		}
	}
	if score < 6+10+12+12 {
		t.Fatalf("score %d ignores open findings", score)
	}
}

func legacyAction(t *testing.T, store *SQLStore, fp, actionType, status, msg string) string {
	t.Helper()
	ctx := context.Background()
	f, err := store.UpsertFindingByFingerprint(ctx, "t1", FindingCandidate{Engine: "corrective", FindingType: "x", Title: fp, Severity: severityHigh, Fingerprint: fp}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.CreateActionIfAbsent(ctx, "t1", f.ID, ActionCandidate{ActionType: actionType})
	if err != nil {
		t.Fatal(err)
	}
	if status != "suggested" {
		if err := store.UpdateActionExecution(ctx, "t1", a.ID, status, "someone", msg, "apr_old"); err != nil {
			t.Fatal(err)
		}
	}
	return a.ID
}

// Rows the old "execute" wrote are made true once, audited, and a real
// execution's row is left alone.
func TestLegacyActionsCorrected(t *testing.T) {
	bus := &recordedPublish{}
	h, store, _ := newPostureHandler(t, bus)
	ctx := context.Background()
	escalated := legacyAction(t, store, "fp1", "escalate_remediation", "executed", "runbook dispatched")
	restarted := legacyAction(t, store, "fp2", "restart_degraded_connector", "executed", "runbook dispatched")
	publishFailed := legacyAction(t, store, "fp3", "failover_hsm_profile", "failed", "runbook publish failed: nats down")
	pending := legacyAction(t, store, "fp4", "quarantine_compromised_client_profile", "suggested", "")
	real := legacyAction(t, store, "fp5", "escalate_remediation", "executed", "escalated finding f from warning to high; SLA restarted, due x")

	h.svc.correctLegacyActions(ctx, "t1")
	want := map[string]string{escalated: "suggested", restarted: "not_performed", publishFailed: "not_performed", pending: "withdrawn", real: "executed"}
	for id, status := range want {
		if got, _ := store.GetAction(ctx, "t1", id); got.Status != status {
			t.Errorf("%s: status %s, want %s (%s)", id, got.Status, status, got.ResultMessage)
		}
	}
	if got, _ := store.GetAction(ctx, "t1", escalated); got.ExecutedBy != "" || got.ApprovalRequestID != "" {
		t.Errorf("reset action kept executor %q / approval %q", got.ExecutedBy, got.ApprovalRequestID)
	}
	h.svc.correctLegacyActions(ctx, "t1")
	if len(bus.subjects) != 1 || bus.subjects[0] != "audit.posture.actions_corrected" {
		t.Fatalf("correction events %v, want exactly one actions_corrected", bus.subjects)
	}
	cockpit := buildRemediationCockpit([]RemediationAction{{ID: restarted, Status: "not_performed"}, {ID: pending, Status: "withdrawn"}})
	for _, g := range cockpit {
		if g.Count != 0 {
			t.Fatalf("closed actions in cockpit group %s", g.ID)
		}
	}
}

// A cluster member never rewrites the replicated action table.
func TestLegacyCorrectionSkippedOnMember(t *testing.T) {
	clusterstate.SetDefault(clusterstate.Static(clusterstate.State{NodeID: "n2", Role: clusterstate.RoleFollower, PrimaryURL: "https://primary:8443", ForwardCredential: "cred"}))
	t.Cleanup(func() { clusterstate.SetDefault(nil) })
	h, store, _ := newPostureHandler(t, nil)
	id := legacyAction(t, store, "fp1", "restart_degraded_connector", "executed", "runbook dispatched")
	h.svc.correctLegacyActions(context.Background(), "t1")
	if got, _ := store.GetAction(context.Background(), "t1", id); got.Status != "executed" {
		t.Fatalf("member rewrote action to %s", got.Status)
	}
}

// Approval calls carry posture's service token and name the verified caller
// as requester.
func TestApprovalCallsCarryServiceIdentity(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "kms-posture-jwt", "expires_at": "2099-01-01T00:00:00Z"})
	}))
	defer auth.Close()
	t.Setenv("AUTH_URL", auth.URL)
	t.Setenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET", "3f9c2a7d5e1b8c4f6a0d2e9b7c5a3f1e8d6b4c2a0f9e7d5c3b1a8f6e4d2c0b9a")
	servicetoken.SetDefault(servicetoken.FromEnv("kms-posture"))
	t.Cleanup(func() { servicetoken.SetDefault(nil) })

	var created ApprovalRequestInput
	gov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kms-posture-jwt" || r.Header.Get("X-Tenant-ID") != "t1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/governance/requests":
			_ = json.NewDecoder(r.Body).Decode(&created)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"request": map[string]any{"id": "apr_1"}})
		case r.Method == http.MethodGet && r.URL.Path == "/governance/requests":
			q := r.URL.Query()
			if q.Get("status") != "approved" || q.Get("target_type") != approvalTargetType || q.Get("target_id") != "a1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"id": "apr_1", "status": "approved", "requester_id": "alice"}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer gov.Close()

	c := NewHTTPGovernanceControlClient(gov.URL, "static-token-must-not-be-used", 0)
	id, err := c.RequestApproval(context.Background(), ApprovalRequestInput{TenantID: "t1", Action: "posture.escalate_remediation", TargetType: approvalTargetType, TargetID: "a1", RequesterID: "alice"})
	if err != nil || id != "apr_1" || created.RequesterID != "alice" || created.TargetID != "a1" {
		t.Fatalf("request: %s %v %+v", id, err, created)
	}
	items, err := c.ListApprovals(context.Background(), "t1", "approved", approvalTargetType, "a1")
	if err != nil || len(items) != 1 || items[0].RequesterID != "alice" {
		t.Fatalf("list: %+v %v", items, err)
	}
}
