package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func notifyHarness(t *testing.T) (*Handler, *Service, *mockEmailSender, *routetest.Recorder) {
	t.Helper()
	h, svc, _, mailer := approvalHarness(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	claims := map[string]*pkgauth.Claims{
		"compliance": {TenantID: "root", Role: "client-service", ClientID: "kms-compliance", Permissions: []string{"service.internal"}},
		"posture":    {TenantID: "root", Role: "client-service", ClientID: "kms-posture", Permissions: []string{"service.internal"}},
		"admin":      {TenantID: "t1", Role: "admin", UserID: "u-admin", Permissions: []string{"*"}},
	}
	h.SetTokenParser(func(tok string) (*pkgauth.Claims, error) {
		if c, ok := claims[tok]; ok {
			return c, nil
		}
		return nil, jwt.ErrTokenSignatureInvalid
	})
	if _, err := svc.store.(*SQLStore).db.SQL().Exec(`UPDATE auth_users SET role='admin' WHERE id='u-admin'`); err != nil {
		t.Fatal(err)
	}
	return h, svc, mailer, rec
}

func notifyCall(h *Handler, token, body string) (int, string) {
	rr := call(h, token, http.MethodPost, "/governance/notify/email?tenant_id=t1", body)
	return rr.Code, rr.Body.String()
}

// The email route refuses anonymous and cross-tenant callers, audited.
func TestNotifyRoutesRefusalsAudited(t *testing.T) {
	h, _, _, rec := notifyHarness(t)
	routetest.RefusalsAudited(t, h.notifyRouter(), rec)
}

// Only the compliance service sends, only to active users of the tenant,
// only through the tenant's SMTP settings.
func TestNotifyEmailOnlyToTenantUsers(t *testing.T) {
	h, svc, mailer, rec := notifyHarness(t)
	ok := `{"tenant_id":"t1","to":["alice@t1.test","role:admin"],"subject":"Canary tripped","body":"key k1","playbook_run_id":"pbrun_1"}`
	for _, tok := range []string{"admin", "posture"} {
		if code, _ := notifyCall(h, tok, ok); code != http.StatusForbidden {
			t.Fatalf("%s sent email: %d", tok, code)
		}
		if ev := rec.Last(t); ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != "service_identity_required" {
			t.Fatalf("refusal: %+v", ev.Event)
		}
	}
	if code, _ := notifyCall(h, "compliance", `{"tenant_id":"t1","to":["attacker@evil.test"],"subject":"x"}`); code != http.StatusBadRequest {
		t.Fatalf("outside recipient: %d", code)
	}
	if ev := rec.Last(t); ev.Event.Details["reason"] != "recipient_not_tenant_user" {
		t.Fatalf("outside recipient refusal: %+v", ev.Event)
	}
	if code, body := notifyCall(h, "compliance", ok); code != http.StatusConflict {
		t.Fatalf("without SMTP: %d %s", code, body)
	}
	if _, err := svc.UpdateSettings(context.Background(), GovernanceSettings{TenantID: "t1", SMTPHost: "smtp.t1.test", SMTPPort: "587", SMTPFrom: "kms@t1.test", ApprovalExpiryMinutes: 60}); err != nil {
		t.Fatal(err)
	}
	code, body := notifyCall(h, "compliance", ok)
	var out struct{ Sent int }
	_ = json.Unmarshal([]byte(body), &out)
	if code != http.StatusOK || out.Sent != 2 || len(mailer.msgs) != 2 || mailer.msgs[0].Subject != "[Vecta KMS] Canary tripped" {
		t.Fatalf("send: %d %s %+v", code, body, mailer.msgs)
	}
	if ev := rec.Last(t); ev.Action != "notification_email_sent" || ev.Event.Result != route.ResultSuccess || ev.Event.Details["recipients"] != 2 || ev.Event.Details["playbook_run_id"] != "pbrun_1" {
		t.Fatalf("send event: %+v", ev)
	}
}

// A playbook step that needs approval opens a request under the built-in
// playbook policy; the person it acts for isn't an approver.
func TestBuiltinPlaybookPolicy(t *testing.T) {
	h, svc, _, _ := notifyHarness(t)
	if _, err := svc.store.(*SQLStore).db.SQL().Exec(`UPDATE auth_users SET role='tenant-admin' WHERE id IN ('u-alice','u-bob')`); err != nil {
		t.Fatal(err)
	}
	body := `{"tenant_id":"t1","action":"playbook.deactivate_key","target_type":"playbook_action","target_id":"pbrun_1#0",
		"target_details":{"payload_hash":"h1"},"requester_id":"u-alice"}`
	rr := call(h, "compliance", http.MethodPost, "/governance/requests", body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("playbook approval request: %d %s", rr.Code, rr.Body.String())
	}
	var out struct{ Request ApprovalRequest }
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.Request.PolicyID != builtinPolicyID("t1", builtinPolicies[1]) || out.Request.RequesterEmail != "alice@t1.test" {
		t.Fatalf("request %+v", out.Request)
	}
	approvers, _ := svc.store.RequestApprovers(context.Background(), out.Request.ID)
	for _, a := range approvers {
		if a == "alice@t1.test" {
			t.Fatalf("the person the playbook acts for approves: %v", approvers)
		}
	}
	if len(approvers) == 0 {
		t.Fatal("no approvers")
	}
}

// The built-in playbook policy stays on: disabling it or dropping
// playbook.* is refused and audited, approvers can still change, and one
// disabled under 2.5.0-beta is switched back on at the next request.
func TestBuiltinPlaybookPolicyRequired(t *testing.T) {
	h, svc, pub := builtinHarness(t)
	ctx := context.Background()
	open := func() int {
		body := `{"tenant_id":"t1","action":"playbook.deactivate_key","target_type":"playbook_action","target_id":"pbrun_1#0",
			"target_details":{"payload_hash":"h1"},"requester_id":"u-alice"}`
		return call(h, "posture", http.MethodPost, "/governance/requests", body).Code
	}
	if code := open(); code != http.StatusCreated {
		t.Fatalf("open: %d", code)
	}
	id := builtinPolicyID("t1", builtinPolicies[1])
	put := func(mut func(*ApprovalPolicy)) int {
		p, err := svc.store.GetPolicy(ctx, "t1", id)
		if err != nil {
			t.Fatal(err)
		}
		mut(&p)
		raw, _ := json.Marshal(p)
		return call(h, "admin", http.MethodPut, "/governance/policies/"+id+"?tenant_id=t1", string(raw)).Code
	}
	for name, mut := range map[string]func(*ApprovalPolicy){
		"disable": func(p *ApprovalPolicy) { p.Status = "inactive" },
		"narrow":  func(p *ApprovalPolicy) { p.TriggerActions = []string{"playbook.revoke_certificate"} },
	} {
		before := len(pub.events["audit.governance.approval_refused"])
		if code := put(mut); code != http.StatusConflict {
			t.Fatalf("%s: %d, want 409", name, code)
		}
		refused := pub.events["audit.governance.approval_refused"]
		if len(refused) != before+1 {
			t.Fatalf("%s: refusal not audited", name)
		}
		if data, _ := refused[len(refused)-1]["data"].(map[string]interface{}); data["reason"] != "builtin_policy_required" || data["result"] != "refused" {
			t.Fatalf("%s: refusal %+v", name, data)
		}
	}
	if code := put(func(p *ApprovalPolicy) { p.ApproverRoles = []string{"admin"} }); code != http.StatusOK {
		t.Fatalf("editing approvers: %d", code)
	}

	// Disabled before 2.6.0: the next request switches it back on.
	if _, err := svc.store.(*SQLStore).db.SQL().Exec(`UPDATE approval_policies SET status='inactive' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if code := open(); code != http.StatusCreated {
		t.Fatalf("open after legacy disable: %d", code)
	}
	if p, _ := svc.store.GetPolicy(ctx, "t1", id); p.Status != "active" || len(pub.events["audit.governance.builtin_policy_restored"]) != 1 {
		t.Fatalf("status %s, restored events %d", p.Status, len(pub.events["audit.governance.builtin_policy_restored"]))
	}
}
