package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	pkgauth "vecta-kms/pkg/auth"
)

// approvalHarness is a governance handler whose tokens map to fixed claims:
// "admin" (tenant admin), "alice"/"bob"/"carol" (users of t1), "other"
// (a user of t2) and "svc" (the hyok service principal).
func approvalHarness(t *testing.T) (*Handler, *Service, *capturePublisher, *mockEmailSender) {
	t.Helper()
	store := newGovernanceStore(t)
	pub := &capturePublisher{}
	mailer := &mockEmailSender{}
	svc := NewService(store, pub, mailer, &mockCallbackExecutor{}, "http://localhost:8050")
	h := NewHandler(svc)
	claims := map[string]*pkgauth.Claims{
		"admin": {TenantID: "t1", Role: "admin", UserID: "u-admin", Permissions: []string{"*"}},
		"alice": {TenantID: "t1", Role: "operator", UserID: "u-alice"},
		"bob":   {TenantID: "t1", Role: "operator", UserID: "u-bob"},
		"carol": {TenantID: "t1", Role: "security", UserID: "u-carol"},
		"other": {TenantID: "t2", Role: "admin", UserID: "u-other", Permissions: []string{"*"}},
		"svc":   {TenantID: "t1", Role: "client-service", ClientID: "kms-hyok-proxy"},
	}
	h.SetTokenParser(func(tok string) (*pkgauth.Claims, error) {
		if c, ok := claims[tok]; ok {
			return c, nil
		}
		return nil, jwt.ErrTokenSignatureInvalid
	})
	for id, email := range map[string]string{"u-admin": "admin@t1.test", "u-alice": "alice@t1.test", "u-bob": "bob@t1.test", "u-carol": "carol@t1.test"} {
		if _, err := store.db.SQL().Exec(`INSERT INTO auth_users (id, tenant_id, email) VALUES ($1,'t1',$2)`, id, email); err != nil {
			t.Fatal(err)
		}
	}
	return h, svc, pub, mailer
}

func call(h *Handler, token, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// No approval route is reachable without a token, from another tenant, or
// (for policy changes) without a tenant administrator; each refusal is
// audited with its reason.
func TestApprovalAPIRequiresAuthenticatedTenantCaller(t *testing.T) {
	h, _, pub, _ := approvalHarness(t)
	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/governance/policies?tenant_id=t1", ""},
		{http.MethodPost, "/governance/policies", `{"tenant_id":"t1","name":"p"}`},
		{http.MethodDelete, "/governance/policies/p1?tenant_id=t1", ""},
		{http.MethodGet, "/governance/requests?tenant_id=t1", ""},
		{http.MethodPost, "/governance/requests", `{"tenant_id":"t1","action":"key.destroy","target_type":"key","target_id":"k1"}`},
		{http.MethodPost, "/governance/requests/r1/cancel?tenant_id=t1", `{}`},
		{http.MethodGet, "/governance/requests/pending?tenant_id=t1&approver_email=alice@t1.test", ""},
		{http.MethodPost, "/governance/approve/r1?tenant_id=t1", `{"vote":"approved","approver_email":"alice@t1.test"}`},
		{http.MethodPost, "/governance/key-approval", `{"tenant_id":"t1","key_id":"k1","operation":"encrypt"}`},
	}
	for _, rt := range routes {
		if rr := call(h, "", rt.method, rt.path, rt.body); rr.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without token: %d %s", rt.method, rt.path, rr.Code, rr.Body.String())
		}
		if rr := call(h, "other", rt.method, rt.path, rt.body); rr.Code != http.StatusForbidden {
			t.Errorf("%s %s from another tenant: %d %s", rt.method, rt.path, rr.Code, rr.Body.String())
		}
	}
	lastRefusal(t, pub, "audit.governance.approval_refused")
	for _, tok := range []string{"alice", "svc"} {
		if rr := call(h, tok, http.MethodPost, "/governance/policies", `{"tenant_id":"t1","name":"p"}`); rr.Code != http.StatusForbidden {
			t.Errorf("policy created by %s: %d", tok, rr.Code)
		}
	}
}

// A dashboard vote counts as the authenticated user, whatever email the body
// names; only approvers the policy names may vote; the requester may not.
func TestDashboardVoteIsBoundToTheAuthenticatedApprover(t *testing.T) {
	h, svc, _, _ := approvalHarness(t)
	createTestPolicy(t, svc, "t1", 2, 2, []string{"bob@t1.test", "admin@t1.test"})
	rr := call(h, "alice", http.MethodPost, "/governance/requests", `{"tenant_id":"t1","action":"key.destroy","target_type":"key","target_id":"k1",
		"requester_id":"u-bob","target_details":{"approver_emails":["alice@t1.test"]},"callback_service":"keycore:18010","callback_action":"/x/Y"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create request: %d %s", rr.Code, rr.Body.String())
	}
	var created struct{ Request ApprovalRequest }
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	req := created.Request
	if req.RequesterID != "u-alice" || req.RequesterEmail != "alice@t1.test" || req.CallbackService != "" || req.TargetDetails["approver_emails"] != nil {
		t.Fatalf("user-chosen requester, approvers or callback kept: %+v", req)
	}
	vote := func(tok, body string) *httptest.ResponseRecorder {
		return call(h, tok, http.MethodPost, "/governance/approve/"+req.ID+"?tenant_id=t1", body)
	}
	// Carol is not an approver; naming Bob's email does not make her one.
	if rr := vote("carol", `{"vote":"approved","approver_email":"bob@t1.test","approver_id":"u-bob"}`); rr.Code == http.StatusOK {
		t.Fatalf("vote cast under another approver's email: %s", rr.Body.String())
	}
	// The requester cannot approve their own request.
	if rr := vote("alice", `{"vote":"approved"}`); rr.Code == http.StatusOK {
		t.Fatalf("requester approved their own request: %s", rr.Body.String())
	}
	if rr := vote("svc", `{"vote":"approved"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("service principal voted: %d", rr.Code)
	}
	if rr := vote("bob", `{"vote":"approved","approver_email":"admin@t1.test"}`); rr.Code != http.StatusOK {
		t.Fatalf("approver vote refused: %d %s", rr.Code, rr.Body.String())
	}
	details, err := svc.GetApprovalRequest(context.Background(), "t1", req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(details.Votes) != 1 || details.Votes[0].ApproverEmail != "bob@t1.test" || details.Request.Status != "pending" {
		t.Fatalf("vote not recorded as Bob, or quorum met by one person: %+v %s", details.Votes, details.Request.Status)
	}
	if rr := vote("bob", `{"vote":"approved"}`); rr.Code == http.StatusOK {
		t.Fatal("same approver counted twice")
	}
	if rr := vote("admin", `{"vote":"approved"}`); rr.Code != http.StatusOK {
		t.Fatalf("second approver refused: %d %s", rr.Code, rr.Body.String())
	}
	if details, _ = svc.GetApprovalRequest(context.Background(), "t1", req.ID); details.Request.Status != "approved" {
		t.Fatalf("two distinct approvers did not reach quorum: %s", details.Request.Status)
	}
}

// The email-link page needs a live token for that request, not any string.
func TestApprovalPageNeedsAValidToken(t *testing.T) {
	h, svc, pub, _ := approvalHarness(t)
	createTestPolicy(t, svc, "t1", 1, 1, []string{"bob@t1.test"})
	req, err := svc.CreateApprovalRequest(context.Background(), CreateApprovalRequestInput{
		TenantID: "t1", Action: "key.destroy", TargetType: "key", TargetID: "k3", RequesterID: "u-alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	rr := call(h, "", http.MethodGet, "/governance/approve/"+req.ID+"?tenant_id=t1&token=guess", "")
	if rr.Code == http.StatusOK {
		t.Fatal("approval page served for a made-up token")
	}
	lastRefusal(t, pub, "audit.governance.link_refused")
}

// A policy's approver roles decide who may vote: every active user of the
// tenant holding the role, directly or through a group binding, becomes an
// approver when the request opens. Anyone else (and the requester, even when
// they hold the role) is refused, and the refusal is audited.
func TestApproverRolesDecideWhoMayVote(t *testing.T) {
	h, svc, pub, _ := approvalHarness(t)
	db := store(svc).db.SQL()
	for _, q := range []string{
		`UPDATE auth_users SET role='security-officer' WHERE id IN ('u-alice','u-bob')`,
		`UPDATE auth_users SET role='operator' WHERE id='u-carol'`,
		`INSERT INTO auth_users (id, tenant_id, email, role, status) VALUES ('u-gone','t1','gone@t1.test','security-officer','disabled')`,
		`INSERT INTO auth_users (id, tenant_id, email, role) VALUES ('u-t2','t2','t2@t2.test','security-officer')`,
		`INSERT INTO auth_group_role_bindings (tenant_id, group_id, role_name) VALUES ('t1','g-sec','Security-Officer')`,
		`INSERT INTO key_access_group_members (tenant_id, group_id, user_id) VALUES ('t1','g-sec','u-admin')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	p, err := svc.CreatePolicy(context.Background(), ApprovalPolicy{
		TenantID: "t1", Name: "role-approval", Scope: "key_operation", TriggerActions: []string{"key.destroy"},
		QuorumMode: "and", RequiredApprovals: 1, TotalApprovers: 1, ApproverRoles: []string{"security-officer"}, Status: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	rr := call(h, "alice", http.MethodPost, "/governance/requests", `{"tenant_id":"t1","policy_id":"`+p.ID+`","action":"key.destroy","target_type":"key","target_id":"k9"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create request: %d %s", rr.Code, rr.Body.String())
	}
	var created struct{ Request ApprovalRequest }
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	req := created.Request
	approvers, err := store(svc).RequestApprovers(context.Background(), req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(approvers, ",") != "admin@t1.test,bob@t1.test" && strings.Join(approvers, ",") != "bob@t1.test,admin@t1.test" {
		t.Fatalf("role holders (minus requester, disabled and other-tenant users) not the approvers: %v", approvers)
	}
	if req.RequiredApprovals != 2 {
		t.Fatalf("all-approvers quorum counts the requester or misses a role holder: %d", req.RequiredApprovals)
	}
	vote := func(tok string) *httptest.ResponseRecorder {
		return call(h, tok, http.MethodPost, "/governance/approve/"+req.ID+"?tenant_id=t1", `{"vote":"approved"}`)
	}
	if rr := vote("carol"); rr.Code == http.StatusOK {
		t.Fatalf("user without the approver role voted: %s", rr.Body.String())
	}
	if data := lastRefusal(t, pub, "audit.governance.approval_refused"); data["reason"] != "vote_refused" {
		t.Fatalf("vote refusal not audited as vote_refused: %+v", data)
	}
	if rr := vote("alice"); rr.Code == http.StatusOK {
		t.Fatal("requester holding the role voted on their own request")
	}
	for _, tok := range []string{"bob", "admin"} {
		if rr := vote(tok); rr.Code != http.StatusOK {
			t.Fatalf("role holder %s refused: %d %s", tok, rr.Code, rr.Body.String())
		}
	}
	if details, _ := svc.GetApprovalRequest(context.Background(), "t1", req.ID); details.Request.Status != "approved" {
		t.Fatalf("role holders did not reach quorum: %s", details.Request.Status)
	}
}

// A policy whose roles no user holds opens no request nobody could approve.
func TestApproverRoleWithNoHoldersRefusesRequest(t *testing.T) {
	_, svc, _, _ := approvalHarness(t)
	if _, err := svc.CreatePolicy(context.Background(), ApprovalPolicy{
		TenantID: "t1", Name: "empty-role", Scope: "key_operation", TriggerActions: []string{"key.destroy"},
		RequiredApprovals: 1, TotalApprovers: 1, ApproverRoles: []string{"nobody-has-this"}, Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateApprovalRequest(context.Background(), CreateApprovalRequestInput{
		TenantID: "t1", Action: "key.destroy", TargetType: "key", TargetID: "k1", RequesterID: "u-alice",
	}); err == nil {
		t.Fatal("request opened with no one able to approve it")
	}
}

func store(svc *Service) *SQLStore { return svc.store.(*SQLStore) }
