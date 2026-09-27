package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"vecta-kms/pkg/clusterstate"
)

// escalationRequest is what posture sends to open an approval for alice.
const escalationRequest = `{"tenant_id":"t1","action":"posture.escalate_remediation","target_type":"posture_action","target_id":"a1",
	"target_details":{"payload_hash":"h1","action_type":"escalate_remediation"},"requester_id":"u-alice"}`

func builtinHarness(t *testing.T) (*Handler, *Service, *capturePublisher) {
	t.Helper()
	h, svc, pub, _ := approvalHarness(t)
	for _, stmt := range []string{
		`UPDATE auth_users SET role='admin' WHERE id='u-admin'`,
		`UPDATE auth_users SET role='tenant-admin' WHERE id IN ('u-alice','u-bob')`,
	} {
		if _, err := svc.store.(*SQLStore).db.SQL().Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	return h, svc, pub
}

func openEscalation(t *testing.T, h *Handler) ApprovalRequest {
	t.Helper()
	rr := call(h, "posture", http.MethodPost, "/governance/requests", escalationRequest)
	if rr.Code != http.StatusCreated {
		t.Fatalf("posture approval request: %d %s", rr.Code, rr.Body.String())
	}
	var out struct{ Request ApprovalRequest }
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return out.Request
}

// On a fresh tenant, the first escalation creates the built-in policy once;
// tenant admins other than the requester approve, and posture then finds the
// approved request bound to its action.
func TestBuiltinPostureEscalationPolicy(t *testing.T) {
	h, svc, pub := builtinHarness(t)
	ctx := context.Background()
	req := openEscalation(t, h)
	id := builtinPolicyID("t1", builtinPolicies[0])
	if req.PolicyID != id || req.RequesterID != "u-alice" || req.RequesterEmail != "alice@t1.test" {
		t.Fatalf("request %+v, want built-in policy %s and requester alice with her email", req, id)
	}
	approvers, err := svc.store.RequestApprovers(ctx, req.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range approvers {
		if a == "alice@t1.test" {
			t.Fatalf("requester is an approver of her own request: %v", approvers)
		}
	}
	if len(approvers) != 2 {
		t.Fatalf("approvers %v, want the two other tenant admins", approvers)
	}
	openEscalation(t, h)
	policies, _ := svc.ListPolicies(ctx, "t1", "", "")
	if len(policies) != 1 || len(pub.events["audit.governance.builtin_policy_created"]) != 1 {
		t.Fatalf("policies %d, created events %d; want one of each", len(policies), len(pub.events["audit.governance.builtin_policy_created"]))
	}

	if rr := call(h, "alice", http.MethodPost, "/governance/approve/"+req.ID+"?tenant_id=t1", `{"vote":"approved"}`); rr.Code == http.StatusOK {
		t.Fatal("requester approved her own escalation")
	}
	if rr := call(h, "bob", http.MethodPost, "/governance/approve/"+req.ID+"?tenant_id=t1", `{"vote":"approved"}`); rr.Code != http.StatusOK {
		t.Fatalf("admin approval: %d %s", rr.Code, rr.Body.String())
	}
	rr := call(h, "posture", http.MethodGet, "/governance/requests?tenant_id=t1&status=approved&target_type=posture_action&target_id=a1", "")
	var list struct{ Items []ApprovalRequest }
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if rr.Code != http.StatusOK || len(list.Items) != 1 || list.Items[0].ID != req.ID || list.Items[0].RequesterID != "u-alice" || list.Items[0].TargetDetails["payload_hash"] != "h1" {
		t.Fatalf("posture's approval lookup: %d %+v", rr.Code, list.Items)
	}
}

// The built-in policy can't be deleted (it would come back); once disabled
// it stays disabled and approvals for its action are refused.
func TestBuiltinPolicyCanBeDisabledNotDeleted(t *testing.T) {
	h, svc, pub := builtinHarness(t)
	openEscalation(t, h)
	id := builtinPolicyID("t1", builtinPolicies[0])
	rr := call(h, "admin", http.MethodDelete, "/governance/policies/"+id+"?tenant_id=t1", "")
	if rr.Code != http.StatusConflict {
		t.Fatalf("delete built-in: %d %s", rr.Code, rr.Body.String())
	}
	refused := pub.events["audit.governance.approval_refused"]
	if len(refused) == 0 {
		t.Fatal("delete refusal not audited")
	}
	if data, _ := refused[len(refused)-1]["data"].(map[string]interface{}); data["reason"] != "builtin_policy_delete" || data["result"] != "refused" {
		t.Fatalf("delete refusal not audited: %+v", refused)
	}
	p, err := svc.store.GetPolicy(context.Background(), "t1", id)
	if err != nil {
		t.Fatal(err)
	}
	p.Status = "inactive"
	if _, err := svc.UpdatePolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	rr = call(h, "posture", http.MethodPost, "/governance/requests", escalationRequest)
	if rr.Code == http.StatusCreated {
		t.Fatalf("request opened under a disabled built-in policy: %s", rr.Body.String())
	}
	if len(pub.events["audit.governance.builtin_policy_created"]) != 1 {
		t.Fatal("disabled built-in policy was created again")
	}
}

// Actions no built-in policy covers still need a policy an admin made, and a
// cluster member never creates one.
func TestBuiltinPolicyScope(t *testing.T) {
	h, svc, _ := builtinHarness(t)
	rr := call(h, "posture", http.MethodPost, "/governance/requests", `{"tenant_id":"t1","action":"key.destroy","target_type":"key","target_id":"k1","requester_id":"u-alice"}`)
	if rr.Code == http.StatusCreated {
		t.Fatalf("request opened with no policy: %s", rr.Body.String())
	}
	clusterstate.SetDefault(clusterstate.Static(clusterstate.State{NodeID: "n2", Role: clusterstate.RoleFollower, PrimaryURL: "https://primary:8443", ForwardCredential: "cred"}))
	t.Cleanup(func() { clusterstate.SetDefault(nil) })
	if rr := call(h, "posture", http.MethodPost, "/governance/requests", escalationRequest); rr.Code == http.StatusCreated {
		t.Fatalf("member created the built-in policy: %s", rr.Body.String())
	}
	if policies, _ := svc.ListPolicies(context.Background(), "t1", "", ""); len(policies) != 0 {
		t.Fatalf("policies on member: %+v", policies)
	}
}
