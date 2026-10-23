package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

var bindAdmin = &pkgauth.Claims{UserID: "u-bind", TenantID: "t1", Role: "operator", Permissions: []string{"key.binding.read", "key.binding.write"}}

// encryptFrom is encryptAs from a given peer address.
func encryptFrom(h http.Handler, keyID string, claims *pkgauth.Claims, remote string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"tenant_id": "t1", "plaintext": "aGVsbG8="})
	req := httptest.NewRequest(http.MethodPost, "/keys/"+keyID+"/encrypt?tenant_id=t1", bytes.NewReader(body))
	req.RemoteAddr = remote
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func servicePrincipal(id string) *pkgauth.Claims {
	c := &pkgauth.Claims{ClientID: id, TenantID: "root", Role: "client-service", Permissions: []string{"service.internal"}}
	c.Subject = id
	return c
}

func TestBindingPolicyRoutesRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.bindingPolicyRouter(rec), rec)
}

// A binding is enforced on every caller, service principals included: a key
// bound to KMIP is refused to a direct caller and to another service, a key
// bound to a network is refused outside it, a disabled binding applies to
// nothing, and every refusal is audited with reason binding_policy.
func TestKeyBindingsAreEnforced(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	ctx := context.Background()
	kmipKey := ownedKey(t, svc)
	netKey, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "prod-db", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Labels: map[string]string{"env": "prod"}, CreatedBy: "owner-1"})
	if err != nil {
		t.Fatal(err)
	}
	creator := &pkgauth.Claims{UserID: "owner-1", TenantID: "t1", Role: "operator"}

	// Before any binding the creator and services reach both keys.
	if w := encryptFrom(h, kmipKey.ID, creator, "192.0.2.1:1234"); w.Code != http.StatusOK {
		t.Fatalf("unbound: %d %s", w.Code, w.Body)
	}

	create := func(body map[string]any) KeyBindingPolicy {
		t.Helper()
		w := metaCall(t, h, bindAdmin, http.MethodPost, "/binding-policies", body)
		if w.Code != http.StatusCreated {
			t.Fatalf("create %v: %d %s", body, w.Code, w.Body)
		}
		var out struct {
			Policy KeyBindingPolicy `json:"policy"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out.Policy
	}
	kmipOnly := create(map[string]any{"name": "kmip only", "key_ids": []string{kmipKey.ID}, "channels": []string{"kms-kmip"}})
	create(map[string]any{"name": "prod from the data centre", "label_selector": map[string]string{"env": "prod"}, "channels": []string{"rest", "kms-ekm"}, "source_networks": []string{"10.0.0.0/8"}})

	if w := encryptFrom(h, kmipKey.ID, creator, "192.0.2.1:1234"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `binding \"kmip only\" allows kms-kmip, not rest`) {
		t.Fatalf("a direct caller reached a KMIP-bound key: %d %s", w.Code, w.Body)
	}
	if d := refusalDetails(t, rec, "audit.key.access_refused"); d["reason"] != "binding_policy" {
		t.Fatalf("refusal audited: %+v", d)
	}
	if w := encryptFrom(h, kmipKey.ID, servicePrincipal("kms-kmip"), "10.9.0.5:443"); w.Code != http.StatusOK {
		t.Fatalf("KMIP refused: %d %s", w.Code, w.Body)
	}
	if w := encryptFrom(h, kmipKey.ID, servicePrincipal("kms-compliance"), "10.9.0.5:443"); w.Code != http.StatusForbidden {
		t.Fatalf("another service reached a KMIP-bound key: %d", w.Code)
	}

	if w := encryptFrom(h, netKey.ID, creator, "192.0.2.1:1234"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "10.0.0.0/8") {
		t.Fatalf("outside the network: %d %s", w.Code, w.Body)
	}
	if w := encryptFrom(h, netKey.ID, creator, "10.4.5.6:1234"); w.Code != http.StatusOK {
		t.Fatalf("inside the network: %d %s", w.Code, w.Body)
	}
	// The network is a direct caller's; a listed service is not held to it.
	if w := encryptFrom(h, netKey.ID, servicePrincipal("kms-ekm"), "172.18.0.9:443"); w.Code != http.StatusOK {
		t.Fatalf("EKM refused: %d %s", w.Code, w.Body)
	}

	// The check route says the same before anyone relies on it.
	w := metaCall(t, h, bindAdmin, http.MethodPost, "/binding-policies/check", map[string]any{"key_id": netKey.ID, "channel": "rest", "source_ip": "192.0.2.1"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"allowed":false`) || !strings.Contains(w.Body.String(), "prod from the data centre") {
		t.Fatalf("check: %d %s", w.Code, w.Body)
	}
	w = metaCall(t, h, bindAdmin, http.MethodPost, "/binding-policies/check", map[string]any{"key_id": kmipKey.ID, "channel": "kms-kmip"})
	if !strings.Contains(w.Body.String(), `"allowed":true`) {
		t.Fatalf("check kmip: %s", w.Body)
	}

	// Disabled, a binding applies to nothing.
	if w := metaCall(t, h, bindAdmin, http.MethodPut, "/binding-policies/"+kmipOnly.ID, bindingPolicyInput{Name: kmipOnly.Name, KeyIDs: kmipOnly.KeyIDs, Channels: kmipOnly.Channels, Status: "disabled"}); w.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", w.Code, w.Body)
	}
	if w := encryptFrom(h, kmipKey.ID, creator, "192.0.2.1:1234"); w.Code != http.StatusOK {
		t.Fatalf("a disabled binding was enforced: %d %s", w.Code, w.Body)
	}
}

func TestBindingProblemWorkloads(t *testing.T) {
	p := KeyBindingPolicy{Name: "prod workloads", AllKeys: true, WorkloadIdentities: []string{"spiffe://prod.example/*"}, Status: bindingActive}
	if got := bindingProblem(p, AccessActor{WorkloadIdentity: "spiffe://prod.example/payments"}); got != "" {
		t.Fatalf("a matching workload: %s", got)
	}
	for _, id := range []string{"spiffe://dev.example/payments", ""} {
		if got := bindingProblem(p, AccessActor{WorkloadIdentity: id}); got == "" {
			t.Fatalf("workload %q passed", id)
		}
	}
	// IPv4-mapped IPv6 addresses match their IPv4 network.
	n := KeyBindingPolicy{Name: "n", AllKeys: true, SourceNetworks: []string{"10.0.0.0/8"}, Status: bindingActive}
	if got := bindingProblem(n, AccessActor{SourceIP: "::ffff:10.1.1.1"}); got != "" {
		t.Fatalf("mapped address: %s", got)
	}
	if got := bindingProblem(n, AccessActor{}); got == "" {
		t.Fatal("an unknown address passed a network binding")
	}
}

// A binding that couldn't be applied as written is refused and audited, and
// the previews it and key access grants replace are retired.
func TestBindingPolicyValidationAndRetiredPreviews(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	router := h.bindingPolicyRouter(rec)
	for name, body := range map[string]map[string]any{
		"no keys":        {"name": "a", "channels": []string{"rest"}},
		"no condition":   {"name": "b", "all_keys": true},
		"bad channel":    {"name": "c", "all_keys": true, "channels": []string{"kms-nonexistent"}},
		"bad network":    {"name": "d", "all_keys": true, "source_networks": []string{"10.0.0.0/33"}},
		"all and listed": {"name": "e", "all_keys": true, "key_ids": []string{"k1"}, "channels": []string{"rest"}},
	} {
		w := metaCall(t, router, bindAdmin, http.MethodPost, "/binding-policies", body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
		if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "invalid_binding_policy" {
			t.Fatalf("%s: %+v", name, ev.Event)
		}
	}
	ops := &routetest.Recorder{}
	opsRouter := h.keyOpsRouter(ops)
	admin := &pkgauth.Claims{UserID: "u-e", TenantID: "t1", Permissions: []string{"key.enterprise.write"}}
	for _, cat := range []string{"binding_policy", "sharing", "edge_agent", "edge_lease", "edge_receipt"} {
		if w := metaCall(t, opsRouter, admin, http.MethodPost, "/enterprise/controls", map[string]any{"category": cat, "name": "x"}); w.Code != http.StatusGone {
			t.Fatalf("%s: %d %s", cat, w.Code, w.Body)
		}
		if ev := ops.Last(t); ev.Event.Details["reason"] != "feature_retired" {
			t.Fatalf("%s: %+v", cat, ev.Event)
		}
	}
	for _, path := range []string{"/enterprise/binding/policies", "/enterprise/sharing/grants", "/enterprise/edge/agents", "/enterprise/edge/leases", "/enterprise/edge/receipts"} {
		if w := metaCall(t, h, admin, http.MethodPost, path, map[string]any{"name": "x"}); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s still answers: %d", path, w.Code)
		}
	}
}
