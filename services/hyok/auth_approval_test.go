package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgkeyaccess "vecta-kms/pkg/keyaccess"
)

func hyokCall(h *Handler, token, method, path, body string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// Client-certificate headers and the TLS peer are never an identity: only a
// verified JWT is, and it must match the tenant.
func TestHYOKRefusesSpoofedIdentity(t *testing.T) {
	h, _, keycore, _, _, _ := newHYOKHandler(t)
	keycore.Seed("tenant-a", "key-1", "AES-256")
	path := "/hyok/generic/v1/keys/key-1/wrap?tenant_id=tenant-a"
	body := `{"plaintext":"aGVsbG8="}`
	if rr := hyokCall(h, "", http.MethodPost, path, body, "X-Client-CN", "tenant-a:cloud", "X-Client-Subject", "CN=tenant-a:cloud"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("spoofed client-cert headers accepted: %d %s", rr.Code, rr.Body.String())
	}
	if rr := hyokCall(h, "jwt:tenant-b:admin", http.MethodPost, path, body); rr.Code != http.StatusUnauthorized {
		t.Fatalf("other tenant's token accepted: %d", rr.Code)
	}
	if rr := hyokCall(h, "forged", http.MethodPost, path, body); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unverifiable token accepted: %d", rr.Code)
	}
}

// Endpoint administration needs a verified token of the tenant, and a tenant
// administrator to change anything; refusals are audited.
func TestHYOKAdminRoutesRequireTenantAdmin(t *testing.T) {
	h, _, _, _, _, pub := newHYOKHandler(t)
	cfg := `{"enabled":true,"auth_mode":"jwt","governance_required":false}`
	if rr := hyokCall(h, "", http.MethodPut, "/hyok/v1/endpoints/generic?tenant_id=tenant-a", cfg); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated configure: %d", rr.Code)
	}
	if rr := hyokCall(h, "jwt:tenant-b:admin", http.MethodPut, "/hyok/v1/endpoints/generic?tenant_id=tenant-a", cfg); rr.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant configure: %d", rr.Code)
	}
	if rr := hyokCall(h, "jwt:tenant-a:operator", http.MethodPut, "/hyok/v1/endpoints/generic?tenant_id=tenant-a", cfg); rr.Code != http.StatusForbidden {
		t.Fatalf("non-admin configure: %d", rr.Code)
	}
	for _, path := range []string{"/hyok/v1/endpoints?tenant_id=tenant-a", "/hyok/v1/requests?tenant_id=tenant-a", "/hyok/v1/health?tenant_id=tenant-a"} {
		if rr := hyokCall(h, "", http.MethodGet, path, ""); rr.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s: %d", path, rr.Code)
		}
	}
	if rr := hyokCall(h, "", http.MethodDelete, "/hyok/v1/endpoints/generic?tenant_id=tenant-a", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated delete: %d", rr.Code)
	}
	if pub.Count("audit.hyok.admin_refused") == 0 {
		t.Fatal("admin refusals not audited")
	}
	if rr := hyokCall(h, "jwt:tenant-a:admin", http.MethodPut, "/hyok/v1/endpoints/generic?tenant_id=tenant-a", `{"enabled":true,"auth_mode":"mtls"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("unverifiable mtls mode stored: %d %s", rr.Code, rr.Body.String())
	}
	if rr := hyokCall(h, "jwt:tenant-a:admin", http.MethodPut, "/hyok/v1/endpoints/generic?tenant_id=tenant-a", cfg); rr.Code != http.StatusOK {
		t.Fatalf("admin configure refused: %d %s", rr.Code, rr.Body.String())
	}
}

// A governance-gated operation completes when retried with its approval:
// once, and only for the approved key, operation and payload.
func TestHYOKGovernanceApprovalReleasesOperationOnce(t *testing.T) {
	svc, _, keycore, _, gov, pub := newHYOKService(t)
	ctx := context.Background()
	keycore.Seed("tenant-g", "key-g", "AES-256")
	if _, err := svc.ConfigureEndpoint(ctx, EndpointConfig{TenantID: "tenant-g", Protocol: ProtocolGeneric, Enabled: true, AuthMode: AuthModeJWT, GovernanceRequired: true}); err != nil {
		t.Fatal(err)
	}
	id := AuthIdentity{Mode: "jwt", Subject: "u1", TenantID: "tenant-g"}
	req := ProxyCryptoRequest{PlaintextB64: "aGVsbG8="}
	run := func(r ProxyCryptoRequest) (ProxyCryptoResponse, error) {
		return svc.ProcessCrypto(ctx, "tenant-g", ProtocolGeneric, "wrap", "key-g", "/hyok/generic/v1/keys/key-g/wrap", id, r)
	}
	pending, err := run(req)
	if err != nil || pending.Status != "pending_approval" || pending.ApprovalRequestID == "" {
		t.Fatalf("expected pending approval: %+v %v", pending, err)
	}
	retry := req
	retry.ApprovalRequestID = pending.ApprovalRequestID
	if _, err := run(retry); err == nil {
		t.Fatal("released before approval")
	}
	gov.status = map[string]GovernanceApprovalStatus{pending.ApprovalRequestID: {
		Status: "approved", Action: "key.wrap", TargetType: "key", TargetID: "key-g", PayloadHash: approvalPayloadHash(req),
	}}
	other := retry
	other.PlaintextB64 = "b3RoZXI="
	if _, err := run(other); err == nil {
		t.Fatal("approval released a different payload")
	}
	out, err := run(retry)
	if err != nil || out.Status != "ok" || out.CiphertextB64 == "" {
		t.Fatalf("approved operation did not run: %+v %v", out, err)
	}
	if _, err := run(retry); err == nil {
		t.Fatal("approval reused")
	}
	if pub.Count("audit.hyok.approval_refused") == 0 {
		t.Fatal("approval refusals not audited")
	}
}

func lastEventData(subjects []string, payloads [][]byte, subject string) map[string]interface{} {
	for i := len(subjects) - 1; i >= 0; i-- {
		if subjects[i] == subject {
			var ev struct {
				Data map[string]interface{} `json:"data"`
			}
			_ = json.Unmarshal(payloads[i], &ev)
			return ev.Data
		}
	}
	return nil
}

// When key access is deployed but unreachable the proxy refuses with 424
// key_access_unavailable. Until 6.10.0-beta HYOK_POLICY_FAIL_CLOSED=false
// turned the error into an allow; 6.20.0-beta removed that setting.
func TestHYOKKeyAccessFailsClosed(t *testing.T) {
	svc, _, keycore, _, _, pub := newHYOKService(t)
	ctx := context.Background()
	keycore.Seed("tenant-k", "key-k", "AES-256")
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	svc.SetKeyAccess(pkgkeyaccess.Deployed(pkgkeyaccess.NewHTTPClient(url, time.Second)))
	if _, err := svc.ConfigureEndpoint(ctx, EndpointConfig{TenantID: "tenant-k", Protocol: ProtocolGeneric, Enabled: true, AuthMode: AuthModeJWT}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.ProcessCrypto(ctx, "tenant-k", ProtocolGeneric, "wrap", "key-k", "/p", AuthIdentity{Mode: "jwt"}, ProxyCryptoRequest{PlaintextB64: "aGVsbG8="})
	var se serviceError
	if !errors.As(err, &se) || se.HTTPStatus != http.StatusFailedDependency || se.Code != pkgkeyaccess.ReasonUnavailable {
		t.Fatalf("got %v, want 424 key_access_unavailable", err)
	}
	ev := pub.Last("audit.hyok.request_denied")
	if ev["result"] != "refused" || ev["reason"] != pkgkeyaccess.ReasonUnavailable {
		t.Fatalf("refusal event %+v", ev)
	}
	if pub.Count(protocolEventSubject(ProtocolGeneric, "wrap")) != 0 {
		t.Fatal("operation ran while key access was unavailable")
	}
}

// Key access not deployed: the request runs and records why no
// justification was checked.
func TestHYOKKeyAccessNotDeployedAllows(t *testing.T) {
	svc, _, keycore, _, _, pub := newHYOKService(t)
	ctx := context.Background()
	keycore.Seed("tenant-k", "key-k", "AES-256")
	svc.SetKeyAccess(pkgkeyaccess.NotDeployed())
	if _, err := svc.ConfigureEndpoint(ctx, EndpointConfig{TenantID: "tenant-k", Protocol: ProtocolGeneric, Enabled: true, AuthMode: AuthModeJWT}); err != nil {
		t.Fatal(err)
	}
	out, err := svc.ProcessCrypto(ctx, "tenant-k", ProtocolGeneric, "wrap", "key-k", "/p", AuthIdentity{Mode: "jwt"}, ProxyCryptoRequest{PlaintextB64: "aGVsbG8="})
	if err != nil || out.Status != "ok" {
		t.Fatalf("not-deployed request refused: %+v %v", out, err)
	}
	ev := pub.Last(protocolEventSubject(ProtocolGeneric, "wrap"))
	if ev["key_access_reason"] != pkgkeyaccess.ReasonNotDeployed {
		t.Fatalf("request event %+v, want key_access_reason %s", ev, pkgkeyaccess.ReasonNotDeployed)
	}
	if pub.Count("audit.hyok.request_denied") != 0 {
		t.Fatal("not-deployed allow audited as a refusal")
	}
}

// An unreachable policy service refuses the request with 424; there is no
// fail-open setting (6.20.0-beta removed HYOK_POLICY_FAIL_CLOSED).
func TestHYOKPolicyUnavailableFailsClosed(t *testing.T) {
	svc, _, keycore, policy, _, pub := newHYOKService(t)
	ctx := context.Background()
	keycore.Seed("tenant-p", "key-p", "AES-256")
	policy.err = errors.New("policy service down")
	if _, err := svc.ConfigureEndpoint(ctx, EndpointConfig{TenantID: "tenant-p", Protocol: ProtocolGeneric, Enabled: true, AuthMode: AuthModeJWT}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.ProcessCrypto(ctx, "tenant-p", ProtocolGeneric, "wrap", "key-p", "/p", AuthIdentity{Mode: "jwt"}, ProxyCryptoRequest{PlaintextB64: "aGVsbG8="})
	var se serviceError
	if !errors.As(err, &se) || se.HTTPStatus != http.StatusFailedDependency || se.Code != "policy_unavailable" {
		t.Fatalf("got %v, want 424 policy_unavailable", err)
	}
	if ev := pub.Last("audit.hyok.request_denied"); ev["result"] != "refused" || ev["reason"] != "policy_unavailable" {
		t.Fatalf("refusal event %+v", ev)
	}
	if pub.Count(protocolEventSubject(ProtocolGeneric, "wrap")) != 0 {
		t.Fatal("operation event emitted for a refused request")
	}
}
