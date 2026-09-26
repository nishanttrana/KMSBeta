package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgcache "vecta-kms/pkg/cache"
	"vecta-kms/pkg/metering"
)

// eventRecorder keeps every published audit payload.
type eventRecorder struct {
	mu     sync.Mutex
	events []map[string]any
}

func (r *eventRecorder) Publish(_ context.Context, subject string, payload []byte) error {
	var ev map[string]any
	_ = json.Unmarshal(payload, &ev)
	if ev == nil {
		ev = map[string]any{}
	}
	ev["_subject"] = subject
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
	return nil
}

func (r *eventRecorder) find(subject string) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.events) - 1; i >= 0; i-- {
		if r.events[i]["_subject"] == subject {
			return r.events[i]
		}
	}
	return nil
}

func newActorTestHandler(t *testing.T) (*Handler, *Service, *eventRecorder) {
	t.Helper()
	rec := &eventRecorder{}
	svc := NewService(newStoreForTest(t), NewKeyCache(pkgcache.NewMemory(5*time.Minute), 5*time.Minute), rec,
		metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	return NewHandler(svc), svc, rec
}

func ownedKey(t *testing.T, svc *Service) Key {
	t.Helper()
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "owned", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "owner-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// encryptAs calls POST /keys/{id}/encrypt with verified claims (nil: no
// token) and the given headers.
func encryptAs(h *Handler, keyID string, claims *pkgauth.Claims, headers map[string]string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"tenant_id": "t1", "plaintext": "aGVsbG8="})
	req := httptest.NewRequest(http.MethodPost, "/keys/"+keyID+"/encrypt?tenant_id=t1", bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if claims != nil {
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func refusalDetails(t *testing.T, rec *eventRecorder, subject string) map[string]any {
	t.Helper()
	ev := rec.find(subject)
	if ev == nil {
		t.Fatalf("no %s event", subject)
	}
	if ev["result"] != "refused" {
		t.Fatalf("%s result = %v, want refused", subject, ev["result"])
	}
	d, _ := ev["details"].(map[string]any)
	if d == nil || d["reason"] == nil || d["reason"] == "" {
		t.Fatalf("%s has no reason: %+v", subject, ev)
	}
	return d
}

var spoofAdmin = map[string]string{
	"X-Actor-Permissions": "*",
	"X-Actor-Role":        "admin",
	"X-Actor-Groups":      "admins",
	"X-KMS-Subject":       "owner-1",
}

// A verified token that carries no permissions can't grant itself admin
// through headers: the request is refused and audited with a reason.
func TestActorHeadersCannotGrantAccess(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	key := ownedKey(t, svc)
	mallory := &pkgauth.Claims{UserID: "mallory", TenantID: "t1", Role: "viewer"}

	w := encryptAs(h, key.ID, mallory, spoofAdmin)
	if w.Code != http.StatusForbidden {
		t.Fatalf("spoofed admin headers: status %d, want 403 (%s)", w.Code, w.Body)
	}
	d := refusalDetails(t, rec, "audit.key.access_refused")
	if d["reason"] != "not_assigned_to_caller" || d["actor"] != "mallory" || d["unverified_actor_headers"] == nil {
		t.Fatalf("access_refused details: %+v", d)
	}
	ignored := refusalDetails(t, rec, "audit.key.actor_headers_ignored")
	if ignored["reason"] != "unverified_identity_headers" {
		t.Fatalf("actor_headers_ignored details: %+v", ignored)
	}

	// A verified admin is still allowed, headers or not.
	admin := &pkgauth.Claims{UserID: "root-admin", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	if w := encryptAs(h, key.ID, admin, nil); w.Code != http.StatusOK {
		t.Fatalf("verified admin refused: %d %s", w.Code, w.Body)
	}
}

// Without any token, headers no longer make a caller "authenticated" or an
// admin: under deny-by-default the request is refused.
func TestActorHeadersWithoutTokenAreNotAnIdentity(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	key := ownedKey(t, svc)
	if _, err := svc.store.UpsertKeyAccessSettings(context.Background(), KeyAccessSettings{TenantID: "t1", DenyByDefault: true}); err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"X-Actor-User-ID": "owner-1", "X-Actor-Role": "admin", "X-Actor-Permissions": "*"}
	if w := encryptAs(h, key.ID, nil, headers); w.Code != http.StatusForbidden {
		t.Fatalf("headers without a token: status %d, want 403 (%s)", w.Code, w.Body)
	}
	if d := refusalDetails(t, rec, "audit.key.access_refused"); d["reason"] != "authentication_required" || d["authenticated"] != false {
		t.Fatalf("details: %+v", d)
	}
}

// Group grants match only groups the store holds for the verified user,
// never a group named in X-Actor-Groups.
func TestActorGroupsHeaderDoesNotMatchGrants(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	key := ownedKey(t, svc)
	if err := svc.store.ReplaceKeyAccessGrants(context.Background(), "t1", key.ID, []KeyAccessGrant{
		{SubjectType: AccessSubjectGroup, SubjectID: "crypto-ops", Operations: []string{"encrypt"}},
	}, "owner-1"); err != nil {
		t.Fatal(err)
	}
	mallory := &pkgauth.Claims{UserID: "mallory", TenantID: "t1", Role: "viewer"}
	if w := encryptAs(h, key.ID, mallory, map[string]string{"X-Actor-Groups": "crypto-ops"}); w.Code != http.StatusForbidden {
		t.Fatalf("spoofed group: status %d, want 403 (%s)", w.Code, w.Body)
	}
	if d := refusalDetails(t, rec, "audit.key.access_refused"); d["reason"] != "no_matching_grant" {
		t.Fatalf("details: %+v", d)
	}
}

// The interface a policy applies to isn't taken from a header, and header
// identity never fills an actor field a policy reads.
func TestActorBuiltFromVerifiedClaimsOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/keys/k/encrypt", nil)
	for k, v := range spoofAdmin {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-KMS-Interface", "kmip")
	req.Header.Set("X-Actor-User-ID", "owner-1")
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{UserID: "mallory", TenantID: "t1"}))
	a := accessActorFromHTTPRequest(req)
	if a.Role != "" || len(a.Permissions) != 0 || len(a.Groups) != 0 || a.SubjectID != "" || a.UserID != "mallory" || a.InterfaceName != "rest" {
		t.Fatalf("actor took identity from headers: %+v", a)
	}
	if !a.Unverified.Present() || a.Unverified.Role != "admin" || a.Unverified.Interface != "kmip" {
		t.Fatalf("unverified context not kept for audit: %+v", a.Unverified)
	}
	if actorIsAdmin(a) {
		t.Fatal("header role made the caller an admin")
	}
}

// A key with no grants, in a tenant without deny-by-default, used to be
// open to any caller without a token. Now every key use needs a verified
// identity; the creator, an admin and a service principal still work.
func TestAnonymousKeyUseIsRefused(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	key := ownedKey(t, svc) // created by owner-1, no grants

	if w := encryptAs(h, key.ID, nil, nil); w.Code != http.StatusForbidden {
		t.Fatalf("no token: status %d, want 403 (%s)", w.Code, w.Body)
	}
	d := refusalDetails(t, rec, "audit.key.access_refused")
	if d["reason"] != "authentication_required" || d["authenticated"] != false || d["actor"] != "unauthenticated" {
		t.Fatalf("refusal details: %+v", d)
	}

	creator := &pkgauth.Claims{UserID: "owner-1", TenantID: "t1", Role: "operator"}
	service := &pkgauth.Claims{ClientID: "kms-compliance", TenantID: "root", Role: "client-service", Permissions: []string{"service.internal"}}
	service.Subject = "kms-compliance"
	for name, c := range map[string]*pkgauth.Claims{"creator": creator, "service principal": service} {
		if w := encryptAs(h, key.ID, c, nil); w.Code != http.StatusOK {
			t.Fatalf("%s refused: %d %s", name, w.Code, w.Body)
		}
	}
}
