package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

var (
	visAlice   = &pkgauth.Claims{UserID: "alice", TenantID: "t1", Role: "operator", Permissions: []string{"key.usage.read", "key.access.read"}}
	visAuditor = &pkgauth.Claims{UserID: "aud", TenantID: "t1", Role: "auditor", Permissions: []string{"key.inventory.read"}}
	visAdmin   = &pkgauth.Claims{UserID: "root-admin", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
)

// visibilityFixture: alice created k1; bob created the rest. k3 has a read
// grant to alice, k4 an expired grant, k5 a grant to someone else.
func visibilityFixture(t *testing.T, svc *Service) map[string]Key {
	t.Helper()
	keys := map[string]Key{}
	for name, creator := range map[string]string{"k1": "alice", "k2": "bob", "k3": "bob", "k4": "bob", "k5": "bob"} {
		k, err := svc.CreateKey(context.Background(), CreateKeyRequest{TenantID: "t1", Name: name, Algorithm: "AES-256",
			KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: creator})
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = k
	}
	past := time.Now().UTC().Add(-time.Hour)
	grant := func(key, subject string, ops []string, expires *time.Time) {
		if err := svc.store.ReplaceKeyAccessGrants(context.Background(), "t1", keys[key].ID, []KeyAccessGrant{
			{SubjectType: AccessSubjectUser, SubjectID: subject, Operations: ops, ExpiresAt: expires},
		}, "bob"); err != nil {
			t.Fatal(err)
		}
	}
	grant("k3", "Alice", []string{"read"}, nil) // user match is case-insensitive, as in evaluateKeyAccess
	grant("k4", "alice", []string{"encrypt"}, &past)
	grant("k5", "carol", []string{"encrypt"}, nil)
	return keys
}

func listNames(t *testing.T, h *Handler, claims *pkgauth.Claims) []string {
	t.Helper()
	w := callKeycore(h, http.MethodGet, "/keys", "", claims)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var out struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	names := []string{}
	for _, it := range out.Items {
		names = append(names, it.Name)
	}
	return names
}

func serveWith(h *Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func sameSet(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g] = true
	}
	for _, w := range want {
		if !seen[w] {
			return false
		}
	}
	return true
}

// A user sees only the keys they created or hold an active grant on; an
// admin and a key.inventory.read holder see every key.
func TestKeyListShowsOnlyVisibleKeys(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	visibilityFixture(t, svc)
	if got := listNames(t, h, visAlice); !sameSet(got, "k1", "k3") {
		t.Fatalf("alice sees %v, want k1 and k3", got)
	}
	for name, c := range map[string]*pkgauth.Claims{"admin": visAdmin, "auditor": visAuditor} {
		if got := listNames(t, h, c); len(got) != 5 {
			t.Fatalf("%s sees %v, want all 5", name, got)
		}
	}
	nobody := &pkgauth.Claims{UserID: "dave", TenantID: "t1", Role: "operator"}
	if got := listNames(t, h, nobody); len(got) != 0 {
		t.Fatalf("a user with no keys sees %v", got)
	}
}

// The filter runs in the query, so a restricted caller gets full pages.
// (Cursor paging is proven on Postgres: SQLite keeps created_at as
// second-resolution text, which the (created_at, id) cursor can't order.)
func TestScopedKeyListPagesFully(t *testing.T) {
	_, svc, _ := newActorTestHandler(t)
	for i := 0; i < 5; i++ {
		creator := "bob"
		if i%2 == 0 {
			creator = "alice"
		}
		if _, err := svc.CreateKey(context.Background(), CreateKeyRequest{TenantID: "t1", Name: "p" + string(rune('a'+i)), Algorithm: "AES-256",
			KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: creator}); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/keys", nil)
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), visAlice))
	view, err := svc.keyViewFor(contextWithAccessActor(req.Context(), accessActorFromHTTPRequest(req)), "t1")
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.ListKeys(context.Background(), "t1", view, 2, 0, false)
	if err != nil || len(first) != 2 {
		t.Fatalf("first page: %d keys, %v", len(first), err)
	}
	rest, err := svc.ListKeys(context.Background(), "t1", view, 2, 2, false)
	if err != nil || len(rest) != 1 {
		t.Fatalf("second page: %d keys, %v", len(rest), err)
	}
	for _, k := range append(first, rest...) {
		if k.CreatedBy != "alice" {
			t.Fatalf("page leaked %s by %s", k.Name, k.CreatedBy)
		}
	}
}

// Reading a hidden key answers exactly like reading a missing one, and the
// refusal is audited with reason not_visible.
func TestHiddenKeyReadsLookMissingAndAreAudited(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	keys := visibilityFixture(t, svc)
	hidden := keys["k2"].ID
	for _, path := range []string{"/keys/" + hidden, "/keys/" + hidden + "/versions", "/keys/" + hidden + "/kcv",
		"/keys/" + hidden + "/usage", "/keys/" + hidden + "/consumers", "/keys/" + hidden + "/access-policy"} {
		w := callKeycore(h, http.MethodGet, path, "", visAlice)
		missing := callKeycore(h, http.MethodGet, "/keys/key_does_not_exist"+path[len("/keys/"+hidden):], "", visAlice)
		if w.Code != http.StatusNotFound || missing.Code != http.StatusNotFound || errCode(w) != errCode(missing) {
			t.Fatalf("%s: hidden %d %s, missing %d %s", path, w.Code, w.Body, missing.Code, missing.Body)
		}
		d := refusalDetails(t, rec, "audit.key.access_refused")
		if d["reason"] != "not_visible" || d["operation"] != "read" || d["key_id"] != hidden {
			t.Fatalf("%s: refusal details %+v", path, d)
		}
	}
	if w := callKeycore(h, http.MethodGet, "/keys/"+hidden, "", visAuditor); w.Code != http.StatusOK {
		t.Fatalf("auditor can't read: %d %s", w.Code, w.Body)
	}
}

// A read grant shows the key but allows no operation on it.
func TestReadGrantIsViewOnly(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	keys := visibilityFixture(t, svc)
	if w := callKeycore(h, http.MethodGet, "/keys/"+keys["k3"].ID, "", visAlice); w.Code != http.StatusOK {
		t.Fatalf("read grant can't read: %d %s", w.Code, w.Body)
	}
	if w := encryptAs(h, keys["k3"].ID, visAlice, nil); w.Code != http.StatusForbidden {
		t.Fatalf("read grant encrypted: %d %s", w.Code, w.Body)
	}
	if d := refusalDetails(t, rec, "audit.key.access_refused"); d["operation"] != "encrypt" {
		t.Fatalf("details %+v", d)
	}
}

// Another tenant's key is refused as a tenant mismatch before any lookup, so
// the answer doesn't depend on whether the key exists there.
func TestHiddenKeyCheckNeverCrossesTenants(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	other, err := svc.CreateKey(context.Background(), CreateKeyRequest{TenantID: "t2", Name: "x", Algorithm: "AES-256",
		KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "eve"})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{other.ID, "key_does_not_exist"} {
		req := routetest.Request("GET /keys/{id}", visAlice, "tenant_id=t2")
		req.SetPathValue("id", id)
		req.URL.Path = "/keys/" + id
		if w := serveWith(h, req); w.Code != http.StatusForbidden {
			t.Fatalf("%s in another tenant: %d %s", id, w.Code, w.Body)
		}
	}
}

func TestInventoryRoutesRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.inventoryRouter(rec), rec)
}

// Tenant-wide views need key.inventory.read.
func TestInventoryViewsNeedInventoryPermission(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	if w := callKeycore(h, http.MethodGet, "/inventory/keys", "", visAlice); w.Code != http.StatusForbidden {
		t.Fatalf("alice read the inventory: %d", w.Code)
	}
	if w := callKeycore(h, http.MethodGet, "/inventory/keys", "", visAuditor); w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
		t.Fatalf("auditor refused: %d %s", w.Code, w.Body)
	}
}

func errCode(w *httptest.ResponseRecorder) string {
	var out struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out.Error.Code
}
