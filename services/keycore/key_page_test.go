package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

// Every key listing says whether more follow, judged on the rows read: a
// page holding a deleted key is still full, and the first page answers
// has_more too (13.24.0-beta). A request above 1000 is held to 1000, not
// cut to 100.
func TestKeyListSaysWhetherMoreFollow(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	for _, name := range []string{"k1", "k2", "k3"} {
		if _, err := svc.CreateKey(context.Background(), CreateKeyRequest{TenantID: "t1", Name: name, Algorithm: "AES-256",
			KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "root-admin"}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := svc.store.ListKeys(context.Background(), "t1", 3, 0)
	if err != nil || len(page) != 3 {
		t.Fatalf("seed: %d %v", len(page), err)
	}
	// The newest key is deleted: it fills a row of the first page.
	if err := svc.store.SetKeyStatus(context.Background(), "t1", page[0].ID, "deleted"); err != nil {
		t.Fatal(err)
	}
	list := func(query string) (items int, more bool, cursor bool) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/keys?tenant_id=t1&"+query, nil)
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), visAdmin))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var out struct {
			Items      []json.RawMessage `json:"items"`
			HasMore    bool              `json:"has_more"`
			NextCursor map[string]string `json:"next_cursor"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatalf("list %s: %d %s", query, w.Code, w.Body)
		}
		return len(out.Items), out.HasMore, out.NextCursor != nil
	}
	if n, more, cursor := list("limit=2&offset=0"); n != 1 || !more || !cursor {
		t.Fatalf("first page: %d items, has_more %v, cursor %v; want 1, true, true", n, more, cursor)
	}
	if n, more, _ := list("limit=2&offset=2"); n != 1 || more {
		t.Fatalf("last page: %d items, has_more %v; want 1, false", n, more)
	}
	if got := keyPageLimit(5000); got != keyPageMax {
		t.Fatalf("a 5000-row request is held to %d, want %d", got, keyPageMax)
	}
}

// q searches names and IDs inside the caller's scope: a restricted user
// finds only keys they could list, LIKE wildcards are literal, and deleted
// keys are left out (13.25.0-beta).
func TestKeySearchStaysInScope(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	for _, k := range []struct{ name, by string }{{"payments_db", "alice"}, {"paymentsXdb", "alice"}, {"payments_api", "bob"}, {"payroll", "alice"}} {
		if _, err := svc.CreateKey(context.Background(), CreateKeyRequest{TenantID: "t1", Name: k.name, Algorithm: "AES-256",
			KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: k.by}); err != nil {
			t.Fatal(err)
		}
	}
	search := func(claims *pkgauth.Claims, q string) []string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/keys?tenant_id=t1&q="+q, nil)
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var out struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatalf("search %q: %d %s", q, w.Code, w.Body)
		}
		names := []string{}
		for _, it := range out.Items {
			names = append(names, it.Name)
		}
		return names
	}
	if got := search(visAdmin, "PAYMENTS"); len(got) != 3 {
		t.Fatalf("admin search: %v", got)
	}
	if got := search(visAlice, "payments"); len(got) != 2 {
		t.Fatalf("alice sees only her own keys: %v", got)
	}
	if got := search(visAdmin, "payments_"); len(got) != 2 {
		t.Fatalf("_ is literal, so paymentsXdb does not match: %v", got)
	}
	all, _ := svc.store.SearchKeys(context.Background(), "t1", nil, "payroll", 10)
	if err := svc.store.SetKeyStatus(context.Background(), "t1", all[0].ID, "deleted"); err != nil {
		t.Fatal(err)
	}
	if got := search(visAdmin, "payroll"); len(got) != 0 {
		t.Fatalf("a deleted key is not found: %v", got)
	}
}
