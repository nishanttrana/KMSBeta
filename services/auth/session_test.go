package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// One sign-in is one session: its token names it, a refresh keeps it, and
// the audit trail can follow it. Sign-out ends the session the token names
// (never one a body names), and its tokens can no longer renew.
func TestSessionFollowsRefreshAndEndsAtSignOut(t *testing.T) {
	h, logic, store, pub := newTestHandler(t)
	hash, _ := HashPassword("S3ssion@Pass2026")
	if err := store.CreateUser(context.Background(), User{
		ID: "u-sess", TenantID: "t1", Username: "sess", Email: "sess@example.com",
		Password: hash, Role: "tenant-admin", Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	call := func(method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	tokenOf := func(rr *httptest.ResponseRecorder) string {
		t.Helper()
		var resp struct {
			AccessToken string `json:"access_token"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		if rr.Code != http.StatusOK || resp.AccessToken == "" {
			t.Fatalf("status %d body %s", rr.Code, rr.Body)
		}
		return resp.AccessToken
	}
	sidOf := func(token string) string {
		t.Helper()
		claims, err := logic.ParseJWT(token)
		if err != nil {
			t.Fatal(err)
		}
		return claims.SessionID
	}
	signIn := func() string {
		raw, _ := json.Marshal(map[string]any{"tenant_id": "t1", "username": "sess", "password": "S3ssion@Pass2026"})
		return tokenOf(call(http.MethodPost, "/auth/login", "", string(raw)))
	}

	first := signIn()
	sid := sidOf(first)
	if !strings.HasPrefix(sid, "sess_") {
		t.Fatalf("a signed-in token must name its session, got sid %q", sid)
	}
	if !publishedWith(pub, "audit.auth.login", "session_id", sid) {
		t.Fatal("the login event must name the session")
	}
	refreshed := tokenOf(call(http.MethodPost, "/auth/refresh", first, ""))
	if got := sidOf(refreshed); got != sid {
		t.Fatalf("a refresh moved the token to session %q, want %q", got, sid)
	}

	// A second sign-in is another session. Signing out of it with a body
	// naming the first one ends only the caller's own.
	other := signIn()
	if sidOf(other) == sid {
		t.Fatal("two sign-ins share a session")
	}
	if rr := call(http.MethodPost, "/auth/logout", other, `{"session_id":"`+sid+`"}`); rr.Code != http.StatusOK {
		t.Fatalf("logout status %d: %s", rr.Code, rr.Body)
	}
	if !publishedWith(pub, "audit.auth.logout", "session_id", sidOf(other)) {
		t.Fatal("the logout event must name the session it ended")
	}
	tokenOf(call(http.MethodPost, "/auth/refresh", refreshed, "")) // the first session lives on

	// After sign-out, its tokens no longer renew, and the refusal is audited.
	rr := call(http.MethodPost, "/auth/refresh", other, "")
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "session_ended") {
		t.Fatalf("refresh after sign-out: status %d body %s", rr.Code, rr.Body)
	}
	if !publishedWith(pub, "audit.auth.refresh_refused", "reason", "session_ended") {
		t.Fatal("a refused refresh must be audited with its reason")
	}

	// The console signs out with no body at all.
	if rr := call(http.MethodPost, "/auth/logout", refreshed, ""); rr.Code != http.StatusOK {
		t.Fatalf("logout without a body: status %d: %s", rr.Code, rr.Body)
	}
	if rr := call(http.MethodPost, "/auth/refresh", refreshed, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("refresh after the console's sign-out: status %d", rr.Code)
	}

	// A token that names no session (issued before sessions were in
	// tokens) lives to its expiry and does not renew.
	bare, _, err := logic.IssueJWT("t1", "tenant-admin", []string{"*"}, "u-sess", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if rr := call(http.MethodPost, "/auth/refresh", bare, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("refresh of a token with no session: status %d", rr.Code)
	}
	if ok, err := store.TouchSession(context.Background(), "t1", "sess_missing", []byte("h"), time.Now()); err != nil || ok {
		t.Fatalf("TouchSession on no session = %v, %v", ok, err)
	}
}

// publishedWith reports whether an event with subject was published with
// data[key] == want.
func publishedWith(pub *mockPublisher, subject, key, want string) bool {
	for i, s := range pub.subjects {
		if s != subject {
			continue
		}
		var msg struct {
			Data map[string]any `json:"data"`
		}
		if json.NewDecoder(bytes.NewReader(pub.payloads[i])).Decode(&msg) == nil && msg.Data[key] == want {
			return true
		}
	}
	return false
}
