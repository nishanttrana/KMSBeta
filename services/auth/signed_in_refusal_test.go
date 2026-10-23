package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

// A signed-in caller who gives a wrong password is refused with 403, never
// 401: a client ends the session on 401, so a typo signed the user out. The
// refusal is audited.
func TestWrongPasswordFromASignedInCallerIs403AndAudited(t *testing.T) {
	h, _, store, _ := newTestHandler(t)
	pub := &payloadPublisher{}
	h.events = pub
	hash, _ := HashPassword("Correct-Horse-2026!")
	if err := store.CreateUser(context.Background(), User{ID: "admin-1", TenantID: "t1", Username: "alice", Password: hash, Role: "tenant-admin", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(`{"current_password":"not-it","new_password":"Another-Horse-2026!"}`))
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{TenantID: "t1", Role: "tenant-admin", UserID: "admin-1", Permissions: []string{"*"}}))
	rr := httptest.NewRecorder()
	h.handleChangePassword(rr, req)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "invalid_current_password") {
		t.Fatalf("wrong current password: %d %s", rr.Code, rr.Body.String())
	}
	ev, ok := pub.last("audit.auth.password_change_refused")
	if !ok || eventData(ev)["reason"] != "invalid_current_password" || eventData(ev)["result"] != "refused" {
		t.Fatalf("the refusal must be audited: %+v", ev)
	}
	if _, changed := pub.last("audit.auth.password_changed"); changed {
		t.Fatal("a refused change was audited as a change")
	}
	user, err := store.GetUserByID(context.Background(), "t1", "admin-1")
	if err != nil || !VerifyPassword(user.Password, "Correct-Horse-2026!") {
		t.Fatal("the password changed despite the refusal")
	}

	cliHash, _ := HashPassword("Cli-Correct-2026!")
	if err := store.CreateUser(context.Background(), User{ID: "c1", TenantID: "t1", Username: "cli-user", Password: cliHash, Role: "cli-user", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.handleCLISession(rr, cliSessionRequest(t, "wrong-password-entirely"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("wrong CLI password: %d %s", rr.Code, rr.Body.String())
	}
}
