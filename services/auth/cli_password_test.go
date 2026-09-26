package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

type payloadPublisher struct {
	mu     sync.Mutex
	events map[string][]map[string]any
}

func (p *payloadPublisher) Publish(_ context.Context, subject string, raw []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.events == nil {
		p.events = map[string][]map[string]any{}
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	p.events[subject] = append(p.events[subject], m)
	return nil
}

func (p *payloadPublisher) last(subject string) (map[string]any, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	evs := p.events[subject]
	if len(evs) == 0 {
		return nil, false
	}
	return evs[len(evs)-1], true
}

func eventData(ev map[string]any) map[string]any {
	if d, ok := ev["data"].(map[string]any); ok {
		return d
	}
	return ev
}

// fakeDocker answers the Docker API calls the exec path makes and records
// every exec request body.
type fakeDocker struct {
	mu    sync.Mutex
	execs []map[string]any
}

func (f *fakeDocker) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/containers/json":
		_, _ = rec.WriteString(`[{"Id":"c1","State":"running","Labels":{"com.docker.compose.service":"hsm-integration"}}]`)
	case r.Method == http.MethodPost && r.URL.Path == "/containers/c1/exec":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.execs = append(f.execs, body)
		f.mu.Unlock()
		rec.WriteHeader(http.StatusCreated)
		_, _ = rec.WriteString(`{"Id":"e1"}`)
	case r.Method == http.MethodPost && r.URL.Path == "/exec/e1/start":
	case r.Method == http.MethodGet && r.URL.Path == "/exec/e1/json":
		_, _ = rec.WriteString(`{"Running":false,"ExitCode":0}`)
	default:
		rec.WriteHeader(http.StatusNotFound)
	}
	return rec.Result(), nil
}

func TestCLIBootstrapPasswordRefusesThePublicDefault(t *testing.T) {
	err := validateCLIBootstrapPassword(retiredCLIPassword)
	if err == nil {
		t.Fatal("the public CLI password must be refused")
	}
	if strings.Contains(err.Error(), retiredCLIPassword) {
		t.Fatal("the refusal must not repeat the password")
	}
	if validateCLIBootstrapPassword("Vk3xQ9mZt7Lw2pRbAa9!") != nil {
		t.Fatal("a generated password must be accepted")
	}
}

// A CLI user still holding the public password gets a random one, the
// change is audited, and its SSH copy is locked.
func TestRevokeRetiredCLIPasswords(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	if err := store.CreateTenant(ctx, Tenant{ID: "root", Name: "Root", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	public, _ := HashPassword(retiredCLIPassword)
	other, _ := HashPassword("Vk3xQ9mZt7Lw2pRbAa9!")
	for _, u := range []User{
		{ID: "u1", TenantID: "root", Username: "cli-user", Password: public, Role: "cli-user", Status: "active"},
		{ID: "u2", TenantID: "root", Username: "cli-two", Password: other, Role: "cli-user", Status: "active"},
		{ID: "u3", TenantID: "root", Username: "admin", Password: public, Role: "admin", Status: "active"},
	} {
		if err := store.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	pub := &payloadPublisher{}
	var locked []string
	n := revokeRetiredCLIPasswords(ctx, store, quietLogger(), pub, func(_ context.Context, user string) error {
		locked = append(locked, user)
		return nil
	})
	if n != 1 || len(locked) != 1 || locked[0] != "cli-user" {
		t.Fatalf("only the CLI user on the public password is revoked: n=%d locked=%v", n, locked)
	}
	u, _ := store.GetUserByUsername(ctx, "root", "cli-user")
	if VerifyPassword(u.Password, retiredCLIPassword) || !u.MustChangePassword {
		t.Fatal("the public password must no longer work, and a change is forced")
	}
	if u2, _ := store.GetUserByUsername(ctx, "root", "cli-two"); !VerifyPassword(u2.Password, "Vk3xQ9mZt7Lw2pRbAa9!") {
		t.Fatal("other CLI users are untouched")
	}
	ev, ok := pub.last("audit.auth.cli_password_revoked")
	if !ok || eventData(ev)["reason"] != "public_default_password" || eventData(ev)["ssh_account"] != "locked" {
		t.Fatalf("the revocation must be audited: %+v", ev)
	}
	if again := revokeRetiredCLIPasswords(ctx, store, quietLogger(), pub, nil); again != 0 {
		t.Fatalf("a second start revokes nothing, got %d", again)
	}
}

func cliSessionRequest(t *testing.T, password string) *http.Request {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "cli-user", "password": password})
	req := httptest.NewRequest(http.MethodPost, "/auth/cli/session", bytes.NewReader(body))
	return req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{TenantID: "t1", Role: "tenant-admin", UserID: "admin-1"}))
}

func TestCLISessionRefusesThePublicPasswordAndAuditsRefusals(t *testing.T) {
	h, _, store, _ := newTestHandler(t)
	pub := &payloadPublisher{}
	h.events = pub
	hash, _ := HashPassword(retiredCLIPassword)
	if err := store.CreateUser(context.Background(), User{ID: "c1", TenantID: "t1", Username: "cli-user", Password: hash, Role: "cli-user", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ password, reason string }{
		{retiredCLIPassword, "public_default_password"},
		{"wrong-password-entirely", "invalid_credentials"},
	} {
		rr := httptest.NewRecorder()
		h.handleCLISession(rr, cliSessionRequest(t, tc.password))
		if rr.Code == http.StatusOK {
			t.Fatalf("%s: a session must be refused", tc.reason)
		}
		if strings.Contains(rr.Body.String(), retiredCLIPassword) {
			t.Fatal("the response must not echo the password")
		}
		ev, ok := pub.last("audit.auth.cli_session_refused")
		if !ok || eventData(ev)["reason"] != tc.reason || eventData(ev)["result"] != "refused" {
			t.Fatalf("%s: the refusal must be audited: %+v", tc.reason, ev)
		}
	}
}

// The password reaches the container in the exec's environment, never in
// its command line, and the copy is audited.
func TestCLISSHPasswordSyncKeepsThePasswordOffTheCommandLine(t *testing.T) {
	h, _, _, _ := newTestHandler(t)
	pub := &payloadPublisher{}
	h.events = pub
	docker := &fakeDocker{}
	h.healthChecker = &SystemHealthChecker{restartHTTP: &http.Client{Transport: docker}, composeProject: "vecta-kms"}
	const password = "Vk3xQ9mZt7Lw2pRbAa9!"
	h.syncCLISSHPassword("t1", "admin-1", "cli-user", password)

	if len(docker.execs) != 1 {
		t.Fatalf("one exec expected, got %d", len(docker.execs))
	}
	exec := docker.execs[0]
	cmd, _ := json.Marshal(exec["Cmd"])
	if strings.Contains(string(cmd), password) || strings.Contains(string(cmd), "base64") {
		t.Fatalf("the password must not be on the command line: %s", cmd)
	}
	env, _ := json.Marshal(exec["Env"])
	if !strings.Contains(string(env), "VECTA_CLI_PASSWORD="+password) {
		t.Fatal("the password must be passed in the exec environment")
	}
	ev, ok := pub.last("audit.auth.cli_ssh_password_synced")
	if !ok || eventData(ev)["result"] != "success" {
		t.Fatalf("the sync must be audited: %+v", ev)
	}
	raw, _ := json.Marshal(ev)
	if strings.Contains(string(raw), password) {
		t.Fatal("the audit event must not contain the password")
	}
}
