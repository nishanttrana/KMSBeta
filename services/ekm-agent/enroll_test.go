package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRegistrationTenantReadsOnlyRegistrationTokens(t *testing.T) {
	if got, err := registrationTenant("vekm-reg.dDE.ekm_1.c2VjcmV0"); err != nil || got != "t1" {
		t.Fatalf("tenant %q, %v", got, err)
	}
	for _, bad := range []string{"", "eyJhbGciOi.x.y", "vekm-reg.dDE.ekm_1", "vekm-reg..ekm_1.s", "other.dDE.ekm_1.s"} {
		if _, err := registrationTenant(bad); err == nil {
			t.Errorf("%q was read as a registration token", bad)
		}
	}
}

// The token is never sent over plain HTTP, and a missing token file is an
// error before any request is made.
func TestEnrollRefusesAPlainHTTPServer(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("vekm-reg.dDE.ekm_1.c2VjcmV0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Enroll(context.Background(), "http://kms.example.com/svc/ekm", tok, "", filepath.Join(dir, "cfg.json")); err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("plain HTTP server: %v", err)
	}
	if _, err := os.Stat(tok); err != nil {
		t.Fatal("the token file was removed although nothing was registered")
	}
	if _, err := Enroll(context.Background(), "https://kms.example.com/svc/ekm", filepath.Join(dir, "missing"), "", filepath.Join(dir, "cfg.json")); err == nil {
		t.Fatal("a missing token file was accepted")
	}
}

func TestConfigWithAClientKeyIsPrivateAndChecksIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "agent-config.json")
	in := AgentConfig{TenantID: "t1", AgentID: "ekm_1", AgentName: "PG-01", DBEngine: "postgresql", Host: "pg01", APIBaseURL: "https://kms.example.com/svc/ekm", ClientKey: "k"}
	if err := writeConfig(path, in); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("config mode %v, %v: it holds the client key", st.Mode().Perm(), err)
	}
	cfg, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatalf("an enrolled PostgreSQL client's config was refused: %v", err)
	}
	if cfg.HeartbeatPath != "/ekm/clients/{agent_id}/check-in" {
		t.Fatalf("an enrolled client checks in at %s", cfg.HeartbeatPath)
	}
	raw, _ := json.Marshal(AgentConfig{TenantID: "t1"})
	if strings.Contains(string(raw), "client_key") {
		t.Fatal("an agent without a client key writes an empty one")
	}
}
