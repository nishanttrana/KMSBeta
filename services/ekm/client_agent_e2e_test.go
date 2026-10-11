package main

import (
	"encoding/pem"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The real agent binary enrols against the real service over TLS 1.3 with a
// one-time token, then checks in with the client key it was issued. Nothing
// here is a double: this is the path a database host takes.
func TestAgentBinaryEnrolsAndChecksIn(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the agent binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "vecta-ekm-agent")
	if out, err := exec.Command("go", "build", "-o", bin, "../ekm-agent").CombinedOutput(); err != nil {
		t.Fatalf("build agent: %v\n%s", err, out)
	}

	r := newClientRig(t)
	srv := httptest.NewTLSServer(r.h)
	defer srv.Close()
	ca := filepath.Join(dir, "kms-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	server := srv.URL

	id := r.create("ORCL-PROD-01")
	tokenFile, cfg := filepath.Join(dir, "registration-token"), filepath.Join(dir, "etc", "agent-config.json")
	if err := os.WriteFile(tokenFile, []byte(r.token(id)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(bin, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("agent %v: %v\n%s", args[:1], err, out)
		}
		return string(out)
	}
	out := run("-enroll", "-server", server, "-token-file", tokenFile, "-ca", ca, "-config", cfg)
	if !strings.Contains(out, "registered as ORCL-PROD-01") {
		t.Fatalf("enroll output: %s", out)
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Fatal("the used registration token is still on disk")
	}
	if st, err := os.Stat(cfg); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("agent config: %v %v", st, err)
	}
	c := r.view(id)["client"].(map[string]interface{})
	if c["registration"] != "registered" || c["health"] != "healthy" || c["credential"] != "client_key" || !strings.HasPrefix(c["version"].(string), "vecta-ekm-agent/") {
		t.Fatalf("after enrolment: %+v", c)
	}

	// A second agent with the same token is turned away.
	if err := os.WriteFile(tokenFile, []byte("vekm-reg.dDE."+id+".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "-enroll", "-server", server, "-token-file", tokenFile, "-ca", ca, "-config", filepath.Join(dir, "other.json")).CombinedOutput(); err == nil || !strings.Contains(string(out), "invalid_registration_token") {
		t.Fatalf("a made-up token enrolled: %v\n%s", err, out)
	}

	r.setLastSeen(id, 0)
	run("-once", "-config", cfg)
	detail := r.view(id)
	if n := len(detail["check_ins"].([]interface{})); n != 2 {
		t.Fatalf("check-ins after enrolment and one run: %d, want 2", n)
	}
	if ev := r.rec.Last(t); ev.Action != "client_read" {
		t.Fatalf("last event: %+v", ev)
	}
	var sawCheckIn bool
	for _, ev := range r.rec.Events() {
		if ev.Action == "client_check_in" && ev.Event.Result == "success" && ev.Event.ActorID == id {
			sawCheckIn = true
		}
	}
	if !sawCheckIn {
		t.Fatal("the agent's check-in was not audited with the client as its actor")
	}
}
