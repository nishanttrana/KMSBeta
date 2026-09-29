package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// policyServer is an httptest stand-in for the policy service's
// /policies routes: one policy per (tenant, name), like its UNIQUE index.
type policyServer struct {
	mu       sync.Mutex
	byName   map[string]appliedPolicy
	writes   []string // "POST name" / "PUT id"
	failList bool
}

func (s *policyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Query().Get("tenant_id") == "" && r.Method != http.MethodPost {
		http.Error(w, "tenant_id required", http.StatusBadRequest)
		return
	}
	var body struct{ YAML string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	name := ""
	if i := strings.Index(body.YAML, "name: "); i >= 0 {
		name = strings.Fields(body.YAML[i+6:])[0]
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/policies":
		if s.failList {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		items := []appliedPolicy{}
		for _, p := range s.byName {
			items = append(items, p)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
	case r.Method == http.MethodPost && r.URL.Path == "/policies":
		if _, dup := s.byName[name]; dup {
			http.Error(w, "duplicate", http.StatusBadRequest)
			return
		}
		s.byName[name] = appliedPolicy{ID: "pol-" + name, Name: name, RawYAML: body.YAML}
		s.writes = append(s.writes, "POST "+name)
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/policies/"):
		id := strings.TrimPrefix(r.URL.Path, "/policies/")
		for n, p := range s.byName {
			if p.ID == id {
				p.RawYAML = body.YAML
				s.byName[n] = p
				s.writes = append(s.writes, "PUT "+id)
				return
			}
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *policyServer) takeWrites() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.writes
	s.writes = nil
	return w
}

func writeManifest(t *testing.T, dir, policyYAML string) {
	t.Helper()
	m := "tenant:\n  id: t1\npolicies:\n  - id: p1\n    yaml: |\n"
	for _, l := range strings.Split(policyYAML, "\n") {
		m += "      " + l + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "t1.yaml"), []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Manifest policies converge: created once, updated when the YAML changes,
// untouched (no write, so no policy audit event) while it stays the same.
func TestManifestPoliciesConverge(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RECONCILER_MANIFEST_DIR", dir)
	srv := &policyServer{byName: map[string]appliedPolicy{}}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	r := newTenantReconciler(ts.Client(), ts.URL, log.Default())
	ctx := context.Background()

	v1 := "metadata:\n  name: deny-rsa\nspec:\n  type: v1"
	writeManifest(t, dir, v1)
	if err := r.Reconcile(ctx); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := srv.takeWrites(); len(got) != 1 || got[0] != "POST deny-rsa" {
		t.Fatalf("create writes = %v", got)
	}

	if err := r.Reconcile(ctx); err != nil {
		t.Fatalf("unchanged: %v", err)
	}
	if got := srv.takeWrites(); len(got) != 0 {
		t.Fatalf("unchanged tick wrote %v", got)
	}

	writeManifest(t, dir, "metadata:\n  name: deny-rsa\nspec:\n  type: v2")
	if err := r.Reconcile(ctx); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := srv.takeWrites(); len(got) != 1 || got[0] != "PUT pol-deny-rsa" {
		t.Fatalf("update writes = %v", got)
	}
	if !strings.Contains(srv.byName["deny-rsa"].RawYAML, "type: v2") {
		t.Fatalf("policy not updated: %q", srv.byName["deny-rsa"].RawYAML)
	}
}

// A failure reaches Reconcile's error (the controller's last_error) instead
// of only a log line.
func TestManifestPolicyFailuresSurface(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RECONCILER_MANIFEST_DIR", dir)
	srv := &policyServer{byName: map[string]appliedPolicy{}, failList: true}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	r := newTenantReconciler(ts.Client(), ts.URL, log.Default())

	writeManifest(t, dir, "metadata:\n  name: deny-rsa")
	if err := r.Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "tenant t1: list policies") {
		t.Fatalf("list failure: err = %v", err)
	}

	srv.failList = false
	writeManifest(t, dir, "spec:\n  type: v1")
	if err := r.Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "policy p1: metadata.name is required") {
		t.Fatalf("nameless policy: err = %v", err)
	}
}
