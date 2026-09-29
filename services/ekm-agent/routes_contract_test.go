package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	ekmRoutePattern = regexp.MustCompile(`"(GET|POST|PUT|DELETE|PATCH) (/ekm/[^" ]+)"`)
	agentEKMLiteral = regexp.MustCompile("[\"`](/ekm/[^\"`]*)[\"`]")
	pathParam       = regexp.MustCompile(`\{[^}]*\}|%[sdv]`)
)

func normalisePath(p string) string { return pathParam.ReplaceAllString(p, "{}") }

// ekmRoutes reads the routes services/ekm registers, as "METHOD /path".
func ekmRoutes(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "ekm", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("read services/ekm sources: %v", err)
	}
	routes := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ekmRoutePattern.FindAllStringSubmatch(string(src), -1) {
			routes[m[1]+" "+normalisePath(m[2])] = true
		}
	}
	if len(routes) == 0 {
		t.Fatal("found no EKM routes; the route pattern no longer matches services/ekm")
	}
	return routes
}

// Every EKM call the agent makes must hit a route the EKM service
// registers. The agent once called GET /ekm/tde/keys/{id} and
// POST /ekm/tde/keys/{id}/export, which never existed (6.14.0-beta).
func TestAgentCallsOnlyRegisteredEKMRoutes(t *testing.T) {
	routes := ekmRoutes(t)
	for _, mode := range []string{"", "bitlocker"} {
		cfg := AgentConfig{AgentMode: mode}
		applyDefaults(&cfg)
		calls := []string{cfg.RegisterPath, cfg.HeartbeatPath}
		if mode == "bitlocker" {
			calls = append(calls, cfg.JobsNextPath, cfg.JobResultPath)
		}
		for _, p := range calls {
			if !routes["POST "+normalisePath(p)] {
				t.Errorf("mode %q: agent calls POST %s, which services/ekm does not register", mode, p)
			}
		}
	}

	// Any other EKM path written into the agent's code must exist too.
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range agentEKMLiteral.FindAllStringSubmatch(string(src), -1) {
			p := normalisePath(m[1])
			found := false
			for r := range routes {
				if strings.SplitN(r, " ", 2)[1] == p {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s names %s, which services/ekm does not register", f, m[1])
			}
		}
	}
}

// TDE key material never leaves the KMS: the agent has no export path.
func TestAgentHasNoKeyExportPath(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"/export", "keycache", "key_cache_enabled"} {
			if strings.Contains(string(src), bad) {
				t.Errorf("%s contains %q; the agent proxies every TDE operation to the KMS", f, bad)
			}
		}
	}
}
