package clusterroute

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDecide(t *testing.T) {
	cases := []struct {
		svc, method, path string
		want              Decision
	}{
		{"kms-keycore", "GET", "/keys", RunLocal},
		{"kms-keycore", "POST", "/keys/k1/encrypt", RunLocal},
		{"kms-keycore", "POST", "/keys/k1/sign", RunLocal},
		{"kms-keycore", "POST", "/keys", Forward},
		{"kms-keycore", "POST", "/keys/k1/rotate", Forward},
		{"kms-keycore", "POST", "/keys/k1/destroy", Forward},
		{"kms-keycore", "DELETE", "/keys/k1", Forward},
		{"kms-keycore", "POST", "/keys//encrypt", Forward}, // empty id matches nothing local
		{"kms-dataprotect", "POST", "/fpe/encrypt", RunLocal},
		{"kms-dataprotect", "POST", "/tokenize", Forward}, // writes vault tokens
		{"kms-auth", "POST", "/auth/login", RunLocal},
		{"kms-auth", "POST", "/users", Forward},
		{"kms-governance", "PUT", "/governance/system/state", RunLocal},
		{"kms-governance", "PUT", "/governance/system/fips-mode", Forward},
		{"kms-cluster-manager", "POST", "/cluster/join/connect", RunLocal},
		{"kms-unknown", "POST", "/anything", Refuse},
		{"kms-unknown", "GET", "/anything", RunLocal},
	}
	for _, c := range cases {
		if got := Decide(c.svc, c.method, c.path); got != c.want {
			t.Errorf("%s %s %s = %d, want %d", c.svc, c.method, c.path, got, c.want)
		}
	}
}

// Every Local pattern must name a route the service really registers, so a
// renamed endpoint cannot leave a stale entry (or a typo run locally).
func TestLocalRoutesExist(t *testing.T) {
	dirs := map[string]string{
		"kms-keycore": "keycore", "kms-dataprotect": "dataprotect", "kms-auth": "auth",
		"kms-governance": "governance", "kms-audit": "audit",
	}
	re := regexp.MustCompile(`HandleFunc\("([A-Z]+ [^"]+)"`)
	for svc, pats := range Local {
		files, _ := filepath.Glob(filepath.Join("..", "..", "services", dirs[svc], "*.go"))
		registered := map[string]bool{}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			raw, _ := os.ReadFile(f)
			for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
				registered[m[1]] = true
			}
		}
		for _, p := range pats {
			if !registered[p] {
				t.Errorf("%s: local route %q is not registered by the service", svc, p)
			}
		}
	}
}
