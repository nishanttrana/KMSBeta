package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgsvctls "vecta-kms/pkg/svctls"
)

// System Health listed 28 of 32 running components: Envoy, the dashboard,
// the reconciler and the watchdog register nothing in Consul and were not
// probed either. Every platform identity must have a probe target.
func TestHealthTargetsCoverEveryPlatformIdentity(t *testing.T) {
	probed := map[string]bool{}
	for _, target := range knownBackendTargets() {
		probed[hostOnly(target.address)] = true
	}
	for _, hosts := range []map[string]string{pkgsvctls.Services, pkgsvctls.Materialized} {
		for identity, host := range hosts {
			if !probed[host] {
				t.Errorf("%s (%s) has no system-health probe target", identity, host)
			}
		}
	}
}

// The auth service does not control the container runtime: the restart route
// is gone (it could only ever answer "unavailable"), and health carries no
// restart or published-port fields.
func TestNoContainerRestartRoute(t *testing.T) {
	h, _, _, _ := newTestHandler(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/auth/system-health/restart", strings.NewReader(`{"service":"certs"}`)))
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("restart route still answers: %d", rr.Code)
	}
	raw, err := json.Marshal(SystemHealthSnapshot{Services: []ServiceHealth{{Name: "kms-certs", Status: "running"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"restart_allowed", "interfaces"} {
		if strings.Contains(string(raw), field) {
			t.Errorf("health still reports %q", field)
		}
	}
}
