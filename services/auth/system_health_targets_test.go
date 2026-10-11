package main

import (
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
