// Package deployed answers whether a compose profile is part of this
// deployment, from VECTA_DEPLOYED_PROFILES (docker-compose.yml sets it from
// COMPOSE_PROFILES, which every installer derives from
// infra/deployment/deployment.yaml).
package deployed

import (
	"os"
	"strings"
)

// Env carries the deployment's compose profiles into a service.
const Env = "VECTA_DEPLOYED_PROFILES"

// Has reports whether profile is deployed. An unset or empty list is
// unknown, and unknown counts as deployed: a caller that skips a service
// because it is "not deployed" must be sure of it.
func Has(profile string) bool { return in(os.Getenv(Env), profile) }

func in(profiles, profile string) bool {
	if strings.TrimSpace(profiles) == "" {
		return true
	}
	for _, p := range strings.Split(profiles, ",") {
		if strings.TrimSpace(p) == profile {
			return true
		}
	}
	return false
}
