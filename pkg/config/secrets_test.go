package config

import (
	"reflect"
	"testing"
)

func TestPlaceholderSecrets(t *testing.T) {
	env := []string{
		"WORKLOAD_IDENTITY_SHARED_SECRET=your-workload-identity-secret",
		"NATS_AUTH_TOKEN=Change-Me",
		"INTERNAL_SERVICE_BOOTSTRAP_SECRET=vecta-internal-svc-dev-secret-change-me",
		"POSTGRES_PASSWORD=3f9c1a7e5b2d4c6e8f0a1b2c3d4e5f60",
		"AUTH_BOOTSTRAP_ADMIN_PASSWORD=changeit", // exempt: forced change
		"CERTS_CRWK_PASSPHRASE_FILE=/your-path",  // config knob, not a secret
		"PATH=/usr/bin",
		"MALFORMED",
		"POSTGRES_DSN=postgres://postgres:postgres@localhost:5432/vecta?sslmode=disable", // user == password
		"POSTGRES_RO_DSN=postgres://reader:Password@replica:5432/vecta",                  // vendor default
		"DATABASE_URL=postgres://app:your-db-password@db/vecta",                          // placeholder
		"AUDIT_DSN=postgres://app:3f9c1a7e5b2d4c6e8f0a1b2c@db/vecta",                     // strong: ok
		"REPORTING_DSN=postgres://app@db/vecta",                                          // no password: ok
	}
	want := []string{"DATABASE_URL", "INTERNAL_SERVICE_BOOTSTRAP_SECRET", "NATS_AUTH_TOKEN", "POSTGRES_DSN", "POSTGRES_RO_DSN", "WORKLOAD_IDENTITY_SHARED_SECRET"}
	if got := PlaceholderSecrets(env); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
