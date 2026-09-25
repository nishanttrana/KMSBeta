package servicetoken

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateBootstrapSecret(t *testing.T) {
	cases := []struct {
		name   string
		secret string
		want   error
	}{
		{"unset", "  ", ErrBootstrapSecretUnset},
		{"public default", insecureDefaultBootstrapSecret, ErrBootstrapSecretDefault},
		{"short", strings.Repeat("a", MinBootstrapSecretLen-1), ErrBootstrapSecretShort},
		{"strong", strings.Repeat("ab", 32), nil},
	}
	for _, tc := range cases {
		if err := ValidateBootstrapSecret(tc.secret); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestDeriveAPIKeyRejectsWeakSecrets(t *testing.T) {
	for _, s := range []string{"", insecureDefaultBootstrapSecret, "short-secret"} {
		if k := DeriveAPIKey(s, "kms-keycore"); k != "" {
			t.Errorf("DeriveAPIKey(%q) = %q, want empty", s, k)
		}
	}
	t.Setenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET", insecureDefaultBootstrapSecret)
	if FromEnv("kms-keycore") != nil {
		t.Error("FromEnv must be disabled with the public default secret")
	}
}

func TestDeriveAPIKeyStrongSecret(t *testing.T) {
	secret := strings.Repeat("cd", 32)
	a, b := DeriveAPIKey(secret, "kms-keycore"), DeriveAPIKey(secret, "kms-kmip")
	if a == "" || a == b || a != DeriveAPIKey(secret, "kms-keycore") {
		t.Fatalf("expected distinct deterministic keys, got %q / %q", a, b)
	}
	if a == InsecureDefaultAPIKey("kms-keycore") {
		t.Fatal("strong-secret key must differ from the insecure default key")
	}
}
