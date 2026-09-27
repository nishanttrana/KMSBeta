package crypto

import (
	"encoding/hex"
	"errors"
	"testing"

	"vecta-kms/pkg/fips/fipstest"
)

// PBKDF2-HMAC-SHA256 known answer (P="password", S="salt", c=1, dkLen=32).
// Strict mode refuses these parameters (SP 800-132 salt/length minimums), so
// there a compliant derivation must succeed instead.
func TestPBKDF2SHA256KnownAnswer(t *testing.T) {
	if k, err := PBKDF2SHA256([]byte("a-long-enough-secret"), []byte("sixteen-byte-salt"), 1000, 32); err != nil || len(k) != 32 {
		t.Fatalf("compliant pbkdf2: %v", err)
	}
	fipstest.SkipIfStrict(t, "PBKDF2 known answer with a 4-byte salt")
	got, err := PBKDF2SHA256([]byte("password"), []byte("salt"), 1, 32)
	if err != nil || hex.EncodeToString(got) != "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b" {
		t.Fatalf("pbkdf2 = %x, %v", got, err)
	}
}

func TestNonApprovedKDFsOutsideStrict(t *testing.T) {
	fipstest.SkipIfStrict(t, "scrypt / Argon2id")
	if k, err := Scrypt([]byte("secret"), []byte("salt-salt-salt-1"), 1<<10, 8, 1, 32); err != nil || len(k) != 32 {
		t.Fatalf("scrypt: %v", err)
	}
	if k, err := Argon2id([]byte("secret"), []byte("salt-salt-salt-1"), 2, 19*1024, 1, 32); err != nil || len(k) != 32 {
		t.Fatalf("argon2id: %v", err)
	}
}

func TestNonApprovedKDFsRefusedInStrict(t *testing.T) {
	fipstest.StrictOnly(t)
	if _, err := Scrypt([]byte("s"), []byte("salt-salt-salt-1"), 1<<10, 8, 1, 32); !errors.Is(err, ErrKDFStrict) {
		t.Fatalf("scrypt in strict: %v", err)
	}
	if _, err := Argon2id([]byte("s"), []byte("salt-salt-salt-1"), 2, 19*1024, 1, 32); !errors.Is(err, ErrKDFStrict) {
		t.Fatalf("argon2id in strict: %v", err)
	}
}
