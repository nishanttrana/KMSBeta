package jwtauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

// makeTestKey returns a fresh RSA-2048 public-key PEM suitable for
// LoadParser. The corresponding private key is discarded — these tests
// only need parser construction, not signature verification.
func makeTestKey(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestLoadParser_NilWhenUnset(t *testing.T) {
	t.Setenv("TEST_JWT_PUBLIC_KEY_PEM", "")
	t.Setenv("TEST_JWT_PUBLIC_KEY_B64", "")
	p, err := LoadParser(Config{Prefix: "TEST"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Fatalf("expected nil parser when env unset; got non-nil")
	}
}

func TestLoadParser_RejectsMalformedPEM(t *testing.T) {
	t.Setenv("TEST_JWT_PUBLIC_KEY_PEM", "not a pem")
	t.Setenv("TEST_JWT_PUBLIC_KEY_B64", "")
	p, err := LoadParser(Config{Prefix: "TEST"})
	if err == nil {
		t.Fatalf("expected error on malformed PEM")
	}
	if p != nil {
		t.Fatalf("expected nil parser on malformed PEM")
	}
}

func TestLoadParser_AcceptsPEM(t *testing.T) {
	t.Setenv("TEST_JWT_PUBLIC_KEY_PEM", makeTestKey(t))
	t.Setenv("TEST_JWT_PUBLIC_KEY_B64", "")
	p, err := LoadParser(Config{Prefix: "TEST", Issuer: "iss", Audience: "aud"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatalf("expected non-nil parser when PEM is valid")
	}
	// Parser is invoked at runtime; we don't sign here, just verify it
	// rejects empty input (i.e., HTTPMiddleware's "no Bearer token" path).
	if _, err := p(""); err == nil {
		t.Fatalf("parser should reject empty token")
	}
}

func TestLoadParser_AcceptsB64(t *testing.T) {
	t.Setenv("TEST_JWT_PUBLIC_KEY_PEM", "")
	t.Setenv("TEST_JWT_PUBLIC_KEY_B64", base64.StdEncoding.EncodeToString([]byte(makeTestKey(t))))
	p, err := LoadParser(Config{Prefix: "TEST"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatalf("expected non-nil parser when B64 is valid")
	}
}

func TestLoadParser_RequiresPrefix(t *testing.T) {
	_, err := LoadParser(Config{})
	if err == nil {
		t.Fatalf("expected error when prefix is empty")
	}
}
