package jwtauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

func TestLoadParser_FallsBackToSharedEnv(t *testing.T) {
	// Per-service vars empty; shared JWT_PUBLIC_KEY_B64 carries the key.
	t.Setenv("TEST_JWT_PUBLIC_KEY_PEM", "")
	t.Setenv("TEST_JWT_PUBLIC_KEY_B64", "")
	t.Setenv("JWT_PUBLIC_KEY_B64", base64.StdEncoding.EncodeToString([]byte(makeTestKey(t))))
	p, err := LoadParser(Config{Prefix: "TEST"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatalf("expected non-nil parser when shared B64 is set")
	}
}

func TestLoadParser_PerServiceOverridesShared(t *testing.T) {
	// When both per-service and shared are set, the per-service value
	// wins. Use an obviously invalid shared value so a fallback would
	// surface as a parse error.
	t.Setenv("TEST_JWT_PUBLIC_KEY_PEM", makeTestKey(t))
	t.Setenv("JWT_PUBLIC_KEY_PEM", "not a pem")
	p, err := LoadParser(Config{Prefix: "TEST"})
	if err != nil {
		t.Fatalf("per-service should win and parse cleanly; got %v", err)
	}
	if p == nil {
		t.Fatalf("expected non-nil parser")
	}
}

// The Helm chart gives services a certificate for auth's signing key (Helm
// can make one from a key but can't print the bare public key): a token
// signed by that key verifies, and one signed by another key doesn't.
func TestLoadParser_AcceptsACertificateForTheSigningKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vecta-jwt"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_JWT_PUBLIC_KEY_PEM", "")
	t.Setenv("TEST_JWT_PUBLIC_KEY_B64", base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	p, err := LoadParser(Config{Prefix: "TEST", Issuer: "iss", Audience: "aud"})
	if err != nil || p == nil {
		t.Fatalf("certificate refused: %v", err)
	}
	sign := func(k *rsa.PrivateKey) string {
		tok, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "iss", "aud": "aud", "sub": "alice", "tenant_id": "root", "exp": time.Now().Add(time.Minute).Unix()}).SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	if _, err := p(sign(priv)); err != nil {
		t.Fatalf("a token signed by the certificate's key was refused: %v", err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := p(sign(other)); err == nil {
		t.Fatal("a token signed by another key verified")
	}
}
