package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseRS256WithOptionsValidatesIssuerAudienceAndExpiry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	now := time.Now().UTC()
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, &Claims{
		TenantID: "root",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer-a",
			Audience:  jwt.ClaimStrings{"aud-a"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
	}).SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	claims, err := ParseRS256WithOptions(token, &key.PublicKey, ParseOptions{
		Issuer:   "issuer-a",
		Audience: "aud-a",
		Leeway:   30 * time.Second,
	})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if claims.TenantID != "root" {
		t.Fatalf("unexpected tenant_id: %q", claims.TenantID)
	}
}

func TestParseRS256WithOptionsRejectsMissingExpiry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	now := time.Now().UTC()
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, &Claims{
		TenantID: "root",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "issuer-a",
			Audience: jwt.ClaimStrings{"aud-a"},
			IssuedAt: jwt.NewNumericDate(now),
		},
	}).SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	if _, err := ParseRS256WithOptions(token, &key.PublicKey, ParseOptions{
		Issuer:   "issuer-a",
		Audience: "aud-a",
		Leeway:   30 * time.Second,
	}); err == nil {
		t.Fatal("expected missing expiry token to be rejected")
	}
}

func TestParseRS256WithOptionsRejectsWrongAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	now := time.Now().UTC()
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, &Claims{
		TenantID: "root",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer-a",
			Audience:  jwt.ClaimStrings{"aud-a"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
	}).SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	if _, err := ParseRS256WithOptions(token, &key.PublicKey, ParseOptions{
		Issuer:   "issuer-a",
		Audience: "aud-b",
		Leeway:   30 * time.Second,
	}); err == nil {
		t.Fatal("expected wrong audience token to be rejected")
	}
}
