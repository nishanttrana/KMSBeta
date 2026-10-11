package main

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
)

// HYOK refuses to start without a token-verification key, and loads the
// shared JWT_PUBLIC_KEY_B64 that compose sets. It used to read only
// HYOK_JWT_PUBLIC_KEY_*, so every compose deployment ran without a parser and
// answered every call 401, which signed the dashboard out.
func TestSharedJWTKeyLoadedAndMissingKeyRefusesStart(t *testing.T) {
	for _, prefix := range []string{"HYOK_", ""} {
		t.Setenv(prefix+"JWT_PUBLIC_KEY_PEM", "")
		t.Setenv(prefix+"JWT_PUBLIC_KEY_B64", "")
	}
	if parser, err := loadJWTParser("", ""); err == nil || parser != nil {
		t.Fatalf("no key: parser=%v err=%v, want a refusal", parser != nil, err)
	}
	t.Setenv("JWT_PUBLIC_KEY_B64", base64.StdEncoding.EncodeToString([]byte("not a key")))
	if _, err := loadJWTParser("", ""); err == nil {
		t.Fatal("a malformed key was accepted")
	}

	kp, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgRSA2048)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := pkgcrypto.MarshalPublicKeyPEM(kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_PUBLIC_KEY_B64", base64.StdEncoding.EncodeToString(pubPEM))
	parser, err := loadJWTParser("", "")
	if err != nil || parser == nil {
		t.Fatalf("shared JWT_PUBLIC_KEY_B64 not loaded: %v", err)
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, &pkgauth.Claims{
		TenantID: "root", Role: "admin", UserID: "root-admin",
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))},
	}).SignedString(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := parser(signed); err != nil || claims.TenantID != "root" {
		t.Fatalf("token signed by the shared key refused: %v", err)
	}
	other, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgRSA2048)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := jwt.NewWithClaims(jwt.SigningMethodRS256, &pkgauth.Claims{
		TenantID: "root", Role: "admin",
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))},
	}).SignedString(other.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser(forged); err == nil {
		t.Fatal("a token signed by another key was accepted")
	}
}
