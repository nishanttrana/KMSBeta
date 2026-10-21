package main

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

// The Helm chart hands services a certificate for auth's signing key
// (docs/KUBERNETES.md); keycore, which parses its own key, takes it too:
// found when the chart's node never started keycore on kind.
func TestKeycoreJWTParserAcceptsACertificateForTheSigningKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vecta-auth-jwt"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYCORE_JWT_PUBLIC_KEY_PEM", "")
	t.Setenv("KEYCORE_JWT_PUBLIC_KEY_B64", "")
	t.Setenv("JWT_PUBLIC_KEY_PEM", "")
	t.Setenv("JWT_PUBLIC_KEY_B64", base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	parse, err := loadJWTParser("iss", "aud")
	if err != nil || parse == nil {
		t.Fatalf("certificate refused: %v", err)
	}
	sign := func(k *rsa.PrivateKey) string {
		s, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "iss", "aud": "aud", "tenant_id": "root", "exp": time.Now().Add(time.Minute).Unix()}).SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if _, err := parse(sign(priv)); err != nil {
		t.Fatalf("token from the certificate's key refused: %v", err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := parse(sign(other)); err == nil {
		t.Fatal("token from another key accepted")
	}
}
