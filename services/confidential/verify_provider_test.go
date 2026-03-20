package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"
)

func TestVerifyAWSAttestationDocumentSuccess(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "aws.nitro-enclaves"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "aws.nitro.leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	payloadBytes, err := cbor.Marshal(map[string]any{
		"module_id":   "i-abc123",
		"digest":      "SHA384",
		"timestamp":   time.Now().UTC().UnixMilli(),
		"nonce":       []byte("nonce-1"),
		"certificate": leafDER,
		"cabundle":    []any{rootDER},
		"pcrs": map[any]any{
			0: []byte{0xaa, 0xbb},
			8: []byte{0xcc, 0xdd},
		},
		"user_data": []byte(`{"workload_identity":"spiffe://root/workloads/payments-authorizer","image_ref":"123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/authorizer:v1.4.2","image_digest":"sha256:abc","cluster_node_id":"vecta-kms-01","claims":{"environment":"prod","team":"payments"}}`),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	protected, err := cbor.Marshal(map[int]any{1: -35})
	if err != nil {
		t.Fatalf("marshal protected: %v", err)
	}
	sigStructure, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, payloadBytes})
	if err != nil {
		t.Fatalf("marshal sig structure: %v", err)
	}
	sum := sha384Sum(sigStructure)
	r, s, err := ecdsa.Sign(rand.Reader, leafKey, sum)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signature := append(paddedBytes(r.Bytes(), 48), paddedBytes(s.Bytes(), 48)...)
	rawDoc, err := cbor.Marshal([]any{protected, map[any]any{}, payloadBytes, signature})
	if err != nil {
		t.Fatalf("marshal sign1: %v", err)
	}

	verifier := NewProviderVerifier()
	verifier.awsRootCerts = x509.NewCertPool()
	verifier.awsRootCerts.AddCert(rootCert)

	result := verifier.verifyAWSAttestation(context.Background(), AttestedReleaseRequest{
		Provider:            "aws_nitro_enclaves",
		AttestationDocument: base64.StdEncoding.EncodeToString(rawDoc),
		Nonce:               "nonce-1",
	})

	if !result.CryptographicallyVerified {
		t.Fatalf("expected cryptographically verified result, got issues: %v", result.Issues)
	}
	if got := result.WorkloadIdentity; got != "spiffe://root/workloads/payments-authorizer" {
		t.Fatalf("unexpected workload identity: %s", got)
	}
	if got := result.ImageDigest; got != "sha256:abc" {
		t.Fatalf("unexpected image digest: %s", got)
	}
	if got := result.Measurements["pcr0"]; got != "aabb" {
		t.Fatalf("unexpected pcr0: %s", got)
	}
	if !result.SecureBoot || !result.DebugDisabled {
		t.Fatalf("expected secure boot/debug disabled to be inferred true")
	}
}

func TestVerifyAzureOIDCAttestationSuccess(t *testing.T) {
	serverURL, verifier := newOIDCTestVerifier(t, "azure")
	token := mustSignedJWT(t, verifier.privateKey, verifier.kid, map[string]any{
		"iss":                    serverURL,
		"aud":                    "kms-key-release",
		"sub":                    "spiffe://root/workloads/payments-authorizer",
		"exp":                    time.Now().Add(5 * time.Minute).Unix(),
		"iat":                    time.Now().Add(-time.Minute).Unix(),
		"x-ms-sgx-mrenclave":     "mrenclave-123",
		"x-ms-sgx-is-debuggable": false,
	})

	result := verifier.verifier.verifyOIDCAttestation(context.Background(), AttestedReleaseRequest{
		Provider:            "azure_secure_key_release",
		AttestationDocument: token,
		Audience:            "kms-key-release",
	}, "azure")

	if !result.CryptographicallyVerified {
		t.Fatalf("expected cryptographically verified result, got issues: %v", result.Issues)
	}
	if got := result.VerificationIssuer; got != serverURL {
		t.Fatalf("unexpected issuer: %s", got)
	}
	if got := result.Measurements["mrenclave"]; got != "mrenclave-123" {
		t.Fatalf("unexpected mrenclave: %s", got)
	}
	if !result.DebugDisabled {
		t.Fatalf("expected debug to be disabled")
	}
}

func TestVerifyGCPOIDCAttestationSuccess(t *testing.T) {
	serverURL, verifier := newOIDCTestVerifier(t, "gcp")
	token := mustSignedJWT(t, verifier.privateKey, verifier.kid, map[string]any{
		"iss":     serverURL,
		"aud":     "kms-key-release",
		"sub":     "serviceAccount:payments@example.iam.gserviceaccount.com",
		"exp":     time.Now().Add(5 * time.Minute).Unix(),
		"iat":     time.Now().Add(-time.Minute).Unix(),
		"secboot": true,
		"dbgstat": "disabled-since-boot",
		"submods": map[string]any{
			"container": map[string]any{
				"image_reference": "us-docker.pkg.dev/demo/payments/authorizer:v1.4.2",
				"image_digest":    "sha256:def",
			},
		},
	})

	result := verifier.verifier.verifyOIDCAttestation(context.Background(), AttestedReleaseRequest{
		Provider:            "gcp_confidential_space",
		AttestationDocument: token,
		Audience:            "kms-key-release",
	}, "gcp")

	if !result.CryptographicallyVerified {
		t.Fatalf("expected cryptographically verified result, got issues: %v", result.Issues)
	}
	if got := result.ImageRef; got != "us-docker.pkg.dev/demo/payments/authorizer:v1.4.2" {
		t.Fatalf("unexpected image ref: %s", got)
	}
	if got := result.ImageDigest; got != "sha256:def" {
		t.Fatalf("unexpected image digest: %s", got)
	}
	if !result.SecureBoot || !result.DebugDisabled {
		t.Fatalf("expected secure boot and debug disabled to be derived true")
	}
}

type oidcVerifierFixture struct {
	verifier   *ProviderVerifier
	privateKey *rsa.PrivateKey
	kid        string
}

func newOIDCTestVerifier(t *testing.T, family string) (string, oidcVerifierFixture) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	kid := "kid-1"

	var serverURL string
	handler := http.NewServeMux()
	handler.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   serverURL,
			"jwks_uri": serverURL + "/certs",
		})
	})
	handler.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": kid,
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
			}},
		})
	})
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	serverURL = server.URL

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	verifier := NewProviderVerifier()
	verifier.client = server.Client()
	switch family {
	case "azure":
		verifier.azureAllowedHosts = []string{parsed.Hostname()}
	case "gcp":
		verifier.gcpAllowedIssuers = []string{server.URL}
	}
	return server.URL, oidcVerifierFixture{
		verifier:   verifier,
		privateKey: privateKey,
		kid:        kid,
	}
}

func mustSignedJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signed
}

func paddedBytes(raw []byte, size int) []byte {
	if len(raw) >= size {
		return raw
	}
	out := make([]byte, size)
	copy(out[size-len(raw):], raw)
	return out
}

func sha384Sum(raw []byte) []byte {
	sum := sha512.Sum384(raw)
	return sum[:]
}
