package main

import (
	"context"
	"encoding/base64"
	"testing"

	"vecta-kms/pkg/crypto"
)

func TestAttestKeyProducesVerifiableSignature(t *testing.T) {
	_, svc := newHandlerForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "attest-me", Algorithm: "AES-256", KeyType: "symmetric",
		Purpose: "encrypt", Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}

	att, err := svc.AttestKey(context.Background(), "t1", key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if att.Statement.KeyID != key.ID || !att.Statement.IntegrityVerified {
		t.Fatalf("unexpected statement: %+v", att.Statement)
	}

	// Fetch the published public key and verify the signature over the exact
	// canonical bytes that were signed.
	pemStr, fp, err := svc.attestationPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if fp != att.PublicKeyFingerprint {
		t.Fatalf("fingerprint mismatch: %s vs %s", fp, att.PublicKeyFingerprint)
	}
	pub, err := crypto.ParsePublicKeyPEM(pemStr)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := base64.StdEncoding.DecodeString(att.StatementB64)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(att.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.Verify(att.SigningAlgorithm, pub, canonical, sig); err != nil {
		t.Fatalf("attestation signature did not verify: %v", err)
	}

	// A tampered statement must NOT verify.
	canonical[10] ^= 0xFF
	if err := crypto.Verify(att.SigningAlgorithm, pub, canonical, sig); err == nil {
		t.Fatal("tampered statement unexpectedly verified")
	}
}
