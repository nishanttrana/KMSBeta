package main

import (
	"testing"
)

func TestMLKEM768RoundTrip(t *testing.T) {
	kp, err := GenerateMLKEM768()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if kp.Algorithm != "ML-KEM-768" {
		t.Fatalf("unexpected algorithm: %s", kp.Algorithm)
	}
	shared1, ct, err := MLKEMEncapsulate("ML-KEM-768", kp.PublicKey)
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	shared2, err := MLKEMDecapsulate("ML-KEM-768", kp.PrivateKey, ct)
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	if string(shared1) != string(shared2) {
		t.Fatalf("shared keys differ between encapsulator and decapsulator")
	}
	if len(shared1) == 0 {
		t.Fatalf("shared key is empty")
	}
}

func TestMLDSA65SignVerify(t *testing.T) {
	kp, err := GenerateMLDSA("ML-DSA-65")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("vecta-kms ml-dsa-65 round-trip")
	ctx := []byte("vecta-kms-test/v1")
	sig, err := MLDSASign("ML-DSA-65", kp.PrivateKey, msg, ctx)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := MLDSAVerify("ML-DSA-65", kp.PublicKey, msg, ctx, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Tampered message must fail.
	tampered := []byte("vecta-kms ml-dsa-65 round-trip!")
	if err := MLDSAVerify("ML-DSA-65", kp.PublicKey, tampered, ctx, sig); err == nil {
		t.Fatalf("verify should have rejected tampered message")
	}
}

func TestPQCKCVStable(t *testing.T) {
	kp, err := GenerateMLKEM768()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	got1, err := ComputePQCKCV("ML-KEM-768", kp.PublicKey)
	if err != nil {
		t.Fatalf("kcv: %v", err)
	}
	got2, err := ComputePQCKCV("ML-KEM-768", kp.PublicKey)
	if err != nil {
		t.Fatalf("kcv: %v", err)
	}
	if got1 != got2 {
		t.Fatalf("KCV must be deterministic; got %s vs %s", got1, got2)
	}
	if err := VerifyPQCKCV("ML-KEM-768", kp.PublicKey, got1); err != nil {
		t.Fatalf("verify kcv: %v", err)
	}
}
