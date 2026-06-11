package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateAESKeySizes(t *testing.T) {
	for _, bits := range []int{128, 256} {
		key, err := GenerateAESKey(bits)
		if err != nil {
			t.Fatalf("GenerateAESKey(%d): %v", bits, err)
		}
		if len(key) != bits/8 {
			t.Fatalf("expected %d bytes, got %d", bits/8, len(key))
		}
	}
	if _, err := GenerateAESKey(192); err == nil {
		t.Fatal("expected error for AES-192 (not in approved suite)")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key, _ := GenerateAESKey(256)
	plaintext := []byte("vecta kms central crypto")
	aad := []byte("tenant-1")

	blob, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := Open(key, blob, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("round trip mismatch")
	}
	if _, err := Open(key, blob, []byte("wrong-aad")); err == nil {
		t.Fatal("expected AAD mismatch failure")
	}
}

func TestSignVerifyAllAlgorithms(t *testing.T) {
	data := []byte("audit-event-payload")
	for _, alg := range []string{AlgRSA2048, AlgECDSAP256, AlgECDSAP384, AlgEd25519} {
		kp, err := GenerateKeyPair(alg)
		if err != nil {
			t.Fatalf("GenerateKeyPair(%s): %v", alg, err)
		}
		sig, err := Sign(kp, data)
		if err != nil {
			t.Fatalf("Sign(%s): %v", alg, err)
		}
		if err := Verify(alg, kp.Public, data, sig); err != nil {
			t.Fatalf("Verify(%s): %v", alg, err)
		}
		if err := Verify(alg, kp.Public, []byte("tampered"), sig); err == nil {
			t.Fatalf("Verify(%s): expected failure on tampered data", alg)
		}
	}
}

func TestPEMRoundTrip(t *testing.T) {
	for _, alg := range []string{AlgECDSAP256, AlgEd25519} {
		kp, err := GenerateKeyPair(alg)
		if err != nil {
			t.Fatalf("GenerateKeyPair(%s): %v", alg, err)
		}
		pemBytes, err := MarshalPrivateKeyPEM(kp)
		if err != nil {
			t.Fatalf("MarshalPrivateKeyPEM(%s): %v", alg, err)
		}
		parsed, err := ParsePrivateKeyPEM(pemBytes)
		if err != nil {
			t.Fatalf("ParsePrivateKeyPEM(%s): %v", alg, err)
		}
		if parsed.Algorithm != alg {
			t.Fatalf("algorithm mismatch: want %s got %s", alg, parsed.Algorithm)
		}
		if _, err := MarshalPublicKeyPEM(parsed.Public); err != nil {
			t.Fatalf("MarshalPublicKeyPEM(%s): %v", alg, err)
		}
	}
}

func TestHMACVerify(t *testing.T) {
	key, _ := GenerateAESKey(256)
	mac, err := HMAC("SHA-256", key, []byte("data"))
	if err != nil {
		t.Fatalf("HMAC: %v", err)
	}
	if !VerifyHMAC("SHA-256", key, []byte("data"), mac) {
		t.Fatal("VerifyHMAC should succeed")
	}
	if VerifyHMAC("SHA-256", key, []byte("other"), mac) {
		t.Fatal("VerifyHMAC should fail on different data")
	}
}
