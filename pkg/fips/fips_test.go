package fips

import (
	"testing"
)

func TestIsApproved(t *testing.T) {
	approved := []string{
		"AES-128-GCM", "aes-256-gcm", "RSA-2048", "rsa-4096",
		"ECDSA-P256", "ecdsa-p384", "SHA-256", "sha-512",
		"HMAC-SHA256", "Ed25519", "ML-KEM-768", "ML-DSA-87",
		"SLH-DSA-SHA2-128s",
	}
	for _, alg := range approved {
		if !IsApproved(alg) {
			t.Errorf("expected %q to be approved", alg)
		}
	}

	notApproved := []string{
		"CHACHA20", "Blowfish", "3DES", "RC4", "MD5", "",
	}
	for _, alg := range notApproved {
		if IsApproved(alg) {
			t.Errorf("expected %q to NOT be approved", alg)
		}
	}
}

func TestEnforceApproved(t *testing.T) {
	origMode := FIPSMode
	defer func() { FIPSMode = origMode }()

	// In non-FIPS mode, everything passes
	FIPSMode = false
	if err := EnforceApproved("CHACHA20"); err != nil {
		t.Errorf("non-FIPS mode should allow anything: %v", err)
	}

	// In FIPS mode, unapproved algorithms are rejected
	FIPSMode = true
	if err := EnforceApproved("AES-256-GCM"); err != nil {
		t.Errorf("AES-256-GCM should be approved: %v", err)
	}
	if err := EnforceApproved("CHACHA20"); err == nil {
		t.Error("CHACHA20 should be rejected in FIPS mode")
	}
}

func TestValidateKeyLength(t *testing.T) {
	tests := []struct {
		alg    string
		bits   int
		wantOK bool
	}{
		{"AES-256-GCM", 256, true},
		{"AES-128-GCM", 128, true},
		{"AES-128-GCM", 64, false},
		{"RSA-2048", 2048, true},
		{"RSA-2048", 1024, false},
		{"ECDSA-P256", 256, true},
		{"ECDSA-P256", 192, false},
	}
	for _, tc := range tests {
		err := ValidateKeyLength(tc.alg, tc.bits)
		if tc.wantOK && err != nil {
			t.Errorf("ValidateKeyLength(%q, %d) unexpected error: %v", tc.alg, tc.bits, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("ValidateKeyLength(%q, %d) expected error", tc.alg, tc.bits)
		}
	}
}

func TestRunSelfTests(t *testing.T) {
	if err := RunSelfTests(); err != nil {
		t.Fatalf("self-tests failed: %v", err)
	}
	report := SelfTestReport()
	if len(report) == 0 {
		t.Fatal("expected non-empty self-test report")
	}
	for _, r := range report {
		if !r.Passed {
			t.Errorf("self-test %q failed: %s", r.Name, r.Error)
		}
		if r.Duration <= 0 {
			t.Errorf("self-test %q has zero duration", r.Name)
		}
	}
}

func TestZeroize(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	Zeroize(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d not zeroed: got 0x%02X", i, b)
		}
	}
}

func TestZeroizeString(t *testing.T) {
	s := string([]byte("secret-key-material"))
	ZeroizeString(&s)
	if s != "" {
		t.Errorf("expected empty string after ZeroizeString, got %q", s)
	}
}

func TestSecureBuffer(t *testing.T) {
	sb := NewSecureBuffer(32)

	// Write data
	n, err := sb.Write([]byte("test-key-material-1234567890ab"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n == 0 {
		t.Fatal("expected non-zero write")
	}

	// Read data back
	data := sb.Bytes()
	if data == nil {
		t.Fatal("Bytes() returned nil before Close")
	}

	// Close and verify zeroization
	sb.Close()
	if sb.Bytes() != nil {
		t.Error("Bytes() should return nil after Close")
	}

	// Double-close should not panic
	sb.Close()

	// Write after close should error
	_, err = sb.Write([]byte("x"))
	if err == nil {
		t.Error("Write after Close should return error")
	}
}

func TestRunIntegrityCheck_NoEnvVar(t *testing.T) {
	// When VECTA_BINARY_HASH is not set, integrity check should pass (skip)
	err := RunIntegrityCheck("/nonexistent")
	if err != nil {
		t.Errorf("expected nil when VECTA_BINARY_HASH not set, got: %v", err)
	}
}
