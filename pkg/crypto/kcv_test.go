package crypto

import "testing"

func TestComputeKCVVectors(t *testing.T) {
	tests := []struct {
		alg string
		key []byte
		exp string
	}{
		{"AES", []byte("1234567890ABCDEF"), "fd748d"},
		{"3DES", []byte("0123456789ABCDEFFEDCBA9876543210"), "ba07ac"},
		{"RSA", []byte("rsa-pub"), "c2592a"},
		{"EC", []byte("ec-pub"), "a9c195"},
		{"HMAC", []byte("hmac-key"), "fb0452"},
	}
	for _, tt := range tests {
		got, err := ComputeKCV(tt.alg, tt.key)
		if err != nil {
			t.Fatalf("ComputeKCV(%s) err=%v", tt.alg, err)
		}
		if got != tt.exp {
			t.Fatalf("ComputeKCV(%s)=%s want=%s", tt.alg, got, tt.exp)
		}
	}
}
