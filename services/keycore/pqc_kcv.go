package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// ComputePQCKCV returns a key check value over post-quantum key material.
// Classical KCVs encrypt a known plaintext under the key; that pattern
// doesn't translate to ML-KEM (a KEM doesn't have an encrypt-fixed-block
// operation) or to ML-DSA / SLH-DSA (signing is randomised). Instead, we
// compute an HMAC-SHA-256 over a domain-separation tag concatenated with
// the public/material bytes; the HMAC key is a fixed, well-known label so
// the value is reproducible across nodes.
//
// Properties:
//   - 16-byte output (matches the symmetric KCV size in audit reports)
//   - same input → same output (idempotent verification)
//   - does not reveal the private key (only public material is hashed)
//   - distinguishable across algorithms via the domain tag
func ComputePQCKCV(algorithm string, publicMaterial []byte) (string, error) {
	if len(publicMaterial) == 0 {
		return "", errors.New("PQC KCV: public material is empty")
	}
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	if alg == "" {
		return "", errors.New("PQC KCV: algorithm is required")
	}
	domain := []byte("vecta-pqc-kcv/v1|" + alg)
	mac := hmac.New(sha256.New, domain)
	mac.Write(publicMaterial) //nolint:errcheck
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:16]), nil
}

// VerifyPQCKCV recomputes the KCV and compares it constant-time to the
// expected value. Returns nil on match, descriptive error on mismatch.
func VerifyPQCKCV(algorithm string, publicMaterial []byte, expected string) error {
	got, err := ComputePQCKCV(algorithm, publicMaterial)
	if err != nil {
		return err
	}
	if !hmacConstantTimeStringEqual(got, expected) {
		return errors.New("PQC KCV: mismatch")
	}
	return nil
}

func hmacConstantTimeStringEqual(a, b string) bool {
	ab := []byte(a)
	bb := []byte(b)
	if len(ab) != len(bb) {
		return false
	}
	return hmac.Equal(ab, bb)
}
