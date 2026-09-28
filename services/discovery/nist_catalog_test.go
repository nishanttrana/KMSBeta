package main

import (
	"crypto/tls"
	"testing"
)

// strength_bits is the SP 800-57 security strength, not the key or parameter
// size (RSA-2048 was stored as 2048, ML-KEM-768 as 768), and classification
// follows pkg/cryptocatalog (RSA-4096 was "strong").
func TestDiscoveryLabelsFollowTheCatalogue(t *testing.T) {
	for alg, want := range map[string]int{"RSA-2048": 112, "ECDSA-P384": 192, "ECDH-P256": 128, "ML-KEM-768": 192, "UNKNOWN": 0} {
		if got := strengthBits(alg); got != want {
			t.Errorf("strengthBits(%s) = %d, want %d", alg, got, want)
		}
	}
	for curve, ready := range map[tls.CurveID]bool{tls.X25519MLKEM768: true, tls.SecP256r1MLKEM768: true, tls.X25519: false, tls.CurveP384: false} {
		kex := keyExchangeName(curve)
		if pqcReady(kex) != ready {
			t.Errorf("%s: pqcReady=%v, want %v", kex, !ready, ready)
		}
	}
	for alg, want := range map[string]string{"RSA-4096": "vulnerable", "ML-DSA-65": "strong", "X25519-ML-KEM-768-HYBRID": "strong", "RSA-KEX": "unknown"} {
		if got := classifyAlgorithm(alg); got != want {
			t.Errorf("classifyAlgorithm(%s) = %s, want %s", alg, got, want)
		}
	}
}
