// Package fips implements FIPS 140-3 Level 1 cryptographic module controls
// including approved algorithm enforcement, key length validation, and
// runtime mode toggling via environment variable.
package fips

import (
	"fmt"
	"os"
	"strings"
)

// FIPSMode indicates whether the module is operating in FIPS 140-3 mode.
// Set at init from the VECTA_FIPS_MODE environment variable.
var FIPSMode bool

func init() {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("VECTA_FIPS_MODE")))
	switch v {
	case "1", "true", "enabled", "on", "strict":
		FIPSMode = true
	default:
		FIPSMode = false
	}
}

// ApprovedAlgorithms contains the set of FIPS 140-3 approved algorithms.
// Keys are uppercase canonical names; values describe the algorithm category.
var ApprovedAlgorithms = map[string]string{
	// Symmetric encryption
	"AES-128-GCM": "Authenticated Encryption",
	"AES-256-GCM": "Authenticated Encryption",

	// Asymmetric signing / encryption
	"RSA-2048":  "Asymmetric",
	"RSA-3072":  "Asymmetric",
	"RSA-4096":  "Asymmetric",
	"ECDSA-P256": "Elliptic Curve Digital Signature",
	"ECDSA-P384": "Elliptic Curve Digital Signature",

	// Hash functions
	"SHA-256": "Hash",
	"SHA-384": "Hash",
	"SHA-512": "Hash",

	// Message authentication
	"HMAC-SHA256": "MAC",
	"HMAC-SHA384": "MAC",

	// Edwards-curve signatures
	"ED25519": "Digital Signature",

	// Post-quantum (NIST PQC standards)
	"ML-KEM-768":        "Post-Quantum KEM",
	"ML-KEM-1024":       "Post-Quantum KEM",
	"ML-DSA-65":         "Post-Quantum Digital Signature",
	"ML-DSA-87":         "Post-Quantum Digital Signature",
	"SLH-DSA-SHA2-128S": "Post-Quantum Hash-Based Signature",
}

// IsApproved performs a case-insensitive check for whether algorithm
// is in the FIPS 140-3 approved set.
func IsApproved(algorithm string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(algorithm))
	_, ok := ApprovedAlgorithms[normalized]
	return ok
}

// EnforceApproved returns an error if FIPS mode is enabled and the
// algorithm is not in the approved set. In non-FIPS mode it always returns nil.
func EnforceApproved(algorithm string) error {
	if !FIPSMode {
		return nil
	}
	if IsApproved(algorithm) {
		return nil
	}
	return fmt.Errorf("fips 140-3: algorithm %q is not approved for use in FIPS mode", algorithm)
}

// Minimum key lengths required by FIPS 140-3 for each algorithm family.
var minKeyLengths = map[string]int{
	"AES":       128,
	"RSA":       2048,
	"ECDSA":     256, // P-256 curve order bit size
	"ECDH":      256,
	"ED25519":   256,
	"HMAC":      128,
	"ML-KEM":    768,
	"ML-DSA":    65,
	"SLH-DSA":   128,
}

// ValidateKeyLength enforces FIPS 140-3 minimum key length requirements.
// The bits parameter is the key size in bits for symmetric algorithms and
// RSA, or the curve size for EC algorithms (e.g. 256 for P-256).
func ValidateKeyLength(algorithm string, bits int) error {
	upper := strings.ToUpper(strings.TrimSpace(algorithm))

	// Determine the algorithm family by prefix matching
	family := ""
	for _, prefix := range []string{"SLH-DSA", "ML-KEM", "ML-DSA", "ECDSA", "ECDH", "ED25519", "HMAC", "AES", "RSA"} {
		if strings.HasPrefix(upper, prefix) || strings.Contains(upper, prefix) {
			family = prefix
			break
		}
	}

	if family == "" {
		if FIPSMode {
			return fmt.Errorf("fips 140-3: unknown algorithm family for %q, cannot validate key length", algorithm)
		}
		return nil
	}

	minBits, ok := minKeyLengths[family]
	if !ok {
		return nil
	}

	if bits < minBits {
		return fmt.Errorf(
			"fips 140-3: %s key length %d bits is below minimum %d bits",
			algorithm, bits, minBits,
		)
	}
	return nil
}
