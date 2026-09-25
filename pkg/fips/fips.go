// Package fips implements the platform's FIPS 140-3 controls: the
// customer-selected runtime mode, verification that the running binary really
// uses the validated Go Cryptographic Module, approved-algorithm enforcement
// and key-length validation. See docs/SECURITY/FIPS.md.
package fips

import (
	"crypto/fips140"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
)

// Runtime modes. The customer chooses one with VECTA_FIPS_MODE; the value is
// passed unchanged to Go as GODEBUG=fips140=<mode>.
const (
	ModeOff  = "off"  // Go Cryptographic Module not in FIPS mode
	ModeOn   = "on"   // FIPS mode: self-tests, approved DRBG, FIPS TLS; platform policy blocks non-approved algorithms
	ModeOnly = "only" // strict: the Go runtime itself refuses every non-approved algorithm
)

// CertifiedModuleVersion is the CMVP-certified Go Cryptographic Module every
// binary is built against (GOFIPS140 in each Dockerfile; see
// $(go env GOROOT)/lib/fips140/certified.txt). scripts/conformance.sh checks
// the Dockerfiles use this exact value.
const CertifiedModuleVersion = "v1.0.0"

// FIPSMode reports whether FIPS policy is active (mode on or only).
var FIPSMode bool

func init() {
	FIPSMode = Mode() != ModeOff
}

// Mode returns the effective runtime mode as reported by the Go runtime, which
// is what actually governs the cryptography.
func Mode() string {
	switch {
	case fips140.Enforced():
		return ModeOnly
	case fips140.Enabled():
		return ModeOn
	default:
		return ModeOff
	}
}

// ModuleValidated reports whether the process runs the certified module in
// FIPS mode: an approved-mode claim is only true when both hold.
func ModuleValidated() bool {
	return fips140.Enabled() && fips140.Version() == CertifiedModuleVersion
}

// builtModule returns the GOFIPS140 value recorded at build time ("" if none).
func builtModule() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "GOFIPS140" {
			return s.Value
		}
	}
	return ""
}

// VerifyRuntime checks that the customer's VECTA_FIPS_MODE choice is what the
// process is actually running. When the variable is unset (tests, go run) it
// accepts whatever the runtime reports. Called at service startup by
// pkg/config; any error must stop the process.
func VerifyRuntime() error {
	want := strings.ToLower(strings.TrimSpace(os.Getenv("VECTA_FIPS_MODE")))
	if want == "" {
		return nil
	}
	switch want {
	case ModeOff, ModeOn, ModeOnly:
	default:
		return fmt.Errorf("VECTA_FIPS_MODE=%q is invalid; use on, only or off", want)
	}
	if got := Mode(); got != want {
		return fmt.Errorf("VECTA_FIPS_MODE=%s but the Go runtime is in FIPS mode %q; set GODEBUG=fips140=%s (docker-compose does this)", want, got, want)
	}
	if want != ModeOff && fips140.Version() != CertifiedModuleVersion {
		return fmt.Errorf("VECTA_FIPS_MODE=%s requires a binary built with GOFIPS140=%s (certified Go Cryptographic Module); this binary reports module %q (built with GOFIPS140=%q)", want, CertifiedModuleVersion, fips140.Version(), builtModule())
	}
	return nil
}

// ApprovedAlgorithms contains the set of FIPS 140-3 approved algorithms.
// Keys are uppercase canonical names; values describe the algorithm category.
var ApprovedAlgorithms = map[string]string{
	// Symmetric encryption
	"AES-128-GCM": "Authenticated Encryption",
	"AES-256-GCM": "Authenticated Encryption",

	// Asymmetric signing / encryption
	"RSA-2048":   "Asymmetric",
	"RSA-3072":   "Asymmetric",
	"RSA-4096":   "Asymmetric",
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
	"AES":     128,
	"RSA":     2048,
	"ECDSA":   256, // P-256 curve order bit size
	"ECDH":    256,
	"ED25519": 256,
	"HMAC":    128,
	"ML-KEM":  768,
	"ML-DSA":  65,
	"SLH-DSA": 128,
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
