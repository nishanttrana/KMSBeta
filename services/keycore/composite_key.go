package main

import (
	"errors"
	"strings"
)

// CompositeKey represents one logical key whose cryptographic identity is
// the concatenation of a classical primitive and a post-quantum primitive.
// Callers see a single key handle; under the hood every encrypt/decrypt
// runs both legs in lockstep. The composite is invalid if either leg is
// missing, so a partial migration cannot leave a key in a hybrid-by-name-
// only state.
//
// The structure is deliberately opaque: callers operate on the composite
// via the Encrypt/Decrypt/Sign/Verify helpers rather than reaching into
// the individual leg material. This keeps the hybridisation rules in one
// place and prevents leg-specific shortcuts from creeping into call sites.
type CompositeKey struct {
	ClassicalAlgorithm string
	PQCAlgorithm       string
	ClassicalKeyID     string
	PQCKeyID           string
	Encoding           string // "concatenated" | "kemtls-rfc-draft" | future variants
}

// ParseCompositeAlgorithm decodes "AES-256-GCM+ML-KEM-768" or
// "ML-DSA-65+ECDSA-P256" into a CompositeKey shell (no key material).
// Returns nil + false when the algorithm string does not name a composite.
func ParseCompositeAlgorithm(alg string) (*CompositeKey, bool) {
	parts := strings.SplitN(strings.TrimSpace(alg), "+", 2)
	if len(parts) != 2 {
		return nil, false
	}
	left := strings.TrimSpace(parts[0])
	right := strings.TrimSpace(parts[1])
	if left == "" || right == "" {
		return nil, false
	}
	classical, pqc := orderForComposite(left, right)
	return &CompositeKey{
		ClassicalAlgorithm: classical,
		PQCAlgorithm:       pqc,
		Encoding:           "concatenated",
	}, true
}

// orderForComposite returns (classical, pqc) regardless of source ordering.
// Operators write algorithms in either order; the keycore canonicalises
// so storage and audit always show classical first.
func orderForComposite(a, b string) (string, string) {
	if isPQCAlgorithm(a) && !isPQCAlgorithm(b) {
		return b, a
	}
	return a, b
}

// IsCompositeAlgorithm is the cheap pre-flight check the keycore uses to
// decide whether a request needs hybrid routing.
func IsCompositeAlgorithm(alg string) bool {
	_, ok := ParseCompositeAlgorithm(alg)
	return ok
}

// isPQCAlgorithm returns true for the standardised PQC primitives plus
// the stateful HBS schemes. Future entries can be added without
// touching call sites.
func isPQCAlgorithm(alg string) bool {
	a := strings.ToUpper(strings.TrimSpace(alg))
	switch {
	case strings.HasPrefix(a, "ML-KEM"),
		strings.HasPrefix(a, "ML-DSA"),
		strings.HasPrefix(a, "SLH-DSA"),
		strings.HasPrefix(a, "XMSS"),
		strings.HasPrefix(a, "LMS"):
		return true
	}
	return false
}

// Validate ensures both legs of the composite are populated. Returns a
// descriptive error so the dashboard can render a remediation hint.
func (c *CompositeKey) Validate() error {
	if c == nil {
		return errors.New("composite key is nil")
	}
	if c.ClassicalAlgorithm == "" || c.PQCAlgorithm == "" {
		return errors.New("composite key requires both classical and PQC legs")
	}
	return nil
}
