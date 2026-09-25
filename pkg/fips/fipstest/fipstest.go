// Package fipstest holds test helpers for the FIPS 140-3 runtime modes.
//
// The suite runs under every customer-selectable mode (VECTA_FIPS_MODE =
// off | on | only, see docs/SECURITY/FIPS.md). In "only" (strict) mode the Go
// Cryptographic Module refuses non-approved algorithms. A test of such a
// feature calls SkipIfStrict, and the refusal itself is proven by a strict-mode
// test (StrictOnly) that asserts a clean error, never a panic.
package fipstest

import (
	"crypto/fips140"
	"testing"
)

// SkipIfStrict skips t under FIPS 140-only mode. feature names the
// non-approved algorithm or construction the test exercises.
func SkipIfStrict(t testing.TB, feature string) {
	t.Helper()
	if fips140.Enforced() {
		t.Skipf("%s is not FIPS-approved and is refused in strict mode; see the strict-mode refusal tests", feature)
	}
}

// StrictOnly skips t unless the runtime enforces FIPS 140-only mode.
func StrictOnly(t testing.TB) {
	t.Helper()
	if !fips140.Enforced() {
		t.Skip("runs only under GODEBUG=fips140=only (VECTA_FIPS_MODE=only)")
	}
}
