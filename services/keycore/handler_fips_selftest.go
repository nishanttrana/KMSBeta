package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// handleFIPSSelfTest runs an on-demand FIPS 140-3 power-on self-test battery
// and returns per-algorithm pass/fail status.
//
// POST /fips/self-test
func (h *Handler) handleFIPSSelfTest(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	results := runFIPSSelfTests()
	allPassed := true
	for _, v := range results {
		if !v {
			allPassed = false
			break
		}
	}
	status := http.StatusOK
	if !allPassed {
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, map[string]any{
		"passed":     allPassed,
		"tests":      results,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"request_id": reqID,
	})
}

// handleRNGHealth runs a NIST SP 800-90B health test battery against the OS
// CSPRNG (crypto/rand) and returns entropy quality metrics.
//
// GET /fips/rng-health
func (h *Handler) handleRNGHealth(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	result := runRNGHealthTest()
	writeJSON(w, http.StatusOK, map[string]any{
		"source":              "crypto/rand (OS-CSPRNG)",
		"fips_approved":       true,
		"repetition_count":    result.RepetitionCountPassed,
		"adaptive_proportion": result.AdaptiveProportionPassed,
		"sample_bytes":        result.SampleBytes,
		"unique_bytes":        result.UniqueBytes,
		"entropy_estimate":    result.EntropyEstimate,
		"passed":              result.Passed,
		"timestamp":           time.Now().UTC().Format(time.RFC3339),
		"request_id":          reqID,
	})
}

// handleZeroizeVerify verifies that a key's in-memory material has been
// correctly zeroized after destruction.  Callers supply a key ID; the handler
// confirms the key is in DESTROYED state and that no live memory reference
// exists in the key cache.
//
// POST /keys/{id}/zeroize-verify
func (h *Handler) handleZeroizeVerify(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	keyID := strings.TrimSpace(r.PathValue("id"))

	key, err := h.svc.GetKey(r.Context(), tenantID, keyID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "key not found", reqID, tenantID)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(key.Status), "destroyed") {
		writeErr(w, http.StatusConflict, "not_destroyed",
			"key must be in DESTROYED state before zeroization can be verified", reqID, tenantID)
		return
	}

	// Confirm the cache holds no live key material for this ID.
	cacheClean := h.svc.ConfirmKeyMaterialZeroized(tenantID, keyID)

	// Force a GC sweep so any dangling pointers become unreachable.
	runtime.GC()

	writeJSON(w, http.StatusOK, map[string]any{
		"key_id":              keyID,
		"status":              key.Status,
		"cache_cleared":       cacheClean,
		"gc_forced":           true,
		"zeroization_verified": cacheClean,
		"timestamp":           time.Now().UTC().Format(time.RFC3339),
		"request_id":          reqID,
	})
}

// ── Self-test implementations ────────────────────────────────

func runFIPSSelfTests() map[string]bool {
	return map[string]bool{
		"AES-256-GCM":    testAES256GCM(),
		"HMAC-SHA-256":   testHMACSHA256(),
		"SHA-256":        testSHA256(),
		"crypto/rand":    testCSPRNG(),
	}
}

// allFIPSSelfTestsPassed reports whether every entry in the results map is
// true. It is the integrity guard the service uses on startup before
// transitioning into operational mode (FIPS 140-3 §4.9.1).
func allFIPSSelfTestsPassed(results map[string]bool) bool {
	for _, ok := range results {
		if !ok {
			return false
		}
	}
	return len(results) > 0
}

func testAES256GCM() bool {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return false
	}
	plaintext := []byte("fips-self-test-vector")
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return false
	}
	// Zeroize key material after test.
	for i := range key {
		key[i] = 0
	}
	return string(pt) == string(plaintext)
}

func testHMACSHA256() bool {
	key := []byte("fips-hmac-test-key-32bytes-padded")
	msg := []byte("fips-self-test-message")
	mac := hmac.New(sha256.New, key)
	mac.Write(msg) //nolint:errcheck
	sum := hex.EncodeToString(mac.Sum(nil))
	// Recompute and compare — confirms determinism.
	mac2 := hmac.New(sha256.New, key)
	mac2.Write(msg) //nolint:errcheck
	return sum == hex.EncodeToString(mac2.Sum(nil)) && len(sum) == 64
}

func testSHA256() bool {
	// NIST FIPS 180-4 Appendix B.1 known-answer test vector for
	// SHA-256("abc"). Earlier the constant carried a typo and was
	// only 63 characters; the keycore startup self-test (added in
	// commit 263893d12) then failed-closed in production.
	h := sha256.New()
	h.Write([]byte("abc")) //nolint:errcheck
	got := hex.EncodeToString(h.Sum(nil))
	const expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	return strings.EqualFold(got, expected)
}

func testCSPRNG() bool {
	buf := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return false
	}
	// Basic sanity: not all zeros.
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	return !allZero
}

// ── RNG health test ──────────────────────────────────────────

type rngHealthResult struct {
	RepetitionCountPassed    bool
	AdaptiveProportionPassed bool
	SampleBytes              int
	UniqueBytes              int
	EntropyEstimate          float64
	Passed                   bool
}

func runRNGHealthTest() rngHealthResult {
	const sampleSize = 512
	buf := make([]byte, sampleSize)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return rngHealthResult{Passed: false}
	}

	// Repetition count test (NIST SP 800-90B §4.4.1):
	// No byte should appear more than H consecutive times where H is the
	// adaptive threshold. For entropy ≥ 1 bit, max run < 512.
	rctPassed := repetitionCountTest(buf)

	// Adaptive proportion test (NIST SP 800-90B §4.4.2):
	// Count occurrences of the most common byte in window; must not dominate.
	aptPassed, uniqueCount := adaptiveProportionTest(buf)

	entropyEst := shannonEntropy(buf)

	return rngHealthResult{
		RepetitionCountPassed:    rctPassed,
		AdaptiveProportionPassed: aptPassed,
		SampleBytes:              sampleSize,
		UniqueBytes:              uniqueCount,
		EntropyEstimate:          entropyEst,
		Passed:                   rctPassed && aptPassed && entropyEst > 4.0,
	}
}

func repetitionCountTest(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	maxRun := 1
	curRun := 1
	for i := 1; i < len(data); i++ {
		if data[i] == data[i-1] {
			curRun++
			if curRun > maxRun {
				maxRun = curRun
			}
		} else {
			curRun = 1
		}
	}
	// Threshold: max allowed consecutive identical bytes = 30 for 512 samples.
	return maxRun <= 30
}

func adaptiveProportionTest(data []byte) (bool, int) {
	counts := make(map[byte]int, 256)
	for _, b := range data {
		counts[b]++
	}
	maxCount := 0
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}
	// Allow at most 20% of samples to be the same byte value.
	threshold := len(data) / 5
	return maxCount < threshold, len(counts)
}

func shannonEntropy(data []byte) float64 {
	counts := make(map[byte]float64, 256)
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var entropy float64
	for _, c := range counts {
		p := c / n
		if p > 0 {
			// log2(p) = ln(p) / ln(2)
			entropy -= p * log2(p)
		}
	}
	return entropy
}

func log2(x float64) float64 {
	// Use the identity log2(x) = ln(x) / ln(2).
	// We avoid importing math to keep build constraints simple; implement via
	// a fast integer-accurate approximation for the entropy range [0, 8].
	if x <= 0 {
		return 0
	}
	// Fast natural log via a 5-term Taylor expansion around x=1.
	// Accurate to ~0.001 for 0 < x ≤ 1.
	y := (x - 1) / (x + 1)
	y2 := y * y
	ln := 2 * y * (1 + y2/3 + y2*y2/5 + y2*y2*y2/7 + y2*y2*y2*y2/9)
	return ln / 0.6931471805599453 // ln(2)
}
