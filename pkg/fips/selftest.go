package fips

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
)

// SelfTestResult captures the outcome of a single CMVP power-on self-test.
type SelfTestResult struct {
	Name     string        `json:"name"`
	Passed   bool          `json:"passed"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"error,omitempty"`
}

var (
	selfTestResults []SelfTestResult
	selfTestMu      sync.RWMutex
)

// RunSelfTests executes all CMVP-required power-on self-tests and returns
// the first failure encountered. Individual results are stored for audit.
func RunSelfTests() error {
	tests := []struct {
		name string
		fn   func() error
	}{
		{"AES-256-GCM KAT", testAESGCMKAT},
		{"SHA-256 KAT", testSHA256KAT},
		{"HMAC-SHA256 KAT", testHMACSHA256KAT},
		{"RSA Signature KAT", testRSASignatureKAT},
		{"ECDSA-P256 KAT", testECDSAP256KAT},
		{"DRBG Health Test", testDRBGHealth},
	}

	selfTestMu.Lock()
	selfTestResults = make([]SelfTestResult, 0, len(tests))
	selfTestMu.Unlock()

	for _, t := range tests {
		start := time.Now()
		err := t.fn()
		elapsed := time.Since(start)

		result := SelfTestResult{
			Name:     t.name,
			Passed:   err == nil,
			Duration: elapsed,
		}
		if err != nil {
			result.Error = err.Error()
		}

		selfTestMu.Lock()
		selfTestResults = append(selfTestResults, result)
		selfTestMu.Unlock()

		if err != nil {
			return fmt.Errorf("fips self-test %q failed: %w", t.name, err)
		}
	}
	return nil
}

// SelfTestReport returns the results of the most recent self-test run.
func SelfTestReport() []SelfTestResult {
	selfTestMu.RLock()
	defer selfTestMu.RUnlock()
	out := make([]SelfTestResult, len(selfTestResults))
	copy(out, selfTestResults)
	return out
}

// ---- AES-256-GCM Known Answer Test ----
// Test vector from NIST SP 800-38D, Test Case 16 (AES-256, 96-bit IV, 128-bit tag).
func testAESGCMKAT() error {
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	nonce, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	plaintext, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	expectedCiphertext, _ := hex.DecodeString("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")
	expectedTag, _ := hex.DecodeString("eb9f796c8d356fc31a8433884b696f4f")

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("cipher.NewGCM: %w", err)
	}

	// Encrypt
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	ct := sealed[:len(sealed)-gcm.Overhead()]
	tag := sealed[len(sealed)-gcm.Overhead():]

	if !bytes.Equal(ct, expectedCiphertext) {
		return fmt.Errorf("ciphertext mismatch: got %x", ct)
	}
	if !bytes.Equal(tag, expectedTag) {
		return fmt.Errorf("tag mismatch: got %x", tag)
	}

	// Decrypt
	decrypted, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return fmt.Errorf("gcm.Open: %w", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		return fmt.Errorf("decrypted plaintext mismatch")
	}
	return nil
}

// ---- SHA-256 Known Answer Test ----
// NIST FIPS 180-4 example: SHA-256("abc")
func testSHA256KAT() error {
	input := []byte("abc")
	expectedHex := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	expected, _ := hex.DecodeString(expectedHex)

	actual := sha256.Sum256(input)
	if !bytes.Equal(actual[:], expected) {
		return fmt.Errorf("sha-256 digest mismatch: got %x", actual)
	}
	return nil
}

// ---- HMAC-SHA256 Known Answer Test ----
// RFC 4231 Test Case 2
func testHMACSHA256KAT() error {
	key := []byte("Jefe")
	data := []byte("what do ya want for nothing?")
	expectedHex := "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	expected, _ := hex.DecodeString(expectedHex)

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	actual := mac.Sum(nil)

	if !hmac.Equal(actual, expected) {
		return fmt.Errorf("hmac-sha256 mismatch: got %x", actual)
	}
	return nil
}

// ---- RSA Signature KAT ----
// Uses an embedded 2048-bit RSA test key for sign/verify round-trip.
var rsaTestKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEArkd+CKFsapTwFyRAC4t1qxGC3mwsTS958uKiwb2lZhXZwld+
RzSpYwMa8V7lr6Enf9sB6nzJeBAcceTrNJESgT3C6DOhkS8TUfJPJFjpwTJRSIZn
CcupMyJihPjHv49gu06mdFnQMpCPF0YQUZ7uu+psZgMSm+/3RJj83USHILOn+rZI
FZ3ucyAIi9zrXGE0zGTzIXFIDikE9UdnaZ0Fa2+gmsCctnYDFMhgyGUpwIe8fzgA
O2hJNeO7P1YEyCohoUWeuTQ5mxEG2XGdi9s2bpEgaGvU3mT8/+19Q28+z8NdBNH1
8xyg46lWQvsoBz10O02kqw7AQ3hUm64K5dgSZwIDAQABAoIBAAWaMlanwLNzmyeq
wPwIsF9R46drbD/R4EiPH5cSYr18GN3ehXvPCCqoUCngtlasIAB3TxtTMMzqyDOR
4feW05sf15pUwCnarvMtORa8oPeSVHIvZKueipfxNmzhDnCfyij9Z4XjLX2zsasy
D3SiXtKsjJAszcc0kE9PV7ENezm+CcCRqPpt4XxOb+B/XOm2elT/57Cc3VWbuJPX
BRZWBF75m6HqgXRgAsxFFzjsAL+3HQNlkh1YzWvNbDMXLza5YF4KrnnQvukR8LTW
kT8FVl4E5VLVhnqGW28HteSC+iPnDdX+WKMAgyMJdXOzvRfWKzLQcCgvmBgOaBic
Uzd0o3kCgYEAwF/065rXtRPa+Niyn8yrxWdDgTYX04rIm02hpTCkJmqWY4/GtTw7
xFLXbIksUuWAI4cbk4L9uy95P2Zks3jdfFSB+6seiQBLYF32yvfT4MMz1z08cU68
G6k/Rh+N+q8xqXuWiREfFC7wuwgiPmfZsQNalhb4Hpxz+48IAWGbQqsCgYEA5+tq
Yxp8lICAXNyhIr1A9BBflca69QsFcr2og4auOTeU4Zd6wRv/KOACbtaHlKG1HRdk
FsEeYoe4DPq98+Av6I1fNewyEZBKkxVCp/fmX4Jhv5LOqlVmpsMBguHEaYDykpNL
tnh06MON+eUZadULE5lNjHksuKc1EKP2+qlhzzUCgYAfRfos6wkyGL46QhAXxlAO
UVE6Ci8pZqBiDua+Uf/9dspn+RGWmOomakk3Db205DZGkEo9WsggzADr+5tXScjH
030mCpV2NCQM0Hm0WUGKgnFFBmFzEhemb4cnwS11mVF7eeno8m2Y/GCKJzJZ7swG
6MKrL6S6ZTi9pmzovJNe7QKBgQDISWDJUZiBTzCMAeYO8E5l+LXzzXqsIOaFnxEm
9WsE8uFaqc1TdHA5xquTOSZB0B1vkEHZ/NHW2cqzOuBM+zGkrmKpWOAsluYwe83i
7Y5AsYLlRU3BgJt0LTji5UMQslHLD/X1EbY1Rp0YUShPY7N7K4vzYrqihZSoWFH1
S86yeQKBgB8hKLjITh6hDtoXRaSKhdt6d1o6TnUWUppePfYlG4mUo+qF7ehbBGAA
skJFwV7i7p+M9eFrzLSFYSUZ0TzlN8DRmFIIcBZc/zXh2dWZQOFvF99I7l89oARf
FyrLEyYhSpgvNuS9cDaWczZK8KSRt0ceAI1i3qTNNXa2ANaEngmH
-----END RSA PRIVATE KEY-----`

func testRSASignatureKAT() error {
	block, _ := pem.Decode([]byte(rsaTestKeyPEM))
	if block == nil {
		return fmt.Errorf("failed to decode RSA test key PEM")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("x509.ParsePKCS1PrivateKey: %w", err)
	}

	message := []byte("FIPS 140-3 RSA self-test message")
	hashed := sha256.Sum256(message)

	// Sign
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		return fmt.Errorf("rsa.SignPKCS1v15: %w", err)
	}

	// Verify
	err = rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return fmt.Errorf("rsa.VerifyPKCS1v15: %w", err)
	}

	// Negative test: tamper with signature and ensure verification fails
	tampered := make([]byte, len(signature))
	copy(tampered, signature)
	tampered[0] ^= 0xFF
	err = rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.SHA256, hashed[:], tampered)
	if err == nil {
		return fmt.Errorf("RSA signature verification should have failed with tampered signature")
	}
	return nil
}

// ---- ECDSA-P256 KAT ----
// Generates a deterministic test key from a fixed seed and performs sign/verify.
func testECDSAP256KAT() error {
	// Use a fixed private key scalar for reproducibility
	curve := elliptic.P256()
	dBytes, _ := hex.DecodeString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
	d := new(big.Int).SetBytes(dBytes)
	x, y := curve.ScalarBaseMult(dBytes)

	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}

	message := []byte("FIPS 140-3 ECDSA-P256 self-test message")
	hashed := sha256.Sum256(message)

	// Sign
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, hashed[:])
	if err != nil {
		return fmt.Errorf("ecdsa.SignASN1: %w", err)
	}

	// Verify
	if !ecdsa.VerifyASN1(&privKey.PublicKey, hashed[:], sig) {
		return fmt.Errorf("ECDSA-P256 signature verification failed")
	}

	// Negative test: tamper with hash
	badHash := sha256.Sum256([]byte("tampered"))
	if ecdsa.VerifyASN1(&privKey.PublicKey, badHash[:], sig) {
		return fmt.Errorf("ECDSA-P256 verification should have failed with wrong hash")
	}
	return nil
}

// ---- DRBG Health Test ----
// Verifies crypto/rand produces non-zero output with sufficient entropy
// using a basic chi-squared uniformity test on byte values.
func testDRBGHealth() error {
	const sampleSize = 4096

	buf := make([]byte, sampleSize)
	n, err := rand.Read(buf)
	if err != nil {
		return fmt.Errorf("crypto/rand.Read: %w", err)
	}
	if n != sampleSize {
		return fmt.Errorf("short read from crypto/rand: got %d, want %d", n, sampleSize)
	}

	// Check not all zeros
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("crypto/rand produced all-zero output")
	}

	// Chi-squared test for byte uniformity.
	// Expected frequency per byte value = sampleSize / 256.
	var observed [256]float64
	for _, b := range buf {
		observed[b]++
	}
	expected := float64(sampleSize) / 256.0
	chiSquared := 0.0
	for i := 0; i < 256; i++ {
		diff := observed[i] - expected
		chiSquared += (diff * diff) / expected
	}

	// With 255 degrees of freedom, the critical value at p=0.001 is ~310.5
	// and at p=0.999 is ~201.1. We use generous bounds to avoid false positives
	// while still catching a stuck or biased RNG.
	const chiLow = 170.0  // very unlikely for a good RNG to be below this
	const chiHigh = 350.0 // very unlikely for a good RNG to be above this
	if chiSquared < chiLow || chiSquared > chiHigh {
		return fmt.Errorf(
			"DRBG chi-squared test failed: χ²=%.2f (expected %.1f–%.1f for 255 df)",
			chiSquared, chiLow, chiHigh,
		)
	}

	// Shannon entropy estimate — expect at least 7.0 bits per byte for random data
	entropy := 0.0
	for i := 0; i < 256; i++ {
		if observed[i] > 0 {
			p := observed[i] / float64(sampleSize)
			entropy -= p * math.Log2(p)
		}
	}
	if entropy < 7.0 {
		return fmt.Errorf("DRBG entropy too low: %.4f bits/byte (minimum 7.0)", entropy)
	}

	return nil
}

// RunIntegrityCheck computes the SHA-256 hash of the binary at binaryPath
// and compares it against the VECTA_BINARY_HASH environment variable (hex-encoded).
// If the env var is not set, the check is skipped (returns nil).
func RunIntegrityCheck(binaryPath string) error {
	expectedHex := strings.TrimSpace(os.Getenv("VECTA_BINARY_HASH"))
	if expectedHex == "" {
		return nil // No expected hash configured, skip
	}

	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		return fmt.Errorf("fips integrity: invalid VECTA_BINARY_HASH hex: %w", err)
	}

	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("fips integrity: cannot read binary %q: %w", binaryPath, err)
	}

	actual := sha256.Sum256(data)
	if !bytes.Equal(actual[:], expected) {
		return fmt.Errorf(
			"fips integrity: binary hash mismatch: expected %x, got %x",
			expected, actual[:],
		)
	}
	return nil
}
