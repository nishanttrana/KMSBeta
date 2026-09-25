package crypto

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
)

type IVMode string

const (
	IVInternal      IVMode = "internal"
	IVExternal      IVMode = "external"
	IVDeterministic IVMode = "deterministic"
)

type EnvelopeCiphertext struct {
	WrappedDEK   []byte
	WrappedDEKIV []byte
	Ciphertext   []byte
	DataIV       []byte
}

func ComputeKCV(algorithm string, key []byte) (string, error) {
	if len(key) == 0 {
		return "", errors.New("empty key")
	}
	tag := []byte(algorithm)
	sum := sha256.Sum256(append(tag, key...))
	return hex.EncodeToString(sum[:3]), nil
}

func GenerateIV(mode IVMode, keyMaterial []byte, externalIV []byte, payload []byte) ([]byte, error) {
	switch mode {
	case IVInternal:
		iv := make([]byte, aes.BlockSize)
		_, err := rand.Read(iv)
		return iv, err
	case IVExternal:
		if len(externalIV) != aes.BlockSize {
			return nil, errors.New("external IV must be 16 bytes")
		}
		out := make([]byte, len(externalIV))
		copy(out, externalIV)
		return out, nil
	case IVDeterministic:
		// HMAC keys under 112 bits panic in FIPS strict mode; fail cleanly.
		if len(keyMaterial) < minHMACKeyBytes {
			return nil, fmt.Errorf("deterministic IV requires key material of at least %d bytes", minHMACKeyBytes)
		}
		mac := hmac.New(sha256.New, keyMaterial)
		_, _ = mac.Write(payload)
		sum := mac.Sum(nil)
		return sum[:aes.BlockSize], nil
	default:
		return nil, errors.New("unsupported IV mode")
	}
}

func EncryptEnvelope(mek []byte, plaintext []byte) (*EnvelopeCiphertext, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	defer Zeroize(dek)

	dataIV, ciphertext, err := SealDetached(dek, plaintext, nil)
	if err != nil {
		return nil, err
	}
	wrappedIV, wrappedDEK, err := SealDetached(mek, dek, nil)
	if err != nil {
		return nil, err
	}
	return &EnvelopeCiphertext{
		WrappedDEK:   wrappedDEK,
		WrappedDEKIV: storedEnvelopeIV(wrappedIV),
		Ciphertext:   ciphertext,
		DataIV:       storedEnvelopeIV(dataIV),
	}, nil
}

func DecryptEnvelope(mek []byte, env *EnvelopeCiphertext) ([]byte, error) {
	dek, err := OpenDetached(mek, envelopeNonce(env.WrappedDEKIV), env.WrappedDEK, nil)
	if err != nil {
		return nil, err
	}
	defer Zeroize(dek)
	return OpenDetached(dek, envelopeNonce(env.DataIV), env.Ciphertext, nil)
}

// minHMACKeyBytes is the 112-bit HMAC key floor of SP 800-131A.
const minHMACKeyBytes = 14

// Envelope IVs are persisted as 16 bytes (keycore packs WrappedDEKIV as a
// fixed 16-byte prefix). AES-GCM uses only the first 12 bytes, the nonce the
// FIPS module generated; bytes 12-15 are zero padding kept for the format.
const storedEnvelopeIVSize = 16

func storedEnvelopeIV(nonce []byte) []byte {
	out := make([]byte, storedEnvelopeIVSize)
	copy(out, nonce)
	return out
}

// envelopeNonce returns the GCM nonce (first 12 bytes) of a stored envelope IV.
func envelopeNonce(iv []byte) []byte {
	if len(iv) > GCMNonceSize {
		return iv[:GCMNonceSize]
	}
	return iv
}

func ConstantTimeEqual(a []byte, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Zeroize overwrites a byte slice with zeros. The //go:noinline directive
// prevents the compiler from dead-store-eliminating the zeroing loop.
//
//go:noinline
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
