package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"errors"
	"fmt"

	"vecta-kms/pkg/fips"
)

// AES-GCM through the FIPS 140-3 Go Cryptographic Module.
//
// FIPS 140-3 IG C.H requires the GCM IV to be generated inside the module
// boundary. Seal, SealDetached and every other encryption helper here use
// cipher.NewGCMWithRandomNonce, so they work in every runtime mode including
// GODEBUG=fips140=only. A caller-chosen nonce (external or deterministic IV
// features) must go through SealGCMWithNonce, which strict mode refuses.

// GCMNonceSize is the only nonce size used for AES-GCM (96 bits).
const GCMNonceSize = 12

// ErrCallerNonceStrict is returned when a caller-supplied GCM nonce is used
// while the runtime enforces FIPS 140-only mode.
var ErrCallerNonceStrict = errors.New("crypto: caller-supplied AES-GCM IV is not permitted in FIPS strict mode (VECTA_FIPS_MODE=only); use an internally generated IV")

func gcmBlock(key []byte) (cipher.Block, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("crypto: AES key must be 16, 24 or 32 bytes, got %d", len(key))
	}
	if err := fips.ValidateKeyLength("AES", len(key)*8); err != nil {
		return nil, err
	}
	return aes.NewCipher(key)
}

// moduleGCM returns AES-GCM whose nonce is generated inside the FIPS module.
// Its Seal/Open work on nonce || ciphertext || tag.
func moduleGCM(key []byte) (cipher.AEAD, error) {
	blk, err := gcmBlock(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(blk)
}

// Seal encrypts plaintext with AES-GCM and returns nonce||ciphertext. aad is
// optional additional authenticated data.
func Seal(key []byte, plaintext []byte, aad []byte) ([]byte, error) {
	aead, err := moduleGCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nil, plaintext, aad), nil
}

// Open decrypts a blob produced by Seal (nonce||ciphertext).
func Open(key []byte, blob []byte, aad []byte) ([]byte, error) {
	if len(blob) < GCMNonceSize {
		return nil, errors.New("crypto: ciphertext shorter than nonce")
	}
	aead, err := moduleGCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nil, blob, aad)
}

// SealDetached encrypts with AES-GCM returning nonce and ciphertext
// separately, for wire formats that transport them as distinct fields.
// Prefer Seal (embedded nonce) for new formats.
func SealDetached(key []byte, plaintext []byte, aad []byte) (nonce []byte, ciphertext []byte, err error) {
	blob, err := Seal(key, plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	return blob[:GCMNonceSize:GCMNonceSize], blob[GCMNonceSize:], nil
}

// OpenDetached decrypts AES-GCM output with a separate 96-bit nonce, as
// produced by SealDetached or SealGCMWithNonce. Works in every FIPS mode.
func OpenDetached(key []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	if len(nonce) != GCMNonceSize {
		return nil, fmt.Errorf("crypto: AES-GCM nonce must be %d bytes, got %d", GCMNonceSize, len(nonce))
	}
	blob := make([]byte, 0, len(nonce)+len(ciphertext))
	return Open(key, append(append(blob, nonce...), ciphertext...), aad)
}

// SealGCMWithNonce encrypts with a caller-supplied nonce. It exists only for
// features where the customer or the protocol chooses the IV (external or
// deterministic IV modes), and is refused in FIPS 140-only mode.
func SealGCMWithNonce(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if fips140.Enforced() {
		return nil, ErrCallerNonceStrict
	}
	if len(nonce) != GCMNonceSize {
		return nil, fmt.Errorf("crypto: AES-GCM nonce must be %d bytes, got %d", GCMNonceSize, len(nonce))
	}
	blk, err := gcmBlock(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}
