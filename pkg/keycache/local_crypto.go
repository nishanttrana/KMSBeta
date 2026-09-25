package keycache

import (
	"errors"
	"fmt"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// EncryptAESGCM performs local AES-GCM encryption using a cached key entry.
// The nonce is generated inside the FIPS module (pkg/crypto), so this works in
// every FIPS runtime mode.
func EncryptAESGCM(entry *Entry, plaintext []byte) (ciphertext, iv []byte, err error) {
	if entry == nil || len(entry.Material) == 0 {
		return nil, nil, errors.New("keycache: nil or empty key entry")
	}
	nonce, ct, err := pkgcrypto.SealDetached(entry.Material, plaintext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("keycache: encrypt: %w", err)
	}
	return ct, nonce, nil
}

// DecryptAESGCM performs local AES-GCM decryption using a cached key entry.
func DecryptAESGCM(entry *Entry, ciphertext, iv []byte) ([]byte, error) {
	if entry == nil || len(entry.Material) == 0 {
		return nil, errors.New("keycache: nil or empty key entry")
	}
	plaintext, err := pkgcrypto.OpenDetached(entry.Material, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("keycache: decrypt: %w", err)
	}
	return plaintext, nil
}
