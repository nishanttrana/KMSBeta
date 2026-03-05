package keycache

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// EncryptAESGCM performs local AES-GCM encryption using a cached key entry.
func EncryptAESGCM(entry *Entry, plaintext []byte) (ciphertext, iv []byte, err error) {
	if entry == nil || len(entry.Material) == 0 {
		return nil, nil, errors.New("keycache: nil or empty key entry")
	}
	blk, err := aes.NewCipher(entry.Material)
	if err != nil {
		return nil, nil, fmt.Errorf("keycache: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, nil, fmt.Errorf("keycache: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("keycache: generate nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return ct, nonce, nil
}

// DecryptAESGCM performs local AES-GCM decryption using a cached key entry.
func DecryptAESGCM(entry *Entry, ciphertext, iv []byte) ([]byte, error) {
	if entry == nil || len(entry.Material) == 0 {
		return nil, errors.New("keycache: nil or empty key entry")
	}
	blk, err := aes.NewCipher(entry.Material)
	if err != nil {
		return nil, fmt.Errorf("keycache: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, fmt.Errorf("keycache: gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("keycache: decrypt: %w", err)
	}
	return plaintext, nil
}
