package crypto

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

// RecipientSealAlgorithm names the construction SealToRecipient produces:
// a fresh AES-256 key wrapped with RSA-OAEP-SHA-256 (SP 800-56B key
// transport), and the plaintext sealed under it with AES-256-GCM using a
// module-generated IV.
const RecipientSealAlgorithm = "RSA-OAEP-256+A256GCM"

// recipientOAEPLabel binds the wrapped key to this construction.
var recipientOAEPLabel = []byte("vecta-kms recipient seal v1")

// ParseRecipientPublicKey parses a DER SubjectPublicKeyInfo and requires an
// RSA key of 2048 to 8192 bits, the recipients SealToRecipient supports.
func ParseRecipientPublicKey(der []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("crypto: recipient key is not a DER SubjectPublicKeyInfo: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("crypto: recipient key must be RSA")
	}
	if bits := rsaPub.N.BitLen(); bits < 2048 || bits > 8192 {
		return nil, fmt.Errorf("crypto: recipient RSA key is %d bits; 2048 to 8192 are accepted", bits)
	}
	return rsaPub, nil
}

// RecipientKeyBinding is how an attestation commits to a recipient key when
// it cannot carry the key itself: base64url (unpadded) SHA-256 of its DER
// SubjectPublicKeyInfo.
func RecipientKeyBinding(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// SealToRecipient encrypts plaintext so only the holder of the recipient's
// private key can read it. aad is authenticated, not encrypted.
func SealToRecipient(pub *rsa.PublicKey, plaintext, aad []byte) (wrappedKey, nonce, ciphertext []byte, err error) {
	if pub == nil {
		return nil, nil, nil, errors.New("crypto: recipient key is required")
	}
	cek, err := RandomBytes(32)
	if err != nil {
		return nil, nil, nil, err
	}
	defer Zeroize(cek)
	if wrappedKey, err = WrapKeyRSAOAEP(pub, cek, recipientOAEPLabel); err != nil {
		return nil, nil, nil, err
	}
	if nonce, ciphertext, err = SealDetached(cek, plaintext, aad); err != nil {
		return nil, nil, nil, err
	}
	return wrappedKey, nonce, ciphertext, nil
}

// OpenFromRecipient reverses SealToRecipient with the recipient's private
// key. It runs where the private key lives (the enclave, or a test).
func OpenFromRecipient(priv *rsa.PrivateKey, wrappedKey, nonce, ciphertext, aad []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("crypto: recipient private key is required")
	}
	cek, err := rsa.DecryptOAEP(sha256.New(), nil, priv, wrappedKey, recipientOAEPLabel)
	if err != nil {
		return nil, errors.New("crypto: recipient seal key did not unwrap")
	}
	defer Zeroize(cek)
	return OpenDetached(cek, nonce, ciphertext, aad)
}
