package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Raw Ed25519 key/signature sizes for callers validating base64-decoded
// material without importing crypto/ed25519 directly.
const (
	Ed25519PublicKeySize = ed25519.PublicKeySize
	Ed25519SignatureSize = ed25519.SignatureSize
)

// Ed25519VerifyRaw verifies a signature with a raw 32-byte public key,
// rejecting malformed key or signature lengths.
func Ed25519VerifyRaw(pubRaw []byte, msg []byte, sig []byte) bool {
	if len(pubRaw) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubRaw), msg, sig)
}

// X25519PublicKeyValid reports whether raw bytes form a valid X25519 public key.
func X25519PublicKeyValid(raw []byte) bool {
	_, err := ecdh.X25519().NewPublicKey(raw)
	return err == nil
}

// HPKESealX25519 encrypts plaintext to a raw X25519 recipient public key
// using HPKE base mode with DHKEM(X25519), HKDF-SHA256 and AES-256-GCM.
// It returns the KEM encapsulation and the ciphertext.
func HPKESealX25519(recipientPubRaw []byte, plaintext []byte, aad []byte, info []byte) (enc []byte, ciphertext []byte, err error) {
	pub, err := ecdh.X25519().NewPublicKey(recipientPubRaw)
	if err != nil {
		return nil, nil, errors.New("crypto: invalid X25519 recipient public key")
	}
	hpkePub, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	enc, sender, err := hpke.NewSender(hpkePub, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err = sender.Seal(aad, plaintext)
	if err != nil {
		return nil, nil, err
	}
	return enc, ciphertext, nil
}

// ECDHX25519Ephemeral generates an ephemeral X25519 key pair and returns the
// ephemeral public key bytes plus the shared secret with the recipient.
// Callers must Zeroize the shared secret after deriving from it.
func ECDHX25519Ephemeral(recipientPubRaw []byte) (ephemeralPubRaw []byte, shared []byte, err error) {
	curve := ecdh.X25519()
	pub, err := curve.NewPublicKey(recipientPubRaw)
	if err != nil {
		return nil, nil, errors.New("crypto: invalid X25519 recipient public key")
	}
	eph, err := curve.GenerateKey(Reader)
	if err != nil {
		return nil, nil, err
	}
	shared, err = eph.ECDH(pub)
	if err != nil {
		return nil, nil, err
	}
	return eph.PublicKey().Bytes(), shared, nil
}

// HKDFSHA256 derives n bytes from a secret with HKDF-SHA256.
func HKDFSHA256(secret []byte, salt []byte, info []byte, n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("crypto: derived length must be positive")
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, salt, info), out); err != nil {
		return nil, err
	}
	return out, nil
}
