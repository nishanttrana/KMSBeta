package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
)

// ParsePublicKeyPEM parses a PEM block containing a PKIX or PKCS#1 public
// key, or an X.509 certificate (returning its public key).
func ParsePublicKeyPEM(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return nil, errors.New("crypto: no PEM block found")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert.PublicKey, nil
	}
	return nil, errors.New("crypto: PEM does not contain a parseable public key")
}

// ParseRSAPublicKeyPEM parses a PEM public key and requires it to be RSA.
func ParseRSAPublicKeyPEM(pemStr string) (*rsa.PublicKey, error) {
	pub, err := ParsePublicKeyPEM(pemStr)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("crypto: public key is not RSA")
	}
	return rsaPub, nil
}

// FingerprintPublicKey returns the uppercase hex SHA-256 fingerprint of the
// key's PKIX DER encoding.
func FingerprintPublicKey(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

// DescribePublicKey reports the key family ("RSA", "ECDSA", "ED25519") and
// size in bits, or ("", 0) for unsupported types.
func DescribePublicKey(pub crypto.PublicKey) (string, int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.Size() * 8
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "ED25519", 256
	default:
		return "", 0
	}
}

// VerifySignatureAny verifies a signature over data accepting the common
// schemes per key family: RSA-PSS or PKCS#1 v1.5 over SHA-256, ECDSA ASN.1
// over SHA-256, or pure Ed25519. Used for client/terminal challenge
// signatures where the signer's library choice is not controlled.
func VerifySignatureAny(pub crypto.PublicKey, data []byte, sig []byte) bool {
	digest := sha256.Sum256(data)
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if rsa.VerifyPSS(key, crypto.SHA256, digest[:], sig, nil) == nil {
			return true
		}
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, digest[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(key, data, sig)
	default:
		return false
	}
}

// WrapKeyRSAOAEP wraps key material to a recipient RSA public key using
// RSA-OAEP with SHA-256 and the given label.
func WrapKeyRSAOAEP(pub crypto.PublicKey, key []byte, label []byte) ([]byte, error) {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("crypto: OAEP wrapping requires an RSA public key")
	}
	return rsa.EncryptOAEP(sha256.New(), Reader, rsaPub, key, label)
}

// SealDetached encrypts with AES-GCM returning nonce and ciphertext
// separately, for wire formats that transport them as distinct fields.
// Prefer Seal (embedded nonce) for new formats.
func SealDetached(key []byte, plaintext []byte, aad []byte) (nonce []byte, ciphertext []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = RandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

// OpenDetached decrypts AES-GCM output produced by SealDetached.
func OpenDetached(key []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}
