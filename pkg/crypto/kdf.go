package crypto

import (
	"crypto/fips140"
	"crypto/pbkdf2"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Password/secret-stretching KDFs for the keycore KDF endpoint. PBKDF2 comes
// from the FIPS 140-3 Go Cryptographic Module; scrypt and Argon2id are not
// approved and are refused in strict mode (listed in pkg/fips impact).

// ErrKDFStrict is returned for a non-approved KDF under VECTA_FIPS_MODE=only.
var ErrKDFStrict = errors.New("crypto: scrypt and Argon2id are not FIPS-approved and are refused in strict mode (VECTA_FIPS_MODE=only); use HKDF-SHA256 or PBKDF2-SHA256")

// PBKDF2SHA256 derives n bytes with PBKDF2-HMAC-SHA256.
func PBKDF2SHA256(secret, salt []byte, iterations, n int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(secret), salt, iterations, n)
}

// Scrypt derives n bytes with scrypt (RFC 7914). Not FIPS-approved.
func Scrypt(secret, salt []byte, N, r, p, n int) ([]byte, error) {
	if fips140.Enforced() {
		return nil, ErrKDFStrict
	}
	return scrypt.Key(secret, salt, N, r, p, n)
}

// Argon2id derives n bytes with Argon2id (RFC 9106). Not FIPS-approved.
func Argon2id(secret, salt []byte, time, memoryKiB uint32, threads uint8, n uint32) ([]byte, error) {
	if fips140.Enforced() {
		return nil, ErrKDFStrict
	}
	return argon2.IDKey(secret, salt, time, memoryKiB, threads, n), nil
}
