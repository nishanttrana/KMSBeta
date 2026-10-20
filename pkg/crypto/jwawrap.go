package crypto

import (
	"crypto/aes"
	"crypto/fips140"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RSA-OAEP (SHA-1): one of the two RSA algorithms Azure Managed HSM external key management sends
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
)

// Wrapping a key under a KMS-held key with the algorithms JOSE (RFC 7518)
// names, as a key management proxy is asked to: Azure Managed HSM external
// key management sends A256KW, A256KWP, RSA-OAEP-256 or RSA-OAEP.
//
//	A256KW        AES key wrap (RFC 3394, SP 800-38F KW), 256-bit key
//	A256KWP       AES key wrap with padding (RFC 5649, SP 800-38F KWP)
//	RSA-OAEP-256  RSA-OAEP, SHA-256 and MGF1-SHA-256
//	RSA-OAEP      RSA-OAEP, SHA-1 and MGF1-SHA-1
//
// FIPS: RSA-OAEP-256 runs in the certified module. KW and KWP are built here
// on the module's AES block cipher and are not module services, and SHA-1
// OAEP is an external protocol mandate: the other three are refused in
// strict mode (pkg/fips impact catalogue, "jwa_key_wrap").
const (
	JWAA256KW     = "A256KW"
	JWAA256KWP    = "A256KWP"
	JWARSAOAEP256 = "RSA-OAEP-256"
	JWARSAOAEP    = "RSA-OAEP"
)

// ErrJWAStrict is a wrapping algorithm that strict FIPS mode refuses.
var ErrJWAStrict = errors.New("crypto: this key wrapping algorithm is not a FIPS module service and is refused in FIPS strict mode; use RSA-OAEP-256")

// ErrJWAUnsupported is an algorithm name this package doesn't implement, or
// one that doesn't fit the key.
var ErrJWAUnsupported = errors.New("crypto: unsupported key wrapping algorithm for this key")

// JWAIsAES reports whether alg wraps under an AES key.
func JWAIsAES(alg string) bool { return alg == JWAA256KW || alg == JWAA256KWP }

// JWAIsRSA reports whether alg wraps under an RSA key.
func JWAIsRSA(alg string) bool { return alg == JWARSAOAEP256 || alg == JWARSAOAEP }

// JWANeedsModuleOutside reports whether strict mode refuses alg.
func JWANeedsModuleOutside(alg string) bool { return alg != JWARSAOAEP256 }

func jwaAllowed(alg string) error {
	if !JWAIsAES(alg) && !JWAIsRSA(alg) {
		return ErrJWAUnsupported
	}
	if JWANeedsModuleOutside(alg) && fips140.Enforced() {
		return ErrJWAStrict
	}
	return nil
}

// JWAWrapAES wraps plain under a 256-bit AES key with A256KW or A256KWP.
func JWAWrapAES(alg string, kek, plain []byte) ([]byte, error) {
	if err := jwaAllowed(alg); err != nil {
		return nil, err
	}
	if !JWAIsAES(alg) || len(kek) != 32 {
		return nil, ErrJWAUnsupported
	}
	if alg == JWAA256KW {
		return wrapKW(kek, plain)
	}
	return wrapKWP(kek, plain)
}

// JWAUnwrapAES reverses JWAWrapAES, checking the integrity value.
func JWAUnwrapAES(alg string, kek, wrapped []byte) ([]byte, error) {
	if err := jwaAllowed(alg); err != nil {
		return nil, err
	}
	if !JWAIsAES(alg) || len(kek) != 32 {
		return nil, ErrJWAUnsupported
	}
	if alg == JWAA256KW {
		return unwrapKW(kek, wrapped)
	}
	return unwrapKWP(kek, wrapped)
}

func jwaOAEPHash(alg string) func() hash.Hash {
	if alg == JWARSAOAEP {
		return sha1.New
	}
	return sha256.New
}

// JWAWrapRSA wraps plain to an RSA public key with RSA-OAEP-256 or RSA-OAEP.
func JWAWrapRSA(alg string, pub *rsa.PublicKey, plain []byte) ([]byte, error) {
	if err := jwaAllowed(alg); err != nil {
		return nil, err
	}
	if !JWAIsRSA(alg) || pub == nil || pub.N.BitLen() < 2048 {
		return nil, ErrJWAUnsupported
	}
	return rsa.EncryptOAEP(jwaOAEPHash(alg)(), Reader, pub, plain, nil)
}

// JWAUnwrapRSA reverses JWAWrapRSA with the private key.
func JWAUnwrapRSA(alg string, priv *rsa.PrivateKey, wrapped []byte) ([]byte, error) {
	if err := jwaAllowed(alg); err != nil {
		return nil, err
	}
	if !JWAIsRSA(alg) || priv == nil || priv.N.BitLen() < 2048 {
		return nil, ErrJWAUnsupported
	}
	return rsa.DecryptOAEP(jwaOAEPHash(alg)(), Reader, priv, wrapped, nil)
}

// kwIV is the RFC 3394 default initial value.
var kwIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// wrapKW is AES key wrap (RFC 3394 section 2.2.1): at least two 64-bit
// blocks, a multiple of eight bytes.
func wrapKW(kek, plain []byte) ([]byte, error) {
	if len(plain) < 16 || len(plain)%8 != 0 {
		return nil, errors.New("crypto: KW input must be a multiple of 8 bytes, at least 16")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(plain) / 8
	a := kwIV
	r := make([]byte, len(plain))
	copy(r, plain)
	var b [16]byte
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(b[:8], a[:])
			copy(b[8:], r[i*8:i*8+8])
			block.Encrypt(b[:], b[:])
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(b[:8])^uint64(n*j+i+1))
			copy(r[i*8:], b[8:])
		}
	}
	Zeroize(b[:])
	return append(a[:], r...), nil
}

// unwrapKW reverses wrapKW and checks the integrity value in constant time.
func unwrapKW(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, errors.New("crypto: KW ciphertext length is invalid")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	var a [8]byte
	copy(a[:], wrapped[:8])
	r := append([]byte(nil), wrapped[8:]...)
	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(a[:])^uint64(n*j+i+1))
			copy(b[8:], r[i*8:i*8+8])
			block.Decrypt(b[:], b[:])
			copy(a[:], b[:8])
			copy(r[i*8:], b[8:])
		}
	}
	Zeroize(b[:])
	if subtle.ConstantTimeCompare(a[:], kwIV[:]) != 1 {
		Zeroize(r)
		return nil, errors.New("crypto: KW integrity check failed")
	}
	return r, nil
}
