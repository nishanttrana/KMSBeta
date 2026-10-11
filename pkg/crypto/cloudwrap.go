package crypto

import (
	"crypto/aes"
	"crypto/fips140"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // CloudWrapRSAOAEPSHA1 / RSAAESKWPSHA1: mandated by Azure Key Vault BYOK and Salesforce Shield only
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"fmt"
	"hash"
)

// Wrapping key material to a cloud KMS's import public key (BYOK). The cloud
// generates an RSA wrapping key, hands out its public half, and unwraps the
// material inside its own HSM. These are the schemes clouds accept; every
// cloud names them differently, the KMS names them once.
//
//	rsa-oaep-sha256     RSA-OAEP, SHA-256 and MGF1-SHA-256, over the material
//	rsa-oaep-sha1       RSA-OAEP, SHA-1 (Salesforce Shield)
//	rsa-aes-kwp-sha256  CKM_RSA_AES_KEY_WRAP: a fresh AES-256 key under
//	                    RSA-OAEP SHA-256, then the material under that key
//	                    with AES key wrap with padding (RFC 5649, SP 800-38F
//	                    KWP); output is the two concatenated
//	rsa-aes-kwp-sha1    the same with SHA-1 in OAEP (Azure Key Vault)
//
// FIPS: RSA-OAEP with SHA-256 runs in the certified module. KWP is built
// here on the module's AES block cipher and is not a module service, and
// SHA-1 OAEP is an external protocol mandate, so the other three are refused
// in strict mode (pkg/fips impact catalogue, "cloud_byok_wrap").
const (
	CloudWrapRSAOAEPSHA256 = "rsa-oaep-sha256"
	CloudWrapRSAOAEPSHA1   = "rsa-oaep-sha1"
	CloudWrapRSAAESKWP256  = "rsa-aes-kwp-sha256"
	CloudWrapRSAAESKWPSHA1 = "rsa-aes-kwp-sha1"
)

// ErrCloudWrapStrict is a scheme that strict FIPS mode refuses.
var ErrCloudWrapStrict = errors.New("crypto: this cloud import wrapping scheme is not a FIPS module service and is refused in FIPS strict mode (VECTA_FIPS_MODE=only); use rsa-oaep-sha256 or generate the key in a PKCS#11 HSM")

// CloudWrapSchemes lists the schemes WrapForCloudImport accepts.
var CloudWrapSchemes = []string{CloudWrapRSAOAEPSHA256, CloudWrapRSAOAEPSHA1, CloudWrapRSAAESKWP256, CloudWrapRSAAESKWPSHA1}

// CloudWrapNeedsModuleOutside reports whether scheme is refused in strict
// mode when the KMS (not an HSM) performs it.
func CloudWrapNeedsModuleOutside(scheme string) bool { return scheme != CloudWrapRSAOAEPSHA256 }

func cloudWrapHash(scheme string) (func() hash.Hash, bool, error) {
	switch scheme {
	case CloudWrapRSAOAEPSHA256:
		return sha256.New, false, nil
	case CloudWrapRSAOAEPSHA1:
		return sha1.New, false, nil
	case CloudWrapRSAAESKWP256:
		return sha256.New, true, nil
	case CloudWrapRSAAESKWPSHA1:
		return sha1.New, true, nil
	}
	return nil, false, fmt.Errorf("crypto: unknown cloud wrapping scheme %q", scheme)
}

// ParseCloudWrappingKey reads a cloud's RSA import key as the clouds hand
// it out: PKIX or PKCS#1 DER, or the same in PEM.
func ParseCloudWrappingKey(raw []byte) (*rsa.PublicKey, error) {
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	if pub, err := x509.ParsePKIXPublicKey(raw); err == nil {
		if k, ok := pub.(*rsa.PublicKey); ok {
			return k, nil
		}
		return nil, errors.New("crypto: the cloud's wrapping key is not RSA")
	}
	if k, err := x509.ParsePKCS1PublicKey(raw); err == nil {
		return k, nil
	}
	return nil, errors.New("crypto: the cloud's wrapping key is not an RSA public key in DER or PEM")
}

// RSAPublicComponents returns the modulus and public exponent, big-endian,
// as PKCS#11 CKA_MODULUS and CKA_PUBLIC_EXPONENT take them.
func RSAPublicComponents(pub *rsa.PublicKey) (modulus, exponent []byte) {
	return pub.N.Bytes(), big.NewInt(int64(pub.E)).Bytes()
}

// WrapForCloudImport wraps material (raw symmetric key bytes, or a PKCS#8
// private key for the rsa-aes-kwp schemes) to a cloud's RSA import key.
func WrapForCloudImport(pub *rsa.PublicKey, material []byte, scheme string) ([]byte, error) {
	newHash, kwp, err := cloudWrapHash(scheme)
	if err != nil {
		return nil, err
	}
	if CloudWrapNeedsModuleOutside(scheme) && fips140.Enforced() {
		return nil, ErrCloudWrapStrict
	}
	if pub == nil || pub.N.BitLen() < 2048 {
		return nil, errors.New("crypto: the cloud's wrapping key must be RSA of at least 2048 bits")
	}
	if len(material) == 0 {
		return nil, errors.New("crypto: no key material to wrap")
	}
	if !kwp {
		return rsa.EncryptOAEP(newHash(), Reader, pub, material, nil)
	}
	ephemeral := make([]byte, 32)
	if _, err := Reader.Read(ephemeral); err != nil {
		return nil, err
	}
	defer Zeroize(ephemeral)
	head, err := rsa.EncryptOAEP(newHash(), Reader, pub, ephemeral, nil)
	if err != nil {
		return nil, err
	}
	tail, err := wrapKWP(ephemeral, material)
	if err != nil {
		return nil, err
	}
	return append(head, tail...), nil
}

// UnwrapCloudImport reverses WrapForCloudImport with the RSA private key.
// It is what a cloud does on import; the KMS uses it to prove its own
// output (tests), never to receive material.
func UnwrapCloudImport(priv *rsa.PrivateKey, wrapped []byte, scheme string) ([]byte, error) {
	newHash, kwp, err := cloudWrapHash(scheme)
	if err != nil {
		return nil, err
	}
	if CloudWrapNeedsModuleOutside(scheme) && fips140.Enforced() {
		return nil, ErrCloudWrapStrict
	}
	if !kwp {
		return rsa.DecryptOAEP(newHash(), Reader, priv, wrapped, nil)
	}
	k := priv.Size()
	if len(wrapped) <= k {
		return nil, errors.New("crypto: wrapped blob is shorter than the RSA part")
	}
	ephemeral, err := rsa.DecryptOAEP(newHash(), Reader, priv, wrapped[:k], nil)
	if err != nil {
		return nil, err
	}
	defer Zeroize(ephemeral)
	return unwrapKWP(ephemeral, wrapped[k:])
}

// kwpIV is the RFC 5649 alternative initial value's constant half.
var kwpIV = [4]byte{0xA6, 0x59, 0x59, 0xA6}

// wrapKWP is AES key wrap with padding (RFC 5649).
func wrapKWP(kek, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	if len(plain) == 0 || uint64(len(plain)) > 0xFFFFFFFF {
		return nil, errors.New("crypto: KWP input length out of range")
	}
	padded := make([]byte, (len(plain)+7)/8*8)
	copy(padded, plain)
	defer Zeroize(padded)
	var a [8]byte
	copy(a[:4], kwpIV[:])
	binary.BigEndian.PutUint32(a[4:], uint32(len(plain)))
	if len(padded) == 8 {
		out := make([]byte, 16)
		copy(out, a[:])
		copy(out[8:], padded)
		block.Encrypt(out, out)
		return out, nil
	}
	n := len(padded) / 8
	r := make([]byte, len(padded))
	copy(r, padded)
	var b [16]byte
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(b[:8], a[:])
			copy(b[8:], r[i*8:i*8+8])
			block.Encrypt(b[:], b[:])
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(b[:8])^t)
			copy(r[i*8:], b[8:])
		}
	}
	return append(a[:], r...), nil
}

// unwrapKWP reverses wrapKWP and checks the integrity value and padding.
func unwrapKWP(kek, wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < 16 || len(wrapped)%8 != 0 {
		return nil, errors.New("crypto: KWP ciphertext length is invalid")
	}
	var a [8]byte
	var r []byte
	if len(wrapped) == 16 {
		var b [16]byte
		block.Decrypt(b[:], wrapped)
		copy(a[:], b[:8])
		r = append([]byte(nil), b[8:]...)
	} else {
		n := len(wrapped)/8 - 1
		copy(a[:], wrapped[:8])
		r = append([]byte(nil), wrapped[8:]...)
		var b [16]byte
		for j := 5; j >= 0; j-- {
			for i := n - 1; i >= 0; i-- {
				t := uint64(n*j + i + 1)
				binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(a[:])^t)
				copy(b[8:], r[i*8:i*8+8])
				block.Decrypt(b[:], b[:])
				copy(a[:], b[:8])
				copy(r[i*8:], b[8:])
			}
		}
	}
	mli := int(binary.BigEndian.Uint32(a[4:]))
	ok := subtle.ConstantTimeCompare(a[:4], kwpIV[:]) == 1 && mli <= len(r) && mli > len(r)-8
	if ok {
		var pad byte
		for _, c := range r[mli:] {
			pad |= c
		}
		ok = pad == 0
	}
	if !ok {
		Zeroize(r)
		return nil, errors.New("crypto: KWP integrity check failed")
	}
	return r[:mli], nil
}
