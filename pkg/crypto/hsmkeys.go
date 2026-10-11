package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"strconv"
)

// Conversions between PKCS#11 object attributes and the forms the platform
// stores, for keys that live in a customer HSM (pkg/hsm, services/hsm-connector).
// No key material is generated or used here.

// PKIXFromRSAComponents builds a PKIX DER public key from CKA_MODULUS and
// CKA_PUBLIC_EXPONENT (big-endian).
func PKIXFromRSAComponents(modulus, exponent []byte) ([]byte, error) {
	e := new(big.Int).SetBytes(exponent)
	if len(modulus) == 0 || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, errors.New("crypto: invalid RSA public components")
	}
	return x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(e.Int64())})
}

// ECCurveParamsDER returns the DER OID PKCS#11 expects in CKA_EC_PARAMS.
func ECCurveParamsDER(curve string) ([]byte, error) {
	switch curve {
	case "P256":
		return asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	case "P384":
		return asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34})
	}
	return nil, errors.New("crypto: unsupported curve " + curve)
}

func namedCurve(curve string) (elliptic.Curve, int, error) {
	switch curve {
	case "P256":
		return elliptic.P256(), 32, nil
	case "P384":
		return elliptic.P384(), 48, nil
	}
	return nil, 0, errors.New("crypto: unsupported curve " + curve)
}

// PKIXFromECPoint builds a PKIX DER public key from CKA_EC_POINT, which
// HSMs return as a DER OCTET STRING around the uncompressed point (some
// return the bare point; both are accepted).
func PKIXFromECPoint(curve string, point []byte) ([]byte, error) {
	c, _, err := namedCurve(curve)
	if err != nil {
		return nil, err
	}
	var inner []byte
	if rest, err := asn1.Unmarshal(point, &inner); err == nil && len(rest) == 0 && len(inner) > 0 {
		point = inner
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(c, point)
	if err != nil {
		return nil, errors.New("crypto: invalid EC point from HSM")
	}
	return x509.MarshalPKIXPublicKey(pub)
}

type ecdsaSig struct{ R, S *big.Int }

// ECDSARawToASN1 converts a PKCS#11 CKM_ECDSA signature (r || s) to the
// ASN.1 DER form the platform returns.
func ECDSARawToASN1(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return nil, errors.New("crypto: invalid raw ECDSA signature")
	}
	n := len(raw) / 2
	return asn1.Marshal(ecdsaSig{R: new(big.Int).SetBytes(raw[:n]), S: new(big.Int).SetBytes(raw[n:])})
}

// ECDSAASN1ToRaw converts an ASN.1 DER ECDSA signature to r || s for curve,
// as CKM_ECDSA verification expects.
func ECDSAASN1ToRaw(curve string, der []byte) ([]byte, error) {
	_, size, err := namedCurve(curve)
	if err != nil {
		return nil, err
	}
	var sig ecdsaSig
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil ||
		sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > size*8 || sig.S.BitLen() > size*8 {
		return nil, errors.New("crypto: invalid ECDSA signature encoding")
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}

// HSMPrivateKey is a private key as the PKCS#11 attributes of a private key
// object and its public key object: what C_CreateObject takes to place an
// existing key in an HSM. Call Zeroize when done.
type HSMPrivateKey struct {
	Algorithm string // RSA-2048, RSA-3072, RSA-4096, ECDSA-P256, ECDSA-P384
	PublicKey []byte // PKIX DER

	// RSA (big-endian, as CKA_MODULUS ... CKA_COEFFICIENT).
	Modulus, PublicExponent, PrivateExponent []byte
	Prime1, Prime2, Exponent1, Exponent2     []byte
	Coefficient                              []byte

	// EC: CKA_EC_PARAMS, CKA_EC_POINT (DER OCTET STRING) and CKA_VALUE.
	ECParams, ECPoint, ECValue []byte
}

// Zeroize clears the private components.
func (k *HSMPrivateKey) Zeroize() {
	for _, b := range [][]byte{k.PrivateExponent, k.Prime1, k.Prime2, k.Exponent1, k.Exponent2, k.Coefficient, k.ECValue} {
		Zeroize(b)
	}
}

// HSMPrivateKeyFromDER reads an RSA or ECDSA private key (PKCS#8, PKCS#1 or
// SEC 1 DER) into PKCS#11 attributes. It accepts what an HSM key in this
// platform can be: a valid two-prime RSA key of 2048, 3072 or 4096 bits, or
// a P-256 or P-384 key. The public half is derived from the private key,
// never taken from the input.
func HSMPrivateKeyFromDER(der []byte) (*HSMPrivateKey, error) {
	var key any
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		key = k
	} else if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		key = k
	} else if k, err := x509.ParseECPrivateKey(der); err == nil {
		key = k
	} else {
		return nil, errors.New("crypto: not an RSA or EC private key in PKCS#8, PKCS#1 or SEC 1 form")
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		bits := k.N.BitLen()
		if bits != 2048 && bits != 3072 && bits != 4096 {
			return nil, errors.New("crypto: an RSA key for the HSM is 2048, 3072 or 4096 bits")
		}
		if len(k.Primes) != 2 {
			return nil, errors.New("crypto: multi-prime RSA keys can't be placed in the HSM")
		}
		if err := k.Validate(); err != nil {
			return nil, errors.New("crypto: the RSA private key is not consistent")
		}
		k.Precompute()
		pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			return nil, err
		}
		return &HSMPrivateKey{
			Algorithm: "RSA-" + strconv.Itoa(bits), PublicKey: pub,
			Modulus: k.N.Bytes(), PublicExponent: big.NewInt(int64(k.E)).Bytes(), PrivateExponent: k.D.Bytes(),
			Prime1: k.Primes[0].Bytes(), Prime2: k.Primes[1].Bytes(),
			Exponent1: k.Precomputed.Dp.Bytes(), Exponent2: k.Precomputed.Dq.Bytes(), Coefficient: k.Precomputed.Qinv.Bytes(),
		}, nil
	case *ecdsa.PrivateKey:
		name := map[elliptic.Curve]string{elliptic.P256(): "P256", elliptic.P384(): "P384"}[k.Curve]
		if name == "" {
			return nil, errors.New("crypto: an EC key for the HSM is on P-256 or P-384")
		}
		// ECDH() checks the scalar and gives it, and the point, at fixed size.
		priv, err := k.ECDH()
		if err != nil {
			return nil, errors.New("crypto: the EC private key is not valid")
		}
		params, err := ECCurveParamsDER(name)
		if err != nil {
			return nil, err
		}
		point, err := asn1.Marshal(priv.PublicKey().Bytes())
		if err != nil {
			return nil, err
		}
		pub, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
		if err != nil {
			return nil, err
		}
		return &HSMPrivateKey{Algorithm: "ECDSA-" + name, PublicKey: pub, ECParams: params, ECPoint: point, ECValue: priv.Bytes()}, nil
	}
	return nil, errors.New("crypto: only RSA and ECDSA private keys can be placed in the HSM")
}

// WrapKeyToHSM wraps key under an RSA public key read from an HSM
// (CKA_MODULUS, CKA_PUBLIC_EXPONENT) with RSA-OAEP, SHA-256, MGF1-SHA-256
// and an empty label: what C_UnwrapKey with CKM_RSA_PKCS_OAEP opens.
func WrapKeyToHSM(modulus, exponent, key []byte) ([]byte, error) {
	e := new(big.Int).SetBytes(exponent)
	n := new(big.Int).SetBytes(modulus)
	if n.BitLen() < 3072 || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, errors.New("crypto: the HSM's wrapping key must be RSA of at least 3072 bits")
	}
	return WrapKeyRSAOAEP(&rsa.PublicKey{N: n, E: int(e.Int64())}, key, nil)
}
