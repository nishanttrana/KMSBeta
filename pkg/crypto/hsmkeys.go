package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
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
