package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // HMACSHA1Interop: required by legacy cloud provider signature protocols only
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

// ParseRSAPublicKeyAny parses an RSA public key from PEM (PKIX or PKCS#1) or
// from raw base64-encoded PKIX DER, as supplied by external KMS providers.
func ParseRSAPublicKeyAny(s string) (*rsa.PublicKey, error) {
	if pub, err := ParseRSAPublicKeyPEM(s); err == nil {
		return pub, nil
	}
	if der, err := base64.StdEncoding.DecodeString(s); err == nil {
		if parsed, err := x509.ParsePKIXPublicKey(der); err == nil {
			if rsaPub, ok := parsed.(*rsa.PublicKey); ok {
				return rsaPub, nil
			}
		}
	}
	return nil, errors.New("crypto: unable to parse RSA public key")
}

// RSAPublicKeyJWK returns the base64url JWK "n" and "e" fields for a key.
func RSAPublicKeyJWK(pub *rsa.PublicKey) (n string, e string) {
	eBytes := []byte{}
	for v := pub.E; v > 0; v >>= 8 {
		eBytes = append([]byte{byte(v & 0xff)}, eBytes...)
	}
	if len(eBytes) == 0 {
		eBytes = []byte{0x01, 0x00, 0x01}
	}
	return base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(eBytes)
}

// RSAPublicKeyFromJWK builds an RSA public key from base64url JWK fields.
func RSAPublicKeyFromJWK(nB64 string, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, errors.New("crypto: invalid JWK modulus")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, errors.New("crypto: invalid JWK exponent")
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e <= 0 {
		return nil, errors.New("crypto: invalid JWK exponent value")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// SignPKCS1v15SHA256PEM signs data with an RSA private key supplied as
// PKCS#8 or PKCS#1 PEM, using RSASSA-PKCS1-v1_5 over SHA-256 (the scheme
// required by external KMS interop such as Google CSE).
func SignPKCS1v15SHA256PEM(privateKeyPEM string, data []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("crypto: no PEM block in private key")
	}
	var keyAny interface{}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		keyAny, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("crypto: unable to parse RSA private key")
		}
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("crypto: private key is not RSA")
	}
	digest := sha256.Sum256(data)
	return rsa.SignPKCS1v15(Reader, rsaKey, crypto.SHA256, digest[:])
}

// PrivateKeyMatchesPublic verifies that a parsed private key corresponds to
// the given public key (e.g. a certificate's), per key family.
func PrivateKeyMatchesPublic(pub crypto.PublicKey, priv interface{}) error {
	mismatch := errors.New("private key does not match certificate public key")
	switch p := pub.(type) {
	case *rsa.PublicKey:
		k, ok := priv.(*rsa.PrivateKey)
		if !ok || k.PublicKey.N.Cmp(p.N) != 0 || k.PublicKey.E != p.E {
			return mismatch
		}
	case *ecdsa.PublicKey:
		k, ok := priv.(*ecdsa.PrivateKey)
		if !ok || k.PublicKey.X.Cmp(p.X) != 0 || k.PublicKey.Y.Cmp(p.Y) != 0 {
			return mismatch
		}
	case ed25519.PublicKey:
		k, ok := priv.(ed25519.PrivateKey)
		if !ok || !k.Public().(ed25519.PublicKey).Equal(p) {
			return mismatch
		}
	default:
		return errors.New("certificate key type is not supported for private key validation")
	}
	return nil
}

// RandomInt returns a uniform random integer in [0, max).
func RandomInt(max *big.Int) (*big.Int, error) {
	return rand.Int(Reader, max)
}

// HMACSHA1Interop computes HMAC-SHA1. SHA-1 is NOT part of the approved
// suite; this exists solely for external provider protocols that mandate it
// (e.g. Alibaba Cloud API request signing). Do not use for new designs.
func HMACSHA1Interop(key []byte, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

// DevServerCertWithCA generates an ephemeral local CA plus a server
// certificate signed by it, for development TLS listeners that require a
// real chain (e.g. the KMIP mTLS listener). It returns the server keypair
// and the CA certificate for the client pool.
func DevServerCertWithCA(caCN string, serverCN string, dnsNames []string) (tls.Certificate, *x509.Certificate, error) {
	caKey, err := rsa.GenerateKey(Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: caCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	srvKey, err := rsa.GenerateKey(Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	srvTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: serverCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	srvDER, err := x509.CreateCertificate(Reader, srvTpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	srvPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)})
	srvCert, err := tls.X509KeyPair(srvPEM, srvKeyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return srvCert, caCert, nil
}
