package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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
	"fmt"
	"math/big"
	"os"
	"path/filepath"
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

// RSAPublicKeyJWK returns the base64url JWK "n" and "e" fields for an RSA key.
func RSAPublicKeyJWK(pub crypto.PublicKey) (n string, e string, err error) {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", "", errors.New("crypto: JWK export requires an RSA public key")
	}
	eBytes := []byte{}
	for v := rsaPub.E; v > 0; v >>= 8 {
		eBytes = append([]byte{byte(v & 0xff)}, eBytes...)
	}
	if len(eBytes) == 0 {
		eBytes = []byte{0x01, 0x00, 0x01}
	}
	return base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(eBytes), nil
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

// VerifyECDSADigestRS verifies an ECDSA signature supplied as raw r||s
// halves of partSize bytes each (the COSE / JOSE ES* wire format) over a
// precomputed digest. Only NIST curves P-256/P-384/P-521 are accepted.
func VerifyECDSADigestRS(pub crypto.PublicKey, digest []byte, signature []byte, partSize int) error {
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("signing key is not ECDSA")
	}
	if partSize <= 0 || len(signature) != partSize*2 {
		return errors.New("ecdsa signature has an unexpected length")
	}
	r := new(big.Int).SetBytes(signature[:partSize])
	s := new(big.Int).SetBytes(signature[partSize:])
	if !ecdsa.Verify(key, digest, r, s) {
		return errors.New("ecdsa signature verification failed")
	}
	switch key.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
		return nil
	default:
		return errors.New("unsupported ecdsa curve")
	}
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

// LoadOrCreateRSAKeyPEM returns the RSA signing key persisted at path,
// creating and persisting a new one (PKCS#8 PEM, mode 0600) if the file does
// not exist. An empty path yields an ephemeral key. This is the sanctioned
// pattern for service signing keys (e.g. the auth JWT issuer key).
func LoadOrCreateRSAKeyPEM(path string, bits int) (*KeyPair, error) {
	alg := fmt.Sprintf("RSA-%d", bits)
	if path == "" {
		return GenerateKeyPair(alg)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		kp, genErr := GenerateKeyPair(alg)
		if genErr != nil {
			return nil, genErr
		}
		pemBytes, marshalErr := MarshalPrivateKeyPEM(kp)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
			return nil, mkErr
		}
		if writeErr := os.WriteFile(path, pemBytes, 0o600); writeErr != nil {
			return nil, writeErr
		}
		return kp, nil
	}
	kp, err := ParsePrivateKeyPEM(raw)
	if err != nil {
		return nil, err
	}
	if _, ok := kp.Private.(*rsa.PrivateKey); !ok {
		return nil, errors.New("crypto: persisted key is not RSA")
	}
	return kp, nil
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
