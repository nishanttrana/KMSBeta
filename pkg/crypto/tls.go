package crypto

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// SelfSignedMTLSConfig builds an ephemeral self-signed TLS 1.3 config with
// mutual auth for service-local gRPC listeners. It replaces the devMTLSConfig
// copies that previously lived in every service main.
func SelfSignedMTLSConfig(commonName string) (*tls.Config, error) {
	key, err := rsa.GenerateKey(Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	cp := x509.NewCertPool()
	cp.AddCert(parsed)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cp,
	}, nil
}

func randSerial() (*big.Int, error) {
	b, err := RandomBytes(8)
	if err != nil {
		return nil, err
	}
	b[0] &= 0x3f // keep below 1<<62 and non-negative
	return new(big.Int).SetBytes(b), nil
}
