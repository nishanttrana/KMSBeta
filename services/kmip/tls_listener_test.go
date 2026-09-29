package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

type testIssuer struct {
	cert *x509.Certificate
	key  *pkgcrypto.KeyPair
	pem  []byte
}

func newIssuer(t *testing.T, cn string) *testIssuer {
	t.Helper()
	kp, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(pkgcrypto.Reader, tpl, tpl, kp.Public, kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testIssuer{cert: c, key: kp, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns certificate and key PEM for cn.
func (ca *testIssuer) issue(t *testing.T, cn string, serial int64, usage x509.ExtKeyUsage) ([]byte, []byte) {
	t.Helper()
	kp, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(pkgcrypto.Reader, tpl, ca.cert, kp.Public, ca.key.Private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func writeFiles(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	for name, b := range files {
		tmp := filepath.Join(dir, "."+name)
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func serve(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if c.(*tls.Conn).Handshake() == nil {
					_, _ = c.Write([]byte("ok"))
				}
				_ = c.Close()
			}(c)
		}
	}()
	return ln.Addr().String()
}

// dial completes a handshake and one read (TLS 1.3 reports a refused client
// certificate only on the first read), returning the server's serial.
func dial(addr string, roots *x509.CertPool, client *tls.Certificate) (string, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "kmip"}
	if client != nil {
		cfg.Certificates = []tls.Certificate{*client}
	}
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2)
	if _, err := c.Read(buf); err != nil {
		return "", err
	}
	return c.ConnectionState().PeerCertificates[0].SerialNumber.String(), nil
}

// The listener refuses to start without its files: there is no fallback
// certificate, and no configuration accepts unverified clients.
func TestKMIPTLSFailsClosed(t *testing.T) {
	old := kmipTLSWait
	kmipTLSWait = 300 * time.Millisecond
	t.Cleanup(func() { kmipTLSWait = old })
	ctx := context.Background()
	if _, err := loadKMIPTLSConfig(ctx, kmipTLSFiles{}, t.Logf); err == nil {
		t.Fatal("no files configured must refuse")
	}
	dir := t.TempDir()
	missing := kmipTLSFiles{Cert: filepath.Join(dir, "tls.crt"), Key: filepath.Join(dir, "tls.key"), ClientCA: filepath.Join(dir, "ca.crt")}
	if _, err := loadKMIPTLSConfig(ctx, missing, t.Logf); err == nil {
		t.Fatal("files that never appear must refuse")
	}
	ca := newIssuer(t, "runtime-root")
	crt, key := ca.issue(t, "kmip", 10, x509.ExtKeyUsageServerAuth)
	writeFiles(t, dir, map[string][]byte{"tls.crt": crt, "tls.key": key, "ca.crt": ca.pem})
	withCRL := missing
	withCRL.CRL = filepath.Join(dir, "missing.crl")
	if _, err := loadKMIPTLSConfig(ctx, withCRL, t.Logf); err == nil || !strings.Contains(err.Error(), "CRL") {
		t.Fatalf("an unreadable configured CRL must refuse: %v", err)
	}
	if _, ok := os.LookupEnv("KMIP_CLIENT_CERT_VERIFY_DISABLED"); ok {
		t.Skip("environment sets the removed override")
	}
	t.Setenv("KMIP_CLIENT_CERT_VERIFY_DISABLED", "true")
	cfg, err := loadKMIPTLSConfig(ctx, missing, t.Logf)
	if err != nil || cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("client certificates are always verified: %v %v", cfg.ClientAuth, err)
	}
}

// Real handshakes: only a client certificate from the client CA is
// accepted, and a certificate certs replaces is served on the next
// handshake without a restart; one that doesn't load keeps the current.
func TestKMIPServerCertificateReloadsAndClientsAreVerified(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	root := newIssuer(t, "runtime-root")
	edge := newIssuer(t, "Customer Issuing CA")
	crt, key := root.issue(t, "kmip", 10, x509.ExtKeyUsageServerAuth)
	writeFiles(t, dir, map[string][]byte{"tls.crt": crt, "tls.key": key, "ca.crt": root.pem})
	files := kmipTLSFiles{Cert: filepath.Join(dir, "tls.crt"), Key: filepath.Join(dir, "tls.key"), ClientCA: filepath.Join(dir, "ca.crt")}
	cfg, err := loadKMIPTLSConfig(ctx, files, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, cfg)

	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	roots.AddCert(edge.cert)
	goodPEM, goodKey := root.issue(t, "client-a", 20, x509.ExtKeyUsageClientAuth)
	good, _ := tls.X509KeyPair(goodPEM, goodKey)
	stranger := newIssuer(t, "stranger")
	badPEM, badKey := stranger.issue(t, "client-b", 21, x509.ExtKeyUsageClientAuth)
	bad, _ := tls.X509KeyPair(badPEM, badKey)

	if _, err := dial(addr, roots, nil); err == nil {
		t.Fatal("a client without a certificate must be refused")
	}
	if _, err := dial(addr, roots, &bad); err == nil {
		t.Fatal("a client certificate from another CA must be refused")
	}
	if serial, err := dial(addr, roots, &good); err != nil || serial != "10" {
		t.Fatalf("verified client: serial %s %v", serial, err)
	}

	// certs installs a certificate from another CA (key first, then cert).
	crt2, key2 := edge.issue(t, "kmip", 30, x509.ExtKeyUsageServerAuth)
	time.Sleep(1100 * time.Millisecond)
	writeFiles(t, dir, map[string][]byte{"tls.key": key2})
	writeFiles(t, dir, map[string][]byte{"tls.crt": crt2})
	deadline := time.Now().Add(5 * time.Second)
	for {
		serial, err := dial(addr, roots, &good)
		if err == nil && serial == "30" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the replaced certificate was not served: %s %v", serial, err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// A replacement that doesn't load keeps the one in force.
	time.Sleep(1100 * time.Millisecond)
	writeFiles(t, dir, map[string][]byte{"tls.crt": []byte("not a certificate")})
	time.Sleep(1100 * time.Millisecond)
	if serial, err := dial(addr, roots, &good); err != nil || serial != "30" {
		t.Fatalf("a broken replacement must keep the current certificate: %s %v", serial, err)
	}
}
