package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipserver"
)

// KMIP over the real wire: TLS with client certificates, the production
// BatchExecutor and connect hook, and the ovh/kmip-go client. Proves client
// authentication, tenant isolation and the key lifecycle end to end.

type testPKI struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kmip-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testPKI{caCert: cert, caKey: key, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

var serialMu sync.Mutex
var serialN int64 = 1

func (p testPKI) issue(t *testing.T, cn string, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialMu.Lock()
	serialN++
	serial := serialN
	serialMu.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

type kmipWire struct {
	addr  string
	pki   testPKI
	store *SQLStore
}

func startKMIPWire(t *testing.T) kmipWire {
	t.Helper()
	h, store, _ := newKMIPHandler(t)
	h.requireRegistered = true // production default: only registered client certificates
	pki := newTestPKI(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pki.issue(t, "127.0.0.1", true)},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS12, // FIPS exception: external protocol mandate (KMIP 1.x clients)
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := kmipserver.NewServer(ln, h.NewBatchExecutor()).WithConnectHook(h.ConnectHook).WithTerminateHook(h.TerminateHook)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return kmipWire{addr: ln.Addr().String(), pki: pki, store: store}
}

// register issues a client certificate and registers it for tenant with the
// given role and status.
func (w kmipWire) register(t *testing.T, tenant, role, status string) tls.Certificate {
	t.Helper()
	cert := w.pki.issue(t, tenant+":"+role, false)
	if err := w.store.CreateClient(context.Background(), KMIPClient{
		ID: newID("kmipc"), TenantID: tenant, Name: tenant + "-" + role, Role: role, Status: status,
		EnrollmentMode: "internal", CertSubject: cert.Leaf.Subject.String(), CertIssuer: cert.Leaf.Issuer.String(),
		CertFingerprintSHA256: clientFingerprintSHA256(cert.Leaf), MetadataJSON: "{}",
	}); err != nil {
		t.Fatal(err)
	}
	return cert
}

func (w kmipWire) dial(t *testing.T, cert tls.Certificate) (*kmipclient.Client, error) {
	t.Helper()
	return kmipclient.Dial(w.addr,
		kmipclient.WithRootCAPem(w.pki.caPEM),
		kmipclient.WithClientCert(cert),
		kmipclient.WithKmipVersions(kmip.V1_4),
	)
}

func TestKMIPWireKeyLifecycle(t *testing.T) {
	w := startKMIPWire(t)
	client, err := w.dial(t, w.register(t, "tenant-a", "kmip-admin", "active"))
	if err != nil {
		t.Fatalf("registered client must connect: %v", err)
	}
	defer client.Close() //nolint:errcheck

	created, err := client.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).Exec()
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id := created.UniqueIdentifier

	plain := []byte("kmip wire payload")
	enc, err := client.Encrypt(id).Data(plain).Exec()
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	dec, err := client.Decrypt(id).WithIvCounterNonce(enc.IVCounterNonce).Data(enc.Data).Exec()
	if err != nil || string(dec.Data) != string(plain) {
		t.Fatalf("decrypt must return the plaintext: %q %v", dec.Data, err)
	}

	loc, err := client.Locate().Exec()
	if err != nil || !contains(loc.UniqueIdentifier, id) {
		t.Fatalf("locate must find the created key: %v %v", loc, err)
	}

	if _, err := client.Revoke(id).Exec(); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := client.Encrypt(id).Data(plain).Exec(); err == nil {
		t.Fatal("a revoked key must not encrypt")
	}
	if dec, err := client.Decrypt(id).WithIvCounterNonce(enc.IVCounterNonce).Data(enc.Data).Exec(); err != nil || string(dec.Data) != string(plain) {
		t.Fatalf("a revoked (deactivated) key must still decrypt existing data: %v", err)
	}
	if _, err := client.Destroy(id).Exec(); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := client.Get(id).Exec(); err == nil {
		t.Fatal("a destroyed key must not be returned")
	}
}

func TestKMIPWireTenantIsolation(t *testing.T) {
	w := startKMIPWire(t)
	a, err := w.dial(t, w.register(t, "tenant-a", "kmip-admin", "active"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close() //nolint:errcheck
	b, err := w.dial(t, w.register(t, "tenant-b", "kmip-admin", "active"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close() //nolint:errcheck

	created, err := a.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).Exec()
	if err != nil {
		t.Fatal(err)
	}
	id := created.UniqueIdentifier
	if _, err := b.Encrypt(id).Data([]byte("x")).Exec(); err == nil {
		t.Fatal("tenant-b must not use tenant-a's key")
	}
	if _, err := b.Get(id).Exec(); err == nil {
		t.Fatal("tenant-b must not read tenant-a's key")
	}
	if _, err := b.Destroy(id).Exec(); err == nil {
		t.Fatal("tenant-b must not destroy tenant-a's key")
	}
	if loc, err := b.Locate().Exec(); err != nil || contains(loc.UniqueIdentifier, id) {
		t.Fatalf("tenant-b must not locate tenant-a's key: %v %v", loc, err)
	}
	if _, err := a.Encrypt(id).Data([]byte("still mine")).Exec(); err != nil {
		t.Fatalf("tenant-a's key must be unaffected: %v", err)
	}
}

func TestKMIPWireRejectsUnregisteredAndInactiveClients(t *testing.T) {
	w := startKMIPWire(t)
	unregistered := w.pki.issue(t, "tenant-a:kmip-client", false)
	inactive := w.register(t, "tenant-a", "kmip-admin", "revoked")
	for name, cert := range map[string]tls.Certificate{"unregistered": unregistered, "inactive": inactive} {
		client, err := w.dial(t, cert)
		if err != nil {
			continue // refused at connect
		}
		_, err = client.Create().AES(256, kmip.CryptographicUsageEncrypt).Exec()
		_ = client.Close()
		if err == nil {
			t.Fatalf("%s client certificate must be refused", name)
		}
	}
}

// A kmip-client may not revoke or destroy. The refusal must be a KMIP error,
// and the server must keep serving: a nil middleware response used to crash
// the whole service here.
func TestKMIPWireRoleDenialDoesNotCrashServer(t *testing.T) {
	w := startKMIPWire(t)
	admin, err := w.dial(t, w.register(t, "tenant-a", "kmip-admin", "active"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close() //nolint:errcheck
	user, err := w.dial(t, w.register(t, "tenant-a", "kmip-client", "active"))
	if err != nil {
		t.Fatal(err)
	}
	defer user.Close() //nolint:errcheck

	created, err := user.Create().AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).Exec()
	if err != nil {
		t.Fatalf("a kmip-client may create keys: %v", err)
	}
	id := created.UniqueIdentifier
	if _, err := user.Revoke(id).Exec(); err == nil {
		t.Fatal("a kmip-client must not revoke")
	}
	if _, err := user.Destroy(id).Exec(); err == nil {
		t.Fatal("a kmip-client must not destroy")
	}
	if _, err := user.Encrypt(id).Data([]byte("still up")).Exec(); err != nil {
		t.Fatalf("the server must keep serving after a refused operation: %v", err)
	}
	fresh, err := w.dial(t, w.register(t, "tenant-a", "kmip-client", "active"))
	if err != nil {
		t.Fatalf("new connections must still be accepted: %v", err)
	}
	_ = fresh.Close()
	if _, err := admin.Revoke(id).Exec(); err != nil {
		t.Fatalf("a kmip-admin may revoke: %v", err)
	}
}

func contains(items []string, v string) bool {
	for _, it := range items {
		if it == v {
			return true
		}
	}
	return false
}
