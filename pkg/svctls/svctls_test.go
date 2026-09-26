package svctls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef"

// testCA is a throwaway Sub CA that signs CSRs like the certs service does:
// SANs from the registry, never from the CSR.
type testCA struct {
	cert   *x509.Certificate
	key    *pkgcrypto.KeyPair
	pem    string
	serial int64
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	kp, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgECDSAP384)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(pkgcrypto.Reader, tpl, tpl, kp.Public, kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: kp, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), serial: 100}
}

func (ca *testCA) Enroll(_ context.Context, identity string, csrDER []byte) (EnrollResponse, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		return EnrollResponse{}, errors.New("bad csr")
	}
	host, _ := HostFor(identity)
	ca.serial++
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(ca.serial), Subject: pkix.Name{CommonName: identity},
		DNSNames: []string{host, identity}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(pkgcrypto.Reader, tpl, ca.cert, csr.PublicKey, ca.key.Private)
	if err != nil {
		return EnrollResponse{}, err
	}
	return EnrollResponse{
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		ChainPEM:       ca.pem, Serial: big.NewInt(ca.serial).Text(16), NotAfter: tpl.NotAfter,
	}, nil
}

func enrolled(t *testing.T, ca *testCA, identity string) *Identity {
	t.Helper()
	trust := filepath.Join(t.TempDir(), "internal-ca.crt")
	if err := os.WriteFile(trust, []byte(ca.pem), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	id, err := Init(ctx, identity, Options{Enroller: ca, TrustFile: trust, KeepDefaultTransport: true, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// mtlsServer serves as keycore; the returned client dials it as "keycore".
func mtlsServer(t *testing.T, server *Identity) (*httptest.Server, func(*tls.Config) *http.Client) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, PeerIdentity(r))
	}))
	srv.TLS = server.ServerConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	return srv, func(cfg *tls.Config) *http.Client {
		cfg = cfg.Clone()
		cfg.ServerName = "keycore"
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: cfg,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		}}
	}
}

func TestMutualTLSBetweenServices(t *testing.T) {
	ca := newTestCA(t, "vecta-internal-services")
	keycore := enrolled(t, ca, "kms-keycore")
	auth := enrolled(t, ca, "kms-auth")
	_, client := mtlsServer(t, keycore)

	res, err := client(auth.ClientConfig()).Get("https://keycore/x")
	if err != nil {
		t.Fatalf("service-to-service mTLS: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "kms-auth" {
		t.Fatalf("server must see the verified caller, got %q", body)
	}
	if res.TLS == nil || res.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("want TLS 1.3, got %+v", res.TLS)
	}
	switch res.TLS.CurveID {
	case tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024:
	default:
		t.Fatalf("internal mTLS must negotiate a hybrid ML-KEM group, got %v", res.TLS.CurveID)
	}
}

func TestServerRefusesMissingOrForeignClientCert(t *testing.T) {
	ca := newTestCA(t, "vecta-internal-services")
	keycore := enrolled(t, ca, "kms-keycore")
	_, client := mtlsServer(t, keycore)

	noCert := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: keycore.roots}
	if _, err := client(noCert).Get("https://keycore/x"); err == nil {
		t.Fatal("a client without a certificate must be refused")
	}

	foreign := enrolled(t, newTestCA(t, "someone-else"), "kms-auth")
	cfg := foreign.ClientConfig()
	cfg.RootCAs = keycore.roots // it trusts the server; the server must not trust it
	if _, err := client(cfg).Get("https://keycore/x"); err == nil {
		t.Fatal("a client certificate from another CA must be refused")
	}
}

func TestClientRefusesServerFromAnotherCA(t *testing.T) {
	ours := newTestCA(t, "vecta-internal-services")
	impostor := enrolled(t, newTestCA(t, "impostor"), "kms-keycore")
	_, client := mtlsServer(t, impostor)
	auth := enrolled(t, ours, "kms-auth")
	if _, err := client(auth.ClientConfig()).Get("https://keycore/x"); err == nil {
		t.Fatal("a server certificate from another CA must be refused")
	}
}

func TestRouterRefusesPlainHTTPToInternalHosts(t *testing.T) {
	id := enrolled(t, newTestCA(t, "vecta-internal-services"), "kms-auth")
	external := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})
	rt := id.Router(external)
	for _, u := range []string{"http://keycore:8010/health", "http://certs:8030/x"} {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		if _, err := rt.RoundTrip(req); !errors.Is(err, ErrPlainHTTP) {
			t.Fatalf("%s: want ErrPlainHTTP, got %v", u, err)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("external hosts keep their own transport: %v", err)
	}
}

func TestEnrollmentProof(t *testing.T) {
	csr := []byte("csr-bytes")
	now := time.Now()
	req := EnrollRequest{Identity: "kms-keycore", Timestamp: now.Unix()}
	good, err := Proof(testSecret, "kms-keycore", req.Timestamp, csr)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProof(testSecret, req, csr, good, now); err != nil {
		t.Fatalf("valid proof refused: %v", err)
	}
	other, _ := Proof(testSecret, "kms-auth", req.Timestamp, csr)
	cases := map[string]func() error{
		"proof made for another identity": func() error { return VerifyProof(testSecret, req, csr, other, now) },
		"different CSR":                   func() error { return VerifyProof(testSecret, req, []byte("other"), good, now) },
		"wrong secret":                    func() error { return VerifyProof(testSecret+"x", req, csr, good, now) },
		"expired":                         func() error { return VerifyProof(testSecret, req, csr, good, now.Add(6*time.Minute)) },
		"unknown identity": func() error {
			return VerifyProof(testSecret, EnrollRequest{Identity: "kms-evil", Timestamp: req.Timestamp}, csr, good, now)
		},
	}
	for name, check := range cases {
		if check() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRenewSwapsKeyAndCertificate(t *testing.T) {
	ca := newTestCA(t, "vecta-internal-services")
	id := enrolled(t, ca, "kms-keycore")
	before := id.Leaf()
	if err := id.renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := id.Leaf()
	if before.SerialNumber.Cmp(after.SerialNumber) == 0 {
		t.Fatal("renewal must issue a new certificate")
	}
	if string(before.RawSubjectPublicKeyInfo) == string(after.RawSubjectPublicKeyInfo) {
		t.Fatal("renewal must use a fresh key")
	}
}
