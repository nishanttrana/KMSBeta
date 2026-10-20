package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/fips/fipstest"
)

// Azure Managed HSM external key management, driven over real mutual TLS
// with the EKM Proxy API's wire format (0.1-preview).

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestCA(t *testing.T, cn string) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (ca testCA) issue(t *testing.T, cn string, usage x509.ExtKeyUsage, dns ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: dns,
		IPAddresses: nil,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

type azureFixture struct {
	svc      *Service
	keycore  *fakeHYOKKeyCore
	pub      *nopHYOKPublisher
	srv      *httptest.Server
	serverCA testCA
	clientCA testCA
}

const azureCN = "mhsm-ekm-client"

func newAzureFixture(t *testing.T) *azureFixture {
	t.Helper()
	svc, _, keycore, _, _, pub := newHYOKService(t)
	keycore.Seed("tenant-a", "k-aes", "AES-256")
	keycore.Seed("tenant-a", "k-rsa", "RSA-2048")
	clientCA := newTestCA(t, "Microsoft test client CA")
	meta, _ := json.Marshal(AzureEKMMetadata{PathPrefix: "contoso/pool-1", ClientCAPEM: clientCA.pem, ClientSubjectCN: azureCN,
		Keys: map[string]string{"aes-key-1": "k-aes", "rsa-key-1": "k-rsa"}})
	if _, err := svc.ConfigureEndpoint(context.Background(), EndpointConfig{TenantID: "tenant-a", Protocol: ProtocolAzureEKM, Enabled: true, AuthMode: AuthModeMTLS, MetadataJSON: string(meta)}); err != nil {
		t.Fatal(err)
	}

	// The listener's own TLS config, with the edge certificate in files.
	serverCA := newTestCA(t, "edge CA")
	edge := serverCA.issue(t, "kms.example", x509.ExtKeyUsageServerAuth, "localhost", "127.0.0.1")
	dir := t.TempDir()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: edge.Certificate[0]})
	keyDER, _ := x509.MarshalECPrivateKey(edge.PrivateKey.(*ecdsa.PrivateKey))
	_ = os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	cfg, err := azureListenerTLS(context.Background(), azureListenerConfig{Port: "0", CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key")}, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(NewAzureEKMHandler(svc, "test"))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &azureFixture{svc: svc, keycore: keycore, pub: pub, srv: srv, serverCA: serverCA, clientCA: clientCA}
}

func (f *azureFixture) client(t *testing.T, cert *tls.Certificate) *http.Client {
	roots := x509.NewCertPool()
	roots.AddCert(f.serverCA.cert)
	cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, ServerName: "localhost"}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

func (f *azureFixture) call(t *testing.T, c *http.Client, path string, body map[string]interface{}, hdr ...string) (int, map[string]interface{}) {
	t.Helper()
	if body == nil {
		body = map[string]interface{}{}
	}
	body["request_context"] = map[string]string{"request_id": "r-1", "correlation_id": "corr-1", "pool_name": "mhsm-pool"}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	out := map[string]interface{}{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

const q = "?api-version=0.1-preview"

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestAzureEKMWrapsAndUnwrapsOverMutualTLS(t *testing.T) {
	f := newAzureFixture(t)
	cert := f.clientCA.issue(t, azureCN, x509.ExtKeyUsageClientAuth)
	c := f.client(t, &cert)

	code, info := f.call(t, c, "/contoso/pool-1/info"+q, nil)
	if code != 200 || info["api_version"] != "0.1-preview" || info["proxy_vendor"] != "Vecta" {
		t.Fatalf("info: %d %v", code, info)
	}
	if f.svc.azure.get("tenant-a").IsZero() {
		t.Fatal("the health probe was not recorded")
	}

	code, md := f.call(t, c, "/contoso/pool-1/aes-key-1/metadata"+q, nil)
	if code != 200 || md["key_type"] != "oct" || md["key_size"] != float64(256) {
		t.Fatalf("aes metadata: %d %v", code, md)
	}
	code, md = f.call(t, c, "/contoso/pool-1/rsa-key-1/metadata"+q, nil)
	wantN, wantE, _ := pkgcrypto.RSAPublicKeyJWK(&getTestRSAKey().PublicKey)
	if code != 200 || md["key_type"] != "RSA" || md["key_size"] != float64(2048) || md["n"] != wantN || md["e"] != wantE || md["e"] != "AQAB" {
		t.Fatalf("rsa metadata: %d %v", code, md)
	}

	dek := bytes.Repeat([]byte{0x42}, 32)
	cases := []struct{ key, alg string }{{"rsa-key-1", pkgcrypto.JWARSAOAEP256}}
	if !fipstest.Strict() {
		cases = append(cases, struct{ key, alg string }{"aes-key-1", pkgcrypto.JWAA256KW}, struct{ key, alg string }{"aes-key-1", pkgcrypto.JWAA256KWP}, struct{ key, alg string }{"rsa-key-1", pkgcrypto.JWARSAOAEP})
	}
	for _, tc := range cases {
		code, w := f.call(t, c, "/contoso/pool-1/"+tc.key+"/wrapkey"+q, map[string]interface{}{"alg": tc.alg, "value": b64u(dek)})
		if code != 200 {
			t.Fatalf("%s wrap: %d %v", tc.alg, code, w)
		}
		wrapped, err := base64.RawURLEncoding.DecodeString(w["value"].(string))
		if err != nil || bytes.Contains(wrapped, dek) {
			t.Fatalf("%s: wrapped value %q", tc.alg, w["value"])
		}
		// The wire value is the named algorithm's output under the key the
		// KMS holds: the key opens it directly.
		var direct []byte
		if pkgcrypto.JWAIsAES(tc.alg) {
			direct, err = pkgcrypto.JWAUnwrapAES(tc.alg, f.keycore.material["tenant-a:k-aes"], wrapped)
		} else {
			direct, err = pkgcrypto.JWAUnwrapRSA(tc.alg, getTestRSAKey(), wrapped)
		}
		if err != nil || !bytes.Equal(direct, dek) {
			t.Fatalf("%s: output is not %s under the key: %v", tc.alg, tc.alg, err)
		}
		code, u := f.call(t, c, "/contoso/pool-1/"+tc.key+"/unwrapkey"+q, map[string]interface{}{"alg": tc.alg, "value": w["value"]})
		if code != 200 || u["value"] != b64u(dek) {
			t.Fatalf("%s unwrap: %d %v", tc.alg, code, u)
		}
	}
	if f.pub.Count("audit.hyok.azure_ekm_request") != 2*len(cases) {
		t.Fatalf("azure_ekm_request events: %d, want %d", f.pub.Count("audit.hyok.azure_ekm_request"), 2*len(cases))
	}
	if ev := f.pub.Last("audit.hyok.azure_ekm_metadata"); ev == nil || ev["key_name"] != "rsa-key-1" || ev["correlation_id"] != "corr-1" {
		t.Fatalf("metadata event %v", ev)
	}
	logs, _ := f.svc.store.ListRequestLogs(context.Background(), "tenant-a", ProtocolAzureEKM, 50, 0)
	for _, l := range logs {
		if strings.Contains(l.RequestJSON+l.ResponseJSON, b64u(dek)) || strings.Contains(l.RequestJSON+l.ResponseJSON, base64.StdEncoding.EncodeToString(dek)) {
			t.Fatalf("the request log holds the data key: %+v", l)
		}
		if l.AuthMode != AuthModeMTLS || l.AuthSubject != "azure-managed-hsm:"+azureCN {
			t.Fatalf("logged caller %q %q", l.AuthMode, l.AuthSubject)
		}
	}
}

func TestAzureEKMRefusesUntrustedCallersAndBadRequests(t *testing.T) {
	f := newAzureFixture(t)
	good := f.clientCA.issue(t, azureCN, x509.ExtKeyUsageClientAuth)
	c := f.client(t, &good)
	refusal := func(t *testing.T, status int, code string, wantStatus int, wantCode string, body map[string]interface{}) {
		t.Helper()
		if status != wantStatus || body["code"] != wantCode {
			t.Fatalf("got %d %v, want %d %s", status, body, wantStatus, wantCode)
		}
		ev := f.pub.Last("audit.hyok.azure_ekm_refused")
		if ev == nil || ev["code"] != wantCode || ev["result"] != "refused" || ev["reason"] == "" {
			t.Fatalf("refusal event %v", ev)
		}
	}

	// No client certificate: the handshake itself fails.
	if _, err := f.client(t, nil).Post(f.srv.URL+"/contoso/pool-1/info"+q, "application/json", strings.NewReader(`{}`)); err == nil {
		t.Fatal("a caller with no client certificate got an answer")
	}
	// Right CN, another CA.
	rogue := newTestCA(t, "rogue")
	forged := rogue.issue(t, azureCN, x509.ExtKeyUsageClientAuth)
	s, b := f.call(t, f.client(t, &forged), "/contoso/pool-1/info"+q, nil)
	refusal(t, s, "", 401, "Unauthorized", b)
	if ev := f.pub.Last("audit.hyok.azure_ekm_refused"); ev["tenant_id"] != nil && ev["tenant_id"] != "tenant-a" {
		t.Fatalf("event tenant %v", ev["tenant_id"])
	}
	// Right CA, another CN.
	other := f.clientCA.issue(t, "someone-else", x509.ExtKeyUsageClientAuth)
	s, b = f.call(t, f.client(t, &other), "/contoso/pool-1/info"+q, nil)
	refusal(t, s, "", 401, "Unauthorized", b)
	// Right CA and CN, but a server certificate, not a client one.
	serverUse := f.clientCA.issue(t, azureCN, x509.ExtKeyUsageServerAuth)
	s, b = f.call(t, f.client(t, &serverUse), "/contoso/pool-1/info"+q, nil)
	refusal(t, s, "", 401, "Unauthorized", b)

	s, b = f.call(t, c, "/other-prefix/info"+q, nil)
	refusal(t, s, "", 404, "NotFound", b)
	s, b = f.call(t, c, "/contoso/pool-1/info?api-version=2.0", nil)
	refusal(t, s, "", 400, "UnsupportedApiVersion", b)
	s, b = f.call(t, c, "/contoso/pool-1/unmapped/metadata"+q, nil)
	refusal(t, s, "", 404, "KeyNotFound", b)
	s, b = f.call(t, c, "/contoso/pool-1/aes-key-1/wrapkey"+q, map[string]interface{}{"alg": "RSA-OAEP-256", "value": b64u(make([]byte, 32))})
	refusal(t, s, "", 400, "UnsupportedAlgorithm", b)
	s, b = f.call(t, c, "/contoso/pool-1/rsa-key-1/unwrapkey"+q, map[string]interface{}{"alg": "RSA-OAEP-256", "value": b64u(make([]byte, 256))})
	refusal(t, s, "", 400, "InvalidRequest", b)

	// A caller-written forwarding header is not the caller's address.
	f.call(t, c, "/contoso/pool-1/unmapped/metadata"+q, nil, "X-Forwarded-For", "203.0.113.66")
	if ev := f.pub.Last("audit.hyok.azure_ekm_refused"); ev["remote_ip"] == "203.0.113.66" || ev["remote_ip"] == "" {
		t.Fatalf("remote_ip %v", ev["remote_ip"])
	}

	f.keycore.SetStatus("tenant-a", "k-rsa", "disabled")
	s, b = f.call(t, c, "/contoso/pool-1/rsa-key-1/wrapkey"+q, map[string]interface{}{"alg": "RSA-OAEP-256", "value": b64u(make([]byte, 32))})
	refusal(t, s, "", 403, "KeyDisabled", b)
}

func TestAzureEndpointSettingsAreChecked(t *testing.T) {
	svc, _, keycore, _, _, pub := newHYOKService(t)
	keycore.Seed("tenant-a", "k-aes", "AES-256")
	keycore.Seed("tenant-a", "k-ec", "ECDSA-P256")
	keycore.Seed("tenant-b", "k-b", "AES-256")
	ca := newTestCA(t, "client CA")
	leaf := ca.issue(t, "leaf", x509.ExtKeyUsageClientAuth)
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}))
	save := func(tenant string, governance bool, m AzureEKMMetadata) error {
		raw, _ := json.Marshal(m)
		_, err := svc.ConfigureEndpoint(context.Background(), EndpointConfig{TenantID: tenant, Protocol: ProtocolAzureEKM, Enabled: true, GovernanceRequired: governance, MetadataJSON: string(raw)})
		return err
	}
	ok := AzureEKMMetadata{PathPrefix: "tenant-a", ClientCAPEM: ca.pem, ClientSubjectCN: azureCN, Keys: map[string]string{"k1": "k-aes"}}
	if err := save("tenant-a", false, ok); err != nil {
		t.Fatalf("valid settings refused: %v", err)
	}
	stored, _ := svc.store.GetEndpoint(context.Background(), "tenant-a", ProtocolAzureEKM)
	if stored.AuthMode != AuthModeMTLS {
		t.Fatalf("auth mode %q", stored.AuthMode)
	}
	for name, tc := range map[string]struct {
		tenant     string
		governance bool
		m          AzureEKMMetadata
	}{
		"approval":      {"tenant-a", true, ok},
		"no prefix":     {"tenant-a", false, AzureEKMMetadata{ClientCAPEM: ca.pem, ClientSubjectCN: azureCN}},
		"bad prefix":    {"tenant-a", false, AzureEKMMetadata{PathPrefix: "a_b", ClientCAPEM: ca.pem, ClientSubjectCN: azureCN}},
		"no CA":         {"tenant-a", false, AzureEKMMetadata{PathPrefix: "p", ClientSubjectCN: azureCN}},
		"leaf as CA":    {"tenant-a", false, AzureEKMMetadata{PathPrefix: "p", ClientCAPEM: leafPEM, ClientSubjectCN: azureCN}},
		"no CN":         {"tenant-a", false, AzureEKMMetadata{PathPrefix: "p", ClientCAPEM: ca.pem}},
		"bad key name":  {"tenant-a", false, AzureEKMMetadata{PathPrefix: "p", ClientCAPEM: ca.pem, ClientSubjectCN: azureCN, Keys: map[string]string{"key_1": "k-aes"}}},
		"EC key":        {"tenant-a", false, AzureEKMMetadata{PathPrefix: "p", ClientCAPEM: ca.pem, ClientSubjectCN: azureCN, Keys: map[string]string{"k1": "k-ec"}}},
		"missing key":   {"tenant-a", false, AzureEKMMetadata{PathPrefix: "p", ClientCAPEM: ca.pem, ClientSubjectCN: azureCN, Keys: map[string]string{"k1": "nope"}}},
		"prefix in use": {"tenant-b", false, AzureEKMMetadata{PathPrefix: "TENANT-A", ClientCAPEM: ca.pem, ClientSubjectCN: azureCN, Keys: map[string]string{"k1": "k-b"}}},
	} {
		before := pub.Count("audit.hyok.endpoint_refused")
		if err := save(tc.tenant, tc.governance, tc.m); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if pub.Count("audit.hyok.endpoint_refused") != before+1 {
			t.Fatalf("%s: refusal not audited", name)
		}
	}
}

func TestAzureListenerNeedsItsCertificate(t *testing.T) {
	old := azureCertWait
	azureCertWait = 0
	t.Cleanup(func() { azureCertWait = old })
	if _, err := azureListenerTLS(context.Background(), azureListenerConfig{Port: "1", CertFile: filepath.Join(t.TempDir(), "missing.crt"), KeyFile: "missing.key"}, t.Logf); err == nil {
		t.Fatal("the listener started without its certificate")
	}
	if _, err := startAzureListener(context.Background(), azureListenerConfig{Port: "1"}, http.NotFoundHandler(), t.Logf); err == nil {
		t.Fatal("the listener started with no certificate files named")
	}
	if srv, err := startAzureListener(context.Background(), azureListenerConfig{}, http.NotFoundHandler(), t.Logf); err != nil || srv != nil {
		t.Fatalf("an unset port started a listener: %v %v", srv, err)
	}
}
