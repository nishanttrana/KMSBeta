package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/digitorus/timestamp"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/credstore"
	"vecta-kms/pkg/route/routetest"
	"vecta-kms/pkg/ssrfguard"
)

// testTSA is an RFC 3161 time-stamp authority under its own root, whose
// answers a test can spoil one way at a time.
type testTSA struct {
	srv      *httptest.Server
	rootPEM  string
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	mu       sync.Mutex
	status   int
	shift    time.Duration // added to the time it states
	noNonce  bool
	noCert   bool
	wrongEKU bool
	requests int
}

func newTestTSA(t *testing.T) *testTSA {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test TSA Root"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	a := &testTSA{rootPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})), status: http.StatusOK}
	issue := func(eku x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Test TSA"}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, key
	}
	a.cert, a.key = issue(x509.ExtKeyUsageTimeStamping)
	otherCert, otherKey := issue(x509.ExtKeyUsageServerAuth)
	a.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.requests++
		raw, _ := io.ReadAll(r.Body)
		req, err := timestamp.ParseRequest(raw)
		if err != nil || r.Header.Get("Content-Type") != "application/timestamp-query" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if a.status != http.StatusOK {
			http.Error(w, "unavailable", a.status)
			return
		}
		ts := timestamp.Timestamp{HashAlgorithm: req.HashAlgorithm, HashedMessage: req.HashedMessage, Time: time.Now().Add(a.shift),
			Nonce: req.Nonce, Policy: asn1.ObjectIdentifier{1, 2, 3, 4, 1}, AddTSACertificate: !a.noCert}
		if a.noNonce {
			ts.Nonce = nil
		}
		cert, key := a.cert, a.key
		if a.wrongEKU {
			cert, key = otherCert, otherKey
		}
		resp, err := ts.CreateResponseWithOpts(cert, key, crypto.SHA256)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(resp)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *testTSA) set(fn func(*testTSA)) { a.mu.Lock(); fn(a); a.mu.Unlock() }

// fakeCreds is the credential store with one tsa credential.
type fakeCreds struct {
	cred   credstore.Credential
	tested []error
}

func (f *fakeCreds) Resolve(_ context.Context, tenantID, id string) (credstore.Credential, error) {
	if tenantID != anchorTenant || id != f.cred.ID {
		return credstore.Credential{}, credstore.ErrNotFound
	}
	return f.cred, nil
}
func (f *fakeCreds) Import(context.Context, string, string, string, string, map[string]string, bool) (string, error) {
	return "", errors.New("not used")
}
func (f *fakeCreds) ReportTest(_ context.Context, _, _ string, err error) error {
	f.tested = append(f.tested, err)
	return nil
}

func anchoredService(t *testing.T) (*Service, *SQLStore, *testTSA, *fakeCreds) {
	t.Helper()
	s := newAuditStore(t)
	tsa := newTestTSA(t)
	creds := &fakeCreds{cred: credstore.Credential{ID: "pbconn_tsa", Type: "tsa", Fields: map[string]string{"url": tsa.srv.URL, "trust_pem": tsa.rootPEM}}}
	svc := NewService(s, AuditConfig{}, nil, nil)
	svc.SetCredentialStore(creds)
	svc.tsaHTTP = tsa.srv.Client() // loopback; production dials through ssrfguard
	return svc, s, tsa, creds
}

func anchorsOf(t *testing.T, svc *Service, tenant string) []CheckpointStatus {
	t.Helper()
	items, err := svc.ListCheckpoints(context.Background(), tenant, 0)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

// Each signed checkpoint is timestamped by the authority, the token is
// verified now against its signer's chain, a failure is audited without
// re-signing, and a token for other data, without a signer, with a stale
// time or from a signer without the timestamping usage is not accepted.
func TestCheckpointsAreTimestamped(t *testing.T) {
	svc, s, tsa, _ := anchoredService(t)
	ctx := context.Background()
	if err := s.PutAnchorSettings(ctx, AnchorSettings{Enabled: true, ConnectionID: "pbconn_tsa", UpdatedBy: "admin-1"}); err != nil {
		t.Fatal(err)
	}
	put := func() {
		t.Helper()
		if _, err := s.PersistEvent(ctx, AuditEvent{TenantID: "t1", Service: "keycore", Action: "audit.key.create", ActorID: "alice", ActorType: "user", Result: "success"}); err != nil {
			t.Fatal(err)
		}
	}
	put()
	if _, err := svc.SignCheckpoints(ctx); err != nil {
		t.Fatal(err)
	}
	items := anchorsOf(t, svc, "t1")
	if len(items) != 1 || items[0].Anchor == nil || items[0].Anchor.Status != anchorVerified || items[0].Anchor.GenTime == "" || !strings.HasPrefix(items[0].Anchor.Trust, "root ") {
		t.Fatalf("anchor %+v", items[0].Anchor)
	}
	// The timestamp is not new history: nothing is signed again.
	if n, err := svc.SignCheckpoints(ctx); err != nil || n != 0 {
		t.Fatalf("a timestamp made the chain re-sign: %d %v", n, err)
	}

	// The token verifies only for its own checkpoint, intact.
	tok, _ := s.QueryEvents(ctx, "t1", EventQuery{Action: actionCheckpointTimestamped, Limit: 1})
	sig, _ := base64.StdEncoding.DecodeString(items[0].Signature)
	if st := anchorStatus(&tok[0], []byte("another signature"), items[0].SignedAt); st.Status != anchorInvalid {
		t.Fatalf("a token over other data: %+v", st)
	}
	bad := tok[0]
	raw, _ := base64.StdEncoding.DecodeString(str(bad.Details["token_b64"]))
	raw[len(raw)-10] ^= 0xff
	bad.Details = map[string]interface{}{"token_b64": base64.StdEncoding.EncodeToString(raw), "trust_pem": tsa.rootPEM}
	if st := anchorStatus(&bad, sig, items[0].SignedAt); st.Status != anchorInvalid {
		t.Fatalf("an altered token: %+v", st)
	}
	stranger := newTestTSA(t)
	other := tok[0]
	other.Details = map[string]interface{}{"token_b64": tok[0].Details["token_b64"], "trust_pem": stranger.rootPEM}
	if st := anchorStatus(&other, sig, items[0].SignedAt); st.Status != anchorInvalid {
		t.Fatalf("a token under another root: %+v", st)
	}

	// Answers the platform refuses, each audited as a failure.
	for name, spoil := range map[string]func(*testTSA){
		"no nonce":       func(a *testTSA) { a.noNonce = true },
		"no certificate": func(a *testTSA) { a.noCert = true },
		"wrong usage":    func(a *testTSA) { a.wrongEKU = true },
		"unavailable":    func(a *testTSA) { a.status = http.StatusServiceUnavailable },
	} {
		tsa.set(func(a *testTSA) { a.noNonce, a.noCert, a.wrongEKU, a.status = false, false, false, http.StatusOK })
		tsa.set(spoil)
		put()
		if _, err := svc.SignCheckpoints(ctx); err != nil {
			t.Fatal(err)
		}
		items := anchorsOf(t, svc, "t1")
		if items[0].Anchor.Status != anchorMissing {
			t.Fatalf("%s: the newest checkpoint must have no accepted timestamp: %+v", name, items[0].Anchor)
		}
		fails, _ := s.QueryEvents(ctx, "t1", EventQuery{Action: actionTimestampFailed, Limit: 1})
		if len(fails) == 0 || fails[0].TargetID != items[0].EventID || fails[0].Result != "failure" || fails[0].Details["reason"] != "timestamp_refused" {
			t.Fatalf("%s: failure not audited: %+v", name, fails)
		}
	}

	// A time far from the checkpoint's is late.
	tsa.set(func(a *testTSA) {
		a.noNonce, a.noCert, a.wrongEKU, a.status, a.shift = false, false, false, http.StatusOK, 3*time.Hour
	})
	put()
	if _, err := svc.SignCheckpoints(ctx); err != nil {
		t.Fatal(err)
	}
	if st := anchorsOf(t, svc, "t1")[0].Anchor; st.Status != anchorLate {
		t.Fatalf("a token three hours after its checkpoint: %+v", st)
	}
}

// PUT /audit/anchor through the kernel: only a person in the root tenant
// sets it, turning it on takes a real token first, and each outcome is
// audited.
func TestAnchorRoute(t *testing.T) {
	svc, s, tsa, creds := anchoredService(t)
	h := &Handler{svc: svc, store: s}
	rec := &routetest.Recorder{}
	r := h.anchorRouter(rec)
	routetest.RefusalsAudited(t, r, rec)
	call := func(body string, claims *pkgauth.Claims) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/audit/anchor", strings.NewReader(body))
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	admin := &pkgauth.Claims{UserID: "admin-1", TenantID: "root", Permissions: []string{"*"}}
	on := `{"enabled":true,"connection_id":"pbconn_tsa"}`

	if w := call(on, &pkgauth.Claims{UserID: "t-admin", TenantID: "t1", Permissions: []string{"*"}}); w.Code != http.StatusForbidden {
		t.Fatalf("another tenant's administrator: %d", w.Code)
	}
	if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "not_root_tenant" {
		t.Fatalf("refusal %+v", ev.Event)
	}
	tsa.set(func(a *testTSA) { a.status = http.StatusBadGateway })
	if w := call(on, admin); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "timestamp_test_failed") {
		t.Fatalf("an authority that fails its test: %d %s", w.Code, w.Body)
	}
	if a, _ := s.AnchorSettings(context.Background()); a.Enabled || len(creds.tested) != 1 || creds.tested[0] == nil {
		t.Fatalf("a failed test must not turn anchoring on, and is reported: %+v %v", a, creds.tested)
	}
	tsa.set(func(a *testTSA) { a.status = http.StatusOK })
	if w := call(on, admin); w.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", w.Code, w.Body)
	}
	if ev := rec.Last(t); ev.Action != "anchor_settings_updated" || ev.Event.Result != "success" || ev.Event.Details["tested"] != true {
		t.Fatalf("enable event %s %+v", ev.Action, ev.Event)
	}
	if a, _ := s.AnchorSettings(context.Background()); !a.Enabled || a.ConnectionID != "pbconn_tsa" || a.UpdatedBy != "admin-1" {
		t.Fatalf("settings %+v", a)
	}
}

// An opt-in test against a real public authority (VECTA_TEST_TSA_URL, and
// VECTA_TEST_TSA_TRUST_PEM naming its root certificate file when it isn't
// in the system roots), run before shipping.
func TestLiveTimestampAuthority(t *testing.T) {
	url := strings.TrimSpace(os.Getenv("VECTA_TEST_TSA_URL"))
	if url == "" {
		t.Skip("set VECTA_TEST_TSA_URL to a public RFC 3161 authority (network required)")
	}
	trust := ""
	if f := os.Getenv("VECTA_TEST_TSA_TRUST_PEM"); f != "" {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		trust = string(raw)
	}
	cfg, err := tsaConfigFrom(credstore.Credential{Type: "tsa", Fields: map[string]string{"url": url, "trust_pem": trust}})
	if err != nil {
		t.Fatal(err)
	}
	roots, label, err := trustRoots(trust)
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	_, _ = rand.Read(digest)
	// The client production uses: TLS 1.3, public addresses only.
	defer ssrfguard.UseSystemResolverForTests()()
	token, ts, err := requestTimestamp(context.Background(), (&Service{}).tsaClient(), cfg, digest, roots)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(ts.Time); d < -time.Minute || d > 5*time.Minute {
		t.Fatalf("the authority's time is %v off", d)
	}
	t.Logf("%s: token of %d bytes at %s, serial %s, trust %s", cfg.host, len(token), ts.Time.UTC().Format(time.RFC3339), ts.SerialNumber, label)
}

// A failure goes out on the AUDIT stream, where playbooks see it (trigger
// audit_timestamp_failed), and is recorded from there.
func TestTimestampFailurePublishedToStream(t *testing.T) {
	svc, s, tsa, _ := anchoredService(t)
	stream := &loopbackPublisher{svc: svc}
	svc.publisher = stream
	ctx := context.Background()
	if err := s.PutAnchorSettings(ctx, AnchorSettings{Enabled: true, ConnectionID: "pbconn_tsa", UpdatedBy: "admin-1"}); err != nil {
		t.Fatal(err)
	}
	tsa.set(func(a *testTSA) { a.status = http.StatusServiceUnavailable })
	if _, err := s.PersistEvent(ctx, AuditEvent{TenantID: "t1", Service: "keycore", Action: "audit.key.create", ActorID: "alice", ActorType: "user", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SignCheckpoints(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(stream.subjects, actionTimestampFailed) {
		t.Fatalf("published %v", stream.subjects)
	}
	if fails, _ := s.QueryEvents(ctx, "t1", EventQuery{Action: actionTimestampFailed, Limit: 5}); len(fails) != 1 {
		t.Fatalf("recorded %+v", fails)
	}
}
