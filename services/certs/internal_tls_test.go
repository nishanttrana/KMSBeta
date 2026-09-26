package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/svctls"
)

const enrollTestSecret = "0123456789abcdef0123456789abcdef0123456789abcdef"

type captureEmitter struct {
	mu     sync.Mutex
	events map[string][]pkgaudit.Event
}

func (c *captureEmitter) Emit(_ context.Context, action string, evt pkgaudit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.events == nil {
		c.events = map[string][]pkgaudit.Event{}
	}
	c.events[action] = append(c.events[action], evt)
	return nil
}

func (c *captureEmitter) last(action string) (pkgaudit.Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	evs := c.events[action]
	if len(evs) == 0 {
		return pkgaudit.Event{}, false
	}
	return evs[len(evs)-1], true
}

func csrFor(t *testing.T, cn string, sans ...string) []byte {
	t.Helper()
	kp, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(pkgcrypto.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: sans}, kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func enroll(t *testing.T, h http.Handler, identity string, csr []byte, proof string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(svctls.EnrollRequest{
		Identity:  identity,
		CSRPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
		Timestamp: time.Now().Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, svctls.EnrollPath, bytes.NewReader(body))
	req.Header.Set(svctls.ProofHeader(), proof)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestInternalSubCAIsCreatedOnceUnderTheRoot(t *testing.T) {
	svc, _ := newCertsService(t)
	root, sub, err := svc.EnsureInternalPKI(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if sub.ParentCAID != root.ID || sub.Name != defaultInternalSubCAName {
		t.Fatalf("Sub CA must sit under the runtime root: root=%s sub=%+v", root.ID, sub)
	}
	_, again, err := svc.EnsureInternalPKI(context.Background(), "root")
	if err != nil || again.ID != sub.ID {
		t.Fatalf("Sub CA must be reused, got %s then %s (%v)", sub.ID, again.ID, err)
	}
}

func TestEnrollmentIssuesRegistrySANsFromTheSubCA(t *testing.T) {
	svc, _ := newCertsService(t)
	em := &captureEmitter{}
	h := svc.enrollHandler("root", enrollTestSecret, em)
	_, sub, err := svc.EnsureInternalPKI(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}

	// The CSR asks for extra names; the certificate must carry only the
	// registry's.
	csr := csrFor(t, "kms-keycore", "evil.example", "keycore")
	proof, _ := svctls.Proof(enrollTestSecret, "kms-keycore", time.Now().Unix(), csr)
	rr := enroll(t, h, "kms-keycore", csr, proof)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid enrolment: %d %s", rr.Code, rr.Body)
	}
	var out svctls.EnrollResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(out.CertificatePEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sans := append([]string{}, leaf.DNSNames...)
	sort.Strings(sans)
	if strings.Join(sans, ",") != "keycore,kms-keycore" || leaf.Subject.CommonName != "kms-keycore" {
		t.Fatalf("SANs must come from the registry, got CN=%s SANs=%v", leaf.Subject.CommonName, leaf.DNSNames)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(sub.CertPEM))
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			t.Fatalf("certificate must chain to the internal Sub CA for %v: %v", usage, err)
		}
	}
	if ev, ok := em.last("internal_enroll"); !ok || ev.Result != "success" {
		t.Fatalf("enrolment must be audited: %+v", ev)
	}

	// Re-enrolment supersedes the previous certificate.
	csr2 := csrFor(t, "kms-keycore")
	proof2, _ := svctls.Proof(enrollTestSecret, "kms-keycore", time.Now().Unix(), csr2)
	if rr := enroll(t, h, "kms-keycore", csr2, proof2); rr.Code != http.StatusOK {
		t.Fatalf("re-enrolment: %d %s", rr.Code, rr.Body)
	}
	active, _ := svc.store.ListCertificates(context.Background(), "root", CertStatusActive, "internal-mtls", 100, 0)
	n := 0
	for _, c := range active {
		if c.SubjectCN == "kms-keycore" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("exactly one active certificate per identity, got %d", n)
	}
}

func TestEnrollmentRefusals(t *testing.T) {
	svc, _ := newCertsService(t)
	em := &captureEmitter{}
	h := svc.enrollHandler("root", enrollTestSecret, em)
	csr := csrFor(t, "kms-keycore")
	forAuth, _ := svctls.Proof(enrollTestSecret, "kms-auth", time.Now().Unix(), csr)
	wrongSecret, _ := svctls.Proof(enrollTestSecret+"x", "kms-keycore", time.Now().Unix(), csr)
	good, _ := svctls.Proof(enrollTestSecret, "kms-keycore", time.Now().Unix(), csr)
	junkProof, _ := svctls.Proof(enrollTestSecret, "kms-keycore", time.Now().Unix(), []byte("junk"))
	cases := []struct {
		name, identity, proof string
		csr                   []byte
		reason                string
	}{
		{"proof made for another identity", "kms-keycore", forAuth, csr, "proof_rejected"},
		{"proof under the wrong secret", "kms-keycore", wrongSecret, csr, "proof_rejected"},
		{"unknown identity", "kms-evil", good, csr, "proof_rejected"},
		{"not a CSR (valid proof)", "kms-keycore", junkProof, []byte("junk"), "issuance_refused"},
	}
	for _, tc := range cases {
		rr := enroll(t, h, tc.identity, tc.csr, tc.proof)
		if rr.Code == http.StatusOK {
			t.Fatalf("%s: accepted", tc.name)
		}
		ev, ok := em.last("internal_enroll")
		if !ok || ev.Result != "refused" || ev.Details["reason"] != tc.reason {
			t.Fatalf("%s: refusal must be audited with reason %q, got %+v", tc.name, tc.reason, ev)
		}
	}
}

func TestCertsEnrolsItselfLocally(t *testing.T) {
	svc, _ := newCertsService(t)
	_, sub, err := svc.EnsureInternalPKI(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root, _, _ := svc.EnsureInternalPKI(context.Background(), "root")
	if err := WriteTrustBundle(dir, root, sub); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id, err := svctls.Init(ctx, "kms-certs", svctls.Options{
		Enroller: localEnroller{svc: svc, tenant: "root"}, TrustFile: dir + "/internal-ca.crt", KeepDefaultTransport: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if leaf := id.Leaf(); leaf == nil || leaf.Subject.CommonName != "kms-certs" {
		t.Fatalf("certs must hold its own internal certificate, got %+v", leaf)
	}
}
