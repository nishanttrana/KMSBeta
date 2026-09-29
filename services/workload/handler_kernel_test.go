package main

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

const ExchangePath = "/workload-identity/token/exchange"

// memStore is an in-memory Store for one or more tenants.
type memStore struct {
	settings  map[string]WorkloadIdentitySettings
	regs      map[string]WorkloadRegistration
	bundles   map[string]WorkloadFederationBundle
	issuances []WorkloadIssuanceRecord
}

func newMemStore() *memStore {
	return &memStore{settings: map[string]WorkloadIdentitySettings{}, regs: map[string]WorkloadRegistration{}, bundles: map[string]WorkloadFederationBundle{}}
}

func (m *memStore) GetSettings(_ context.Context, t string) (WorkloadIdentitySettings, error) {
	s, ok := m.settings[t]
	if !ok {
		return WorkloadIdentitySettings{}, errNotFound
	}
	return s, nil
}
func (m *memStore) UpsertSettings(_ context.Context, s WorkloadIdentitySettings) (WorkloadIdentitySettings, error) {
	m.settings[s.TenantID] = s
	return s, nil
}
func (m *memStore) ListRegistrations(_ context.Context, t string) ([]WorkloadRegistration, error) {
	var out []WorkloadRegistration
	for _, r := range m.regs {
		if r.TenantID == t {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *memStore) GetRegistration(_ context.Context, t, id string) (WorkloadRegistration, error) {
	r, ok := m.regs[id]
	if !ok || r.TenantID != t {
		return WorkloadRegistration{}, errNotFound
	}
	return r, nil
}
func (m *memStore) GetRegistrationBySPIFFEID(_ context.Context, t, sid string) (WorkloadRegistration, error) {
	for _, r := range m.regs {
		if r.TenantID == t && r.SpiffeID == sid {
			return r, nil
		}
	}
	return WorkloadRegistration{}, errNotFound
}
func (m *memStore) UpsertRegistration(_ context.Context, r WorkloadRegistration) (WorkloadRegistration, error) {
	m.regs[r.ID] = r
	return r, nil
}
func (m *memStore) DeleteRegistration(_ context.Context, _, id string) error {
	delete(m.regs, id)
	return nil
}
func (m *memStore) TouchRegistrationIssued(context.Context, string, string, time.Time) error { return nil }
func (m *memStore) TouchRegistrationUsed(context.Context, string, string, time.Time) error   { return nil }
func (m *memStore) ListFederationBundles(_ context.Context, t string) ([]WorkloadFederationBundle, error) {
	var out []WorkloadFederationBundle
	for _, b := range m.bundles {
		if b.TenantID == t {
			out = append(out, b)
		}
	}
	return out, nil
}
func (m *memStore) GetFederationBundleByTrustDomain(context.Context, string, string) (WorkloadFederationBundle, error) {
	return WorkloadFederationBundle{}, errNotFound
}
func (m *memStore) UpsertFederationBundle(_ context.Context, b WorkloadFederationBundle) (WorkloadFederationBundle, error) {
	m.bundles[b.ID] = b
	return b, nil
}
func (m *memStore) DeleteFederationBundle(_ context.Context, _, id string) error {
	delete(m.bundles, id)
	return nil
}
func (m *memStore) InsertIssuanceRecord(_ context.Context, r WorkloadIssuanceRecord) error {
	m.issuances = append(m.issuances, r)
	return nil
}
func (m *memStore) ListIssuanceRecords(context.Context, string, int) ([]WorkloadIssuanceRecord, error) {
	return m.issuances, nil
}

// tokenIssuer stands in for auth's /auth/workload-token and records what it
// was asked to mint.
type tokenIssuer struct{ last AuthWorkloadTokenRequest }

func (a *tokenIssuer) IssueWorkloadToken(_ context.Context, req AuthWorkloadTokenRequest) (AuthWorkloadTokenResponse, error) {
	a.last = req
	return AuthWorkloadTokenResponse{AccessToken: "kms-token-probe", ExpiresAt: time.Now().Add(time.Minute)}, nil
}

type fixture struct {
	h      *Handler
	store  *memStore
	auth   *tokenIssuer
	rec    *routetest.Recorder
	admin  *pkgauth.Claims
	regA   WorkloadRegistration
	regB   WorkloadRegistration
	x509A  IssuedSVID
	jwtA   IssuedSVID
	tenant string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{store: newMemStore(), auth: &tokenIssuer{}, rec: &routetest.Recorder{}, tenant: "t1"}
	f.h = NewHandler(NewService(f.store, f.auth, nil), f.rec, nil)
	f.admin = &pkgauth.Claims{UserID: "admin", TenantID: "t1", Permissions: []string{"workload.*"}}
	f.do(t, "PUT", "/workload-identity/settings", `{"enabled":true,"trust_domain":"t1.example","token_exchange_enabled":true,"allowed_audiences":["kms"]}`, f.admin, http.StatusOK)
	for _, name := range []string{"a", "b"} {
		w := f.do(t, "POST", "/workload-identity/registrations", `{"name":"`+name+`","issue_x509_svid":true,"issue_jwt_svid":true,"enabled":true,"permissions":["key.encrypt"]}`, f.admin, http.StatusOK)
		var out struct{ Registration WorkloadRegistration }
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if name == "a" {
			f.regA = out.Registration
		} else {
			f.regB = out.Registration
		}
	}
	f.jwtA = f.issue(t, f.regA.ID, "jwt")
	f.x509A = f.issue(t, f.regA.ID, "x509")
	return f
}

func (f *fixture) issue(t *testing.T, regID, typ string) IssuedSVID {
	t.Helper()
	w := f.do(t, "POST", "/workload-identity/issue", `{"registration_id":"`+regID+`","svid_type":"`+typ+`","audiences":["kms"]}`, f.admin, http.StatusOK)
	var out struct{ Issued IssuedSVID }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out.Issued
}

func (f *fixture) do(t *testing.T, method, target, body string, c *pkgauth.Claims, want int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if c != nil {
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), c))
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	if w.Code != want {
		t.Fatalf("%s %s: status %d, want %d: %s", method, target, w.Code, want, w.Body.String())
	}
	return w
}

// expectRefused checks the last event is token_exchanged refused with reason.
func (f *fixture) expectRefused(t *testing.T, reason, actor string) {
	t.Helper()
	ev := f.rec.Last(t)
	if ev.Action != "token_exchanged" || ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != reason || ev.Event.ActorID != actor {
		t.Fatalf("event %s result=%s reason=%v actor=%q, want refused %s by %q", ev.Action, ev.Event.Result, ev.Event.Details["reason"], ev.Event.ActorID, reason, actor)
	}
}

func proofFor(t *testing.T, tenant string, svid IssuedSVID, signedAt time.Time) string {
	t.Helper()
	leaf, err := parseFirstCertificatePEM(svid.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := pkgcrypto.ParsePrivateKeyPEM([]byte(svid.PrivateKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	at := signedAt.UTC().Format(time.RFC3339)
	digest := pkgcrypto.SHA256(X509ProofMessage(tenant, leaf, at))
	sig, err := kp.Private.Sign(pkgcrypto.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return `{"signed_at":"` + at + `","signature":"` + base64.StdEncoding.EncodeToString(sig) + `"}`
}

// Every workload route but the SVID exchange refuses an unauthenticated
// caller, a caller without the permission and a caller naming another
// tenant, and audits each refusal (before 6.9.0-beta none of them did).
func TestWorkloadRefusalsAudited(t *testing.T) {
	f := newFixture(t)
	routetest.RefusalsAudited(t, f.h.router, f.rec)
}

// The token exchange takes no bearer token: a verified JWT-SVID is the
// credential, and the workload's SPIFFE ID is the audited actor.
func TestExchangeWithJWTSVID(t *testing.T) {
	f := newFixture(t)
	body := `{"tenant_id":"t1","interface_name":"rest","audience":"kms","jwt_svid":"` + f.jwtA.JWTSVID + `"}`
	f.do(t, "POST", ExchangePath, body, nil, http.StatusOK)
	ev := f.rec.Last(t)
	if ev.Event.Result != route.ResultSuccess || ev.Event.ActorID != f.regA.SpiffeID || ev.Event.ActorType != "workload" || ev.Event.TargetID != f.regA.ID {
		t.Fatalf("event %+v", ev.Event)
	}
	if f.auth.last.ClientID != f.regA.ID || f.auth.last.SubjectID != f.regA.SpiffeID {
		t.Fatalf("token minted for %+v", f.auth.last)
	}
}

// An SVID buys only its own registration's permissions, only for an audience
// the tenant accepts, and only if it verifies against the tenant's anchors.
func TestExchangeRefusals(t *testing.T) {
	f := newFixture(t)
	jwtBody := func(extra string) string {
		return `{"tenant_id":"t1","interface_name":"rest","jwt_svid":"` + f.jwtA.JWTSVID + `"` + extra + `}`
	}
	f.do(t, "POST", ExchangePath, jwtBody(`,"registration_id":"`+f.regB.ID+`"`), nil, http.StatusForbidden)
	f.expectRefused(t, "svid_registration_mismatch", f.regA.SpiffeID)

	f.do(t, "POST", ExchangePath, jwtBody(`,"audience":"vault"`), nil, http.StatusUnauthorized)
	f.expectRefused(t, "audience_not_allowed", "")

	// Another tenant's SVID doesn't verify against t1's signer.
	other := newFixture(t)
	f.do(t, "POST", ExchangePath, `{"tenant_id":"t1","interface_name":"rest","jwt_svid":"`+other.jwtA.JWTSVID+`"}`, nil, http.StatusUnauthorized)
	f.expectRefused(t, "svid_invalid", "")

	// A caller that does send a token can't use it to reach another tenant.
	f.do(t, "POST", ExchangePath, jwtBody(""), &pkgauth.Claims{UserID: "u", TenantID: "t2", Permissions: []string{"*"}}, http.StatusForbidden)
	f.expectRefused(t, route.ReasonTenantMismatch, "u")
}

// An X.509-SVID chain is public, so it buys nothing without a fresh
// signature from its private key, and each signature works once.
func TestExchangeWithX509SVIDNeedsProofOfPossession(t *testing.T) {
	f := newFixture(t)
	chain, _ := json.Marshal(f.x509A.CertificatePEM)
	body := func(proof string) string {
		b := `{"tenant_id":"t1","interface_name":"rest","x509_svid_chain_pem":` + string(chain)
		if proof != "" {
			b += `,"x509_svid_proof":` + proof
		}
		return b + `}`
	}
	f.do(t, "POST", ExchangePath, body(""), nil, http.StatusUnauthorized)
	f.expectRefused(t, "svid_proof_required", "")

	f.do(t, "POST", ExchangePath, body(proofFor(t, "t2", f.x509A, time.Now())), nil, http.StatusUnauthorized)
	f.expectRefused(t, "svid_proof_invalid", "")

	f.do(t, "POST", ExchangePath, body(proofFor(t, "t1", f.x509A, time.Now().Add(-10*time.Minute))), nil, http.StatusUnauthorized)
	f.expectRefused(t, "svid_proof_expired", "")

	proof := proofFor(t, "t1", f.x509A, time.Now())
	f.do(t, "POST", ExchangePath, body(proof), nil, http.StatusOK)
	if ev := f.rec.Last(t).Event; ev.ActorID != f.regA.SpiffeID || ev.Details["svid_type"] != "x509" {
		t.Fatalf("event %+v", ev)
	}
	f.do(t, "POST", ExchangePath, body(proof), nil, http.StatusUnauthorized)
	f.expectRefused(t, "svid_proof_replayed", "")
}

// Federated trust domains verify SVIDs only while federation is enabled.
func TestFederatedSVIDNeedsFederationEnabled(t *testing.T) {
	f := newFixture(t)
	peer := newFixture(t)
	peer.do(t, "PUT", "/workload-identity/settings", `{"enabled":true,"trust_domain":"peer.example","token_exchange_enabled":true,"allowed_audiences":["kms"]}`, peer.admin, http.StatusOK)
	peerSettings := peer.store.settings["t1"]
	w := peer.do(t, "POST", "/workload-identity/registrations", `{"name":"p","issue_jwt_svid":true,"enabled":true}`, peer.admin, http.StatusOK)
	var out struct{ Registration WorkloadRegistration }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	svid := peer.issue(t, out.Registration.ID, "jwt")
	f.store.regs["peer"] = WorkloadRegistration{ID: "peer", TenantID: "t1", SpiffeID: out.Registration.SpiffeID, Enabled: true,
		AllowedInterfaces: []string{"rest"}, Permissions: []string{"key.encrypt"}, IssueJWTSVID: true}
	f.do(t, "POST", "/workload-identity/federation", `{"trust_domain":"peer.example","jwks_json":`+strings.TrimSpace(mustJSON(peerSettings.LocalBundleJWKS))+`,"enabled":true}`, f.admin, http.StatusOK)

	body := `{"tenant_id":"t1","interface_name":"rest","jwt_svid":"` + svid.JWTSVID + `"}`
	f.do(t, "POST", ExchangePath, body, nil, http.StatusUnauthorized)
	f.expectRefused(t, "svid_invalid", "")

	f.do(t, "PUT", "/workload-identity/settings", `{"enabled":true,"trust_domain":"t1.example","federation_enabled":true,"token_exchange_enabled":true,"allowed_audiences":["kms"]}`, f.admin, http.StatusOK)
	f.do(t, "POST", ExchangePath, body, nil, http.StatusOK)
}

// Issuing an SVID needs workload.issue, not just workload.write, and the
// event says whether a private key left the service.
func TestIssueNeedsIssuePermission(t *testing.T) {
	f := newFixture(t)
	writer := &pkgauth.Claims{UserID: "w", TenantID: "t1", Permissions: []string{"workload.write", "workload.read"}}
	f.do(t, "POST", "/workload-identity/issue", `{"registration_id":"`+f.regA.ID+`","svid_type":"x509"}`, writer, http.StatusForbidden)
	f.issue(t, f.regA.ID, "x509")
	if ev := f.rec.Last(t).Event; ev.Details["private_key_returned"] != true || ev.TargetID != f.regA.ID {
		t.Fatalf("event %+v", ev)
	}
}

// Key usage comes from the audit log read with the caller's own token;
// without one it is reported unavailable, never as zero.
func TestSummaryReportsUsageUnavailable(t *testing.T) {
	f := newFixture(t)
	w := f.do(t, "GET", "/workload-identity/summary", "", f.admin, http.StatusOK)
	if !strings.Contains(w.Body.String(), `"key_usage_unavailable"`) {
		t.Fatalf("summary without an audit client must say usage is unavailable: %s", w.Body.String())
	}
	f.do(t, "GET", "/workload-identity/usage", "", f.admin, http.StatusBadGateway)
}
