package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/credstore"
	"vecta-kms/pkg/oidc"
	"vecta-kms/pkg/route/routetest"
	"vecta-kms/pkg/tenantcheck"
)

// OCI External KMS: tokens signed RS256 by an identity domain double that
// serves its JWKS (optionally behind a client-credentials token, as a
// domain that does not expose its signing certificate does), and requests
// in the External KMS vendor API v1 wire format.

const (
	ociAud      = "https://kms.example.com/"
	ociClient   = "ocid-ekms-client"
	ociAppID    = "ocid-resource-app"
	ociAppValue = "resource-app-secret-value"
)

type ociDomain struct {
	srv        *httptest.Server
	key        *rsa.PrivateKey
	protected  bool
	tokenCalls atomic.Int32
}

func newOCIDomain(t *testing.T, protected bool) *ociDomain {
	t.Helper()
	d := &ociDomain{key: getTestRSAKey(), protected: protected}
	d.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/v1/token":
			id, secret, ok := r.BasicAuth()
			_ = r.ParseForm()
			if !ok || id != ociAppID || secret != ociAppValue || r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("scope") != ociJWKSScope {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			d.tokenCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "domain-access-token", "expires_in": 3600})
		case "/admin/v1/SigningCert/jwk":
			if d.protected && r.Header.Get("Authorization") != "Bearer domain-access-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			pub := d.key.PublicKey
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{
				"kty": "RSA", "kid": "SIGNING_KEY", "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(d.srv.Close)
	prev := newOCIVerifier
	newOCIVerifier = func() *oidc.Verifier { return &oidc.Verifier{HTTP: d.srv.Client()} }
	t.Cleanup(func() { newOCIVerifier = prev })
	return d
}

func (d *ociDomain) jwksURL() string { return d.srv.URL + "/admin/v1/SigningCert/jwk" }

// token is an identity domain client-credentials access token; edit
// changes its claims.
func (d *ociDomain) token(t *testing.T, key *rsa.PrivateKey, edit func(jwt.MapClaims)) string {
	t.Helper()
	now := time.Now()
	c := jwt.MapClaims{
		"iss": ociDefaultIssuer, "aud": []string{ociAud, "urn:opc:lbaas:logicalguid=x"}, "sub": ociClient, "client_id": ociClient,
		"scope": "oci_ekms", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "tok_type": "AT",
	}
	if edit != nil {
		edit(c)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "SIGNING_KEY"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type ociFixture struct {
	h       *Handler
	svc     *Service
	keycore *fakeHYOKKeyCore
	pub     *nopHYOKPublisher
	rec     *routetest.Recorder
	domain  *ociDomain
}

func newOCIFixture(t *testing.T, protected bool) *ociFixture {
	t.Helper()
	svc, _, keycore, _, _, pub := newHYOKService(t)
	keycore.Seed("tenant-a", "k-aes", "AES-256")
	keycore.Seed("tenant-a", "k-128", "AES-128")
	keycore.Seed("tenant-a", "k-rsa", "RSA-2048")
	keycore.Seed("tenant-b", "k-b", "AES-256")
	svc.SetCredentials(&fakeCreds{byID: map[string]credstore.Credential{
		"pbconn_oci":  {ID: "pbconn_oci", Type: "oci_identity_domain", Fields: map[string]string{"client_id": ociAppID, "client_secret": ociAppValue}},
		"pbconn_smtp": {ID: "pbconn_smtp", Type: "smtp", Fields: map[string]string{"host": "mail"}},
	}})
	d := newOCIDomain(t, protected)
	m := OCIEKMMetadata{PathPrefix: "contoso", VaultID: "vault-1", JWKSURL: d.jwksURL(), Audience: ociAud, ClientIDs: []string{ociClient},
		Keys: map[string]string{"orders": "k-aes", "small": "k-128"}}
	if protected {
		m.JWKSCredentialID = "pbconn_oci"
	}
	if err := saveOCI(svc, "tenant-a", adminClaims(), m, false); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(svc, testJWTParser)
	rec := &routetest.Recorder{}
	h.MountKernel(rec, nil, "test")
	return &ociFixture{h: h, svc: svc, keycore: keycore, pub: pub, rec: rec, domain: d}
}

func saveOCI(svc *Service, tenant string, claims *pkgauth.Claims, m OCIEKMMetadata, governance bool) error {
	raw, _ := json.Marshal(m)
	ctx := pkgauth.ContextWithClaims(context.Background(), claims)
	_, err := svc.ConfigureEndpoint(ctx, EndpointConfig{TenantID: tenant, Protocol: ProtocolOCIEKM, Enabled: true, GovernanceRequired: governance, MetadataJSON: string(raw)})
	return err
}

// call serves a request as Envoy hands it on (/svc/hyok rewritten to /).
func (f *ociFixture) call(t *testing.T, method, path string, body interface{}, token string) (int, map[string]interface{}) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, "/oci/contoso/ekm/v1/"+path, rd)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("opc-request-id", "oci-req-1")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if got := w.Header().Get("opc-request-id"); got != "oci-req-1" {
		t.Fatalf("opc-request-id %q", got)
	}
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestOCIEKMEncryptsAndDecryptsAcrossRotation(t *testing.T) {
	f := newOCIFixture(t, false)
	tok := f.domain.token(t, f.domain.key, nil)
	aad := base64.StdEncoding.EncodeToString([]byte("tenancy=ocid1.tenancy"))
	plain := base64.StdEncoding.EncodeToString([]byte("a data encryption key.......32b!"))

	code, v := f.call(t, http.MethodGet, "vaults/vault-1/metadata", nil, tok)
	if code != 200 || v["state"] != "ACTIVE" || v["vendor"] != ociVendor {
		t.Fatalf("vault metadata %d %v", code, v)
	}
	code, km := f.call(t, http.MethodGet, "vaults/vault-1/keys/orders/metadata", nil, tok)
	shape, _ := km["keyShape"].(map[string]interface{})
	if code != 200 || km["currentKeyVersionId"] != "1" || km["state"] != "ACTIVE" || shape["algorithm"] != "AES" || shape["length"] != float64(32) {
		t.Fatalf("key metadata %d %v", code, km)
	}
	if _, small := f.call(t, http.MethodGet, "vaults/vault-1/keys/small/metadata", nil, tok); small["keyShape"].(map[string]interface{})["length"] != float64(16) {
		t.Fatalf("AES-128 shape %v", small)
	}

	code, e1 := f.call(t, http.MethodPost, "vaults/vault-1/keys/orders/encrypt", map[string]interface{}{"plaintext": plain, "aad": aad, "mode": "AES_GCM", "tagLen": 16, "pad": "PKCS7"}, tok)
	if code != 200 || e1["keyVersionId"] != "1" || e1["keyId"] != "orders" || e1["mode"] != "AES_GCM" || e1["aad"] != aad {
		t.Fatalf("encrypt %d %v", code, e1)
	}
	if ct := dec(t, e1["ciphertext"]); len(ct) != 32 || len(dec(t, e1["tag"])) != 16 || len(dec(t, e1["iv"])) != 12 {
		t.Fatalf("encrypt output sizes %v", e1)
	}
	if e := f.rec.Last(t); e.Action != "oci_ekm_request" || e.Event.Result != "success" || e.Event.Details["opc_request_id"] != "oci-req-1" {
		t.Fatalf("event %+v", e.Event)
	}
	if f.pub.Count("audit.hyok.oci_ekm_request") == 0 {
		t.Fatal("the crypto call was not audited")
	}

	f.keycore.Rotate("tenant-a", "k-aes")
	code, e2 := f.call(t, http.MethodPost, "vaults/vault-1/keys/orders/encrypt", map[string]interface{}{"plaintext": plain, "aad": aad, "mode": "AES_GCM"}, tok)
	if code != 200 || e2["keyVersionId"] != "2" {
		t.Fatalf("encrypt after rotation %d %v", code, e2)
	}
	for _, e := range []map[string]interface{}{e1, e2} {
		code, d := f.call(t, http.MethodPost, "vaults/vault-1/keys/orders/decrypt", map[string]interface{}{
			"ciphertext": e["ciphertext"], "iv": e["iv"], "tag": e["tag"], "aad": aad, "mode": "AES_GCM", "keyVersionId": e["keyVersionId"],
		}, tok)
		if code != 200 || d["plaintext"] != plain || d["keyVersionId"] != e["keyVersionId"] {
			t.Fatalf("decrypt v%v: %d %v", e["keyVersionId"], code, d)
		}
	}
	// The AAD, the version and the tag are all authenticated.
	for name, body := range map[string]map[string]interface{}{
		"other aad":     {"ciphertext": e1["ciphertext"], "iv": e1["iv"], "tag": e1["tag"], "aad": base64.StdEncoding.EncodeToString([]byte("x")), "keyVersionId": "1"},
		"other version": {"ciphertext": e1["ciphertext"], "iv": e1["iv"], "tag": e1["tag"], "aad": aad, "keyVersionId": "2"},
		"no aad":        {"ciphertext": e1["ciphertext"], "iv": e1["iv"], "tag": e1["tag"], "keyVersionId": "1"},
		"tag of e2":     {"ciphertext": e1["ciphertext"], "iv": e1["iv"], "tag": e2["tag"], "aad": aad, "keyVersionId": "1"},
	} {
		if code, out := f.call(t, http.MethodPost, "vaults/vault-1/keys/orders/decrypt", body, tok); code != 400 || out["code"] != "400" {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	// Encrypt only with the current version.
	if code, out := f.call(t, http.MethodPost, "vaults/vault-1/keys/orders/encrypt", map[string]interface{}{"plaintext": plain, "keyVersionId": "1"}, tok); code != 400 {
		t.Fatalf("encrypt with a retired version: %d %v", code, out)
	}

	code, kv := f.call(t, http.MethodGet, "vaults/vault-1/keys/orders/keyVersions/1/metadata", nil, tok)
	if code != 200 || kv["state"] != "ACTIVE" || len(kv["keyVersionOps"].([]interface{})) != 1 {
		t.Fatalf("old version metadata %d %v", code, kv)
	}
	f.keycore.versionStatus = map[string]string{"tenant-a:k-aes:1": "deactivated"}
	if code, kv := f.call(t, http.MethodGet, "vaults/vault-1/keys/orders/keyVersions/1/metadata", nil, tok); code != 200 || kv["state"] != "DISABLED" {
		t.Fatalf("deactivated version %d %v", code, kv)
	}
	if code, kv := f.call(t, http.MethodGet, "vaults/vault-1/keys/orders/keyVersions/2/metadata", nil, tok); code != 200 || len(kv["keyVersionOps"].([]interface{})) != 2 {
		t.Fatalf("current version %d %v", code, kv)
	}
	if code, _ := f.call(t, http.MethodGet, "vaults/vault-1/keys/orders/keyVersions/9/metadata", nil, tok); code != 404 {
		t.Fatalf("missing version %d", code)
	}

	code, rb := f.call(t, http.MethodPost, "vaults/vault-1/generateRandomBytes", map[string]interface{}{"length": 32}, tok)
	if code != 201 || rb["length"] != float64(32) || len(dec(t, rb["randomBytes"])) != 32 {
		t.Fatalf("random bytes %d %v", code, rb)
	}
}

func TestOCIEKMRefusesAndAuditsBadCalls(t *testing.T) {
	f := newOCIFixture(t, false)
	good := f.domain.token(t, f.domain.key, nil)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc := map[string]interface{}{"plaintext": base64.StdEncoding.EncodeToString([]byte("data")), "mode": "AES_GCM"}
	refused := func(t *testing.T, name string, code int, out map[string]interface{}, wantCode int, wantReason string) {
		t.Helper()
		if code != wantCode || out["code"] != itoa(wantCode) {
			t.Fatalf("%s: got %d %v, want %d", name, code, out, wantCode)
		}
		e := f.rec.Last(t)
		if e.Action != "oci_ekm_request" || e.Event.Result == "success" || e.Event.Details["reason"] != wantReason {
			t.Fatalf("%s: event %+v", name, e.Event)
		}
	}
	for name, tok := range map[string]string{
		"no token":        "",
		"other signer":    f.domain.token(t, other, nil),
		"other audience":  f.domain.token(t, f.domain.key, func(c jwt.MapClaims) { c["aud"] = "https://elsewhere/" }),
		"other issuer":    f.domain.token(t, f.domain.key, func(c jwt.MapClaims) { c["iss"] = "https://idcs-evil.identity.oraclecloud.com" }),
		"expired":         f.domain.token(t, f.domain.key, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }),
		"no oci_ekms":     f.domain.token(t, f.domain.key, func(c jwt.MapClaims) { c["scope"] = "urn:opc:idm:__myscopes__" }),
		"unlisted client": f.domain.token(t, f.domain.key, func(c jwt.MapClaims) { c["client_id"] = "someone-else" }),
		"no client_id":    f.domain.token(t, f.domain.key, func(c jwt.MapClaims) { delete(c, "client_id") }),
		"a Vecta JWT":     "jwt:tenant-a:admin",
	} {
		code, out := f.call(t, http.MethodPost, "vaults/vault-1/keys/orders/encrypt", enc, tok)
		refused(t, name, code, out, 401, "invalid_token")
	}
	code, out := f.call(t, http.MethodGet, "vaults/vault-2/metadata", nil, good)
	refused(t, "other vault", code, out, 404, "vault_not_found")
	code, out = f.call(t, http.MethodPost, "vaults/vault-1/keys/nope/encrypt", enc, good)
	refused(t, "unmapped key", code, out, 404, "key_not_found")
	code, out = f.call(t, http.MethodPost, "vaults/vault-1/keys/orders/encrypt", map[string]interface{}{"plaintext": "ZGF0YQ==", "mode": "AES_CBC"}, good)
	refused(t, "CBC", code, out, 400, "mode_unsupported")
	code, out = f.call(t, http.MethodPost, "vaults/vault-1/keys/orders/encrypt", map[string]interface{}{"plaintext": "ZGF0YQ==", "tagLen": 12}, good)
	refused(t, "short tag", code, out, 400, "bad_request")
	code, out = f.call(t, http.MethodPost, "vaults/vault-1/keys/orders/encrypt", map[string]interface{}{"plaintext": "not base64!"}, good)
	refused(t, "bad base64", code, out, 400, "bad_request")
	code, out = f.call(t, http.MethodPost, "vaults/vault-1/generateRandomBytes", map[string]interface{}{"length": 64}, good)
	refused(t, "64 random bytes", code, out, 400, "bad_request")
	f.keycore.SetStatus("tenant-a", "k-aes", "disabled")
	code, out = f.call(t, http.MethodPost, "vaults/vault-1/keys/orders/encrypt", enc, good)
	refused(t, "disabled key", code, out, 403, "key_disabled")

	// An unknown prefix answers 404 before any token is read.
	r := httptest.NewRequest(http.MethodGet, "/oci/nobody/ekm/v1/vaults/v/metadata", nil)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != 404 || !strings.Contains(w.Body.String(), `"code":"404"`) {
		t.Fatalf("unknown prefix %d %s", w.Code, w.Body.String())
	}
	// A Vecta token on a protocol route can't stand in for the identity
	// domain's: the endpoint takes only tokens the OCI handler verified.
	if err := checkAuthMode(AuthModeOCIJWT, AuthModeJWT); err == nil {
		t.Fatal("a Vecta JWT satisfied an OCI endpoint")
	}
}

// A domain whose signing certificate is not public: the endpoint's
// oci_identity_domain credential gets a token to read the JWKS.
func TestOCIEKMReadsAProtectedJWKSWithTheDomainCredential(t *testing.T) {
	f := newOCIFixture(t, true)
	tok := f.domain.token(t, f.domain.key, nil)
	for i := 0; i < 2; i++ {
		if code, out := f.call(t, http.MethodGet, "vaults/vault-1/metadata", nil, tok); code != 200 {
			t.Fatalf("call %d: %d %v", i, code, out)
		}
	}
	if n := f.domain.tokenCalls.Load(); n != 1 {
		t.Fatalf("token endpoint called %d times, want 1 (JWKS cached)", n)
	}

	// Without the credential the protected JWKS can't be read.
	g := newOCIFixture(t, true)
	raw, _ := g.svc.store.GetEndpoint(context.Background(), "tenant-a", ProtocolOCIEKM)
	m, _ := parseOCIEKMMetadata(raw.MetadataJSON)
	m.JWKSCredentialID = ""
	if err := saveOCI(g.svc, "tenant-a", adminClaims(), m, false); err != nil {
		t.Fatal(err)
	}
	if code, _ := g.call(t, http.MethodGet, "vaults/vault-1/metadata", nil, g.domain.token(t, g.domain.key, nil)); code != 401 {
		t.Fatalf("protected JWKS without a credential: %d", code)
	}
}

func TestOCIEKMEndpointSettingsAreChecked(t *testing.T) {
	f := newOCIFixture(t, false)
	jwks := f.domain.jwksURL()
	ok := OCIEKMMetadata{PathPrefix: "tenant-b", VaultID: "v", JWKSURL: jwks, Audience: ociAud, ClientIDs: []string{"c"}, Keys: map[string]string{"k": "k-b"}}
	bClaims := &pkgauth.Claims{TenantID: "tenant-b", UserID: "bob", Permissions: []string{"*"}}
	if err := saveOCI(f.svc, "tenant-b", bClaims, ok, false); err != nil {
		t.Fatalf("valid settings refused: %v", err)
	}
	stored, _ := f.svc.store.GetEndpoint(context.Background(), "tenant-b", ProtocolOCIEKM)
	if stored.AuthMode != AuthModeOCIJWT || !strings.Contains(stored.MetadataJSON, ociDefaultIssuer) {
		t.Fatalf("stored %q %s", stored.AuthMode, stored.MetadataJSON)
	}
	with := func(edit func(*OCIEKMMetadata)) OCIEKMMetadata {
		m := ok
		m.ClientIDs = append([]string{}, ok.ClientIDs...)
		edit(&m)
		return m
	}
	hyokOnly := &pkgauth.Claims{TenantID: "tenant-b", UserID: "carol", Permissions: []string{"hyok.write"}}
	for name, tc := range map[string]struct {
		claims     *pkgauth.Claims
		governance bool
		m          OCIEKMMetadata
	}{
		"approval":          {bClaims, true, ok},
		"no vault":          {bClaims, false, with(func(m *OCIEKMMetadata) { m.VaultID = "" })},
		"http jwks":         {bClaims, false, with(func(m *OCIEKMMetadata) { m.JWKSURL = "http://idcs.example.com/jwk" })},
		"http issuer":       {bClaims, false, with(func(m *OCIEKMMetadata) { m.Issuer = "http://identity.oraclecloud.com/" })},
		"no audience":       {bClaims, false, with(func(m *OCIEKMMetadata) { m.Audience = "" })},
		"no clients":        {bClaims, false, with(func(m *OCIEKMMetadata) { m.ClientIDs = nil })},
		"duplicate clients": {bClaims, false, with(func(m *OCIEKMMetadata) { m.ClientIDs = []string{"c", "c"} })},
		"wrong cred type":   {bClaims, false, with(func(m *OCIEKMMetadata) { m.JWKSCredentialID = "pbconn_smtp" })},
		"missing cred":      {bClaims, false, with(func(m *OCIEKMMetadata) { m.JWKSCredentialID = "pbconn_gone" })},
		"no connection.use": {hyokOnly, false, with(func(m *OCIEKMMetadata) { m.JWKSCredentialID = "pbconn_oci" })},
		"prefix in use":     {bClaims, false, with(func(m *OCIEKMMetadata) { m.PathPrefix = "CONTOSO" })},
		"bad prefix":        {bClaims, false, with(func(m *OCIEKMMetadata) { m.PathPrefix = "a b" })},
	} {
		before := f.pub.Count("audit.hyok.endpoint_refused")
		if err := saveOCI(f.svc, "tenant-b", tc.claims, tc.m, tc.governance); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if f.pub.Count("audit.hyok.endpoint_refused") != before+1 {
			t.Fatalf("%s: refusal not audited", name)
		}
	}
	m := OCIEKMMetadata{PathPrefix: "contoso", VaultID: "v", JWKSURL: jwks, Audience: ociAud, ClientIDs: []string{"c"}, Keys: map[string]string{"r": "k-rsa"}}
	if err := saveOCI(f.svc, "tenant-a", adminClaims(), m, false); err == nil {
		t.Fatal("an RSA key accepted for OCI External KMS")
	}
}

// The credential store sees which OCI endpoint uses a domain credential.
func TestOCIEKMCredentialUsageNamesTheEndpoint(t *testing.T) {
	f := newOCIFixture(t, true)
	h := NewHandler(f.svc, func(tok string) (*pkgauth.Claims, error) {
		if tok == "compliance" {
			return &pkgauth.Claims{TenantID: tenantcheck.InternalServiceTenant(), Role: "client-service", ClientID: "kms-compliance", Permissions: []string{"service.internal"}}, nil
		}
		return testJWTParser(tok)
	})
	h.MountKernel(&routetest.Recorder{}, nil, "test")
	r := httptest.NewRequest(http.MethodGet, "/hyok/credential-usage?tenant_id=tenant-a", nil)
	r.Header.Set("Authorization", "Bearer compliance")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"connection_id":"pbconn_oci"`) {
		t.Fatalf("usage %d %s", w.Code, w.Body.String())
	}
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }
