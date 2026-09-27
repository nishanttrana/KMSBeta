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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"vecta-kms/pkg/oidc"
)

const (
	testEntraTenant = "11111111-2222-3333-4444-555555555555"
	testEntraIssuer = "https://login.microsoftonline.com/" + testEntraTenant + "/v2.0"
)

// entraHarness serves an Entra-style JWKS for entra's key and points the DKE
// verifier at it; tenant-ms has a DKE endpoint that trusts that issuer.
func entraHarness(t *testing.T, meta map[string]any) (*Handler, *nopHYOKPublisher, *rsa.PrivateKey) {
	t.Helper()
	entra, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "e1", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(entra.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(entra.PublicKey.E)).Bytes())}}})
	}))
	t.Cleanup(srv.Close)
	oldV, oldURL := entraVerifier, entraJWKSURL
	entraVerifier = &oidc.Verifier{HTTP: srv.Client()}
	jwksTenant := ""
	entraJWKSURL = func(tid string) string { jwksTenant = tid; return srv.URL + "/keys" }
	t.Cleanup(func() {
		entraVerifier, entraJWKSURL = oldV, oldURL
		if jwksTenant != "" && jwksTenant != testEntraTenant {
			t.Errorf("keys fetched for Entra tenant %q", jwksTenant)
		}
	})

	h, svc, keycore, _, _, pub := newHYOKHandler(t)
	keycore.Seed("tenant-ms", "rsa-1", "RSA-2048")
	raw, _ := json.Marshal(meta)
	if err := svc.store.UpsertEndpoint(context.Background(), EndpointConfig{TenantID: "tenant-ms", Protocol: ProtocolDKE,
		Enabled: true, AuthMode: AuthModeJWT, MetadataJSON: string(raw)}); err != nil {
		t.Fatal(err)
	}
	return h, pub, entra
}

func entraMeta() map[string]any {
	return map[string]any{
		"valid_issuers":     []string{testEntraIssuer},
		"jwt_audiences":     []string{"api://dke.contoso.test"},
		"authorized_emails": []string{"alice@contoso.test"},
		"authorized_roles":  []string{"DKE.Decrypt"},
		"key_uri_hostname":  "dke.contoso.test",
	}
}

func entraToken(t *testing.T, key *rsa.PrivateKey, mut func(jwt.MapClaims)) string {
	t.Helper()
	now := time.Now()
	c := jwt.MapClaims{"iss": testEntraIssuer, "aud": "api://dke.contoso.test", "tid": testEntraTenant,
		"oid": "oid-alice", "preferred_username": "Alice@contoso.test", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	if mut != nil {
		mut(c)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "e1"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func dkeDecrypt(h *Handler, host, token string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"alg": "RSA-OAEP-256",
		"value": base64.StdEncoding.EncodeToString([]byte("wrap:aGVsbG8="))})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rsa-1/1/decrypt", bytes.NewReader(body))
	req.Host = host
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// Office decrypts with an Entra ID token: verified against the Entra
// tenant's keys, for the endpoint's issuer and audience, by an authorized
// user. The Vecta tenant comes from the endpoint that trusts the issuer.
func TestMicrosoftDKEAcceptsVerifiedEntraToken(t *testing.T) {
	h, pub, entra := entraHarness(t, entraMeta())
	if rr := dkeDecrypt(h, "dke.contoso.test", entraToken(t, entra, nil)); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"value":"aGVsbG8="`) {
		t.Fatalf("authorized Entra user refused: %d %s", rr.Code, rr.Body.String())
	}
	// An app role authorizes a user whose email is not listed.
	byRole := entraToken(t, entra, func(c jwt.MapClaims) {
		c["preferred_username"] = "bob@contoso.test"
		c["roles"] = []string{"DKE.Decrypt"}
	})
	if rr := dkeDecrypt(h, "dke.contoso.test", byRole); rr.Code != http.StatusOK {
		t.Fatalf("user with the DKE app role refused: %d %s", rr.Code, rr.Body.String())
	}
	if pub.Count("audit.hyok.dke_refused") != 0 {
		t.Fatal("successful calls audited as refusals")
	}
}

// Every way an Entra token can be wrong is refused and audited.
func TestMicrosoftDKERefusesBadEntraTokens(t *testing.T) {
	h, pub, entra := entraHarness(t, entraMeta())
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherTenant := "99999999-2222-3333-4444-555555555555"
	cases := map[string]string{
		"forged signature": entraToken(t, attacker, nil),
		"other audience":   entraToken(t, entra, func(c jwt.MapClaims) { c["aud"] = "api://something-else" }),
		"expired":          entraToken(t, entra, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }),
		"untrusted issuer": entraToken(t, entra, func(c jwt.MapClaims) {
			c["iss"] = "https://login.microsoftonline.com/" + otherTenant + "/v2.0"
			c["tid"] = otherTenant
		}),
		"tid mismatch":      entraToken(t, entra, func(c jwt.MapClaims) { c["tid"] = otherTenant }),
		"unauthorized user": entraToken(t, entra, func(c jwt.MapClaims) { c["preferred_username"] = "mallory@contoso.test" }),
		"email claim only": entraToken(t, entra, func(c jwt.MapClaims) {
			c["preferred_username"] = "mallory@contoso.test"
			c["email"] = "alice@contoso.test"
		}),
		"role split by comma": entraToken(t, entra, func(c jwt.MapClaims) {
			c["preferred_username"] = "mallory@contoso.test"
			c["roles"] = "DKE.Decrypt,Other"
		}),
	}
	for name, tok := range cases {
		before := pub.Count("audit.hyok.dke_refused")
		if rr := dkeDecrypt(h, "dke.contoso.test", tok); rr.Code == http.StatusOK {
			t.Errorf("%s: decrypt allowed: %s", name, rr.Body.String())
		}
		if pub.Count("audit.hyok.dke_refused") != before+1 {
			t.Errorf("%s: refusal not audited", name)
		}
	}
	if rr := dkeDecrypt(h, "dke.contoso.test", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("decrypt without a token: %d", rr.Code)
	}
}

// An endpoint that names no audience or no authorized users admits no Entra
// token at all.
func TestMicrosoftDKEEntraNeedsAudienceAndAuthorizedUsers(t *testing.T) {
	for _, drop := range []string{"jwt_audiences", "authorized_emails"} {
		meta := entraMeta()
		delete(meta, drop)
		if drop == "authorized_emails" {
			delete(meta, "authorized_roles")
		}
		h, _, entra := entraHarness(t, meta)
		if rr := dkeDecrypt(h, "dke.contoso.test", entraToken(t, entra, nil)); rr.Code == http.StatusOK {
			t.Errorf("without %s: Entra token accepted", drop)
		}
	}
}

// Office fetches the public key without a token; that is served only on the
// endpoint's configured host.
func TestMicrosoftDKEPublicKeyWithoutToken(t *testing.T) {
	h, pub, _ := entraHarness(t, entraMeta())
	get := func(host string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/rsa-1", nil)
		req.Host = host
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	if rr := get("dke.contoso.test"); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"kid":"https://dke.contoso.test/api/v1/keys/rsa-1/1"`) {
		t.Fatalf("public key refused on the DKE host: %d %s", rr.Code, rr.Body.String())
	}
	if rr := get("kms.other.test"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("public key served without a token on another host: %d", rr.Code)
	}
	if pub.Count("audit.hyok.dke_refused") != 1 {
		t.Fatal("anonymous refusal not audited")
	}
}
