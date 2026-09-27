package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"vecta-kms/pkg/oidc"
)

const testCSEIssuer = "gsuitecse-tokenissuer-drive@system.gserviceaccount.com"

func rsaJWK(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())}
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The CSE authorization token is honoured only when Google's token issuer
// signed it for audience cse-authorization; a forged or re-targeted one is
// refused and nothing is read from it.
func TestKACLSAuthorizationTokenMustBeGoogleSigned(t *testing.T) {
	google, _ := rsa.GenerateKey(rand.Reader, 2048)
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK("g1", &google.PublicKey)}})
	}))
	defer srv.Close()
	oldV, oldURL := kaclsVerifier, kaclsJWKSURL
	kaclsVerifier = &oidc.Verifier{HTTP: srv.Client()}
	kaclsJWKSURL = func(string) string { return srv.URL + "/jwk" }
	defer func() { kaclsVerifier, kaclsJWKSURL = oldV, oldURL }()

	now := time.Now()
	claims := func(mut func(jwt.MapClaims)) jwt.MapClaims {
		c := jwt.MapClaims{"iss": testCSEIssuer, "aud": "cse-authorization", "email": "alice@corp.test",
			"resource_name": "//drive/doc1", "kacls_url": "https://kms.test/kacls/k1", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
		if mut != nil {
			mut(c)
		}
		return c
	}
	good := signRS256(t, google, "g1", claims(nil))
	got, err := verifyKACLSAuthorization(context.Background(), good)
	if err != nil || got.Email != "alice@corp.test" || got.KeyURI != "https://kms.test/kacls/k1" {
		t.Fatalf("valid authorization token refused: %+v %v", got, err)
	}
	for name, tok := range map[string]string{
		"attacker key":   signRS256(t, attacker, "g1", claims(nil)),
		"wrong audience": signRS256(t, google, "g1", claims(func(c jwt.MapClaims) { c["aud"] = "other" })),
		"expired":        signRS256(t, google, "g1", claims(func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Hour).Unix() })),
		"foreign issuer": signRS256(t, google, "g1", claims(func(c jwt.MapClaims) { c["iss"] = "evil@attacker.test" })),
		"no email":       signRS256(t, google, "g1", claims(func(c jwt.MapClaims) { delete(c, "email") })),
		"unsigned":       "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+testCSEIssuer+`","aud":"cse-authorization","email":"a@b"}`)) + ".",
	} {
		if _, err := verifyKACLSAuthorization(context.Background(), tok); err == nil {
			t.Errorf("%s: authorization token accepted", name)
		}
	}
}

// The authentication token needs an expiry, an audience that is one of the
// config's OAuth client IDs, and a hosted domain the config allows; a config
// with no client IDs or no allowed domains admits nobody.
func TestGoogleAuthenticationTokenIsStrict(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := NewGoogleCSEProvider(nil)
	p.googleKeysCache = map[string]crypto.PublicKey{"k": &key.PublicKey}
	p.googleKeysTTL = time.Now().Add(time.Hour)
	now := time.Now()
	tok := func(c jwt.MapClaims) string { return signRS256(t, key, "k", c) }
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"iss": "https://accounts.google.com", "aud": "cse-client.apps.googleusercontent.com", "email": "alice@corp.test", "hd": "corp.test", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
	}
	clients := []string{"cse-client.apps.googleusercontent.com"}
	if _, err := p.ValidateGoogleJWT(tok(base()), []string{"corp.test"}, clients); err != nil {
		t.Fatalf("valid authentication token refused: %v", err)
	}
	listAud := base()
	listAud["aud"] = []string{"other-app", "cse-client.apps.googleusercontent.com"}
	if _, err := p.ValidateGoogleJWT(tok(listAud), []string{"corp.test"}, clients); err != nil {
		t.Fatalf("authentication token with a list audience refused: %v", err)
	}
	noExp := base()
	delete(noExp, "exp")
	noHD := base()
	delete(noHD, "hd")
	otherApp := base()
	otherApp["aud"] = "some-other-app.apps.googleusercontent.com"
	noAud := base()
	delete(noAud, "aud")
	for name, c := range map[string]struct {
		claims  jwt.MapClaims
		domains []string
		clients []string
	}{
		"no expiry":          {noExp, []string{"corp.test"}, clients},
		"consumer account":   {noHD, []string{"corp.test"}, clients},
		"other domain":       {base(), []string{"elsewhere.test"}, clients},
		"no allowed domains": {base(), nil, clients},
		"other application":  {otherApp, []string{"corp.test"}, clients},
		"no audience":        {noAud, []string{"corp.test"}, clients},
		"no client IDs":      {base(), []string{"corp.test"}, nil},
	} {
		if _, err := p.ValidateGoogleJWT(tok(c.claims), c.domains, c.clients); err == nil {
			t.Errorf("%s: authentication token accepted", name)
		}
	}
}

// The configured client IDs are stored and read back; a config cannot be
// created without one, so no config admits authentication tokens minted for
// some other application.
func TestGoogleCSEConfigKeepsAuthenticationClientIDs(t *testing.T) {
	svc, store, _, _ := newEKMService(t)
	migration, err := os.ReadFile("migrations/004_google_cse.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{string(migration), `ALTER TABLE ekm_google_cse_configs ADD COLUMN authentication_client_ids TEXT NOT NULL DEFAULT '[]'`} {
		if _, err := store.db.SQL().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	cfg := GoogleCSEConfig{ID: "gcse1", TenantID: "t1", GoogleWorkspaceCustomerID: "C1", AllowedDomains: []string{"corp.test"},
		AuthenticationClientIDs: []string{" cse-client.apps.googleusercontent.com ", ""}, Status: "active"}
	if err := store.CreateGoogleCSEConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetGoogleCSEConfig(ctx, "t1", "gcse1")
	if err != nil || len(got.AuthenticationClientIDs) != 1 || got.AuthenticationClientIDs[0] != "cse-client.apps.googleusercontent.com" {
		t.Fatalf("client IDs not stored: %+v %v", got.AuthenticationClientIDs, err)
	}
	got.AuthenticationClientIDs = []string{"a", "b"}
	if err := store.UpdateGoogleCSEConfig(ctx, got); err != nil {
		t.Fatal(err)
	}
	if got, _ = store.GetGoogleCSEConfig(ctx, "t1", "gcse1"); len(got.AuthenticationClientIDs) != 2 {
		t.Fatalf("client IDs not updated: %+v", got.AuthenticationClientIDs)
	}

	h := NewHandler(svc)
	h.SetJWTParser(testEKMJWT)
	req := httptest.NewRequest(http.MethodPost, "/ekm/google-cse/configs?tenant_id=t1",
		strings.NewReader(`{"tenant_id":"t1","google_workspace_customer_id":"C2","allowed_domains":["corp.test"]}`))
	req.Header.Set("Authorization", "Bearer jwt:t1:admin")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "authentication_client_ids") {
		t.Fatalf("config without client IDs accepted: %d %s", rr.Code, rr.Body.String())
	}
}
