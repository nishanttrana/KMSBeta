package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type testIssuer struct {
	srv *httptest.Server
	key *ecdsa.PrivateKey
	v   *Verifier
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ti := &testIssuer{key: key}
	mux := http.NewServeMux()
	ti.srv = httptest.NewTLSServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Discovery{Issuer: ti.srv.URL, AuthorizationEndpoint: ti.srv.URL + "/auth", TokenEndpoint: ti.srv.URL + "/token", JwksURI: ti.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		b := func(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig", "alg": "ES256",
			"x": b(key.PublicKey.X.FillBytes(make([]byte, 32))), "y": b(key.PublicKey.Y.FillBytes(make([]byte, 32))),
		}}})
	})
	t.Cleanup(ti.srv.Close)
	ti.v = &Verifier{HTTP: ti.srv.Client()}
	return ti
}

func (ti *testIssuer) token(t *testing.T, claims jwt.MapClaims, kid string, key any, method jwt.SigningMethod) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (ti *testIssuer) claims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{"iss": ti.srv.URL, "aud": "client-1", "sub": "user-1", "nonce": "n1", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
}

func TestVerifyIDTokenAcceptsTokenSignedByIssuer(t *testing.T) {
	ti := newTestIssuer(t)
	d, err := ti.v.Discover(context.Background(), ti.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ti.v.VerifyIDToken(context.Background(), ti.token(t, ti.claims(), "k1", ti.key, jwt.SigningMethodES256), d, "client-1", "n1", time.Now())
	if err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	if got["sub"] != "user-1" {
		t.Fatalf("claims: %v", got)
	}
}

func TestVerifyIDTokenRefusesForgedOrMisdirectedTokens(t *testing.T) {
	ti := newTestIssuer(t)
	d, err := ti.v.Discover(context.Background(), ti.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	with := func(k string, v any) jwt.MapClaims { c := ti.claims(); c[k] = v; return c }
	cases := map[string]string{
		"signed by other key": ti.token(t, ti.claims(), "k1", other, jwt.SigningMethodES256),
		"wrong audience":      ti.token(t, with("aud", "client-2"), "k1", ti.key, jwt.SigningMethodES256),
		"wrong issuer":        ti.token(t, with("iss", "https://evil.test"), "k1", ti.key, jwt.SigningMethodES256),
		"expired":             ti.token(t, with("exp", time.Now().Add(-10*time.Minute).Unix()), "k1", ti.key, jwt.SigningMethodES256),
		"no expiry":           ti.token(t, jwt.MapClaims{"iss": ti.srv.URL, "aud": "client-1", "sub": "u", "nonce": "n1"}, "k1", ti.key, jwt.SigningMethodES256),
		"wrong nonce":         ti.token(t, with("nonce", "n2"), "k1", ti.key, jwt.SigningMethodES256),
		"unknown kid":         ti.token(t, ti.claims(), "k9", ti.key, jwt.SigningMethodES256),
		"hmac with secret":    ti.token(t, ti.claims(), "k1", []byte("client-secret-of-thirty-two-byte"), jwt.SigningMethodHS256),
		"azp other client":    ti.token(t, with("aud", []string{"client-1", "client-2"}), "k1", ti.key, jwt.SigningMethodES256),
		"unsigned":            "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`)) + ".",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ti.v.VerifyIDToken(context.Background(), tok, d, "client-1", "n1", time.Now()); err == nil {
				t.Fatal("token accepted")
			}
		})
	}
}

func TestDiscoverRefusesIssuerMismatch(t *testing.T) {
	ti := newTestIssuer(t)
	if _, err := ti.v.Discover(context.Background(), ti.srv.URL+"/other"); err == nil {
		t.Fatal("discovery accepted a document for a different issuer")
	}
	if _, err := ti.v.Discover(context.Background(), "http://idp.test"); err == nil {
		t.Fatal("plain-http issuer accepted")
	}
}
