// Package oidc verifies OpenID Connect ID tokens: discovery, the issuer's
// JWKS, the token signature, and the iss/aud/exp/azp/nonce claims (OIDC Core
// 1.0 §3.1.3.7). It is the one place services turn an ID token into a verified
// identity; a claim is never read from an unverified token.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"vecta-kms/pkg/restauth"
	"vecta-kms/pkg/ssrfguard"
)

// Discovery is the subset of the provider configuration document we use.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

// Asymmetric algorithms only: HS* would let anyone holding the client secret
// mint tokens, and "none" is never accepted.
var signingMethods = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

const (
	maxDocBytes = 1 << 20
	jwksTTL     = 10 * time.Minute
	leeway      = time.Minute
)

// Verifier fetches discovery documents and JWKS over HTTPS. CheckURL guards
// every outbound URL (ssrfguard by default); tests replace it and HTTP.
type Verifier struct {
	HTTP     *http.Client
	CheckURL func(string) error

	mu   sync.Mutex
	jwks map[string]jwksEntry
}

type jwksEntry struct {
	keys    []map[string]any
	fetched time.Time
}

// NewVerifier returns a Verifier with a 10 s timeout and SSRF guard.
func NewVerifier() *Verifier {
	return &Verifier{HTTP: &http.Client{Timeout: 10 * time.Second}, CheckURL: ssrfguard.ValidateWebhookURL}
}

// Discover fetches issuer/.well-known/openid-configuration and requires the
// document's issuer to be exactly the issuer asked for (OIDC Discovery §4.3).
func (v *Verifier) Discover(ctx context.Context, issuer string) (Discovery, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return Discovery{}, errors.New("oidc issuer is required")
	}
	var d Discovery
	if err := v.getJSON(ctx, issuer+"/.well-known/openid-configuration", &d); err != nil {
		return Discovery{}, fmt.Errorf("oidc discovery: %w", err)
	}
	if strings.TrimRight(d.Issuer, "/") != issuer {
		return Discovery{}, fmt.Errorf("oidc discovery issuer %q does not match %q", d.Issuer, issuer)
	}
	if d.JwksURI == "" {
		return Discovery{}, errors.New("oidc discovery document has no jwks_uri")
	}
	return d, nil
}

// VerifyIDToken checks the token signature against the issuer's JWKS and the
// standard claims, and returns the verified claims. nonce is checked when
// non-empty.
func (v *Verifier) VerifyIDToken(ctx context.Context, raw string, d Discovery, audience, nonce string, now time.Time) (jwt.MapClaims, error) {
	claims, err := v.VerifyJWT(ctx, raw, d.JwksURI, d.Issuer, audience, now)
	if err != nil {
		return nil, err
	}
	if aud, _ := claims.GetAudience(); len(aud) > 1 {
		if azp, _ := claims["azp"].(string); azp != audience {
			return nil, errors.New("id token has several audiences and azp is not this client")
		}
	}
	if nonce != "" {
		if got, _ := claims["nonce"].(string); got != nonce {
			return nil, errors.New("id token nonce does not match this login")
		}
	}
	if sub, _ := claims["sub"].(string); strings.TrimSpace(sub) == "" {
		return nil, errors.New("id token has no subject")
	}
	return claims, nil
}

// VerifyJWT checks a JWT's signature against jwksURI and requires iss to be
// exactly issuer, aud to include audience, and exp to be present and
// unexpired. It is for signed tokens that are not OIDC ID tokens (for
// example Google CSE authorization tokens).
func (v *Verifier) VerifyJWT(ctx context.Context, raw, jwksURI, issuer, audience string, now time.Time) (jwt.MapClaims, error) {
	raw = strings.TrimSpace(raw)
	audience = strings.TrimSpace(audience)
	if raw == "" {
		return nil, errors.New("token is required")
	}
	if audience == "" || issuer == "" || jwksURI == "" {
		return nil, errors.New("issuer, audience and jwks uri are required")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods(signingMethods),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(leeway),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	claims := jwt.MapClaims{}
	if _, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return v.key(ctx, jwksURI, kid, t.Method.Alg())
	}); err != nil {
		return nil, fmt.Errorf("token rejected: %w", err)
	}
	return claims, nil
}

// UnverifiedIssuer reads iss without checking anything, only to pick which
// configured issuer to verify against. Never trust it beyond that.
func UnverifiedIssuer(raw string) (string, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(strings.TrimSpace(raw), claims); err != nil {
		return "", fmt.Errorf("id token is malformed: %w", err)
	}
	iss, _ := claims["iss"].(string)
	if iss == "" {
		return "", errors.New("id token has no issuer")
	}
	return iss, nil
}

// key returns the JWKS key for kid, refetching once when kid is unknown (key
// rotation). A key whose use or alg contradicts the token is refused.
func (v *Verifier) key(ctx context.Context, jwksURI, kid, alg string) (any, error) {
	for attempt := 0; attempt < 2; attempt++ {
		keys, err := v.keys(ctx, jwksURI, attempt > 0)
		if err != nil {
			return nil, err
		}
		var match map[string]any
		for _, k := range keys {
			if use, _ := k["use"].(string); use != "" && use != "sig" {
				continue
			}
			if a, _ := k["alg"].(string); a != "" && a != alg {
				continue
			}
			if id, _ := k["kid"].(string); kid == "" || id == kid {
				if match != nil && kid == "" {
					return nil, errors.New("id token has no kid and the JWKS holds several keys")
				}
				match = k
			}
		}
		if match != nil {
			return restauth.JWKPublicKey(match)
		}
	}
	return nil, fmt.Errorf("no signing key %q in the issuer's JWKS", kid)
}

func (v *Verifier) keys(ctx context.Context, jwksURI string, refresh bool) ([]map[string]any, error) {
	v.mu.Lock()
	e, ok := v.jwks[jwksURI]
	v.mu.Unlock()
	if ok && !refresh && time.Since(e.fetched) < jwksTTL {
		return e.keys, nil
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := v.getJSON(ctx, jwksURI, &doc); err != nil {
		return nil, fmt.Errorf("oidc jwks: %w", err)
	}
	v.mu.Lock()
	if v.jwks == nil {
		v.jwks = map[string]jwksEntry{}
	}
	v.jwks[jwksURI] = jwksEntry{keys: doc.Keys, fetched: time.Now()}
	v.mu.Unlock()
	return doc.Keys, nil
}

func (v *Verifier) getJSON(ctx context.Context, url string, out any) error {
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		return fmt.Errorf("%s is not an https URL", url)
	}
	if v.CheckURL != nil {
		if err := v.CheckURL(url); err != nil {
			return fmt.Errorf("%s blocked: %w", url, err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	client := v.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d", url, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}
