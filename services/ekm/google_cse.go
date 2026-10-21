package main

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// GoogleCSEProvider implements the KACLS (Key Access Control List Service) API
// for Google Workspace Client-Side Encryption. Google calls this service to
// wrap/unwrap DEKs used to encrypt Gmail, Drive, Calendar, and Meet data.
type GoogleCSEProvider struct {
	httpClient *http.Client
	logger     *log.Logger

	// Google OIDC public key cache
	googleKeysMu    sync.RWMutex
	googleKeysCache map[string]crypto.PublicKey
	googleKeysTTL   time.Time
}

// GoogleCSEClaims holds validated claims from Google's JWT tokens.
type GoogleCSEClaims struct {
	Email        string      `json:"email"`
	HD           string      `json:"hd"`            // hosted domain
	ResourceName string      `json:"resource_name"` // from authorization JWT
	KeyURI       string      `json:"kacls_url"`     // KACLS key URI from authorization JWT
	Issuer       string      `json:"iss"`
	Subject      string      `json:"sub"`
	Audience     jwtAudience `json:"aud"`
	ExpiresAt    int64       `json:"exp"`
	IssuedAt     int64       `json:"iat"`
}

// jwtAudience is a JWT "aud" claim, which may be one string or a list.
type jwtAudience []string

func (a *jwtAudience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = jwtAudience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("aud must be a string or a list of strings")
	}
	*a = many
	return nil
}

// googleJWKSResponse represents Google's JWKS endpoint response.
type googleJWKSResponse struct {
	Keys []googleJWK `json:"keys"`
}

type googleJWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func NewGoogleCSEProvider(logger *log.Logger) *GoogleCSEProvider {
	if logger == nil {
		logger = log.Default()
	}
	return &GoogleCSEProvider{
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		logger:          logger,
		googleKeysCache: make(map[string]crypto.PublicKey),
	}
}

// fetchGooglePublicKeys retrieves Google's OIDC public keys from the JWKS endpoint.
// Keys are cached for 1 hour to reduce API calls.
func (p *GoogleCSEProvider) fetchGooglePublicKeys() (map[string]crypto.PublicKey, error) {
	p.googleKeysMu.RLock()
	if time.Now().Before(p.googleKeysTTL) && len(p.googleKeysCache) > 0 {
		keys := p.googleKeysCache
		p.googleKeysMu.RUnlock()
		return keys, nil
	}
	p.googleKeysMu.RUnlock()

	p.googleKeysMu.Lock()
	defer p.googleKeysMu.Unlock()

	// Double-check after acquiring write lock
	if time.Now().Before(p.googleKeysTTL) && len(p.googleKeysCache) > 0 {
		return p.googleKeysCache, nil
	}

	resp, err := p.httpClient.Get("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		return nil, fmt.Errorf("google cse: fetch JWKS: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("google cse: read JWKS body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google cse: JWKS returned HTTP %d", resp.StatusCode)
	}

	var jwks googleJWKSResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("google cse: decode JWKS: %w", err)
	}

	keys := make(map[string]crypto.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, jwkErr := pkgcrypto.RSAPublicKeyFromJWK(k.N, k.E)
		if jwkErr != nil {
			continue
		}
		keys[k.Kid] = pub
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("google cse: no RSA keys in JWKS response")
	}

	p.googleKeysCache = keys
	p.googleKeysTTL = time.Now().Add(1 * time.Hour)
	p.logger.Printf("[google-cse] refreshed %d OIDC public keys from Google", len(keys))
	return keys, nil
}

// ValidateGoogleJWT validates a CSE authentication token: a Google ID token
// signed with Google's OIDC keys, unexpired, issued to one of the config's
// OAuth client IDs (aud) for a user whose hosted domain (hd) the config
// allows. A config with no client IDs or no domains admits nobody.
func (p *GoogleCSEProvider) ValidateGoogleJWT(tokenString string, allowedDomains, clientIDs []string) (*GoogleCSEClaims, error) {
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return nil, fmt.Errorf("google cse: empty JWT token")
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("google cse: invalid JWT format")
	}

	// Decode header to get kid
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("google cse: decode JWT header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("google cse: parse JWT header: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("google cse: unsupported JWT algorithm: %s", header.Alg)
	}

	// Fetch Google's public keys
	publicKeys, err := p.fetchGooglePublicKeys()
	if err != nil {
		return nil, err
	}

	pubKey, ok := publicKeys[header.Kid]
	if !ok {
		return nil, fmt.Errorf("google cse: unknown key ID: %s", header.Kid)
	}

	// Verify RS256 signature
	signedContent := parts[0] + "." + parts[1]
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("google cse: decode JWT signature: %w", err)
	}

	if !pkgcrypto.VerifySignatureAny(pubKey, []byte(signedContent), signatureBytes) {
		return nil, fmt.Errorf("google cse: JWT signature verification failed")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("google cse: decode JWT payload: %w", err)
	}

	var claims GoogleCSEClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("google cse: parse JWT claims: %w", err)
	}

	// Verify issuer
	if claims.Issuer != "accounts.google.com" && claims.Issuer != "https://accounts.google.com" {
		return nil, fmt.Errorf("google cse: invalid JWT issuer: %s", claims.Issuer)
	}

	// Verify expiry with 60s leeway
	now := time.Now().Unix()
	if claims.ExpiresAt <= 0 {
		return nil, fmt.Errorf("google cse: JWT has no expiry")
	}
	if now > claims.ExpiresAt+60 {
		return nil, fmt.Errorf("google cse: JWT expired at %d, now %d", claims.ExpiresAt, now)
	}
	if claims.IssuedAt > 0 && now < claims.IssuedAt-60 {
		return nil, fmt.Errorf("google cse: JWT issued in the future: iat=%d, now=%d", claims.IssuedAt, now)
	}

	// The token must have been issued to the customer's CSE client: an ID
	// token Google minted for any other application is not an
	// authentication for this KACLS.
	if len(clientIDs) == 0 {
		return nil, fmt.Errorf("google cse: config lists no authentication client IDs")
	}
	audienceAllowed := false
	for _, aud := range claims.Audience {
		for _, id := range clientIDs {
			if aud != "" && aud == strings.TrimSpace(id) {
				audienceAllowed = true
			}
		}
	}
	if !audienceAllowed {
		return nil, fmt.Errorf("google cse: token audience %v is not a configured client ID", []string(claims.Audience))
	}

	// The user's hosted domain must be one the config allows; a config that
	// names none, or a token without hd (a consumer account), is refused.
	if len(allowedDomains) == 0 {
		return nil, fmt.Errorf("google cse: config lists no allowed domains")
	}
	if strings.TrimSpace(claims.HD) == "" {
		return nil, fmt.Errorf("google cse: token has no hosted domain")
	}
	{
		domainAllowed := false
		for _, d := range allowedDomains {
			if strings.EqualFold(strings.TrimSpace(d), strings.TrimSpace(claims.HD)) {
				domainAllowed = true
				break
			}
		}
		if !domainAllowed {
			return nil, fmt.Errorf("google cse: domain %q not in allowed domains", claims.HD)
		}
	}

	return &claims, nil
}

// WrapDEK wraps a DEK (Data Encryption Key) using the Vecta KMS key via KeyCore.
func (p *GoogleCSEProvider) WrapDEK(ctx context.Context, vectaKeyID string, dek []byte, keycore KeyCoreClient, tenantID string) ([]byte, error) {
	if len(dek) == 0 {
		return nil, fmt.Errorf("google cse: empty DEK")
	}

	dekB64 := base64.StdEncoding.EncodeToString(dek)
	result, err := keycore.Wrap(ctx, tenantID, vectaKeyID, dekB64, "", "google-cse")
	if err != nil {
		return nil, fmt.Errorf("google cse: keycore wrap failed: %w", err)
	}

	ciphertextB64, ok := result["ciphertext"].(string)
	if !ok || ciphertextB64 == "" {
		return nil, fmt.Errorf("google cse: keycore wrap returned no ciphertext")
	}

	wrappedBytes, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("google cse: decode wrapped DEK: %w", err)
	}

	return wrappedBytes, nil
}

// UnwrapDEK unwraps a wrapped DEK using the Vecta KMS key via KeyCore.
func (p *GoogleCSEProvider) UnwrapDEK(ctx context.Context, vectaKeyID string, wrappedDEK []byte, keycore KeyCoreClient, tenantID string) ([]byte, error) {
	if len(wrappedDEK) == 0 {
		return nil, fmt.Errorf("google cse: empty wrapped DEK")
	}

	wrappedB64 := base64.StdEncoding.EncodeToString(wrappedDEK)
	result, err := keycore.Unwrap(ctx, tenantID, vectaKeyID, wrappedB64, "")
	if err != nil {
		return nil, fmt.Errorf("google cse: keycore unwrap failed: %w", err)
	}

	plaintextB64, ok := result["plaintext"].(string)
	if !ok || plaintextB64 == "" {
		return nil, fmt.Errorf("google cse: keycore unwrap returned no plaintext")
	}

	dekBytes, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("google cse: decode unwrapped DEK: %w", err)
	}

	return dekBytes, nil
}

// ValidatePrivilegedAccess checks that the reason for privileged unwrap is valid.
func (p *GoogleCSEProvider) ValidatePrivilegedAccess(reason string) error {
	reason = strings.TrimSpace(strings.ToUpper(reason))
	if reason != "ADMIN_ACCESS" && reason != "LEGAL_HOLD" {
		return fmt.Errorf("google cse: privileged unwrap reason must be ADMIN_ACCESS or LEGAL_HOLD, got %q", reason)
	}
	return nil
}
