// Package servicetoken provides per-service JWT identities for internal
// service-to-service authentication. Each service derives its own API key from
// a single shared bootstrap secret + its service name (so no per-service secret
// has to be distributed), exchanges it at the auth service's client-credentials
// endpoint for a short-lived signed JWT, and attaches that token as a Bearer
// credential on outbound internal calls. The auth bootstrap pre-registers a
// client + API-key hash for each service using the same derivation.
package servicetoken

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const apiKeyDerivationLabel = "kms-service-api-key:"

// insecureDefaultBootstrapSecret is the placeholder older docker-compose files
// shipped as the fallback value. It is public, so any key derived from it is
// forgeable: it is never accepted, and auth revokes keys derived from it.
const insecureDefaultBootstrapSecret = "vecta-internal-svc-dev-secret-change-me"

// MinBootstrapSecretLen is the minimum accepted secret length (32 chars; the
// installers generate 64 hex chars = 256 bits).
const MinBootstrapSecretLen = 32

var (
	ErrBootstrapSecretUnset   = errors.New("INTERNAL_SERVICE_BOOTSTRAP_SECRET is unset")
	ErrBootstrapSecretDefault = errors.New("INTERNAL_SERVICE_BOOTSTRAP_SECRET is the public default placeholder; generate one with: openssl rand -hex 32")
	ErrBootstrapSecretShort   = errors.New("INTERNAL_SERVICE_BOOTSTRAP_SECRET must be at least 32 characters; generate one with: openssl rand -hex 32")
)

// ValidateBootstrapSecret rejects an unset, publicly known, or short secret.
func ValidateBootstrapSecret(secret string) error {
	secret = strings.TrimSpace(secret)
	switch {
	case secret == "":
		return ErrBootstrapSecretUnset
	case secret == insecureDefaultBootstrapSecret:
		return ErrBootstrapSecretDefault
	case len(secret) < MinBootstrapSecretLen:
		return ErrBootstrapSecretShort
	}
	return nil
}

// DeriveAPIKey deterministically derives a service's raw API key from the shared
// bootstrap secret and the service name. Both the auth bootstrap (to seed the
// key hash) and the service (to present the key) call this. Returns "" when the
// secret fails ValidateBootstrapSecret, which disables service tokens, so a
// weak secret can never yield a usable identity.
func DeriveAPIKey(bootstrapSecret, serviceName string) string {
	if ValidateBootstrapSecret(bootstrapSecret) != nil {
		return ""
	}
	return deriveAPIKey(strings.TrimSpace(bootstrapSecret), serviceName)
}

// InsecureDefaultAPIKey returns the key a service would have derived from the
// old public default secret. Auth uses it only to find and revoke such keys.
func InsecureDefaultAPIKey(serviceName string) string {
	return deriveAPIKey(insecureDefaultBootstrapSecret, serviceName)
}

func deriveAPIKey(bootstrapSecret, serviceName string) string {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(bootstrapSecret))
	mac.Write([]byte(apiKeyDerivationLabel + serviceName))
	return hex.EncodeToString(mac.Sum(nil))
}

// Source mints, caches and refreshes a service JWT for one service identity.
type Source struct {
	authURL  string
	tenantID string
	clientID string // == service name, e.g. "kms-ekm"
	apiKey   string
	client   *http.Client

	mu    sync.Mutex
	token string
	exp   time.Time
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// FromEnv builds a Source for serviceName using INTERNAL_SERVICE_BOOTSTRAP_SECRET
// (shared), AUTH_URL and INTERNAL_SERVICE_TENANT. Returns nil (disabled) when the
// bootstrap secret is unset or fails ValidateBootstrapSecret.
func FromEnv(serviceName string) *Source {
	key := DeriveAPIKey(os.Getenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET"), serviceName)
	if key == "" {
		return nil
	}
	return &Source{
		authURL:  strings.TrimRight(envOr("AUTH_URL", "https://auth:8001"), "/"),
		tenantID: envOr("INTERNAL_SERVICE_TENANT", "root"),
		clientID: serviceName,
		apiKey:   key,
		client:   &http.Client{Timeout: 8 * time.Second},
	}
}

// Token returns a valid cached token, minting a fresh one when none is cached or
// it is within 60s of expiry. A nil/disabled Source returns "" with no error.
func (s *Source) Token(ctx context.Context) (string, error) {
	if s == nil || s.apiKey == "" {
		return "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Until(s.exp) > 60*time.Second {
		return s.token, nil
	}
	body, _ := json.Marshal(map[string]any{
		"tenant_id":   s.tenantID,
		"client_id":   s.clientID,
		"ttl_seconds": 3600,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.authURL+"/auth/client-token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", s.apiKey)
	req.Header.Set("X-Tenant-ID", s.tenantID)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("service token mint failed: status " + resp.Status)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.AccessToken == "" {
		return "", errors.New("service token mint returned empty token")
	}
	s.token = payload.AccessToken
	if exp, perr := time.Parse(time.RFC3339, payload.ExpiresAt); perr == nil {
		s.exp = exp
	} else {
		s.exp = time.Now().Add(50 * time.Minute)
	}
	return s.token, nil
}

// Authorize attaches the service token as a Bearer credential, best-effort: on
// any minting error it leaves the request unauthenticated (so a rollout in
// progress, or an auth blip, never hard-fails the call).
func (s *Source) Authorize(ctx context.Context, req *http.Request) {
	if s == nil {
		return
	}
	if tok, err := s.Token(ctx); err == nil && tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
}

// defaultSource is the process-wide source set once at startup via SetDefault,
// so internal HTTP clients can attach the service token with a single
// package-level Authorize call rather than threading a Source through every
// constructor.
var defaultSource *Source

// SetDefault installs the process default Source. Call once in main with
// FromEnv(serviceName). A nil source disables attachment (no-op Authorize).
func SetDefault(s *Source) { defaultSource = s }

// Authorize attaches the default service token to req, if a default is set.
// Safe to call when no default/secret is configured (no-op), so it can be
// dropped into every internal client unconditionally.
func Authorize(ctx context.Context, req *http.Request) { defaultSource.Authorize(ctx, req) }
