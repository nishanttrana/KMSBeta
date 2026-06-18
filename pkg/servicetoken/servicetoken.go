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

// DeriveAPIKey deterministically derives a service's raw API key from the shared
// bootstrap secret and the service name. Both the auth bootstrap (to seed the
// key hash) and the service (to present the key) call this. Returns "" when the
// secret is unset, which disables service tokens (callers stay tokenless).
func DeriveAPIKey(bootstrapSecret, serviceName string) string {
	bootstrapSecret = strings.TrimSpace(bootstrapSecret)
	serviceName = strings.TrimSpace(serviceName)
	if bootstrapSecret == "" || serviceName == "" {
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
// bootstrap secret is unset, so deployments without it keep working tokenless.
func FromEnv(serviceName string) *Source {
	key := DeriveAPIKey(os.Getenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET"), serviceName)
	if key == "" {
		return nil
	}
	return &Source{
		authURL:  strings.TrimRight(envOr("AUTH_URL", "http://auth:8001"), "/"),
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
