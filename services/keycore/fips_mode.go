package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type FIPSModeProvider interface {
	IsEnabled(ctx context.Context, tenantID string) (bool, error)
}

type staticFIPSModeProvider struct {
	enabled bool
}

func (p staticFIPSModeProvider) IsEnabled(_ context.Context, _ string) (bool, error) {
	return p.enabled, nil
}

type fipsCacheEntry struct {
	enabled bool
	expiry  time.Time
}

type HTTPFIPSModeProvider struct {
	baseURL  string
	client   *http.Client
	cacheTTL time.Duration
	mu       sync.RWMutex
	cache    map[string]fipsCacheEntry
}

func NewHTTPFIPSModeProvider(baseURL string, timeout time.Duration, cacheTTL time.Duration) *HTTPFIPSModeProvider {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if cacheTTL <= 0 {
		cacheTTL = 5 * time.Second
	}
	return &HTTPFIPSModeProvider{
		baseURL:  strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:   &http.Client{Timeout: timeout},
		cacheTTL: cacheTTL,
		cache:    map[string]fipsCacheEntry{},
	}
}

func (p *HTTPFIPSModeProvider) IsEnabled(ctx context.Context, tenantID string) (bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return false, errors.New("tenant_id is required for fips mode check")
	}

	now := time.Now().UTC()
	p.mu.RLock()
	cached, ok := p.cache[tenantID]
	p.mu.RUnlock()
	if ok && now.Before(cached.expiry) {
		return cached.enabled, nil
	}

	enabled, err := p.fetch(ctx, tenantID)
	if err != nil {
		if ok {
			// Fallback to last-known value on transient read failure.
			return cached.enabled, nil
		}
		// Fail open to standard mode when governance is unreachable.
		return false, nil
	}

	p.mu.Lock()
	p.cache[tenantID] = fipsCacheEntry{
		enabled: enabled,
		expiry:  now.Add(p.cacheTTL),
	}
	p.mu.Unlock()
	return enabled, nil
}

func (p *HTTPFIPSModeProvider) fetch(ctx context.Context, tenantID string) (bool, error) {
	if strings.TrimSpace(p.baseURL) == "" {
		return false, errors.New("governance base url is empty")
	}
	endpoint := fmt.Sprintf("%s/governance/system/state?tenant_id=%s", p.baseURL, url.QueryEscape(tenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Tenant-ID", tenantID)

	resp, err := p.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var payload struct {
		State struct {
			FIPSMode string `json:"fips_mode"`
		} `json:"state"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		msg := strings.TrimSpace(payload.Error.Message)
		if msg == "" {
			msg = "governance fips mode request failed"
		}
		return false, errors.New(msg)
	}
	return isFIPSModeEnabledValue(payload.State.FIPSMode), nil
}

func isFIPSModeEnabledValue(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "enabled", "strict", "fips", "true", "on":
		return true
	default:
		return false
	}
}

func isFIPSApprovedKeyAlgorithm(algorithm string) bool {
	v := strings.ToUpper(strings.TrimSpace(algorithm))
	if v == "" {
		return false
	}
	if strings.Contains(v, "CHACHA20") ||
		strings.Contains(v, "CAMELLIA") ||
		strings.Contains(v, "ECIES") ||
		strings.Contains(v, "BRAINPOOL") ||
		strings.Contains(v, "KECCAK") ||
		strings.Contains(v, "RIPEMD") ||
		strings.Contains(v, "BLAKE") ||
		strings.Contains(v, "POLY1305") ||
		(strings.Contains(v, "AES") && strings.Contains(v, "ECB")) {
		return false
	}
	switch {
	case strings.Contains(v, "AES"):
		return true
	case strings.Contains(v, "RSA"):
		return true
	case strings.Contains(v, "ECDSA"):
		return true
	case strings.Contains(v, "ECDH"):
		return true
	case strings.Contains(v, "HMAC"):
		return true
	case strings.Contains(v, "CMAC"):
		return true
	case strings.Contains(v, "GMAC"):
		return true
	case strings.Contains(v, "ML-KEM"):
		return true
	case strings.Contains(v, "ML-DSA"):
		return true
	case strings.Contains(v, "SLH-DSA"):
		return true
	default:
		return false
	}
}

func isFIPSApprovedHashAlgorithm(algorithm string) bool {
	switch normalizeDigestAlgorithm(algorithm) {
	case "sha-256", "sha-384", "sha-512", "sha3-256", "sha3-384", "sha3-512":
		return true
	default:
		return false
	}
}

func isFIPSApprovedRandomSource(source string) bool {
	switch normalizeRandomSource(source) {
	case "kms-csprng", "hsm-trng":
		return true
	default:
		return false
	}
}

type fipsModeViolationError struct {
	Operation string
	Algorithm string
}

func (e fipsModeViolationError) Error() string {
	op := strings.TrimSpace(e.Operation)
	if op == "" {
		op = "operation"
	}
	alg := strings.TrimSpace(e.Algorithm)
	if alg == "" {
		alg = "selected algorithm"
	}
	return fmt.Sprintf("%s blocked: %s is not allowed while FIPS mode is enabled", op, alg)
}

func (s *Service) SetFIPSModeProvider(provider FIPSModeProvider) {
	if provider == nil {
		provider = staticFIPSModeProvider{enabled: false}
	}
	s.fipsMode = provider
}

func (s *Service) isFIPSEnabled(ctx context.Context, tenantID string) (bool, error) {
	if s.fipsMode == nil {
		return false, nil
	}
	return s.fipsMode.IsEnabled(ctx, tenantID)
}

func (s *Service) enforceFIPSKeyAlgorithm(ctx context.Context, tenantID string, algorithm string, operation string) error {
	enabled, err := s.isFIPSEnabled(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("fips mode check failed: %w", err)
	}
	if !enabled {
		return nil
	}
	if isFIPSApprovedKeyAlgorithm(algorithm) {
		return nil
	}
	return fipsModeViolationError{
		Operation: operation,
		Algorithm: strings.TrimSpace(algorithm),
	}
}

func (s *Service) enforceFIPSHashAlgorithm(ctx context.Context, tenantID string, algorithm string) error {
	enabled, err := s.isFIPSEnabled(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("fips mode check failed: %w", err)
	}
	if !enabled {
		return nil
	}
	if isFIPSApprovedHashAlgorithm(algorithm) {
		return nil
	}
	return fipsModeViolationError{
		Operation: "crypto.hash",
		Algorithm: strings.TrimSpace(algorithm),
	}
}

func (s *Service) enforceFIPSRandomSource(ctx context.Context, tenantID string, source string) error {
	enabled, err := s.isFIPSEnabled(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("fips mode check failed: %w", err)
	}
	if !enabled {
		return nil
	}
	if isFIPSApprovedRandomSource(source) {
		return nil
	}
	return fipsModeViolationError{
		Operation: "crypto.random",
		Algorithm: strings.TrimSpace(source),
	}
}
