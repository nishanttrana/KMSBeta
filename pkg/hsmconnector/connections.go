package hsmconnector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"vecta-kms/pkg/servicetoken"
)

// An HSM credential (Playbooks → Credentials, type pkcs11_hsm) is an HSM that
// holds keys, apart from the tenant's HSM profile, which is the KMS's root
// of trust. A tenant may add several, and each key records the one it was
// created on. The connector opens the credential from compliance as the
// kms-hsm identity for every session it starts: the PIN is sealed there, and
// held here only in memory, as a profile's PIN is.

var (
	// ErrConnectionNotFound is an HSM credential that doesn't exist in the
	// tenant, or is not a PKCS#11 HSM credential.
	ErrConnectionNotFound = errors.New("no such HSM credential for this tenant")
	// errConnectionsUnavailable: the credential store can't be reached, or
	// this connector has none.
	errConnectionsUnavailable = errors.New("HSM credentials are unavailable")
	// errPINMismatch: another configuration is logged in to the same token
	// with a different PIN.
	errPINMismatch = errors.New("this token is in use with a different PIN: a second credential or profile for the same slot must carry the same PIN")
)

// ConnectionSource resolves an HSM credential to a session configuration.
type ConnectionSource interface {
	LoadConnection(ctx context.Context, tenant, connectionID string) (TenantConfig, error)
}

// Credentials opens HSM credentials from the compliance service.
type Credentials struct {
	BaseURL string
	HTTP    *http.Client

	mu    sync.Mutex
	cache map[string]cachedConfig
}

// CredentialsFromEnv reads COMPLIANCE_URL (default https://compliance:8110,
// internal mTLS).
func CredentialsFromEnv() *Credentials {
	base := strings.TrimSpace(os.Getenv("COMPLIANCE_URL"))
	if base == "" {
		base = "https://compliance:8110"
	}
	return &Credentials{BaseURL: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: 10 * time.Second}}
}

// LoadConnection opens the credential, cached as briefly as a profile.
func (s *Credentials) LoadConnection(ctx context.Context, tenant, id string) (TenantConfig, error) {
	key := tenant + "\x00" + id
	s.mu.Lock()
	if c, ok := s.cache[key]; ok && time.Since(c.at) < configTTL {
		s.mu.Unlock()
		return c.cfg, c.err
	}
	s.mu.Unlock()
	cfg, err := s.resolve(ctx, tenant, id)
	// Only a definite answer is cached: an outage must not outlive itself.
	if err == nil || errors.Is(err, ErrConnectionNotFound) {
		s.mu.Lock()
		if s.cache == nil {
			s.cache = map[string]cachedConfig{}
		}
		s.cache[key] = cachedConfig{cfg: cfg, err: err, at: time.Now()}
		s.mu.Unlock()
	}
	return cfg, err
}

func (s *Credentials) resolve(ctx context.Context, tenant, id string) (TenantConfig, error) {
	cfg := TenantConfig{TenantID: tenant, ConnectionID: id}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.BaseURL+"/compliance/connections/"+url.PathEscape(id)+"/resolve?tenant_id="+url.QueryEscape(tenant), bytes.NewReader([]byte("{}")))
	if err != nil {
		return cfg, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenant)
	servicetoken.Authorize(ctx, req)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return cfg, fmt.Errorf("%w: the credential store is unreachable", errConnectionsUnavailable)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusConflict:
		// 409: the credential exists but is not a PKCS#11 HSM.
		return cfg, ErrConnectionNotFound
	case resp.StatusCode >= 300:
		return cfg, fmt.Errorf("%w: the credential store answered HTTP %d", errConnectionsUnavailable, resp.StatusCode)
	}
	var out struct {
		Data struct {
			Type   string            `json:"type"`
			Fields map[string]string `json:"fields"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Data.Type != "pkcs11_hsm" {
		return cfg, ErrConnectionNotFound
	}
	return FromCredential(tenant, id, out.Data.Fields)
}

// FromCredential builds the session configuration from a pkcs11_hsm
// credential's fields. The library is confined exactly as a profile's is.
func FromCredential(tenant, id string, f map[string]string) (TenantConfig, error) {
	cfg := TenantConfig{
		TenantID: tenant, ConnectionID: id, Provider: firstNonEmpty(strings.TrimSpace(f["vendor"]), "pkcs11"),
		SlotID: strings.TrimSpace(f["slot_id"]), TokenLabel: strings.TrimSpace(f["token_label"]), PIN: f["pin"],
	}
	lib, err := checkLibrary(f["library_path"])
	if err != nil {
		return cfg, err
	}
	cfg.Library = lib
	if cfg.PIN == "" {
		return cfg, errPINMissing
	}
	return cfg, nil
}
