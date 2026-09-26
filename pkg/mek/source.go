package mek

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vecta-kms/pkg/servicetoken"
	"vecta-kms/pkg/tenantcheck"
)

// KeycoreSource gets a service's MEK from keycore with the service's own
// JWT (pkg/servicetoken default source, set in the service's main).
type KeycoreSource struct {
	baseURL string
	purpose string
	tenant  string
	client  *http.Client
}

// NewKeycoreSource returns the source for service (Catalog key) at keycore's
// base URL. The keycore purpose is "<service>-mek".
func NewKeycoreSource(baseURL string, st ServiceTables) *KeycoreSource {
	return &KeycoreSource{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		purpose: st.Service + "-mek",
		tenant:  tenantcheck.InternalServiceTenant(),
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *KeycoreSource) EnsureKey(ctx context.Context) (string, int, error) {
	var out struct {
		KeyID   string `json:"key_id"`
		Version int    `json:"version"`
	}
	if err := s.post(ctx, "/system-keys/ensure", map[string]interface{}{"purpose": s.purpose}, &out); err != nil {
		return "", 0, err
	}
	if out.KeyID == "" || out.Version <= 0 {
		return "", 0, errors.New("keycore returned no system key")
	}
	return out.KeyID, out.Version, nil
}

func (s *KeycoreSource) Derive(ctx context.Context, keyID string, version int) ([]byte, int, error) {
	var out struct {
		Version int    `json:"version"`
		Derived string `json:"derived_key"`
	}
	path := "/keys/" + url.PathEscape(keyID) + "/service-derive?tenant_id=" + url.QueryEscape(s.tenant)
	if err := s.post(ctx, path, map[string]interface{}{"tenant_id": s.tenant, "purpose": s.purpose, "version": version}, &out); err != nil {
		return nil, 0, err
	}
	key, err := base64.StdEncoding.DecodeString(out.Derived)
	if err != nil || len(key) != 32 {
		return nil, 0, errors.New("keycore service-derive returned no 32-byte key")
	}
	return key, out.Version, nil
}

func (s *KeycoreSource) post(ctx context.Context, path string, body interface{}, out interface{}) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	servicetoken.Authorize(ctx, req)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("keycore %s: %d %s %s", path, resp.StatusCode, e.Error.Code, e.Error.Message)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
