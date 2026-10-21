// Package kmsplugin is the Kubernetes KMS v2 plugin's key service: it
// implements k8s.io/kms/pkg/service.Service against keycore, so
// kube-apiserver's data encryption keys (which it generates itself) are
// wrapped by a Vecta AES-256 key that never leaves the KMS.
//
// The plugin runs on each control-plane node (services/k8s-kms-plugin) and
// calls keycore through the HTTPS edge as an API client, so every wrap and
// unwrap is decided by the key's access rules and audited by keycore.
//
// Wire format, per KMS v2: Encrypt returns iv(12) || AES-GCM ciphertext and
// a key_id of "<key id>:v<version>". kube-apiserver re-encrypts its DEK seed
// when the key_id Status reports changes, so rotating the Vecta key rotates
// the cluster's wrapping; Decrypt reads the version back from the key_id it
// stored. The AAD binds the ciphertext to the key ID.
package kmsplugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/kms/pkg/service"
)

const ivSize = 12

// Config names the key and where keycore is.
type Config struct {
	// Server is the KMS edge, e.g. https://kms.example.com.
	Server   string
	TenantID string
	KeyID    string
}

// Authorizer adds the caller's credential to a request (pkg/agentauth).
type Authorizer func(*http.Request) error

// Service is the plugin's KMS v2 key service.
type Service struct {
	cfg  Config
	http *http.Client
	auth Authorizer

	mu       sync.Mutex
	status   *service.StatusResponse
	statusAt time.Time
}

var _ service.Service = (*Service)(nil)

// New returns the service. client carries the edge's trust (its CA).
func New(cfg Config, client *http.Client, auth Authorizer) (*Service, error) {
	cfg.Server = strings.TrimRight(strings.TrimSpace(cfg.Server), "/")
	if cfg.Server == "" || cfg.TenantID == "" || cfg.KeyID == "" {
		return nil, errors.New("kmsplugin: server, tenant_id and key_id are required")
	}
	if !strings.HasPrefix(cfg.Server, "https://") {
		return nil, errors.New("kmsplugin: server must be https")
	}
	return &Service{cfg: cfg, http: client, auth: auth}, nil
}

// statusCache bounds keycore reads: kube-apiserver asks for Status about
// once a minute per server, and its health checks more often.
var statusCache = 10 * time.Second

// Status reports health and the key_id new encryptions will carry.
func (s *Service) Status(ctx context.Context) (*service.StatusResponse, error) {
	s.mu.Lock()
	if s.status != nil && time.Since(s.statusAt) < statusCache {
		out := *s.status
		s.mu.Unlock()
		return &out, nil
	}
	s.mu.Unlock()
	var resp struct {
		Key struct {
			Status         string `json:"status"`
			CurrentVersion int    `json:"current_version"`
			Algorithm      string `json:"algorithm"`
		} `json:"key"`
	}
	if err := s.call(ctx, http.MethodGet, "/svc/keycore/keys/"+url.PathEscape(s.cfg.KeyID), nil, &resp); err != nil {
		return nil, err
	}
	healthz := "ok"
	if !strings.EqualFold(resp.Key.Status, "active") {
		healthz = "key is " + resp.Key.Status
	}
	if resp.Key.CurrentVersion < 1 {
		return nil, errors.New("kmsplugin: keycore reported no current key version")
	}
	out := &service.StatusResponse{Version: "v2", Healthz: healthz, KeyID: s.keyIDFor(resp.Key.CurrentVersion)}
	s.mu.Lock()
	s.status, s.statusAt = out, time.Now()
	s.mu.Unlock()
	cp := *out
	return &cp, nil
}

func (s *Service) keyIDFor(version int) string { return s.cfg.KeyID + ":v" + strconv.Itoa(version) }

// versionOf parses a key_id this plugin issued.
func (s *Service) versionOf(keyID string) (int, error) {
	id, v, ok := strings.Cut(keyID, ":v")
	n, err := strconv.Atoi(v)
	if !ok || id != s.cfg.KeyID || err != nil || n < 1 {
		return 0, fmt.Errorf("kmsplugin: key_id %q was not issued for key %s", keyID, s.cfg.KeyID)
	}
	return n, nil
}

func (s *Service) aad() string {
	return base64.StdEncoding.EncodeToString([]byte("vecta-k8s-kms-v2:" + s.cfg.TenantID + ":" + s.cfg.KeyID))
}

// Encrypt wraps the DEK seed kube-apiserver generated.
func (s *Service) Encrypt(ctx context.Context, uid string, data []byte) (*service.EncryptResponse, error) {
	var resp struct {
		Ciphertext string `json:"ciphertext"`
		IV         string `json:"iv"`
		Version    int    `json:"version"`
	}
	body := map[string]interface{}{
		"tenant_id": s.cfg.TenantID, "plaintext": base64.StdEncoding.EncodeToString(data),
		"aad": s.aad(), "iv_mode": "internal", "reference_id": uid,
	}
	if err := s.call(ctx, http.MethodPost, "/svc/keycore/keys/"+url.PathEscape(s.cfg.KeyID)+"/encrypt", body, &resp); err != nil {
		return nil, err
	}
	ct, err1 := base64.StdEncoding.DecodeString(resp.Ciphertext)
	iv, err2 := base64.StdEncoding.DecodeString(resp.IV)
	if err1 != nil || err2 != nil || len(iv) != ivSize || resp.Version < 1 || len(ct) <= 16 {
		return nil, errors.New("kmsplugin: keycore returned an unexpected AES-GCM output")
	}
	return &service.EncryptResponse{Ciphertext: append(iv, ct...), KeyID: s.keyIDFor(resp.Version)}, nil
}

// Decrypt unwraps with the key version the key_id names.
func (s *Service) Decrypt(ctx context.Context, uid string, req *service.DecryptRequest) ([]byte, error) {
	version, err := s.versionOf(req.KeyID)
	if err != nil {
		return nil, err
	}
	if len(req.Ciphertext) <= ivSize+16 {
		return nil, errors.New("kmsplugin: ciphertext too short")
	}
	var resp struct {
		Plaintext string `json:"plaintext"`
	}
	body := map[string]interface{}{
		"tenant_id": s.cfg.TenantID, "ciphertext": base64.StdEncoding.EncodeToString(req.Ciphertext[ivSize:]),
		"iv": base64.StdEncoding.EncodeToString(req.Ciphertext[:ivSize]), "aad": s.aad(), "version": version, "reference_id": uid,
	}
	if err := s.call(ctx, http.MethodPost, "/svc/keycore/keys/"+url.PathEscape(s.cfg.KeyID)+"/decrypt", body, &resp); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Plaintext)
}

// keycoreError is keycore's refusal, with its status.
type keycoreError struct {
	Status int
	Code   string
	Msg    string
}

func (e keycoreError) Error() string {
	return fmt.Sprintf("kmsplugin: keycore answered %d %s: %s", e.Status, e.Code, e.Msg)
}

func (s *Service) call(ctx context.Context, method, path string, in, out interface{}) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	req, err := http.NewRequestWithContext(ctx, method, s.cfg.Server+path+sep+"tenant_id="+url.QueryEscape(s.cfg.TenantID), body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", s.cfg.TenantID)
	if s.auth != nil {
		if err := s.auth(req); err != nil {
			return fmt.Errorf("kmsplugin: authenticate: %w", err)
		}
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("kmsplugin: keycore: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		return keycoreError{Status: resp.StatusCode, Code: e.Error.Code, Msg: e.Error.Message}
	}
	return json.Unmarshal(raw, out)
}
