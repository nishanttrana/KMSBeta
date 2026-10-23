// Package vecta is the Go client for Vecta KMS: keys, cryptographic
// operations and secrets over the KMS REST API.
//
// It authenticates as a REST client: the client ID and API key an
// administrator issued (Workbench → REST API), exchanged for short-lived
// tokens it renews itself. To use keys the client needs a role with key
// permissions and a key access assignment for the client
// (docs/CI_CD_AUTOMATION.md, "A role for a client").
//
//	c, err := vecta.New(vecta.Config{
//		BaseURL: "https://kms.example.com", TenantID: "acme",
//		ClientID: os.Getenv("KMS_CLIENT_ID"), APIKey: os.Getenv("KMS_API_KEY"),
//	})
//	ct, err := c.Encrypt(ctx, "key_123", []byte("secret"), nil)
package vecta

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config says where the KMS is and who the client is.
type Config struct {
	// BaseURL is the KMS edge, https://<host>; the service paths
	// (/svc/keycore/..., /svc/auth/...) are appended.
	BaseURL  string
	TenantID string
	// ClientID and APIKey are the REST client's credentials; the client
	// exchanges them for tokens and renews them before they expire.
	ClientID string
	APIKey   string
	// Token is a bearer token to use as is, instead of ClientID/APIKey.
	Token string
	// CAPEM is the PEM bundle of the KMS certificate's CA, when it is the
	// KMS's own; empty uses the system roots.
	CAPEM []byte
	// TokenTTL is how long each token is asked for (60s to 1h; default 5m).
	TokenTTL time.Duration
	// HTTPClient replaces the default client (TLS 1.3, 30s timeout); its
	// transport must keep TLS verification on.
	HTTPClient *http.Client
}

// Client calls the KMS. It is safe for concurrent use.
type Client struct {
	base   string
	tenant string
	cfg    Config
	http   *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// New checks the configuration and builds a client.
func New(cfg Config) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("vecta: BaseURL is https://<host>")
	}
	if strings.TrimSpace(cfg.TenantID) == "" {
		return nil, errors.New("vecta: TenantID is required")
	}
	if cfg.Token == "" && (cfg.ClientID == "" || cfg.APIKey == "") {
		return nil, errors.New("vecta: set ClientID and APIKey, or Token")
	}
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = 5 * time.Minute
	}
	if cfg.TokenTTL < time.Minute || cfg.TokenTTL > time.Hour {
		return nil, errors.New("vecta: TokenTTL is between 1 minute and 1 hour")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
		if len(cfg.CAPEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CAPEM) {
				return nil, errors.New("vecta: no certificate in CAPEM")
			}
			tlsCfg.RootCAs = pool
		}
		hc = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	}
	return &Client{base: base, tenant: strings.TrimSpace(cfg.TenantID), cfg: cfg, http: hc, token: cfg.Token}, nil
}

// APIError is the KMS's answer to a refused or failed call. Code is the
// KMS's reason (for example no_matching_grant, binding_policy,
// metadata_profile_violation); every refusal is also in the KMS audit log
// under RequestID.
type APIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("vecta: %d %s: %s (request %s)", e.Status, e.Code, e.Message, e.RequestID)
}

// IsRefused reports whether err is the KMS refusing the call (401 or 403).
func IsRefused(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden)
}

// IsNotFound reports whether the KMS answered 404: the object doesn't exist,
// or the caller may not see it.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// bearer returns a token, exchanging the API key when the last one is
// within 30 seconds of expiring.
func (c *Client) bearer(ctx context.Context, renew bool) (string, error) {
	if c.cfg.Token != "" {
		return c.cfg.Token, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !renew && c.token != "" && time.Until(c.expires) > 30*time.Second {
		return c.token, nil
	}
	body, _ := json.Marshal(map[string]any{"tenant_id": c.tenant, "client_id": c.cfg.ClientID, "ttl_seconds": int(c.cfg.TokenTTL / time.Second)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/svc/auth/auth/client-token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.cfg.APIKey)
	var out struct {
		AccessToken string    `json:"access_token"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	if err := c.send(req, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", errors.New("vecta: the KMS issued no token")
	}
	c.token, c.expires = out.AccessToken, out.ExpiresAt
	return c.token, nil
}

// call sends one request to a KMS service. A 401 renews the token once.
func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	var raw []byte
	if in != nil {
		var err error
		if raw, err = json.Marshal(in); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		token, err := c.bearer(ctx, attempt > 0)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Tenant-ID", c.tenant)
		err = c.send(req, out)
		var ae *APIError
		if attempt == 0 && c.cfg.Token == "" && errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
			continue
		}
		return err
	}
}

func (c *Client) send(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code      string `json:"code"`
				Message   string `json:"message"`
				RequestID string `json:"request_id"`
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error.Message == "" {
			e.Error.Message = strings.TrimSpace(string(data))
		}
		return &APIError{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message, RequestID: e.Error.RequestID}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// query is the tenant query every path carries.
func (c *Client) query(extra url.Values) string {
	v := url.Values{"tenant_id": {c.tenant}}
	for k, vals := range extra {
		v[k] = vals
	}
	return "?" + v.Encode()
}
