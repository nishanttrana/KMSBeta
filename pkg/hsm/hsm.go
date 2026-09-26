// Package hsm is the platform's client for the hsm-connector service, the
// only process that loads a customer's PKCS#11 library and holds the HSM
// PIN (docs/SECURITY/HSM_INTEGRATION.md).
//
// Two uses, both per tenant:
//   - tenant key: each tenant with "tenant key in HSM" on gets an AES-256 key
//     generated inside its HSM (never extractable). New key versions of that
//     tenant have their data key encrypted by it (AES-GCM in the HSM).
//   - HSM-resident keys: a key created with "create in HSM" is generated in
//     the HSM and never leaves it; keycore sends encrypt, decrypt, sign and
//     verify to the HSM.
//
// Every object the platform creates is labelled vecta:<tenant>:..., and the
// connector refuses a label outside the caller's tenant, so tenants sharing a
// partition can't reach each other's keys.
package hsm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"vecta-kms/pkg/servicetoken"
)

// Algorithms an HSM-resident key can have. Each maps to a PKCS#11 mechanism
// on the FIPS approved list (AES-GCM, RSA-PSS, ECDSA P-256/P-384).
var Algorithms = map[string]bool{
	"AES-128": true, "AES-192": true, "AES-256": true,
	"RSA-2048": true, "RSA-3072": true, "RSA-4096": true,
	"ECDSA-P256": true, "ECDSA-P384": true,
}

// NormalizeAlgorithm maps a keycore algorithm name to the HSM form
// ("AES-256-GCM" → "AES-256", "ECDSA-P384" → "ECDSA-P384"), or "" when the
// algorithm can't be HSM-resident. It matches names the way keycore does.
func NormalizeAlgorithm(alg string) string {
	a := strings.ToUpper(strings.TrimSpace(alg))
	pick := func(sizes []string, def string) string {
		for _, s := range sizes {
			if strings.Contains(a, s) {
				return s
			}
		}
		return def
	}
	switch {
	case strings.Contains(a, "BRAINPOOL"), strings.Contains(a, "ECDH"), strings.Contains(a, "OAEP"),
		strings.Contains(a, "521"), strings.Contains(a, "8192"):
		return ""
	case strings.HasPrefix(a, "AES"):
		for _, mode := range []string{"CBC", "CTR", "ECB", "CCM", "CFB", "OFB", "XTS", "SIV", "KW"} {
			if strings.Contains(a, mode) {
				return "" // the HSM runs AES-GCM only
			}
		}
		return "AES-" + pick([]string{"128", "192", "256"}, "256")
	case strings.Contains(a, "RSA"):
		return "RSA-" + pick([]string{"3072", "4096", "2048"}, "2048")
	case strings.Contains(a, "ECDSA"):
		if strings.Contains(a, "384") {
			return "ECDSA-P384"
		}
		return "ECDSA-P256"
	}
	return ""
}

var tenantRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// TenantPrefix is the label prefix every object of tenant carries.
func TenantPrefix(tenant string) string { return "vecta:" + tenant + ":" }

// TenantKeyLabel names a tenant's key in its HSM.
func TenantKeyLabel(tenant string) string { return TenantPrefix(tenant) + "tenant-key" }

// KeyLabel names an HSM-resident key version.
func KeyLabel(tenant, keyID string, version int) string {
	return fmt.Sprintf("%skey:%s:v%d", TenantPrefix(tenant), keyID, version)
}

// CheckLabel refuses a label that isn't one of tenant's objects.
func CheckLabel(tenant, label string) error {
	if !tenantRE.MatchString(tenant) {
		return errors.New("invalid tenant_id")
	}
	if !strings.HasPrefix(label, TenantPrefix(tenant)) || len(label) > 255 || strings.ContainsAny(label, "\x00\n") {
		return ErrForeignLabel
	}
	return nil
}

// Errors the connector returns, by error code.
var (
	ErrNotConfigured = errors.New("hsm: no HSM is configured and enabled for this tenant")
	ErrUnavailable   = errors.New("hsm: the HSM connector is unavailable")
	ErrForeignLabel  = errors.New("hsm: the object label is outside the caller's tenant")
	ErrNotFound      = errors.New("hsm: object not found in the HSM")
)

// GenerateResult is a key generated in the HSM.
type GenerateResult struct {
	Label     string   `json:"label"`
	PublicKey []byte   `json:"public_key,omitempty"` // PKIX DER, asymmetric only
	KCV       []byte   `json:"kcv,omitempty"`        // AES: first 3 bytes of E(K, 0^128), computed in the HSM
	HSM       Identity `json:"hsm"`                  // the token the key was generated on
}

// Identity names the HSM token as its library reports it. A tenant has one
// HSM profile; keycore records this on each HSM key so a key can always be
// traced to the device that holds it.
type Identity struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	TokenLabel   string `json:"token_label,omitempty"`
}

// ObjectInfo is what the HSM reports about one object. Boolean attributes
// the library doesn't report are nil.
type ObjectInfo struct {
	Label            string    `json:"label"`
	IDHex            string    `json:"id_hex,omitempty"`
	Class            string    `json:"class"` // secret_key, private_key, public_key, certificate, data, other
	KeyType          string    `json:"key_type,omitempty"`
	SizeBits         int       `json:"size_bits,omitempty"`
	Curve            string    `json:"curve,omitempty"`
	Token            *bool     `json:"token,omitempty"`
	Private          *bool     `json:"private,omitempty"`
	Sensitive        *bool     `json:"sensitive,omitempty"`
	Extractable      *bool     `json:"extractable,omitempty"`
	AlwaysSensitive  *bool     `json:"always_sensitive,omitempty"`
	NeverExtractable *bool     `json:"never_extractable,omitempty"`
	Local            *bool     `json:"local,omitempty"` // generated on the token
	Encrypt          *bool     `json:"encrypt,omitempty"`
	Decrypt          *bool     `json:"decrypt,omitempty"`
	Sign             *bool     `json:"sign,omitempty"`
	Verify           *bool     `json:"verify,omitempty"`
	Wrap             *bool     `json:"wrap,omitempty"`
	Unwrap           *bool     `json:"unwrap,omitempty"`
	Managed          bool      `json:"managed"` // created for this tenant through the KMS
	Certificate      *CertInfo `json:"certificate,omitempty"`
}

// CertInfo describes a certificate object stored in the HSM.
type CertInfo struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	Serial    string `json:"serial"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	SHA256    string `json:"sha256"`
}

// Status is what the connector reports about a tenant's HSM.
type Status struct {
	Configured     bool   `json:"configured"`
	Connected      bool   `json:"connected"`
	ProviderName   string `json:"provider_name,omitempty"`
	Library        string `json:"library,omitempty"`
	Manufacturer   string `json:"manufacturer,omitempty"`
	Model          string `json:"model,omitempty"`
	TokenLabel     string `json:"token_label,omitempty"`
	SerialNumber   string `json:"serial_number,omitempty"`
	Firmware       string `json:"firmware,omitempty"`
	CryptokiVer    string `json:"cryptoki_version,omitempty"`
	TenantKeyReady bool   `json:"tenant_key_ready"`
	Error          string `json:"error,omitempty"`
}

// Client calls the hsm-connector with the calling service's identity.
type Client struct {
	base string
	http *http.Client
}

// New returns a client for the connector at base.
func New(base string) *Client {
	return &Client{base: strings.TrimRight(strings.TrimSpace(base), "/"), http: &http.Client{Timeout: 20 * time.Second}}
}

// FromEnv returns a client for HSM_CONNECTOR_URL (default
// http://hsm-connector:8430).
func FromEnv() *Client {
	base := strings.TrimSpace(os.Getenv("HSM_CONNECTOR_URL"))
	if base == "" {
		base = "http://hsm-connector:8430"
	}
	return New(base)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func (c *Client) call(ctx context.Context, method, path string, in, out interface{}) error {
	if c == nil || c.base == "" {
		return ErrUnavailable
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	servicetoken.Authorize(ctx, req)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		switch e.Error.Code {
		case "hsm_not_configured":
			return ErrNotConfigured
		case "foreign_label":
			return ErrForeignLabel
		case "not_found":
			return ErrNotFound
		}
		if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable {
			return fmt.Errorf("%w: %s", ErrUnavailable, strings.TrimSpace(e.Error.Message))
		}
		return fmt.Errorf("hsm: %s (%d %s)", strings.TrimSpace(e.Error.Message), resp.StatusCode, e.Error.Code)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// Generate creates a non-extractable key in tenant's HSM.
func (c *Client) Generate(ctx context.Context, tenant, label, algorithm string) (GenerateResult, error) {
	var out struct {
		Label     string   `json:"label"`
		PublicKey string   `json:"public_key_b64"`
		KCV       string   `json:"kcv_b64"`
		HSM       Identity `json:"hsm"`
	}
	err := c.call(ctx, http.MethodPost, "/hsm/keys", map[string]string{"tenant_id": tenant, "label": label, "algorithm": algorithm}, &out)
	if err != nil {
		return GenerateResult{}, err
	}
	res := GenerateResult{Label: out.Label, HSM: out.HSM}
	if res.PublicKey, err = unb64(out.PublicKey); err != nil {
		return GenerateResult{}, err
	}
	if res.KCV, err = unb64(out.KCV); err != nil {
		return GenerateResult{}, err
	}
	return res, nil
}

// EnsureTenantKey returns the label of tenant's key, generating it the first
// time.
func (c *Client) EnsureTenantKey(ctx context.Context, tenant string) (string, error) {
	var out struct {
		Label string `json:"label"`
	}
	if err := c.call(ctx, http.MethodPost, "/hsm/tenant-key", map[string]string{"tenant_id": tenant}, &out); err != nil {
		return "", err
	}
	return out.Label, nil
}

// Encrypt runs AES-GCM in the HSM. The IV comes from the HSM's generator.
func (c *Client) Encrypt(ctx context.Context, tenant, label string, plaintext, aad []byte) (iv, ciphertext []byte, err error) {
	var out struct {
		IV         string `json:"iv_b64"`
		Ciphertext string `json:"ciphertext_b64"`
	}
	if err := c.call(ctx, http.MethodPost, "/hsm/encrypt", map[string]string{
		"tenant_id": tenant, "label": label, "plaintext_b64": b64(plaintext), "aad_b64": b64(aad),
	}, &out); err != nil {
		return nil, nil, err
	}
	if iv, err = unb64(out.IV); err != nil {
		return nil, nil, err
	}
	ciphertext, err = unb64(out.Ciphertext)
	return iv, ciphertext, err
}

// Decrypt reverses Encrypt; a wrong tag is an error.
func (c *Client) Decrypt(ctx context.Context, tenant, label string, iv, ciphertext, aad []byte) ([]byte, error) {
	var out struct {
		Plaintext string `json:"plaintext_b64"`
	}
	if err := c.call(ctx, http.MethodPost, "/hsm/decrypt", map[string]string{
		"tenant_id": tenant, "label": label, "iv_b64": b64(iv), "ciphertext_b64": b64(ciphertext), "aad_b64": b64(aad),
	}, &out); err != nil {
		return nil, err
	}
	return unb64(out.Plaintext)
}

// Sign signs a digest (hash is SHA-256, SHA-384 or SHA-512): RSA-PSS with
// salt = hash length, or ECDSA (ASN.1 DER signature).
func (c *Client) Sign(ctx context.Context, tenant, label, hash string, digest []byte) ([]byte, error) {
	var out struct {
		Signature string `json:"signature_b64"`
	}
	if err := c.call(ctx, http.MethodPost, "/hsm/sign", map[string]string{
		"tenant_id": tenant, "label": label, "hash": hash, "digest_b64": b64(digest),
	}, &out); err != nil {
		return nil, err
	}
	return unb64(out.Signature)
}

// Verify checks a signature made by Sign.
func (c *Client) Verify(ctx context.Context, tenant, label, hash string, digest, signature []byte) (bool, error) {
	var out struct {
		Verified bool `json:"verified"`
	}
	err := c.call(ctx, http.MethodPost, "/hsm/verify", map[string]string{
		"tenant_id": tenant, "label": label, "hash": hash, "digest_b64": b64(digest), "signature_b64": b64(signature),
	}, &out)
	return out.Verified, err
}

// Destroy deletes every object with label from tenant's HSM.
func (c *Client) Destroy(ctx context.Context, tenant, label string) error {
	return c.call(ctx, http.MethodPost, "/hsm/keys/destroy", map[string]string{"tenant_id": tenant, "label": label}, nil)
}

// Inspect reads the attributes of every object labelled label (a key pair
// is two objects) back from the HSM.
func (c *Client) Inspect(ctx context.Context, tenant, label string) ([]ObjectInfo, Identity, error) {
	var out struct {
		Objects []ObjectInfo `json:"objects"`
		HSM     Identity     `json:"hsm"`
	}
	err := c.call(ctx, http.MethodPost, "/hsm/keys/inspect", map[string]string{"tenant_id": tenant, "label": label}, &out)
	return out.Objects, out.HSM, err
}

// Objects lists the keys and certificates the tenant's HSM login can see:
// the tenant's own KMS objects and objects the KMS didn't create. Other
// tenants' KMS objects are left out.
func (c *Client) Objects(ctx context.Context, tenant string) ([]ObjectInfo, Identity, error) {
	var out struct {
		Objects []ObjectInfo `json:"objects"`
		HSM     Identity     `json:"hsm"`
	}
	err := c.call(ctx, http.MethodGet, "/hsm/objects?tenant_id="+tenant, nil, &out)
	return out.Objects, out.HSM, err
}

// Status reports tenant's HSM connection.
func (c *Client) Status(ctx context.Context, tenant string) (Status, error) {
	var out struct {
		Status Status `json:"status"`
	}
	err := c.call(ctx, http.MethodGet, "/hsm/status?tenant_id="+tenant, nil, &out)
	return out.Status, err
}
