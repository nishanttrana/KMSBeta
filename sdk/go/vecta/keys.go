package vecta

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"time"
)

// Key is a key's metadata; material never leaves the KMS.
type Key struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	Algorithm      string            `json:"algorithm"`
	KeyType        string            `json:"key_type"`
	Purpose        string            `json:"purpose"`
	Status         string            `json:"status"`
	Owner          string            `json:"owner"`
	Tags           []string          `json:"tags"`
	Labels         map[string]string `json:"labels"`
	CurrentVersion int               `json:"current_version"`
	KCV            string            `json:"kcv"`
	CreatedAt      time.Time         `json:"created_at"`
}

// CreateKeyInput is a new key. Algorithm is for example AES-256,
// ECDSA-P256 or RSA-3072; Purpose encrypt, sign, wrap, mac or derive.
type CreateKeyInput struct {
	Name        string            `json:"name"`
	Algorithm   string            `json:"algorithm"`
	KeyType     string            `json:"key_type,omitempty"`
	Purpose     string            `json:"purpose"`
	Description string            `json:"description,omitempty"`
	Owner       string            `json:"owner,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// CreateKey creates a key and returns its ID. The tenant's metadata profiles
// apply (an APIError with Code metadata_profile_violation lists what is
// missing).
func (c *Client) CreateKey(ctx context.Context, in CreateKeyInput) (string, error) {
	body := struct {
		CreateKeyInput
		TenantID string `json:"tenant_id"`
	}{in, c.tenant}
	var out struct {
		KeyID string `json:"key_id"`
	}
	if err := c.call(ctx, http.MethodPost, "/svc/keycore/keys"+c.query(nil), body, &out); err != nil {
		return "", err
	}
	return out.KeyID, nil
}

// GetKey reads one key the client can see.
func (c *Client) GetKey(ctx context.Context, id string) (Key, error) {
	var out struct {
		Key Key `json:"key"`
	}
	err := c.call(ctx, http.MethodGet, "/svc/keycore/keys/"+url.PathEscape(id)+c.query(nil), nil, &out)
	return out.Key, err
}

// ListKeys calls fn with every key the client can see, a page at a time,
// until fn returns false or the keys run out.
func (c *Client) ListKeys(ctx context.Context, fn func(Key) bool) error {
	q := url.Values{"limit": {"200"}}
	for {
		var out struct {
			Items      []Key `json:"items"`
			HasMore    bool  `json:"has_more"`
			NextCursor *struct {
				AfterCreatedAt string `json:"after_created_at"`
				AfterID        string `json:"after_id"`
			} `json:"next_cursor"`
		}
		if err := c.call(ctx, http.MethodGet, "/svc/keycore/keys"+c.query(q), nil, &out); err != nil {
			return err
		}
		for _, k := range out.Items {
			if !fn(k) {
				return nil
			}
		}
		if !out.HasMore || out.NextCursor == nil {
			return nil
		}
		q.Set("after_created_at", out.NextCursor.AfterCreatedAt)
		q.Set("after_id", out.NextCursor.AfterID)
	}
}

// KeyUpdate names the metadata to change; a nil field is left as stored
// (PATCH /keys/{id}). The client must manage the key: its creator, a
// key-access administrator, or a holder of a grant of "all".
type KeyUpdate struct {
	Name        *string            `json:"name,omitempty"`
	Description *string            `json:"description,omitempty"`
	Purpose     *string            `json:"purpose,omitempty"`
	Owner       *string            `json:"owner,omitempty"`
	Tags        *[]string          `json:"tags,omitempty"`
	Labels      *map[string]string `json:"labels,omitempty"`
}

// UpdateKey changes the named metadata and returns the key as stored.
func (c *Client) UpdateKey(ctx context.Context, id string, u KeyUpdate) (Key, error) {
	var out struct {
		Key Key `json:"key"`
	}
	err := c.call(ctx, http.MethodPatch, "/svc/keycore/keys/"+url.PathEscape(id)+c.query(nil), u, &out)
	return out.Key, err
}

// DeactivateKey stops new encryption and signing with the key; existing
// ciphertext still decrypts and signatures still verify.
func (c *Client) DeactivateKey(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodPost, "/svc/keycore/keys/"+url.PathEscape(id)+"/deactivate"+c.query(nil), struct{}{}, nil)
}

// Grant is a key access assignment: SubjectType "user", "group" or "client".
type Grant struct {
	SubjectType string   `json:"subject_type"`
	SubjectID   string   `json:"subject_id"`
	Operations  []string `json:"operations"`
	NotBefore   *string  `json:"not_before,omitempty"`
	ExpiresAt   *string  `json:"expires_at,omitempty"`
}

// GetKeyAccess reads the key's grants.
func (c *Client) GetKeyAccess(ctx context.Context, id string) ([]Grant, error) {
	var out struct {
		Policy struct {
			Grants []Grant `json:"grants"`
		} `json:"policy"`
	}
	err := c.call(ctx, http.MethodGet, "/svc/keycore/keys/"+url.PathEscape(id)+"/access-policy"+c.query(nil), nil, &out)
	return out.Policy.Grants, err
}

// SetKeyAccess replaces the key's grants. An approval-gated tenant answers
// with a pending approval, returned as an APIError with Status 202.
func (c *Client) SetKeyAccess(ctx context.Context, id string, grants []Grant) error {
	if grants == nil {
		grants = []Grant{}
	}
	var out struct {
		Status            string `json:"status"`
		ApprovalRequestID string `json:"approval_request_id"`
	}
	if err := c.call(ctx, http.MethodPut, "/svc/keycore/keys/"+url.PathEscape(id)+"/access-policy"+c.query(nil), map[string]any{"grants": grants}, &out); err != nil {
		return err
	}
	if out.Status == "pending_approval" {
		return &APIError{Status: http.StatusAccepted, Code: "pending_approval", Message: "the change waits for approval " + out.ApprovalRequestID}
	}
	return nil
}

// RotateKey makes a new version current and returns its number.
func (c *Client) RotateKey(ctx context.Context, id, reason string) (int, error) {
	var out struct {
		Version int `json:"version"`
	}
	err := c.call(ctx, http.MethodPost, "/svc/keycore/keys/"+url.PathEscape(id)+"/rotate"+c.query(nil), map[string]string{"reason": reason}, &out)
	return out.Version, err
}

// Ciphertext is what Encrypt returns and Decrypt takes.
type Ciphertext struct {
	KeyID      string
	Version    int
	Ciphertext []byte
	IV         []byte
}

func b64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func unb64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// Encrypt encrypts plaintext under the key's current version; aad, if
// any, must be given again to Decrypt.
func (c *Client) Encrypt(ctx context.Context, keyID string, plaintext, aad []byte) (Ciphertext, error) {
	var out struct {
		KeyID      string `json:"key_id"`
		Version    int    `json:"version"`
		Ciphertext string `json:"ciphertext"`
		IV         string `json:"iv"`
	}
	in := map[string]string{"tenant_id": c.tenant, "plaintext": b64(plaintext), "aad": b64(aad)}
	if err := c.call(ctx, http.MethodPost, "/svc/keycore/keys/"+url.PathEscape(keyID)+"/encrypt"+c.query(nil), in, &out); err != nil {
		return Ciphertext{}, err
	}
	ct, err := unb64(out.Ciphertext)
	if err != nil {
		return Ciphertext{}, err
	}
	iv, err := unb64(out.IV)
	return Ciphertext{KeyID: out.KeyID, Version: out.Version, Ciphertext: ct, IV: iv}, err
}

// Decrypt decrypts what Encrypt returned, with the same aad.
func (c *Client) Decrypt(ctx context.Context, ct Ciphertext, aad []byte) ([]byte, error) {
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	in := map[string]any{"tenant_id": c.tenant, "ciphertext": b64(ct.Ciphertext), "iv": b64(ct.IV), "aad": b64(aad), "version": ct.Version}
	if err := c.call(ctx, http.MethodPost, "/svc/keycore/keys/"+url.PathEscape(ct.KeyID)+"/decrypt"+c.query(nil), in, &out); err != nil {
		return nil, err
	}
	return unb64(out.Plaintext)
}

// Signature is what Sign returns.
type Signature struct {
	KeyID     string
	Version   int
	Signature []byte
}

// Sign signs data with the key's current version. algorithm may be empty
// for the key's default (for example ECDSA-SHA256 for a P-256 key).
func (c *Client) Sign(ctx context.Context, keyID string, data []byte, algorithm string) (Signature, error) {
	var out struct {
		KeyID     string `json:"key_id"`
		Version   int    `json:"version"`
		Signature string `json:"signature"`
	}
	in := map[string]string{"tenant_id": c.tenant, "data": b64(data), "algorithm": algorithm}
	if err := c.call(ctx, http.MethodPost, "/svc/keycore/keys/"+url.PathEscape(keyID)+"/sign"+c.query(nil), in, &out); err != nil {
		return Signature{}, err
	}
	sig, err := unb64(out.Signature)
	return Signature{KeyID: out.KeyID, Version: out.Version, Signature: sig}, err
}

// Verify checks a signature Sign made.
func (c *Client) Verify(ctx context.Context, sig Signature, data []byte, algorithm string) (bool, error) {
	var out struct {
		Verified bool `json:"verified"`
	}
	in := map[string]any{"tenant_id": c.tenant, "data": b64(data), "signature": b64(sig.Signature), "algorithm": algorithm, "version": sig.Version}
	err := c.call(ctx, http.MethodPost, "/svc/keycore/keys/"+url.PathEscape(sig.KeyID)+"/verify"+c.query(nil), in, &out)
	return out.Verified, err
}

// DataKey is a 256-bit key for local encryption: use Plaintext, keep only
// Wrapped, and decrypt Wrapped with Decrypt later.
type DataKey struct {
	Plaintext []byte
	Wrapped   Ciphertext
}

// GenerateDataKey makes a data key wrapped under keyID (envelope
// encryption). aad, if any, binds the wrapped copy.
func (c *Client) GenerateDataKey(ctx context.Context, keyID string, aad []byte) (DataKey, error) {
	var out struct {
		KeyID        string `json:"key_id"`
		Version      int    `json:"version"`
		WrappedDEK   string `json:"wrapped_dek"`
		WrappedDEKIV string `json:"wrapped_dek_iv"`
		PlaintextDEK string `json:"plaintext_dek"`
	}
	in := map[string]any{"tenant_id": c.tenant, "key_bytes": 32, "aad": b64(aad)}
	if err := c.call(ctx, http.MethodPost, "/svc/keycore/keys/"+url.PathEscape(keyID)+"/generate-data-key"+c.query(nil), in, &out); err != nil {
		return DataKey{}, err
	}
	plain, err := unb64(out.PlaintextDEK)
	if err != nil {
		return DataKey{}, err
	}
	wrapped, err := unb64(out.WrappedDEK)
	if err != nil {
		return DataKey{}, err
	}
	iv, err := unb64(out.WrappedDEKIV)
	return DataKey{Plaintext: plain, Wrapped: Ciphertext{KeyID: out.KeyID, Version: out.Version, Ciphertext: wrapped, IV: iv}}, err
}

// SecretValue is a secret's current value.
type SecretValue struct {
	Value       string `json:"value"`
	Version     int    `json:"version"`
	Format      string `json:"format"`
	ContentType string `json:"content_type"`
}

// GetSecretValue reads a secret's value (the secrets permission
// secrets.value.read, which a REST client holds by default).
func (c *Client) GetSecretValue(ctx context.Context, id string) (SecretValue, error) {
	var out SecretValue
	err := c.call(ctx, http.MethodGet, "/svc/secrets/secrets/"+url.PathEscape(id)+"/value"+c.query(nil), nil, &out)
	return out, err
}
