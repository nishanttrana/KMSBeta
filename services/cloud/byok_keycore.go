package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/delegation"
	"vecta-kms/pkg/servicetoken"
)

// The BYOK engine's keycore calls. The material is wrapped by keycore for
// the user who asked (delegated usage "cloud-import"); a rotation is made
// with the user's own token, so keycore applies the user's rights to it.

type keycoreError struct {
	Status        int
	Code, Message string
}

func (e *keycoreError) Error() string { return e.Code + ": " + e.Message }

type CloudWrapResult struct {
	KeyID             string `json:"key_id"`
	Version           int    `json:"version"`
	Scheme            string `json:"scheme"`
	WrappedB64        string `json:"wrapped_b64"`
	MaterialSHA256B64 string `json:"material_sha256_b64"`
	KCV               string `json:"kcv"`
	Source            string `json:"source"`
	WrappingKeySHA256 string `json:"wrapping_key_sha256"`
}

// BYOKKeycore is what the engine needs from keycore.
type BYOKKeycore interface {
	KeyInfo(ctx context.Context, tenantID, keyID string) (map[string]interface{}, error)
	CloudWrap(ctx context.Context, tenantID, keyID string, wrappingKey []byte, scheme string, version int, digest bool) (CloudWrapResult, []byte, []byte, error)
	RotateForBYOK(ctx context.Context, tenantID, keyID, reason string) (int, error)
}

func (c *HTTPKeyCoreClient) call(ctx context.Context, method, path string, body interface{}, usage string, asUser bool, out interface{}) error {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok, ok := pkgauth.VerifiedTokenFromContext(ctx); asUser && ok {
		// servicetoken-exempt: the user's own verified token, so keycore
		// decides this rotation on the user's rights.
		req.Header.Set("Authorization", "Bearer "+tok)
	} else {
		servicetoken.Authorize(ctx, req)
		if usage != "" {
			delegation.Attach(ctx, req, usage)
		}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	var env struct {
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	data := new(bytes.Buffer)
	_, _ = data.ReadFrom(resp.Body)
	if resp.StatusCode >= 300 {
		_ = json.Unmarshal(data.Bytes(), &env)
		e := &keycoreError{Status: resp.StatusCode, Code: "keycore_error", Message: http.StatusText(resp.StatusCode)}
		if env.Error != nil {
			e.Code, e.Message = env.Error.Code, env.Error.Message
		}
		return e
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data.Bytes(), out)
}

func (c *HTTPKeyCoreClient) KeyInfo(ctx context.Context, tenantID, keyID string) (map[string]interface{}, error) {
	var out struct {
		Key map[string]interface{} `json:"key"`
	}
	err := c.call(ctx, http.MethodGet, "/keys/"+url.PathEscape(keyID)+"?tenant_id="+url.QueryEscape(tenantID), nil, "", true, &out)
	if err == nil && out.Key == nil {
		err = fmt.Errorf("keycore returned no key %s", keyID)
	}
	return out.Key, err
}

func (c *HTTPKeyCoreClient) CloudWrap(ctx context.Context, tenantID, keyID string, wrappingKey []byte, scheme string, version int, digest bool) (CloudWrapResult, []byte, []byte, error) {
	var out struct {
		Data CloudWrapResult `json:"data"`
	}
	err := c.call(ctx, http.MethodPost, "/keys/"+url.PathEscape(keyID)+"/cloud-wrap?tenant_id="+url.QueryEscape(tenantID), map[string]interface{}{
		"wrapping_key_b64": base64.StdEncoding.EncodeToString(wrappingKey), "scheme": scheme, "version": version, "digest": digest,
	}, "cloud-import", false, &out)
	if err != nil {
		return CloudWrapResult{}, nil, nil, err
	}
	wrapped, err := base64.StdEncoding.DecodeString(out.Data.WrappedB64)
	if err != nil || len(wrapped) == 0 {
		return CloudWrapResult{}, nil, nil, fmt.Errorf("keycore returned no wrapped material")
	}
	var sum []byte
	if s := strings.TrimSpace(out.Data.MaterialSHA256B64); s != "" {
		sum, _ = base64.StdEncoding.DecodeString(s)
	}
	return out.Data, wrapped, sum, nil
}

func (c *HTTPKeyCoreClient) RotateForBYOK(ctx context.Context, tenantID, keyID, reason string) (int, error) {
	var out struct {
		Version int `json:"version"`
	}
	err := c.call(ctx, http.MethodPost, "/keys/"+url.PathEscape(keyID)+"/rotate?tenant_id="+url.QueryEscape(tenantID),
		map[string]interface{}{"reason": defaultString(reason, "cloud BYOK rotation")}, "", true, &out)
	if err != nil {
		return 0, err
	}
	if out.Version < 1 {
		return 0, fmt.Errorf("keycore returned no new version")
	}
	return out.Version, nil
}
