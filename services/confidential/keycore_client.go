package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vecta-kms/pkg/servicetoken"
)

type keycoreReleaseRequest struct {
	TenantID           string `json:"tenant_id"`
	RecipientPublicKey string `json:"recipient_public_key"`
	ReleaseID          string `json:"release_id"`
	AttestationHash    string `json:"attestation_document_hash"`
	Provider           string `json:"provider"`
}

// HTTPKeycoreReleaser calls keycore over internal mTLS with the
// kms-confidential service token; keycore accepts the release from that
// identity only.
type HTTPKeycoreReleaser struct {
	baseURL string
	client  *http.Client
}

func NewHTTPKeycoreReleaser(baseURL string, timeout time.Duration) *HTTPKeycoreReleaser {
	return &HTTPKeycoreReleaser{baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), client: &http.Client{Timeout: timeout}}
}

func (c *HTTPKeycoreReleaser) AttestedRelease(ctx context.Context, tenantID, keyID string, req keycoreReleaseRequest) (SealedKeyRelease, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return SealedKeyRelease{}, err
	}
	endpoint := c.baseURL + "/keys/" + url.PathEscape(strings.TrimSpace(keyID)) + "/attested-release"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return SealedKeyRelease{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Tenant-ID", tenantID)
	servicetoken.Authorize(ctx, httpReq)
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return SealedKeyRelease{}, err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error.Message != "" {
			return SealedKeyRelease{}, fmt.Errorf("%s (%d)", e.Error.Message, resp.StatusCode)
		}
		return SealedKeyRelease{}, fmt.Errorf("keycore returned %d", resp.StatusCode)
	}
	var out SealedKeyRelease
	if err := json.Unmarshal(body, &out); err != nil {
		return SealedKeyRelease{}, err
	}
	if out.WrappedKey == "" || out.Ciphertext == "" {
		return SealedKeyRelease{}, errors.New("keycore returned no sealed material")
	}
	return out, nil
}
