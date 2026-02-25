package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPCertsClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPCertsClient(baseURL string, timeout time.Duration) *HTTPCertsClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPCertsClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPCertsClient) ListCAs(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("certs base url is not configured")
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/certs/ca?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	out := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, parseServiceHTTPError(resp.StatusCode, out, "certs list ca request failed")
	}
	rawItems, _ := out["items"].([]interface{})
	items := make([]map[string]interface{}, 0, len(rawItems))
	for _, item := range rawItems {
		m, _ := item.(map[string]interface{})
		if m != nil {
			items = append(items, m)
		}
	}
	return items, nil
}

func (c *HTTPCertsClient) SignCSR(ctx context.Context, reqIn FieldEncryptionSignCSRRequest) (FieldEncryptionIssuedCertificate, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return FieldEncryptionIssuedCertificate{}, errors.New("certs base url is not configured")
	}
	payload, err := json.Marshal(map[string]interface{}{
		"tenant_id": reqIn.TenantID,
		"ca_id":     reqIn.CAID,
		"csr_pem":   reqIn.CSRPEM,
		"cert_type": defaultString(strings.TrimSpace(reqIn.CertType), "tls-client"),
		"algorithm": defaultString(strings.TrimSpace(reqIn.Algorithm), "ECDSA-P384"),
		"protocol":  defaultString(strings.TrimSpace(reqIn.Protocol), "field-encryption-wrapper"),
	})
	if err != nil {
		return FieldEncryptionIssuedCertificate{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/certs/sign-csr", bytes.NewReader(payload))
	if err != nil {
		return FieldEncryptionIssuedCertificate{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return FieldEncryptionIssuedCertificate{}, err
	}
	defer resp.Body.Close() //nolint:errcheck
	out := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return FieldEncryptionIssuedCertificate{}, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return FieldEncryptionIssuedCertificate{}, parseServiceHTTPError(resp.StatusCode, out, "certs sign csr request failed")
	}
	certMap, _ := out["certificate"].(map[string]interface{})
	if certMap == nil {
		return FieldEncryptionIssuedCertificate{}, newServiceError(http.StatusBadGateway, "certs_failed", "certificate service did not return a certificate object")
	}
	return FieldEncryptionIssuedCertificate{
		CertID:   strings.TrimSpace(firstString(certMap["id"])),
		CertPEM:  strings.TrimSpace(firstString(certMap["cert_pem"])),
		CAID:     defaultString(strings.TrimSpace(firstString(certMap["ca_id"])), strings.TrimSpace(reqIn.CAID)),
		NotAfter: strings.TrimSpace(firstString(certMap["not_after"])),
	}, nil
}

func parseServiceHTTPError(status int, payload map[string]interface{}, fallback string) error {
	errAny, ok := payload["error"]
	if !ok {
		return newServiceError(status, "remote_error", fallback)
	}
	errMap, ok := errAny.(map[string]interface{})
	if !ok {
		return newServiceError(status, "remote_error", fallback)
	}
	code := strings.TrimSpace(firstString(errMap["code"]))
	msg := strings.TrimSpace(firstString(errMap["message"]))
	if code == "" {
		code = "remote_error"
	}
	if msg == "" {
		msg = fallback
	}
	return newServiceError(status, code, msg)
}
