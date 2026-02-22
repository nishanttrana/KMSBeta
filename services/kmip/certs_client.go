package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type CertsClient interface {
	ListCAs(ctx context.Context, tenantID string) ([]CertsCA, error)
	IssueCertificate(ctx context.Context, req CertsIssueCertificateRequest) (CertsIssuedCertificate, error)
}

type CertsCA struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	CertPEM  string `json:"cert_pem"`
	Subject  string `json:"subject"`
	Status   string `json:"status"`
}

type CertsIssueCertificateRequest struct {
	TenantID     string   `json:"tenant_id"`
	CAID         string   `json:"ca_id"`
	ProfileID    string   `json:"profile_id"`
	CertType     string   `json:"cert_type"`
	Algorithm    string   `json:"algorithm"`
	CertClass    string   `json:"cert_class"`
	SubjectCN    string   `json:"subject_cn"`
	SANs         []string `json:"sans"`
	CSRPem       string   `json:"csr_pem"`
	ServerKeygen bool     `json:"server_keygen"`
	ValidityDays int64    `json:"validity_days"`
	NotAfter     string   `json:"not_after"`
	Protocol     string   `json:"protocol"`
	MetadataJSON string   `json:"metadata_json"`
}

type CertsIssuedCertificate struct {
	ID        string    `json:"id"`
	CAID      string    `json:"ca_id"`
	SubjectCN string    `json:"subject_cn"`
	CertPEM   string    `json:"cert_pem"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	KeyPEM    string    `json:"private_key_pem"`
}

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

func (c *HTTPCertsClient) ListCAs(ctx context.Context, tenantID string) ([]CertsCA, error) {
	tenant := strings.TrimSpace(tenantID)
	if tenant == "" {
		return nil, errors.New("tenant_id is required")
	}
	type listResp struct {
		Items []CertsCA `json:"items"`
	}
	var out listResp
	if err := c.doJSON(ctx, http.MethodGet, "/certs/ca?tenant_id="+tenant, nil, &out); err != nil {
		return nil, err
	}
	if out.Items == nil {
		return []CertsCA{}, nil
	}
	return out.Items, nil
}

func (c *HTTPCertsClient) IssueCertificate(ctx context.Context, req CertsIssueCertificateRequest) (CertsIssuedCertificate, error) {
	type certPayload struct {
		ID        string `json:"id"`
		CAID      string `json:"ca_id"`
		SubjectCN string `json:"subject_cn"`
		CertPEM   string `json:"cert_pem"`
		NotBefore string `json:"not_before"`
		NotAfter  string `json:"not_after"`
	}
	type issueResp struct {
		Certificate   certPayload `json:"certificate"`
		PrivateKeyPEM string      `json:"private_key_pem"`
	}
	var out issueResp
	if err := c.doJSON(ctx, http.MethodPost, "/certs", req, &out); err != nil {
		return CertsIssuedCertificate{}, err
	}
	issued := CertsIssuedCertificate{
		ID:        strings.TrimSpace(out.Certificate.ID),
		CAID:      strings.TrimSpace(out.Certificate.CAID),
		SubjectCN: strings.TrimSpace(out.Certificate.SubjectCN),
		CertPEM:   strings.TrimSpace(out.Certificate.CertPEM),
		KeyPEM:    strings.TrimSpace(out.PrivateKeyPEM),
	}
	issued.NotBefore = parseRFC3339(out.Certificate.NotBefore)
	issued.NotAfter = parseRFC3339(out.Certificate.NotAfter)
	return issued, nil
}

func (c *HTTPCertsClient) doJSON(ctx context.Context, method string, path string, reqBody interface{}, out interface{}) error {
	if strings.TrimSpace(c.baseURL) == "" {
		return errors.New("certs base url is empty")
	}
	var body []byte
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		body = raw
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= http.StatusBadRequest {
		var errPayload struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errPayload)
		if strings.TrimSpace(errPayload.Error.Message) != "" {
			return errors.New(strings.TrimSpace(errPayload.Error.Message))
		}
		return errors.New("certs request failed")
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func parseRFC3339(v string) time.Time {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return time.Time{}
	}
	ts, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}
	}
	return ts.UTC()
}
