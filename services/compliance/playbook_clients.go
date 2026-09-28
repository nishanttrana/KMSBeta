package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"

	"vecta-kms/pkg/servicetoken"
)

// platformURLs are the services playbook actions call as the compliance
// service identity. http.DefaultTransport is svctls's router, so each call
// is internal mTLS.
type platformURLs struct {
	Keycore, Certs, Auth, Governance, Reporting, Posture string
}

func platformURLsFromEnv() platformURLs {
	return platformURLs{
		Keycore:    envOr("KEYCORE_URL", "https://keycore:8010"),
		Certs:      envOr("CERTS_URL", "https://certs:8030"),
		Auth:       envOr("AUTH_URL", "https://auth:8001"),
		Governance: envOr("GOVERNANCE_URL", "https://governance:8050"),
		Reporting:  envOr("REPORTING_URL", "https://reporting:8140"),
		Posture:    envOr("POSTURE_URL", "https://posture:8220"),
	}
}

// Authority is what auth says about a person's current standing.
type Authority struct {
	Active  bool     `json:"active"`
	Missing []string `json:"missing"`
}

// AuthorityChecker asks auth whether a user is still active and still holds
// permissions, now (not when the playbook was saved).
type AuthorityChecker interface {
	Authority(ctx context.Context, tenantID, userID string, perms []string) (Authority, error)
}

// GovernanceApproval is the part of a governance approval request a resume
// checks.
type GovernanceApproval struct {
	ID            string                 `json:"id"`
	Action        string                 `json:"action"`
	TargetType    string                 `json:"target_type"`
	TargetID      string                 `json:"target_id"`
	TargetDetails map[string]interface{} `json:"target_details"`
	RequesterID   string                 `json:"requester_id"`
	Status        string                 `json:"status"`
}

// ApprovalRequestInput opens a governance approval request.
type ApprovalRequestInput struct {
	TenantID      string                 `json:"tenant_id"`
	Action        string                 `json:"action"`
	TargetType    string                 `json:"target_type"`
	TargetID      string                 `json:"target_id"`
	TargetDetails map[string]interface{} `json:"target_details"`
	RequesterID   string                 `json:"requester_id"`
}

// ApprovalService is governance's approval API.
type ApprovalService interface {
	RequestApproval(ctx context.Context, in ApprovalRequestInput) (string, error)
	GetApproval(ctx context.Context, tenantID, id string) (GovernanceApproval, error)
	CancelApproval(ctx context.Context, tenantID, id, requesterID string) error
}

// platformClient is the HTTP implementation of AuthorityChecker and
// ApprovalService.
type platformClient struct {
	urls platformURLs
	http *http.Client
}

func (p platformClient) Authority(ctx context.Context, tenantID, userID string, perms []string) (Authority, error) {
	var out Authority
	_, err := callJSON(ctx, p.http, http.MethodPost, p.urls.Auth+"/auth/delegated/authority", tenantID, "", map[string]interface{}{
		"user_id": userID, "permissions": perms,
	}, &out)
	return out, err
}

func (p platformClient) RequestApproval(ctx context.Context, in ApprovalRequestInput) (string, error) {
	var out struct {
		Request struct {
			ID string `json:"id"`
		} `json:"request"`
	}
	if _, err := callJSON(ctx, p.http, http.MethodPost, p.urls.Governance+"/governance/requests", in.TenantID, "", in, &out); err != nil {
		return "", err
	}
	if out.Request.ID == "" {
		return "", errors.New("governance returned no approval request id")
	}
	return out.Request.ID, nil
}

func (p platformClient) GetApproval(ctx context.Context, tenantID, id string) (GovernanceApproval, error) {
	var out struct {
		Request GovernanceApproval `json:"request"`
	}
	_, err := callJSON(ctx, p.http, http.MethodGet, p.urls.Governance+"/governance/requests/"+neturl.PathEscape(id)+"?tenant_id="+neturl.QueryEscape(tenantID), tenantID, "", nil, &out)
	return out.Request, err
}

func (p platformClient) CancelApproval(ctx context.Context, tenantID, id, requesterID string) error {
	_, err := callJSON(ctx, p.http, http.MethodPost, p.urls.Governance+"/governance/requests/"+neturl.PathEscape(id)+"/cancel?tenant_id="+neturl.QueryEscape(tenantID), tenantID, "", map[string]string{"requester_id": requesterID}, nil)
	return err
}

// platformError is a platform service's error answer.
type platformError struct {
	Host   string
	Status int
	Code   string
	Msg    string
}

func (e platformError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("%s HTTP %d %s", e.Host, e.Status, http.StatusText(e.Status))
	}
	return fmt.Sprintf("%s HTTP %d %s: %s", e.Host, e.Status, e.Code, e.Msg)
}

// callJSON calls a platform service as the compliance service identity for
// tenantID and decodes the answer into out. It returns the answer's
// top-level "status" (keycore reports "pending_approval" there).
func callJSON(ctx context.Context, client *http.Client, method, url, tenantID, correlation string, body, out interface{}) (string, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Tenant-ID", tenantID)
	if correlation != "" {
		req.Header.Set("X-Correlation-ID", correlation)
	}
	servicetoken.Authorize(ctx, req)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s unreachable: %w", req.URL.Host, unwrapURLError(err))
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var envelope struct {
		Status string `json:"status"`
		Error  struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &envelope)
	if resp.StatusCode >= 400 {
		return "", platformError{Host: req.URL.Host, Status: resp.StatusCode, Code: envelope.Error.Code, Msg: strings.TrimSpace(envelope.Error.Message)}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return "", fmt.Errorf("%s: unreadable answer: %w", req.URL.Host, err)
		}
	}
	return envelope.Status, nil
}
