package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/servicetoken"
)

// Remediation approvals are governance approval requests bound to one
// posture action: target_type posture_action, target_id the action ID,
// action posture.<action_type>, and a payload hash over the tenant, action,
// type and finding. Posture opens them as its own service identity, naming
// the verified caller as requester (governance then excludes that caller
// from the approvers and refuses their vote), and executes only when a
// matching request is approved and the executor is its requester.

const approvalTargetType = "posture_action"

// GovernanceApproval is the part of a governance approval request posture
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

type ApprovalClient interface {
	ListApprovals(ctx context.Context, tenantID, status, targetType, targetID string) ([]GovernanceApproval, error)
	RequestApproval(ctx context.Context, in ApprovalRequestInput) (string, error)
}

func approvalAction(actionType string) string { return "posture." + actionType }

// approvalPayloadHash binds an approval to exactly one action.
func approvalPayloadHash(item RemediationAction) string {
	sum := pkgcrypto.SHA256([]byte(strings.Join([]string{"posture-action", item.TenantID, item.ID, item.ActionType, item.FindingID}, "|")))
	return hex.EncodeToString(sum)
}

// approvalMatches reports whether a governance request authorizes item for
// executor.
func approvalMatches(a GovernanceApproval, item RemediationAction, executor string) bool {
	hash, _ := a.TargetDetails["payload_hash"].(string)
	return strings.EqualFold(a.TargetType, approvalTargetType) &&
		a.TargetID == item.ID &&
		strings.EqualFold(a.Action, approvalAction(item.ActionType)) &&
		hash == approvalPayloadHash(item) &&
		a.RequesterID != "" && a.RequesterID == executor
}

func (c *HTTPGovernanceControlClient) ListApprovals(ctx context.Context, tenantID, status, targetType, targetID string) ([]GovernanceApproval, error) {
	q := url.Values{}
	q.Set("tenant_id", tenantID)
	q.Set("status", status)
	q.Set("target_type", targetType)
	q.Set("target_id", targetID)
	var out struct {
		Items []GovernanceApproval `json:"items"`
	}
	if err := c.approvalCall(ctx, http.MethodGet, "/governance/requests?"+q.Encode(), tenantID, nil, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *HTTPGovernanceControlClient) RequestApproval(ctx context.Context, in ApprovalRequestInput) (string, error) {
	var out struct {
		Request struct {
			ID string `json:"id"`
		} `json:"request"`
	}
	if err := c.approvalCall(ctx, http.MethodPost, "/governance/requests", in.TenantID, in, &out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out.Request.ID) == "" {
		return "", errors.New("governance returned no approval request id")
	}
	return out.Request.ID, nil
}

// approvalCall always uses posture's service token: only a service
// principal may name the requester, and a static bearer token would make
// governance record that token's identity instead.
func (c *HTTPGovernanceControlClient) approvalCall(ctx context.Context, method, path, tenantID string, payload, out interface{}) error {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	servicetoken.Authorize(ctx, req)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &apiErr) == nil && strings.TrimSpace(apiErr.Error.Message) != "" {
			return errors.New(strings.TrimSpace(apiErr.Error.Message))
		}
		return fmt.Errorf("governance approval request failed (%d)", resp.StatusCode)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}
