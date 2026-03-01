package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type PostureControlPatch struct {
	UpdatedBy                 string `json:"updated_by"`
	ForceQuorumDestructiveOps *bool  `json:"force_quorum_destructive_ops,omitempty"`
	RequireStepUpAuth         *bool  `json:"require_step_up_auth,omitempty"`
	PauseConnectorSync        *bool  `json:"pause_connector_sync,omitempty"`
	GuardrailPolicyRequired   *bool  `json:"guardrail_policy_required,omitempty"`
	Reason                    string `json:"reason,omitempty"`
	SourceFindingID           string `json:"source_finding_id,omitempty"`
	SourceActionID            string `json:"source_action_id,omitempty"`
}

type GovernanceControlClient interface {
	ApplyPostureControls(ctx context.Context, patch PostureControlPatch) error
}

type HTTPGovernanceControlClient struct {
	baseURL     string
	bearerToken string
	client      *http.Client
}

func NewHTTPGovernanceControlClient(baseURL string, bearerToken string, timeout time.Duration) *HTTPGovernanceControlClient {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPGovernanceControlClient{
		baseURL:     baseURL,
		bearerToken: strings.TrimSpace(bearerToken),
		client:      &http.Client{Timeout: timeout},
	}
}

func (c *HTTPGovernanceControlClient) ApplyPostureControls(ctx context.Context, patch PostureControlPatch) error {
	if c == nil {
		return nil
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/governance/system/posture-controls?tenant_id=root", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "root")
	if c.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= http.StatusBadRequest {
		var apiErr struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &apiErr); err == nil {
			if msg := strings.TrimSpace(apiErr.Error.Message); msg != "" {
				return errors.New(msg)
			}
		}
		return fmt.Errorf("governance posture-controls request failed (%d)", resp.StatusCode)
	}
	return nil
}
