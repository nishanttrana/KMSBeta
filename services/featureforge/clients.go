package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// --- Local sandbox (config-mode dry-run, no MCP server) ------------------

type localSandbox struct{}

// NewLocalSandbox returns the local config dry-run sandbox.
func NewLocalSandbox() LocalSandbox { return localSandbox{} }

func (localSandbox) DryRunConfig(action string, params map[string]interface{}) (GuardrailResult, error) {
	switch action {
	case "policy.set_min_key_size":
		bits, _ := params["min_bits"].(string)
		n, err := strconv.Atoi(bits)
		if err != nil || n < 1024 {
			return GuardrailResult{Layer: "sandbox", Passed: false, Detail: "min_bits invalid or below 1024"}, nil
		}
	case "policy.restrict_algorithm":
		if alg, _ := params["algorithm"].(string); strings.TrimSpace(alg) == "" {
			return GuardrailResult{Layer: "sandbox", Passed: false, Detail: "algorithm is empty"}, nil
		}
	}
	return GuardrailResult{Layer: "sandbox", Passed: true, Detail: "dry-run clean"}, nil
}

// --- HTTP policy client --------------------------------------------------

// HTTPPolicyClient calls the existing policy service for evaluate + apply.
type HTTPPolicyClient struct {
	baseURL string
	client  *http.Client
}

// NewHTTPPolicyClient builds a policy client against baseURL (e.g. http://kms-policy:8040).
func NewHTTPPolicyClient(baseURL string, timeout time.Duration) *HTTPPolicyClient {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &HTTPPolicyClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (p *HTTPPolicyClient) Evaluate(tenantID, action string, params map[string]interface{}) (GuardrailResult, error) {
	// Defensive rule applied client-side regardless of remote policy: never
	// allow blocking a PQC algorithm (would lower the security posture).
	if action == "policy.restrict_algorithm" {
		if alg, _ := params["algorithm"].(string); strings.HasPrefix(strings.ToUpper(alg), "ML-") {
			return GuardrailResult{Layer: "policy", Passed: false,
				Detail: "refusing to block a PQC algorithm (" + alg + ")"}, nil
		}
	}
	body := map[string]interface{}{"tenant_id": tenantID, "action": action, "params": params}
	resp, err := p.post(context.Background(), "/policy/evaluate", body)
	if err != nil {
		return GuardrailResult{Layer: "policy", Passed: false, Detail: "policy evaluate unreachable: " + err.Error()}, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return GuardrailResult{Layer: "policy", Passed: true, Detail: "permitted"}, nil
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnprocessableEntity {
		return GuardrailResult{Layer: "policy", Passed: false, Detail: "denied by policy service"}, nil
	}
	return GuardrailResult{Layer: "policy", Passed: false,
		Detail: fmt.Sprintf("policy evaluate http %d", resp.StatusCode)}, nil
}

func (p *HTTPPolicyClient) Apply(tenantID, actor, action string, params map[string]interface{}) (GuardrailResult, error) {
	// Translate the catalog action into a policy create/update call. The exact
	// policy spec shape lives in the policy service; here we send a typed
	// guardrail policy document the policy service understands.
	body := map[string]interface{}{
		"tenant_id":   tenantID,
		"created_by":  actor,
		"name":        "featureforge-" + strings.ReplaceAll(action, ".", "-"),
		"spec_type":   "guardrail",
		"description": "Applied by FeatureForge",
		"action":      action,
		"params":      params,
	}
	resp, err := p.post(context.Background(), "/policies", body)
	if err != nil {
		return GuardrailResult{Layer: "apply", Passed: false, Detail: err.Error()}, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return GuardrailResult{Layer: "apply", Passed: true, Detail: "policy applied"}, nil
	}
	return GuardrailResult{Layer: "apply", Passed: false,
		Detail: fmt.Sprintf("policy apply http %d", resp.StatusCode)}, nil
}

func (p *HTTPPolicyClient) post(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return p.client.Do(req)
}

// --- HTTP governance client ---------------------------------------------

// HTTPGovernanceClient opens quorum approvals against the governance service.
type HTTPGovernanceClient struct {
	baseURL string
	client  *http.Client
}

// NewHTTPGovernanceClient builds a governance client (e.g. http://kms-governance:8050).
func NewHTTPGovernanceClient(baseURL string, timeout time.Duration) *HTTPGovernanceClient {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &HTTPGovernanceClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (g *HTTPGovernanceClient) RequestApproval(in *Intent) (string, error) {
	body := map[string]interface{}{
		"tenant_id":   in.TenantID,
		"requested_by": in.Actor,
		"action":      "featureforge.promote",
		"resource":    in.ID,
		"reason":      "FeatureForge prod promotion: " + in.RawText,
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, g.baseURL+"/approval-requests", bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("governance request http %d", resp.StatusCode)
	}
	var out struct {
		ID        string `json:"id"`
		RequestID string `json:"request_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.ID != "" {
		return out.ID, nil
	}
	if out.RequestID != "" {
		return out.RequestID, nil
	}
	return "", errors.New("governance returned no approval id")
}

func (g *HTTPGovernanceClient) ApprovalState(approvalID string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, g.baseURL+"/approval-requests/"+approvalID, nil)
	if err != nil {
		return false, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("governance state http %d", resp.StatusCode)
	}
	var out struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return strings.EqualFold(out.Status, "approved"), nil
}

// --- External MCP client (scaffold-mode build/validate) ------------------

// HTTPMCPClient talks to the EXTERNAL, separately-deployed MCP server that
// scaffolds, builds, and validates code. The URL is configured via
// MCP_SERVER_URL. featureforge never builds code itself — it delegates to the
// MCP server and consumes its pass/fail verdict.
type HTTPMCPClient struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewHTTPMCPClient builds an MCP client. Returns nil if baseURL is empty
// (scaffold mode then reports that no MCP server is configured).
func NewHTTPMCPClient(baseURL, apiKey string, timeout time.Duration) *HTTPMCPClient {
	if strings.TrimSpace(baseURL) == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &HTTPMCPClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		apiKey:  strings.TrimSpace(apiKey),
		client:  &http.Client{Timeout: timeout},
	}
}

func (m *HTTPMCPClient) auth(req *http.Request) {
	if m.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+m.apiKey)
	}
}

// Submit sends the feature intent to the MCP server's build endpoint.
func (m *HTTPMCPClient) Submit(in *Intent) (string, error) {
	body := map[string]interface{}{
		"tenant_id": in.TenantID,
		"actor":     in.Actor,
		"intent":    in.RawText,
		"target":    "staging",
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, m.baseURL+"/v1/builds", bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	m.auth(req)
	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("mcp build submit http %d", resp.StatusCode)
	}
	var out struct {
		JobID string `json:"job_id"`
		ID    string `json:"id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.JobID != "" {
		return out.JobID, nil
	}
	if out.ID != "" {
		return out.ID, nil
	}
	return "", errors.New("mcp returned no job id")
}

// Status polls the MCP server for the build/validation verdict.
func (m *HTTPMCPClient) Status(jobID string) (GuardrailResult, error) {
	req, err := http.NewRequest(http.MethodGet, m.baseURL+"/v1/builds/"+jobID, nil)
	if err != nil {
		return GuardrailResult{Layer: "mcp", Passed: false, Detail: err.Error()}, err
	}
	m.auth(req)
	resp, err := m.client.Do(req)
	if err != nil {
		return GuardrailResult{Layer: "mcp", Passed: false, Detail: err.Error()}, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return GuardrailResult{Layer: "mcp", Passed: false,
			Detail: fmt.Sprintf("mcp status http %d", resp.StatusCode)}, nil
	}
	var out struct {
		Status   string `json:"status"`   // queued|building|passed|failed
		Detail   string `json:"detail"`
		Validated bool  `json:"validated"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	passed := strings.EqualFold(out.Status, "passed") || out.Validated
	detail := out.Detail
	if detail == "" {
		detail = "mcp status=" + out.Status
	}
	return GuardrailResult{Layer: "mcp", Passed: passed, Detail: detail}, nil
}
