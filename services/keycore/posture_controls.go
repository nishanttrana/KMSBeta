package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type postureCtxKey string

const (
	stepUpAuthContextKey postureCtxKey = "step_up_auth"
)

type GovernancePostureControls struct {
	ForceQuorumDestructiveOps bool
	RequireStepUpAuth         bool
	PauseConnectorSync        bool
	GuardrailPolicyRequired   bool
}

type GovernancePostureControlsProvider interface {
	Controls(ctx context.Context, tenantID string) (GovernancePostureControls, error)
}

type staticPostureControlsProvider struct {
	controls GovernancePostureControls
}

func (p staticPostureControlsProvider) Controls(_ context.Context, _ string) (GovernancePostureControls, error) {
	return p.controls, nil
}

type postureControlsCacheEntry struct {
	controls GovernancePostureControls
	expiry   time.Time
}

type HTTPGovernancePostureControlsProvider struct {
	baseURL  string
	client   *http.Client
	cacheTTL time.Duration
	mu       sync.RWMutex
	cache    map[string]postureControlsCacheEntry
}

func NewHTTPGovernancePostureControlsProvider(baseURL string, timeout time.Duration, cacheTTL time.Duration) *HTTPGovernancePostureControlsProvider {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if cacheTTL <= 0 {
		cacheTTL = 5 * time.Second
	}
	return &HTTPGovernancePostureControlsProvider{
		baseURL:  strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:   &http.Client{Timeout: timeout},
		cacheTTL: cacheTTL,
		cache:    map[string]postureControlsCacheEntry{},
	}
}

func (p *HTTPGovernancePostureControlsProvider) Controls(ctx context.Context, tenantID string) (GovernancePostureControls, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return GovernancePostureControls{}, errors.New("tenant_id is required for posture controls check")
	}
	now := time.Now().UTC()
	p.mu.RLock()
	cached, ok := p.cache[tenantID]
	p.mu.RUnlock()
	if ok && now.Before(cached.expiry) {
		return cached.controls, nil
	}
	controls, err := p.fetch(ctx, tenantID)
	if err != nil {
		if ok {
			return cached.controls, nil
		}
		return GovernancePostureControls{}, err
	}
	p.mu.Lock()
	p.cache[tenantID] = postureControlsCacheEntry{
		controls: controls,
		expiry:   now.Add(p.cacheTTL),
	}
	p.mu.Unlock()
	return controls, nil
}

func (p *HTTPGovernancePostureControlsProvider) fetch(ctx context.Context, tenantID string) (GovernancePostureControls, error) {
	if strings.TrimSpace(p.baseURL) == "" {
		return GovernancePostureControls{}, errors.New("governance base url is empty")
	}
	endpoint := fmt.Sprintf("%s/governance/system/state?tenant_id=%s", p.baseURL, url.QueryEscape(tenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return GovernancePostureControls{}, err
	}
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err := p.client.Do(req)
	if err != nil {
		return GovernancePostureControls{}, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var payload struct {
		State struct {
			ForceQuorumDestructiveOps bool `json:"posture_force_quorum_destructive_ops"`
			RequireStepUpAuth         bool `json:"posture_require_step_up_auth"`
			PauseConnectorSync        bool `json:"posture_pause_connector_sync"`
			GuardrailPolicyRequired   bool `json:"posture_guardrail_policy_required"`
		} `json:"state"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return GovernancePostureControls{}, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		msg := strings.TrimSpace(payload.Error.Message)
		if msg == "" {
			msg = "governance posture controls request failed"
		}
		return GovernancePostureControls{}, errors.New(msg)
	}
	return GovernancePostureControls{
		ForceQuorumDestructiveOps: payload.State.ForceQuorumDestructiveOps,
		RequireStepUpAuth:         payload.State.RequireStepUpAuth,
		PauseConnectorSync:        payload.State.PauseConnectorSync,
		GuardrailPolicyRequired:   payload.State.GuardrailPolicyRequired,
	}, nil
}

func contextWithStepUpAuth(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, stepUpAuthContextKey, enabled)
}

func stepUpAuthFromContext(ctx context.Context) bool {
	v, ok := ctx.Value(stepUpAuthContextKey).(bool)
	return ok && v
}

type stepUpRequiredError struct {
	Operation string
}

func (e stepUpRequiredError) Error() string {
	op := strings.TrimSpace(e.Operation)
	if op == "" {
		op = "operation"
	}
	return op + " requires step-up authentication"
}
