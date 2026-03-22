package main

import (
	"context"
	"time"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type GovernanceClient interface {
	CreateApprovalRequest(ctx context.Context, req GovernanceCreateApprovalRequest) (GovernanceApprovalRequest, error)
}

type Store interface {
	GetSettings(ctx context.Context, tenantID string) (KeyAccessSettings, error)
	UpsertSettings(ctx context.Context, item KeyAccessSettings) (KeyAccessSettings, error)
	ListRules(ctx context.Context, tenantID string) ([]KeyAccessRule, error)
	UpsertRule(ctx context.Context, item KeyAccessRule) (KeyAccessRule, error)
	DeleteRule(ctx context.Context, tenantID string, id string) error
	CreateDecision(ctx context.Context, item KeyAccessDecision) error
	ListDecisions(ctx context.Context, tenantID string, service string, action string, limit int) ([]KeyAccessDecision, error)
}

type KeyAccessSettings struct {
	TenantID                 string    `json:"tenant_id"`
	Enabled                  bool      `json:"enabled"`
	Mode                     string    `json:"mode"`
	DefaultAction            string    `json:"default_action"`
	RequireJustificationCode bool      `json:"require_justification_code"`
	RequireJustificationText bool      `json:"require_justification_text"`
	ApprovalPolicyID         string    `json:"approval_policy_id,omitempty"`
	UpdatedBy                string    `json:"updated_by,omitempty"`
	UpdatedAt                time.Time `json:"updated_at,omitempty"`
}

// TimeWindow restricts a justification code to a specific UTC time range.
// StartUTC and EndUTC use "HH:MM" 24-hour format. Days is an optional list
// of weekday names ("mon","tue","wed","thu","fri","sat","sun"); empty means
// every day. Example: BACKUP code valid Mon–Fri 01:00–05:00 UTC only.
type TimeWindow struct {
	StartUTC string   `json:"start_utc"`      // "01:00"
	EndUTC   string   `json:"end_utc"`        // "05:00"
	Days     []string `json:"days,omitempty"` // ["mon","fri"] or empty = all days
}

type KeyAccessRule struct {
	ID               string       `json:"id"`
	TenantID         string       `json:"tenant_id"`
	Code             string       `json:"code"`
	Label            string       `json:"label"`
	Description      string       `json:"description,omitempty"`
	Action           string       `json:"action"`
	Services         []string     `json:"services"`
	Operations       []string     `json:"operations"`
	RequireText      bool         `json:"require_text"`
	ApprovalPolicyID string       `json:"approval_policy_id,omitempty"`
	// AllowedTimeWindows restricts when this code is valid (UTC). Empty = no
	// restriction. Multiple windows are OR-ed (valid if any window matches).
	AllowedTimeWindows  []TimeWindow `json:"allowed_time_windows,omitempty"`
	// OutsideWindowAction overrides the rule Action when a request arrives
	// outside all time windows. Accepted values: "deny", "require_approval".
	// Defaults to "deny" when omitted.
	OutsideWindowAction string       `json:"outside_window_action,omitempty"`
	Enabled             bool         `json:"enabled"`
	UpdatedBy           string       `json:"updated_by,omitempty"`
	UpdatedAt           time.Time    `json:"updated_at,omitempty"`
}

type KeyAccessDecision struct {
	ID                string                 `json:"id"`
	TenantID          string                 `json:"tenant_id"`
	Service           string                 `json:"service"`
	Connector         string                 `json:"connector,omitempty"`
	Operation         string                 `json:"operation"`
	KeyID             string                 `json:"key_id,omitempty"`
	ResourceID        string                 `json:"resource_id,omitempty"`
	TargetType        string                 `json:"target_type,omitempty"`
	RequestID         string                 `json:"request_id,omitempty"`
	RequesterID       string                 `json:"requester_id,omitempty"`
	RequesterEmail    string                 `json:"requester_email,omitempty"`
	RequesterIP       string                 `json:"requester_ip,omitempty"`
	JustificationCode string                 `json:"justification_code,omitempty"`
	JustificationText string                 `json:"justification_text,omitempty"`
	Decision          string                 `json:"decision"`
	ApprovalRequired  bool                   `json:"approval_required"`
	ApprovalRequestID string                 `json:"approval_request_id,omitempty"`
	MatchedRuleID     string                 `json:"matched_rule_id,omitempty"`
	MatchedCode       string                 `json:"matched_code,omitempty"`
	PolicyMode        string                 `json:"policy_mode"`
	Reason            string                 `json:"reason,omitempty"`
	BypassDetected    bool                   `json:"bypass_detected"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt         time.Time              `json:"created_at,omitempty"`
}

type KeyAccessServiceSummary struct {
	Service            string `json:"service"`
	Requests24h        int    `json:"requests_24h"`
	AllowCount24h      int    `json:"allow_count_24h"`
	DenyCount24h       int    `json:"deny_count_24h"`
	ApprovalCount24h   int    `json:"approval_count_24h"`
	BypassCount24h     int    `json:"bypass_count_24h"`
	UnjustifiedCount24h int   `json:"unjustified_count_24h"`
}

type KeyAccessSummary struct {
	TenantID             string                    `json:"tenant_id"`
	Enabled              bool                      `json:"enabled"`
	Mode                 string                    `json:"mode"`
	DefaultAction        string                    `json:"default_action"`
	RuleCount            int                       `json:"rule_count"`
	TotalRequests24h     int                       `json:"total_requests_24h"`
	AllowCount24h        int                       `json:"allow_count_24h"`
	DenyCount24h         int                       `json:"deny_count_24h"`
	ApprovalCount24h     int                       `json:"approval_count_24h"`
	BypassCount24h       int                       `json:"bypass_count_24h"`
	UnjustifiedCount24h  int                       `json:"unjustified_count_24h"`
	Services             []KeyAccessServiceSummary `json:"services"`
}

type EvaluateKeyAccessInput struct {
	TenantID          string                 `json:"tenant_id"`
	Service           string                 `json:"service"`
	Connector         string                 `json:"connector,omitempty"`
	Operation         string                 `json:"operation"`
	KeyID             string                 `json:"key_id,omitempty"`
	ResourceID        string                 `json:"resource_id,omitempty"`
	TargetType        string                 `json:"target_type,omitempty"`
	RequestID         string                 `json:"request_id,omitempty"`
	RequesterID       string                 `json:"requester_id,omitempty"`
	RequesterEmail    string                 `json:"requester_email,omitempty"`
	RequesterIP       string                 `json:"requester_ip,omitempty"`
	JustificationCode string                 `json:"justification_code,omitempty"`
	JustificationText string                 `json:"justification_text,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

type EvaluateKeyAccessResult struct {
	DecisionID        string                 `json:"decision_id"`
	Enabled           bool                   `json:"enabled"`
	Mode              string                 `json:"mode"`
	Action            string                 `json:"action"`
	ApprovalRequired  bool                   `json:"approval_required"`
	ApprovalRequestID string                 `json:"approval_request_id,omitempty"`
	MatchedRuleID     string                 `json:"matched_rule_id,omitempty"`
	MatchedCode       string                 `json:"matched_code,omitempty"`
	BypassDetected    bool                   `json:"bypass_detected"`
	Reason            string                 `json:"reason,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

type GovernanceCreateApprovalRequest struct {
	TenantID        string                 `json:"tenant_id"`
	PolicyID        string                 `json:"policy_id,omitempty"`
	Action          string                 `json:"action"`
	TargetType      string                 `json:"target_type"`
	TargetID        string                 `json:"target_id"`
	TargetDetails   map[string]interface{} `json:"target_details,omitempty"`
	RequesterID     string                 `json:"requester_id,omitempty"`
	RequesterEmail  string                 `json:"requester_email,omitempty"`
	RequesterIP     string                 `json:"requester_ip,omitempty"`
	CallbackService string                 `json:"callback_service,omitempty"`
	CallbackAction  string                 `json:"callback_action,omitempty"`
	CallbackPayload map[string]interface{} `json:"callback_payload,omitempty"`
}

type GovernanceApprovalRequest struct {
	ID                string                 `json:"id"`
	TenantID          string                 `json:"tenant_id"`
	PolicyID          string                 `json:"policy_id"`
	Action            string                 `json:"action"`
	TargetType        string                 `json:"target_type"`
	TargetID          string                 `json:"target_id"`
	TargetDetails     map[string]interface{} `json:"target_details,omitempty"`
	RequesterID       string                 `json:"requester_id,omitempty"`
	RequesterEmail    string                 `json:"requester_email,omitempty"`
	Status            string                 `json:"status"`
	RequiredApprovals int                    `json:"required_approvals"`
	CurrentApprovals  int                    `json:"current_approvals"`
	CurrentDenials    int                    `json:"current_denials"`
	CreatedAt         time.Time              `json:"created_at,omitempty"`
	ExpiresAt         time.Time              `json:"expires_at,omitempty"`
}
