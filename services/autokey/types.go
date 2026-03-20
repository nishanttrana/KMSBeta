package main

import (
	"context"
	"time"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type KeyCoreClient interface {
	CreateKey(ctx context.Context, req KeyCoreCreateKeyRequest) (KeyCoreCreateKeyResponse, error)
}

type GovernanceClient interface {
	CreateApprovalRequest(ctx context.Context, req GovernanceCreateApprovalRequest) (GovernanceApprovalRequest, error)
	GetApprovalRequest(ctx context.Context, tenantID string, requestID string) (GovernanceApprovalRequest, error)
}

type Store interface {
	GetSettings(ctx context.Context, tenantID string) (AutokeySettings, error)
	UpsertSettings(ctx context.Context, item AutokeySettings) (AutokeySettings, error)

	ListTemplates(ctx context.Context, tenantID string) ([]AutokeyTemplate, error)
	GetTemplate(ctx context.Context, tenantID string, id string) (AutokeyTemplate, error)
	UpsertTemplate(ctx context.Context, item AutokeyTemplate) (AutokeyTemplate, error)
	DeleteTemplate(ctx context.Context, tenantID string, id string) error

	ListServicePolicies(ctx context.Context, tenantID string) ([]AutokeyServicePolicy, error)
	GetServicePolicy(ctx context.Context, tenantID string, serviceName string) (AutokeyServicePolicy, error)
	UpsertServicePolicy(ctx context.Context, item AutokeyServicePolicy) (AutokeyServicePolicy, error)
	DeleteServicePolicy(ctx context.Context, tenantID string, serviceName string) error

	CreateRequest(ctx context.Context, item AutokeyRequest) error
	UpdateRequest(ctx context.Context, item AutokeyRequest) error
	GetRequest(ctx context.Context, tenantID string, id string) (AutokeyRequest, error)
	ListRequests(ctx context.Context, tenantID string, status string, limit int) ([]AutokeyRequest, error)

	GetHandleByBinding(ctx context.Context, tenantID string, serviceName string, resourceType string, resourceRef string) (AutokeyHandle, error)
	GetHandle(ctx context.Context, tenantID string, id string) (AutokeyHandle, error)
	ListHandles(ctx context.Context, tenantID string, serviceName string, limit int) ([]AutokeyHandle, error)
	UpsertHandle(ctx context.Context, item AutokeyHandle) (AutokeyHandle, error)
}

type AutokeySettings struct {
	TenantID              string    `json:"tenant_id"`
	Enabled               bool      `json:"enabled"`
	Mode                  string    `json:"mode"`
	RequireApproval       bool      `json:"require_approval"`
	RequireJustification  bool      `json:"require_justification"`
	AllowTemplateOverride bool      `json:"allow_template_override"`
	DefaultPolicyID       string    `json:"default_policy_id,omitempty"`
	DefaultRotationDays   int       `json:"default_rotation_days"`
	UpdatedBy             string    `json:"updated_by,omitempty"`
	UpdatedAt             time.Time `json:"updated_at,omitempty"`
}

type AutokeyTemplate struct {
	ID                string            `json:"id"`
	TenantID          string            `json:"tenant_id"`
	Name              string            `json:"name"`
	ServiceName       string            `json:"service_name"`
	ResourceType      string            `json:"resource_type"`
	HandleNamePattern string            `json:"handle_name_pattern"`
	KeyNamePattern    string            `json:"key_name_pattern"`
	Algorithm         string            `json:"algorithm"`
	KeyType           string            `json:"key_type"`
	Purpose           string            `json:"purpose"`
	ExportAllowed     bool              `json:"export_allowed"`
	IVMode            string            `json:"iv_mode"`
	Tags              []string          `json:"tags"`
	Labels            map[string]string `json:"labels"`
	OpsLimit          int64             `json:"ops_limit"`
	OpsLimitWindow    string            `json:"ops_limit_window"`
	ApprovalRequired  bool              `json:"approval_required"`
	ApprovalPolicyID  string            `json:"approval_policy_id,omitempty"`
	Description       string            `json:"description,omitempty"`
	Enabled           bool              `json:"enabled"`
	UpdatedBy         string            `json:"updated_by,omitempty"`
	UpdatedAt         time.Time         `json:"updated_at,omitempty"`
}

type AutokeyServicePolicy struct {
	TenantID          string            `json:"tenant_id"`
	ServiceName       string            `json:"service_name"`
	DisplayName       string            `json:"display_name,omitempty"`
	DefaultTemplateID string            `json:"default_template_id,omitempty"`
	Algorithm         string            `json:"algorithm,omitempty"`
	KeyType           string            `json:"key_type,omitempty"`
	Purpose           string            `json:"purpose,omitempty"`
	ExportAllowed     bool              `json:"export_allowed"`
	IVMode            string            `json:"iv_mode,omitempty"`
	Tags              []string          `json:"tags"`
	Labels            map[string]string `json:"labels"`
	OpsLimit          int64             `json:"ops_limit"`
	OpsLimitWindow    string            `json:"ops_limit_window,omitempty"`
	ApprovalRequired  bool              `json:"approval_required"`
	ApprovalPolicyID  string            `json:"approval_policy_id,omitempty"`
	EnforcePolicy     bool              `json:"enforce_policy"`
	Description       string            `json:"description,omitempty"`
	Enabled           bool              `json:"enabled"`
	UpdatedBy         string            `json:"updated_by,omitempty"`
	UpdatedAt         time.Time         `json:"updated_at,omitempty"`
}

type AutokeyRequest struct {
	ID                   string                 `json:"id"`
	TenantID             string                 `json:"tenant_id"`
	ServiceName          string                 `json:"service_name"`
	ResourceType         string                 `json:"resource_type"`
	ResourceRef          string                 `json:"resource_ref"`
	TemplateID           string                 `json:"template_id,omitempty"`
	RequesterID          string                 `json:"requester_id,omitempty"`
	RequesterEmail       string                 `json:"requester_email,omitempty"`
	RequesterIP          string                 `json:"requester_ip,omitempty"`
	Justification        string                 `json:"justification,omitempty"`
	RequestedAlgorithm   string                 `json:"requested_algorithm,omitempty"`
	RequestedKeyType     string                 `json:"requested_key_type,omitempty"`
	RequestedPurpose     string                 `json:"requested_purpose,omitempty"`
	HandleName           string                 `json:"handle_name,omitempty"`
	KeyName              string                 `json:"key_name,omitempty"`
	Status               string                 `json:"status"`
	ApprovalRequired     bool                   `json:"approval_required"`
	GovernanceRequestID  string                 `json:"governance_request_id,omitempty"`
	HandleID             string                 `json:"handle_id,omitempty"`
	KeyID                string                 `json:"key_id,omitempty"`
	PolicyMatched        bool                   `json:"policy_matched"`
	PolicyMismatchReason string                 `json:"policy_mismatch_reason,omitempty"`
	ResolvedSpec         map[string]interface{} `json:"resolved_spec,omitempty"`
	FailureReason        string                 `json:"failure_reason,omitempty"`
	CreatedAt            time.Time              `json:"created_at,omitempty"`
	UpdatedAt            time.Time              `json:"updated_at,omitempty"`
	FulfilledAt          time.Time              `json:"fulfilled_at,omitempty"`
}

type AutokeyHandle struct {
	ID            string                 `json:"id"`
	TenantID      string                 `json:"tenant_id"`
	ServiceName   string                 `json:"service_name"`
	ResourceType  string                 `json:"resource_type"`
	ResourceRef   string                 `json:"resource_ref"`
	HandleName    string                 `json:"handle_name"`
	KeyID         string                 `json:"key_id"`
	TemplateID    string                 `json:"template_id,omitempty"`
	RequestID     string                 `json:"request_id,omitempty"`
	Status        string                 `json:"status"`
	Managed       bool                   `json:"managed"`
	PolicyMatched bool                   `json:"policy_matched"`
	Spec          map[string]interface{} `json:"spec,omitempty"`
	CreatedAt     time.Time              `json:"created_at,omitempty"`
	UpdatedAt     time.Time              `json:"updated_at,omitempty"`
}

type AutokeySummary struct {
	TenantID            string                  `json:"tenant_id"`
	Enabled             bool                    `json:"enabled"`
	Mode                string                  `json:"mode"`
	TemplateCount       int                     `json:"template_count"`
	ServicePolicyCount  int                     `json:"service_policy_count"`
	HandleCount         int                     `json:"handle_count"`
	PendingApprovals    int                     `json:"pending_approvals"`
	Provisioned24h      int                     `json:"provisioned_24h"`
	DeniedCount         int                     `json:"denied_count"`
	FailedCount         int                     `json:"failed_count"`
	PolicyMatchedCount  int                     `json:"policy_matched_count"`
	PolicyMismatchCount int                     `json:"policy_mismatch_count"`
	Services            []AutokeyServiceSummary `json:"services"`
}

type AutokeyServiceSummary struct {
	ServiceName         string `json:"service_name"`
	HandleCount         int    `json:"handle_count"`
	PendingApprovals    int    `json:"pending_approvals"`
	Provisioned24h      int    `json:"provisioned_24h"`
	PolicyMismatchCount int    `json:"policy_mismatch_count"`
}

type CreateAutokeyRequestInput struct {
	TenantID           string            `json:"tenant_id"`
	ServiceName        string            `json:"service_name"`
	ResourceType       string            `json:"resource_type"`
	ResourceRef        string            `json:"resource_ref"`
	TemplateID         string            `json:"template_id,omitempty"`
	HandleName         string            `json:"handle_name,omitempty"`
	KeyName            string            `json:"key_name,omitempty"`
	RequestedAlgorithm string            `json:"requested_algorithm,omitempty"`
	RequestedKeyType   string            `json:"requested_key_type,omitempty"`
	RequestedPurpose   string            `json:"requested_purpose,omitempty"`
	Tags               []string          `json:"tags,omitempty"`
	Labels             map[string]string `json:"labels,omitempty"`
	Justification      string            `json:"justification,omitempty"`
	RequesterID        string            `json:"requester_id,omitempty"`
	RequesterEmail     string            `json:"requester_email,omitempty"`
	RequesterIP        string            `json:"requester_ip,omitempty"`
}

type KeyCoreCreateKeyRequest struct {
	TenantID       string            `json:"tenant_id"`
	Name           string            `json:"name"`
	Algorithm      string            `json:"algorithm"`
	KeyType        string            `json:"key_type"`
	Purpose        string            `json:"purpose"`
	Tags           []string          `json:"tags,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	ExportAllowed  bool              `json:"export_allowed"`
	ActivationMode string            `json:"activation_mode,omitempty"`
	IVMode         string            `json:"iv_mode,omitempty"`
	CreatedBy      string            `json:"created_by,omitempty"`
	OpsLimit       int64             `json:"ops_limit,omitempty"`
	OpsLimitWindow string            `json:"ops_limit_window,omitempty"`
}

type KeyCoreCreateKeyResponse struct {
	KeyID     string `json:"key_id"`
	TenantID  string `json:"tenant_id"`
	KCV       string `json:"kcv"`
	RequestID string `json:"request_id,omitempty"`
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
