package main

import (
	"context"
	"time"
)

const (
	severityCritical = "critical"
	severityHigh     = "high"
	severityWarning  = "warning"
	severityInfo     = "info"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type AuditClient interface {
	ListEvents(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
	GetEvent(ctx context.Context, tenantID string, id string) (map[string]interface{}, error)
}

type ComplianceClient interface {
	GetPosture(ctx context.Context, tenantID string) (map[string]interface{}, error)
}

type Alert struct {
	ID             string            `json:"id"`
	TenantID       string            `json:"tenant_id"`
	AuditEventID   string            `json:"audit_event_id"`
	AuditAction    string            `json:"audit_action"`
	Severity       string            `json:"severity"`
	Category       string            `json:"category"`
	Title          string            `json:"title"`
	Description    string            `json:"description"`
	Service        string            `json:"service"`
	ActorID        string            `json:"actor_id"`
	ActorType      string            `json:"actor_type"`
	TargetType     string            `json:"target_type"`
	TargetID       string            `json:"target_id"`
	SourceIP       string            `json:"source_ip"`
	Status         string            `json:"status"`
	AcknowledgedBy string            `json:"acknowledged_by"`
	AcknowledgedAt time.Time         `json:"acknowledged_at"`
	ResolvedBy     string            `json:"resolved_by"`
	ResolvedAt     time.Time         `json:"resolved_at"`
	ResolutionNote string            `json:"resolution_note"`
	IncidentID     string            `json:"incident_id"`
	CorrelationID  string            `json:"correlation_id"`
	RuleID         string            `json:"rule_id"`
	IsEscalated    bool              `json:"is_escalated"`
	EscalatedFrom  string            `json:"escalated_from"`
	DedupCount     int               `json:"dedup_count"`
	ChannelsSent   []string          `json:"channels_sent"`
	ChannelStatus  map[string]string `json:"channel_status"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

type Incident struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Title        string    `json:"title"`
	Severity     string    `json:"severity"`
	Status       string    `json:"status"`
	AlertCount   int       `json:"alert_count"`
	FirstAlertAt time.Time `json:"first_alert_at"`
	LastAlertAt  time.Time `json:"last_alert_at"`
	AssignedTo   string    `json:"assigned_to"`
	Notes        string    `json:"notes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type AlertRule struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Name         string    `json:"name"`
	Condition    string    `json:"condition"`
	Severity     string    `json:"severity"`
	EventPattern string    `json:"event_pattern"`
	Threshold    int       `json:"threshold"`
	WindowSecond int       `json:"window_seconds"`
	Channels     []string  `json:"channels"`
	Enabled      bool      `json:"enabled"`
	Expression   string    `json:"expression"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type SeverityOverride struct {
	TenantID    string    `json:"tenant_id"`
	AuditAction string    `json:"audit_action"`
	Severity    string    `json:"severity"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type NotificationChannel struct {
	TenantID  string                 `json:"tenant_id"`
	Name      string                 `json:"name"`
	Enabled   bool                   `json:"enabled"`
	Config    map[string]interface{} `json:"config"`
	UpdatedAt time.Time              `json:"updated_at"`
}

type ReportTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Formats     []string `json:"formats"`
}

type ReportJob struct {
	ID                string                 `json:"id"`
	TenantID          string                 `json:"tenant_id"`
	TemplateID        string                 `json:"template_id"`
	Format            string                 `json:"format"`
	Status            string                 `json:"status"`
	Filters           map[string]interface{} `json:"filters"`
	ResultContent     string                 `json:"result_content"`
	ResultContentType string                 `json:"result_content_type"`
	RequestedBy       string                 `json:"requested_by"`
	Error             string                 `json:"error"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	CompletedAt       time.Time              `json:"completed_at"`
}

type ScheduledReport struct {
	ID         string                 `json:"id"`
	TenantID   string                 `json:"tenant_id"`
	Name       string                 `json:"name"`
	TemplateID string                 `json:"template_id"`
	Format     string                 `json:"format"`
	Schedule   string                 `json:"schedule"`
	Filters    map[string]interface{} `json:"filters"`
	Recipients []string               `json:"recipients"`
	Enabled    bool                   `json:"enabled"`
	LastRunAt  time.Time              `json:"last_run_at"`
	NextRunAt  time.Time              `json:"next_run_at"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

type ErrorTelemetryEvent struct {
	ID          string                 `json:"id"`
	TenantID    string                 `json:"tenant_id"`
	Source      string                 `json:"source"`
	Service     string                 `json:"service"`
	Component   string                 `json:"component"`
	Level       string                 `json:"level"`
	Message     string                 `json:"message"`
	StackTrace  string                 `json:"stack_trace"`
	Context     map[string]interface{} `json:"context"`
	Fingerprint string                 `json:"fingerprint"`
	RequestID   string                 `json:"request_id"`
	ReleaseTag  string                 `json:"release_tag"`
	BuildVer    string                 `json:"build_version"`
	CreatedAt   time.Time              `json:"created_at"`
}

type ErrorTelemetryQuery struct {
	Source      string
	Service     string
	Component   string
	Level       string
	Fingerprint string
	RequestID   string
	From        time.Time
	To          time.Time
	Limit       int
	Offset      int
}

type AlertQuery struct {
	Severity   string
	Status     string
	Action     string
	TargetType string
	TargetID   string
	From       time.Time
	To         time.Time
	Limit      int
	Offset     int
}
