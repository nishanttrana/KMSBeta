package main

import "time"

type AuditEvent struct {
	ID            string                 `json:"id"`
	TenantID      string                 `json:"tenant_id"`
	Sequence      int64                  `json:"sequence"`
	ChainHash     string                 `json:"chain_hash"`
	PreviousHash  string                 `json:"previous_hash"`
	Timestamp     time.Time              `json:"timestamp"`
	Service       string                 `json:"service"`
	Action        string                 `json:"action"`
	ActorID       string                 `json:"actor_id"`
	ActorType     string                 `json:"actor_type"`
	TargetType    string                 `json:"target_type"`
	TargetID      string                 `json:"target_id"`
	Method        string                 `json:"method"`
	Endpoint      string                 `json:"endpoint"`
	SourceIP      string                 `json:"source_ip"`
	UserAgent     string                 `json:"user_agent"`
	RequestHash   string                 `json:"request_hash"`
	CorrelationID string                 `json:"correlation_id"`
	ParentEventID string                 `json:"parent_event_id"`
	SessionID     string                 `json:"session_id"`
	Result        string                 `json:"result"`
	StatusCode    int                    `json:"status_code"`
	ErrorMessage  string                 `json:"error_message"`
	DurationMS    float64                `json:"duration_ms"`
	FIPSCompliant bool                   `json:"fips_compliant"`
	ApprovalID    string                 `json:"approval_id"`
	RiskScore     int                    `json:"risk_score"`
	Tags          []string               `json:"tags"`
	NodeID        string                 `json:"node_id"`
	Details       map[string]interface{} `json:"details"`
	CreatedAt     time.Time              `json:"created_at"`
}

type Alert struct {
	ID                 string                 `json:"id"`
	TenantID           string                 `json:"tenant_id"`
	AuditEventID       string                 `json:"audit_event_id"`
	Severity           string                 `json:"severity"`
	Category           string                 `json:"category"`
	Title              string                 `json:"title"`
	Description        string                 `json:"description"`
	SourceService      string                 `json:"source_service"`
	ActorID            string                 `json:"actor_id"`
	TargetID           string                 `json:"target_id"`
	RiskScore          int                    `json:"risk_score"`
	Status             string                 `json:"status"`
	AcknowledgedBy     string                 `json:"acknowledged_by"`
	AcknowledgedAt     time.Time              `json:"acknowledged_at"`
	ResolvedBy         string                 `json:"resolved_by"`
	ResolvedAt         time.Time              `json:"resolved_at"`
	ResolutionNote     string                 `json:"resolution_note"`
	DispatchedChannels []string               `json:"dispatched_channels"`
	DispatchStatus     map[string]interface{} `json:"dispatch_status"`
	DedupKey           string                 `json:"dedup_key"`
	OccurrenceCount    int                    `json:"occurrence_count"`
	EscalatedFrom      string                 `json:"escalated_from"`
	EscalatedAt        time.Time              `json:"escalated_at"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}

type AlertStats struct {
	OpenBySeverity map[string]int `json:"open_by_severity"`
	TotalOpen      int            `json:"total_open"`
	TotalAck       int            `json:"total_acknowledged"`
	TotalResolved  int            `json:"total_resolved"`
}

type AlertRule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Condition string `json:"condition"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
}

type DispatchPlan struct {
	Channels []string               `json:"channels"`
	Status   map[string]interface{} `json:"status"`
}

type AuditConfig struct {
	FailClosed          bool
	WALPath             string
	WALMaxSizeMB        int64
	WALHMACKey          []byte
	DedupWindowSeconds  int
	EscalationThreshold int
	EscalationMinutes   int
}
