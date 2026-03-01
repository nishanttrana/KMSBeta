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
}

// NormalizedEvent is the required unified posture schema across all service streams.
type NormalizedEvent struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	TenantID   string                 `json:"tenant_id"`
	Service    string                 `json:"service"`
	Action     string                 `json:"action"`
	Result     string                 `json:"result"`
	Severity   string                 `json:"severity"`
	Actor      string                 `json:"actor"`
	IP         string                 `json:"ip"`
	RequestID  string                 `json:"request_id"`
	ResourceID string                 `json:"resource_id"`
	ErrorCode  string                 `json:"error_code"`
	LatencyMS  float64                `json:"latency_ms"`
	NodeID     string                 `json:"node_id"`
	Details    map[string]interface{} `json:"details"`
	CreatedAt  time.Time              `json:"created_at"`
}

type Finding struct {
	ID                string                 `json:"id"`
	TenantID          string                 `json:"tenant_id"`
	Engine            string                 `json:"engine"`
	FindingType       string                 `json:"finding_type"`
	Title             string                 `json:"title"`
	Description       string                 `json:"description"`
	Severity          string                 `json:"severity"`
	RiskScore         int                    `json:"risk_score"`
	RecommendedAction string                 `json:"recommended_action"`
	AutoActionAllowed bool                   `json:"auto_action_allowed"`
	Status            string                 `json:"status"`
	Fingerprint       string                 `json:"fingerprint"`
	Evidence          map[string]interface{} `json:"evidence"`
	DetectedAt        time.Time              `json:"detected_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	ResolvedAt        time.Time              `json:"resolved_at"`
	SLADueAt          time.Time              `json:"sla_due_at"`
	ReopenCount       int                    `json:"reopen_count"`
}

type RiskSnapshot struct {
	ID              string                 `json:"id"`
	TenantID        string                 `json:"tenant_id"`
	Risk24h         int                    `json:"risk_24h"`
	Risk7d          int                    `json:"risk_7d"`
	PredictiveScore int                    `json:"predictive_score"`
	PreventiveScore int                    `json:"preventive_score"`
	CorrectiveScore int                    `json:"corrective_score"`
	TopSignals      map[string]interface{} `json:"top_signals"`
	CapturedAt      time.Time              `json:"captured_at"`
}

type RemediationAction struct {
	ID                string                 `json:"id"`
	TenantID          string                 `json:"tenant_id"`
	FindingID         string                 `json:"finding_id"`
	ActionType        string                 `json:"action_type"`
	RecommendedAction string                 `json:"recommended_action"`
	SafetyGate        string                 `json:"safety_gate"`
	ApprovalRequired  bool                   `json:"approval_required"`
	ApprovalRequestID string                 `json:"approval_request_id"`
	Status            string                 `json:"status"`
	ExecutedBy        string                 `json:"executed_by"`
	ExecutedAt        time.Time              `json:"executed_at"`
	Evidence          map[string]interface{} `json:"evidence"`
	ResultMessage     string                 `json:"result_message"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

type FindingQuery struct {
	Engine      string
	Status      string
	Severity    string
	FindingType string
	Limit       int
	Offset      int
	From        time.Time
	To          time.Time
}

type RiskQuery struct {
	Limit  int
	Offset int
}

type ActionQuery struct {
	Status     string
	ActionType string
	Limit      int
	Offset     int
}

type SignalSummary struct {
	TotalEvents           int
	FailedAuthCount       int
	FailedCryptoCount     int
	PolicyDenyCount       int
	KeyDeleteCount        int
	CertDeleteCount       int
	QuorumBypassCount     int
	TenantMismatchCount   int
	ClusterDriftCount     int
	ConnectorAuthFlaps    int
	ReplicationRetry      int
	ExpiryBacklogCount    int
	NonApprovedAlgoCount  int
	HSMLatencyAvgMS       float64
	ClusterLagAvgMS       float64
	BYOKEvents            int
	BYOKFailures          int
	BYOKLatencyAvgMS      float64
	HYOKEvents            int
	HYOKFailures          int
	HYOKLatencyAvgMS      float64
	EKMEvents             int
	EKMFailures           int
	EKMLatencyAvgMS       float64
	KMIPEvents            int
	KMIPFailures          int
	KMIPInteropFailures   int
	KMIPLatencyAvgMS      float64
	BitLockerEvents       int
	BitLockerFailures     int
	BitLockerLatencyAvgMS float64
	SDKEvents             int
	SDKFailures           int
	SDKReceiptMissing     int
	SDKLatencyAvgMS       float64
}

type FindingCandidate struct {
	Engine            string
	FindingType       string
	Title             string
	Description       string
	Severity          string
	RiskScore         int
	RecommendedAction string
	AutoActionAllowed bool
	Fingerprint       string
	Evidence          map[string]interface{}
}

type ActionCandidate struct {
	FindingFingerprint string
	ActionType         string
	RecommendedAction  string
	SafetyGate         string
	ApprovalRequired   bool
	Evidence           map[string]interface{}
}
