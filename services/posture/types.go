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
	ID                string                   `json:"id"`
	TenantID          string                   `json:"tenant_id"`
	Engine            string                   `json:"engine"`
	FindingType       string                   `json:"finding_type"`
	Title             string                   `json:"title"`
	Description       string                   `json:"description"`
	Severity          string                   `json:"severity"`
	RiskScore         int                      `json:"risk_score"`
	RecommendedAction string                   `json:"recommended_action"`
	AutoActionAllowed bool                     `json:"auto_action_allowed"`
	Status            string                   `json:"status"`
	Fingerprint       string                   `json:"fingerprint"`
	Evidence          map[string]interface{}   `json:"evidence"`
	DetectedAt        time.Time                `json:"detected_at"`
	UpdatedAt         time.Time                `json:"updated_at"`
	ResolvedAt        time.Time                `json:"resolved_at"`
	SLADueAt          time.Time                `json:"sla_due_at"`
	ReopenCount       int                      `json:"reopen_count"`
	RiskDrivers       []RiskDriverContribution `json:"risk_drivers,omitempty"`
	BlastRadius       BlastRadius              `json:"blast_radius,omitempty"`
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
	ImpactEstimate    RemediationImpact      `json:"impact_estimate,omitempty"`
	RollbackHint      string                 `json:"rollback_hint,omitempty"`
	BlastRadius       BlastRadius            `json:"blast_radius,omitempty"`
	Priority          string                 `json:"priority,omitempty"`
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

type RiskDriverContribution struct {
	ID          string                 `json:"id"`
	Label       string                 `json:"label"`
	Domain      string                 `json:"domain,omitempty"`
	DeltaPoints int                    `json:"delta_points"`
	Severity    string                 `json:"severity"`
	Explanation string                 `json:"explanation"`
	Evidence    map[string]interface{} `json:"evidence,omitempty"`
}

type RiskDriverExplainer struct {
	CurrentRisk24h  int                      `json:"current_risk_24h"`
	PreviousRisk24h int                      `json:"previous_risk_24h"`
	NetDelta        int                      `json:"net_delta"`
	Summary         string                   `json:"summary"`
	Drivers         []RiskDriverContribution `json:"drivers"`
}

type BlastRadius struct {
	Tenants    []string  `json:"tenants,omitempty"`
	Apps       []string  `json:"apps,omitempty"`
	Services   []string  `json:"services,omitempty"`
	Resources  []string  `json:"resources,omitempty"`
	Actors     []string  `json:"actors,omitempty"`
	EventCount int       `json:"event_count"`
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
	Summary    string    `json:"summary,omitempty"`
}

type RemediationImpact struct {
	RiskReduction   int    `json:"risk_reduction"`
	OperationalCost string `json:"operational_cost,omitempty"`
	TimeToApply     string `json:"time_to_apply,omitempty"`
}

type RemediationCockpitGroup struct {
	ID          string              `json:"id"`
	Label       string              `json:"label"`
	Description string              `json:"description,omitempty"`
	Count       int                 `json:"count"`
	Actions     []RemediationAction `json:"actions"`
}

type ValidationBadge struct {
	Domain        string    `json:"domain"`
	Kind          string    `json:"kind"`
	Label         string    `json:"label"`
	Status        string    `json:"status"`
	Detail        string    `json:"detail"`
	LastCheckedAt time.Time `json:"last_checked_at,omitempty"`
	LastSuccessAt time.Time `json:"last_success_at,omitempty"`
	Metric        float64   `json:"metric,omitempty"`
}

type ScenarioSimulation struct {
	ID               string   `json:"id"`
	Label            string   `json:"label"`
	Category         string   `json:"category"`
	ActionType       string   `json:"action_type,omitempty"`
	CurrentRisk24h   int      `json:"current_risk_24h"`
	ProjectedRisk24h int      `json:"projected_risk_24h"`
	RiskDelta        int      `json:"risk_delta"`
	Summary          string   `json:"summary"`
	ImpactEstimate   string   `json:"impact_estimate,omitempty"`
	RollbackHint     string   `json:"rollback_hint,omitempty"`
	ApprovalRequired bool     `json:"approval_required"`
	BasedOn          []string `json:"based_on,omitempty"`
}

type SLAOverview struct {
	OpenCount       int      `json:"open_count"`
	OverdueCount    int      `json:"overdue_count"`
	DueSoonCount    int      `json:"due_soon_count"`
	AverageAgeHours float64  `json:"average_age_hours"`
	BreachedIDs     []string `json:"breached_ids,omitempty"`
}

type PostureDashboard struct {
	Risk               RiskSnapshot              `json:"risk"`
	RecentFindings     []Finding                 `json:"recent_findings"`
	PendingActions     []RemediationAction       `json:"pending_actions"`
	OpenFindings       int                       `json:"open_findings"`
	CriticalFindings   int                       `json:"critical_findings"`
	RiskDrivers        RiskDriverExplainer       `json:"risk_drivers"`
	RemediationCockpit []RemediationCockpitGroup `json:"remediation_cockpit"`
	BlastRadius        []BlastRadius             `json:"blast_radius"`
	ScenarioSimulator  []ScenarioSimulation      `json:"scenario_simulator"`
	ValidationBadges   []ValidationBadge         `json:"validation_badges"`
	SLAOverview        SLAOverview               `json:"sla_overview"`
}
