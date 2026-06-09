package main

import "time"

const (
	controlCategoryAnomaly               = "anomaly"
	controlCategoryOrchestrationWorkflow = "orchestration_workflow"
	controlCategoryOrchestrationRun      = "orchestration_run"
	controlCategoryFederationProvider    = "federation_provider"
	controlCategoryFederationMapping     = "federation_mapping"
	controlCategoryFederationFailover    = "federation_failover"
	controlCategoryEscrowTier            = "escrow_tier"
	controlCategoryEscrowShamir          = "escrow_shamir"
	controlCategoryKDFDerivation         = "kdf_derivation"
	controlCategoryVerification          = "verification"
	controlCategoryAdvancedEncryption    = "advanced_encryption"
	controlCategoryBindingPolicy         = "binding_policy"
	controlCategoryEdgeAgent             = "edge_agent"
	controlCategoryEdgeLease             = "edge_lease"
	controlCategoryEdgeReceipt           = "edge_receipt"
	controlCategorySharingGrant          = "sharing_grant"
	controlCategoryMetadataProfile       = "metadata_profile"
	controlCategoryThreatSignal          = "threat_signal"
)

type EnterpriseControlRecord struct {
	RecordID  string         `json:"record_id"`
	TenantID  string         `json:"tenant_id"`
	Category  string         `json:"category"`
	KeyID     string         `json:"key_id,omitempty"`
	Name      string         `json:"name"`
	Status    string         `json:"status"`
	Severity  string         `json:"severity,omitempty"`
	RiskScore int            `json:"risk_score,omitempty"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type EnterpriseControlQuery struct {
	Category string
	KeyID    string
	Status   string
	Limit    int
	Offset   int
}

type DSPMFinding struct {
	FindingID         string         `json:"finding_id"`
	TenantID          string         `json:"tenant_id"`
	Source            string         `json:"source"`
	FindingType       string         `json:"finding_type"`
	Title             string         `json:"title"`
	Description       string         `json:"description"`
	Severity          string         `json:"severity"`
	RiskScore         int            `json:"risk_score"`
	Status            string         `json:"status"`
	KeyID             string         `json:"key_id,omitempty"`
	RecommendedAction string         `json:"recommended_action"`
	Evidence          map[string]any `json:"evidence,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

type DSPMFindingQuery struct {
	Source      string
	FindingType string
	Status      string
	Severity    string
	KeyID       string
	Limit       int
	Offset      int
}

type AuditChainAnchor struct {
	AnchorID          string         `json:"anchor_id"`
	TenantID          string         `json:"tenant_id"`
	AnchorType        string         `json:"anchor_type"`
	MerkleRoot        string         `json:"merkle_root"`
	PreviousHash      string         `json:"previous_hash,omitempty"`
	AnchorHash        string         `json:"anchor_hash"`
	ExternalReference string         `json:"external_reference,omitempty"`
	Status            string         `json:"status"`
	Metadata          map[string]any `json:"metadata,omitempty"`
	AnchoredAt        time.Time      `json:"anchored_at"`
	VerifiedAt        *time.Time     `json:"verified_at,omitempty"`
}

type KDFDeriveRequest struct {
	TenantID     string `json:"tenant_id"`
	KeyID        string `json:"key_id,omitempty"`
	Algorithm    string `json:"algorithm"`
	SecretBase64 string `json:"secret_base64"`
	SaltBase64   string `json:"salt_base64"`
	InfoBase64   string `json:"info_base64,omitempty"`
	Length       int    `json:"length"`
	Iterations   int    `json:"iterations,omitempty"`
	MemoryKiB    uint32 `json:"memory_kib,omitempty"`
	Parallelism  uint8  `json:"parallelism,omitempty"`
}

type KDFDeriveResponse struct {
	Algorithm          string `json:"algorithm"`
	DerivedKeyBase64   string `json:"derived_key_base64"`
	DerivedKeySHA256   string `json:"derived_key_sha256"`
	Length             int    `json:"length"`
	ParameterSummary   string `json:"parameter_summary"`
	SaltSHA256         string `json:"salt_sha256"`
	SecretNotPersisted bool   `json:"secret_not_persisted"`
}

type ShamirSplitRequest struct {
	TenantID     string `json:"tenant_id"`
	SecretBase64 string `json:"secret_base64"`
	Threshold    int    `json:"threshold"`
	Shares       int    `json:"shares"`
	Context      string `json:"context,omitempty"`
}

type ShamirShare struct {
	Index       int    `json:"index"`
	ShareBase64 string `json:"share_base64"`
	ShareSHA256 string `json:"share_sha256"`
}

type ShamirSplitResponse struct {
	SplitID            string        `json:"split_id"`
	Threshold          int           `json:"threshold"`
	Shares             []ShamirShare `json:"shares"`
	SecretSHA256       string        `json:"secret_sha256"`
	SharesReturnedOnce bool          `json:"shares_returned_once"`
}

type ShamirVerifyRequest struct {
	TenantID string        `json:"tenant_id"`
	SplitID  string        `json:"split_id"`
	Shares   []ShamirShare `json:"shares"`
}

type ShamirVerifyResponse struct {
	Valid        bool   `json:"valid"`
	SecretSHA256 string `json:"secret_sha256,omitempty"`
	Message      string `json:"message"`
}

type EnterpriseComplianceDashboard struct {
	TenantID         string                 `json:"tenant_id"`
	OverallScore     int                    `json:"overall_score"`
	ControlScores    map[string]int         `json:"control_scores"`
	OpenFindings     int                    `json:"open_findings"`
	CriticalFindings int                    `json:"critical_findings"`
	Evidence         map[string]interface{} `json:"evidence"`
	GeneratedAt      time.Time              `json:"generated_at"`
}

type EnterpriseCostOptimization struct {
	TenantID            string                 `json:"tenant_id"`
	WindowDays          int                    `json:"window_days"`
	EstimatedOperations int64                  `json:"estimated_operations"`
	EstimatedCostUSD    float64                `json:"estimated_cost_usd"`
	OptimizationScore   int                    `json:"optimization_score"`
	Recommendations     []string               `json:"recommendations"`
	Evidence            map[string]interface{} `json:"evidence"`
	GeneratedAt         time.Time              `json:"generated_at"`
}
