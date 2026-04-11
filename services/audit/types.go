package main

import "time"

// CategoryGroup is the FIPS 140-3 aligned functional category for an audit event.
// Values are one of: authentication, key_management, cryptographic_operations,
// data_protection, certificate_management, policy_and_governance,
// system_administration, network_and_access, financial, supply_chain,
// quantum, cloud_integration.
type CategoryGroup = string

const (
	CatAuthentication         CategoryGroup = "authentication"
	CatKeyManagement          CategoryGroup = "key_management"
	CatCryptographicOps       CategoryGroup = "cryptographic_operations"
	CatDataProtection         CategoryGroup = "data_protection"
	CatCertificateManagement  CategoryGroup = "certificate_management"
	CatPolicyAndGovernance    CategoryGroup = "policy_and_governance"
	CatSystemAdministration   CategoryGroup = "system_administration"
	CatNetworkAndAccess       CategoryGroup = "network_and_access"
	CatFinancial              CategoryGroup = "financial"
	CatSupplyChain            CategoryGroup = "supply_chain"
	CatQuantum                CategoryGroup = "quantum"
	CatCloudIntegration       CategoryGroup = "cloud_integration"
)

type AuditEvent struct {
	ID            string                 `json:"id"`
	TenantID      string                 `json:"tenant_id"`
	Sequence      int64                  `json:"sequence"`
	ChainHash     string                 `json:"chain_hash"`
	PreviousHash  string                 `json:"previous_hash"`
	// HMACSig is HMAC-SHA256(chain_hash, service_signing_key).
	// Provides event authenticity in addition to hash-chain integrity.
	HMACSig       string                 `json:"hmac_sig,omitempty"`
	// CategoryGroup is the FIPS 140-3 aligned functional category.
	CategoryGroup string                 `json:"category_group,omitempty"`
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
	// EventSigningKey is a 32-byte HMAC-SHA256 key used to sign each audit event.
	// Loaded from AUDIT_EVENT_SIGNING_KEY_B64 env var; auto-generated if missing.
	EventSigningKey     []byte
	DedupWindowSeconds  int
	EscalationThreshold int
	EscalationMinutes   int
}

// ── Merkle Tree Types ───────────────────────────────────────

type MerkleEpoch struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	EpochNumber int       `json:"epoch_number"`
	SeqFrom     int64     `json:"seq_from"`
	SeqTo       int64     `json:"seq_to"`
	LeafCount   int       `json:"leaf_count"`
	TreeRoot    string    `json:"tree_root"`
	// PreviousEpochRoot is the tree_root of epoch N-1, enabling linear proof chain.
	PreviousEpochRoot string `json:"previous_epoch_root,omitempty"`
	// EpochHash = SHA256(previous_epoch_root || tree_root) — tamper-evident linkage.
	EpochHash string `json:"epoch_hash,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type MerkleLeaf struct {
	EpochID   string `json:"epoch_id"`
	TenantID  string `json:"tenant_id"`
	LeafIndex int    `json:"leaf_index"`
	EventID   string `json:"event_id"`
	Sequence  int64  `json:"sequence"`
	LeafHash  string `json:"leaf_hash"`
}

type MerkleEpochResult struct {
	Epoch  MerkleEpoch `json:"epoch"`
	Leaves int         `json:"leaves"`
}

type MerkleProofResponse struct {
	EventID   string         `json:"event_id"`
	Sequence  int64          `json:"sequence"`
	EpochID   string         `json:"epoch_id"`
	LeafHash  string         `json:"leaf_hash"`
	LeafIndex int            `json:"leaf_index"`
	Siblings  []ProofSibling `json:"siblings"`
	Root      string         `json:"root"`
}
