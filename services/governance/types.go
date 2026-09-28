package main

import "time"

type ApprovalPolicy struct {
	ID                   string    `json:"id"`
	TenantID             string    `json:"tenant_id"`
	Name                 string    `json:"name"`
	Description          string    `json:"description"`
	Scope                string    `json:"scope"`
	TriggerActions       []string  `json:"trigger_actions"`
	QuorumMode           string    `json:"quorum_mode"`
	RequiredApprovals    int       `json:"required_approvals"`
	TotalApprovers       int       `json:"total_approvers"`
	ApproverRoles        []string  `json:"approver_roles"`
	ApproverUsers        []string  `json:"approver_users"`
	TimeoutHours         int       `json:"timeout_hours"`
	EscalationHours      int       `json:"escalation_hours"`
	EscalationTo         []string  `json:"escalation_to"`
	RetentionDays        int       `json:"retention_days"`
	NotificationChannels []string  `json:"notification_channels"`
	Status               string    `json:"status"`
	CreatedAt            time.Time `json:"created_at"`
}

type ApprovalRequest struct {
	ID                string                 `json:"id"`
	TenantID          string                 `json:"tenant_id"`
	PolicyID          string                 `json:"policy_id"`
	Action            string                 `json:"action"`
	TargetType        string                 `json:"target_type"`
	TargetID          string                 `json:"target_id"`
	TargetDetails     map[string]interface{} `json:"target_details"`
	RequesterID       string                 `json:"requester_id"`
	RequesterEmail    string                 `json:"requester_email"`
	RequesterIP       string                 `json:"requester_ip"`
	Status            string                 `json:"status"`
	RequiredApprovals int                    `json:"required_approvals"`
	CurrentApprovals  int                    `json:"current_approvals"`
	CurrentDenials    int                    `json:"current_denials"`
	CreatedAt         time.Time              `json:"created_at"`
	ExpiresAt         time.Time              `json:"expires_at"`
	ResolvedAt        time.Time              `json:"resolved_at"`
	RetainUntil       time.Time              `json:"retain_until"`
	CallbackService   string                 `json:"callback_service"`
	CallbackAction    string                 `json:"callback_action"`
	CallbackPayload   map[string]interface{} `json:"callback_payload"`
}

type ApprovalVote struct {
	ID            string    `json:"id"`
	RequestID     string    `json:"request_id"`
	TenantID      string    `json:"tenant_id"`
	ApproverID    string    `json:"approver_id"`
	ApproverEmail string    `json:"approver_email"`
	Vote          string    `json:"vote"`
	VoteMethod    string    `json:"vote_method"`
	Comment       string    `json:"comment"`
	TokenHash     []byte    `json:"-"`
	VotedAt       time.Time `json:"voted_at"`
	IPAddress     string    `json:"ip_address"`
}

type ApprovalToken struct {
	ID            string    `json:"id"`
	RequestID     string    `json:"request_id"`
	ApproverEmail string    `json:"approver_email"`
	TokenHash     []byte    `json:"-"`
	Action        string    `json:"action"`
	Used          bool      `json:"used"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
}

type CreateApprovalRequestInput struct {
	TenantID        string                 `json:"tenant_id"`
	PolicyID        string                 `json:"policy_id"`
	Action          string                 `json:"action"`
	TargetType      string                 `json:"target_type"`
	TargetID        string                 `json:"target_id"`
	TargetDetails   map[string]interface{} `json:"target_details"`
	RequesterID     string                 `json:"requester_id"`
	RequesterEmail  string                 `json:"requester_email"`
	RequesterIP     string                 `json:"requester_ip"`
	CallbackService string                 `json:"callback_service"`
	CallbackAction  string                 `json:"callback_action"`
	CallbackPayload map[string]interface{} `json:"callback_payload"`
}

type VoteInput struct {
	TenantID      string `json:"tenant_id"`
	RequestID     string `json:"request_id"`
	Vote          string `json:"vote"`
	Comment       string `json:"comment"`
	Token         string `json:"token"`
	ChallengeCode string `json:"challenge_code"`
	ApproverID    string `json:"approver_id"`
	ApproverEmail string `json:"approver_email"`
	VoteMethod    string `json:"vote_method"`
	IPAddress     string `json:"ip_address"`
	// Set only by the handler after authenticating the caller: the approver
	// identity above came from the verified token, not the request body.
	VerifiedIdentity bool `json:"-"`
}

type ApprovalRequestDetails struct {
	Request ApprovalRequest `json:"request"`
	Votes   []ApprovalVote  `json:"votes"`
}

type CreateKeyApprovalInput struct {
	TenantID        string                 `json:"tenant_id"`
	PolicyID        string                 `json:"policy_id"`
	KeyID           string                 `json:"key_id"`
	Operation       string                 `json:"operation"`
	PayloadHash     string                 `json:"payload_hash"`
	RequesterID     string                 `json:"requester_id"`
	RequesterEmail  string                 `json:"requester_email"`
	RequesterIP     string                 `json:"requester_ip"`
	CallbackService string                 `json:"callback_service"`
	CallbackAction  string                 `json:"callback_action"`
	CallbackPayload map[string]interface{} `json:"callback_payload"`
}

type ApprovalStatus struct {
	Status           string    `json:"status"`
	CurrentApprovals int       `json:"current_approvals"`
	CurrentDenials   int       `json:"current_denials"`
	ExpiresAt        time.Time `json:"expires_at"`
	// What was approved, so the requesting service can bind a release to it.
	Action      string `json:"action"`
	TargetType  string `json:"target_type"`
	TargetID    string `json:"target_id"`
	Operation   string `json:"operation,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
}

type GovernanceSettings struct {
	TenantID                   string `json:"tenant_id"`
	ApprovalExpiryMinutes      int    `json:"approval_expiry_minutes"`
	ExpiryCheckIntervalSeconds int    `json:"expiry_check_interval_seconds"`
	ApprovalDeliveryMode       string `json:"approval_delivery_mode"`
	SMTPHost                   string `json:"smtp_host"`
	SMTPPort                   string `json:"smtp_port"`
	SMTPUsername               string `json:"smtp_username"`
	SMTPPassword               string `json:"smtp_password,omitempty"`
	SMTPFrom                   string `json:"smtp_from"`
	SMTPStartTLS               bool   `json:"smtp_starttls"`
	NotifyDashboard            bool   `json:"notify_dashboard"`
	NotifyEmail                bool   `json:"notify_email"`
	NotifySlack                bool   `json:"notify_slack"`
	NotifyTeams                bool   `json:"notify_teams"`
	// Slack and Teams notices go through compliance connections. The URL
	// fields are what an earlier release stored in plaintext; they are never
	// returned or accepted, and the migration moves them into connections
	// (notify_connections.go).
	SlackConnectionID         string    `json:"slack_connection_id"`
	TeamsConnectionID         string    `json:"teams_connection_id"`
	SlackWebhookURL           string    `json:"-"`
	TeamsWebhookURL           string    `json:"-"`
	DeliveryWebhookTimeoutSec int       `json:"delivery_webhook_timeout_seconds"`
	ChallengeResponseEnabled  bool      `json:"challenge_response_enabled"`
	UpdatedBy                 string    `json:"updated_by"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

// GovernanceSystemState is what System Administration shows. Only runtime
// facts and settings the platform enforces are exposed; the `json:"-"`
// fields are legacy columns (network, license, backup schedule, TLS mode, HSM
// and cluster labels, QRNG) that nothing ever read or applied.
type GovernanceSystemState struct {
	TenantID                         string    `json:"tenant_id"`
	FIPSMode                         string    `json:"fips_mode"`
	FIPSModePolicy                   string    `json:"fips_mode_policy"`
	FIPSCryptoLibrary                string    `json:"fips_crypto_library"`
	FIPSLibraryValidated             bool      `json:"fips_library_validated"`
	FIPSRuntimeEnabled               bool      `json:"fips_runtime_enabled"`
	FIPSRuntimeEnforced              bool      `json:"fips_runtime_enforced"`
	FIPSModuleVersion                string    `json:"fips_module_version"`
	FIPSTLSProfile                   string    `json:"fips_tls_profile"`
	FIPSRNGMode                      string    `json:"fips_rng_mode"`
	FIPSEntropySource                string    `json:"fips_entropy_source"`
	FIPSEntropyHealth                string    `json:"fips_entropy_health"`
	FIPSEntropyBitsByte              float64   `json:"-"`
	FIPSEntropyBytes                 int       `json:"fips_entropy_sample_bytes"`
	FIPSEntropyReadUs                int64     `json:"fips_entropy_read_micros"`
	FIPSEntropyAt                    time.Time `json:"fips_entropy_measured_at"`
	HSMMode                          string    `json:"-"`
	ClusterMode                      string    `json:"-"`
	LicenseKey                       string    `json:"-"`
	LicenseStatus                    string    `json:"-"`
	MgmtIP                           string    `json:"-"`
	ClusterIP                        string    `json:"-"`
	DNSServers                       string    `json:"-"`
	NTPServers                       string    `json:"-"`
	TLSMode                          string    `json:"-"`
	TLSCertPEM                       string    `json:"-"`
	TLSKeyPEM                        string    `json:"-"`
	TLSCABundlePEM                   string    `json:"-"`
	BackupSchedule                   string    `json:"-"`
	BackupTarget                     string    `json:"-"`
	BackupRetentionDays              int       `json:"-"`
	BackupEncrypted                  bool      `json:"-"`
	ProxyEndpoint                    string    `json:"-"`
	SNMPTarget                       string    `json:"snmp_target"`
	GoRuntimeVersion                 string    `json:"go_runtime_version"`
	FlightRecorderReady              bool      `json:"flight_recorder_ready"`
	RuntimeSecretReady               bool      `json:"runtime_secret_ready"`
	PostureForceQuorumDestructiveOps bool      `json:"posture_force_quorum_destructive_ops"`
	PostureRequireStepUpAuth         bool      `json:"posture_require_step_up_auth"`
	PosturePauseConnectorSync        bool      `json:"posture_pause_connector_sync"`
	PostureGuardrailPolicyRequired   bool      `json:"posture_guardrail_policy_required"`
	QRNGEnabled                      bool      `json:"-"`
	QRNGDefaultSource                string    `json:"-"`
	QRNGMinEntropyBPB                float64   `json:"-"`
	UpdatedBy                        string    `json:"updated_by"`
	UpdatedAt                        time.Time `json:"updated_at"`
}

type PostureControlPatch struct {
	TenantID                  string `json:"tenant_id"`
	UpdatedBy                 string `json:"updated_by"`
	ForceQuorumDestructiveOps *bool  `json:"force_quorum_destructive_ops"`
	RequireStepUpAuth         *bool  `json:"require_step_up_auth"`
	PauseConnectorSync        *bool  `json:"pause_connector_sync"`
	GuardrailPolicyRequired   *bool  `json:"guardrail_policy_required"`
	Reason                    string `json:"reason"`
	SourceFindingID           string `json:"source_finding_id"`
	SourceActionID            string `json:"source_action_id"`
}

type SystemIntegrityStatus struct {
	TenantID  string            `json:"tenant_id"`
	Status    string            `json:"status"`
	Checks    map[string]string `json:"checks"`
	Timestamp time.Time         `json:"timestamp"`
}

type CreateBackupInput struct {
	TenantID       string `json:"tenant_id"`
	Scope          string `json:"scope"`
	TargetTenantID string `json:"target_tenant_id"`
	BindToHSM      *bool  `json:"bind_to_hsm,omitempty"`
	CreatedBy      string `json:"created_by"`
	// KeySplit, when set, splits a software-mode backup key into one Shamir
	// share per guardian; any Threshold of them restore the backup.
	KeySplit *BackupKeySplit `json:"key_split,omitempty"`
}

type BackupKeySplit struct {
	Threshold int      `json:"threshold"`
	Guardians []string `json:"guardians"`
}

type BackupJob struct {
	ID                    string                 `json:"id"`
	TenantID              string                 `json:"tenant_id"`
	Scope                 string                 `json:"scope"`
	TargetTenantID        string                 `json:"target_tenant_id"`
	Status                string                 `json:"status"`
	BackupFormat          string                 `json:"backup_format"`
	EncryptionAlgorithm   string                 `json:"encryption_algorithm"`
	CiphertextSHA256      string                 `json:"ciphertext_sha256"`
	ArtifactSizeBytes     int64                  `json:"artifact_size_bytes"`
	RowCountTotal         int64                  `json:"row_count_total"`
	TableCount            int                    `json:"table_count"`
	HSMBound              bool                   `json:"hsm_bound"`
	HSMProviderName       string                 `json:"hsm_provider_name,omitempty"`
	HSMSlotID             string                 `json:"hsm_slot_id,omitempty"`
	HSMPartitionLabel     string                 `json:"hsm_partition_label,omitempty"`
	HSMTokenLabel         string                 `json:"hsm_token_label,omitempty"`
	HSMBindingFingerprint string                 `json:"hsm_binding_fingerprint,omitempty"`
	KeyPackage            map[string]interface{} `json:"key_package,omitempty"`
	CreatedBy             string                 `json:"created_by"`
	CreatedAt             time.Time              `json:"created_at"`
	CompletedAt           time.Time              `json:"completed_at"`
	FailureReason         string                 `json:"failure_reason,omitempty"`
	ArtifactCiphertext    []byte                 `json:"-"`
	ArtifactNonce         []byte                 `json:"-"`
	KeyPackageRaw         []byte                 `json:"-"`
}

type RestoreBackupInput struct {
	TenantID            string `json:"tenant_id"`
	ArtifactFileName    string `json:"artifact_file_name"`
	ArtifactContentBase string `json:"artifact_content_base64"`
	KeyFileName         string `json:"key_file_name"`
	KeyContentBase      string `json:"key_content_base64"`
	// KeyShares restores a split backup from guardian share files instead
	// of a key file.
	KeyShares []BackupKeyFile `json:"key_shares,omitempty"`
	CreatedBy string          `json:"created_by"`
}

type RestoreBackupResult struct {
	Scope            string   `json:"scope"`
	TargetTenantID   string   `json:"target_tenant_id,omitempty"`
	RowsRestored     int64    `json:"rows_restored"`
	TablesProcessed  int      `json:"tables_processed"`
	TablesSkipped    []string `json:"tables_skipped,omitempty"`
	ExcludedTables   []string `json:"excluded_tables,omitempty"`
	BackupCapturedAt string   `json:"backup_captured_at,omitempty"`
}
