package main

import "time"

const (
	AgentStatusConnected    = "connected"
	AgentStatusDegraded     = "degraded"
	AgentStatusDisconnected = "disconnected"
)

const (
	DefaultTDEAlgorithm = "RSA-3072"
	DefaultDBEngine     = "mssql"
	DefaultHeartbeatSec = 30
)

type Agent struct {
	ID                   string    `json:"id"`
	TenantID             string    `json:"tenant_id"`
	Name                 string    `json:"name"`
	Role                 string    `json:"role"`
	DBEngine             string    `json:"db_engine"`
	Host                 string    `json:"host"`
	Version              string    `json:"version"`
	Status               string    `json:"status"`
	TDEState             string    `json:"tde_state"`
	HeartbeatIntervalSec int       `json:"heartbeat_interval_sec"`
	LastHeartbeatAt      time.Time `json:"last_heartbeat_at"`
	AssignedKeyID        string    `json:"assigned_key_id"`
	AssignedKeyVersion   string    `json:"assigned_key_version"`
	ConfigVersion        int       `json:"config_version"`
	ConfigVersionAck     int       `json:"config_version_ack"`
	MetadataJSON         string    `json:"metadata_json"`
	TLSClientCN          string    `json:"tls_client_cn"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type DatabaseInstance struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	AgentID         string    `json:"agent_id"`
	Name            string    `json:"name"`
	Engine          string    `json:"engine"`
	Host            string    `json:"host"`
	Port            int       `json:"port"`
	DatabaseName    string    `json:"database_name"`
	Status          string    `json:"status"` // registered, tde_enabled, tde_disabled, key_revoked, error
	TDEEnabled      bool      `json:"tde_enabled"`
	TDEState        string    `json:"tde_state"`
	KeyID           string    `json:"key_id"`
	AutoProvisioned bool      `json:"auto_provisioned"`
	MetadataJSON    string    `json:"metadata_json"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Revocation types
type RevokeTDEKeyRequest struct {
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason"`
}

type RevokeTDEKeyResponse struct {
	KeyID             string   `json:"key_id"`
	AffectedAgentIDs  []string `json:"affected_agent_ids"`
	AffectedDatabases int      `json:"affected_databases"`
}

type RevokeDatabaseTDERequest struct {
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason"`
}

type RevokeDatabaseTDEResponse struct {
	DatabaseID string `json:"database_id"`
	KeyID      string `json:"key_id"`
	Status     string `json:"status"`
}

// Validate deployment types
type ValidateDeploymentRequest struct {
	TenantID    string `json:"tenant_id"`
	AgentID     string `json:"agent_id"`
	Version     string `json:"version"`
	Host        string `json:"host"`
	DBEngine    string `json:"db_engine"`
	Connectivity string `json:"connectivity"` // ok, degraded, failed
}

type ValidateDeploymentResponse struct {
	AgentID  string `json:"agent_id"`
	Status   string `json:"status"` // valid, invalid
	Messages []string `json:"messages"`
}

type TDEKeyRecord struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	KeyCoreKeyID    string    `json:"keycore_key_id"`
	Name            string    `json:"name"`
	Algorithm       string    `json:"algorithm"`
	Status          string    `json:"status"`
	CurrentVersion  string    `json:"current_version"`
	PublicKey       string    `json:"public_key"`
	PublicKeyFormat string    `json:"public_key_format"`
	CreatedBy       string    `json:"created_by"`
	AutoProvisioned bool      `json:"auto_provisioned"`
	MetadataJSON    string    `json:"metadata_json"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	RotatedAt       time.Time `json:"rotated_at"`
	LastAccessedAt  time.Time `json:"last_accessed_at"`
}

type KeyAccessLog struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	KeyID        string    `json:"key_id"`
	AgentID      string    `json:"agent_id"`
	DatabaseID   string    `json:"database_id"`
	Operation    string    `json:"operation"`
	Status       string    `json:"status"`
	ErrorMessage string    `json:"error_message"`
	CreatedAt    time.Time `json:"created_at"`
}

type RegisterAgentRequest struct {
	TenantID             string `json:"tenant_id"`
	AgentID              string `json:"agent_id"`
	Name                 string `json:"name"`
	Role                 string `json:"role"`
	DBEngine             string `json:"db_engine"`
	Host                 string `json:"host"`
	Version              string `json:"version"`
	HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	MetadataJSON         string `json:"metadata_json"`
	AutoProvisionTDE     *bool  `json:"auto_provision_tde"`
}

type AgentHeartbeatRequest struct {
	TenantID         string `json:"tenant_id"`
	Status           string `json:"status"`
	TDEState         string `json:"tde_state"`
	ActiveKeyID      string `json:"active_key_id"`
	ActiveKeyVersion string `json:"active_key_version"`
	ConfigVersionAck int    `json:"config_version_ack"`
	MetadataJSON     string `json:"metadata_json"`
}

type AgentStatus struct {
	Agent               Agent `json:"agent"`
	ManagedDatabases    int   `json:"managed_databases"`
	TDEEnabledDatabases int   `json:"tde_enabled_databases"`
	LastHeartbeatAgeSec int64 `json:"last_heartbeat_age_sec"`
}

type AgentOSMetrics struct {
	Hostname        string  `json:"hostname"`
	OSName          string  `json:"os_name"`
	OSVersion       string  `json:"os_version"`
	Kernel          string  `json:"kernel"`
	Arch            string  `json:"arch"`
	CPUUsagePct     float64 `json:"cpu_usage_pct"`
	MemoryUsagePct  float64 `json:"memory_usage_pct"`
	DiskUsagePct    float64 `json:"disk_usage_pct"`
	Load1           float64 `json:"load_1"`
	UptimeSec       int64   `json:"uptime_sec"`
	AgentRuntimeSec int64   `json:"agent_runtime_sec"`
}

type AgentHealthStatus struct {
	Agent               Agent          `json:"agent"`
	Health              string         `json:"health"`
	LastHeartbeatAgeSec int64          `json:"last_heartbeat_age_sec"`
	Metrics             AgentOSMetrics `json:"metrics"`
	Warnings            []string       `json:"warnings"`
}

type DeployPackageFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode"`
}

type DeployPackage struct {
	AgentID             string              `json:"agent_id"`
	Name                string              `json:"name"`
	DBEngine            string              `json:"db_engine"`
	TargetOS            string              `json:"target_os"`
	CreatedAt           time.Time           `json:"created_at"`
	PKCS11Provider      string              `json:"pkcs11_provider"`
	HeartbeatPath       string              `json:"heartbeat_path"`
	RegisterPath        string              `json:"register_path"`
	RotatePath          string              `json:"rotate_path"`
	SupportedDatabases  []string            `json:"supported_databases"`
	RecommendedProfiles []string            `json:"recommended_profiles"`
	Files               []DeployPackageFile `json:"files"`
}

type RegisterDatabaseRequest struct {
	TenantID         string `json:"tenant_id"`
	DatabaseID       string `json:"database_id"`
	AgentID          string `json:"agent_id"`
	Name             string `json:"name"`
	Engine           string `json:"engine"`
	Host             string `json:"host"`
	Port             int    `json:"port"`
	DatabaseName     string `json:"database_name"`
	TDEEnabled       bool   `json:"tde_enabled"`
	TDEState         string `json:"tde_state"`
	KeyID            string `json:"key_id"`
	MetadataJSON     string `json:"metadata_json"`
	AutoProvisionKey *bool  `json:"auto_provision_key"`
}

type CreateTDEKeyRequest struct {
	TenantID        string `json:"tenant_id"`
	Name            string `json:"name"`
	Algorithm       string `json:"algorithm"`
	CreatedBy       string `json:"created_by"`
	AgentID         string `json:"agent_id"`
	DatabaseID      string `json:"database_id"`
	MetadataJSON    string `json:"metadata_json"`
	AutoProvisioned bool   `json:"auto_provisioned"`
}

type WrapDEKRequest struct {
	TenantID     string `json:"tenant_id"`
	PlaintextB64 string `json:"plaintext"`
	IVB64        string `json:"iv"`
	ReferenceID  string `json:"reference_id"`
	AgentID      string `json:"agent_id"`
	DatabaseID   string `json:"database_id"`
	RequesterID       string `json:"requester_id,omitempty"`
	RequesterEmail    string `json:"requester_email,omitempty"`
	JustificationCode string `json:"justification_code,omitempty"`
	JustificationText string `json:"justification_text,omitempty"`
}

type WrapDEKResponse struct {
	KeyID         string `json:"key_id"`
	Version       int    `json:"version"`
	CiphertextB64 string `json:"ciphertext"`
	IVB64         string `json:"iv"`
	Status            string `json:"status,omitempty"`
	ApprovalRequestID string `json:"approval_request_id,omitempty"`
}

type UnwrapDEKRequest struct {
	TenantID      string `json:"tenant_id"`
	CiphertextB64 string `json:"ciphertext"`
	IVB64         string `json:"iv"`
	AgentID       string `json:"agent_id"`
	DatabaseID    string `json:"database_id"`
	RequesterID       string `json:"requester_id,omitempty"`
	RequesterEmail    string `json:"requester_email,omitempty"`
	JustificationCode string `json:"justification_code,omitempty"`
	JustificationText string `json:"justification_text,omitempty"`
}

type UnwrapDEKResponse struct {
	KeyID        string `json:"key_id"`
	Version      int    `json:"version"`
	PlaintextB64 string `json:"plaintext"`
	Status            string `json:"status,omitempty"`
	ApprovalRequestID string `json:"approval_request_id,omitempty"`
}

type RotateTDEKeyRequest struct {
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason"`
	RequesterID       string `json:"requester_id,omitempty"`
	RequesterEmail    string `json:"requester_email,omitempty"`
	JustificationCode string `json:"justification_code,omitempty"`
	JustificationText string `json:"justification_text,omitempty"`
}

type RotateTDEKeyResponse struct {
	KeyID            string   `json:"key_id"`
	VersionID        string   `json:"version_id"`
	AffectedAgentIDs []string `json:"affected_agent_ids"`
	Status            string   `json:"status,omitempty"`
	ApprovalRequestID string   `json:"approval_request_id,omitempty"`
}

type DeleteAgentRequest struct {
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason"`
}

type DeleteAgentResponse struct {
	AgentID         string   `json:"agent_id"`
	DeletedDatabase int      `json:"deleted_databases"`
	DeletedKeys     int      `json:"deleted_keys"`
	DeletedLogs     int      `json:"deleted_logs"`
	DeletedKeyIDs   []string `json:"deleted_key_ids"`
}

type PublicKeyResponse struct {
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm"`
	PublicKey  string `json:"public_key"`
	Format     string `json:"format"`
	KeyVersion string `json:"key_version"`
}

type BitLockerClient struct {
	ID                   string    `json:"id"`
	TenantID             string    `json:"tenant_id"`
	Name                 string    `json:"name"`
	Host                 string    `json:"host"`
	OSVersion            string    `json:"os_version"`
	Status               string    `json:"status"`
	Health               string    `json:"health"`
	ProtectionStatus     string    `json:"protection_status"`
	EncryptionPercentage float64   `json:"encryption_percentage"`
	MountPoint           string    `json:"mount_point"`
	HeartbeatIntervalSec int       `json:"heartbeat_interval_sec"`
	LastHeartbeatAt      time.Time `json:"last_heartbeat_at"`
	TPMPresent           bool      `json:"tpm_present"`
	TPMReady             bool      `json:"tpm_ready"`
	JWTSubject           string    `json:"jwt_subject"`
	TLSClientCN          string    `json:"tls_client_cn"`
	MetadataJSON         string    `json:"metadata_json"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type RegisterBitLockerClientRequest struct {
	TenantID             string `json:"tenant_id"`
	ClientID             string `json:"client_id"`
	Name                 string `json:"name"`
	Host                 string `json:"host"`
	OSVersion            string `json:"os_version"`
	MountPoint           string `json:"mount_point"`
	HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	MetadataJSON         string `json:"metadata_json"`
}

type BitLockerHeartbeatRequest struct {
	TenantID             string  `json:"tenant_id"`
	Status               string  `json:"status"`
	Health               string  `json:"health"`
	ProtectionStatus     string  `json:"protection_status"`
	EncryptionPercentage float64 `json:"encryption_percentage"`
	MountPoint           string  `json:"mount_point"`
	TPMPresent           bool    `json:"tpm_present"`
	TPMReady             bool    `json:"tpm_ready"`
	MetadataJSON         string  `json:"metadata_json"`
}

type BitLockerOperationRequest struct {
	TenantID    string                 `json:"tenant_id"`
	Operation   string                 `json:"operation"`
	RequestedBy string                 `json:"requested_by"`
	RequestID   string                 `json:"request_id"`
	Params      map[string]interface{} `json:"params"`
}

type BitLockerJob struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	ClientID       string    `json:"client_id"`
	Operation      string    `json:"operation"`
	ParamsJSON     string    `json:"params_json"`
	Status         string    `json:"status"`
	RequestedBy    string    `json:"requested_by"`
	RequestID      string    `json:"request_id"`
	RequestedAt    time.Time `json:"requested_at"`
	DispatchedAt   time.Time `json:"dispatched_at"`
	CompletedAt    time.Time `json:"completed_at"`
	ResultJSON     string    `json:"result_json"`
	ErrorMessage   string    `json:"error_message"`
	RecoveryKeyRef string    `json:"recovery_key_ref"`
}

type BitLockerJobResultRequest struct {
	TenantID         string                 `json:"tenant_id"`
	Status           string                 `json:"status"`
	ProtectionStatus string                 `json:"protection_status"`
	Result           map[string]interface{} `json:"result"`
	ErrorMessage     string                 `json:"error_message"`
	RecoveryKey      string                 `json:"recovery_key"`
	ProtectorID      string                 `json:"protector_id"`
	VolumeMountPoint string                 `json:"volume_mount_point"`
}

type BitLockerRecoveryKeyRecord struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	ClientID         string    `json:"client_id"`
	JobID            string    `json:"job_id"`
	VolumeMountPoint string    `json:"volume_mount_point"`
	ProtectorID      string    `json:"protector_id"`
	KeyFingerprint   string    `json:"key_fingerprint"`
	KeyMasked        string    `json:"key_masked"`
	WrappedDEK       string    `json:"wrapped_dek"`
	WrappedDEKIV     string    `json:"wrapped_dek_iv"`
	Ciphertext       string    `json:"ciphertext"`
	DataIV           string    `json:"data_iv"`
	Source           string    `json:"source"`
	CreatedAt        time.Time `json:"created_at"`
}

type BitLockerRecoveryKeyView struct {
	ID               string    `json:"id"`
	ClientID         string    `json:"client_id"`
	VolumeMountPoint string    `json:"volume_mount_point"`
	ProtectorID      string    `json:"protector_id"`
	KeyFingerprint   string    `json:"key_fingerprint"`
	KeyMasked        string    `json:"key_masked"`
	Source           string    `json:"source"`
	CreatedAt        time.Time `json:"created_at"`
}

type DeleteBitLockerClientRequest struct {
	TenantID      string `json:"tenant_id"`
	Reason        string `json:"reason"`
	ConfirmBackup bool   `json:"confirm_backup"`
}

type DeleteBitLockerClientResponse struct {
	ClientID                string `json:"client_id"`
	DeletedClients          int    `json:"deleted_clients"`
	DeletedJobs             int    `json:"deleted_jobs"`
	DeletedRecoveryKeyCount int    `json:"deleted_recovery_keys"`
}

type BitLockerDeletePreview struct {
	ClientID              string    `json:"client_id"`
	ClientName            string    `json:"client_name"`
	Host                  string    `json:"host"`
	LatestRecoveryKey     string    `json:"latest_recovery_key"`
	LatestRecoveryMasked  string    `json:"latest_recovery_key_masked"`
	LatestRecoveryAt      time.Time `json:"latest_recovery_at"`
	RecoveryKeysAvailable int       `json:"recovery_keys_available"`
}

type BitLockerNetworkScanRequest struct {
	TenantID      string `json:"tenant_id"`
	IPRange       string `json:"ip_range"`
	PortTimeoutMS int    `json:"port_timeout_ms"`
	MaxHosts      int    `json:"max_hosts"`
	Concurrency   int    `json:"concurrency"`
	RequireWinRM  bool   `json:"require_winrm"`
}

type BitLockerNetworkCandidate struct {
	IP             string `json:"ip"`
	Host           string `json:"host"`
	OSGuess        string `json:"os_guess"`
	Confidence     string `json:"confidence"`
	SMBReachable   bool   `json:"smb_reachable"`
	WinRMReachable bool   `json:"winrm_reachable"`
	PortsOpen      []int  `json:"ports_open"`
}

type BitLockerNetworkScanResult struct {
	IPRange      string                      `json:"ip_range"`
	ScannedHosts int                         `json:"scanned_hosts"`
	WindowsHosts int                         `json:"windows_hosts"`
	Candidates   []BitLockerNetworkCandidate `json:"candidates"`
	DurationMS   int64                       `json:"duration_ms"`
}

// Azure EKM — Vecta KMS acts as external key provider for Azure services
type AzureEKMConfig struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	AzureTenantID  string    `json:"azure_tenant_id"`
	SubscriptionID string    `json:"subscription_id"`
	ResourceGroup  string    `json:"resource_group"`
	VaultName      string    `json:"vault_name"`
	VaultURL       string    `json:"vault_url"`
	ManagedHSMName string    `json:"managed_hsm_name,omitempty"`
	ManagedHSMURL  string    `json:"managed_hsm_url,omitempty"`
	ClientID       string    `json:"client_id"`
	ClientSecret   string    `json:"client_secret"`
	AuthMode       string    `json:"auth_mode"`
	Status         string    `json:"status"`
	KeyMappings    int       `json:"key_mappings"`
	LastSyncAt     time.Time `json:"last_sync_at"`
	CreatedAt      time.Time `json:"created_at"`
}

type AzureKeyMapping struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	ConfigID        string    `json:"config_id"`
	VectaKeyID      string    `json:"vecta_key_id"`
	AzureKeyName    string    `json:"azure_key_name"`
	AzureKeyVersion string    `json:"azure_key_version"`
	AzureKeyID      string    `json:"azure_key_id"`
	Purpose         string    `json:"purpose"`
	SyncStatus      string    `json:"sync_status"`
	LastSyncAt      time.Time `json:"last_sync_at"`
	CreatedAt       time.Time `json:"created_at"`
}

type AzureSyncResult struct {
	MappingID  string `json:"mapping_id"`
	Status     string `json:"status"`
	AzureKeyID string `json:"azure_key_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

type CreateAzureEKMConfigRequest struct {
	TenantID       string `json:"tenant_id"`
	AzureTenantID  string `json:"azure_tenant_id"`
	SubscriptionID string `json:"subscription_id"`
	ResourceGroup  string `json:"resource_group"`
	VaultName      string `json:"vault_name"`
	VaultURL       string `json:"vault_url"`
	ManagedHSMName string `json:"managed_hsm_name,omitempty"`
	ManagedHSMURL  string `json:"managed_hsm_url,omitempty"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	AuthMode       string `json:"auth_mode"`
}

type CreateAzureKeyMappingRequest struct {
	TenantID   string `json:"tenant_id"`
	ConfigID   string `json:"config_id"`
	VectaKeyID string `json:"vecta_key_id"`
	AzureKeyName string `json:"azure_key_name"`
	Purpose    string `json:"purpose"`
}

type AzureWrapUnwrapRequest struct {
	TenantID  string `json:"tenant_id"`
	Algorithm string `json:"algorithm"`
	ValueB64  string `json:"value"`
}

// Google CSE — Vecta KMS acts as KACLS (Key Access Control List Service) for Google Workspace
type GoogleCSEConfig struct {
	ID                        string    `json:"id"`
	TenantID                  string    `json:"tenant_id"`
	GoogleWorkspaceCustomerID string    `json:"google_workspace_customer_id"`
	ServiceAccountEmail       string    `json:"service_account_email"`
	ServiceAccountKeyJSON     string    `json:"service_account_key_json"` // encrypted at rest
	AllowedDomains            []string  `json:"allowed_domains"`         // e.g., ["company.com"]
	KACLSEndpoint             string    `json:"kacls_endpoint"`          // public URL where Google calls us
	Status                    string    `json:"status"`
	KeyCount                  int       `json:"key_count"`
	LastActivityAt            time.Time `json:"last_activity_at"`
	CreatedAt                 time.Time `json:"created_at"`
}

type GoogleCSEKey struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	ConfigID     string    `json:"config_id"`
	KeyName      string    `json:"key_name"`
	VectaKeyID   string    `json:"vecta_key_id"`  // Backing key in Vecta KMS
	GoogleKeyURI string    `json:"google_key_uri"` // URI Google uses to reference this key
	Purpose      string    `json:"purpose"`        // "gmail", "drive", "calendar", "meet"
	Status       string    `json:"status"`         // "active", "disabled", "destroyed"
	WrapCount    int64     `json:"wrap_count"`
	UnwrapCount  int64     `json:"unwrap_count"`
	LastUsedAt   time.Time `json:"last_used_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// KACLS API types per Google CSE spec
type KACLSWrapRequest struct {
	Authentication string `json:"authentication"` // JWT from Google
	Authorization  string `json:"authorization"`  // JWT with user/resource claims
	Key            string `json:"key"`            // base64url DEK to wrap
	Reason         string `json:"reason,omitempty"`
}

type KACLSWrapResponse struct {
	WrappedKey string `json:"wrapped_key"` // base64url wrapped DEK
}

type KACLSUnwrapRequest struct {
	Authentication string `json:"authentication"`
	Authorization  string `json:"authorization"`
	WrappedKey     string `json:"wrapped_key"`
	Reason         string `json:"reason,omitempty"`
}

type KACLSUnwrapResponse struct {
	Key string `json:"key"` // base64url unwrapped DEK
}

type KACLSStatusResponse struct {
	ServerType string `json:"server_type"` // "KACLS"
	Vendor     string `json:"vendor"`      // "Vecta KMS"
	Version    string `json:"version"`
	Name       string `json:"name"`
}

type KACLSPrivilegedUnwrapRequest struct {
	Authentication string `json:"authentication"`
	WrappedKey     string `json:"wrapped_key"`
	Reason         string `json:"reason"` // must be "ADMIN_ACCESS" or "LEGAL_HOLD"
}

type CreateGoogleCSEConfigRequest struct {
	TenantID                  string   `json:"tenant_id"`
	GoogleWorkspaceCustomerID string   `json:"google_workspace_customer_id"`
	ServiceAccountEmail       string   `json:"service_account_email"`
	ServiceAccountKeyJSON     string   `json:"service_account_key_json"`
	AllowedDomains            []string `json:"allowed_domains"`
	KACLSEndpoint             string   `json:"kacls_endpoint"`
}

type CreateGoogleCSEKeyRequest struct {
	TenantID   string `json:"tenant_id"`
	ConfigID   string `json:"config_id"`
	KeyName    string `json:"key_name"`
	VectaKeyID string `json:"vecta_key_id"`
	Purpose    string `json:"purpose"`
}

type SDKProviderSummary struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	ArtifactName     string   `json:"artifact_name"`
	Version          string   `json:"version"`
	Status           string   `json:"status"`
	SizeLabel        string   `json:"size_label"`
	Transport        string   `json:"transport"`
	SessionsActive   int      `json:"sessions_active"`
	Ops24h           int64    `json:"ops_24h"`
	ClientsConnected int      `json:"clients_connected"`
	TopMechanism     string   `json:"top_mechanism"`
	Platforms        []string `json:"platforms"`
	Capabilities     []string `json:"capabilities"`
}

type SDKMechanismUsage struct {
	Mechanism string  `json:"mechanism"`
	Ops24h    int64   `json:"ops_24h"`
	Percent   float64 `json:"percent"`
}

type SDKClient struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SDK       string `json:"sdk"`
	Mechanism string `json:"mechanism"`
	Ops24h    int64  `json:"ops_24h"`
	Status    string `json:"status"`
}

type SDKOverview struct {
	RefreshedAt string               `json:"refreshed_at"`
	Providers   []SDKProviderSummary `json:"providers"`
	Mechanisms  []SDKMechanismUsage  `json:"mechanisms"`
	Clients     []SDKClient          `json:"clients"`
}

type SDKDownloadArtifact struct {
	Provider    string `json:"provider"`
	TargetOS    string `json:"target_os"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Encoding    string `json:"encoding"`
	Content     string `json:"content"`
	SizeBytes   int    `json:"size_bytes"`
	SHA256      string `json:"sha256"`
}
