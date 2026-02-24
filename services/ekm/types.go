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
	TDEEnabled      bool      `json:"tde_enabled"`
	TDEState        string    `json:"tde_state"`
	KeyID           string    `json:"key_id"`
	AutoProvisioned bool      `json:"auto_provisioned"`
	MetadataJSON    string    `json:"metadata_json"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
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
}

type WrapDEKResponse struct {
	KeyID         string `json:"key_id"`
	Version       int    `json:"version"`
	CiphertextB64 string `json:"ciphertext"`
	IVB64         string `json:"iv"`
}

type UnwrapDEKRequest struct {
	TenantID      string `json:"tenant_id"`
	CiphertextB64 string `json:"ciphertext"`
	IVB64         string `json:"iv"`
	AgentID       string `json:"agent_id"`
	DatabaseID    string `json:"database_id"`
}

type UnwrapDEKResponse struct {
	KeyID        string `json:"key_id"`
	Version      int    `json:"version"`
	PlaintextB64 string `json:"plaintext"`
}

type RotateTDEKeyRequest struct {
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason"`
}

type RotateTDEKeyResponse struct {
	KeyID            string   `json:"key_id"`
	VersionID        string   `json:"version_id"`
	AffectedAgentIDs []string `json:"affected_agent_ids"`
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
	TenantID string                 `json:"tenant_id"`
	Operation string                `json:"operation"`
	RequestedBy string              `json:"requested_by"`
	RequestID string                `json:"request_id"`
	Params map[string]interface{}   `json:"params"`
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
