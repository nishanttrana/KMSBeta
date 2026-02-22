package main

import "time"

const (
	ProviderAWS        = "aws"
	ProviderAzure      = "azure"
	ProviderGCP        = "gcp"
	ProviderOCI        = "oci"
	ProviderSalesforce = "salesforce"
)

type CloudAccount struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	Provider      string    `json:"provider"`
	Name          string    `json:"name"`
	DefaultRegion string    `json:"default_region"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`

	CredentialsWrappedDEK   []byte `json:"-"`
	CredentialsWrappedDEKIV []byte `json:"-"`
	CredentialsCiphertext   []byte `json:"-"`
	CredentialsDataIV       []byte `json:"-"`
}

type RegionMapping struct {
	TenantID    string    `json:"tenant_id"`
	Provider    string    `json:"provider"`
	VectaRegion string    `json:"vecta_region"`
	CloudRegion string    `json:"cloud_region"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CloudKeyBinding struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	KeyID        string    `json:"key_id"`
	Provider     string    `json:"provider"`
	AccountID    string    `json:"account_id"`
	CloudKeyID   string    `json:"cloud_key_id"`
	CloudKeyRef  string    `json:"cloud_key_ref"`
	Region       string    `json:"region"`
	SyncStatus   string    `json:"sync_status"`
	LastSyncedAt time.Time `json:"last_synced_at"`
	MetadataJSON string    `json:"metadata_json"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type SyncJob struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Provider     string    `json:"provider"`
	AccountID    string    `json:"account_id"`
	Mode         string    `json:"mode"`
	Status       string    `json:"status"`
	SummaryJSON  string    `json:"summary_json"`
	ErrorMessage string    `json:"error_message"`
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type InventoryItem struct {
	CloudKeyID     string `json:"cloud_key_id"`
	CloudKeyRef    string `json:"cloud_key_ref"`
	Provider       string `json:"provider"`
	AccountID      string `json:"account_id"`
	Region         string `json:"region"`
	State          string `json:"state"`
	Algorithm      string `json:"algorithm"`
	ManagedByVecta bool   `json:"managed_by_vecta"`
}

type RegisterCloudAccountRequest struct {
	TenantID        string `json:"tenant_id"`
	Provider        string `json:"provider"`
	Name            string `json:"name"`
	DefaultRegion   string `json:"default_region"`
	CredentialsJSON string `json:"credentials_json"`
}

type SetRegionMappingRequest struct {
	TenantID    string `json:"tenant_id"`
	Provider    string `json:"provider"`
	VectaRegion string `json:"vecta_region"`
	CloudRegion string `json:"cloud_region"`
}

type ImportKeyToCloudRequest struct {
	TenantID     string `json:"tenant_id"`
	KeyID        string `json:"key_id"`
	Provider     string `json:"provider"`
	AccountID    string `json:"account_id"`
	VectaRegion  string `json:"vecta_region"`
	CloudRegion  string `json:"cloud_region"`
	MetadataJSON string `json:"metadata_json"`
}

type RotateCloudKeyRequest struct {
	TenantID  string `json:"tenant_id"`
	BindingID string `json:"binding_id"`
	Reason    string `json:"reason"`
}

type SyncCloudKeysRequest struct {
	TenantID  string `json:"tenant_id"`
	Provider  string `json:"provider"`
	AccountID string `json:"account_id"`
	Mode      string `json:"mode"`
}

type DiscoverInventoryRequest struct {
	TenantID    string `json:"tenant_id"`
	Provider    string `json:"provider"`
	AccountID   string `json:"account_id"`
	CloudRegion string `json:"cloud_region"`
}
