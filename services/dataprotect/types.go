package main

import (
	"context"
	"time"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type KeyCoreClient interface {
	GetKey(ctx context.Context, tenantID string, keyID string) (map[string]interface{}, error)
	MeterUsage(ctx context.Context, tenantID string, keyID string, operation string) error
}

type Store interface {
	CreateTokenVault(ctx context.Context, item TokenVault) error
	ListTokenVaults(ctx context.Context, tenantID string, limit int, offset int) ([]TokenVault, error)
	GetTokenVault(ctx context.Context, tenantID string, id string) (TokenVault, error)
	DeleteTokenVault(ctx context.Context, tenantID string, id string) error
	CountTokensByVault(ctx context.Context, tenantID string, vaultID string) (int, error)

	CreateToken(ctx context.Context, item TokenRecord) error
	GetTokenByValue(ctx context.Context, tenantID string, token string) (TokenRecord, error)
	GetTokenByHash(ctx context.Context, tenantID string, vaultID string, hash string) (TokenRecord, error)

	CreateMaskingPolicy(ctx context.Context, item MaskingPolicy) error
	UpdateMaskingPolicy(ctx context.Context, item MaskingPolicy) error
	DeleteMaskingPolicy(ctx context.Context, tenantID string, id string) error
	ListMaskingPolicies(ctx context.Context, tenantID string) ([]MaskingPolicy, error)
	GetMaskingPolicy(ctx context.Context, tenantID string, id string) (MaskingPolicy, error)

	CreateRedactionPolicy(ctx context.Context, item RedactionPolicy) error
	ListRedactionPolicies(ctx context.Context, tenantID string) ([]RedactionPolicy, error)
	GetRedactionPolicy(ctx context.Context, tenantID string, id string) (RedactionPolicy, error)

	CreateFLEMetadata(ctx context.Context, item FLEMetadata) error
	ListFLEMetadataByDocument(ctx context.Context, tenantID string, documentID string) ([]FLEMetadata, error)

	GetDataProtectionPolicy(ctx context.Context, tenantID string) (DataProtectionPolicy, error)
	UpsertDataProtectionPolicy(ctx context.Context, item DataProtectionPolicy) (DataProtectionPolicy, error)
}

type DataProtectionPolicy struct {
	TenantID                   string    `json:"tenant_id"`
	AllowedDataAlgorithms      []string  `json:"allowed_data_algorithms"`
	RequireAADForAEAD          bool      `json:"require_aad_for_aead"`
	MaxFieldsPerOperation      int       `json:"max_fields_per_operation"`
	MaxDocumentBytes           int       `json:"max_document_bytes"`
	AllowVaultlessTokenization bool      `json:"allow_vaultless_tokenization"`
	RequireTokenTTL            bool      `json:"require_token_ttl"`
	MaxTokenTTLHours           int       `json:"max_token_ttl_hours"`
	AllowRedactionDetectOnly   bool      `json:"allow_redaction_detect_only"`
	AllowCustomRegexTokens     bool      `json:"allow_custom_regex_tokens"`
	MaxTokenBatch              int       `json:"max_token_batch"`
	UpdatedBy                  string    `json:"updated_by,omitempty"`
	UpdatedAt                  time.Time `json:"updated_at"`
}

type TokenVault struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Mode        string    `json:"mode"`
	TokenType   string    `json:"token_type"`
	Format      string    `json:"format"`
	KeyID       string    `json:"key_id"`
	CustomRegex string    `json:"custom_regex,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type TokenRecord struct {
	ID             string                 `json:"id"`
	TenantID       string                 `json:"tenant_id"`
	VaultID        string                 `json:"vault_id"`
	Token          string                 `json:"token"`
	OriginalEnc    []byte                 `json:"-"`
	OriginalHash   string                 `json:"original_hash,omitempty"`
	FormatMetadata map[string]interface{} `json:"format_metadata,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	ExpiresAt      time.Time              `json:"expires_at,omitempty"`
}

type MaskingPolicy struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	Name          string    `json:"name"`
	TargetType    string    `json:"target_type"`
	FieldPath     string    `json:"field_path"`
	MaskPattern   string    `json:"mask_pattern"`
	RolesFull     []string  `json:"roles_full"`
	RolesPartial  []string  `json:"roles_partial"`
	RolesRedacted []string  `json:"roles_redacted"`
	Consistent    bool      `json:"consistent"`
	KeyID         string    `json:"key_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type RedactionPattern struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
	Label   string `json:"label"`
}

type RedactionPolicy struct {
	ID          string             `json:"id"`
	TenantID    string             `json:"tenant_id"`
	Name        string             `json:"name"`
	Patterns    []RedactionPattern `json:"patterns"`
	Scope       string             `json:"scope"`
	Action      string             `json:"action"`
	Placeholder string             `json:"placeholder"`
	AppliesTo   []string           `json:"applies_to"`
	CreatedAt   time.Time          `json:"created_at"`
}

type FLEMetadata struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	DocumentID string    `json:"document_id"`
	FieldPath  string    `json:"field_path"`
	KeyID      string    `json:"key_id"`
	KeyVersion int       `json:"key_version"`
	Algorithm  string    `json:"algorithm"`
	IV         []byte    `json:"iv,omitempty"`
	Searchable bool      `json:"searchable"`
	CreatedAt  time.Time `json:"created_at"`
}

type TokenizeRequest struct {
	TenantID    string   `json:"tenant_id"`
	Mode        string   `json:"mode"`
	VaultID     string   `json:"vault_id"`
	KeyID       string   `json:"key_id"`
	TokenType   string   `json:"token_type"`
	Format      string   `json:"format"`
	CustomRegex string   `json:"custom_regex"`
	Values      []string `json:"values"`
	TTLHours    int      `json:"ttl_hours"`
}

type DetokenizeRequest struct {
	TenantID string   `json:"tenant_id"`
	Tokens   []string `json:"tokens"`
}

type FPERequest struct {
	TenantID   string `json:"tenant_id"`
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm"`
	Radix      int    `json:"radix"`
	Tweak      string `json:"tweak"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

type MaskRequest struct {
	TenantID  string                 `json:"tenant_id"`
	PolicyID  string                 `json:"policy_id"`
	Data      map[string]interface{} `json:"data"`
	Role      string                 `json:"role"`
	Preview   bool                   `json:"preview"`
	Document  string                 `json:"document"`
	FieldPath string                 `json:"field_path"`
}

type RedactRequest struct {
	TenantID     string `json:"tenant_id"`
	PolicyID     string `json:"policy_id"`
	Content      string `json:"content"`
	ContentType  string `json:"content_type"`
	DetectOnly   bool   `json:"detect_only"`
	EndpointName string `json:"endpoint_name"`
}

type AppFieldRequest struct {
	TenantID   string                 `json:"tenant_id"`
	DocumentID string                 `json:"document_id"`
	Document   map[string]interface{} `json:"document"`
	Fields     []string               `json:"fields"`
	KeyID      string                 `json:"key_id"`
	Algorithm  string                 `json:"algorithm"`
	Searchable bool                   `json:"searchable"`
	AAD        string                 `json:"aad"`
}

type EnvelopeRequest struct {
	TenantID     string `json:"tenant_id"`
	KeyID        string `json:"key_id"`
	Algorithm    string `json:"algorithm"`
	Plaintext    string `json:"plaintext"`
	Ciphertext   string `json:"ciphertext"`
	IV           string `json:"iv"`
	WrappedDEK   string `json:"wrapped_dek"`
	WrappedDEKIV string `json:"wrapped_dek_iv"`
	AAD          string `json:"aad"`
}

type SearchableRequest struct {
	TenantID   string `json:"tenant_id"`
	KeyID      string `json:"key_id"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
	AAD        string `json:"aad"`
}
