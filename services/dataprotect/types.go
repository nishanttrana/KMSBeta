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

type CertsClient interface {
	ListCAs(ctx context.Context, tenantID string) ([]map[string]interface{}, error)
	SignCSR(ctx context.Context, req FieldEncryptionSignCSRRequest) (FieldEncryptionIssuedCertificate, error)
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
	ConsumeTokenUse(ctx context.Context, tenantID string, id string) (TokenRecord, error)
	RenewTokenLease(ctx context.Context, tenantID string, id string, expiresAt time.Time, maxRenewals int) (TokenRecord, error)

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

	CreateFieldEncryptionWrapperChallenge(ctx context.Context, item FieldEncryptionWrapperChallenge) error
	GetFieldEncryptionWrapperChallenge(ctx context.Context, tenantID string, challengeID string) (FieldEncryptionWrapperChallenge, error)
	MarkFieldEncryptionWrapperChallengeUsed(ctx context.Context, tenantID string, challengeID string) error

	UpsertFieldEncryptionWrapper(ctx context.Context, item FieldEncryptionWrapper) (FieldEncryptionWrapper, error)
	GetFieldEncryptionWrapper(ctx context.Context, tenantID string, wrapperID string) (FieldEncryptionWrapper, error)
	ListFieldEncryptionWrappers(ctx context.Context, tenantID string, limit int, offset int) ([]FieldEncryptionWrapper, error)

	CreateFieldEncryptionLease(ctx context.Context, item FieldEncryptionLease) error
	GetFieldEncryptionLease(ctx context.Context, tenantID string, leaseID string) (FieldEncryptionLease, error)
	ListFieldEncryptionLeases(ctx context.Context, tenantID string, wrapperID string, limit int, offset int) ([]FieldEncryptionLease, error)
	ConsumeFieldEncryptionLeaseOps(ctx context.Context, tenantID string, leaseID string, ops int) (FieldEncryptionLease, error)
	RevokeFieldEncryptionLease(ctx context.Context, tenantID string, leaseID string, reason string) error

	CreateFieldEncryptionUsageReceipt(ctx context.Context, item FieldEncryptionUsageReceipt) error
	GetFieldEncryptionUsageReceiptByNonce(ctx context.Context, tenantID string, wrapperID string, nonce string) (FieldEncryptionUsageReceipt, error)
	ListFieldEncryptionLeaseReceiptStates(ctx context.Context, limit int) ([]FieldEncryptionLeaseReceiptState, error)

	UpsertFieldProtectionProfile(ctx context.Context, item FieldProtectionProfile) (FieldProtectionProfile, error)
	GetFieldProtectionProfile(ctx context.Context, tenantID string, profileID string) (FieldProtectionProfile, error)
	ListFieldProtectionProfiles(ctx context.Context, tenantID string, appID string, wrapperID string, status string, limit int, offset int) ([]FieldProtectionProfile, error)
	ResolveFieldProtectionProfiles(ctx context.Context, tenantID string, appID string, wrapperID string, limit int) ([]FieldProtectionProfile, error)
	DeleteFieldProtectionProfile(ctx context.Context, tenantID string, profileID string) error

	WriteAuditEntry(ctx context.Context, entry DataProtectAuditEntry) error
	ListAuditLog(ctx context.Context, tenantID string, category string, limit int, offset int) ([]DataProtectAuditEntry, error)
	GetStats(ctx context.Context, tenantID string) (DataProtectStats, error)
}

type DataProtectionPolicy struct {
	TenantID                       string              `json:"tenant_id"`
	AllowedDataAlgorithms          []string            `json:"allowed_data_algorithms"`
	AlgorithmProfilePolicy         map[string][]string `json:"algorithm_profile_policy"`
	RequireAADForAEAD              bool                `json:"require_aad_for_aead"`
	RequiredAADClaims              []string            `json:"required_aad_claims"`
	EnforceAADTenantBinding        bool                `json:"enforce_aad_tenant_binding"`
	AllowedAADEvironments          []string            `json:"allowed_aad_environments"`
	MaxFieldsPerOperation          int                 `json:"max_fields_per_operation"`
	MaxDocumentBytes               int                 `json:"max_document_bytes"`
	MaxAppCryptoRequestBytes       int                 `json:"max_app_crypto_request_bytes"`
	MaxAppCryptoBatchSize          int                 `json:"max_app_crypto_batch_size"`
	RequireSymmetricKeys           bool                `json:"require_symmetric_keys"`
	RequireFIPSKeys                bool                `json:"require_fips_keys"`
	MinKeySizeBits                 int                 `json:"min_key_size_bits"`
	AllowedEncryptFieldPaths       []string            `json:"allowed_encrypt_field_paths"`
	AllowedDecryptFieldPaths       []string            `json:"allowed_decrypt_field_paths"`
	DeniedDecryptFieldPaths        []string            `json:"denied_decrypt_field_paths"`
	BlockWildcardFieldPaths        bool                `json:"block_wildcard_field_paths"`
	AllowDeterministicEncryption   bool                `json:"allow_deterministic_encryption"`
	AllowSearchableEncryption      bool                `json:"allow_searchable_encryption"`
	AllowRangeSearch               bool                `json:"allow_range_search"`
	EnvelopeKEKAllowlist           []string            `json:"envelope_kek_allowlist"`
	MaxWrappedDEKAgeMinutes        int                 `json:"max_wrapped_dek_age_minutes"`
	RequireRewrapOnDEKAgeExceeded  bool                `json:"require_rewrap_on_dek_age_exceeded"`
	AllowVaultlessTokenization     bool                `json:"allow_vaultless_tokenization"`
	TokenizationModePolicy         map[string][]string `json:"tokenization_mode_policy"`
	TokenFormatPolicy              map[string][]string `json:"token_format_policy"`
	CustomTokenFormats             map[string]string   `json:"custom_token_formats"`
	ReuseExistingTokenForSameInput bool               `json:"reuse_existing_token_for_same_input"`
	EnforceUniqueTokenPerVault     bool               `json:"enforce_unique_token_per_vault"`
	RequireTokenTTL                bool                `json:"require_token_ttl"`
	MaxTokenTTLHours               int                 `json:"max_token_ttl_hours"`
	AllowTokenRenewal              bool                `json:"allow_token_renewal"`
	MaxTokenRenewals               int                 `json:"max_token_renewals"`
	AllowOneTimeTokens             bool                `json:"allow_one_time_tokens"`
	DetokenizeAllowedPurposes      []string            `json:"detokenize_allowed_purposes"`
	DetokenizeAllowedWorkflows     []string            `json:"detokenize_allowed_workflows"`
	RequireDetokenizeJustification bool                `json:"require_detokenize_justification"`
	AllowBulkTokenize              bool                `json:"allow_bulk_tokenize"`
	AllowBulkDetokenize            bool                `json:"allow_bulk_detokenize"`
	AllowRedactionDetectOnly       bool                `json:"allow_redaction_detect_only"`
	AllowedRedactionDetectors      []string            `json:"allowed_redaction_detectors"`
	AllowedRedactionActions        []string            `json:"allowed_redaction_actions"`
	AllowCustomRegexTokens         bool                `json:"allow_custom_regex_tokens"`
	MaxCustomRegexLength           int                 `json:"max_custom_regex_length"`
	MaxCustomRegexGroups           int                 `json:"max_custom_regex_groups"`
	MaxTokenBatch                  int                 `json:"max_token_batch"`
	MaxDetokenizeBatch             int                 `json:"max_detokenize_batch"`
	RequireTokenContextTags        bool                `json:"require_token_context_tags"`
	RequiredTokenContextKeys       []string            `json:"required_token_context_keys"`
	MaskingRolePolicy              map[string]string   `json:"masking_role_policy"`
	TokenMetadataRetentionDays     int                 `json:"token_metadata_retention_days"`
	RedactionEventRetentionDays    int                 `json:"redaction_event_retention_days"`
	RequireRegisteredWrapper       bool                `json:"require_registered_wrapper"`
	LocalCryptoAllowed             bool                `json:"local_crypto_allowed"`
	CacheEnabled                   bool                `json:"cache_enabled"`
	CacheTTLSeconds                int                 `json:"cache_ttl_sec"`
	LeaseMaxOps                    int                 `json:"lease_max_ops"`
	MaxCachedKeys                  int                 `json:"max_cached_keys"`
	AllowedLocalAlgorithms         []string            `json:"allowed_local_algorithms"`
	AllowedKeyClassesForLocal      []string            `json:"allowed_key_classes_for_local_export"`
	ForceRemoteOps                 []string            `json:"force_remote_ops"`
	RequireMTLS                    bool                `json:"require_mtls"`
	RequireSignedNonce             bool                `json:"require_signed_nonce"`
	AntiReplayWindowSeconds        int                 `json:"anti_replay_window_sec"`
	AttestedWrapperOnly            bool                `json:"attested_wrapper_only"`
	RevokeOnPolicyChange           bool                `json:"revoke_on_policy_change"`
	RekeyOnPolicyChange            bool                `json:"rekey_on_policy_change"`
	ReceiptReconciliationEnabled   bool                `json:"receipt_reconciliation_enabled"`
	ReceiptHeartbeatSec            int                 `json:"receipt_heartbeat_sec"`
	ReceiptMissingGraceSec         int                 `json:"receipt_missing_grace_sec"`
	RequireTPMAttestation          bool                `json:"require_tpm_attestation"`
	RequireNonExportableWrapperKey bool                `json:"require_non_exportable_wrapper_keys"`
	AttestationAKAllowlist         []string            `json:"attestation_ak_allowlist"`
	AttestationAllowedPCRs         map[string][]string `json:"attestation_allowed_pcrs"`
	UpdatedBy                      string              `json:"updated_by,omitempty"`
	UpdatedAt                      time.Time           `json:"updated_at"`
}

type FieldEncryptionWrapper struct {
	TenantID            string            `json:"tenant_id"`
	WrapperID           string            `json:"wrapper_id"`
	AppID               string            `json:"app_id"`
	DisplayName         string            `json:"display_name"`
	SigningPublicKeyB64 string            `json:"signing_public_key_b64"`
	EncryptionPublicKey string            `json:"encryption_public_key_b64"`
	Transport           string            `json:"transport"`
	Status              string            `json:"status"`
	CertFingerprint     string            `json:"cert_fingerprint,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
	ApprovedBy          string            `json:"approved_by,omitempty"`
	ApprovedAt          time.Time         `json:"approved_at,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

type FieldEncryptionWrapperChallenge struct {
	TenantID            string            `json:"tenant_id"`
	ChallengeID         string            `json:"challenge_id"`
	WrapperID           string            `json:"wrapper_id"`
	AppID               string            `json:"app_id"`
	ChallengeB64        string            `json:"challenge_b64"`
	Nonce               string            `json:"nonce"`
	SigningPublicKeyB64 string            `json:"signing_public_key_b64"`
	EncryptionPublicKey string            `json:"encryption_public_key_b64"`
	Metadata            map[string]string `json:"metadata,omitempty"`
	ExpiresAt           time.Time         `json:"expires_at"`
	Used                bool              `json:"used"`
	CreatedAt           time.Time         `json:"created_at"`
}

type FieldEncryptionLease struct {
	TenantID          string                 `json:"tenant_id"`
	LeaseID           string                 `json:"lease_id"`
	WrapperID         string                 `json:"wrapper_id"`
	KeyID             string                 `json:"key_id"`
	Operation         string                 `json:"operation"`
	LeasePackage      map[string]interface{} `json:"lease_package"`
	PolicyHash        string                 `json:"policy_hash"`
	RevocationCounter int                    `json:"revocation_counter"`
	MaxOps            int                    `json:"max_ops"`
	UsedOps           int                    `json:"used_ops"`
	ExpiresAt         time.Time              `json:"expires_at"`
	Revoked           bool                   `json:"revoked"`
	RevokeReason      string                 `json:"revoke_reason,omitempty"`
	IssuedAt          time.Time              `json:"issued_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

type FieldEncryptionUsageReceipt struct {
	TenantID     string    `json:"tenant_id"`
	ReceiptID    string    `json:"receipt_id"`
	LeaseID      string    `json:"lease_id"`
	WrapperID    string    `json:"wrapper_id"`
	KeyID        string    `json:"key_id"`
	Operation    string    `json:"operation"`
	OpCount      int       `json:"op_count"`
	Nonce        string    `json:"nonce"`
	Timestamp    time.Time `json:"timestamp"`
	SignatureB64 string    `json:"signature_b64"`
	PayloadHash  string    `json:"payload_hash"`
	Accepted     bool      `json:"accepted"`
	RejectReason string    `json:"reject_reason,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type FieldEncryptionLeaseReceiptState struct {
	TenantID      string    `json:"tenant_id"`
	LeaseID       string    `json:"lease_id"`
	WrapperID     string    `json:"wrapper_id"`
	PolicyHash    string    `json:"policy_hash"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	LastReceiptAt time.Time `json:"last_receipt_at,omitempty"`
	ReceiptCount  int       `json:"receipt_count"`
}

type FieldProtectionRule struct {
	RuleID             string            `json:"rule_id"`
	DataClass          string            `json:"data_class,omitempty"`
	TableName          string            `json:"table,omitempty"`
	ColumnName         string            `json:"column,omitempty"`
	JSONPath           string            `json:"json_path,omitempty"`
	WriteAction        string            `json:"write_action"`
	ReadAction         string            `json:"read_action"`
	Algorithm          string            `json:"algorithm,omitempty"`
	KeyID              string            `json:"key_id,omitempty"`
	TokenVaultID       string            `json:"token_vault_id,omitempty"`
	MaskPattern        string            `json:"mask_pattern,omitempty"`
	RedactionPolicyID  string            `json:"redaction_policy_id,omitempty"`
	AllowedDecryptRoles []string         `json:"allowed_decrypt_roles,omitempty"`
	MaskedRoles        []string          `json:"masked_roles,omitempty"`
	TokenOnlyRoles     []string          `json:"token_only_roles,omitempty"`
	AllowedPurposes    []string          `json:"allowed_purposes,omitempty"`
	AllowedWorkflows   []string          `json:"allowed_workflows,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

type FieldProtectionProfile struct {
	TenantID         string               `json:"tenant_id"`
	ProfileID        string               `json:"profile_id"`
	Name             string               `json:"name"`
	AppID            string               `json:"app_id"`
	WrapperID        string               `json:"wrapper_id"`
	Status           string               `json:"status"`
	Priority         int                  `json:"priority"`
	CacheTTLSeconds  int                  `json:"cache_ttl_sec"`
	PolicyHash       string               `json:"policy_hash"`
	Rules            []FieldProtectionRule `json:"rules"`
	Metadata         map[string]string    `json:"metadata,omitempty"`
	UpdatedBy        string               `json:"updated_by,omitempty"`
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
}

type FieldProtectionResolvedRule struct {
	ProfileID   string `json:"profile_id"`
	ProfileName string `json:"profile_name"`
	Priority    int    `json:"priority"`
	FieldProtectionRule
}

type FieldProtectionResolveRequest struct {
	TenantID     string `json:"tenant_id"`
	AppID        string `json:"app_id"`
	WrapperID    string `json:"wrapper_id"`
	Role         string `json:"role,omitempty"`
	Purpose      string `json:"purpose,omitempty"`
	Workflow     string `json:"workflow,omitempty"`
	AuthToken    string `json:"-"`
	ClientCertFP string `json:"-"`
}

type FieldProtectionPolicyBundle struct {
	TenantID         string                      `json:"tenant_id"`
	AppID            string                      `json:"app_id"`
	WrapperID        string                      `json:"wrapper_id"`
	ETag             string                      `json:"etag"`
	CacheTTLSeconds  int                         `json:"cache_ttl_sec"`
	GeneratedAt      time.Time                   `json:"generated_at"`
	Profiles         []FieldProtectionProfile    `json:"profiles"`
	Rules            []FieldProtectionResolvedRule `json:"rules"`
}

type TokenVault struct {
	ID                  string            `json:"id"`
	TenantID            string            `json:"tenant_id"`
	Name                string            `json:"name"`
	Mode                string            `json:"mode"`
	StorageType         string            `json:"storage_type"`
	ExternalProvider    string            `json:"external_provider,omitempty"`
	ExternalConfig      map[string]string `json:"external_config,omitempty"`
	ExternalSchemaVersion string          `json:"external_schema_version,omitempty"`
	TokenType           string            `json:"token_type"`
	Format              string            `json:"format"`
	CustomTokenFormat   string            `json:"custom_token_format,omitempty"`
	KeyID               string            `json:"key_id"`
	CustomRegex         string            `json:"custom_regex,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
}

type TokenRecord struct {
	ID             string                 `json:"id"`
	TenantID       string                 `json:"tenant_id"`
	VaultID        string                 `json:"vault_id"`
	Token          string                 `json:"token"`
	OriginalEnc    []byte                 `json:"-"`
	OriginalHash   string                 `json:"original_hash,omitempty"`
	FormatMetadata map[string]interface{} `json:"format_metadata,omitempty"`
	UseCount       int                    `json:"use_count"`
	UseLimit       int                    `json:"use_limit"`
	RenewCount     int                    `json:"renew_count"`
	MetadataTags   map[string]string      `json:"metadata_tags,omitempty"`
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
	TenantID     string            `json:"tenant_id"`
	Mode         string            `json:"mode"`
	VaultID      string            `json:"vault_id"`
	KeyID        string            `json:"key_id"`
	TokenType    string            `json:"token_type"`
	Format       string            `json:"format"`
	CustomTokenFormat string       `json:"custom_token_format"`
	CustomRegex  string            `json:"custom_regex"`
	Values       []string          `json:"values"`
	TTLHours     int               `json:"ttl_hours"`
	OneTimeToken bool              `json:"one_time_token"`
	MetadataTags map[string]string `json:"metadata_tags"`
}

type DetokenizeRequest struct {
	TenantID      string            `json:"tenant_id"`
	Tokens        []string          `json:"tokens"`
	Purpose       string            `json:"purpose"`
	Workflow      string            `json:"workflow"`
	Justification string            `json:"justification"`
	MetadataTags  map[string]string `json:"metadata_tags"`
	RenewTTLHours int               `json:"renew_ttl_hours"`
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
	DEKCreatedAt string `json:"dek_created_at"`
	AAD          string `json:"aad"`
}

type SearchableRequest struct {
	TenantID   string `json:"tenant_id"`
	KeyID      string `json:"key_id"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
	AAD        string `json:"aad"`
	QueryType  string `json:"query_type"`
}

type FieldEncryptionRegisterInitRequest struct {
	TenantID            string            `json:"tenant_id"`
	WrapperID           string            `json:"wrapper_id"`
	AppID               string            `json:"app_id"`
	DisplayName         string            `json:"display_name"`
	SigningPublicKeyB64 string            `json:"signing_public_key_b64"`
	EncryptionPublicKey string            `json:"encryption_public_key_b64"`
	Transport           string            `json:"transport"`
	Metadata            map[string]string `json:"metadata"`
}

type FieldEncryptionRegisterCompleteRequest struct {
	TenantID           string            `json:"tenant_id"`
	ChallengeID        string            `json:"challenge_id"`
	WrapperID          string            `json:"wrapper_id"`
	SignatureB64       string            `json:"signature_b64"`
	CSRPEM             string            `json:"csr_pem"`
	CertFingerprint    string            `json:"cert_fingerprint"`
	GovernanceApproved bool              `json:"governance_approved"`
	ApprovedBy         string            `json:"approved_by"`
	Metadata           map[string]string `json:"metadata"`
	AttestationEvidenceB64 string `json:"attestation_evidence_b64"`
	AttestationSignatureB64 string `json:"attestation_signature_b64"`
	AttestationPublicKeyPEM string `json:"attestation_public_key_pem"`
}

type FieldEncryptionAuthProfile struct {
	Mode      string   `json:"mode"`
	TokenType string   `json:"token_type"`
	Token     string   `json:"token"`
	ExpiresAt string   `json:"expires_at"`
	Scopes    []string `json:"scopes"`
	Issuer    string   `json:"issuer"`
	Audience  string   `json:"audience"`
}

type FieldEncryptionIssuedCertificate struct {
	CertID          string `json:"cert_id,omitempty"`
	CertPEM         string `json:"cert_pem,omitempty"`
	CertFingerprint string `json:"cert_fingerprint,omitempty"`
	CAID            string `json:"ca_id,omitempty"`
	NotAfter        string `json:"not_after,omitempty"`
}

type FieldEncryptionWrapperRegistrationResult struct {
	Wrapper     FieldEncryptionWrapper           `json:"wrapper"`
	AuthProfile FieldEncryptionAuthProfile       `json:"auth_profile"`
	Certificate FieldEncryptionIssuedCertificate `json:"certificate,omitempty"`
	Warnings    []string                         `json:"warnings,omitempty"`
}

type FieldEncryptionSignCSRRequest struct {
	TenantID  string `json:"tenant_id"`
	CAID      string `json:"ca_id"`
	CSRPEM    string `json:"csr_pem"`
	CertType  string `json:"cert_type"`
	Algorithm string `json:"algorithm"`
	Protocol  string `json:"protocol"`
}

type FieldEncryptionLeaseRequest struct {
	TenantID           string `json:"tenant_id"`
	WrapperID          string `json:"wrapper_id"`
	KeyID              string `json:"key_id"`
	Operation          string `json:"operation"`
	Nonce              string `json:"nonce"`
	Timestamp          string `json:"timestamp"`
	SignatureB64       string `json:"signature_b64"`
	RequestedTTLSecond int    `json:"requested_ttl_sec"`
	RequestedMaxOps    int    `json:"requested_max_ops"`
	AuthToken          string `json:"-"`
	ClientCertFP       string `json:"-"`
}

type FieldEncryptionReceiptRequest struct {
	TenantID     string `json:"tenant_id"`
	LeaseID      string `json:"lease_id"`
	WrapperID    string `json:"wrapper_id"`
	KeyID        string `json:"key_id"`
	Operation    string `json:"operation"`
	OpCount      int    `json:"op_count"`
	Nonce        string `json:"nonce"`
	Timestamp    string `json:"timestamp"`
	SignatureB64 string `json:"signature_b64"`
	ClientStatus string `json:"client_status"`
	AuthToken    string `json:"-"`
	ClientCertFP string `json:"-"`
}

type FieldEncryptionSDKArtifact struct {
	TargetOS    string `json:"target_os"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Encoding    string `json:"encoding"`
	Content     string `json:"content"`
	SizeBytes   int    `json:"size_bytes"`
	SHA256      string `json:"sha256"`
}

type DataProtectAuditEntry struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Operation string    `json:"operation"`
	Category  string    `json:"category"`
	Actor     string    `json:"actor"`
	Detail    string    `json:"detail"`
	Metadata  string    `json:"metadata"`
	CreatedAt time.Time `json:"created_at"`
}

type DataProtectStats struct {
	TenantID           string `json:"tenant_id"`
	TokenVaults        int    `json:"token_vaults"`
	TotalTokens        int    `json:"total_tokens"`
	MaskingPolicies    int    `json:"masking_policies"`
	RedactionPolicies  int    `json:"redaction_policies"`
	RegisteredWrappers int    `json:"registered_wrappers"`
	ActiveLeases       int    `json:"active_leases"`
	TotalLeases        int    `json:"total_leases"`
	AuditEntries       int    `json:"audit_entries"`
	FieldProfiles      int    `json:"field_profiles"`
}
