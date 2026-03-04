package main

import "time"

const (
	CAStatusActive  = "active"
	CAStatusRevoked = "revoked"

	CertStatusActive  = "active"
	CertStatusRevoked = "revoked"
	CertStatusExpired = "expired"
	CertStatusDeleted = "deleted"
)

type CA struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	Name              string    `json:"name"`
	ParentCAID        string    `json:"parent_ca_id"`
	CALevel           string    `json:"ca_level"`
	Algorithm         string    `json:"algorithm"`
	CAType            string    `json:"ca_type"`
	KeyBackend        string    `json:"key_backend"`
	KeyRef            string    `json:"key_ref"`
	CertPEM           string    `json:"cert_pem"`
	Subject           string    `json:"subject"`
	Status            string    `json:"status"`
	OTSCurrent        int64     `json:"ots_current"`
	OTSMax            int64     `json:"ots_max"`
	OTSAlertThreshold int64     `json:"ots_alert_threshold"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`

	SignerWrappedDEK   []byte `json:"-"`
	SignerWrappedDEKIV []byte `json:"-"`
	SignerCiphertext   []byte `json:"-"`
	SignerDataIV       []byte `json:"-"`
	SignerKeyVersion   string `json:"-"`
	SignerFingerprint  string `json:"-"`
}

type Certificate struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	CAID             string    `json:"ca_id"`
	SerialNumber     string    `json:"serial_number"`
	SubjectCN        string    `json:"subject_cn"`
	SANs             []string  `json:"sans"`
	CertType         string    `json:"cert_type"`
	Algorithm        string    `json:"algorithm"`
	ProfileID        string    `json:"profile_id"`
	Protocol         string    `json:"protocol"`
	CertClass        string    `json:"cert_class"`
	CertPEM          string    `json:"cert_pem"`
	Status           string    `json:"status"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	RevokedAt        time.Time `json:"revoked_at"`
	RevocationReason string    `json:"revocation_reason"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	KeyRef           string    `json:"key_ref"`
}

type CertificateProfile struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	CertType    string    `json:"cert_type"`
	Algorithm   string    `json:"algorithm"`
	CertClass   string    `json:"cert_class"`
	ProfileJSON string    `json:"profile_json"`
	IsDefault   bool      `json:"is_default"`
	CreatedAt   time.Time `json:"created_at"`
}

type EncryptedSigner struct {
	WrappedDEK   []byte
	WrappedDEKIV []byte
	Ciphertext   []byte
	DataIV       []byte
	KeyVersion   string
	Fingerprint  string
}

type IssueCertificateRequest struct {
	TenantID     string   `json:"tenant_id"`
	CAID         string   `json:"ca_id"`
	ProfileID    string   `json:"profile_id"`
	CertType     string   `json:"cert_type"`
	Algorithm    string   `json:"algorithm"`
	CertClass    string   `json:"cert_class"`
	SubjectCN    string   `json:"subject_cn"`
	SANs         []string `json:"sans"`
	CSRPem       string   `json:"csr_pem"`
	ServerKeygen bool     `json:"server_keygen"`
	ValidityDays int64    `json:"validity_days"`
	NotAfter     string   `json:"not_after"`
	Protocol     string   `json:"protocol"`
	MetadataJSON string   `json:"metadata_json"`
}

type DownloadCertificateRequest struct {
	TenantID     string `json:"tenant_id"`
	CertID       string `json:"cert_id"`
	Asset        string `json:"asset"`
	Format       string `json:"format"`
	Password     string `json:"password"`
	IncludeChain bool   `json:"include_chain"`
}

type CreateCARequest struct {
	TenantID          string `json:"tenant_id"`
	Name              string `json:"name"`
	ParentCAID        string `json:"parent_ca_id"`
	CALevel           string `json:"ca_level"`
	Algorithm         string `json:"algorithm"`
	CAType            string `json:"ca_type"`
	KeyBackend        string `json:"key_backend"`
	KeyRef            string `json:"key_ref"`
	Subject           string `json:"subject"`
	ValidityDays      int64  `json:"validity_days"`
	OTSMax            int64  `json:"ots_max"`
	OTSAlertThreshold int64  `json:"ots_alert_threshold"`
}

type RenewCertificateRequest struct {
	TenantID     string `json:"tenant_id"`
	CertID       string `json:"cert_id"`
	ValidityDays int64  `json:"validity_days"`
}

type RevokeCertificateRequest struct {
	TenantID string `json:"tenant_id"`
	CertID   string `json:"cert_id"`
	Reason   string `json:"reason"`
}

type CreateProfileRequest struct {
	TenantID    string `json:"tenant_id"`
	Name        string `json:"name"`
	CertType    string `json:"cert_type"`
	Algorithm   string `json:"algorithm"`
	CertClass   string `json:"cert_class"`
	ProfileJSON string `json:"profile_json"`
	IsDefault   bool   `json:"is_default"`
}

type ValidatePQCChainRequest struct {
	TenantID string   `json:"tenant_id"`
	CertIDs  []string `json:"cert_ids"`
}

type MigrateToPQCRequest struct {
	TenantID        string `json:"tenant_id"`
	CertID          string `json:"cert_id"`
	TargetAlgorithm string `json:"target_algorithm"`
	TargetProfileID string `json:"target_profile_id"`
}

type OTSStatus struct {
	CurrentIndex int64 `json:"current_index"`
	MaxIndex     int64 `json:"max_index"`
	Remaining    int64 `json:"remaining"`
	Alert        bool  `json:"alert"`
}

type PQCReadiness struct {
	Total     int64 `json:"total"`
	Classical int64 `json:"classical"`
	Hybrid    int64 `json:"hybrid"`
	PQC       int64 `json:"pqc"`
}

type InventoryCertificateItem struct {
	CertID    string `json:"cert_id"`
	CAID      string `json:"ca_id"`
	CertType  string `json:"cert_type"`
	CertClass string `json:"cert_class"`
	Status    string `json:"status"`
	NotAfter  string `json:"not_after"`
	ProfileID string `json:"profile_id"`
}

type ProtocolConfig struct {
	TenantID   string    `json:"tenant_id"`
	Protocol   string    `json:"protocol"`
	Enabled    bool      `json:"enabled"`
	ConfigJSON string    `json:"config_json"`
	UpdatedBy  string    `json:"updated_by"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type CertExpiryAlertPolicy struct {
	TenantID        string    `json:"tenant_id"`
	DaysBefore      int       `json:"days_before"`
	IncludeExternal bool      `json:"include_external"`
	UpdatedBy       string    `json:"updated_by"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type UpsertCertExpiryAlertPolicyRequest struct {
	TenantID        string `json:"tenant_id"`
	DaysBefore      int    `json:"days_before"`
	IncludeExternal bool   `json:"include_external"`
	UpdatedBy       string `json:"updated_by"`
}

type CertExpiryAlertState struct {
	TenantID     string    `json:"tenant_id"`
	CertID       string    `json:"cert_id"`
	LastDaysLeft int       `json:"last_days_left"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type UpsertProtocolConfigRequest struct {
	TenantID   string `json:"tenant_id"`
	Protocol   string `json:"protocol"`
	Enabled    bool   `json:"enabled"`
	ConfigJSON string `json:"config_json"`
	UpdatedBy  string `json:"updated_by"`
}

type UploadThirdPartyCertificateRequest struct {
	TenantID       string `json:"tenant_id"`
	Purpose        string `json:"purpose"`
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	CABundlePEM    string `json:"ca_bundle_pem"`
	SetActive      bool   `json:"set_active"`
	EnableOCSP     bool   `json:"enable_ocsp_stapling"`
	AutoRenewACME  bool   `json:"auto_renew_acme"`
	UpdatedBy      string `json:"updated_by"`
}

type AcmeAccount struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type AcmeOrder struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	AccountID   string    `json:"account_id"`
	CAID        string    `json:"ca_id"`
	SubjectCN   string    `json:"subject_cn"`
	SANs        []string  `json:"sans"`
	ChallengeID string    `json:"challenge_id"`
	Status      string    `json:"status"`
	CSRPem      string    `json:"csr_pem"`
	CertID      string    `json:"cert_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ACMENewAccountRequest struct {
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
}

type ACMENewOrderRequest struct {
	TenantID          string   `json:"tenant_id"`
	CAID              string   `json:"ca_id"`
	AccountID         string   `json:"account_id"`
	SubjectCN         string   `json:"subject_cn"`
	SANs              []string `json:"sans"`
	ChallengeType     string   `json:"challenge_type"`
	ExternalAccountID string   `json:"external_account_id"`
	ExternalHMAC      string   `json:"external_hmac"`
}

type ACMEFinalizeRequest struct {
	TenantID string `json:"tenant_id"`
	OrderID  string `json:"order_id"`
	CSRPem   string `json:"csr_pem"`
}

type ESTSimpleEnrollRequest struct {
	TenantID   string `json:"tenant_id"`
	CAID       string `json:"ca_id"`
	CSRPem     string `json:"csr_pem"`
	ProfileID  string `json:"profile_id"`
	AuthMethod string `json:"auth_method"`
	AuthToken  string `json:"auth_token"`
}

type ESTSimpleReenrollRequest struct {
	TenantID   string `json:"tenant_id"`
	CertID     string `json:"cert_id"`
	CSRPem     string `json:"csr_pem"`
	AuthMethod string `json:"auth_method"`
	AuthToken  string `json:"auth_token"`
}

type ESTServerKeygenRequest struct {
	TenantID   string   `json:"tenant_id"`
	CAID       string   `json:"ca_id"`
	SubjectCN  string   `json:"subject_cn"`
	SANs       []string `json:"sans"`
	ProfileID  string   `json:"profile_id"`
	AuthMethod string   `json:"auth_method"`
	AuthToken  string   `json:"auth_token"`
}

type SCEPPKIOperationRequest struct {
	TenantID          string `json:"tenant_id"`
	CAID              string `json:"ca_id"`
	CSRPem            string `json:"csr_pem"`
	TransactionID     string `json:"transaction_id"`
	MessageType       string `json:"message_type"`
	ChallengePassword string `json:"challenge_password"`
	CertID            string `json:"cert_id"`
}

type CMPv2RequestMessage struct {
	TenantID      string `json:"tenant_id"`
	CAID          string `json:"ca_id"`
	MessageType   string `json:"message_type"`
	CSRPem        string `json:"csr_pem"`
	CertID        string `json:"cert_id"`
	PayloadJSON   string `json:"payload_json"`
	TransactionID string `json:"transaction_id"`
	Protected     bool   `json:"protected"`
	ProtectionAlg string `json:"protection_alg"`
}

type InternalMTLSRequest struct {
	TenantID     string `json:"tenant_id"`
	CAID         string `json:"ca_id"`
	Algorithm    string `json:"algorithm"`
	CertClass    string `json:"cert_class"`
	Protocol     string `json:"protocol"`
	ValidityDays int64  `json:"validity_days"`
}

// ── Certificate Transparency (Merkle) types ──────────────────

type CertMerkleEpoch struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	EpochNumber int       `json:"epoch_number"`
	LeafCount   int       `json:"leaf_count"`
	TreeRoot    string    `json:"tree_root"`
	CreatedAt   time.Time `json:"created_at"`
}

type CertMerkleLeaf struct {
	EpochID      string `json:"epoch_id"`
	TenantID     string `json:"tenant_id"`
	LeafIndex    int    `json:"leaf_index"`
	CertID       string `json:"cert_id"`
	SerialNumber string `json:"serial_number"`
	SubjectCN    string `json:"subject_cn"`
	LeafHash     string `json:"leaf_hash"`
	LoggedAt     string `json:"logged_at"`
}

type CertMerkleEpochResult struct {
	Epoch  CertMerkleEpoch `json:"epoch"`
	Leaves int             `json:"leaves"`
}

type CertMerkleProofResponse struct {
	CertID       string         `json:"cert_id"`
	SerialNumber string         `json:"serial_number"`
	SubjectCN    string         `json:"subject_cn"`
	EpochID      string         `json:"epoch_id"`
	LeafHash     string         `json:"leaf_hash"`
	LeafIndex    int            `json:"leaf_index"`
	Siblings     []ProofSibling `json:"siblings"`
	Root         string         `json:"root"`
}
