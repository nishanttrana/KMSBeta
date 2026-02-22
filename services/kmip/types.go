package main

import "time"

const (
	KMIPPort = "5696"
)

type Principal struct {
	TenantID string
	Role     string
	CN       string
}

type Session struct {
	ID             string
	TenantID       string
	ClientCN       string
	Role           string
	RemoteAddr     string
	TLSSubject     string
	TLSIssuer      string
	ConnectedAt    time.Time
	DisconnectedAt time.Time
}

type OperationRecord struct {
	ID            string
	TenantID      string
	SessionID     string
	RequestID     string
	Operation     string
	ObjectID      string
	Status        string
	ErrorMessage  string
	RequestBytes  int
	ResponseBytes int
	CreatedAt     time.Time
}

type ObjectMapping struct {
	TenantID       string
	ObjectID       string
	KeyID          string
	ObjectType     string
	Name           string
	State          string
	Algorithm      string
	AttributesJSON string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type CreateRequest struct {
	Name             string `json:"name"`
	Algorithm        string `json:"algorithm"`
	KeyType          string `json:"key_type"`
	Purpose          string `json:"purpose"`
	IVMode           string `json:"iv_mode"`
	OpsLimit         int64  `json:"ops_limit"`
	OpsWindow        string `json:"ops_limit_window"`
	ApprovalRequired bool   `json:"approval_required"`
	ApprovalPolicyID string `json:"approval_policy_id"`
}

type RegisterRequest struct {
	Name        string `json:"name"`
	Algorithm   string `json:"algorithm"`
	KeyType     string `json:"key_type"`
	Purpose     string `json:"purpose"`
	MaterialB64 string `json:"material"`
	ExpectedKCV string `json:"expected_kcv"`
}

type EncryptRequest struct {
	ObjectID     string `json:"object_id"`
	PlaintextB64 string `json:"plaintext"`
	IVB64        string `json:"iv"`
	ReferenceID  string `json:"reference_id"`
}

type DecryptRequest struct {
	ObjectID      string `json:"object_id"`
	CiphertextB64 string `json:"ciphertext"`
	IVB64         string `json:"iv"`
}

type SignRequest struct {
	ObjectID string `json:"object_id"`
	DataB64  string `json:"data"`
}

type LocateRequest struct {
	Name       string `json:"name"`
	ObjectType string `json:"object_type"`
	Algorithm  string `json:"algorithm"`
	State      string `json:"state"`
	Limit      int    `json:"limit"`
}

type ReKeyRequest struct {
	ObjectID string `json:"object_id"`
	Reason   string `json:"reason"`
}

type SetStateRequest struct {
	ObjectID string `json:"object_id"`
	Reason   string `json:"reason"`
}

type KMIPClientProfile struct {
	ID                      string    `json:"id"`
	TenantID                string    `json:"tenant_id"`
	Name                    string    `json:"name"`
	CAID                    string    `json:"ca_id"`
	UsernameLocation        string    `json:"username_location"`
	SubjectFieldToModify    string    `json:"subject_field_to_modify"`
	DoNotModifySubjectDN    bool      `json:"do_not_modify_subject_dn"`
	CertificateDurationDays int       `json:"certificate_duration_days"`
	Role                    string    `json:"role"`
	MetadataJSON            string    `json:"metadata_json"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

type KMIPClient struct {
	ID                    string    `json:"id"`
	TenantID              string    `json:"tenant_id"`
	ProfileID             string    `json:"profile_id"`
	Name                  string    `json:"name"`
	Role                  string    `json:"role"`
	Status                string    `json:"status"`
	EnrollmentMode        string    `json:"enrollment_mode"`
	RegistrationToken     string    `json:"registration_token"`
	CertID                string    `json:"cert_id"`
	CertSubject           string    `json:"cert_subject"`
	CertIssuer            string    `json:"cert_issuer"`
	CertSerial            string    `json:"cert_serial"`
	CertFingerprintSHA256 string    `json:"cert_fingerprint_sha256"`
	CertNotBefore         time.Time `json:"cert_not_before"`
	CertNotAfter          time.Time `json:"cert_not_after"`
	CertificatePEM        string    `json:"certificate_pem"`
	CABundlePEM           string    `json:"ca_bundle_pem"`
	MetadataJSON          string    `json:"metadata_json"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type CreateKMIPClientProfileRequest struct {
	TenantID                string `json:"tenant_id"`
	Name                    string `json:"name"`
	CAID                    string `json:"ca_id"`
	UsernameLocation        string `json:"username_location"`
	SubjectFieldToModify    string `json:"subject_field_to_modify"`
	DoNotModifySubjectDN    bool   `json:"do_not_modify_subject_dn"`
	CertificateDurationDays int    `json:"certificate_duration_days"`
	Role                    string `json:"role"`
	MetadataJSON            string `json:"metadata_json"`
}

type CreateKMIPClientRequest struct {
	TenantID          string `json:"tenant_id"`
	ProfileID         string `json:"profile_id"`
	Name              string `json:"name"`
	Role              string `json:"role"`
	RegistrationToken string `json:"registration_token"`
	EnrollmentMode    string `json:"enrollment_mode"`
	CSRPEM            string `json:"csr_pem"`
	CertificatePEM    string `json:"certificate_pem"`
	PrivateKeyPEM     string `json:"private_key_pem"`
	CABundlePEM       string `json:"ca_bundle_pem"`
	CommonName        string `json:"common_name"`
	MetadataJSON      string `json:"metadata_json"`
}

type CreateKMIPClientResult struct {
	Client        KMIPClient `json:"client"`
	IssuedCertPEM string     `json:"issued_cert_pem"`
	IssuedKeyPEM  string     `json:"issued_key_pem"`
}
