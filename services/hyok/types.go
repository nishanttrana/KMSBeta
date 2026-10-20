package main

import (
	"time"

	pkgauth "vecta-kms/pkg/auth"
)

const (
	ProtocolDKE        = "dke"
	ProtocolSalesforce = "salesforce"
	ProtocolGoogleEKM  = "google"
	ProtocolGeneric    = "generic"
	ProtocolServiceNow = "servicenow" // ServiceNow HYOK/Cache-Only Key
	ProtocolAlibaba    = "alibaba"    // Alibaba Cloud EKM
	// Azure Managed HSM external key management (EKM Proxy API), served on
	// its own mTLS listener (azure_ekm.go).
	ProtocolAzureEKM = "azure"
	// AWS KMS external key store (XKS proxy API), SigV4-signed (aws_xks.go).
	ProtocolAWSXKS = "aws_xks"
)

const (
	AuthModeMTLSOrJWT = "mtls_or_jwt"
	AuthModeMTLS      = "mtls"
	AuthModeJWT       = "jwt"
	// AuthModeSigV4: AWS SigV4 with an aws_xks credential (AWS XKS only).
	AuthModeSigV4 = "sigv4"
)

type EndpointConfig struct {
	TenantID           string    `json:"tenant_id"`
	Protocol           string    `json:"protocol"`
	Enabled            bool      `json:"enabled"`
	AuthMode           string    `json:"auth_mode"`
	PolicyID           string    `json:"policy_id"`
	GovernanceRequired bool      `json:"governance_required"`
	MetadataJSON       string    `json:"metadata_json"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type ProxyRequestLog struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	Protocol          string    `json:"protocol"`
	Operation         string    `json:"operation"`
	KeyID             string    `json:"key_id"`
	Endpoint          string    `json:"endpoint"`
	AuthMode          string    `json:"auth_mode"`
	AuthSubject       string    `json:"auth_subject"`
	RequesterID       string    `json:"requester_id"`
	RequesterEmail    string    `json:"requester_email"`
	PolicyDecision    string    `json:"policy_decision"`
	GovernanceReq     bool      `json:"governance_required"`
	ApprovalRequestID string    `json:"approval_request_id"`
	Status            string    `json:"status"`
	RequestJSON       string    `json:"request_json"`
	ResponseJSON      string    `json:"response_json"`
	ErrorMessage      string    `json:"error_message"`
	CreatedAt         time.Time `json:"created_at"`
	CompletedAt       time.Time `json:"completed_at"`
}

type AuthIdentity struct {
	Mode         string   `json:"mode"`
	Subject      string   `json:"subject"`
	TenantID     string   `json:"tenant_id"`
	UserID       string   `json:"user_id"`
	Role         string   `json:"role"`
	TokenJTI     string   `json:"token_jti"`
	ClientCN     string   `json:"client_cn"`
	Issuer       string   `json:"issuer"`
	RemoteIP     string   `json:"remote_ip"`
	JWTIssuer    string   `json:"jwt_issuer,omitempty"`
	JWTAudiences []string `json:"jwt_audiences,omitempty"`
	// EntraTenantID is the verified Entra ID tenant (tid) of a Microsoft
	// DKE caller; empty for a Vecta token.
	EntraTenantID string `json:"entra_tenant_id,omitempty"`
	// Claims is the verified Vecta token, for permission checks.
	Claims *pkgauth.Claims `json:"-"`
}

type ProxyCryptoRequest struct {
	TenantID          string   `json:"tenant_id"`
	PlaintextB64      string   `json:"plaintext"`
	CiphertextB64     string   `json:"ciphertext"`
	IVB64             string   `json:"iv"`
	ReferenceID       string   `json:"reference_id"`
	RequesterID       string   `json:"requester_id"`
	RequesterEmail    string   `json:"requester_email"`
	JustificationCode string   `json:"justification_code,omitempty"`
	JustificationText string   `json:"justification_text,omitempty"`
	ApproverEmails    []string `json:"approver_emails"`
	// ApprovalRequestID retries a pending request once governance approved it.
	ApprovalRequestID string `json:"approval_request_id,omitempty"`
	// WrapAlgorithm asks keycore for a named wrap format (A256KW, A256KWP,
	// RSA-OAEP-256, RSA-OAEP). Set only by the Azure EKM listener; no
	// request body names it.
	WrapAlgorithm string `json:"-"`
	// AADB64 and Version reach keycore's encrypt and decrypt for AWS XKS;
	// set only by the XKS handler.
	AADB64  string `json:"-"`
	Version int    `json:"-"`
}

type ProxyCryptoResponse struct {
	Status            string `json:"status"`
	KeyID             string `json:"key_id"`
	Protocol          string `json:"protocol"`
	Operation         string `json:"operation"`
	Version           int    `json:"version,omitempty"`
	CiphertextB64     string `json:"ciphertext,omitempty"`
	PlaintextB64      string `json:"plaintext,omitempty"`
	IVB64             string `json:"iv,omitempty"`
	ApprovalRequestID string `json:"approval_request_id,omitempty"`
}

type DKEPublicKeyResponse struct {
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm"`
	PublicKey  string `json:"public_key"`
	Format     string `json:"format"`
	KeyVersion int    `json:"key_version,omitempty"`
}

// MicrosoftDKEKeyResponse follows the public key payload shape expected by
// Microsoft-compatible DKE clients.
// MicrosoftDKEKeyResponse is the DKE public key document Office reads: the
// key, whose kid is the URL Office posts decrypt requests under, and how
// long Office may cache it.
type MicrosoftDKEKeyResponse struct {
	Key   MicrosoftDKEPublicKey `json:"key"`
	Cache MicrosoftDKEKeyCache  `json:"cache"`
}

type MicrosoftDKEPublicKey struct {
	KTY string `json:"kty"`
	N   string `json:"n"`
	E   int    `json:"e"`
	Alg string `json:"alg"`
	KID string `json:"kid"`
}

type MicrosoftDKEKeyCache struct {
	Exp string `json:"exp"`
}

type MicrosoftDKEDecryptRequest struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

type MicrosoftDKEDecryptResponse struct {
	Value string `json:"value"`
}

type DKEEndpointMetadata struct {
	AuthorizedTenants []string
	ValidIssuers      []string
	JWTAudiences      []string
	KeyURIHostname    string
	AllowedAlgorithms []string
	// Who may decrypt with an Entra ID token: users with one of these
	// emails, or with one of these app roles (the token's roles claim).
	AuthorizedEmails []string
	AuthorizedRoles  []string
}

type PolicyEvaluateRequest struct {
	TenantID  string `json:"tenant_id"`
	Operation string `json:"operation"`
	KeyID     string `json:"key_id,omitempty"`
	PolicyID  string `json:"policy_id,omitempty"`
}

type PolicyEvaluateResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type GovernanceApprovalRequest struct {
	TenantID        string                 `json:"tenant_id"`
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

type GovernanceApprovalStatus struct {
	Status           string `json:"status"`
	CurrentApprovals int    `json:"current_approvals"`
	CurrentDenials   int    `json:"current_denials"`
	ExpiresAt        string `json:"expires_at"`
	Action           string `json:"action"`
	TargetType       string `json:"target_type"`
	TargetID         string `json:"target_id"`
	Operation        string `json:"operation"`
	PayloadHash      string `json:"payload_hash"`
}
