package main

import "time"

const (
	ProtocolDKE        = "dke"
	ProtocolSalesforce = "salesforce"
	ProtocolGoogleEKM  = "google"
	ProtocolGeneric    = "generic"
)

const (
	AuthModeMTLSOrJWT = "mtls_or_jwt"
	AuthModeMTLS      = "mtls"
	AuthModeJWT       = "jwt"
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
}

type ProxyCryptoRequest struct {
	TenantID       string   `json:"tenant_id"`
	PlaintextB64   string   `json:"plaintext"`
	CiphertextB64  string   `json:"ciphertext"`
	IVB64          string   `json:"iv"`
	ReferenceID    string   `json:"reference_id"`
	RequesterID    string   `json:"requester_id"`
	RequesterEmail string   `json:"requester_email"`
	ApproverEmails []string `json:"approver_emails"`
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
type MicrosoftDKEKeyResponse struct {
	KTY    string   `json:"kty"`
	KeyOps []string `json:"key_ops,omitempty"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	Alg    string   `json:"alg,omitempty"`
	KID    string   `json:"kid,omitempty"`
	Use    string   `json:"use,omitempty"`
}

type MicrosoftDKEDecryptRequest struct {
	Alg   string `json:"alg,omitempty"`
	Value string `json:"value"`
	KID   string `json:"kid,omitempty"`
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
}
