package main

import "time"

type WorkloadIdentitySettings struct {
	TenantID              string    `json:"tenant_id"`
	Enabled               bool      `json:"enabled"`
	TrustDomain           string    `json:"trust_domain"`
	FederationEnabled     bool      `json:"federation_enabled"`
	TokenExchangeEnabled  bool      `json:"token_exchange_enabled"`
	DisableStaticAPIKeys  bool      `json:"disable_static_api_keys"`
	DefaultX509TTLSeconds int       `json:"default_x509_ttl_seconds"`
	DefaultJWTTTLSeconds  int       `json:"default_jwt_ttl_seconds"`
	RotationWindowSeconds int       `json:"rotation_window_seconds"`
	AllowedAudiences      []string  `json:"allowed_audiences"`
	LocalBundleJWKS       string    `json:"local_bundle_jwks,omitempty"`
	LocalCACertificatePEM string    `json:"local_ca_certificate_pem,omitempty"`
	JWTSignerKeyID        string    `json:"jwt_signer_key_id,omitempty"`
	UpdatedBy             string    `json:"updated_by,omitempty"`
	UpdatedAt             time.Time `json:"updated_at,omitempty"`
	LocalCAKeyPEM         string    `json:"-"`
	JWTSignerPrivatePEM   string    `json:"-"`
	JWTSignerPublicPEM    string    `json:"-"`
}

type WorkloadRegistration struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	Name              string    `json:"name"`
	SpiffeID          string    `json:"spiffe_id"`
	Selectors         []string  `json:"selectors"`
	AllowedInterfaces []string  `json:"allowed_interfaces"`
	AllowedKeyIDs     []string  `json:"allowed_key_ids"`
	Permissions       []string  `json:"permissions"`
	IssueX509SVID     bool      `json:"issue_x509_svid"`
	IssueJWTSVID      bool      `json:"issue_jwt_svid"`
	DefaultTTLSeconds int       `json:"default_ttl_seconds"`
	Enabled           bool      `json:"enabled"`
	LastIssuedAt      time.Time `json:"last_issued_at,omitempty"`
	LastUsedAt        time.Time `json:"last_used_at,omitempty"`
	CreatedAt         time.Time `json:"created_at,omitempty"`
	UpdatedAt         time.Time `json:"updated_at,omitempty"`
}

type WorkloadFederationBundle struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	TrustDomain    string    `json:"trust_domain"`
	BundleEndpoint string    `json:"bundle_endpoint,omitempty"`
	JWKSJSON       string    `json:"jwks_json,omitempty"`
	CABundlePEM    string    `json:"ca_bundle_pem,omitempty"`
	Enabled        bool      `json:"enabled"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
}

type WorkloadIssuanceRecord struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	RegistrationID string    `json:"registration_id"`
	SpiffeID       string    `json:"spiffe_id"`
	SVIDType       string    `json:"svid_type"`
	Audiences      []string  `json:"audiences,omitempty"`
	SerialOrKeyID  string    `json:"serial_or_key_id"`
	DocumentHash   string    `json:"document_hash,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
	RotationDueAt  time.Time `json:"rotation_due_at,omitempty"`
	Status         string    `json:"status"`
	IssuedAt       time.Time `json:"issued_at"`
}

type WorkloadUsageRecord struct {
	EventID          string    `json:"event_id"`
	TenantID         string    `json:"tenant_id"`
	WorkloadIdentity string    `json:"workload_identity"`
	TrustDomain      string    `json:"trust_domain,omitempty"`
	KeyID            string    `json:"key_id,omitempty"`
	Operation        string    `json:"operation"`
	InterfaceName    string    `json:"interface_name,omitempty"`
	ClientID         string    `json:"client_id,omitempty"`
	Result           string    `json:"result,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

type WorkloadIdentitySummary struct {
	TenantID                    string    `json:"tenant_id"`
	Enabled                     bool      `json:"enabled"`
	TrustDomain                 string    `json:"trust_domain"`
	FederationEnabled           bool      `json:"federation_enabled"`
	TokenExchangeEnabled        bool      `json:"token_exchange_enabled"`
	DisableStaticAPIKeys        bool      `json:"disable_static_api_keys"`
	RegistrationCount           int       `json:"registration_count"`
	EnabledRegistrationCount    int       `json:"enabled_registration_count"`
	FederatedTrustDomainCount   int       `json:"federated_trust_domain_count"`
	IssuanceCount24h            int       `json:"issuance_count_24h"`
	TokenExchangeCount24h       int       `json:"token_exchange_count_24h"`
	KeyUsageCount24h            int       `json:"key_usage_count_24h"`
	UniqueWorkloadsUsingKeys24h int       `json:"unique_workloads_using_keys_24h"`
	UniqueKeysUsed24h           int       `json:"unique_keys_used_24h"`
	ExpiringSVIDCount           int       `json:"expiring_svid_count"`
	ExpiredSVIDCount            int       `json:"expired_svid_count"`
	OverPrivilegedCount         int       `json:"over_privileged_count"`
	LastExchangeAt              time.Time `json:"last_exchange_at,omitempty"`
	LastKeyUseAt                time.Time `json:"last_key_use_at,omitempty"`
	RotationHealthy             bool      `json:"rotation_healthy"`
}

type WorkloadGraphNode struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type WorkloadGraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label"`
	Kind   string `json:"kind"`
	Weight int    `json:"weight,omitempty"`
}

type WorkloadAuthorizationGraph struct {
	TenantID    string              `json:"tenant_id"`
	GeneratedAt time.Time           `json:"generated_at"`
	Nodes       []WorkloadGraphNode `json:"nodes"`
	Edges       []WorkloadGraphEdge `json:"edges"`
}

type IssueSVIDRequest struct {
	TenantID       string   `json:"tenant_id"`
	RegistrationID string   `json:"registration_id"`
	SpiffeID       string   `json:"spiffe_id,omitempty"`
	SVIDType       string   `json:"svid_type"`
	Audiences      []string `json:"audiences,omitempty"`
	TTLSeconds     int      `json:"ttl_seconds,omitempty"`
	RequestedBy    string   `json:"requested_by,omitempty"`
}

type IssuedSVID struct {
	IssuanceID              string    `json:"issuance_id"`
	RegistrationID          string    `json:"registration_id"`
	SpiffeID                string    `json:"spiffe_id"`
	SVIDType                string    `json:"svid_type"`
	CertificatePEM          string    `json:"certificate_pem,omitempty"`
	PrivateKeyPEM           string    `json:"private_key_pem,omitempty"`
	BundlePEM               string    `json:"bundle_pem,omitempty"`
	JWTSVID                 string    `json:"jwt_svid,omitempty"`
	JWKSJSON                string    `json:"jwks_json,omitempty"`
	SerialOrKeyID           string    `json:"serial_or_key_id"`
	ExpiresAt               time.Time `json:"expires_at"`
	RotationDueAt           time.Time `json:"rotation_due_at"`
	CryptographicallySigned bool      `json:"cryptographically_signed"`
}

type TokenExchangeRequest struct {
	TenantID             string   `json:"tenant_id"`
	RegistrationID       string   `json:"registration_id,omitempty"`
	InterfaceName        string   `json:"interface_name"`
	ClientID             string   `json:"client_id,omitempty"`
	Audience             string   `json:"audience,omitempty"`
	JWTSVID              string   `json:"jwt_svid,omitempty"`
	X509SVIDChainPEM     string   `json:"x509_svid_chain_pem,omitempty"`
	RequestedPermissions []string `json:"requested_permissions,omitempty"`
	RequestedKeyIDs      []string `json:"requested_key_ids,omitempty"`
}

type TokenExchangeResult struct {
	TenantID             string    `json:"tenant_id"`
	RegistrationID       string    `json:"registration_id"`
	SpiffeID             string    `json:"spiffe_id"`
	TrustDomain          string    `json:"trust_domain"`
	SVIDType             string    `json:"svid_type"`
	InterfaceName        string    `json:"interface_name"`
	AllowedPermissions   []string  `json:"allowed_permissions"`
	AllowedKeyIDs        []string  `json:"allowed_key_ids"`
	KMSAccessToken       string    `json:"kms_access_token"`
	KMSAccessTokenExpiry time.Time `json:"kms_access_token_expiry"`
	SVIDExpiresAt        time.Time `json:"svid_expires_at,omitempty"`
	RotationDueAt        time.Time `json:"rotation_due_at,omitempty"`
}
