package main

import "time"

// MeshService represents a service registered in the mTLS mesh.
type MeshService struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	Name            string     `json:"name"`
	Namespace       string     `json:"namespace"`
	Endpoint        string     `json:"endpoint"`
	CertID          string     `json:"cert_id,omitempty"`
	CertCN          string     `json:"cert_cn,omitempty"`
	CertExpiry      *time.Time `json:"cert_expiry,omitempty"`
	CertStatus      string     `json:"cert_status"`
	LastRenewedAt   *time.Time `json:"last_renewed_at,omitempty"`
	AutoRenew       bool       `json:"auto_renew"`
	RenewDaysBefore int        `json:"renew_days_before"`
	TrustAnchors    []string   `json:"trust_anchors"`
	MTLSEnabled     bool       `json:"mtls_enabled"`
	CreatedAt       time.Time  `json:"created_at"`
}

// MeshCertificate represents a certificate issued to a mesh service.
type MeshCertificate struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	ServiceID    string    `json:"service_id"`
	ServiceName  string    `json:"service_name"`
	CN           string    `json:"cn"`
	SANs         []string  `json:"sans"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Serial       string    `json:"serial"`
	Fingerprint  string    `json:"fingerprint"`
	KeyAlgorithm string    `json:"key_algorithm"`
	Revoked      bool      `json:"revoked"`
	CreatedAt    time.Time `json:"created_at"`
}

// TrustAnchor represents a trusted CA certificate in the mesh.
type TrustAnchor struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Fingerprint string  `json:"fingerprint"`
	Subject   string    `json:"subject"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	CreatedAt time.Time `json:"created_at"`
}

// MeshTopologyEdge represents a verified mTLS connection between two mesh services.
type MeshTopologyEdge struct {
	TenantID        string     `json:"tenant_id"`
	FromService     string     `json:"from_service"`
	ToService       string     `json:"to_service"`
	MTLSVerified    bool       `json:"mtls_verified"`
	LastHandshakeAt *time.Time `json:"last_handshake_at,omitempty"`
}

// RegisterServiceRequest is the request body for registering a mesh service.
type RegisterServiceRequest struct {
	TenantID        string   `json:"tenant_id"`
	Name            string   `json:"name"`
	Namespace       string   `json:"namespace"`
	Endpoint        string   `json:"endpoint"`
	AutoRenew       bool     `json:"auto_renew"`
	RenewDaysBefore int      `json:"renew_days_before"`
	TrustAnchors    []string `json:"trust_anchors"`
	MTLSEnabled     bool     `json:"mtls_enabled"`
}

// AddTrustAnchorRequest is the request body for adding a trust anchor.
type AddTrustAnchorRequest struct {
	TenantID    string `json:"tenant_id"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
}
