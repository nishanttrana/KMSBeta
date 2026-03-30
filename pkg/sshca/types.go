package sshca

import "time"

// UserCertRequest describes a request to sign an SSH user certificate.
type UserCertRequest struct {
	TenantID        string            `json:"tenant_id"`
	PublicKey        []byte            `json:"public_key"`         // authorized_keys format or raw SSH public key bytes
	Username         string            `json:"username"`           // maps to KeyId in the certificate
	Principals       []string          `json:"principals"`         // allowed login usernames
	TTL              time.Duration     `json:"ttl"`                // certificate validity duration
	SourceAddresses  []string          `json:"source_addresses"`   // CriticalOption: source-address (CIDR)
	ForceCommand     string            `json:"force_command"`      // CriticalOption: force-command
	Extensions       map[string]string `json:"extensions"`         // additional extensions
}

// HostCertRequest describes a request to sign an SSH host certificate.
type HostCertRequest struct {
	TenantID  string        `json:"tenant_id"`
	PublicKey []byte        `json:"public_key"` // authorized_keys format or raw SSH public key bytes
	Hostnames []string      `json:"hostnames"`  // ValidPrincipals for the host cert
	TTL       time.Duration `json:"ttl"`
}

// IssuedCert tracks a certificate that was signed by the CA.
type IssuedCert struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	CertType    string    `json:"cert_type"` // "user" or "host"
	KeyID       string    `json:"key_id"`
	Principals  []string  `json:"principals"`
	Serial      uint64    `json:"serial"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
}

// CertPolicy defines constraints for certificate issuance per tenant.
type CertPolicy struct {
	TenantID              string   `json:"tenant_id"`
	MaxTTL                time.Duration `json:"max_ttl"`
	AllowedPrincipals     []string `json:"allowed_principals"`
	AllowedExtensions     []string `json:"allowed_extensions"`
	AllowedSourceAddresses []string `json:"allowed_source_addresses"`
	RequireSourceAddress  bool     `json:"require_source_address"`
}
