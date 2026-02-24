package main

import "time"

const (
	SecretStatusActive  = "active"
	SecretStatusDeleted = "deleted"
)

var supportedSecretTypes = map[string]struct{}{
	"api_key":               {},
	"ssh_private_key":       {},
	"ssh_public_key":        {},
	"pgp_private_key":       {},
	"pgp_public_key":        {},
	"ppk":                   {},
	"x509_certificate":      {},
	"pkcs12":                {},
	"jwk":                   {},
	"kerberos_keytab":       {},
	"oauth_client_secret":   {},
	"wireguard_private_key": {},
	"wireguard_public_key":  {},
	"bitlocker_keys":        {},
	"age_key":               {},
	"password":              {},
	"token":                 {},
	"database_credentials":  {},
	"tls_private_key":       {},
	"tls_certificate":       {},
	"binary_blob":           {},
}

type Secret struct {
	ID              string                 `json:"id"`
	TenantID        string                 `json:"tenant_id"`
	Name            string                 `json:"name"`
	SecretType      string                 `json:"secret_type"`
	Description     string                 `json:"description"`
	Labels          map[string]string      `json:"labels"`
	Metadata        map[string]interface{} `json:"metadata"`
	Status          string                 `json:"status"`
	LeaseTTLSeconds int64                  `json:"lease_ttl_seconds"`
	ExpiresAt       *time.Time             `json:"expires_at,omitempty"`
	CurrentVersion  int                    `json:"current_version"`
	CreatedBy       string                 `json:"created_by"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

type EncryptedSecretValue struct {
	WrappedDEK   []byte
	WrappedDEKIV []byte
	Ciphertext   []byte
	DataIV       []byte
	ValueHash    []byte
}

type CreateSecretRequest struct {
	TenantID        string                 `json:"tenant_id"`
	Name            string                 `json:"name"`
	SecretType      string                 `json:"secret_type"`
	Value           string                 `json:"value"`
	Description     string                 `json:"description"`
	Labels          map[string]string      `json:"labels"`
	Metadata        map[string]interface{} `json:"metadata"`
	LeaseTTLSeconds int64                  `json:"lease_ttl_seconds"`
	CreatedBy       string                 `json:"created_by"`
}

type UpdateSecretRequest struct {
	Name            *string                 `json:"name,omitempty"`
	Description     *string                 `json:"description,omitempty"`
	Labels          *map[string]string      `json:"labels,omitempty"`
	Metadata        *map[string]interface{} `json:"metadata,omitempty"`
	LeaseTTLSeconds *int64                  `json:"lease_ttl_seconds,omitempty"`
	Value           *string                 `json:"value,omitempty"`
	UpdatedBy       string                  `json:"updated_by"`
}

type GenerateSSHKeyRequest struct {
	TenantID        string            `json:"tenant_id"`
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	Labels          map[string]string `json:"labels"`
	LeaseTTLSeconds int64             `json:"lease_ttl_seconds"`
	CreatedBy       string            `json:"created_by"`
}

type GenerateKeyPairRequest struct {
	TenantID        string            `json:"tenant_id"`
	Name            string            `json:"name"`
	KeyType         string            `json:"key_type"`
	Description     string            `json:"description"`
	Labels          map[string]string `json:"labels"`
	LeaseTTLSeconds int64             `json:"lease_ttl_seconds"`
	CreatedBy       string            `json:"created_by"`
}

type SecretValueResponse struct {
	Value       string `json:"value"`
	Format      string `json:"format"`
	ContentType string `json:"content_type"`
}
