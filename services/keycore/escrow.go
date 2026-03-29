package main

import "time"

// EscrowGuardian is a trusted party who holds a share of an escrowed key.
type EscrowGuardian struct {
	ID                   string    `json:"id"`
	TenantID             string    `json:"tenant_id"`
	Name                 string    `json:"name"`
	Email                string    `json:"email"`
	Organization         string    `json:"organization"`
	NotaryCertFingerprint string   `json:"notary_cert_fingerprint"`
	Status               string    `json:"status"`
	AddedAt              time.Time `json:"added_at"`
}

// EscrowPolicy defines which keys are escrowed and how many guardians must
// approve a recovery request.
type EscrowPolicy struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	KeyFilter      string    `json:"key_filter"`
	Threshold      int       `json:"threshold"`
	GuardianIDs    []string  `json:"guardian_ids"`
	LegalHold      bool      `json:"legal_hold"`
	Jurisdiction   string    `json:"jurisdiction"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	EscrowCount    int       `json:"escrow_count"`
}

// EscrowedKey represents a key that has been placed into escrow under a policy.
type EscrowedKey struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	PolicyID    string    `json:"policy_id"`
	PolicyName  string    `json:"policy_name"`
	KeyID       string    `json:"key_id"`
	KeyName     string    `json:"key_name"`
	Algorithm   string    `json:"algorithm"`
	GuardianIDs []string  `json:"guardian_ids"`
	Status      string    `json:"status"`
	EscrowedAt  time.Time `json:"escrowed_at"`
	EscrowedBy  string    `json:"escrowed_by"`
}

// RecoveryApproval records a single guardian's approval or denial of a
// recovery request.
type RecoveryApproval struct {
	GuardianID string    `json:"guardian_id"`
	Decision   string    `json:"decision"`
	DecidedAt  time.Time `json:"decided_at"`
	Notes      string    `json:"notes,omitempty"`
}

// RecoveryRequest is a request to recover an escrowed key.
type RecoveryRequest struct {
	ID               string             `json:"id"`
	TenantID         string             `json:"tenant_id"`
	EscrowID         string             `json:"escrow_id"`
	KeyID            string             `json:"key_id"`
	KeyName          string             `json:"key_name"`
	Requestor        string             `json:"requestor"`
	Reason           string             `json:"reason"`
	LegalReference   string             `json:"legal_reference"`
	Status           string             `json:"status"`
	RequiredApprovals int               `json:"required_approvals"`
	Approvals        []RecoveryApproval `json:"approvals"`
	CreatedAt        time.Time          `json:"created_at"`
	CompletedAt      *time.Time         `json:"completed_at,omitempty"`
}
