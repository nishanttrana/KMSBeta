package main

import "time"

// KEK is a Key Encryption Key used to wrap DEKs.
type KEK struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	Name          string     `json:"name"`
	Algorithm     string     `json:"algorithm"`
	Version       int        `json:"version"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	LastRotatedAt *time.Time `json:"last_rotated_at,omitempty"`
}

// DEK is a Data Encryption Key that has been wrapped by a KEK.
type DEK struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	KEKID        string     `json:"kek_id"`
	KEKName      string     `json:"kek_name"`
	Name         string     `json:"name"`
	Algorithm    string     `json:"algorithm"`
	Purpose      string     `json:"purpose"`
	OwnerService string     `json:"owner_service"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

// EnvelopeHierarchyNode represents a KEK with its associated DEKs.
type EnvelopeHierarchyNode struct {
	KEK  KEK   `json:"kek"`
	DEKs []DEK `json:"deks"`
}

// RewrapJob tracks the progress of re-wrapping DEKs from one KEK to another.
type RewrapJob struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	OldKEKID      string     `json:"old_kek_id"`
	NewKEKID      string     `json:"new_kek_id"`
	TotalDEKs     int        `json:"total_deks"`
	ProcessedDEKs int        `json:"processed_deks"`
	Status        string     `json:"status"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	Error         string     `json:"error,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// CreateKEKRequest is the request body for creating a new KEK.
type CreateKEKRequest struct {
	TenantID  string `json:"tenant_id"`
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
}

// StartRewrapRequest is the request body for starting a DEK rewrap job.
type StartRewrapRequest struct {
	TenantID string `json:"tenant_id"`
	OldKEKID string `json:"old_kek_id"`
	NewKEKID string `json:"new_kek_id"`
}
