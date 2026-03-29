package main

import "time"

type CeremonyGuardian struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	JoinedAt  time.Time `json:"joined_at"`
	CreatedAt time.Time `json:"created_at"`
}

type CeremonyShare struct {
	CeremonyID   string     `json:"ceremony_id"`
	TenantID     string     `json:"tenant_id"`
	GuardianID   string     `json:"guardian_id"`
	GuardianName string     `json:"guardian_name"`
	Status       string     `json:"status"`
	SubmittedAt  *time.Time `json:"submitted_at,omitempty"`
}

type Ceremony struct {
	ID          string          `json:"id"`
	TenantID    string          `json:"tenant_id"`
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Threshold   int             `json:"threshold"`
	TotalShares int             `json:"total_shares"`
	Status      string          `json:"status"`
	KeyID       string          `json:"key_id,omitempty"`
	KeyName     string          `json:"key_name,omitempty"`
	Notes       string          `json:"notes"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	Shares      []CeremonyShare `json:"shares"`
}

type CreateCeremonyRequest struct {
	TenantID    string   `json:"tenant_id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Threshold   int      `json:"threshold"`
	TotalShares int      `json:"total_shares"`
	GuardianIDs []string `json:"guardian_ids"`
	KeyID       string   `json:"key_id,omitempty"`
	Notes       string   `json:"notes,omitempty"`
}

type CreateGuardianRequest struct {
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

type SubmitShareRequest struct {
	GuardianID   string `json:"guardian_id"`
	SharePayload string `json:"share_payload"`
}
