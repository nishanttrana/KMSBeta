package main

import "time"

// TFEAgent represents a Transparent File Encryption agent registered with the KMS.
type TFEAgent struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`           // linux, windows
	AgentVersion string    `json:"agent_version"`
	Status       string    `json:"status"` // registered, active, inactive, error
	LastSeen     time.Time `json:"last_seen"`
	PolicyCount  int       `json:"policy_count"`
	CreatedAt    time.Time `json:"created_at"`
}

// TFEPolicy defines a file encryption policy applied by an agent.
type TFEPolicy struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	AgentID        string    `json:"agent_id"`
	Name           string    `json:"name"`
	Path           string    `json:"path"`      // e.g. /var/data or C:\SensitiveData
	Recursive      bool      `json:"recursive"`
	KeyID          string    `json:"key_id"`
	Algorithm      string    `json:"algorithm"`     // AES-256-CBC, AES-256-XTS
	IncludeGlobs   []string  `json:"include_globs"` // e.g. ["*.pii", "*.csv"]
	ExcludeGlobs   []string  `json:"exclude_globs"`
	Status         string    `json:"status"` // active, paused, error
	FilesEncrypted int       `json:"files_encrypted"`
	LastActivity   time.Time `json:"last_activity"`
	CreatedAt      time.Time `json:"created_at"`
}

// TFESummary contains aggregated statistics for the TFE service.
type TFESummary struct {
	TotalAgents    int            `json:"total_agents"`
	ActiveAgents   int            `json:"active_agents"`
	TotalPolicies  int            `json:"total_policies"`
	TotalEncrypted int            `json:"total_encrypted"`
	ByOS           map[string]int `json:"by_os"`
	ByStatus       map[string]int `json:"by_status"`
}

// RegisterAgentRequest is the request body for registering a TFE agent.
type RegisterAgentRequest struct {
	TenantID     string `json:"tenant_id"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	AgentVersion string `json:"agent_version"`
}

// HeartbeatRequest is the request body for updating an agent heartbeat.
type HeartbeatRequest struct {
	Status string `json:"status"`
}

// CreatePolicyRequest is the request body for creating a TFE policy.
type CreateTFEPolicyRequest struct {
	TenantID     string   `json:"tenant_id"`
	AgentID      string   `json:"agent_id"`
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	Recursive    bool     `json:"recursive"`
	KeyID        string   `json:"key_id"`
	Algorithm    string   `json:"algorithm"`
	IncludeGlobs []string `json:"include_globs"`
	ExcludeGlobs []string `json:"exclude_globs"`
}

// UpdateTFEPolicyRequest is the request body for updating a TFE policy.
type UpdateTFEPolicyRequest struct {
	Status    *string  `json:"status,omitempty"`
	Path      *string  `json:"path,omitempty"`
	KeyID     *string  `json:"key_id,omitempty"`
	Recursive *bool    `json:"recursive,omitempty"`
	Algorithm *string  `json:"algorithm,omitempty"`
	IncludeGlobs *[]string `json:"include_globs,omitempty"`
	ExcludeGlobs *[]string `json:"exclude_globs,omitempty"`
}
