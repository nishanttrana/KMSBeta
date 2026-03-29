package main

import "time"

// BackupPolicy defines a scheduled backup policy.
type BackupPolicy struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	Scope          string     `json:"scope"`
	TagFilter      string     `json:"tag_filter"`
	CronExpr       string     `json:"cron_expr"`
	RetentionDays  int        `json:"retention_days"`
	EncryptBackup  bool       `json:"encrypt_backup"`
	Compress       bool       `json:"compress"`
	Destination    string     `json:"destination"`
	DestinationURI string     `json:"destination_uri"`
	Enabled        bool       `json:"enabled"`
	LastRunAt      *time.Time `json:"last_run_at,omitempty"`
	NextRunAt      *time.Time `json:"next_run_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// BackupRun records a single backup execution.
type BackupRun struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	PolicyID        string     `json:"policy_id,omitempty"`
	PolicyName      string     `json:"policy_name,omitempty"`
	Status          string     `json:"status"`
	Scope           string     `json:"scope"`
	TotalKeys       int        `json:"total_keys"`
	BackedUpKeys    int        `json:"backed_up_keys"`
	FailedKeys      int        `json:"failed_keys"`
	BackupSizeBytes int64      `json:"backup_size_bytes"`
	Destination     string     `json:"destination"`
	DestinationPath string     `json:"destination_path"`
	TriggeredBy     string     `json:"triggered_by"`
	StartedAt       time.Time  `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	Error           string     `json:"error,omitempty"`
}

// RestorePoint represents a restorable backup snapshot.
type RestorePoint struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	RunID           string     `json:"run_id"`
	Name            string     `json:"name"`
	KeyCount        int        `json:"key_count"`
	BackupSizeBytes int64      `json:"backup_size_bytes"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	Checksum        string     `json:"checksum"`
	Status          string     `json:"status"`
}

// BackupMetrics contains aggregated backup statistics for a tenant.
type BackupMetrics struct {
	TenantID          string    `json:"tenant_id"`
	TotalPolicies     int       `json:"total_policies"`
	EnabledPolicies   int       `json:"enabled_policies"`
	TotalRuns         int       `json:"total_runs"`
	SuccessfulRuns    int       `json:"successful_runs"`
	FailedRuns        int       `json:"failed_runs"`
	RunningRuns       int       `json:"running_runs"`
	TotalRestorePoints int      `json:"total_restore_points"`
	TotalBackupBytes  int64     `json:"total_backup_bytes"`
	LastRunAt         *time.Time `json:"last_run_at,omitempty"`
	ComputedAt        time.Time  `json:"computed_at"`
}

// CreatePolicyRequest is the request body for creating a backup policy.
type CreatePolicyRequest struct {
	TenantID       string `json:"tenant_id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	Scope          string `json:"scope"`
	TagFilter      string `json:"tag_filter"`
	CronExpr       string `json:"cron_expr"`
	RetentionDays  int    `json:"retention_days"`
	EncryptBackup  bool   `json:"encrypt_backup"`
	Compress       bool   `json:"compress"`
	Destination    string `json:"destination"`
	DestinationURI string `json:"destination_uri"`
}

// UpdatePolicyRequest is the request body for patching a backup policy.
type UpdatePolicyRequest struct {
	Enabled        *bool   `json:"enabled,omitempty"`
	CronExpr       *string `json:"cron_expr,omitempty"`
	RetentionDays  *int    `json:"retention_days,omitempty"`
	DestinationURI *string `json:"destination_uri,omitempty"`
}

// TriggerBackupRequest is the optional request body for a manual backup trigger.
type TriggerBackupRequest struct {
	TriggeredBy string `json:"triggered_by"`
}
