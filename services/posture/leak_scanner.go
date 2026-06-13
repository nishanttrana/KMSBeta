package main

import "time"

// LeakScanTarget is a registered source to be scanned for credential/secret leaks.
type LeakScanTarget struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	Name         string     `json:"name"`
	Type         string     `json:"type"` // git_repo, container_image, log_stream, s3_bucket, env_file
	URI          string     `json:"uri"`
	Enabled      bool       `json:"enabled"`
	LastScannedAt *time.Time `json:"last_scanned_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	ScanCount    int        `json:"scan_count"`
	OpenFindings int        `json:"open_findings"`
}

// LeakScanJob represents an in-progress or completed scan job.
type LeakScanJob struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	TargetID      string     `json:"target_id"`
	TargetName    string     `json:"target_name"`
	TargetType    string     `json:"target_type"`
	Status        string     `json:"status"` // queued, running, completed, failed
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	FindingsCount int        `json:"findings_count"`
	Error         string     `json:"error,omitempty"`
	ProgressPct   int        `json:"progress_pct"`
	CreatedAt     time.Time  `json:"created_at"`
}

// LeakFinding is a detected secret or credential exposure found during a scan.
type LeakFinding struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	JobID          string     `json:"job_id"`
	TargetID       string     `json:"target_id"`
	TargetName     string     `json:"target_name"`
	Severity       string     `json:"severity"` // critical, high, medium, low
	Type           string     `json:"type"`
	Description    string     `json:"description"`
	Location       string     `json:"location"`
	ContextPreview string     `json:"context_preview"`
	Entropy        float64    `json:"entropy"`
	// SecretFingerprint is the SHA-256 of the matched secret; the join key
	// the unified console uses to correlate a leaked credential with the KMS
	// key that protects it (via keycore's credential-binding registry).
	SecretFingerprint string  `json:"secret_fingerprint,omitempty"`
	Status         string     `json:"status"` // open, resolved, suppressed, false_positive
	DetectedAt     time.Time  `json:"detected_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy     string     `json:"resolved_by,omitempty"`
	Notes          string     `json:"notes,omitempty"`
}

// CreateLeakTargetRequest is the request body for registering a new scan target.
type CreateLeakTargetRequest struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	URI     string `json:"uri"`
	Enabled *bool  `json:"enabled"`
}

// UpdateLeakFindingRequest is the request body for updating a finding's status/notes.
type UpdateLeakFindingRequest struct {
	Status     *string `json:"status"`
	ResolvedBy *string `json:"resolved_by"`
	Notes      *string `json:"notes"`
}
