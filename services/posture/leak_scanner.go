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

// syntheticFindingsForTargetType returns a set of simulated findings appropriate
// for the given target type. These are used during simulated async scans.
func syntheticFindingsForTargetType(targetType string) []struct {
	severity       string
	findingType    string
	description    string
	location       string
	contextPreview string
	entropy        float64
} {
	switch targetType {
	case "git_repo":
		return []struct {
			severity       string
			findingType    string
			description    string
			location       string
			contextPreview string
			entropy        float64
		}{
			{"high", "aws_access_key", "AWS Access Key ID detected in source code", "config/aws.go:42", "AKIA...EXAMPLE", 4.8},
			{"critical", "private_key", "RSA private key found in repository", ".ssh/id_rsa:1", "-----BEGIN RSA PRIVATE KEY-----", 5.9},
			{"medium", "generic_secret", "Generic high-entropy string in environment file", ".env:17", "SECRET_KEY=8f3a...", 4.1},
		}
	case "container_image":
		return []struct {
			severity       string
			findingType    string
			description    string
			location       string
			contextPreview string
			entropy        float64
		}{
			{"high", "database_password", "Database password found in image layer", "layer:3/etc/app.conf:8", "DB_PASSWORD=...", 4.5},
			{"medium", "api_key", "API key embedded in container environment", "layer:1/etc/environment:3", "API_KEY=...", 4.2},
		}
	case "env_file":
		return []struct {
			severity       string
			findingType    string
			description    string
			location       string
			contextPreview string
			entropy        float64
		}{
			{"critical", "oauth_token", "OAuth token with broad permissions found", ".env.production:5", "OAUTH_TOKEN=ghp_...", 5.2},
			{"high", "jwt_secret", "JWT signing secret detected", ".env:12", "JWT_SECRET=...", 4.7},
		}
	case "s3_bucket":
		return []struct {
			severity       string
			findingType    string
			description    string
			location       string
			contextPreview string
			entropy        float64
		}{
			{"high", "aws_secret_key", "AWS Secret Access Key found in S3 object", "backups/config.json", "aws_secret_access_key: ...", 4.9},
		}
	case "log_stream":
		return []struct {
			severity       string
			findingType    string
			description    string
			location       string
			contextPreview string
			entropy        float64
		}{
			{"medium", "token_in_log", "Bearer token logged in request trace", "app.log:1042", "Authorization: Bearer ey...", 3.8},
		}
	default:
		return []struct {
			severity       string
			findingType    string
			description    string
			location       string
			contextPreview string
			entropy        float64
		}{
			{"medium", "generic_secret", "High-entropy string that may be a secret", "unknown:0", "...", 3.5},
		}
	}
}
