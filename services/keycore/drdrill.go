package main

import "time"

// DrillStepStatus represents the outcome of a single step in a DR drill.
type DrillStepStatus string

const (
	DrillStepStatusPending DrillStepStatus = "pending"
	DrillStepStatusRunning DrillStepStatus = "running"
	DrillStepStatusPassed  DrillStepStatus = "passed"
	DrillStepStatusFailed  DrillStepStatus = "failed"
	DrillStepStatusSkipped DrillStepStatus = "skipped"
)

// DrillStep records the outcome of one discrete step within a drill run.
type DrillStep struct {
	Name        string          `json:"name"`
	Status      DrillStepStatus `json:"status"`
	DurationMs  int64           `json:"duration_ms"`
	Detail      string          `json:"detail,omitempty"`
	ErrorMsg    string          `json:"error,omitempty"`
}

// DrillSchedule defines a recurring DR drill.
type DrillSchedule struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Name       string     `json:"name"`
	CronExpr   string     `json:"cron_expr"`
	DrillType  string     `json:"drill_type"`
	Scope      string     `json:"scope"`
	TargetEnv  string     `json:"target_env"`
	Enabled    bool       `json:"enabled"`
	LastRunAt  *time.Time `json:"last_run_at,omitempty"`
	NextRunAt  *time.Time `json:"next_run_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// DrillRun is a single execution of a DR drill, either triggered manually or
// by a schedule.
type DrillRun struct {
	ID           string      `json:"id"`
	TenantID     string      `json:"tenant_id"`
	ScheduleID   string      `json:"schedule_id,omitempty"`
	ScheduleName string      `json:"schedule_name,omitempty"`
	DrillType    string      `json:"drill_type"`
	Status       string      `json:"status"`
	StartedAt    time.Time   `json:"started_at"`
	CompletedAt  *time.Time  `json:"completed_at,omitempty"`
	RTOSeconds   int         `json:"rto_seconds,omitempty"`
	RPOSeconds   int         `json:"rpo_seconds,omitempty"`
	TotalKeys    int         `json:"total_keys"`
	RestoredKeys int         `json:"restored_keys"`
	FailedKeys   int         `json:"failed_keys"`
	Steps        []DrillStep `json:"steps"`
	TriggeredBy  string      `json:"triggered_by"`
}

// DrillMetrics aggregates statistics across all drill runs for a tenant.
type DrillMetrics struct {
	TotalRuns        int     `json:"total_runs"`
	SuccessfulRuns   int     `json:"successful_runs"`
	FailedRuns       int     `json:"failed_runs"`
	AvgRTOSeconds    float64 `json:"avg_rto_seconds"`
	AvgRPOSeconds    float64 `json:"avg_rpo_seconds"`
	AvgKeyRestoreRate float64 `json:"avg_key_restore_rate"` // percentage
	LastRunStatus    string  `json:"last_run_status"`
	LastRunAt        *time.Time `json:"last_run_at,omitempty"`
}
