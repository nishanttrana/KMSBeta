package main

import "time"

type RotationPolicy struct {
	ID               string     `json:"id"`
	TenantID         string     `json:"tenant_id"`
	Name             string     `json:"name"`
	TargetType       string     `json:"target_type"`
	TargetFilter     string     `json:"target_filter"`
	IntervalDays     int        `json:"interval_days"`
	CronExpr         string     `json:"cron_expr,omitempty"`
	AutoRotate       bool       `json:"auto_rotate"`
	NotifyDaysBefore int        `json:"notify_days_before"`
	Enabled          bool       `json:"enabled"`
	Status           string     `json:"status"`
	LastRotationAt   *time.Time `json:"last_rotation_at,omitempty"`
	NextRotationAt   *time.Time `json:"next_rotation_at,omitempty"`
	TotalRotations   int        `json:"total_rotations"`
	LastError        string     `json:"last_error,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type RotationRun struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	PolicyID    string     `json:"policy_id"`
	PolicyName  string     `json:"policy_name"`
	TargetID    string     `json:"target_id"`
	TargetName  string     `json:"target_name"`
	TargetType  string     `json:"target_type"`
	Status      string     `json:"status"`
	TriggeredBy string     `json:"triggered_by"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}

type UpcomingRotation struct {
	PolicyID    string    `json:"policy_id"`
	PolicyName  string    `json:"policy_name"`
	TargetID    string    `json:"target_id"`
	TargetName  string    `json:"target_name"`
	TargetType  string    `json:"target_type"`
	ScheduledAt time.Time `json:"scheduled_at"`
	DaysUntil   int       `json:"days_until"`
	Overdue     bool      `json:"overdue"`
}

type CreateRotationPolicyRequest struct {
	TenantID         string `json:"tenant_id"`
	Name             string `json:"name"`
	TargetType       string `json:"target_type"`
	TargetFilter     string `json:"target_filter"`
	IntervalDays     int    `json:"interval_days"`
	CronExpr         string `json:"cron_expr,omitempty"`
	AutoRotate       bool   `json:"auto_rotate"`
	NotifyDaysBefore int    `json:"notify_days_before"`
}
