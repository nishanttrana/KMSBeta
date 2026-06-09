package main

import "time"

type RotationMetric struct {
	RotationID      string         `json:"rotation_id"`
	TenantID        string         `json:"tenant_id"`
	KeyID           string         `json:"key_id"`
	ScheduledDate   time.Time      `json:"scheduled_date"`
	ActualDate      *time.Time     `json:"actual_date,omitempty"`
	Status          string         `json:"status"`
	DurationMs      int64          `json:"duration_ms,omitempty"`
	Reason          string         `json:"reason,omitempty"`
	InitiatedBy     string         `json:"initiated_by,omitempty"`
	CompletedBy     string         `json:"completed_by,omitempty"`
	ErrorDetails    string         `json:"error_details,omitempty"`
	OldVersion      int            `json:"old_version,omitempty"`
	NewVersion      int            `json:"new_version,omitempty"`
	RollbackAttempt bool           `json:"rollback_attempted,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

type RotationAnalyticsSummary struct {
	TenantID          string     `json:"tenant_id"`
	WindowDays        int        `json:"window_days"`
	Total             int        `json:"total"`
	Scheduled         int        `json:"scheduled"`
	InProgress        int        `json:"in_progress"`
	Completed         int        `json:"completed"`
	Failed            int        `json:"failed"`
	Cancelled         int        `json:"cancelled"`
	Overdue           int        `json:"overdue"`
	SuccessRate       float64    `json:"success_rate"`
	AverageDurationMs int64      `json:"average_duration_ms"`
	BatchOperations   int        `json:"batch_operations"`
	NextScheduledAt   *time.Time `json:"next_scheduled_at,omitempty"`
	LastCompletedAt   *time.Time `json:"last_completed_at,omitempty"`
	GeneratedAt       time.Time  `json:"generated_at"`
}

type KeyAnalyticsMetric struct {
	MetricID          string         `json:"metric_id"`
	TenantID          string         `json:"tenant_id"`
	KeyID             string         `json:"key_id"`
	MetricType        string         `json:"metric_type"`
	Value             float64        `json:"value"`
	AggregationPeriod string         `json:"aggregation_period"`
	Timestamp         time.Time      `json:"timestamp"`
	Metadata          map[string]any `json:"metadata,omitempty"`
}

type MetricAggregate struct {
	Type    string  `json:"type"`
	Count   int64   `json:"count"`
	Average float64 `json:"average"`
	Maximum float64 `json:"maximum"`
	Minimum float64 `json:"minimum"`
}

type KeyUsageMetricSummary struct {
	TenantID    string            `json:"tenant_id"`
	KeyID       string            `json:"key_id,omitempty"`
	Since       time.Time         `json:"since"`
	Metrics     []MetricAggregate `json:"metrics"`
	GeneratedAt time.Time         `json:"generated_at"`
}

type KeyHotspot struct {
	KeyID       string     `json:"key_id"`
	AccessCount int64      `json:"access_count"`
	Percentile  float64    `json:"percentile"`
	LastAccess  *time.Time `json:"last_access,omitempty"`
	ServiceIDs  []string   `json:"service_ids,omitempty"`
}

type TrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Change    float64   `json:"change"`
}

type AlgorithmBenchmark struct {
	Algorithm       string  `json:"algorithm"`
	Operation       string  `json:"operation"`
	Count           int64   `json:"count"`
	AverageLatency  float64 `json:"average_latency_ms"`
	FailureRate     float64 `json:"failure_rate"`
	SuccessRate     float64 `json:"success_rate"`
	PerformanceBand string  `json:"performance_band"`
}

type KeyHealthScore struct {
	KeyID              string     `json:"key_id"`
	TenantID           string     `json:"tenant_id"`
	HealthScore        int        `json:"health_score"`
	EntropyScore       int        `json:"entropy_score"`
	AgeScore           int        `json:"age_score"`
	UsageScore         int        `json:"usage_score"`
	AlgorithmScore     int        `json:"algorithm_score"`
	BackupStatus       string     `json:"backup_status"`
	RotationOverdue    bool       `json:"rotation_overdue"`
	ExpiryImminent     bool       `json:"expiry_imminent"`
	ComplianceWarnings []string   `json:"compliance_warnings,omitempty"`
	RecommendedActions []string   `json:"recommended_actions,omitempty"`
	LastAuditDate      *time.Time `json:"last_audit_date,omitempty"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type KeyHealthSummary struct {
	TenantID         string    `json:"tenant_id"`
	TotalKeys        int       `json:"total_keys"`
	AverageHealth    float64   `json:"average_health"`
	HealthyKeys      int       `json:"healthy_keys"`
	AtRiskKeys       int       `json:"at_risk_keys"`
	CriticalKeys     int       `json:"critical_keys"`
	OverdueRotations int       `json:"overdue_rotations"`
	ExpiringSoon     int       `json:"expiring_soon"`
	HealthPercentage float64   `json:"health_percentage"`
	GeneratedAt      time.Time `json:"generated_at"`
}

type KeyInventoryItem struct {
	KeyID              string         `json:"key_id"`
	TenantID           string         `json:"tenant_id"`
	KeyName            string         `json:"key_name"`
	KeyType            string         `json:"key_type"`
	Algorithm          string         `json:"algorithm"`
	Owner              string         `json:"owner"`
	Status             string         `json:"status"`
	CreatedDate        time.Time      `json:"created_date"`
	LastUsed           *time.Time     `json:"last_used,omitempty"`
	LastRotated        *time.Time     `json:"last_rotated,omitempty"`
	RotationFrequency  string         `json:"rotation_frequency,omitempty"`
	NextRotation       *time.Time     `json:"next_rotation,omitempty"`
	ExpiryDate         *time.Time     `json:"expiry_date,omitempty"`
	BackupVerifiedAt   *time.Time     `json:"backup_verified_at,omitempty"`
	HSMStored          bool           `json:"hsm_stored"`
	CloudProvider      string         `json:"cloud_provider,omitempty"`
	Region             string         `json:"region,omitempty"`
	ComplianceTags     []string       `json:"compliance_tags,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	DiscoveredVia      string         `json:"discovered_via,omitempty"`
	DiscoveryTimestamp *time.Time     `json:"discovery_timestamp,omitempty"`
}

type KeyDependencyRecord struct {
	DependencyID       string         `json:"dependency_id"`
	TenantID           string         `json:"tenant_id"`
	KeyID              string         `json:"key_id"`
	ServiceID          string         `json:"service_id"`
	AppID              string         `json:"app_id,omitempty"`
	DependencyType     string         `json:"dependency_type"`
	Criticality        string         `json:"criticality"`
	LastVerified       *time.Time     `json:"last_verified,omitempty"`
	VerificationStatus string         `json:"verification_status"`
	UsageFrequency     string         `json:"usage_frequency"`
	LastAccessLogID    string         `json:"last_access_log_id,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	DiscoveredAt       time.Time      `json:"discovered_at"`
}

type KeyInventorySummary struct {
	TenantID      string    `json:"tenant_id"`
	TotalKeys     int       `json:"total_keys"`
	ActiveKeys    int       `json:"active_keys"`
	OrphanedKeys  int       `json:"orphaned_keys"`
	DuplicateSets int       `json:"duplicate_sets"`
	ExpiredKeys   int       `json:"expired_keys"`
	ExpiringSoon  int       `json:"expiring_soon"`
	HSMStoredKeys int       `json:"hsm_stored_keys"`
	CloudKeys     int       `json:"cloud_keys"`
	GeneratedAt   time.Time `json:"generated_at"`
}

type DuplicateKeyGroup struct {
	Fingerprint string   `json:"fingerprint"`
	Algorithm   string   `json:"algorithm"`
	KeyIDs      []string `json:"key_ids"`
	Count       int      `json:"count"`
}

type CompromiseEvent struct {
	EventID           string         `json:"event_id"`
	TenantID          string         `json:"tenant_id"`
	KeyID             string         `json:"key_id"`
	CVEID             string         `json:"cve_id,omitempty"`
	ThreatType        string         `json:"threat_type"`
	Severity          string         `json:"severity"`
	DetectionDate     time.Time      `json:"detection_date"`
	ConfirmedDate     *time.Time     `json:"confirmed_date,omitempty"`
	Status            string         `json:"status"`
	RemediationPlan   string         `json:"remediation_plan,omitempty"`
	RemediationStatus string         `json:"remediation_status"`
	RemediationDate   *time.Time     `json:"remediation_date,omitempty"`
	AffectedSystems   []string       `json:"affected_systems,omitempty"`
	NotificationsSent []string       `json:"notifications_sent,omitempty"`
	RootCause         string         `json:"root_cause,omitempty"`
	DetectionSource   string         `json:"detection_source,omitempty"`
	Metadata          map[string]any `json:"metadata,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

type CompromiseSummary struct {
	TenantID          string    `json:"tenant_id"`
	OpenEvents        int       `json:"open_events"`
	CriticalEvents    int       `json:"critical_events"`
	HighEvents        int       `json:"high_events"`
	ConfirmedEvents   int       `json:"confirmed_events"`
	PendingEvents     int       `json:"pending_events"`
	RemediatedEvents  int       `json:"remediated_events"`
	AutoSuspendedKeys int       `json:"auto_suspended_keys"`
	GeneratedAt       time.Time `json:"generated_at"`
}

type CompromiseAdvisory struct {
	CVEID              string         `json:"cve_id"`
	ThreatType         string         `json:"threat_type"`
	Severity           string         `json:"severity"`
	Summary            string         `json:"summary,omitempty"`
	AffectedAlgorithms []string       `json:"affected_algorithms,omitempty"`
	AffectedKeyIDs     []string       `json:"affected_key_ids,omitempty"`
	DetectionSource    string         `json:"detection_source,omitempty"`
	PublishedAt        *time.Time     `json:"published_at,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

type CompromiseIngestResult struct {
	AdvisoriesProcessed int               `json:"advisories_processed"`
	EventsCreated       int               `json:"events_created"`
	AutoSuspendedKeys   int               `json:"auto_suspended_keys"`
	Events              []CompromiseEvent `json:"events"`
}

type EnterpriseAuditSummary struct {
	TenantID     string                    `json:"tenant_id"`
	GeneratedAt  time.Time                 `json:"generated_at"`
	Rotation     RotationAnalyticsSummary  `json:"rotation"`
	Health       KeyHealthSummary          `json:"health"`
	Inventory    KeyInventorySummary       `json:"inventory"`
	Compromise   CompromiseSummary         `json:"compromise"`
	Hotspots     []KeyHotspot              `json:"hotspots,omitempty"`
	Algorithms   []AlgorithmBenchmark      `json:"algorithms,omitempty"`
	DSPMFindings []DSPMFinding             `json:"dspm_findings,omitempty"`
	Controls     []EnterpriseControlRecord `json:"controls,omitempty"`
	Roadmap      []AuditRoadmapItem        `json:"roadmap"`
}

type AuditRoadmapItem struct {
	ID           int      `json:"id"`
	Tier         int      `json:"tier"`
	Name         string   `json:"name"`
	Status       string   `json:"status"`
	Impact       string   `json:"impact"`
	Effort       string   `json:"effort"`
	Capabilities []string `json:"capabilities"`
}
