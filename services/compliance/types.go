package main

import (
	"context"
	"time"
)

const (
	frameworkPCIDSS = "pci-dss-4.0"
	frameworkFIPS   = "fips-140-3"
	frameworkNIST   = "nist-800-57"
	frameworkEIDAS  = "eidas"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type PostureSnapshot struct {
	ID               string             `json:"id"`
	TenantID         string             `json:"tenant_id"`
	OverallScore     int                `json:"overall_score"`
	KeyHygiene       int                `json:"key_hygiene"`
	PolicyCompliance int                `json:"policy_compliance"`
	AccessSecurity   int                `json:"access_security"`
	CryptoPosture    int                `json:"crypto_posture"`
	PQCReadiness     int                `json:"pqc_readiness"`
	FrameworkScores  map[string]int     `json:"framework_scores"`
	Metrics          map[string]float64 `json:"metrics"`
	GapCount         int                `json:"gap_count"`
	CreatedAt        time.Time          `json:"created_at"`
}

type Framework struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Version     string             `json:"version"`
	Description string             `json:"description"`
	Controls    []FrameworkControl `json:"controls,omitempty"`
}

type FrameworkControl struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Category    string  `json:"category"`
	Requirement string  `json:"requirement"`
	Weight      float64 `json:"weight"`
	Status      string  `json:"status"`
	Score       int     `json:"score"`
	Evidence    string  `json:"evidence"`
}

type FrameworkAssessment struct {
	ID          string             `json:"id"`
	TenantID    string             `json:"tenant_id"`
	FrameworkID string             `json:"framework_id"`
	Score       int                `json:"score"`
	Status      string             `json:"status"`
	Controls    []FrameworkControl `json:"controls"`
	Gaps        []ComplianceGap    `json:"gaps"`
	PQCReady    int                `json:"pqc_ready"`
	QSLAvg      float64            `json:"qsl_avg"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

type ComplianceGap struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	FrameworkID string    `json:"framework_id"`
	ControlID   string    `json:"control_id"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	ResourceID  string    `json:"resource_id"`
	Status      string    `json:"status"`
	DetectedAt  time.Time `json:"detected_at"`
	ResolvedAt  time.Time `json:"resolved_at"`
}

type KeyHygieneReport struct {
	TenantID              string                   `json:"tenant_id"`
	TotalKeys             int                      `json:"total_keys"`
	ApprovedAlgorithmPct  float64                  `json:"approved_algorithm_pct"`
	RotationCoveragePct   float64                  `json:"rotation_coverage_pct"`
	PolicyCoveragePct     float64                  `json:"policy_coverage_pct"`
	OrphanedCount         int                      `json:"orphaned_count"`
	ExpiringCount         int                      `json:"expiring_count"`
	DeprecatedCount       int                      `json:"deprecated_count"`
	Unused90DaysCount     int                      `json:"unused_90_days_count"`
	PQCReadyPct           float64                  `json:"pqc_ready_pct"`
	AlgorithmDistribution map[string]int           `json:"algorithm_distribution"`
	OrphanedKeys          []map[string]interface{} `json:"orphaned_keys"`
	ExpiringKeys          []map[string]interface{} `json:"expiring_keys"`
}

type CorrelationItem struct {
	CorrelationID string    `json:"correlation_id"`
	Count         int       `json:"count"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	TopActions    []string  `json:"top_actions"`
}

type AnomalyItem struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Count       int       `json:"count"`
	DetectedAt  time.Time `json:"detected_at"`
}

type SBOMDocument struct {
	Format         string                   `json:"format"`
	SpecVersion    string                   `json:"spec_version"`
	GeneratedAt    time.Time                `json:"generated_at"`
	Appliance      string                   `json:"appliance"`
	Components     []map[string]interface{} `json:"components"`
	Infrastructure []map[string]interface{} `json:"infrastructure"`
	Licenses       []string                 `json:"licenses"`
}

type CBOMDocument struct {
	Format              string                   `json:"format"`
	SpecVersion         string                   `json:"spec_version"`
	GeneratedAt         time.Time                `json:"generated_at"`
	TenantID            string                   `json:"tenant_id"`
	Assets              []map[string]interface{} `json:"assets"`
	AlgorithmSummary    map[string]int           `json:"algorithm_summary"`
	StrengthHistogram   map[string]int           `json:"strength_histogram"`
	DeprecatedCount     int                      `json:"deprecated_count"`
	PQCReadyCount       int                      `json:"pqc_ready_count"`
	TotalAssetCount     int                      `json:"total_asset_count"`
	PQCReadinessPercent float64                  `json:"pqc_readiness_percent"`
}

type CBOMSnapshot struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	GeneratedAt  time.Time `json:"generated_at"`
	SummaryJSON  string    `json:"summary_json"`
	DocumentJSON string    `json:"document_json"`
}

type CertHygieneReport struct {
	TenantID           string  `json:"tenant_id"`
	TotalCerts         int     `json:"total_certs"`
	ActiveCount        int     `json:"active_count"`
	RevokedCount       int     `json:"revoked_count"`
	ExpiredCount       int     `json:"expired_count"`
	Expiring30Days     int     `json:"expiring_30_days"`
	WeakAlgorithmCount int     `json:"weak_algorithm_count"`
	PQCClassCount      int     `json:"pqc_class_count"`
	PQCClassPct        float64 `json:"pqc_class_pct"`
}

type AssessmentFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Fix      string `json:"fix"`
	Count    int    `json:"count"`
}

type AssessmentPQC struct {
	ReadyPercent   float64 `json:"ready_percent"`
	MLKEMMigrated  int     `json:"ml_kem_migrated"`
	MLDSAMigrated  int     `json:"ml_dsa_migrated"`
	Pending        int     `json:"pending"`
	TotalEvaluated int     `json:"total_evaluated"`
}

type AssessmentResult struct {
	ID              string              `json:"id"`
	TenantID        string              `json:"tenant_id"`
	Trigger         string              `json:"trigger"`
	TemplateID      string              `json:"template_id"`
	TemplateName    string              `json:"template_name"`
	OverallScore    int                 `json:"overall_score"`
	FrameworkScores map[string]int      `json:"framework_scores"`
	Findings        []AssessmentFinding `json:"findings"`
	PQC             AssessmentPQC       `json:"pqc"`
	CertMetrics     map[string]float64  `json:"cert_metrics"`
	Posture         PostureSnapshot     `json:"posture"`
	CreatedAt       time.Time           `json:"created_at"`
}

type AssessmentSchedule struct {
	TenantID  string    `json:"tenant_id"`
	Enabled   bool      `json:"enabled"`
	Frequency string    `json:"frequency"`
	LastRunAt time.Time `json:"last_run_at"`
	NextRunAt time.Time `json:"next_run_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ComplianceTemplate struct {
	ID          string                        `json:"id"`
	TenantID    string                        `json:"tenant_id"`
	Name        string                        `json:"name"`
	Description string                        `json:"description"`
	Enabled     bool                          `json:"enabled"`
	Frameworks  []ComplianceTemplateFramework `json:"frameworks"`
	CreatedAt   time.Time                     `json:"created_at"`
	UpdatedAt   time.Time                     `json:"updated_at"`
}

type ComplianceTemplateFramework struct {
	FrameworkID string                      `json:"framework_id"`
	Label       string                      `json:"label"`
	Enabled     bool                        `json:"enabled"`
	Weight      float64                     `json:"weight"`
	Controls    []ComplianceTemplateControl `json:"controls"`
}

type ComplianceTemplateControl struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Category    string  `json:"category"`
	Requirement string  `json:"requirement"`
	Enabled     bool    `json:"enabled"`
	Weight      float64 `json:"weight"`
	Threshold   int     `json:"threshold"`
}
