package health

import "time"

// HealthScore represents the overall health of a key
type HealthScore struct {
	KeyID              string
	TenantID           string
	HealthScore        int // 0-100
	EntropyScore       int
	AgeScore           int
	UsageScore         int
	AlgorithmScore     int
	BackupStatus       string // unknown, verified, stale, missing
	RotationOverdue    bool
	ExpiryImminent     bool
	ComplianceWarnings []string
	LastAuditDate      *time.Time
	UpdatedAt          time.Time
	RecommendedActions []string
}

// ScoringConfig contains configuration for health scoring
type ScoringConfig struct {
	MaxKeyAge              int // days
	RotationIntervalDays   int
	EntropySizeInBits      int
	AlgorithmThreshold     string // current, acceptable, deprecated
	BackupVerificationDays int
	ExpiryWarningDays      int
}

// HealthScorer interface defines health scoring operations
type HealthScorer interface {
	CalculateHealth(tenantID, keyID string) (*HealthScore, error)
	CalculateEntropyScore(entropyValue int) int
	CalculateAgeScore(createdAt time.Time) int
	CalculateUsageScore(totalOps int64, opsPerDay float64) int
	CalculateAlgorithmScore(algorithm string) int
	DetermineBackupStatus(lastVerified *time.Time) string
	GenerateRecommendations(score *HealthScore) []string
	GetHealthSummary(tenantID string) (map[string]interface{}, error)
}
