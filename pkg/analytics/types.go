package analytics

import (
	"time"
)

// RotationMetrics represents key rotation analytics
type RotationMetrics struct {
	RotationID      string
	TenantID        string
	KeyID           string
	ScheduledDate   time.Time
	ActualDate      *time.Time
	Status          string // scheduled, in_progress, completed, failed, cancelled
	DurationMs      int64
	Reason          string
	InitiatedBy     string
	CompletedBy     string
	ErrorDetails    string
	OldVersion      int
	NewVersion      int
	RollbackAttempt bool
	MetadataJSON    map[string]interface{}
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// RotationAnalytics provides methods for rotation analytics
type RotationAnalytics interface {
	RecordRotation(rm RotationMetrics) error
	GetRotationSchedule(tenantID string, days int) ([]RotationMetrics, error)
	GetRotationHistory(tenantID, keyID string, limit int) ([]RotationMetrics, error)
	CalculateSuccessRate(tenantID string, days int) (float64, error)
	CalculateAverageRotationTime(tenantID string, days int) (int64, error)
	GetOverdueRotations(tenantID string) ([]RotationMetrics, error)
}

// MetricsCollector gathers real-time metrics
type MetricsCollector interface {
	RecordKeyUsage(tenantID, keyID string, operationType string) error
	RecordKeyAccess(tenantID, keyID string, operation string, latencyMs int) error
	GetUsageMetrics(tenantID, keyID string, period string) (map[string]interface{}, error)
	GetTrendData(tenantID string, metric string, days int) ([]interface{}, error)
	GetHotspotKeys(tenantID string, limit int) ([]map[string]interface{}, error)
}

// MetricsPoint represents a single metric data point
type MetricsPoint struct {
	MetricID          string
	TenantID          string
	KeyID             string
	MetricType        string
	Value             float64
	AggregationPeriod string // hourly, daily, weekly, monthly
	Timestamp         time.Time
	MetadataJSON      map[string]interface{}
}

// AlgorithmMetrics represents performance metrics for a specific algorithm
type AlgorithmMetrics struct {
	Algorithm   string
	TenantID    string
	SuccessRate float64
	AverageTime int64
	FailureRate float64
	Usage       int64
	Performance string // excellent, good, fair, poor
}

// Hotspot represents a key with high access rate
type Hotspot struct {
	KeyID       string
	AccessCount int64
	Percentile  float64
	LastAccess  time.Time
	ServiceIDs  []string
}

// TrendData represents trend information
type TrendData struct {
	Timestamp time.Time
	Value     float64
	Change    float64
}
