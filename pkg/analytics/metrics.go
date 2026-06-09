package analytics

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"
)

// MetricsCollectorService implements MetricsCollector interface
type MetricsCollectorService struct {
	db *sql.DB
}

// NewMetricsCollectorService creates a metrics collector service
func NewMetricsCollectorService(db *sql.DB) *MetricsCollectorService {
	return &MetricsCollectorService{db: db}
}

// RecordKeyUsage records a key usage event
func (s *MetricsCollectorService) RecordKeyUsage(tenantID, keyID string, operationType string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Generate metric ID
	metricID := generateID("metric")
	now := time.Now()

	query := `
INSERT INTO key_analytics_metrics
(metric_id, tenant_id, key_id, metric_type, value, aggregation_period, timestamp)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`

	_, err := s.db.ExecContext(ctx, query,
		metricID, tenantID, keyID, "usage_"+operationType, 1, "hourly", now)

	return err
}

// RecordKeyAccess records key access with latency
func (s *MetricsCollectorService) RecordKeyAccess(tenantID, keyID string, operation string, latencyMs int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	metricID := generateID("metric")
	now := time.Now()

	query := `
INSERT INTO key_analytics_metrics
(metric_id, tenant_id, key_id, metric_type, value, aggregation_period, timestamp)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`

	_, err := s.db.ExecContext(ctx, query,
		metricID, tenantID, keyID, "access_latency_"+operation, float64(latencyMs), "hourly", now)

	return err
}

// GetUsageMetrics retrieves usage metrics for a key
func (s *MetricsCollectorService) GetUsageMetrics(tenantID, keyID string, period string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	since := periodStart(period)

	query := `
SELECT
metric_type,
COUNT(*) as count,
AVG(value) as avg_value,
MAX(value) as max_value,
MIN(value) as min_value
FROM key_analytics_metrics
WHERE tenant_id = $1
AND key_id = $2
AND timestamp >= $3
GROUP BY metric_type
`

	rows, err := s.db.QueryContext(ctx, query, tenantID, keyID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]interface{})
	metrics := make([]map[string]interface{}, 0)

	for rows.Next() {
		var metricType string
		var count int64
		var avgVal, maxVal, minVal float64

		if err := rows.Scan(&metricType, &count, &avgVal, &maxVal, &minVal); err != nil {
			return nil, err
		}

		metrics = append(metrics, map[string]interface{}{
			"type":  metricType,
			"count": count,
			"avg":   avgVal,
			"max":   maxVal,
			"min":   minVal,
		})
	}

	result["metrics"] = metrics
	result["period"] = period
	return result, rows.Err()
}

// GetTrendData retrieves trend data for a metric
func (s *MetricsCollectorService) GetTrendData(tenantID string, metric string, days int) ([]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if days <= 0 {
		days = 30
	}
	since := time.Now().UTC().AddDate(0, 0, -days)

	query := `
SELECT
DATE_TRUNC('day', timestamp) as date,
AVG(value) as avg_value
FROM key_analytics_metrics
WHERE tenant_id = $1
AND metric_type = $2
AND timestamp >= $3
GROUP BY DATE_TRUNC('day', timestamp)
ORDER BY date ASC
`

	rows, err := s.db.QueryContext(ctx, query, tenantID, metric, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var trends []interface{}
	for rows.Next() {
		var date time.Time
		var value float64

		if err := rows.Scan(&date, &value); err != nil {
			return nil, err
		}

		trends = append(trends, TrendData{
			Timestamp: date,
			Value:     value,
		})
	}

	return trends, rows.Err()
}

// GetHotspotKeys retrieves keys with highest access rates
func (s *MetricsCollectorService) GetHotspotKeys(tenantID string, limit int) ([]map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
SELECT
key_id,
COUNT(*) as access_count,
PERCENT_RANK() OVER (ORDER BY COUNT(*)) as percentile,
MAX(timestamp) as last_access
FROM key_analytics_metrics
WHERE tenant_id = $1
AND timestamp >= NOW() - INTERVAL '7 days'
GROUP BY key_id
ORDER BY access_count DESC
LIMIT $2
`

	rows, err := s.db.QueryContext(ctx, query, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hotspots []map[string]interface{}
	for rows.Next() {
		var keyID string
		var accessCount int64
		var percentile float64
		var lastAccess time.Time

		if err := rows.Scan(&keyID, &accessCount, &percentile, &lastAccess); err != nil {
			return nil, err
		}

		hotspots = append(hotspots, map[string]interface{}{
			"key_id":       keyID,
			"access_count": accessCount,
			"percentile":   percentile,
			"last_access":  lastAccess,
		})
	}

	return hotspots, rows.Err()
}

// helper function to generate IDs
func generateID(prefix string) string {
	return prefix + "-" + time.Now().UTC().Format("20060102150405") + "-" + randomString(8)
}

// randomString generates a random string of given length
func randomString(length int) string {
	if length <= 0 {
		return ""
	}
	buf := make([]byte, (length+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return time.Now().UTC().Format("150405.000000000")
	}
	out := hex.EncodeToString(buf)
	if len(out) > length {
		return out[:length]
	}
	return out
}

func periodStart(period string) time.Time {
	now := time.Now().UTC()
	switch period {
	case "hour", "hourly":
		return now.Add(-time.Hour)
	case "day", "daily":
		return now.AddDate(0, 0, -1)
	case "week", "weekly":
		return now.AddDate(0, 0, -7)
	case "month", "monthly":
		return now.AddDate(0, -1, 0)
	case "quarter", "quarterly":
		return now.AddDate(0, -3, 0)
	case "year", "yearly":
		return now.AddDate(-1, 0, 0)
	default:
		return now.AddDate(0, 0, -1)
	}
}
