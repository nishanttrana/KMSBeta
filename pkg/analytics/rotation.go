package analytics

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// RotationAnalyticsService implements RotationAnalytics interface
type RotationAnalyticsService struct {
	db *sql.DB
}

// NewRotationAnalyticsService creates a new rotation analytics service
func NewRotationAnalyticsService(db *sql.DB) *RotationAnalyticsService {
	return &RotationAnalyticsService{db: db}
}

// RecordRotation stores a rotation event
func (s *RotationAnalyticsService) RecordRotation(rm RotationMetrics) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if rm.CreatedAt.IsZero() {
		rm.CreatedAt = time.Now().UTC()
	}
	if rm.UpdatedAt.IsZero() {
		rm.UpdatedAt = rm.CreatedAt
	}

	metadataJSON, _ := json.Marshal(rm.MetadataJSON)

	query := `
INSERT INTO key_rotation_metrics
(rotation_id, tenant_id, key_id, scheduled_date, actual_date, status, duration_ms,
 reason, initiated_by, completed_by, error_details, old_version, new_version,
 rollback_attempted, metadata_json, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
ON CONFLICT (tenant_id, rotation_id) DO UPDATE SET
actual_date = EXCLUDED.actual_date,
status = EXCLUDED.status,
duration_ms = EXCLUDED.duration_ms,
completed_by = EXCLUDED.completed_by,
error_details = EXCLUDED.error_details,
metadata_json = EXCLUDED.metadata_json,
updated_at = NOW()
`

	_, err := s.db.ExecContext(ctx, query,
		rm.RotationID, rm.TenantID, rm.KeyID, rm.ScheduledDate, rm.ActualDate,
		rm.Status, rm.DurationMs, rm.Reason, rm.InitiatedBy, rm.CompletedBy,
		rm.ErrorDetails, rm.OldVersion, rm.NewVersion, rm.RollbackAttempt,
		metadataJSON, rm.CreatedAt, rm.UpdatedAt)

	return err
}

// GetRotationSchedule retrieves upcoming rotations
func (s *RotationAnalyticsService) GetRotationSchedule(tenantID string, days int) ([]RotationMetrics, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if days <= 0 {
		days = 30
	}
	horizon := time.Now().UTC().AddDate(0, 0, days)

	query := `
SELECT rotation_id, tenant_id, key_id, scheduled_date, actual_date, status,
       duration_ms, reason, initiated_by, completed_by, error_details,
       old_version, new_version, rollback_attempted, metadata_json,
       created_at, updated_at
FROM key_rotation_metrics
WHERE tenant_id = $1
AND status = 'scheduled'
AND scheduled_date BETWEEN NOW() AND $2
ORDER BY scheduled_date ASC
LIMIT 1000
`

	rows, err := s.db.QueryContext(ctx, query, tenantID, horizon)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []RotationMetrics
	for rows.Next() {
		var m RotationMetrics
		var metadataJSON []byte
		var actualDate sql.NullTime

		if err := rows.Scan(&m.RotationID, &m.TenantID, &m.KeyID, &m.ScheduledDate, &actualDate,
			&m.Status, &m.DurationMs, &m.Reason, &m.InitiatedBy, &m.CompletedBy, &m.ErrorDetails,
			&m.OldVersion, &m.NewVersion, &m.RollbackAttempt, &metadataJSON, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}

		if actualDate.Valid {
			m.ActualDate = &actualDate.Time
		}
		json.Unmarshal(metadataJSON, &m.MetadataJSON)
		metrics = append(metrics, m)
	}

	return metrics, rows.Err()
}

// GetRotationHistory retrieves completed rotations
func (s *RotationAnalyticsService) GetRotationHistory(tenantID, keyID string, limit int) ([]RotationMetrics, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
SELECT rotation_id, tenant_id, key_id, scheduled_date, actual_date, status,
       duration_ms, reason, initiated_by, completed_by, error_details,
       old_version, new_version, rollback_attempted, metadata_json,
       created_at, updated_at
FROM key_rotation_metrics
WHERE tenant_id = $1 AND key_id = $2
ORDER BY created_at DESC
LIMIT $3
`

	rows, err := s.db.QueryContext(ctx, query, tenantID, keyID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []RotationMetrics
	for rows.Next() {
		var m RotationMetrics
		var metadataJSON []byte
		var actualDate sql.NullTime

		if err := rows.Scan(&m.RotationID, &m.TenantID, &m.KeyID, &m.ScheduledDate, &actualDate,
			&m.Status, &m.DurationMs, &m.Reason, &m.InitiatedBy, &m.CompletedBy, &m.ErrorDetails,
			&m.OldVersion, &m.NewVersion, &m.RollbackAttempt, &metadataJSON, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}

		if actualDate.Valid {
			m.ActualDate = &actualDate.Time
		}
		json.Unmarshal(metadataJSON, &m.MetadataJSON)
		metrics = append(metrics, m)
	}

	return metrics, rows.Err()
}

// CalculateSuccessRate computes rotation success rate
func (s *RotationAnalyticsService) CalculateSuccessRate(tenantID string, days int) (float64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if days <= 0 {
		days = 30
	}
	since := time.Now().UTC().AddDate(0, 0, -days)

	query := `
SELECT
COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful,
COUNT(*) as total
FROM key_rotation_metrics
WHERE tenant_id = $1
AND created_at >= $2
AND status IN ('completed', 'failed')
`

	var successful, total int
	err := s.db.QueryRowContext(ctx, query, tenantID, since).Scan(&successful, &total)
	if err != nil {
		return 0, err
	}
	if total == 0 {
		return 0, nil
	}

	return float64(successful) / float64(total) * 100, nil
}

// CalculateAverageRotationTime computes average rotation duration
func (s *RotationAnalyticsService) CalculateAverageRotationTime(tenantID string, days int) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if days <= 0 {
		days = 30
	}
	since := time.Now().UTC().AddDate(0, 0, -days)

	query := `
SELECT COALESCE(AVG(duration_ms), 0)
FROM key_rotation_metrics
WHERE tenant_id = $1
AND created_at >= $2
AND status = 'completed'
AND duration_ms IS NOT NULL
`

	var avgDuration int64
	err := s.db.QueryRowContext(ctx, query, tenantID, since).Scan(&avgDuration)
	return avgDuration, err
}

// GetOverdueRotations finds keys needing rotation
func (s *RotationAnalyticsService) GetOverdueRotations(tenantID string) ([]RotationMetrics, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
SELECT rotation_id, tenant_id, key_id, scheduled_date, actual_date, status,
       duration_ms, reason, initiated_by, completed_by, error_details,
       old_version, new_version, rollback_attempted, metadata_json,
       created_at, updated_at
FROM key_rotation_metrics
WHERE tenant_id = $1
AND status = 'scheduled'
AND scheduled_date < NOW()
ORDER BY scheduled_date ASC
LIMIT 1000
`

	rows, err := s.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []RotationMetrics
	for rows.Next() {
		var m RotationMetrics
		var metadataJSON []byte
		var actualDate sql.NullTime

		if err := rows.Scan(&m.RotationID, &m.TenantID, &m.KeyID, &m.ScheduledDate, &actualDate,
			&m.Status, &m.DurationMs, &m.Reason, &m.InitiatedBy, &m.CompletedBy, &m.ErrorDetails,
			&m.OldVersion, &m.NewVersion, &m.RollbackAttempt, &metadataJSON, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}

		if actualDate.Valid {
			m.ActualDate = &actualDate.Time
		}
		json.Unmarshal(metadataJSON, &m.MetadataJSON)
		metrics = append(metrics, m)
	}

	return metrics, rows.Err()
}
