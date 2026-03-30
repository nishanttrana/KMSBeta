package metering

import (
	"context"
	"fmt"
	"strings"
	"time"

	"vecta-kms/pkg/db"
)

const meteringMigration = `
CREATE TABLE IF NOT EXISTS usage_records (
	id BIGSERIAL PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	operation TEXT NOT NULL,
	algorithm TEXT NOT NULL,
	count BIGINT NOT NULL DEFAULT 1,
	recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_usage_tenant_time ON usage_records(tenant_id, recorded_at);
`

// SQLStore implements MeterStore backed by PostgreSQL or SQLite.
type SQLStore struct {
	db *db.DB
}

// NewSQLStore creates a new SQL-backed metering store.
func NewSQLStore(database *db.DB) *SQLStore {
	return &SQLStore{db: database}
}

// Migrate creates the required tables and indexes.
func (s *SQLStore) Migrate(ctx context.Context) error {
	_, err := s.db.SQL().ExecContext(ctx, meteringMigration)
	if err != nil {
		return fmt.Errorf("metering: migrate: %w", err)
	}
	return nil
}

// FlushRecords batch-inserts usage records using a single multi-row INSERT.
func (s *SQLStore) FlushRecords(ctx context.Context, records []UsageRecord) error {
	if len(records) == 0 {
		return nil
	}

	// Build a single INSERT with multiple VALUES rows for efficiency.
	// INSERT INTO usage_records (tenant_id, operation, algorithm, count, recorded_at)
	// VALUES ($1,$2,$3,$4,$5), ($6,$7,$8,$9,$10), ...
	const cols = 5
	var b strings.Builder
	b.WriteString("INSERT INTO usage_records (tenant_id, operation, algorithm, count, recorded_at) VALUES ")

	args := make([]interface{}, 0, len(records)*cols)
	for i, rec := range records {
		if i > 0 {
			b.WriteByte(',')
		}
		base := i * cols
		fmt.Fprintf(&b, "($%d,$%d,$%d,$%d,$%d)", base+1, base+2, base+3, base+4, base+5)
		args = append(args, rec.TenantID, rec.Operation, rec.Algorithm, rec.Count, rec.Timestamp)
	}

	_, err := s.db.SQL().ExecContext(ctx, b.String(), args...)
	if err != nil {
		return fmt.Errorf("metering: flush records: %w", err)
	}
	return nil
}

// parsePeriod converts a period string like "2026-03" into a start and end time.
func parsePeriod(period string) (start, end time.Time, err error) {
	start, err = time.Parse("2006-01", period)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("metering: invalid period %q (expected YYYY-MM): %w", period, err)
	}
	end = start.AddDate(0, 1, 0)
	return start, end, nil
}

// GetSummary returns aggregated usage for a tenant over a billing period (YYYY-MM).
func (s *SQLStore) GetSummary(ctx context.Context, tenantID, period string) (*TenantUsageSummary, error) {
	start, end, err := parsePeriod(period)
	if err != nil {
		return nil, err
	}

	const query = `
		SELECT operation, algorithm, COALESCE(SUM(count), 0)
		FROM usage_records
		WHERE tenant_id = $1 AND recorded_at >= $2 AND recorded_at < $3
		GROUP BY operation, algorithm
	`
	rows, err := s.db.ROSQL().QueryContext(ctx, query, tenantID, start, end)
	if err != nil {
		return nil, fmt.Errorf("metering: get summary: %w", err)
	}
	defer rows.Close()

	summary := &TenantUsageSummary{
		TenantID:       tenantID,
		Period:         period,
		OpsByType:      make(map[string]int64),
		OpsByAlgorithm: make(map[string]int64),
	}

	for rows.Next() {
		var operation, algorithm string
		var count int64
		if err := rows.Scan(&operation, &algorithm, &count); err != nil {
			return nil, fmt.Errorf("metering: scan summary row: %w", err)
		}
		summary.TotalOps += count
		summary.OpsByType[operation] += count
		if algorithm != "" {
			summary.OpsByAlgorithm[algorithm] += count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("metering: iterate summary: %w", err)
	}

	// Compute estimated cost from default pricing
	for op, cnt := range summary.OpsByType {
		if price, ok := defaultPricing[op]; ok {
			summary.EstimatedCostUSD += price * float64(cnt)
		}
	}

	return summary, nil
}

// GetTopTenants returns the top tenants by total operation count in a billing period.
func (s *SQLStore) GetTopTenants(ctx context.Context, period string, limit int) ([]TenantUsageSummary, error) {
	start, end, err := parsePeriod(period)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 10
	}

	const query = `
		SELECT tenant_id, COALESCE(SUM(count), 0) AS total
		FROM usage_records
		WHERE recorded_at >= $1 AND recorded_at < $2
		GROUP BY tenant_id
		ORDER BY total DESC
		LIMIT $3
	`
	rows, err := s.db.ROSQL().QueryContext(ctx, query, start, end, limit)
	if err != nil {
		return nil, fmt.Errorf("metering: get top tenants: %w", err)
	}
	defer rows.Close()

	var results []TenantUsageSummary
	for rows.Next() {
		var s TenantUsageSummary
		if err := rows.Scan(&s.TenantID, &s.TotalOps); err != nil {
			return nil, fmt.Errorf("metering: scan top tenant: %w", err)
		}
		s.Period = period
		results = append(results, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("metering: iterate top tenants: %w", err)
	}

	return results, nil
}
