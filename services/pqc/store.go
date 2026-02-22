package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) CreateReadinessScan(ctx context.Context, item ReadinessScan) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO pqc_readiness_scans (
	tenant_id, id, status, total_assets, pqc_ready_assets, hybrid_assets, classical_assets,
	average_qsl, readiness_score, algorithm_summary_json, timeline_status_json, risk_items_json,
	metadata_json, created_at, completed_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,CURRENT_TIMESTAMP,$14
)
`, item.TenantID, item.ID, item.Status, item.TotalAssets, item.PQCReadyAssets, item.HybridAssets, item.ClassicalAssets,
		item.AverageQSL, item.ReadinessScore, mustJSON(item.AlgorithmSummary, "{}"), mustJSON(item.TimelineStatus, "{}"),
		mustJSON(item.RiskItems, "[]"), mustJSON(item.Metadata, "{}"), nullableTime(item.CompletedAt))
	return err
}

func (s *SQLStore) GetReadinessScan(ctx context.Context, tenantID string, id string) (ReadinessScan, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, status, total_assets, pqc_ready_assets, hybrid_assets, classical_assets,
	average_qsl, readiness_score, algorithm_summary_json, timeline_status_json, risk_items_json,
	metadata_json, created_at, completed_at
FROM pqc_readiness_scans
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanReadiness(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ReadinessScan{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) GetLatestReadinessScan(ctx context.Context, tenantID string) (ReadinessScan, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, status, total_assets, pqc_ready_assets, hybrid_assets, classical_assets,
	average_qsl, readiness_score, algorithm_summary_json, timeline_status_json, risk_items_json,
	metadata_json, created_at, completed_at
FROM pqc_readiness_scans
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT 1
`, strings.TrimSpace(tenantID))
	item, err := scanReadiness(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ReadinessScan{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListReadinessScans(ctx context.Context, tenantID string, limit int, offset int) ([]ReadinessScan, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, status, total_assets, pqc_ready_assets, hybrid_assets, classical_assets,
	average_qsl, readiness_score, algorithm_summary_json, timeline_status_json, risk_items_json,
	metadata_json, created_at, completed_at
FROM pqc_readiness_scans
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3
`, strings.TrimSpace(tenantID), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ReadinessScan, 0)
	for rows.Next() {
		item, err := scanReadiness(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateMigrationPlan(ctx context.Context, item MigrationPlan) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO pqc_migration_plans (
	tenant_id, id, name, status, target_profile, timeline_standard, deadline,
	summary_json, steps_json, created_by, created_at, updated_at, executed_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,$11
)
`, item.TenantID, item.ID, item.Name, item.Status, item.TargetProfile, item.TimelineStandard, nullableTime(item.Deadline),
		mustJSON(item.Summary, "{}"), mustJSON(item.Steps, "[]"), item.CreatedBy, nullableTime(item.ExecutedAt))
	return err
}

func (s *SQLStore) UpdateMigrationPlan(ctx context.Context, item MigrationPlan) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE pqc_migration_plans
SET status = $3,
	target_profile = $4,
	timeline_standard = $5,
	deadline = $6,
	summary_json = $7,
	steps_json = $8,
	updated_at = CURRENT_TIMESTAMP,
	executed_at = $9
WHERE tenant_id = $1 AND id = $2
`, item.TenantID, item.ID, item.Status, item.TargetProfile, item.TimelineStandard, nullableTime(item.Deadline),
		mustJSON(item.Summary, "{}"), mustJSON(item.Steps, "[]"), nullableTime(item.ExecutedAt))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetMigrationPlan(ctx context.Context, tenantID string, id string) (MigrationPlan, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, name, status, target_profile, timeline_standard, deadline,
	summary_json, steps_json, created_by, created_at, updated_at, executed_at
FROM pqc_migration_plans
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanPlan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return MigrationPlan{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListMigrationPlans(ctx context.Context, tenantID string, limit int, offset int) ([]MigrationPlan, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, name, status, target_profile, timeline_standard, deadline,
	summary_json, steps_json, created_by, created_at, updated_at, executed_at
FROM pqc_migration_plans
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3
`, strings.TrimSpace(tenantID), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MigrationPlan, 0)
	for rows.Next() {
		item, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateMigrationRun(ctx context.Context, item MigrationRun) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO pqc_migration_runs (
	tenant_id, id, plan_id, status, dry_run, summary_json, created_at, completed_at
) VALUES (
	$1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP,$7
)
`, item.TenantID, item.ID, item.PlanID, item.Status, item.DryRun, mustJSON(item.Summary, "{}"), nullableTime(item.CompletedAt))
	return err
}

func (s *SQLStore) UpdateMigrationRun(ctx context.Context, item MigrationRun) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE pqc_migration_runs
SET status = $3,
	dry_run = $4,
	summary_json = $5,
	completed_at = $6
WHERE tenant_id = $1 AND id = $2
`, item.TenantID, item.ID, item.Status, item.DryRun, mustJSON(item.Summary, "{}"), nullableTime(item.CompletedAt))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) ListMigrationRuns(ctx context.Context, tenantID string, planID string) ([]MigrationRun, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, plan_id, status, dry_run, summary_json, created_at, completed_at
FROM pqc_migration_runs
WHERE tenant_id = $1 AND ($2 = '' OR plan_id = $2)
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID), strings.TrimSpace(planID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MigrationRun, 0)
	for rows.Next() {
		item, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanReadiness(scanner interface {
	Scan(dest ...interface{}) error
}) (ReadinessScan, error) {
	var (
		item         ReadinessScan
		algoJS       string
		timelineJS   string
		riskJS       string
		metadataJS   string
		createdRaw   interface{}
		completedRaw interface{}
	)
	if err := scanner.Scan(
		&item.TenantID,
		&item.ID,
		&item.Status,
		&item.TotalAssets,
		&item.PQCReadyAssets,
		&item.HybridAssets,
		&item.ClassicalAssets,
		&item.AverageQSL,
		&item.ReadinessScore,
		&algoJS,
		&timelineJS,
		&riskJS,
		&metadataJS,
		&createdRaw,
		&completedRaw,
	); err != nil {
		return ReadinessScan{}, err
	}
	item.AlgorithmSummary = parseStringIntMap(algoJS)
	item.TimelineStatus = parseJSONObject(timelineJS)
	item.RiskItems = parseRiskItems(riskJS)
	item.Metadata = parseJSONObject(metadataJS)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.CompletedAt = parseTimeValue(completedRaw)
	return item, nil
}

func scanPlan(scanner interface {
	Scan(dest ...interface{}) error
}) (MigrationPlan, error) {
	var (
		item        MigrationPlan
		summaryJS   string
		stepsJS     string
		deadlineRaw interface{}
		createdRaw  interface{}
		updatedRaw  interface{}
		executedRaw interface{}
	)
	if err := scanner.Scan(
		&item.TenantID,
		&item.ID,
		&item.Name,
		&item.Status,
		&item.TargetProfile,
		&item.TimelineStandard,
		&deadlineRaw,
		&summaryJS,
		&stepsJS,
		&item.CreatedBy,
		&createdRaw,
		&updatedRaw,
		&executedRaw,
	); err != nil {
		return MigrationPlan{}, err
	}
	item.Deadline = parseTimeValue(deadlineRaw)
	item.Summary = parseJSONObject(summaryJS)
	item.Steps = parseMigrationSteps(stepsJS)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	item.ExecutedAt = parseTimeValue(executedRaw)
	return item, nil
}

func scanRun(scanner interface {
	Scan(dest ...interface{}) error
}) (MigrationRun, error) {
	var (
		item         MigrationRun
		summaryJS    string
		createdRaw   interface{}
		completedRaw interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.ID, &item.PlanID, &item.Status, &item.DryRun, &summaryJS, &createdRaw, &completedRaw); err != nil {
		return MigrationRun{}, err
	}
	item.Summary = parseJSONObject(summaryJS)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.CompletedAt = parseTimeValue(completedRaw)
	return item, nil
}
