package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) CreateScan(ctx context.Context, scan DiscoveryScan) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO discovery_scans (
	tenant_id, id, scan_type, status, trigger, stats_json, started_at, completed_at, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP
)
`, scan.TenantID, scan.ID, scan.ScanType, scan.Status, scan.Trigger, mustJSON(scan.Stats, "{}"), nullableTime(scan.StartedAt), nullableTime(scan.CompletedAt))
	return err
}

func (s *SQLStore) UpdateScan(ctx context.Context, scan DiscoveryScan) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE discovery_scans
SET status = $3,
	stats_json = $4,
	started_at = $5,
	completed_at = $6
WHERE tenant_id = $1 AND id = $2
`, scan.TenantID, scan.ID, scan.Status, mustJSON(scan.Stats, "{}"), nullableTime(scan.StartedAt), nullableTime(scan.CompletedAt))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetScan(ctx context.Context, tenantID string, id string) (DiscoveryScan, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, scan_type, status, trigger, stats_json, started_at, completed_at, created_at
FROM discovery_scans
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanDiscoveryScan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return DiscoveryScan{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListScans(ctx context.Context, tenantID string, limit int, offset int) ([]DiscoveryScan, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, scan_type, status, trigger, stats_json, started_at, completed_at, created_at
FROM discovery_scans
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3
`, strings.TrimSpace(tenantID), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]DiscoveryScan, 0)
	for rows.Next() {
		item, err := scanDiscoveryScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertAsset(ctx context.Context, asset CryptoAsset) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO discovery_assets (
	tenant_id, id, scan_id, asset_type, name, location, source, algorithm, strength_bits, status, classification, pqc_ready, qsl_score,
	metadata_json, first_seen, last_seen, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, id) DO UPDATE SET
	scan_id = excluded.scan_id,
	asset_type = excluded.asset_type,
	name = excluded.name,
	location = excluded.location,
	source = excluded.source,
	algorithm = excluded.algorithm,
	strength_bits = excluded.strength_bits,
	status = excluded.status,
	classification = excluded.classification,
	pqc_ready = excluded.pqc_ready,
	qsl_score = excluded.qsl_score,
	metadata_json = excluded.metadata_json,
	last_seen = excluded.last_seen,
	updated_at = CURRENT_TIMESTAMP
`, asset.TenantID, asset.ID, asset.ScanID, asset.AssetType, asset.Name, asset.Location, asset.Source, asset.Algorithm,
		asset.StrengthBits, asset.Status, asset.Classification, asset.PQCReady, asset.QSLScore, mustJSON(asset.Metadata, "{}"), nullableTime(asset.FirstSeen), nullableTime(asset.LastSeen))
	return err
}

func (s *SQLStore) GetAsset(ctx context.Context, tenantID string, id string) (CryptoAsset, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, scan_id, asset_type, name, location, source, algorithm, strength_bits, status, classification,
	pqc_ready, qsl_score, metadata_json, first_seen, last_seen, created_at, updated_at
FROM discovery_assets
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanCryptoAsset(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CryptoAsset{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) DeleteAsset(ctx context.Context, tenantID string, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM discovery_assets WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// EachAsset streams every asset of a tenant, most recently updated first,
// with no cap: counts and filtered lists read the whole inventory, never a
// sample. fn must not use the store.
func (s *SQLStore) EachAsset(ctx context.Context, tenantID string, fn func(CryptoAsset) error) error {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, scan_id, asset_type, name, location, source, algorithm, strength_bits, status, classification,
	pqc_ready, qsl_score, metadata_json, first_seen, last_seen, created_at, updated_at
FROM discovery_assets
WHERE tenant_id = $1
ORDER BY updated_at DESC, id
`, strings.TrimSpace(tenantID))
	if err != nil {
		return err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		item, err := scanCryptoAsset(rows)
		if err != nil {
			return err
		}
		if err := fn(item); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *SQLStore) CreateTarget(ctx context.Context, t ScanTarget) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO discovery_scan_targets (tenant_id, id, host, port, protocol, created_by, created_at)
VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP)
`, t.TenantID, t.ID, t.Host, t.Port, t.proto(), t.CreatedBy)
	return err
}

func (s *SQLStore) ListTargets(ctx context.Context, tenantID string) ([]ScanTarget, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, host, port, protocol, created_by, created_at
FROM discovery_scan_targets
WHERE tenant_id = $1
ORDER BY host, port
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ScanTarget, 0)
	for rows.Next() {
		var (
			t          ScanTarget
			createdRaw interface{}
		)
		if err := rows.Scan(&t.TenantID, &t.ID, &t.Host, &t.Port, &t.Protocol, &t.CreatedBy, &createdRaw); err != nil {
			return nil, err
		}
		t.CreatedAt = parseTimeValue(createdRaw)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteTarget(ctx context.Context, tenantID string, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM discovery_scan_targets WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func scanDiscoveryScan(scanner interface {
	Scan(dest ...interface{}) error
}) (DiscoveryScan, error) {
	var (
		item         DiscoveryScan
		statsJS      string
		startedRaw   interface{}
		completedRaw interface{}
		createdRaw   interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.ID, &item.ScanType, &item.Status, &item.Trigger, &statsJS, &startedRaw, &completedRaw, &createdRaw); err != nil {
		return DiscoveryScan{}, err
	}
	item.Stats = parseJSONObject(statsJS)
	item.StartedAt = parseTimeValue(startedRaw)
	item.CompletedAt = parseTimeValue(completedRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}

func scanCryptoAsset(scanner interface {
	Scan(dest ...interface{}) error
}) (CryptoAsset, error) {
	var (
		item       CryptoAsset
		metadataJS string
		firstRaw   interface{}
		lastRaw    interface{}
		createdRaw interface{}
		updatedRaw interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.ID, &item.ScanID, &item.AssetType, &item.Name, &item.Location, &item.Source, &item.Algorithm,
		&item.StrengthBits, &item.Status, &item.Classification, &item.PQCReady, &item.QSLScore, &metadataJS, &firstRaw, &lastRaw, &createdRaw, &updatedRaw); err != nil {
		return CryptoAsset{}, err
	}
	item.Metadata = parseJSONObject(metadataJS)
	item.FirstSeen = parseTimeValue(firstRaw)
	item.LastSeen = parseTimeValue(lastRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func (s *SQLStore) CreateRepository(ctx context.Context, r Repository) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO discovery_repositories (tenant_id, id, url, ref, provider, connection_id, created_by, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP)
`, r.TenantID, r.ID, r.URL, r.Ref, r.Provider, r.ConnectionID, r.CreatedBy)
	return err
}

func (s *SQLStore) ListRepositories(ctx context.Context, tenantID string) ([]Repository, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, url, ref, provider, connection_id, created_by, created_at
FROM discovery_repositories
WHERE tenant_id = $1
ORDER BY url, ref
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]Repository, 0)
	for rows.Next() {
		var (
			r          Repository
			createdRaw interface{}
		)
		if err := rows.Scan(&r.TenantID, &r.ID, &r.URL, &r.Ref, &r.Provider, &r.ConnectionID, &r.CreatedBy, &createdRaw); err != nil {
			return nil, err
		}
		r.CreatedAt = parseTimeValue(createdRaw)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteRepository(ctx context.Context, tenantID string, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM discovery_repositories WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

const scheduleColumns = `tenant_id, enabled, interval_hours, sources, authorized_by, next_run_at, last_run_at, last_scan_id, paused_reason, updated_at`

func scanSchedule(scanner interface {
	Scan(dest ...interface{}) error
}) (Schedule, error) {
	var (
		sch                       Schedule
		sources                   string
		nextRaw, lastRaw, updated interface{}
	)
	if err := scanner.Scan(&sch.TenantID, &sch.Enabled, &sch.IntervalHours, &sources, &sch.AuthorizedBy, &nextRaw, &lastRaw, &sch.LastScanID, &sch.PausedReason, &updated); err != nil {
		return Schedule{}, err
	}
	sch.Sources = []string{}
	if sources != "" {
		sch.Sources = strings.Split(sources, ",")
	}
	sch.NextRunAt, sch.LastRunAt, sch.UpdatedAt = parseTimeValue(nextRaw), parseTimeValue(lastRaw), parseTimeValue(updated)
	return sch, nil
}

// GetSchedule returns errNotFound for a tenant that never saved one.
func (s *SQLStore) GetSchedule(ctx context.Context, tenantID string) (Schedule, error) {
	sch, err := scanSchedule(s.db.SQL().QueryRowContext(ctx, `SELECT `+scheduleColumns+` FROM discovery_schedules WHERE tenant_id = $1`, strings.TrimSpace(tenantID)))
	if errors.Is(err, sql.ErrNoRows) {
		return Schedule{}, errNotFound
	}
	return sch, err
}

func (s *SQLStore) PutSchedule(ctx context.Context, sch Schedule) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO discovery_schedules (`+scheduleColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id) DO UPDATE SET
	enabled = excluded.enabled,
	interval_hours = excluded.interval_hours,
	sources = excluded.sources,
	authorized_by = excluded.authorized_by,
	next_run_at = excluded.next_run_at,
	last_run_at = excluded.last_run_at,
	last_scan_id = excluded.last_scan_id,
	paused_reason = excluded.paused_reason,
	updated_at = CURRENT_TIMESTAMP
`, sch.TenantID, sch.Enabled, sch.IntervalHours, strings.Join(sch.Sources, ","), sch.AuthorizedBy, nullableTime(sch.NextRunAt), nullableTime(sch.LastRunAt), sch.LastScanID, sch.PausedReason)
	return err
}

// DueSchedules lists, for every tenant, the enabled, unpaused schedules whose
// next run has come.
func (s *SQLStore) DueSchedules(ctx context.Context, now time.Time) ([]Schedule, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT `+scheduleColumns+`
FROM discovery_schedules
WHERE enabled = TRUE AND paused_reason = ''
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]Schedule, 0)
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		// Compared here, not in SQL: the two databases store and compare
		// timestamps differently.
		if !sch.NextRunAt.IsZero() && !sch.NextRunAt.After(now) {
			out = append(out, sch)
		}
	}
	return out, rows.Err()
}
