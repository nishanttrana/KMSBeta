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

func (s *SQLStore) ListAssets(ctx context.Context, tenantID string, limit int, offset int, source string, assetType string, classification string) ([]CryptoAsset, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, scan_id, asset_type, name, location, source, algorithm, strength_bits, status, classification,
	pqc_ready, qsl_score, metadata_json, first_seen, last_seen, created_at, updated_at
FROM discovery_assets
WHERE tenant_id = $1
	AND ($2 = '' OR source = $2)
	AND ($3 = '' OR asset_type = $3)
	AND ($4 = '' OR classification = $4)
ORDER BY updated_at DESC
LIMIT $5 OFFSET $6
`, strings.TrimSpace(tenantID), strings.ToLower(strings.TrimSpace(source)), strings.ToLower(strings.TrimSpace(assetType)), strings.ToLower(strings.TrimSpace(classification)), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]CryptoAsset, 0)
	for rows.Next() {
		item, err := scanCryptoAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CountAssets(ctx context.Context, tenantID string) (int, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*) FROM discovery_assets WHERE tenant_id = $1
`, strings.TrimSpace(tenantID))
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
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
