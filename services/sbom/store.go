package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	SaveSBOMSnapshot(ctx context.Context, item SBOMSnapshot) error
	GetLatestSBOMSnapshot(ctx context.Context) (SBOMSnapshot, error)
	ListSBOMSnapshots(ctx context.Context, limit int) ([]SBOMSnapshot, error)
	GetSBOMSnapshotByID(ctx context.Context, id string) (SBOMSnapshot, error)

	SaveCBOMSnapshot(ctx context.Context, item CBOMSnapshot) error
	GetLatestCBOMSnapshot(ctx context.Context, tenantID string) (CBOMSnapshot, error)
	ListCBOMSnapshots(ctx context.Context, tenantID string, limit int) ([]CBOMSnapshot, error)
	GetCBOMSnapshotByID(ctx context.Context, tenantID string, id string) (CBOMSnapshot, error)
	ListKnownCBOMTenants(ctx context.Context) ([]string, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) SaveSBOMSnapshot(ctx context.Context, item SBOMSnapshot) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO sbom_snapshots (
	id, appliance_id, format, spec_version, source_hash, summary_json, document_json, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP
)
`, item.ID, defaultString(item.Document.Appliance, "vecta-kms"), defaultString(item.Document.Format, "cyclonedx"),
		defaultString(item.Document.SpecVersion, "1.6"), item.SourceHash, mustJSON(item.Summary, "{}"), mustJSON(item.Document, "{}"))
	return err
}

func (s *SQLStore) GetLatestSBOMSnapshot(ctx context.Context) (SBOMSnapshot, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, source_hash, summary_json, document_json, created_at
FROM sbom_snapshots
ORDER BY created_at DESC
LIMIT 1
`)
	item, err := scanSBOMSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SBOMSnapshot{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListSBOMSnapshots(ctx context.Context, limit int) ([]SBOMSnapshot, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, source_hash, summary_json, document_json, created_at
FROM sbom_snapshots
ORDER BY created_at DESC
LIMIT $1
`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]SBOMSnapshot, 0)
	for rows.Next() {
		item, err := scanSBOMSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetSBOMSnapshotByID(ctx context.Context, id string) (SBOMSnapshot, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, source_hash, summary_json, document_json, created_at
FROM sbom_snapshots
WHERE id = $1
`, id)
	item, err := scanSBOMSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SBOMSnapshot{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) SaveCBOMSnapshot(ctx context.Context, item CBOMSnapshot) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cbom_snapshots (
	tenant_id, id, format, spec_version, source_hash, summary_json, document_json, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, defaultString(item.Document.Format, "cyclonedx-crypto"), defaultString(item.Document.SpecVersion, "1.6"),
		item.SourceHash, mustJSON(item.Summary, "{}"), mustJSON(item.Document, "{}"))
	return err
}

func (s *SQLStore) GetLatestCBOMSnapshot(ctx context.Context, tenantID string) (CBOMSnapshot, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, source_hash, summary_json, document_json, created_at
FROM cbom_snapshots
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT 1
`, tenantID)
	item, err := scanCBOMSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CBOMSnapshot{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListCBOMSnapshots(ctx context.Context, tenantID string, limit int) ([]CBOMSnapshot, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, source_hash, summary_json, document_json, created_at
FROM cbom_snapshots
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2
`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]CBOMSnapshot, 0)
	for rows.Next() {
		item, err := scanCBOMSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetCBOMSnapshotByID(ctx context.Context, tenantID string, id string) (CBOMSnapshot, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, source_hash, summary_json, document_json, created_at
FROM cbom_snapshots
WHERE tenant_id = $1 AND id = $2
`, tenantID, id)
	item, err := scanCBOMSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CBOMSnapshot{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListKnownCBOMTenants(ctx context.Context) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT DISTINCT tenant_id
FROM cbom_snapshots
ORDER BY tenant_id
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []string{}
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		tenantID = defaultString(tenantID, "")
		if tenantID != "" {
			out = append(out, tenantID)
		}
	}
	return out, rows.Err()
}

func scanSBOMSnapshot(scanner interface {
	Scan(dest ...interface{}) error
}) (SBOMSnapshot, error) {
	var (
		item       SBOMSnapshot
		summaryJS  string
		documentJS string
		createdRaw interface{}
	)
	err := scanner.Scan(&item.ID, &item.SourceHash, &summaryJS, &documentJS, &createdRaw)
	if err != nil {
		return SBOMSnapshot{}, err
	}
	if stringsTrim(documentJS) != "" {
		_ = json.Unmarshal([]byte(documentJS), &item.Document)
	}
	if stringsTrim(summaryJS) != "" {
		_ = json.Unmarshal([]byte(summaryJS), &item.Summary)
	}
	if item.Document.Components == nil {
		item.Document.Components = []BOMComponent{}
	}
	if item.Summary == nil {
		item.Summary = map[string]interface{}{}
	}
	item.CreatedAt = parseTimeValue(createdRaw)
	if item.Document.GeneratedAt.IsZero() {
		item.Document.GeneratedAt = item.CreatedAt
	}
	return item, nil
}

func scanCBOMSnapshot(scanner interface {
	Scan(dest ...interface{}) error
}) (CBOMSnapshot, error) {
	var (
		item       CBOMSnapshot
		summaryJS  string
		documentJS string
		createdRaw interface{}
	)
	err := scanner.Scan(&item.TenantID, &item.ID, &item.SourceHash, &summaryJS, &documentJS, &createdRaw)
	if err != nil {
		return CBOMSnapshot{}, err
	}
	if stringsTrim(documentJS) != "" {
		_ = json.Unmarshal([]byte(documentJS), &item.Document)
	}
	if stringsTrim(summaryJS) != "" {
		_ = json.Unmarshal([]byte(summaryJS), &item.Summary)
	}
	if item.Document.Assets == nil {
		item.Document.Assets = []CryptoAsset{}
	}
	if item.Document.AlgorithmDistribution == nil {
		item.Document.AlgorithmDistribution = map[string]int{}
	}
	if item.Document.StrengthHistogram == nil {
		item.Document.StrengthHistogram = map[string]int{}
	}
	if item.Document.SourceCount == nil {
		item.Document.SourceCount = map[string]int{}
	}
	if item.Document.Metadata == nil {
		item.Document.Metadata = map[string]string{}
	}
	if item.Summary == nil {
		item.Summary = map[string]interface{}{}
	}
	item.CreatedAt = parseTimeValue(createdRaw)
	if item.Document.GeneratedAt.IsZero() {
		item.Document.GeneratedAt = item.CreatedAt
	}
	return item, nil
}

func stringsTrim(v string) string {
	return defaultString(v, "")
}
