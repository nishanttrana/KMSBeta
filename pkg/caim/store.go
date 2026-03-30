package caim

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

const caimMigrationSQL = `
CREATE TABLE IF NOT EXISTS caim_crypto_assets (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	asset_type TEXT NOT NULL,
	name TEXT NOT NULL,
	location_service TEXT NOT NULL DEFAULT '',
	location_host TEXT NOT NULL DEFAULT '',
	location_cloud TEXT NOT NULL DEFAULT '',
	location_path TEXT NOT NULL DEFAULT '',
	algorithm TEXT NOT NULL DEFAULT '',
	key_size INTEGER NOT NULL DEFAULT 0,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at TIMESTAMP,
	owner TEXT NOT NULL DEFAULT '',
	compliance_status TEXT NOT NULL DEFAULT 'unknown',
	risk_score REAL NOT NULL DEFAULT 0.0,
	discovery_source TEXT NOT NULL DEFAULT '',
	last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	metadata TEXT NOT NULL DEFAULT '{}',
	removed BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_caim_assets_tenant ON caim_crypto_assets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_caim_assets_type ON caim_crypto_assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_caim_assets_compliance ON caim_crypto_assets(compliance_status);
CREATE INDEX IF NOT EXISTS idx_caim_assets_risk ON caim_crypto_assets(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_caim_assets_expires ON caim_crypto_assets(expires_at);
`

// SQLStore persists crypto asset inventory data.
type SQLStore struct {
	db *sql.DB
}

// NewSQLStore creates a new CAIM SQL store and runs migrations.
func NewSQLStore(db *sql.DB) (*SQLStore, error) {
	s := &SQLStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("caim/store: migration failed: %w", err)
	}
	return s, nil
}

func (s *SQLStore) migrate() error {
	_, err := s.db.Exec(caimMigrationSQL)
	return err
}

// CreateAsset inserts a new crypto asset.
func (s *SQLStore) CreateAsset(ctx context.Context, asset *CryptoAsset) error {
	meta, err := json.Marshal(asset.Metadata)
	if err != nil {
		meta = []byte("{}")
	}

	var expiresAt *time.Time
	if !asset.ExpiresAt.IsZero() {
		expiresAt = &asset.ExpiresAt
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO caim_crypto_assets (id, tenant_id, asset_type, name, location_service, location_host, location_cloud, location_path, algorithm, key_size, created_at, expires_at, owner, compliance_status, risk_score, discovery_source, last_seen, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
		asset.ID, asset.TenantID, asset.AssetType, asset.Name,
		asset.Location.Service, asset.Location.Host, asset.Location.Cloud, asset.Location.Path,
		asset.Algorithm, asset.KeySize, asset.CreatedAt, expiresAt,
		asset.Owner, asset.ComplianceStatus, asset.RiskScore,
		asset.DiscoverySource, asset.LastSeen, string(meta),
	)
	if err != nil {
		return fmt.Errorf("caim/store: create asset: %w", err)
	}
	return nil
}

// UpdateAsset updates an existing crypto asset.
func (s *SQLStore) UpdateAsset(ctx context.Context, asset *CryptoAsset) error {
	meta, err := json.Marshal(asset.Metadata)
	if err != nil {
		meta = []byte("{}")
	}

	var expiresAt *time.Time
	if !asset.ExpiresAt.IsZero() {
		expiresAt = &asset.ExpiresAt
	}

	_, err = s.db.ExecContext(ctx,
		`UPDATE caim_crypto_assets SET
			asset_type = $2, name = $3, location_service = $4, location_host = $5,
			location_cloud = $6, location_path = $7, algorithm = $8, key_size = $9,
			expires_at = $10, owner = $11, compliance_status = $12, risk_score = $13,
			discovery_source = $14, last_seen = $15, metadata = $16, removed = FALSE
		 WHERE id = $1`,
		asset.ID, asset.AssetType, asset.Name,
		asset.Location.Service, asset.Location.Host, asset.Location.Cloud, asset.Location.Path,
		asset.Algorithm, asset.KeySize, expiresAt, asset.Owner,
		asset.ComplianceStatus, asset.RiskScore, asset.DiscoverySource,
		asset.LastSeen, string(meta),
	)
	if err != nil {
		return fmt.Errorf("caim/store: update asset: %w", err)
	}
	return nil
}

// MarkAssetRemoved soft-deletes an asset that was not seen in the latest discovery run.
func (s *SQLStore) MarkAssetRemoved(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE caim_crypto_assets SET removed = TRUE WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("caim/store: mark removed: %w", err)
	}
	return nil
}

// GetAsset retrieves a single asset by ID.
func (s *SQLStore) GetAsset(ctx context.Context, id string) (*CryptoAsset, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, asset_type, name, location_service, location_host, location_cloud, location_path,
			algorithm, key_size, created_at, expires_at, owner, compliance_status, risk_score,
			discovery_source, last_seen, metadata
		 FROM caim_crypto_assets WHERE id = $1 AND removed = FALSE`, id)

	return s.scanAsset(row)
}

// ListAssets returns all active crypto assets for a tenant.
func (s *SQLStore) ListAssets(ctx context.Context, tenantID string) ([]CryptoAsset, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, asset_type, name, location_service, location_host, location_cloud, location_path,
			algorithm, key_size, created_at, expires_at, owner, compliance_status, risk_score,
			discovery_source, last_seen, metadata
		 FROM caim_crypto_assets WHERE tenant_id = $1 AND removed = FALSE
		 ORDER BY risk_score DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("caim/store: list assets: %w", err)
	}
	defer rows.Close()

	var assets []CryptoAsset
	for rows.Next() {
		a, err := s.scanAssetFromRows(rows)
		if err != nil {
			return nil, err
		}
		assets = append(assets, *a)
	}
	return assets, rows.Err()
}

// ListAssetsByType returns assets filtered by type.
func (s *SQLStore) ListAssetsByType(ctx context.Context, tenantID, assetType string) ([]CryptoAsset, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, asset_type, name, location_service, location_host, location_cloud, location_path,
			algorithm, key_size, created_at, expires_at, owner, compliance_status, risk_score,
			discovery_source, last_seen, metadata
		 FROM caim_crypto_assets WHERE tenant_id = $1 AND asset_type = $2 AND removed = FALSE
		 ORDER BY risk_score DESC`, tenantID, assetType)
	if err != nil {
		return nil, fmt.Errorf("caim/store: list by type: %w", err)
	}
	defer rows.Close()

	var assets []CryptoAsset
	for rows.Next() {
		a, err := s.scanAssetFromRows(rows)
		if err != nil {
			return nil, err
		}
		assets = append(assets, *a)
	}
	return assets, rows.Err()
}

func (s *SQLStore) scanAsset(row *sql.Row) (*CryptoAsset, error) {
	var a CryptoAsset
	var expiresAt sql.NullTime
	var metaJSON string

	err := row.Scan(&a.ID, &a.TenantID, &a.AssetType, &a.Name,
		&a.Location.Service, &a.Location.Host, &a.Location.Cloud, &a.Location.Path,
		&a.Algorithm, &a.KeySize, &a.CreatedAt, &expiresAt, &a.Owner,
		&a.ComplianceStatus, &a.RiskScore, &a.DiscoverySource, &a.LastSeen, &metaJSON)
	if err != nil {
		return nil, fmt.Errorf("caim/store: scan asset: %w", err)
	}

	if expiresAt.Valid {
		a.ExpiresAt = expiresAt.Time
	}
	if metaJSON != "" {
		_ = json.Unmarshal([]byte(metaJSON), &a.Metadata)
	}
	return &a, nil
}

func (s *SQLStore) scanAssetFromRows(rows *sql.Rows) (*CryptoAsset, error) {
	var a CryptoAsset
	var expiresAt sql.NullTime
	var metaJSON string

	err := rows.Scan(&a.ID, &a.TenantID, &a.AssetType, &a.Name,
		&a.Location.Service, &a.Location.Host, &a.Location.Cloud, &a.Location.Path,
		&a.Algorithm, &a.KeySize, &a.CreatedAt, &expiresAt, &a.Owner,
		&a.ComplianceStatus, &a.RiskScore, &a.DiscoverySource, &a.LastSeen, &metaJSON)
	if err != nil {
		return nil, fmt.Errorf("caim/store: scan asset: %w", err)
	}

	if expiresAt.Valid {
		a.ExpiresAt = expiresAt.Time
	}
	if metaJSON != "" {
		_ = json.Unmarshal([]byte(metaJSON), &a.Metadata)
	}
	return &a, nil
}
