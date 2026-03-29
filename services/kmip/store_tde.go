package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ListTDEDatabases returns all TDE database registrations for the given tenant.
func (s *SQLStore) ListTDEDatabases(ctx context.Context, tenantID string) ([]TDEDatabase, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, engine, host, port, db_name, key_id, key_algorithm,
       status, rotation_policy, last_rotated, created_at, updated_at
FROM tde_databases
WHERE tenant_id = $1
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]TDEDatabase, 0)
	for rows.Next() {
		item, err := scanTDEDatabase(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// CreateTDEDatabase inserts a new TDE database registration and returns the persisted record.
func (s *SQLStore) CreateTDEDatabase(ctx context.Context, db TDEDatabase) (TDEDatabase, error) {
	now := time.Now().UTC()
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO tde_databases (
    id, tenant_id, name, engine, host, port, db_name, key_id, key_algorithm,
    status, rotation_policy, last_rotated, created_at, updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
)
ON CONFLICT DO NOTHING
`, db.ID, strings.TrimSpace(db.TenantID), strings.TrimSpace(db.Name),
		strings.TrimSpace(db.Engine), strings.TrimSpace(db.Host), db.Port,
		strings.TrimSpace(db.Database), strings.TrimSpace(db.KeyID),
		strings.TrimSpace(db.KeyAlgorithm), strings.TrimSpace(db.Status),
		strings.TrimSpace(db.RotationPolicy), nullTime(db.LastRotated), now, now)
	if err != nil {
		return TDEDatabase{}, err
	}
	return s.GetTDEDatabase(ctx, db.TenantID, db.ID)
}

// GetTDEDatabase fetches a single TDE database registration by tenant and ID.
func (s *SQLStore) GetTDEDatabase(ctx context.Context, tenantID, id string) (TDEDatabase, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, engine, host, port, db_name, key_id, key_algorithm,
       status, rotation_policy, last_rotated, created_at, updated_at
FROM tde_databases
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	out, err := scanTDEDatabase(row)
	if errors.Is(err, sql.ErrNoRows) {
		return TDEDatabase{}, errNotFound
	}
	return out, err
}

// UpdateTDEDatabase persists changes to an existing TDE database registration.
func (s *SQLStore) UpdateTDEDatabase(ctx context.Context, db TDEDatabase) (TDEDatabase, error) {
	now := time.Now().UTC()
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE tde_databases
SET name            = $1,
    engine          = $2,
    host            = $3,
    port            = $4,
    db_name         = $5,
    key_id          = $6,
    key_algorithm   = $7,
    status          = $8,
    rotation_policy = $9,
    last_rotated    = $10,
    updated_at      = $11
WHERE tenant_id = $12 AND id = $13
`, strings.TrimSpace(db.Name), strings.TrimSpace(db.Engine),
		strings.TrimSpace(db.Host), db.Port, strings.TrimSpace(db.Database),
		strings.TrimSpace(db.KeyID), strings.TrimSpace(db.KeyAlgorithm),
		strings.TrimSpace(db.Status), strings.TrimSpace(db.RotationPolicy),
		nullTime(db.LastRotated), now,
		strings.TrimSpace(db.TenantID), strings.TrimSpace(db.ID))
	if err != nil {
		return TDEDatabase{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return TDEDatabase{}, errNotFound
	}
	return s.GetTDEDatabase(ctx, db.TenantID, db.ID)
}

// scanTDEDatabase scans a database row into a TDEDatabase value.
func scanTDEDatabase(scanner interface {
	Scan(dest ...interface{}) error
}) (TDEDatabase, error) {
	var (
		out            TDEDatabase
		lastRotatedRaw interface{}
		createdRaw     interface{}
		updatedRaw     interface{}
	)
	err := scanner.Scan(
		&out.ID, &out.TenantID, &out.Name, &out.Engine,
		&out.Host, &out.Port, &out.Database,
		&out.KeyID, &out.KeyAlgorithm, &out.Status,
		&out.RotationPolicy, &lastRotatedRaw, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return TDEDatabase{}, err
	}
	out.LastRotated = parseTimeValue(lastRotatedRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}
