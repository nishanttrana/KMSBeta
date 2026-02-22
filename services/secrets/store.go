package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	CreateSecret(ctx context.Context, secret Secret, value EncryptedSecretValue) error
	ListSecrets(ctx context.Context, tenantID string, secretType string, limit int, offset int) ([]Secret, error)
	GetSecret(ctx context.Context, tenantID string, secretID string) (Secret, error)
	GetSecretByName(ctx context.Context, tenantID string, name string) (Secret, error)
	GetSecretWithValue(ctx context.Context, tenantID string, secretID string) (Secret, EncryptedSecretValue, error)
	UpdateSecret(ctx context.Context, tenantID string, secretID string, req UpdateSecretRequest, expiresAt *time.Time, value *EncryptedSecretValue) (Secret, error)
	DeleteSecret(ctx context.Context, tenantID string, secretID string) error
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) CreateSecret(ctx context.Context, secret Secret, value EncryptedSecretValue) error {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	_, _ = tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", secret.TenantID)

	labels, _ := json.Marshal(secret.Labels)
	meta, _ := json.Marshal(secret.Metadata)
	_, err = tx.ExecContext(ctx, `
INSERT INTO secrets (
	id, tenant_id, name, secret_type, description, labels, metadata,
	status, lease_ttl_seconds, expires_at, current_version, created_by, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
`, secret.ID, secret.TenantID, secret.Name, secret.SecretType, secret.Description, labels, meta, secret.Status, secret.LeaseTTLSeconds, nullableTime(secret.ExpiresAt), secret.CreatedBy)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO secret_values (
	tenant_id, secret_id, version, wrapped_dek, wrapped_dek_iv, ciphertext, data_iv, value_hash, created_at
) VALUES ($1,$2,1,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP)
`, secret.TenantID, secret.ID, value.WrappedDEK, value.WrappedDEKIV, value.Ciphertext, value.DataIV, value.ValueHash)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) ListSecrets(ctx context.Context, tenantID string, secretType string, limit int, offset int) ([]Secret, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if secretType != "" {
		rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, secret_type, description, labels, metadata, status, lease_ttl_seconds,
	   expires_at, current_version, created_by, created_at, updated_at
FROM secrets
WHERE tenant_id = $1 AND secret_type = $2
ORDER BY created_at DESC
LIMIT $3 OFFSET $4
`, tenantID, secretType, limit, offset)
		if err != nil {
			return nil, err
		}
		defer rows.Close() //nolint:errcheck
		return scanSecrets(rows)
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, secret_type, description, labels, metadata, status, lease_ttl_seconds,
	   expires_at, current_version, created_by, created_at, updated_at
FROM secrets
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3
`, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanSecrets(rows)
}

func (s *SQLStore) GetSecret(ctx context.Context, tenantID string, secretID string) (Secret, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, secret_type, description, labels, metadata, status, lease_ttl_seconds,
	   expires_at, current_version, created_by, created_at, updated_at
FROM secrets
WHERE tenant_id = $1 AND id = $2
`, tenantID, secretID)
	secret, err := scanSecret(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, errNotFound
	}
	return secret, err
}

func (s *SQLStore) GetSecretByName(ctx context.Context, tenantID string, name string) (Secret, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, secret_type, description, labels, metadata, status, lease_ttl_seconds,
	   expires_at, current_version, created_by, created_at, updated_at
FROM secrets
WHERE tenant_id = $1 AND name = $2
ORDER BY updated_at DESC
LIMIT 1
`, tenantID, name)
	secret, err := scanSecret(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, errNotFound
	}
	return secret, err
}

func (s *SQLStore) GetSecretWithValue(ctx context.Context, tenantID string, secretID string) (Secret, EncryptedSecretValue, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT s.id, s.tenant_id, s.name, s.secret_type, s.description, s.labels, s.metadata, s.status, s.lease_ttl_seconds,
	   s.expires_at, s.current_version, s.created_by, s.created_at, s.updated_at,
	   v.wrapped_dek, v.wrapped_dek_iv, v.ciphertext, v.data_iv, v.value_hash
FROM secrets s
JOIN secret_values v
	ON v.tenant_id = s.tenant_id
   AND v.secret_id = s.id
   AND v.version = s.current_version
WHERE s.tenant_id = $1 AND s.id = $2
`, tenantID, secretID)
	var (
		secret                   Secret
		labelsJSON, metadataJSON []byte
		expiresAt                sql.NullTime
		value                    EncryptedSecretValue
	)
	err := row.Scan(
		&secret.ID, &secret.TenantID, &secret.Name, &secret.SecretType, &secret.Description, &labelsJSON, &metadataJSON,
		&secret.Status, &secret.LeaseTTLSeconds, &expiresAt, &secret.CurrentVersion, &secret.CreatedBy, &secret.CreatedAt, &secret.UpdatedAt,
		&value.WrappedDEK, &value.WrappedDEKIV, &value.Ciphertext, &value.DataIV, &value.ValueHash,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, EncryptedSecretValue{}, errNotFound
	}
	if err != nil {
		return Secret{}, EncryptedSecretValue{}, err
	}
	if len(labelsJSON) > 0 {
		_ = json.Unmarshal(labelsJSON, &secret.Labels)
	}
	if secret.Labels == nil {
		secret.Labels = map[string]string{}
	}
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &secret.Metadata)
	}
	if secret.Metadata == nil {
		secret.Metadata = map[string]interface{}{}
	}
	if expiresAt.Valid {
		ts := expiresAt.Time.UTC()
		secret.ExpiresAt = &ts
	}
	return secret, value, nil
}

func (s *SQLStore) UpdateSecret(ctx context.Context, tenantID string, secretID string, req UpdateSecretRequest, expiresAt *time.Time, value *EncryptedSecretValue) (Secret, error) {
	current, err := s.GetSecret(ctx, tenantID, secretID)
	if err != nil {
		return Secret{}, err
	}

	if req.Name != nil {
		current.Name = *req.Name
	}
	if req.Description != nil {
		current.Description = *req.Description
	}
	if req.Labels != nil {
		current.Labels = *req.Labels
	}
	if req.Metadata != nil {
		current.Metadata = *req.Metadata
	}
	if req.LeaseTTLSeconds != nil {
		current.LeaseTTLSeconds = *req.LeaseTTLSeconds
		current.ExpiresAt = expiresAt
	}

	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return Secret{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	_, _ = tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID)

	labels, _ := json.Marshal(current.Labels)
	meta, _ := json.Marshal(current.Metadata)
	nextVersion := current.CurrentVersion
	if value != nil {
		nextVersion++
		_, err = tx.ExecContext(ctx, `
INSERT INTO secret_values (
	tenant_id, secret_id, version, wrapped_dek, wrapped_dek_iv, ciphertext, data_iv, value_hash, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP)
`, tenantID, secretID, nextVersion, value.WrappedDEK, value.WrappedDEKIV, value.Ciphertext, value.DataIV, value.ValueHash)
		if err != nil {
			return Secret{}, err
		}
	}
	_, err = tx.ExecContext(ctx, `
UPDATE secrets
SET name = $1,
	description = $2,
	labels = $3,
	metadata = $4,
	lease_ttl_seconds = $5,
	expires_at = $6,
	current_version = $7,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $8 AND id = $9
`, current.Name, current.Description, labels, meta, current.LeaseTTLSeconds, nullableTime(current.ExpiresAt), nextVersion, tenantID, secretID)
	if err != nil {
		return Secret{}, err
	}
	if err := tx.Commit(); err != nil {
		return Secret{}, err
	}
	return s.GetSecret(ctx, tenantID, secretID)
}

func (s *SQLStore) DeleteSecret(ctx context.Context, tenantID string, secretID string) error {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	_, _ = tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID)

	res, err := tx.ExecContext(ctx, `DELETE FROM secrets WHERE tenant_id = $1 AND id = $2`, tenantID, secretID)
	if err != nil {
		return err
	}
	_, _ = tx.ExecContext(ctx, `DELETE FROM secret_values WHERE tenant_id = $1 AND secret_id = $2`, tenantID, secretID)
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return errNotFound
	}
	return tx.Commit()
}

func scanSecrets(rows *sql.Rows) ([]Secret, error) {
	out := make([]Secret, 0)
	for rows.Next() {
		s, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func scanSecret(scanner interface {
	Scan(dest ...interface{}) error
}) (Secret, error) {
	var (
		secret                   Secret
		labelsJSON, metadataJSON []byte
		expiresAt                sql.NullTime
	)
	err := scanner.Scan(
		&secret.ID, &secret.TenantID, &secret.Name, &secret.SecretType, &secret.Description,
		&labelsJSON, &metadataJSON, &secret.Status, &secret.LeaseTTLSeconds, &expiresAt, &secret.CurrentVersion,
		&secret.CreatedBy, &secret.CreatedAt, &secret.UpdatedAt,
	)
	if err != nil {
		return Secret{}, err
	}
	if len(labelsJSON) > 0 {
		_ = json.Unmarshal(labelsJSON, &secret.Labels)
	}
	if secret.Labels == nil {
		secret.Labels = map[string]string{}
	}
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &secret.Metadata)
	}
	if secret.Metadata == nil {
		secret.Metadata = map[string]interface{}{}
	}
	if expiresAt.Valid {
		ts := expiresAt.Time.UTC()
		secret.ExpiresAt = &ts
	}
	return secret, nil
}

func nullableTime(ts *time.Time) interface{} {
	if ts == nil || ts.IsZero() {
		return nil
	}
	return ts.UTC()
}
