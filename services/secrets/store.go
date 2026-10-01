package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
)

func newAuditID() string {
	b := make([]byte, 8)
	_, _ = pkgcrypto.Reader.Read(b)
	return "aud_" + hex.EncodeToString(b)
}

var (
	errNotFound        = errors.New("not found")
	errVersionNotFound = errors.New("version not found")
	errVersionConflict = errors.New("the secret is not at the expected version")
	errDeleted         = errors.New("secret is deleted; restore it first")
	errNotDeleted      = errors.New("secret is not deleted")
	errVersionCurrent  = errors.New("the current version cannot be destroyed; destroy the secret instead")
)

type Store interface {
	CreateSecret(ctx context.Context, secret Secret, value EncryptedSecretValue) error
	ListSecrets(ctx context.Context, tenantID string, secretType string, status string, limit int, offset int) ([]Secret, error)
	GetSecret(ctx context.Context, tenantID string, secretID string) (Secret, error)
	GetSecretByName(ctx context.Context, tenantID string, name string) (Secret, error)
	GetSecretWithValue(ctx context.Context, tenantID string, secretID string, version int) (Secret, EncryptedSecretValue, error)
	UpdateSecret(ctx context.Context, tenantID string, secretID string, req UpdateSecretRequest, expiresAt *time.Time, value *EncryptedSecretValue) (Secret, error)
	SoftDeleteSecret(ctx context.Context, tenantID string, secretID string, actor string) error
	RestoreSecret(ctx context.Context, tenantID string, secretID string, actor string) error
	DestroySecret(ctx context.Context, tenantID string, secretID string, actor string) error
	DestroyVersion(ctx context.Context, tenantID string, secretID string, version int, actor string) error
	ListVersions(ctx context.Context, tenantID string, secretID string) ([]SecretVersionInfo, error)
	VersionCounts(ctx context.Context, tenantID string) (map[string]int, error)
	GetSecretAuditLog(ctx context.Context, tenantID string, secretID string, limit int) ([]SecretAuditEntry, error)
	ListAccessRules(ctx context.Context, tenantID string) ([]AccessRule, error)
	CreateAccessRule(ctx context.Context, rule AccessRule) error
	DeleteAccessRule(ctx context.Context, tenantID string, ruleID string) (AccessRule, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

const secretColumns = `id, tenant_id, name, secret_type, description, labels, metadata, status, lease_ttl_seconds,
	   expires_at, current_version, created_by, created_at, updated_at, deleted_at, deleted_by`

// logChange appends to the secret's change history. It is a convenience view
// of the secret's own changes; the audit record is the AUDIT stream.
func logChange(ctx context.Context, tx *sql.Tx, tenantID, secretID, action, actor, detail string) {
	_, _ = tx.ExecContext(ctx, `INSERT INTO secret_audit_log (id, tenant_id, secret_id, action, actor, detail, created_at) VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP)`,
		newAuditID(), tenantID, secretID, action, actor, detail)
}

func (s *SQLStore) begin(ctx context.Context, tenantID string) (*sql.Tx, error) {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	_, _ = tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID)
	return tx, nil
}

func (s *SQLStore) CreateSecret(ctx context.Context, secret Secret, value EncryptedSecretValue) error {
	tx, err := s.begin(ctx, secret.TenantID)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

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
	if err := insertValue(ctx, tx, secret.TenantID, secret.ID, 1, value); err != nil {
		return err
	}
	logChange(ctx, tx, secret.TenantID, secret.ID, "created", secret.CreatedBy, fmt.Sprintf("Secret '%s' (%s) created, version 1", secret.Name, secret.SecretType))
	return tx.Commit()
}

func insertValue(ctx context.Context, tx *sql.Tx, tenantID, secretID string, version int, value EncryptedSecretValue) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO secret_values (
	tenant_id, secret_id, version, wrapped_dek, wrapped_dek_iv, ciphertext, data_iv, value_hash, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP)
`, tenantID, secretID, version, value.WrappedDEK, value.WrappedDEKIV, value.Ciphertext, value.DataIV, value.ValueHash)
	return err
}

// ListSecrets lists the tenant's secrets of one status (active or deleted).
func (s *SQLStore) ListSecrets(ctx context.Context, tenantID string, secretType string, status string, limit int, offset int) ([]Secret, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if status == "" {
		status = SecretStatusActive
	}
	query := `SELECT ` + secretColumns + ` FROM secrets WHERE tenant_id = $1 AND status = $2`
	args := []interface{}{tenantID, status}
	if secretType != "" {
		query += ` AND secret_type = $5`
		args = append(args, limit, offset, secretType)
	} else {
		args = append(args, limit, offset)
	}
	rows, err := s.db.SQL().QueryContext(ctx, query+` ORDER BY created_at DESC, id LIMIT $3 OFFSET $4`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]Secret, 0)
	for rows.Next() {
		sec, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sec)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetSecret(ctx context.Context, tenantID string, secretID string) (Secret, error) {
	return s.one(ctx, `SELECT `+secretColumns+` FROM secrets WHERE tenant_id = $1 AND id = $2`, tenantID, secretID)
}

func (s *SQLStore) GetSecretByName(ctx context.Context, tenantID string, name string) (Secret, error) {
	return s.one(ctx, `SELECT `+secretColumns+` FROM secrets WHERE tenant_id = $1 AND name = $2`, tenantID, name)
}

func (s *SQLStore) one(ctx context.Context, query string, args ...interface{}) (Secret, error) {
	secret, err := scanSecret(s.db.SQL().QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, errNotFound
	}
	return secret, err
}

// GetSecretWithValue returns the secret and one version of its value: the
// current one when version is 0.
func (s *SQLStore) GetSecretWithValue(ctx context.Context, tenantID string, secretID string, version int) (Secret, EncryptedSecretValue, error) {
	secret, err := s.GetSecret(ctx, tenantID, secretID)
	if err != nil {
		return Secret{}, EncryptedSecretValue{}, err
	}
	if version <= 0 {
		version = secret.CurrentVersion
	}
	var value EncryptedSecretValue
	err = s.db.SQL().QueryRowContext(ctx, `
SELECT wrapped_dek, wrapped_dek_iv, ciphertext, data_iv, value_hash
FROM secret_values WHERE tenant_id = $1 AND secret_id = $2 AND version = $3
`, tenantID, secretID, version).Scan(&value.WrappedDEK, &value.WrappedDEKIV, &value.Ciphertext, &value.DataIV, &value.ValueHash)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, EncryptedSecretValue{}, errVersionNotFound
	}
	return secret, value, err
}

// UpdateSecret applies req and, with a value, adds the next version. The
// write holds only if the secret is still at the version it was read at (and
// at req.ExpectedVersion when given), so concurrent writers cannot both win.
func (s *SQLStore) UpdateSecret(ctx context.Context, tenantID string, secretID string, req UpdateSecretRequest, expiresAt *time.Time, value *EncryptedSecretValue) (Secret, error) {
	current, err := s.GetSecret(ctx, tenantID, secretID)
	if err != nil {
		return Secret{}, err
	}
	if current.Status != SecretStatusActive {
		return Secret{}, errDeleted
	}
	if req.ExpectedVersion != nil && *req.ExpectedVersion != current.CurrentVersion {
		return Secret{}, errVersionConflict
	}
	readVersion := current.CurrentVersion

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

	tx, err := s.begin(ctx, tenantID)
	if err != nil {
		return Secret{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	labels, _ := json.Marshal(current.Labels)
	meta, _ := json.Marshal(current.Metadata)
	nextVersion := readVersion
	if value != nil {
		nextVersion++
	}
	res, err := tx.ExecContext(ctx, `
UPDATE secrets
SET name = $1,
	description = $2,
	labels = $3,
	metadata = $4,
	lease_ttl_seconds = $5,
	expires_at = $6,
	current_version = $7,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $8 AND id = $9 AND current_version = $10 AND status = $11
`, current.Name, current.Description, labels, meta, current.LeaseTTLSeconds, nullableTime(current.ExpiresAt), nextVersion, tenantID, secretID, readVersion, SecretStatusActive)
	if err != nil {
		return Secret{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Secret{}, errVersionConflict
	}
	if value != nil {
		if err := insertValue(ctx, tx, tenantID, secretID, nextVersion, *value); err != nil {
			return Secret{}, err
		}
	}
	action, detail := "updated", fmt.Sprintf("Secret updated at version %d", nextVersion)
	if value != nil {
		action, detail = "rotated", fmt.Sprintf("Secret value rotated to version %d", nextVersion)
	}
	if req.changeAction != "" {
		action, detail = req.changeAction, req.changeDetail
	}
	logChange(ctx, tx, tenantID, secretID, action, req.UpdatedBy, detail)
	if err := tx.Commit(); err != nil {
		return Secret{}, err
	}
	return s.GetSecret(ctx, tenantID, secretID)
}

// setStatus moves a secret between active and deleted; from is the status it
// must have, and missing is the error when it has the other one.
func (s *SQLStore) setStatus(ctx context.Context, tenantID, secretID, actor, from, to, action, detail string, missing error) error {
	current, err := s.GetSecret(ctx, tenantID, secretID)
	if err != nil {
		return err
	}
	if current.Status != from {
		return missing
	}
	tx, err := s.begin(ctx, tenantID)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	deletedBy := actor
	stamp := "CURRENT_TIMESTAMP"
	if to == SecretStatusActive {
		deletedBy, stamp = "", "NULL"
	}
	res, err := tx.ExecContext(ctx, `UPDATE secrets SET status = $1, deleted_at = `+stamp+`, deleted_by = $2 WHERE tenant_id = $3 AND id = $4 AND status = $5`,
		to, deletedBy, tenantID, secretID, from)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return missing
	}
	logChange(ctx, tx, tenantID, secretID, action, actor, detail)
	return tx.Commit()
}

func (s *SQLStore) SoftDeleteSecret(ctx context.Context, tenantID string, secretID string, actor string) error {
	return s.setStatus(ctx, tenantID, secretID, actor, SecretStatusActive, SecretStatusDeleted, "deleted", "Secret deleted; its versions are kept until it is destroyed", errDeleted)
}

func (s *SQLStore) RestoreSecret(ctx context.Context, tenantID string, secretID string, actor string) error {
	return s.setStatus(ctx, tenantID, secretID, actor, SecretStatusDeleted, SecretStatusActive, "restored", "Secret restored", errNotDeleted)
}

// DestroySecret removes the secret and every version of its value.
func (s *SQLStore) DestroySecret(ctx context.Context, tenantID string, secretID string, actor string) error {
	tx, err := s.begin(ctx, tenantID)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.ExecContext(ctx, `DELETE FROM secrets WHERE tenant_id = $1 AND id = $2`, tenantID, secretID)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return errNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM secret_values WHERE tenant_id = $1 AND secret_id = $2`, tenantID, secretID); err != nil {
		return err
	}
	logChange(ctx, tx, tenantID, secretID, "destroyed", actor, "Secret and all its versions destroyed")
	return tx.Commit()
}

// DestroyVersion removes one earlier version's value.
func (s *SQLStore) DestroyVersion(ctx context.Context, tenantID string, secretID string, version int, actor string) error {
	current, err := s.GetSecret(ctx, tenantID, secretID)
	if err != nil {
		return err
	}
	if version == current.CurrentVersion {
		return errVersionCurrent
	}
	tx, err := s.begin(ctx, tenantID)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	// The guard on current_version holds even if a rollback raced this call.
	res, err := tx.ExecContext(ctx, `
DELETE FROM secret_values WHERE tenant_id = $1 AND secret_id = $2 AND version = $3
  AND version <> (SELECT current_version FROM secrets WHERE tenant_id = $1 AND id = $2)
`, tenantID, secretID, version)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errVersionNotFound
	}
	logChange(ctx, tx, tenantID, secretID, "version_destroyed", actor, fmt.Sprintf("Version %d destroyed", version))
	return tx.Commit()
}

func scanSecret(scanner interface {
	Scan(dest ...interface{}) error
}) (Secret, error) {
	var (
		secret                   Secret
		labelsJSON, metadataJSON []byte
		expiresAt, deletedAt     sql.NullTime
	)
	err := scanner.Scan(
		&secret.ID, &secret.TenantID, &secret.Name, &secret.SecretType, &secret.Description,
		&labelsJSON, &metadataJSON, &secret.Status, &secret.LeaseTTLSeconds, &expiresAt, &secret.CurrentVersion,
		&secret.CreatedBy, &secret.CreatedAt, &secret.UpdatedAt, &deletedAt, &secret.DeletedBy,
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
	if deletedAt.Valid {
		ts := deletedAt.Time.UTC()
		secret.DeletedAt = &ts
	}
	secret.Path = secretPath(secret.Labels, secret.Name)
	return secret, nil
}

func (s *SQLStore) ListVersions(ctx context.Context, tenantID string, secretID string) ([]SecretVersionInfo, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT version, created_at
FROM secret_values
WHERE tenant_id = $1 AND secret_id = $2
ORDER BY version DESC
`, tenantID, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]SecretVersionInfo, 0)
	for rows.Next() {
		var v SecretVersionInfo
		if err := rows.Scan(&v.Version, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// VersionCounts is the number of stored versions of each secret.
func (s *SQLStore) VersionCounts(ctx context.Context, tenantID string) (map[string]int, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT secret_id, COUNT(*) FROM secret_values WHERE tenant_id = $1 GROUP BY secret_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

func (s *SQLStore) GetSecretAuditLog(ctx context.Context, tenantID string, secretID string, limit int) ([]SecretAuditEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, secret_id, action, actor, detail, created_at
FROM secret_audit_log
WHERE tenant_id = $1 AND secret_id = $2
ORDER BY created_at DESC
LIMIT $3
`, tenantID, secretID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]SecretAuditEntry, 0)
	for rows.Next() {
		var e SecretAuditEntry
		if err := rows.Scan(&e.ID, &e.SecretID, &e.Action, &e.Actor, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListAccessRules(ctx context.Context, tenantID string) ([]AccessRule, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, path, subject_type, subject_id, capabilities, effect, created_by, created_at
FROM secret_access_rules WHERE tenant_id = $1 ORDER BY path, created_at, id
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]AccessRule, 0)
	for rows.Next() {
		var r AccessRule
		var caps string
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Path, &r.SubjectType, &r.SubjectID, &caps, &r.Effect, &r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Capabilities = strings.Split(caps, ",")
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateAccessRule(ctx context.Context, r AccessRule) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO secret_access_rules (id, tenant_id, path, subject_type, subject_id, capabilities, effect, created_by, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP)
`, r.ID, r.TenantID, r.Path, r.SubjectType, r.SubjectID, strings.Join(r.Capabilities, ","), r.Effect, r.CreatedBy)
	return err
}

// DeleteAccessRule removes a rule and returns what it was, for the audit event.
func (s *SQLStore) DeleteAccessRule(ctx context.Context, tenantID string, ruleID string) (AccessRule, error) {
	rules, err := s.ListAccessRules(ctx, tenantID)
	if err != nil {
		return AccessRule{}, err
	}
	for _, r := range rules {
		if r.ID != ruleID {
			continue
		}
		if _, err := s.db.SQL().ExecContext(ctx, `DELETE FROM secret_access_rules WHERE tenant_id = $1 AND id = $2`, tenantID, ruleID); err != nil {
			return AccessRule{}, err
		}
		return r, nil
	}
	return AccessRule{}, errNotFound
}

func nullableTime(ts *time.Time) interface{} {
	if ts == nil || ts.IsZero() {
		return nil
	}
	return ts.UTC()
}
