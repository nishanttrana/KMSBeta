package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

const dbRoleColumns = `tenant_id, name, connection_id, engine, creation_statements, revocation_statements,
	default_ttl_seconds, max_ttl_seconds, created_by, created_at, updated_at`

const dbLeaseColumns = `tenant_id, id, role_name, username, state, created_by, created_at, expires_at, max_expires_at, ended_at, last_error`

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanDBRole(row rowScanner) (DBRole, error) {
	var r DBRole
	var creation, revocation string
	if err := row.Scan(&r.TenantID, &r.Name, &r.ConnectionID, &r.Engine, &creation, &revocation, &r.DefaultTTLSeconds, &r.MaxTTLSeconds, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return DBRole{}, err
	}
	if err := json.Unmarshal([]byte(creation), &r.CreationStatements); err != nil {
		return DBRole{}, err
	}
	if err := json.Unmarshal([]byte(revocation), &r.RevocationStatements); err != nil {
		return DBRole{}, err
	}
	return r, nil
}

func scanDBLease(row rowScanner) (DBLease, error) {
	var l DBLease
	var ended sql.NullTime
	if err := row.Scan(&l.TenantID, &l.ID, &l.RoleName, &l.Username, &l.State, &l.CreatedBy, &l.CreatedAt, &l.ExpiresAt, &l.MaxExpiresAt, &ended, &l.LastError); err != nil {
		return DBLease{}, err
	}
	if ended.Valid {
		t := ended.Time
		l.EndedAt = &t
	}
	return l, nil
}

func (s *SQLStore) PutDBRole(ctx context.Context, r DBRole) error {
	creation, _ := json.Marshal(r.CreationStatements)
	revocation, _ := json.Marshal(r.RevocationStatements)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO secret_db_roles (`+dbRoleColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id, name) DO UPDATE SET connection_id = excluded.connection_id, engine = excluded.engine,
	creation_statements = excluded.creation_statements, revocation_statements = excluded.revocation_statements,
	default_ttl_seconds = excluded.default_ttl_seconds, max_ttl_seconds = excluded.max_ttl_seconds, updated_at = CURRENT_TIMESTAMP
`, r.TenantID, r.Name, r.ConnectionID, r.Engine, string(creation), string(revocation), r.DefaultTTLSeconds, r.MaxTTLSeconds, r.CreatedBy)
	return err
}

func (s *SQLStore) GetDBRole(ctx context.Context, tenantID, name string) (DBRole, error) {
	r, err := scanDBRole(s.db.SQL().QueryRowContext(ctx, `SELECT `+dbRoleColumns+` FROM secret_db_roles WHERE tenant_id = $1 AND name = $2`, tenantID, name))
	if errors.Is(err, sql.ErrNoRows) {
		return DBRole{}, errNotFound
	}
	return r, err
}

func (s *SQLStore) ListDBRoles(ctx context.Context, tenantID string) ([]DBRole, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+dbRoleColumns+` FROM secret_db_roles WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []DBRole{}
	for rows.Next() {
		r, err := scanDBRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteDBRole(ctx context.Context, tenantID, name string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM secret_db_roles WHERE tenant_id = $1 AND name = $2`, tenantID, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateDBLease(ctx context.Context, l DBLease) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO secret_db_leases (tenant_id, id, role_name, username, state, created_by, created_at, expires_at, max_expires_at, last_error)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'')`, l.TenantID, l.ID, l.RoleName, l.Username, l.State, l.CreatedBy, l.CreatedAt, l.ExpiresAt, l.MaxExpiresAt)
	return err
}

func (s *SQLStore) GetDBLease(ctx context.Context, tenantID, id string) (DBLease, error) {
	l, err := scanDBLease(s.db.SQL().QueryRowContext(ctx, `SELECT `+dbLeaseColumns+` FROM secret_db_leases WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return DBLease{}, errNotFound
	}
	return l, err
}

// ListDBLeases lists the newest leases, at most limit (1 to 500).
func (s *SQLStore) ListDBLeases(ctx context.Context, tenantID, role string, limit int) ([]DBLease, error) {
	if limit < 1 || limit > 500 {
		limit = 500
	}
	q := `SELECT ` + dbLeaseColumns + ` FROM secret_db_leases WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	if role != "" {
		q += ` AND role_name = $2`
		args = append(args, role)
	}
	q += ` ORDER BY created_at DESC, id LIMIT ` + strconv.Itoa(limit)
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []DBLease{}
	for rows.Next() {
		l, err := scanDBLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *SQLStore) CountActiveDBLeases(ctx context.Context, tenantID, role string) (int, error) {
	var n int
	err := s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(1) FROM secret_db_leases WHERE tenant_id = $1 AND role_name = $2 AND state IN ('active','revoke_failed')`, tenantID, role).Scan(&n)
	return n, err
}

func (s *SQLStore) SetDBLeaseExpiry(ctx context.Context, tenantID, id string, expires time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `UPDATE secret_db_leases SET expires_at = $3 WHERE tenant_id = $1 AND id = $2 AND state = 'active'`, tenantID, id, expires)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) EndDBLease(ctx context.Context, tenantID, id, state, lastError string, endedAt *time.Time) error {
	var ended interface{}
	if endedAt != nil {
		ended = *endedAt
	}
	res, err := s.db.SQL().ExecContext(ctx, `UPDATE secret_db_leases SET state = $3, last_error = $4, ended_at = $5 WHERE tenant_id = $1 AND id = $2`, tenantID, id, state, lastError, ended)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// DueDBLeases are leases past their end that still hold a login: active
// ones that expired, and failed revocations to retry.
func (s *SQLStore) DueDBLeases(ctx context.Context, now time.Time, limit int) ([]DBLease, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+dbLeaseColumns+` FROM secret_db_leases
WHERE (state = 'active' AND expires_at <= $1) OR state = 'revoke_failed' ORDER BY expires_at LIMIT `+strconv.Itoa(limit), now)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []DBLease{}
	for rows.Next() {
		l, err := scanDBLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
