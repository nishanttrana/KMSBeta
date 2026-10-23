package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Edge devices, leases and receipts (migration 012, edge.go).

const edgeDeviceColumns = `tenant_id, id, name, status, allowed_key_ids, max_lease_seconds, token_hash, token_expires_at, credential_hash,
	   signing_public_key, kem_public_key, last_receipt_seq, last_seen_at, last_source_ip, agent_version, created_by, created_at,
	   enrolled_at, revoked_at, revoked_by, revoke_reason`

func scanEdgeDevice(sc interface {
	Scan(dest ...interface{}) error
}) (edgeDevice, error) {
	var (
		d                                         edgeDevice
		keys                                      string
		tokenExp, seen, created, enrolled, revoke interface{}
	)
	err := sc.Scan(&d.TenantID, &d.ID, &d.Name, &d.Status, &keys, &d.MaxLeaseSeconds, &d.TokenHash, &tokenExp, &d.CredentialHash,
		&d.SigningPublicKey, &d.KEMPublicKey, &d.LastReceiptSeq, &seen, &d.LastSourceIP, &d.AgentVersion, &d.CreatedBy, &created,
		&enrolled, &revoke, &d.RevokedBy, &d.RevokeReason)
	if err != nil {
		return edgeDevice{}, err
	}
	_ = json.Unmarshal([]byte(keys), &d.AllowedKeyIDs)
	if d.AllowedKeyIDs == nil {
		d.AllowedKeyIDs = []string{}
	}
	d.TokenExpiresAt, d.CreatedAt = parseTimeValue(tokenExp), parseTimeValue(created)
	d.LastSeenAt, d.EnrolledAt, d.RevokedAt = optionalTime(seen), optionalTime(enrolled), optionalTime(revoke)
	return d, nil
}

func optionalTime(v interface{}) *time.Time {
	if t := parseTimeValue(v); !t.IsZero() {
		return &t
	}
	return nil
}

func keysJSON(ids []string) string {
	if ids == nil {
		ids = []string{}
	}
	raw, _ := json.Marshal(ids)
	return string(raw)
}

func (s *SQLStore) CreateEdgeDevice(ctx context.Context, d edgeDevice) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_edge_devices (tenant_id, id, name, status, allowed_key_ids, max_lease_seconds, created_by, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, d.TenantID, d.ID, d.Name, d.Status, keysJSON(d.AllowedKeyIDs), d.MaxLeaseSeconds, d.CreatedBy, d.CreatedAt.UTC())
	return err
}

func (s *SQLStore) GetEdgeDevice(ctx context.Context, tenantID, id string) (edgeDevice, error) {
	d, err := scanEdgeDevice(s.db.SQL().QueryRowContext(ctx, `SELECT `+edgeDeviceColumns+` FROM ekm_edge_devices WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return edgeDevice{}, errNotFound
	}
	return d, err
}

func (s *SQLStore) ListEdgeDevices(ctx context.Context, tenantID string) ([]edgeDevice, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+edgeDeviceColumns+` FROM ekm_edge_devices WHERE tenant_id = $1 ORDER BY name, id LIMIT 1000`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []edgeDevice{}
	for rows.Next() {
		d, err := scanEdgeDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateEdgeDevicePolicy(ctx context.Context, tenantID, id string, keys []string, maxLease int64) error {
	return affected(s.db.SQL().ExecContext(ctx, `UPDATE ekm_edge_devices SET allowed_key_ids = $1, max_lease_seconds = $2 WHERE tenant_id = $3 AND id = $4`,
		keysJSON(keys), maxLease, tenantID, id))
}

func (s *SQLStore) SetEdgeDeviceToken(ctx context.Context, tenantID, id, tokenHash string, expires time.Time) error {
	return affected(s.db.SQL().ExecContext(ctx, `UPDATE ekm_edge_devices SET token_hash = $1, token_expires_at = $2 WHERE tenant_id = $3 AND id = $4 AND status <> 'revoked'`,
		tokenHash, expires.UTC(), tenantID, id))
}

// ConsumeEdgeDeviceToken enrols the device: the token is cleared in the same
// statement, so of two agents presenting one token only one is enrolled.
func (s *SQLStore) ConsumeEdgeDeviceToken(ctx context.Context, d edgeDevice, tokenHash string) (bool, error) {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_edge_devices SET status = 'active', token_hash = '', token_expires_at = NULL, credential_hash = $1, signing_public_key = $2,
	kem_public_key = $3, last_receipt_seq = 0, enrolled_at = $4, last_seen_at = $4, last_source_ip = $5, agent_version = $6
WHERE tenant_id = $7 AND id = $8 AND token_hash = $9 AND token_hash <> '' AND status <> 'revoked'`,
		d.CredentialHash, d.SigningPublicKey, d.KEMPublicKey, d.EnrolledAt.UTC(), d.LastSourceIP, d.AgentVersion, d.TenantID, d.ID, tokenHash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *SQLStore) TouchEdgeDevice(ctx context.Context, tenantID, id, ip, version string, at time.Time) error {
	return affected(s.db.SQL().ExecContext(ctx, `UPDATE ekm_edge_devices SET last_seen_at = $1, last_source_ip = $2, agent_version = $3 WHERE tenant_id = $4 AND id = $5`,
		at.UTC(), ip, version, tenantID, id))
}

// RevokeEdgeDevice revokes the device and every lease it holds.
func (s *SQLStore) RevokeEdgeDevice(ctx context.Context, tenantID, id, by, reason string, at time.Time) error {
	if err := affected(s.db.SQL().ExecContext(ctx, `
UPDATE ekm_edge_devices SET status = 'revoked', revoked_at = $1, revoked_by = $2, revoke_reason = $3, token_hash = '', credential_hash = ''
WHERE tenant_id = $4 AND id = $5 AND status <> 'revoked'`, at.UTC(), by, reason, tenantID, id)); err != nil {
		return err
	}
	_, err := s.db.SQL().ExecContext(ctx, `UPDATE ekm_edge_leases SET revoked_at = $1 WHERE tenant_id = $2 AND device_id = $3 AND revoked_at IS NULL`, at.UTC(), tenantID, id)
	return err
}

const edgeLeaseColumns = `tenant_id, id, device_id, key_id, key_version, wrapped_dek, wrapped_dek_iv, issued_at, expires_at, revoked_at`

func scanEdgeLease(sc interface {
	Scan(dest ...interface{}) error
}) (edgeLease, error) {
	var (
		l                        edgeLease
		issued, expires, revoked interface{}
	)
	if err := sc.Scan(&l.TenantID, &l.ID, &l.DeviceID, &l.KeyID, &l.KeyVersion, &l.WrappedDEK, &l.WrappedDEKIV, &issued, &expires, &revoked); err != nil {
		return edgeLease{}, err
	}
	l.IssuedAt, l.ExpiresAt, l.RevokedAt = parseTimeValue(issued), parseTimeValue(expires), optionalTime(revoked)
	return l, nil
}

func (s *SQLStore) CreateEdgeLease(ctx context.Context, l edgeLease) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_edge_leases (tenant_id, id, device_id, key_id, key_version, wrapped_dek, wrapped_dek_iv, issued_at, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, l.TenantID, l.ID, l.DeviceID, l.KeyID, l.KeyVersion, l.WrappedDEK, l.WrappedDEKIV, l.IssuedAt.UTC(), l.ExpiresAt.UTC())
	return err
}

func (s *SQLStore) GetEdgeLease(ctx context.Context, tenantID, id string) (edgeLease, error) {
	l, err := scanEdgeLease(s.db.SQL().QueryRowContext(ctx, `SELECT `+edgeLeaseColumns+` FROM ekm_edge_leases WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return edgeLease{}, errNotFound
	}
	return l, err
}

// ListEdgeLeases lists a device's leases, newest first, at most limit.
func (s *SQLStore) ListEdgeLeases(ctx context.Context, tenantID, deviceID string, limit int) ([]edgeLease, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+edgeLeaseColumns+` FROM ekm_edge_leases WHERE tenant_id = $1 AND device_id = $2 ORDER BY issued_at DESC, id DESC LIMIT $3`,
		tenantID, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []edgeLease{}
	for rows.Next() {
		l, err := scanEdgeLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *SQLStore) RevokeEdgeLease(ctx context.Context, tenantID, id string, at time.Time) error {
	return affected(s.db.SQL().ExecContext(ctx, `UPDATE ekm_edge_leases SET revoked_at = $1 WHERE tenant_id = $2 AND id = $3 AND revoked_at IS NULL`, at.UTC(), tenantID, id))
}

// AddEdgeReceipts stores a verified batch and moves the device's sequence
// forward, only from the sequence the batch was checked against: a batch
// racing another for the same device stores nothing.
func (s *SQLStore) AddEdgeReceipts(ctx context.Context, tenantID, deviceID string, from int64, receipts []edgeReceipt, at time.Time) (bool, error) {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck
	last := receipts[len(receipts)-1].Seq
	res, err := tx.ExecContext(ctx, `UPDATE ekm_edge_devices SET last_receipt_seq = $1 WHERE tenant_id = $2 AND id = $3 AND last_receipt_seq = $4`, last, tenantID, deviceID, from)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, nil
	}
	for _, r := range receipts {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO ekm_edge_receipts (tenant_id, device_id, seq, lease_id, operation, bytes, device_time, received_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tenantID, deviceID, r.Seq, r.LeaseID, r.Operation, r.Bytes, r.At.UTC(), at.UTC()); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

// ListEdgeReceipts lists a device's receipts, newest first, at most limit.
func (s *SQLStore) ListEdgeReceipts(ctx context.Context, tenantID, deviceID string, limit int) ([]edgeReceipt, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT seq, lease_id, operation, bytes, device_time, received_at FROM ekm_edge_receipts WHERE tenant_id = $1 AND device_id = $2 ORDER BY seq DESC LIMIT $3`,
		tenantID, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []edgeReceipt{}
	for rows.Next() {
		var (
			r            edgeReceipt
			at, received interface{}
		)
		if err := rows.Scan(&r.Seq, &r.LeaseID, &r.Operation, &r.Bytes, &at, &received); err != nil {
			return nil, err
		}
		r.At, r.ReceivedAt = parseTimeValue(at), parseTimeValue(received)
		out = append(out, r)
	}
	return out, rows.Err()
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}
