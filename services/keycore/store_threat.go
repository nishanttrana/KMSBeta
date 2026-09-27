package main

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// KeyActorPair is a (key, actor) combination seen in the usage trail.
type KeyActorPair struct {
	KeyID   string
	ActorID string
}

func (s *SQLStore) InsertKeyUsageEvent(ctx context.Context, e KeyUsageEvent) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_usage_events (id, tenant_id, key_id, operation, actor_id, actor_ip, interface, occurred_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		e.ID, e.TenantID, e.KeyID, e.Operation, e.ActorID, e.ActorIP, e.Interface, e.OccurredAt)
	return err
}

func (s *SQLStore) PruneKeyUsageEvents(ctx context.Context, tenantID string, before time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx,
		`DELETE FROM key_usage_events WHERE tenant_id=$1 AND occurred_at < $2`, tenantID, before)
	return err
}

func (s *SQLStore) ListRecentKeyActorPairs(ctx context.Context, tenantID string, since time.Time, limit int) ([]KeyActorPair, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT DISTINCT key_id, actor_id FROM key_usage_events
WHERE tenant_id=$1 AND occurred_at >= $2 LIMIT $3`, tenantID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []KeyActorPair
	for rows.Next() {
		var p KeyActorPair
		if err := rows.Scan(&p.KeyID, &p.ActorID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// KeyActorFirstUse returns the earliest time this actor used this key, or the
// zero time if the actor has never used it.
func (s *SQLStore) KeyActorFirstUse(ctx context.Context, tenantID, keyID, actorID string) (time.Time, error) {
	var ts sql.NullTime
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT occurred_at FROM key_usage_events
WHERE tenant_id=$1 AND key_id=$2 AND actor_id=$3
ORDER BY occurred_at ASC LIMIT 1`, tenantID, keyID, actorID).Scan(&ts)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	if !ts.Valid {
		return time.Time{}, nil
	}
	return ts.Time, nil
}

func (s *SQLStore) ListRecentlyUsedKeyIDs(ctx context.Context, tenantID string, since time.Time, limit int) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT DISTINCT key_id FROM key_usage_events
WHERE tenant_id=$1 AND occurred_at >= $2 LIMIT $3`, tenantID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *SQLStore) CountKeyUsageBetween(ctx context.Context, tenantID, keyID string, from, to time.Time) (int, error) {
	var n int
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*) FROM key_usage_events
WHERE tenant_id=$1 AND key_id=$2 AND occurred_at >= $3 AND occurred_at < $4`,
		tenantID, keyID, from, to).Scan(&n)
	return n, err
}

func (s *SQLStore) LastKeyUsageBefore(ctx context.Context, tenantID, keyID string, before time.Time) (time.Time, error) {
	var ts sql.NullTime
	// ORDER BY ... LIMIT 1 (not MAX) so the driver returns the column's
	// native time value rather than an aggregate string.
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT occurred_at FROM key_usage_events
WHERE tenant_id=$1 AND key_id=$2 AND occurred_at < $3
ORDER BY occurred_at DESC LIMIT 1`,
		tenantID, keyID, before).Scan(&ts)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	if !ts.Valid {
		return time.Time{}, nil
	}
	return ts.Time, nil
}

// ListUsageTenants returns the tenants with key usage on this node since t.
func (s *SQLStore) ListUsageTenants(ctx context.Context, since time.Time) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx,
		`SELECT DISTINCT tenant_id FROM key_usage_events WHERE occurred_at >= $1`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CreateThreatSignal inserts a signal; returns false if an identical
// detection (same dedupe key) already exists for the tenant.
func (s *SQLStore) CreateThreatSignal(ctx context.Context, sig ThreatSignal) (bool, error) {
	res, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO threat_signals (id, tenant_id, signal_type, key_id, actor_id, severity, description, dedupe_key, detected_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`,
		sig.ID, sig.TenantID, sig.SignalType, sig.KeyID, sig.ActorID, sig.Severity,
		sig.Description, sig.DedupeKey, sig.DetectedAt)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
