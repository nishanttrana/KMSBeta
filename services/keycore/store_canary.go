package main

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// canary_keys is replicated; canary_trip_events is node-local
// (pkg/clustercatalog). A trip is only ever written to the node-local log, so
// a probe served by a cluster member never writes a replicated table. Trip
// counts are read from that log, not kept on the key row.

func (s *SQLStore) ListCanaryKeys(ctx context.Context, tenantID string) ([]CanaryKey, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, active, created_at FROM canary_keys
WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	out := []CanaryKey{}
	for rows.Next() {
		var k CanaryKey
		if err := rows.Scan(&k.ID, &k.TenantID, &k.Name, &k.Active, &k.CreatedAt); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		out = append(out, k)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.fillCanaryTrips(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *SQLStore) CreateCanaryKey(ctx context.Context, key CanaryKey) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO canary_keys (id, tenant_id, name, active, created_at)
VALUES ($1,$2,$3,$4,CURRENT_TIMESTAMP)`, key.ID, key.TenantID, key.Name, key.Active)
	return err
}

func (s *SQLStore) GetCanaryKey(ctx context.Context, tenantID, id string) (CanaryKey, error) {
	var k CanaryKey
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, active, created_at FROM canary_keys
WHERE tenant_id=$1 AND id=$2`, tenantID, id).Scan(&k.ID, &k.TenantID, &k.Name, &k.Active, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CanaryKey{}, errStoreNotFound
	}
	if err != nil {
		return CanaryKey{}, err
	}
	return k, s.fillCanaryTrips(ctx, &k)
}

func (s *SQLStore) DeactivateCanaryKey(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx,
		`UPDATE canary_keys SET active=false WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

// fillCanaryTrips sets the trip count and latest trip from this node's log.
// ORDER BY ... LIMIT 1 (not MAX) so the driver returns a native time value.
func (s *SQLStore) fillCanaryTrips(ctx context.Context, k *CanaryKey) error {
	k.CreatedAt = k.CreatedAt.UTC()
	if err := s.db.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM canary_trip_events WHERE tenant_id=$1 AND canary_id=$2`,
		k.TenantID, k.ID).Scan(&k.TripCount); err != nil {
		return err
	}
	if k.TripCount == 0 {
		return nil
	}
	var last time.Time
	if err := s.db.SQL().QueryRowContext(ctx, `
SELECT tripped_at FROM canary_trip_events WHERE tenant_id=$1 AND canary_id=$2
ORDER BY tripped_at DESC LIMIT 1`, k.TenantID, k.ID).Scan(&last); err != nil {
		return err
	}
	last = last.UTC()
	k.LastTripped = &last
	return nil
}

func (s *SQLStore) RecordCanaryTrip(ctx context.Context, event CanaryTripEvent) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO canary_trip_events
  (id, canary_id, tenant_id, actor_id, actor_ip, user_agent, tripped_at, severity, raw_request)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		event.ID, event.CanaryID, event.TenantID, event.ActorID, event.ActorIP,
		event.UserAgent, event.TrippedAt, event.Severity, event.RawRequest)
	return err
}

func (s *SQLStore) ListCanaryTrips(ctx context.Context, tenantID, canaryID string, limit int) ([]CanaryTripEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, canary_id, tenant_id, actor_id, actor_ip, user_agent, tripped_at, severity, raw_request
FROM canary_trip_events
WHERE tenant_id=$1 AND canary_id=$2
ORDER BY tripped_at DESC
LIMIT $3`, tenantID, canaryID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []CanaryTripEvent{}
	for rows.Next() {
		var e CanaryTripEvent
		if err := rows.Scan(&e.ID, &e.CanaryID, &e.TenantID, &e.ActorID, &e.ActorIP,
			&e.UserAgent, &e.TrippedAt, &e.Severity, &e.RawRequest); err != nil {
			return nil, err
		}
		e.TrippedAt = e.TrippedAt.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}
