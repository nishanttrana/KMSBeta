package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// ---- Canary Keys ----

func (s *SQLStore) ListCanaryKeys(ctx context.Context, tenantID string) ([]CanaryKey, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, algorithm, purpose, trip_count, last_tripped, created_at, active, notify_email, metadata
FROM canary_keys
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []CanaryKey
	for rows.Next() {
		k, err := scanCanaryKeyRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if out == nil {
		out = []CanaryKey{}
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateCanaryKey(ctx context.Context, key CanaryKey) error {
	if key.Metadata == nil {
		key.Metadata = map[string]string{}
	}
	metaJSON, err := json.Marshal(key.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.SQL().ExecContext(ctx, `
INSERT INTO canary_keys
  (id, tenant_id, name, algorithm, purpose, trip_count, active, notify_email, metadata, created_at)
VALUES ($1,$2,$3,$4,$5,0,$6,$7,$8,CURRENT_TIMESTAMP)
`, key.ID, key.TenantID, key.Name, key.Algorithm, key.Purpose,
		key.Active, nullable(key.NotifyEmail), string(metaJSON))
	return err
}

func (s *SQLStore) GetCanaryKey(ctx context.Context, tenantID, id string) (CanaryKey, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, algorithm, purpose, trip_count, last_tripped, created_at, active, notify_email, metadata
FROM canary_keys
WHERE tenant_id=$1 AND id=$2
`, tenantID, id)
	k, err := scanCanaryKeySingleRow(row)
	if err == sql.ErrNoRows {
		return CanaryKey{}, errStoreNotFound
	}
	return k, err
}

func (s *SQLStore) DeleteCanaryKey(ctx context.Context, tenantID, id string) error {
	result, err := s.db.SQL().ExecContext(ctx,
		`UPDATE canary_keys SET active=false WHERE tenant_id=$1 AND id=$2`,
		tenantID, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errStoreNotFound
	}
	return nil
}

// ---- Canary Trip Events ----

func (s *SQLStore) RecordCanaryTrip(ctx context.Context, event CanaryTripEvent) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO canary_trip_events
  (id, canary_id, tenant_id, actor_id, actor_ip, user_agent, tripped_at, severity, raw_request)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
`, event.ID, event.CanaryID, event.TenantID, event.ActorID, event.ActorIP,
		event.UserAgent, event.TrippedAt, event.Severity, event.RawRequest)
	if err != nil {
		return err
	}
	// Update the canary key trip_count and last_tripped.
	_, err = s.db.SQL().ExecContext(ctx, `
UPDATE canary_keys
SET trip_count = trip_count + 1, last_tripped = $3
WHERE tenant_id = $1 AND id = $2
`, event.TenantID, event.CanaryID, event.TrippedAt)
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
LIMIT $3
`, tenantID, canaryID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []CanaryTripEvent
	for rows.Next() {
		var e CanaryTripEvent
		if err := rows.Scan(
			&e.ID, &e.CanaryID, &e.TenantID, &e.ActorID, &e.ActorIP,
			&e.UserAgent, &e.TrippedAt, &e.Severity, &e.RawRequest,
		); err != nil {
			return nil, err
		}
		e.TrippedAt = e.TrippedAt.UTC()
		out = append(out, e)
	}
	if out == nil {
		out = []CanaryTripEvent{}
	}
	return out, rows.Err()
}

func (s *SQLStore) GetCanarySummary(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	// Total canaries and active count.
	var totalCanaries, activeCanaries int
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT
  COUNT(*) AS total,
  SUM(CASE WHEN active THEN 1 ELSE 0 END) AS active_count
FROM canary_keys
WHERE tenant_id=$1
`, tenantID)
	if err := row.Scan(&totalCanaries, &activeCanaries); err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Total trips and trips in last 24h.
	var totalTrips, trips24h int
	row = s.db.SQL().QueryRowContext(ctx, `
SELECT
  COUNT(*) AS total_trips,
  SUM(CASE WHEN tripped_at >= NOW() - INTERVAL '24 hours' THEN 1 ELSE 0 END) AS trips_24h
FROM canary_trip_events
WHERE tenant_id=$1
`, tenantID)
	if err := row.Scan(&totalTrips, &trips24h); err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Most recent trip.
	var mostRecentTrip *time.Time
	var canaryID, actorID sql.NullString
	var trippedAt sql.NullTime
	row = s.db.SQL().QueryRowContext(ctx, `
SELECT canary_id, actor_id, tripped_at
FROM canary_trip_events
WHERE tenant_id=$1
ORDER BY tripped_at DESC
LIMIT 1
`, tenantID)
	_ = row.Scan(&canaryID, &actorID, &trippedAt)
	if trippedAt.Valid {
		t := trippedAt.Time.UTC()
		mostRecentTrip = &t
	}

	out := map[string]interface{}{
		"total_canaries":    totalCanaries,
		"active_canaries":   activeCanaries,
		"total_trips":       totalTrips,
		"trips_24h":         trips24h,
		"most_recent_trip":  mostRecentTrip,
		"most_recent_canary_id": canaryID.String,
		"most_recent_actor_id":  actorID.String,
	}
	return out, nil
}

// ---- scan helpers ----

func scanCanaryKeyRow(rows interface {
	Scan(dest ...any) error
}) (CanaryKey, error) {
	var k CanaryKey
	var lastTripped sql.NullTime
	var notifyEmail sql.NullString
	var rawMeta string
	if err := rows.Scan(
		&k.ID, &k.TenantID, &k.Name, &k.Algorithm, &k.Purpose,
		&k.TripCount, &lastTripped, &k.CreatedAt, &k.Active,
		&notifyEmail, &rawMeta,
	); err != nil {
		return CanaryKey{}, err
	}
	if lastTripped.Valid {
		t := lastTripped.Time.UTC()
		k.LastTripped = &t
	}
	k.NotifyEmail = notifyEmail.String
	k.CreatedAt = k.CreatedAt.UTC()
	if rawMeta != "" && rawMeta != "null" {
		_ = json.Unmarshal([]byte(rawMeta), &k.Metadata)
	}
	if k.Metadata == nil {
		k.Metadata = map[string]string{}
	}
	return k, nil
}

func scanCanaryKeySingleRow(row *sql.Row) (CanaryKey, error) {
	var k CanaryKey
	var lastTripped sql.NullTime
	var notifyEmail sql.NullString
	var rawMeta string
	if err := row.Scan(
		&k.ID, &k.TenantID, &k.Name, &k.Algorithm, &k.Purpose,
		&k.TripCount, &lastTripped, &k.CreatedAt, &k.Active,
		&notifyEmail, &rawMeta,
	); err != nil {
		return CanaryKey{}, err
	}
	if lastTripped.Valid {
		t := lastTripped.Time.UTC()
		k.LastTripped = &t
	}
	k.NotifyEmail = notifyEmail.String
	k.CreatedAt = k.CreatedAt.UTC()
	if rawMeta != "" && rawMeta != "null" {
		_ = json.Unmarshal([]byte(rawMeta), &k.Metadata)
	}
	if k.Metadata == nil {
		k.Metadata = map[string]string{}
	}
	return k, nil
}
