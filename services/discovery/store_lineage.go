package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// InsertLineageEvent persists a LineageEvent to the lineage_events table and
// returns the stored record (with ID and CreatedAt populated).
func (s *SQLStore) InsertLineageEvent(ctx context.Context, e LineageEvent) (LineageEvent, error) {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO lineage_events (
	id, tenant_id, event_type,
	source_id, source_type, source_label,
	dest_id, dest_type, dest_label,
	actor_id, actor_type, service_name,
	metadata, occurred_at, created_at
) VALUES (
	$1,$2,$3,
	$4,$5,$6,
	$7,$8,$9,
	$10,$11,$12,
	$13,$14,$15
)`,
		e.ID, e.TenantID, string(e.EventType),
		e.SourceID, e.SourceType, e.SourceLabel,
		e.DestID, e.DestType, e.DestLabel,
		e.ActorID, e.ActorType, e.ServiceName,
		mustJSON(e.Metadata, "{}"), e.OccurredAt.UTC(), e.CreatedAt.UTC(),
	)
	if err != nil {
		return LineageEvent{}, err
	}
	return e, nil
}

// GetLineageByKey returns all events where source_id or dest_id equals keyID
// for the given tenant, ordered by occurred_at DESC, up to limit rows.
func (s *SQLStore) GetLineageByKey(ctx context.Context, tenantID, keyID string, limit int) ([]LineageEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, event_type,
       source_id, source_type, source_label,
       dest_id, dest_type, dest_label,
       actor_id, actor_type, service_name,
       metadata, occurred_at, created_at
FROM lineage_events
WHERE tenant_id = $1
  AND (source_id = $2 OR dest_id = $2)
ORDER BY occurred_at DESC
LIMIT $3
`, strings.TrimSpace(tenantID), strings.TrimSpace(keyID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanLineageEvents(rows)
}

// GetLineageGraph returns all events for a tenant since the given time, up to
// limit rows, ordered by occurred_at DESC.  The caller assembles the graph.
func (s *SQLStore) GetLineageGraph(ctx context.Context, tenantID string, since time.Time, limit int) ([]LineageEvent, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, event_type,
       source_id, source_type, source_label,
       dest_id, dest_type, dest_label,
       actor_id, actor_type, service_name,
       metadata, occurred_at, created_at
FROM lineage_events
WHERE tenant_id = $1
  AND occurred_at >= $2
ORDER BY occurred_at DESC
LIMIT $3
`, strings.TrimSpace(tenantID), since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanLineageEvents(rows)
}

// GetLineageEventsByType returns events for a key filtered by specific event types.
func (s *SQLStore) GetLineageEventsByType(ctx context.Context, tenantID, keyID string, eventTypes []string, limit int) ([]LineageEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	if len(eventTypes) == 0 {
		return []LineageEvent{}, nil
	}

	// Build parameterized IN clause
	placeholders := make([]string, len(eventTypes))
	args := make([]interface{}, 0, len(eventTypes)+3)
	args = append(args, strings.TrimSpace(tenantID), strings.TrimSpace(keyID))
	for i, et := range eventTypes {
		placeholders[i] = fmt.Sprintf("$%d", i+3)
		args = append(args, et)
	}
	args = append(args, limit)
	limitPlaceholder := fmt.Sprintf("$%d", len(args))

	query := fmt.Sprintf(`
SELECT id, tenant_id, event_type,
       source_id, source_type, source_label,
       dest_id, dest_type, dest_label,
       actor_id, actor_type, service_name,
       metadata, occurred_at, created_at
FROM lineage_events
WHERE tenant_id = $1
  AND (source_id = $2 OR dest_id = $2)
  AND event_type IN (%s)
ORDER BY occurred_at DESC
LIMIT %s
`, strings.Join(placeholders, ","), limitPlaceholder)

	rows, err := s.db.SQL().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanLineageEvents(rows)
}

// GetAccessEvents returns wrap, unwrap, encrypt, and decrypt events for a key since a given time.
func (s *SQLStore) GetAccessEvents(ctx context.Context, tenantID, keyID string, since time.Time) ([]LineageEvent, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, event_type,
       source_id, source_type, source_label,
       dest_id, dest_type, dest_label,
       actor_id, actor_type, service_name,
       metadata, occurred_at, created_at
FROM lineage_events
WHERE tenant_id = $1
  AND (source_id = $2 OR dest_id = $2)
  AND event_type IN ('wrap', 'unwrap', 'encrypt', 'decrypt')
  AND occurred_at >= $3
ORDER BY occurred_at DESC
LIMIT 5000
`, strings.TrimSpace(tenantID), strings.TrimSpace(keyID), since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanLineageEvents(rows)
}

// GetAllKeyProvenanceData returns all lineage events for a tenant, up to limit,
// ordered by occurred_at DESC. Used for heatmap and bulk provenance analysis.
func (s *SQLStore) GetAllKeyProvenanceData(ctx context.Context, tenantID string, limit int) ([]LineageEvent, error) {
	if limit <= 0 || limit > 10000 {
		limit = 5000
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, event_type,
       source_id, source_type, source_label,
       dest_id, dest_type, dest_label,
       actor_id, actor_type, service_name,
       metadata, occurred_at, created_at
FROM lineage_events
WHERE tenant_id = $1
ORDER BY occurred_at DESC
LIMIT $2
`, strings.TrimSpace(tenantID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanLineageEvents(rows)
}

// CountEventsByHour returns an hourly distribution of events for a key since a given time.
func (s *SQLStore) CountEventsByHour(ctx context.Context, tenantID, keyID string, since time.Time) (map[int]int, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT EXTRACT(HOUR FROM occurred_at)::int AS hour, COUNT(*) AS cnt
FROM lineage_events
WHERE tenant_id = $1
  AND (source_id = $2 OR dest_id = $2)
  AND occurred_at >= $3
GROUP BY hour
ORDER BY hour
`, strings.TrimSpace(tenantID), strings.TrimSpace(keyID), since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	result := make(map[int]int)
	for rows.Next() {
		var hour, cnt int
		if err := rows.Scan(&hour, &cnt); err != nil {
			return nil, err
		}
		result[hour] = cnt
	}
	return result, rows.Err()
}

// GetDistinctActors returns unique actors who accessed a key since a given time.
func (s *SQLStore) GetDistinctActors(ctx context.Context, tenantID, keyID string, since time.Time) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT DISTINCT actor_id
FROM lineage_events
WHERE tenant_id = $1
  AND (source_id = $2 OR dest_id = $2)
  AND occurred_at >= $3
ORDER BY actor_id
`, strings.TrimSpace(tenantID), strings.TrimSpace(keyID), since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var actors []string
	for rows.Next() {
		var actor string
		if err := rows.Scan(&actor); err != nil {
			return nil, err
		}
		actors = append(actors, actor)
	}
	return actors, rows.Err()
}

// GetNewActors returns actors who first accessed a key after firstSeenSince
// and have accessed it since accessedSince.
func (s *SQLStore) GetNewActors(ctx context.Context, tenantID, keyID string, firstSeenSince, accessedSince time.Time) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT actor_id
FROM lineage_events
WHERE tenant_id = $1
  AND (source_id = $2 OR dest_id = $2)
  AND occurred_at >= $4
GROUP BY actor_id
HAVING MIN(occurred_at) >= $3
ORDER BY actor_id
`, strings.TrimSpace(tenantID), strings.TrimSpace(keyID), firstSeenSince.UTC(), accessedSince.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var actors []string
	for rows.Next() {
		var actor string
		if err := rows.Scan(&actor); err != nil {
			return nil, err
		}
		actors = append(actors, actor)
	}
	return actors, rows.Err()
}

// scanLineageEvents reads all rows from the result set into a slice.
func scanLineageEvents(rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Err() error
}) ([]LineageEvent, error) {
	out := make([]LineageEvent, 0)
	for rows.Next() {
		e, err := scanLineageEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// scanLineageEvent scans a single row into a LineageEvent.
func scanLineageEvent(scanner interface {
	Scan(dest ...interface{}) error
}) (LineageEvent, error) {
	var (
		e           LineageEvent
		evtType     string
		metadataRaw string
		occurredRaw interface{}
		createdRaw  interface{}
	)
	if err := scanner.Scan(
		&e.ID, &e.TenantID, &evtType,
		&e.SourceID, &e.SourceType, &e.SourceLabel,
		&e.DestID, &e.DestType, &e.DestLabel,
		&e.ActorID, &e.ActorType, &e.ServiceName,
		&metadataRaw, &occurredRaw, &createdRaw,
	); err != nil {
		return LineageEvent{}, err
	}
	e.EventType = LineageEventType(evtType)
	e.Metadata = parseJSONObject(metadataRaw)
	e.OccurredAt = parseTimeValue(occurredRaw)
	e.CreatedAt = parseTimeValue(createdRaw)
	return e, nil
}
