package main

import (
	"context"
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
