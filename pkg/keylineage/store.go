package keylineage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const createTableSQL = `
CREATE TABLE IF NOT EXISTS key_lineage_events (
    id             TEXT PRIMARY KEY,
    key_id         TEXT NOT NULL,
    tenant_id      TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    parent_key_id  TEXT,
    related_key_ids TEXT,
    actor          TEXT NOT NULL,
    metadata       TEXT,
    timestamp      DATETIME NOT NULL,

    CONSTRAINT idx_lineage_key_id UNIQUE (id)
);

CREATE INDEX IF NOT EXISTS idx_kle_key_id ON key_lineage_events(key_id);
CREATE INDEX IF NOT EXISTS idx_kle_parent_key_id ON key_lineage_events(parent_key_id);
CREATE INDEX IF NOT EXISTS idx_kle_tenant_id ON key_lineage_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_kle_event_type ON key_lineage_events(event_type);
`

// SQLStore implements Store backed by a SQL database (PostgreSQL, SQLite, etc.).
type SQLStore struct {
	db *sql.DB
}

// NewSQLStore creates a SQLStore and ensures the schema exists.
func NewSQLStore(db *sql.DB) (*SQLStore, error) {
	if _, err := db.Exec(createTableSQL); err != nil {
		return nil, fmt.Errorf("keylineage: create table: %w", err)
	}
	return &SQLStore{db: db}, nil
}

// InsertEvent persists a lineage event.
func (s *SQLStore) InsertEvent(ctx context.Context, event LineageEvent) error {
	relatedJSON, err := json.Marshal(event.RelatedKeyIDs)
	if err != nil {
		return fmt.Errorf("keylineage: marshal related_key_ids: %w", err)
	}
	metaJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("keylineage: marshal metadata: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO key_lineage_events (id, key_id, tenant_id, event_type, parent_key_id, related_key_ids, actor, metadata, timestamp)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.KeyID, event.TenantID, string(event.EventType),
		event.ParentKeyID, string(relatedJSON), event.Actor, string(metaJSON), event.Timestamp.UTC(),
	)
	if err != nil {
		return fmt.Errorf("keylineage: insert event: %w", err)
	}
	return nil
}

// GetEventsByKeyID returns all events for a specific key.
func (s *SQLStore) GetEventsByKeyID(ctx context.Context, keyID string) ([]LineageEvent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, key_id, tenant_id, event_type, parent_key_id, related_key_ids, actor, metadata, timestamp
		 FROM key_lineage_events WHERE key_id = ? ORDER BY timestamp ASC`, keyID)
	if err != nil {
		return nil, fmt.Errorf("keylineage: query events: %w", err)
	}
	defer rows.Close()

	return scanEvents(rows)
}

// GetDescendants finds all keys derived from the given key using a recursive CTE.
// Traverses parent_key_id -> key_id relationships up to depth levels.
func (s *SQLStore) GetDescendants(ctx context.Context, keyID string, depth int) ([]LineageEvent, error) {
	query := `
		WITH RECURSIVE descendants(key_id, lvl) AS (
			SELECT key_id, 1
			FROM key_lineage_events
			WHERE parent_key_id = ?

			UNION ALL

			SELECT e.key_id, d.lvl + 1
			FROM key_lineage_events e
			INNER JOIN descendants d ON e.parent_key_id = d.key_id
			WHERE d.lvl < ?
		)
		SELECT DISTINCT e.id, e.key_id, e.tenant_id, e.event_type, e.parent_key_id,
		       e.related_key_ids, e.actor, e.metadata, e.timestamp
		FROM key_lineage_events e
		INNER JOIN descendants d ON e.key_id = d.key_id
		ORDER BY e.timestamp ASC
	`

	rows, err := s.db.QueryContext(ctx, query, keyID, depth)
	if err != nil {
		return nil, fmt.Errorf("keylineage: query descendants: %w", err)
	}
	defer rows.Close()

	return scanEvents(rows)
}

// GetAncestors traces back through parent keys using a recursive CTE.
func (s *SQLStore) GetAncestors(ctx context.Context, keyID string, depth int) ([]LineageEvent, error) {
	query := `
		WITH RECURSIVE ancestors(parent_key_id, lvl) AS (
			SELECT parent_key_id, 1
			FROM key_lineage_events
			WHERE key_id = ? AND parent_key_id IS NOT NULL AND parent_key_id != ''

			UNION ALL

			SELECT e.parent_key_id, a.lvl + 1
			FROM key_lineage_events e
			INNER JOIN ancestors a ON e.key_id = a.parent_key_id
			WHERE a.lvl < ? AND e.parent_key_id IS NOT NULL AND e.parent_key_id != ''
		)
		SELECT DISTINCT e.id, e.key_id, e.tenant_id, e.event_type, e.parent_key_id,
		       e.related_key_ids, e.actor, e.metadata, e.timestamp
		FROM key_lineage_events e
		INNER JOIN ancestors a ON e.key_id = a.parent_key_id OR e.parent_key_id = a.parent_key_id
		ORDER BY e.timestamp ASC
	`

	rows, err := s.db.QueryContext(ctx, query, keyID, depth)
	if err != nil {
		return nil, fmt.Errorf("keylineage: query ancestors: %w", err)
	}
	defer rows.Close()

	return scanEvents(rows)
}

// GetRelatedServices extracts unique service names from event metadata for the given key IDs.
func (s *SQLStore) GetRelatedServices(ctx context.Context, keyIDs []string) ([]string, error) {
	if len(keyIDs) == 0 {
		return nil, nil
	}

	placeholders := make([]string, len(keyIDs))
	args := make([]interface{}, len(keyIDs))
	for i, id := range keyIDs {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf(
		`SELECT DISTINCT metadata FROM key_lineage_events WHERE key_id IN (%s)`,
		strings.Join(placeholders, ","),
	)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("keylineage: query services: %w", err)
	}
	defer rows.Close()

	serviceSet := make(map[string]bool)
	for rows.Next() {
		var metaStr string
		if err := rows.Scan(&metaStr); err != nil {
			continue
		}
		var meta map[string]string
		if err := json.Unmarshal([]byte(metaStr), &meta); err != nil {
			continue
		}
		if svc, ok := meta["service"]; ok && svc != "" {
			serviceSet[svc] = true
		}
	}

	services := make([]string, 0, len(serviceSet))
	for svc := range serviceSet {
		services = append(services, svc)
	}
	return services, rows.Err()
}

// scanEvents reads rows into LineageEvent slices.
func scanEvents(rows *sql.Rows) ([]LineageEvent, error) {
	var events []LineageEvent
	for rows.Next() {
		var evt LineageEvent
		var eventType, relatedJSON, metaJSON, parentKeyID string
		var ts time.Time

		if err := rows.Scan(
			&evt.ID, &evt.KeyID, &evt.TenantID, &eventType,
			&parentKeyID, &relatedJSON, &evt.Actor, &metaJSON, &ts,
		); err != nil {
			return nil, fmt.Errorf("keylineage: scan row: %w", err)
		}

		evt.EventType = EventType(eventType)
		evt.ParentKeyID = parentKeyID
		evt.Timestamp = ts

		if relatedJSON != "" {
			_ = json.Unmarshal([]byte(relatedJSON), &evt.RelatedKeyIDs)
		}
		if metaJSON != "" {
			_ = json.Unmarshal([]byte(metaJSON), &evt.Metadata)
		}

		events = append(events, evt)
	}
	return events, rows.Err()
}
