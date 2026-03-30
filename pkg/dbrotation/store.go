package dbrotation

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"vecta-kms/pkg/db"
)

const dbRotationMigration = `
CREATE TABLE IF NOT EXISTS db_rotation_targets (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	db_type TEXT NOT NULL,
	connection_string TEXT NOT NULL,
	username TEXT NOT NULL,
	current_password TEXT NOT NULL,
	previous_password TEXT NOT NULL DEFAULT '',
	rotation_interval_ns BIGINT NOT NULL,
	grace_period_ns BIGINT NOT NULL DEFAULT 300000000000,
	last_rotated TIMESTAMPTZ,
	next_rotation TIMESTAMPTZ NOT NULL,
	status TEXT NOT NULL DEFAULT 'active',
	failure_count INT NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_db_rotation_tenant ON db_rotation_targets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_db_rotation_next ON db_rotation_targets(next_rotation);

CREATE TABLE IF NOT EXISTS db_rotation_events (
	id BIGSERIAL PRIMARY KEY,
	target_id TEXT NOT NULL,
	tenant_id TEXT NOT NULL,
	db_type TEXT NOT NULL,
	username TEXT NOT NULL,
	success BOOLEAN NOT NULL,
	error TEXT NOT NULL DEFAULT '',
	rotated_at TIMESTAMPTZ NOT NULL,
	duration_ns BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_db_rotation_events_target ON db_rotation_events(target_id, rotated_at DESC);
`

// Store persists database rotation targets and events in SQL.
type Store struct {
	database *db.DB
}

// NewStore creates a new database rotation store.
func NewStore(database *db.DB) *Store {
	return &Store{database: database}
}

// Migrate creates the required tables and indexes.
func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.database.SQL().ExecContext(ctx, dbRotationMigration)
	if err != nil {
		return fmt.Errorf("dbrotation: migrate: %w", err)
	}
	return nil
}

// SaveTarget inserts or updates a rotation target (upsert).
func (s *Store) SaveTarget(ctx context.Context, target *RotationTarget) error {
	const query = `
		INSERT INTO db_rotation_targets
			(id, tenant_id, db_type, connection_string, username, current_password,
			 previous_password, rotation_interval_ns, grace_period_ns, last_rotated,
			 next_rotation, status, failure_count, last_error)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (id) DO UPDATE SET
			tenant_id = EXCLUDED.tenant_id,
			db_type = EXCLUDED.db_type,
			connection_string = EXCLUDED.connection_string,
			username = EXCLUDED.username,
			current_password = EXCLUDED.current_password,
			previous_password = EXCLUDED.previous_password,
			rotation_interval_ns = EXCLUDED.rotation_interval_ns,
			grace_period_ns = EXCLUDED.grace_period_ns,
			last_rotated = EXCLUDED.last_rotated,
			next_rotation = EXCLUDED.next_rotation,
			status = EXCLUDED.status,
			failure_count = EXCLUDED.failure_count,
			last_error = EXCLUDED.last_error
	`

	var lastRotated *time.Time
	if !target.LastRotated.IsZero() {
		lastRotated = &target.LastRotated
	}

	_, err := s.database.SQL().ExecContext(ctx, query,
		target.ID, target.TenantID, string(target.DBType), target.ConnectionString,
		target.Username, target.CurrentPassword, target.PreviousPassword,
		target.RotationInterval.Nanoseconds(), target.GracePeriod.Nanoseconds(),
		lastRotated, target.NextRotation, string(target.Status),
		target.FailureCount, target.LastError,
	)
	if err != nil {
		return fmt.Errorf("dbrotation: save target: %w", err)
	}
	return nil
}

// GetTarget retrieves a rotation target by ID.
func (s *Store) GetTarget(ctx context.Context, targetID string) (*RotationTarget, error) {
	const query = `
		SELECT id, tenant_id, db_type, connection_string, username, current_password,
			   previous_password, rotation_interval_ns, grace_period_ns, last_rotated,
			   next_rotation, status, failure_count, last_error
		FROM db_rotation_targets WHERE id = $1
	`
	return s.scanTarget(s.database.SQL().QueryRowContext(ctx, query, targetID))
}

// ListTargets returns all targets for a tenant.
func (s *Store) ListTargets(ctx context.Context, tenantID string) ([]*RotationTarget, error) {
	const query = `
		SELECT id, tenant_id, db_type, connection_string, username, current_password,
			   previous_password, rotation_interval_ns, grace_period_ns, last_rotated,
			   next_rotation, status, failure_count, last_error
		FROM db_rotation_targets WHERE tenant_id = $1 ORDER BY next_rotation
	`
	rows, err := s.database.SQL().QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("dbrotation: list targets: %w", err)
	}
	defer rows.Close()

	return s.scanTargets(rows)
}

// ListDueTargets returns all active targets whose next_rotation is at or before the given time.
func (s *Store) ListDueTargets(ctx context.Context, now time.Time) ([]*RotationTarget, error) {
	const query = `
		SELECT id, tenant_id, db_type, connection_string, username, current_password,
			   previous_password, rotation_interval_ns, grace_period_ns, last_rotated,
			   next_rotation, status, failure_count, last_error
		FROM db_rotation_targets
		WHERE next_rotation <= $1 AND status = 'active'
		ORDER BY next_rotation
	`
	rows, err := s.database.SQL().QueryContext(ctx, query, now)
	if err != nil {
		return nil, fmt.Errorf("dbrotation: list due targets: %w", err)
	}
	defer rows.Close()

	return s.scanTargets(rows)
}

// UpdateTargetStatus updates only the status and last_error fields.
func (s *Store) UpdateTargetStatus(ctx context.Context, targetID string, status RotationStatus, lastError string) error {
	const query = `
		UPDATE db_rotation_targets SET status = $1, last_error = $2 WHERE id = $3
	`
	_, err := s.database.SQL().ExecContext(ctx, query, string(status), lastError, targetID)
	if err != nil {
		return fmt.Errorf("dbrotation: update status: %w", err)
	}
	return nil
}

// DeleteTarget removes a rotation target.
func (s *Store) DeleteTarget(ctx context.Context, targetID string) error {
	const query = `DELETE FROM db_rotation_targets WHERE id = $1`
	result, err := s.database.SQL().ExecContext(ctx, query, targetID)
	if err != nil {
		return fmt.Errorf("dbrotation: delete target: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("dbrotation: target %q not found", targetID)
	}
	return nil
}

// SaveEvent records a rotation event.
func (s *Store) SaveEvent(ctx context.Context, event *RotationEvent) error {
	const query = `
		INSERT INTO db_rotation_events
			(target_id, tenant_id, db_type, username, success, error, rotated_at, duration_ns)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := s.database.SQL().ExecContext(ctx, query,
		event.TargetID, event.TenantID, string(event.DBType), event.Username,
		event.Success, event.Error, event.RotatedAt, event.Duration.Nanoseconds(),
	)
	if err != nil {
		return fmt.Errorf("dbrotation: save event: %w", err)
	}
	return nil
}

// ListEvents returns recent events for a target.
func (s *Store) ListEvents(ctx context.Context, targetID string, limit int) ([]*RotationEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	const query = `
		SELECT target_id, tenant_id, db_type, username, success, error, rotated_at, duration_ns
		FROM db_rotation_events WHERE target_id = $1 ORDER BY rotated_at DESC LIMIT $2
	`
	rows, err := s.database.SQL().QueryContext(ctx, query, targetID, limit)
	if err != nil {
		return nil, fmt.Errorf("dbrotation: list events: %w", err)
	}
	defer rows.Close()

	var events []*RotationEvent
	for rows.Next() {
		e := &RotationEvent{}
		var dbType string
		var durationNS int64
		if err := rows.Scan(
			&e.TargetID, &e.TenantID, &dbType, &e.Username,
			&e.Success, &e.Error, &e.RotatedAt, &durationNS,
		); err != nil {
			return nil, fmt.Errorf("dbrotation: scan event: %w", err)
		}
		e.DBType = DBType(dbType)
		e.Duration = time.Duration(durationNS)
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *Store) scanTarget(row *sql.Row) (*RotationTarget, error) {
	t := &RotationTarget{}
	var dbType, status string
	var intervalNS, graceNS int64
	var lastRotated sql.NullTime

	if err := row.Scan(
		&t.ID, &t.TenantID, &dbType, &t.ConnectionString,
		&t.Username, &t.CurrentPassword, &t.PreviousPassword,
		&intervalNS, &graceNS, &lastRotated,
		&t.NextRotation, &status, &t.FailureCount, &t.LastError,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("dbrotation: target not found")
		}
		return nil, fmt.Errorf("dbrotation: scan target: %w", err)
	}

	t.DBType = DBType(dbType)
	t.Status = RotationStatus(status)
	t.RotationInterval = time.Duration(intervalNS)
	t.GracePeriod = time.Duration(graceNS)
	if lastRotated.Valid {
		t.LastRotated = lastRotated.Time
	}
	return t, nil
}

func (s *Store) scanTargets(rows *sql.Rows) ([]*RotationTarget, error) {
	var targets []*RotationTarget
	for rows.Next() {
		t := &RotationTarget{}
		var dbType, status string
		var intervalNS, graceNS int64
		var lastRotated sql.NullTime

		if err := rows.Scan(
			&t.ID, &t.TenantID, &dbType, &t.ConnectionString,
			&t.Username, &t.CurrentPassword, &t.PreviousPassword,
			&intervalNS, &graceNS, &lastRotated,
			&t.NextRotation, &status, &t.FailureCount, &t.LastError,
		); err != nil {
			return nil, fmt.Errorf("dbrotation: scan target: %w", err)
		}

		t.DBType = DBType(dbType)
		t.Status = RotationStatus(status)
		t.RotationInterval = time.Duration(intervalNS)
		t.GracePeriod = time.Duration(graceNS)
		if lastRotated.Valid {
			t.LastRotated = lastRotated.Time
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}
