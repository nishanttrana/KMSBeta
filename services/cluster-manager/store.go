package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) ListProfiles(ctx context.Context, tenantID string) ([]ClusterProfile, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, description, components_json, is_default, created_at, updated_at
FROM cluster_profiles
WHERE tenant_id = $1
ORDER BY is_default DESC, name ASC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ClusterProfile, 0)
	for rows.Next() {
		item, scanErr := scanProfile(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetProfile(ctx context.Context, tenantID string, profileID string) (ClusterProfile, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, description, components_json, is_default, created_at, updated_at
FROM cluster_profiles
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(profileID))
	item, err := scanProfile(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ClusterProfile{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) UpsertProfile(ctx context.Context, item ClusterProfile) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cluster_profiles (
	id, tenant_id, name, description, components_json, is_default, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, id) DO UPDATE SET
	name = EXCLUDED.name,
	description = EXCLUDED.description,
	components_json = EXCLUDED.components_json,
	is_default = EXCLUDED.is_default,
	updated_at = CURRENT_TIMESTAMP
`, strings.TrimSpace(item.ID), strings.TrimSpace(item.TenantID), strings.TrimSpace(item.Name), strings.TrimSpace(item.Description), mustJSON(item.Components, "[]"), item.IsDefault)
	return err
}

func (s *SQLStore) SetDefaultProfile(ctx context.Context, tenantID string, profileID string) error {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, `
UPDATE cluster_profiles
SET is_default = FALSE, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1
`, strings.TrimSpace(tenantID)); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
UPDATE cluster_profiles
SET is_default = TRUE, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(profileID))
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return errNotFound
	}
	return tx.Commit()
}

func (s *SQLStore) DeleteProfile(ctx context.Context, tenantID string, profileID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM cluster_profiles
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(profileID))
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) ListNodes(ctx context.Context, tenantID string) ([]ClusterNode, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, role, endpoint, status, cpu_percent, ram_gb, enabled_components_json,
       profile_id, join_state, cert_fingerprint, last_heartbeat_at, last_sync_at, created_at, updated_at
FROM cluster_nodes
WHERE tenant_id = $1
ORDER BY CASE WHEN role='leader' THEN 0 ELSE 1 END, name ASC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ClusterNode, 0)
	for rows.Next() {
		item, scanErr := scanNode(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetNode(ctx context.Context, tenantID string, nodeID string) (ClusterNode, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, role, endpoint, status, cpu_percent, ram_gb, enabled_components_json,
       profile_id, join_state, cert_fingerprint, last_heartbeat_at, last_sync_at, created_at, updated_at
FROM cluster_nodes
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(nodeID))
	item, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ClusterNode{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) UpsertNode(ctx context.Context, item ClusterNode) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cluster_nodes (
	id, tenant_id, name, role, endpoint, status, cpu_percent, ram_gb, enabled_components_json,
	profile_id, join_state, cert_fingerprint, last_heartbeat_at, last_sync_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9,
	$10, $11, $12, $13, $14, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, id) DO UPDATE SET
	name = EXCLUDED.name,
	role = EXCLUDED.role,
	endpoint = EXCLUDED.endpoint,
	status = EXCLUDED.status,
	cpu_percent = EXCLUDED.cpu_percent,
	ram_gb = EXCLUDED.ram_gb,
	enabled_components_json = EXCLUDED.enabled_components_json,
	profile_id = EXCLUDED.profile_id,
	join_state = EXCLUDED.join_state,
	cert_fingerprint = EXCLUDED.cert_fingerprint,
	last_heartbeat_at = EXCLUDED.last_heartbeat_at,
	last_sync_at = EXCLUDED.last_sync_at,
	updated_at = CURRENT_TIMESTAMP
`, strings.TrimSpace(item.ID), strings.TrimSpace(item.TenantID), strings.TrimSpace(item.Name), normalizeRole(item.Role), strings.TrimSpace(item.Endpoint), normalizeNodeStatus(item.Status), item.CPUPercent, item.RAMGB, mustJSON(item.EnabledComponents, "[]"), strings.TrimSpace(item.ProfileID), strings.TrimSpace(item.JoinState), strings.TrimSpace(item.CertFingerprint), nullableTime(item.LastHeartbeatAt), nullableTime(item.LastSyncAt))
	return err
}

func (s *SQLStore) DeleteNode(ctx context.Context, tenantID string, nodeID string) error {
	tenantID = strings.TrimSpace(tenantID)
	nodeID = strings.TrimSpace(nodeID)
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, `
DELETE FROM cluster_sync_checkpoints
WHERE tenant_id = $1 AND node_id = $2
`, tenantID, nodeID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM cluster_join_tokens
WHERE tenant_id = $1 AND target_node_id = $2
`, tenantID, nodeID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM cluster_sync_nonces
WHERE tenant_id = $1 AND source_node_id = $2
`, tenantID, nodeID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
DELETE FROM cluster_nodes
WHERE tenant_id = $1 AND id = $2
`, tenantID, nodeID)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return errNotFound
	}
	return tx.Commit()
}

func (s *SQLStore) CreateJoinToken(ctx context.Context, token ClusterJoinToken) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cluster_join_tokens (
	id, tenant_id, target_node_id, target_node_name, endpoint, profile_id,
	secret_hash, nonce, requested_by, expires_at, consumed_at, created_at
) VALUES (
	$1, $2, $3, $4, $5, $6,
	$7, $8, $9, $10, $11, CURRENT_TIMESTAMP
)
`, strings.TrimSpace(token.ID), strings.TrimSpace(token.TenantID), strings.TrimSpace(token.TargetNodeID), strings.TrimSpace(token.TargetNode), strings.TrimSpace(token.Endpoint), strings.TrimSpace(token.ProfileID), strings.TrimSpace(token.SecretHash), strings.TrimSpace(token.Nonce), strings.TrimSpace(token.RequestedBy), nullableTime(token.ExpiresAt), nullableTime(token.ConsumedAt))
	return err
}

func (s *SQLStore) GetJoinToken(ctx context.Context, tenantID string, tokenID string) (ClusterJoinToken, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, target_node_id, target_node_name, endpoint, profile_id,
       secret_hash, nonce, requested_by, expires_at, consumed_at, created_at
FROM cluster_join_tokens
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(tokenID))
	item, err := scanJoinToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ClusterJoinToken{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) MarkJoinTokenConsumed(ctx context.Context, tenantID string, tokenID string, consumedAt time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE cluster_join_tokens
SET consumed_at = $3
WHERE tenant_id = $1 AND id = $2 AND consumed_at IS NULL
`, strings.TrimSpace(tenantID), strings.TrimSpace(tokenID), nullableTime(consumedAt))
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) PurgeExpiredJoinTokens(ctx context.Context, now time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM cluster_join_tokens
WHERE expires_at < $1 OR (consumed_at IS NOT NULL AND consumed_at < ($1 - INTERVAL '1 day'))
`, nullableTime(now))
	return err
}

func (s *SQLStore) CreateSyncEvent(ctx context.Context, event ClusterSyncEvent) (ClusterSyncEvent, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO cluster_sync_events (
	tenant_id, profile_id, component, entity_type, entity_id, operation, payload_json, source_node_id, created_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP
)
RETURNING id, created_at
`, strings.TrimSpace(event.TenantID), strings.TrimSpace(event.ProfileID), normalizeComponentName(event.Component), strings.TrimSpace(event.EntityType), strings.TrimSpace(event.EntityID), strings.TrimSpace(event.Operation), mustJSON(event.Payload, "{}"), strings.TrimSpace(event.SourceNodeID))
	var createdRaw interface{}
	if err := row.Scan(&event.ID, &createdRaw); err != nil {
		return ClusterSyncEvent{}, err
	}
	event.CreatedAt = parseTimeValue(createdRaw)
	return event, nil
}

func (s *SQLStore) ListSyncEvents(ctx context.Context, tenantID string, profileID string, afterID int64, limit int, components []string) ([]ClusterSyncEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	componentSet := normalizeComponents(components)
	if len(componentSet) == 0 {
		rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, profile_id, component, entity_type, entity_id, operation, payload_json, source_node_id, created_at
FROM cluster_sync_events
WHERE tenant_id = $1 AND profile_id = $2 AND id > $3
ORDER BY id ASC
LIMIT $4
`, strings.TrimSpace(tenantID), strings.TrimSpace(profileID), afterID, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close() //nolint:errcheck
		out := make([]ClusterSyncEvent, 0)
		for rows.Next() {
			item, scanErr := scanSyncEvent(rows)
			if scanErr != nil {
				return nil, scanErr
			}
			out = append(out, item)
		}
		return out, rows.Err()
	}

	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, profile_id, component, entity_type, entity_id, operation, payload_json, source_node_id, created_at
FROM cluster_sync_events
WHERE tenant_id = $1 AND profile_id = $2 AND id > $3 AND component = ANY($4::text[])
ORDER BY id ASC
LIMIT $5
`, strings.TrimSpace(tenantID), strings.TrimSpace(profileID), afterID, pqStringArray(componentSet), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ClusterSyncEvent, 0)
	for rows.Next() {
		item, scanErr := scanSyncEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertSyncCheckpoint(ctx context.Context, checkpoint ClusterSyncCheckpoint) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cluster_sync_checkpoints (
	tenant_id, node_id, profile_id, last_event_id, updated_at
) VALUES (
	$1, $2, $3, $4, CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, node_id, profile_id) DO UPDATE SET
	last_event_id = EXCLUDED.last_event_id,
	updated_at = CURRENT_TIMESTAMP
`, strings.TrimSpace(checkpoint.TenantID), strings.TrimSpace(checkpoint.NodeID), strings.TrimSpace(checkpoint.ProfileID), checkpoint.LastEventID)
	return err
}

func (s *SQLStore) GetSyncCheckpoint(ctx context.Context, tenantID string, nodeID string, profileID string) (ClusterSyncCheckpoint, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, node_id, profile_id, last_event_id, updated_at
FROM cluster_sync_checkpoints
WHERE tenant_id = $1 AND node_id = $2 AND profile_id = $3
`, strings.TrimSpace(tenantID), strings.TrimSpace(nodeID), strings.TrimSpace(profileID))
	var item ClusterSyncCheckpoint
	var updatedRaw interface{}
	if err := row.Scan(&item.TenantID, &item.NodeID, &item.ProfileID, &item.LastEventID, &updatedRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ClusterSyncCheckpoint{}, errNotFound
		}
		return ClusterSyncCheckpoint{}, err
	}
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func (s *SQLStore) ConsumeSyncNonce(ctx context.Context, tenantID string, sourceNodeID string, nonce string, expiresAt time.Time) (bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	sourceNodeID = strings.TrimSpace(sourceNodeID)
	nonce = strings.TrimSpace(nonce)
	if tenantID == "" || nonce == "" {
		return false, nil
	}
	_, _ = s.db.SQL().ExecContext(ctx, `
DELETE FROM cluster_sync_nonces
WHERE expires_at < CURRENT_TIMESTAMP
`)
	res, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cluster_sync_nonces (
	tenant_id, source_node_id, nonce, seen_at, expires_at
) VALUES (
	$1, $2, $3, CURRENT_TIMESTAMP, $4
)
ON CONFLICT (tenant_id, source_node_id, nonce) DO NOTHING
`, tenantID, sourceNodeID, nonce, nullableTime(expiresAt))
	if err != nil {
		return false, err
	}
	rows, _ := res.RowsAffected()
	return rows > 0, nil
}

func (s *SQLStore) AppendClusterLog(ctx context.Context, entry ClusterLogEntry) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cluster_operation_logs (
	tenant_id, node_id, level, event_type, message, details_json, created_at
) VALUES (
	$1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP
)
`, strings.TrimSpace(entry.TenantID), strings.TrimSpace(entry.NodeID), normalizeLogLevel(entry.Level), strings.TrimSpace(entry.EventType), strings.TrimSpace(entry.Message), mustJSON(entry.Details, "{}"))
	return err
}

func (s *SQLStore) ListClusterLogs(ctx context.Context, tenantID string, nodeID string, eventType string, limit int) ([]ClusterLogEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	tenantID = strings.TrimSpace(tenantID)
	nodeID = strings.TrimSpace(nodeID)
	eventType = strings.TrimSpace(eventType)
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, node_id, level, event_type, message, details_json, created_at
FROM cluster_operation_logs
WHERE tenant_id = $1
  AND ($2 = '' OR node_id = $2)
  AND ($3 = '' OR event_type = $3)
ORDER BY id DESC
LIMIT $4
`, tenantID, nodeID, eventType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ClusterLogEntry, 0, limit)
	for rows.Next() {
		item, scanErr := scanClusterLog(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanProfile(scanner interface {
	Scan(dest ...interface{}) error
}) (ClusterProfile, error) {
	var item ClusterProfile
	var componentsJSON string
	var createdRaw interface{}
	var updatedRaw interface{}
	if err := scanner.Scan(&item.ID, &item.TenantID, &item.Name, &item.Description, &componentsJSON, &item.IsDefault, &createdRaw, &updatedRaw); err != nil {
		return ClusterProfile{}, err
	}
	item.Components = parseJSONArrayString(componentsJSON)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanNode(scanner interface {
	Scan(dest ...interface{}) error
}) (ClusterNode, error) {
	var item ClusterNode
	var componentsJSON string
	var hbRaw interface{}
	var syncRaw interface{}
	var createdRaw interface{}
	var updatedRaw interface{}
	if err := scanner.Scan(&item.ID, &item.TenantID, &item.Name, &item.Role, &item.Endpoint, &item.Status, &item.CPUPercent, &item.RAMGB, &componentsJSON, &item.ProfileID, &item.JoinState, &item.CertFingerprint, &hbRaw, &syncRaw, &createdRaw, &updatedRaw); err != nil {
		return ClusterNode{}, err
	}
	item.EnabledComponents = parseJSONArrayString(componentsJSON)
	item.LastHeartbeatAt = parseTimeValue(hbRaw)
	item.LastSyncAt = parseTimeValue(syncRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanJoinToken(scanner interface {
	Scan(dest ...interface{}) error
}) (ClusterJoinToken, error) {
	var item ClusterJoinToken
	var expiresRaw interface{}
	var consumedRaw interface{}
	var createdRaw interface{}
	if err := scanner.Scan(&item.ID, &item.TenantID, &item.TargetNodeID, &item.TargetNode, &item.Endpoint, &item.ProfileID, &item.SecretHash, &item.Nonce, &item.RequestedBy, &expiresRaw, &consumedRaw, &createdRaw); err != nil {
		return ClusterJoinToken{}, err
	}
	item.ExpiresAt = parseTimeValue(expiresRaw)
	item.ConsumedAt = parseTimeValue(consumedRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}

func scanSyncEvent(scanner interface {
	Scan(dest ...interface{}) error
}) (ClusterSyncEvent, error) {
	var item ClusterSyncEvent
	var payloadJSON string
	var createdRaw interface{}
	if err := scanner.Scan(&item.ID, &item.TenantID, &item.ProfileID, &item.Component, &item.EntityType, &item.EntityID, &item.Operation, &payloadJSON, &item.SourceNodeID, &createdRaw); err != nil {
		return ClusterSyncEvent{}, err
	}
	item.Payload = parseJSONObject(payloadJSON)
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}

func scanClusterLog(scanner interface {
	Scan(dest ...interface{}) error
}) (ClusterLogEntry, error) {
	var item ClusterLogEntry
	var detailsJSON string
	var createdRaw interface{}
	if err := scanner.Scan(&item.ID, &item.TenantID, &item.NodeID, &item.Level, &item.EventType, &item.Message, &detailsJSON, &createdRaw); err != nil {
		return ClusterLogEntry{}, err
	}
	item.Details = parseJSONObject(detailsJSON)
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}

func normalizeLogLevel(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "debug":
		return "debug"
	case "warn", "warning":
		return "warn"
	case "error":
		return "error"
	default:
		return "info"
	}
}

type stringArray []string

func pqStringArray(values []string) interface{} {
	return stringArray(values)
}

func (a stringArray) Value() (driver.Value, error) {
	quoted := make([]string, 0, len(a))
	for _, item := range a {
		escaped := strings.ReplaceAll(item, `"`, `\\"`)
		quoted = append(quoted, `"`+escaped+`"`)
	}
	return "{" + strings.Join(quoted, ",") + "}", nil
}
