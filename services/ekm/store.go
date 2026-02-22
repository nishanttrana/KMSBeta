package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	UpsertAgent(ctx context.Context, agent Agent) error
	GetAgent(ctx context.Context, tenantID string, agentID string) (Agent, error)
	ListAgents(ctx context.Context, tenantID string) ([]Agent, error)
	UpdateAgentHeartbeat(ctx context.Context, tenantID string, agentID string, status string, tdeState string, activeKeyID string, activeKeyVersion string, configVersionAck int, metadataJSON string, at time.Time) error
	MarkAgentDisconnected(ctx context.Context, tenantID string, agentID string, at time.Time) error
	BumpAgentConfigVersion(ctx context.Context, tenantID string, agentID string, keyID string, keyVersion string) error
	PurgeAgent(ctx context.Context, tenantID string, agentID string, keyIDs []string) (int, int, int, error)

	UpsertDatabase(ctx context.Context, db DatabaseInstance) error
	GetDatabase(ctx context.Context, tenantID string, databaseID string) (DatabaseInstance, error)
	ListDatabases(ctx context.Context, tenantID string, agentID string) ([]DatabaseInstance, error)
	ListDatabasesByKey(ctx context.Context, tenantID string, keyID string) ([]DatabaseInstance, error)

	CreateTDEKey(ctx context.Context, key TDEKeyRecord) error
	GetTDEKey(ctx context.Context, tenantID string, keyID string) (TDEKeyRecord, error)
	UpdateTDEKeyMetadata(ctx context.Context, tenantID string, keyID string, publicKey string, publicKeyFormat string, metadataJSON string) error
	TouchTDEKeyAccess(ctx context.Context, tenantID string, keyID string, at time.Time) error
	UpdateTDEKeyRotation(ctx context.Context, tenantID string, keyID string, version string, rotatedAt time.Time) error

	RecordKeyAccess(ctx context.Context, item KeyAccessLog) error
	ListKeyAccessByAgent(ctx context.Context, tenantID string, agentID string, limit int) ([]KeyAccessLog, error)
	ListKeyAccessByTenant(ctx context.Context, tenantID string, since time.Time, limit int) ([]KeyAccessLog, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) UpsertAgent(ctx context.Context, agent Agent) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_agents (
	tenant_id, id, name, role, db_engine, host, version, status, tde_state,
	heartbeat_interval_sec, last_heartbeat_at, assigned_key_id, assigned_key_version,
	config_version, config_version_ack, metadata_json, tls_client_cn, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,
	$10,$11,$12,$13,
	$14,$15,$16,$17,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, id) DO UPDATE SET
	name = excluded.name,
	role = excluded.role,
	db_engine = excluded.db_engine,
	host = excluded.host,
	version = excluded.version,
	status = excluded.status,
	tde_state = excluded.tde_state,
	heartbeat_interval_sec = excluded.heartbeat_interval_sec,
	last_heartbeat_at = excluded.last_heartbeat_at,
	assigned_key_id = excluded.assigned_key_id,
	assigned_key_version = excluded.assigned_key_version,
	config_version = excluded.config_version,
	config_version_ack = excluded.config_version_ack,
	metadata_json = excluded.metadata_json,
	tls_client_cn = excluded.tls_client_cn,
	updated_at = CURRENT_TIMESTAMP
`, agent.TenantID, agent.ID, agent.Name, agent.Role, agent.DBEngine, agent.Host, agent.Version, agent.Status, agent.TDEState,
		defaultInt(agent.HeartbeatIntervalSec, DefaultHeartbeatSec), nullableTime(agent.LastHeartbeatAt), agent.AssignedKeyID, agent.AssignedKeyVersion,
		defaultInt(agent.ConfigVersion, 1), agent.ConfigVersionAck, validJSONOr(agent.MetadataJSON, "{}"), agent.TLSClientCN)
	return err
}

func (s *SQLStore) GetAgent(ctx context.Context, tenantID string, agentID string) (Agent, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, name, role, db_engine, host, version, status, tde_state,
	   heartbeat_interval_sec, last_heartbeat_at, assigned_key_id, assigned_key_version,
	   config_version, config_version_ack, metadata_json, tls_client_cn, created_at, updated_at
FROM ekm_agents
WHERE tenant_id = $1 AND id = $2
`, tenantID, agentID)
	out, err := scanAgent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Agent{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListAgents(ctx context.Context, tenantID string) ([]Agent, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, name, role, db_engine, host, version, status, tde_state,
	   heartbeat_interval_sec, last_heartbeat_at, assigned_key_id, assigned_key_version,
	   config_version, config_version_ack, metadata_json, tls_client_cn, created_at, updated_at
FROM ekm_agents
WHERE tenant_id = $1
ORDER BY updated_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]Agent, 0)
	for rows.Next() {
		item, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateAgentHeartbeat(ctx context.Context, tenantID string, agentID string, status string, tdeState string, activeKeyID string, activeKeyVersion string, configVersionAck int, metadataJSON string, at time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_agents
SET status = $1,
	tde_state = $2,
	assigned_key_id = CASE WHEN $3 = '' THEN assigned_key_id ELSE $3 END,
	assigned_key_version = CASE WHEN $4 = '' THEN assigned_key_version ELSE $4 END,
	config_version_ack = CASE WHEN $5 <= 0 THEN config_version_ack ELSE $5 END,
	metadata_json = $6,
	last_heartbeat_at = $7,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $8 AND id = $9
`, status, tdeState, strings.TrimSpace(activeKeyID), strings.TrimSpace(activeKeyVersion), configVersionAck, validJSONOr(metadataJSON, "{}"), at.UTC(), tenantID, agentID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) MarkAgentDisconnected(ctx context.Context, tenantID string, agentID string, at time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_agents
SET status = $1, updated_at = $2
WHERE tenant_id = $3 AND id = $4
`, AgentStatusDisconnected, at.UTC(), tenantID, agentID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) BumpAgentConfigVersion(ctx context.Context, tenantID string, agentID string, keyID string, keyVersion string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_agents
SET config_version = config_version + 1,
	assigned_key_id = CASE WHEN $1 = '' THEN assigned_key_id ELSE $1 END,
	assigned_key_version = CASE WHEN $2 = '' THEN assigned_key_version ELSE $2 END,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $3 AND id = $4
`, strings.TrimSpace(keyID), strings.TrimSpace(keyVersion), tenantID, agentID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) PurgeAgent(ctx context.Context, tenantID string, agentID string, keyIDs []string) (int, int, int, error) {
	type outCounts struct {
		deletedDB   int
		deletedKeys int
		deletedLogs int
	}
	counts := outCounts{}
	err := s.db.WithTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		dbRows, err := tx.QueryContext(ctx, `
SELECT id
FROM ekm_databases
WHERE tenant_id = $1 AND agent_id = $2
`, tenantID, agentID)
		if err != nil {
			return err
		}
		dbIDs := make([]string, 0)
		for dbRows.Next() {
			var dbID string
			if scanErr := dbRows.Scan(&dbID); scanErr != nil {
				_ = dbRows.Close()
				return scanErr
			}
			dbIDs = append(dbIDs, strings.TrimSpace(dbID))
		}
		if err = dbRows.Err(); err != nil {
			_ = dbRows.Close()
			return err
		}
		_ = dbRows.Close()

		logRes, err := tx.ExecContext(ctx, `
DELETE FROM ekm_key_access_log
WHERE tenant_id = $1 AND agent_id = $2
`, tenantID, agentID)
		if err != nil {
			return err
		}
		if n, nErr := logRes.RowsAffected(); nErr == nil {
			counts.deletedLogs += int(n)
		}

		for _, dbID := range dbIDs {
			if dbID == "" {
				continue
			}
			res, qErr := tx.ExecContext(ctx, `
DELETE FROM ekm_key_access_log
WHERE tenant_id = $1 AND database_id = $2
`, tenantID, dbID)
			if qErr != nil {
				return qErr
			}
			if n, nErr := res.RowsAffected(); nErr == nil {
				counts.deletedLogs += int(n)
			}
		}

		dbRes, err := tx.ExecContext(ctx, `
DELETE FROM ekm_databases
WHERE tenant_id = $1 AND agent_id = $2
`, tenantID, agentID)
		if err != nil {
			return err
		}
		if n, nErr := dbRes.RowsAffected(); nErr == nil {
			counts.deletedDB += int(n)
		}

		seenKeys := map[string]struct{}{}
		for _, keyID := range keyIDs {
			id := strings.TrimSpace(keyID)
			if id == "" {
				continue
			}
			if _, ok := seenKeys[id]; ok {
				continue
			}
			seenKeys[id] = struct{}{}
			res, qErr := tx.ExecContext(ctx, `
DELETE FROM ekm_key_access_log
WHERE tenant_id = $1 AND key_id = $2
`, tenantID, id)
			if qErr != nil {
				return qErr
			}
			if n, nErr := res.RowsAffected(); nErr == nil {
				counts.deletedLogs += int(n)
			}
		}

		for keyID := range seenKeys {
			res, qErr := tx.ExecContext(ctx, `
DELETE FROM ekm_tde_keys
WHERE tenant_id = $1 AND id = $2
`, tenantID, keyID)
			if qErr != nil {
				return qErr
			}
			if n, nErr := res.RowsAffected(); nErr == nil {
				counts.deletedKeys += int(n)
			}
		}

		agentRes, err := tx.ExecContext(ctx, `
DELETE FROM ekm_agents
WHERE tenant_id = $1 AND id = $2
`, tenantID, agentID)
		if err != nil {
			return err
		}
		affected, _ := agentRes.RowsAffected()
		if affected == 0 {
			return errNotFound
		}
		return nil
	})
	if err != nil {
		return 0, 0, 0, err
	}
	return counts.deletedDB, counts.deletedKeys, counts.deletedLogs, nil
}

func (s *SQLStore) UpsertDatabase(ctx context.Context, dbi DatabaseInstance) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_databases (
	tenant_id, id, agent_id, name, engine, host, port, database_name, tde_enabled,
	tde_state, key_id, auto_provisioned, metadata_json, last_seen_at, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,
	$10,$11,$12,$13,$14,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, id) DO UPDATE SET
	agent_id = excluded.agent_id,
	name = excluded.name,
	engine = excluded.engine,
	host = excluded.host,
	port = excluded.port,
	database_name = excluded.database_name,
	tde_enabled = excluded.tde_enabled,
	tde_state = excluded.tde_state,
	key_id = excluded.key_id,
	auto_provisioned = excluded.auto_provisioned,
	metadata_json = excluded.metadata_json,
	last_seen_at = excluded.last_seen_at,
	updated_at = CURRENT_TIMESTAMP
`, dbi.TenantID, dbi.ID, dbi.AgentID, dbi.Name, dbi.Engine, dbi.Host, dbi.Port, dbi.DatabaseName, dbi.TDEEnabled,
		dbi.TDEState, dbi.KeyID, dbi.AutoProvisioned, validJSONOr(dbi.MetadataJSON, "{}"), nullableTime(dbi.LastSeenAt))
	return err
}

func (s *SQLStore) GetDatabase(ctx context.Context, tenantID string, databaseID string) (DatabaseInstance, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, agent_id, name, engine, host, port, database_name, tde_enabled,
	   tde_state, key_id, auto_provisioned, metadata_json, last_seen_at, created_at, updated_at
FROM ekm_databases
WHERE tenant_id = $1 AND id = $2
`, tenantID, databaseID)
	out, err := scanDatabase(row)
	if errors.Is(err, sql.ErrNoRows) {
		return DatabaseInstance{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListDatabases(ctx context.Context, tenantID string, agentID string) ([]DatabaseInstance, error) {
	q := `
SELECT tenant_id, id, agent_id, name, engine, host, port, database_name, tde_enabled,
	   tde_state, key_id, auto_provisioned, metadata_json, last_seen_at, created_at, updated_at
FROM ekm_databases
WHERE tenant_id = $1
`
	args := []interface{}{tenantID}
	if strings.TrimSpace(agentID) != "" {
		q += " AND agent_id = $2"
		args = append(args, strings.TrimSpace(agentID))
	}
	q += " ORDER BY updated_at DESC"
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]DatabaseInstance, 0)
	for rows.Next() {
		item, err := scanDatabase(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListDatabasesByKey(ctx context.Context, tenantID string, keyID string) ([]DatabaseInstance, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, agent_id, name, engine, host, port, database_name, tde_enabled,
	   tde_state, key_id, auto_provisioned, metadata_json, last_seen_at, created_at, updated_at
FROM ekm_databases
WHERE tenant_id = $1 AND key_id = $2
ORDER BY updated_at DESC
`, tenantID, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]DatabaseInstance, 0)
	for rows.Next() {
		item, err := scanDatabase(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateTDEKey(ctx context.Context, key TDEKeyRecord) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_tde_keys (
	tenant_id, id, keycore_key_id, name, algorithm, status, current_version,
	public_key_cache, public_key_format, created_by, auto_provisioned, metadata_json,
	created_at, updated_at, rotated_at, last_accessed_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,
	$8,$9,$10,$11,$12,
	CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,$13,$14
)
`, key.TenantID, key.ID, key.KeyCoreKeyID, key.Name, key.Algorithm, key.Status, key.CurrentVersion,
		key.PublicKey, key.PublicKeyFormat, key.CreatedBy, key.AutoProvisioned, validJSONOr(key.MetadataJSON, "{}"),
		nullableTime(key.RotatedAt), nullableTime(key.LastAccessedAt))
	return err
}

func (s *SQLStore) GetTDEKey(ctx context.Context, tenantID string, keyID string) (TDEKeyRecord, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, keycore_key_id, name, algorithm, status, current_version,
	   public_key_cache, public_key_format, created_by, auto_provisioned, metadata_json,
	   created_at, updated_at, rotated_at, last_accessed_at
FROM ekm_tde_keys
WHERE tenant_id = $1 AND id = $2
`, tenantID, keyID)
	out, err := scanTDEKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return TDEKeyRecord{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) UpdateTDEKeyMetadata(ctx context.Context, tenantID string, keyID string, publicKey string, publicKeyFormat string, metadataJSON string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_tde_keys
SET public_key_cache = CASE WHEN $1 = '' THEN public_key_cache ELSE $1 END,
	public_key_format = CASE WHEN $2 = '' THEN public_key_format ELSE $2 END,
	metadata_json = CASE WHEN $3 = '' THEN metadata_json ELSE $3 END,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $4 AND id = $5
`, strings.TrimSpace(publicKey), strings.TrimSpace(publicKeyFormat), strings.TrimSpace(metadataJSON), tenantID, keyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) TouchTDEKeyAccess(ctx context.Context, tenantID string, keyID string, at time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_tde_keys
SET last_accessed_at = $1, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $2 AND id = $3
`, at.UTC(), tenantID, keyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) UpdateTDEKeyRotation(ctx context.Context, tenantID string, keyID string, version string, rotatedAt time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_tde_keys
SET current_version = CASE WHEN $1 = '' THEN current_version ELSE $1 END,
	status = 'active',
	rotated_at = $2,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $3 AND id = $4
`, strings.TrimSpace(version), rotatedAt.UTC(), tenantID, keyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) RecordKeyAccess(ctx context.Context, item KeyAccessLog) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_key_access_log (
	tenant_id, id, key_id, agent_id, database_id, operation, status, error_message, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9
)
`, item.TenantID, item.ID, item.KeyID, item.AgentID, item.DatabaseID, item.Operation, item.Status, item.ErrorMessage, item.CreatedAt.UTC())
	return err
}

func (s *SQLStore) ListKeyAccessByAgent(ctx context.Context, tenantID string, agentID string, limit int) ([]KeyAccessLog, error) {
	max := limit
	if max <= 0 {
		max = 50
	}
	if max > 500 {
		max = 500
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, key_id, agent_id, database_id, operation, status, error_message, created_at
FROM ekm_key_access_log
WHERE tenant_id = $1 AND agent_id = $2
ORDER BY created_at DESC
LIMIT $3
`, tenantID, agentID, max)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]KeyAccessLog, 0)
	for rows.Next() {
		item, err := scanKeyAccess(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListKeyAccessByTenant(ctx context.Context, tenantID string, since time.Time, limit int) ([]KeyAccessLog, error) {
	max := defaultInt(limit, 1000)
	if max > 20000 {
		max = 20000
	}
	q := `
SELECT tenant_id, id, key_id, agent_id, database_id, operation, status, error_message, created_at
FROM ekm_key_access_log
WHERE tenant_id = $1
`
	args := []interface{}{tenantID}
	if !since.IsZero() {
		q += " AND created_at >= $2"
		args = append(args, since.UTC())
	}
	q += " ORDER BY created_at DESC LIMIT $" + strconvItoa(len(args)+1)
	args = append(args, max)
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]KeyAccessLog, 0, max)
	for rows.Next() {
		item, scanErr := scanKeyAccess(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanAgent(scanner interface {
	Scan(dest ...interface{}) error
}) (Agent, error) {
	var (
		out        Agent
		lastRaw    interface{}
		createdRaw interface{}
		updatedRaw interface{}
	)
	err := scanner.Scan(
		&out.TenantID, &out.ID, &out.Name, &out.Role, &out.DBEngine, &out.Host, &out.Version, &out.Status, &out.TDEState,
		&out.HeartbeatIntervalSec, &lastRaw, &out.AssignedKeyID, &out.AssignedKeyVersion,
		&out.ConfigVersion, &out.ConfigVersionAck, &out.MetadataJSON, &out.TLSClientCN, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return Agent{}, err
	}
	out.LastHeartbeatAt = parseTimeValue(lastRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	if out.MetadataJSON == "" {
		out.MetadataJSON = "{}"
	}
	return out, nil
}

func scanDatabase(scanner interface {
	Scan(dest ...interface{}) error
}) (DatabaseInstance, error) {
	var (
		out           DatabaseInstance
		tdeEnabledRaw interface{}
		autoRaw       interface{}
		lastSeenRaw   interface{}
		createdRaw    interface{}
		updatedRaw    interface{}
	)
	err := scanner.Scan(
		&out.TenantID, &out.ID, &out.AgentID, &out.Name, &out.Engine, &out.Host, &out.Port, &out.DatabaseName, &tdeEnabledRaw,
		&out.TDEState, &out.KeyID, &autoRaw, &out.MetadataJSON, &lastSeenRaw, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return DatabaseInstance{}, err
	}
	out.TDEEnabled = boolValue(tdeEnabledRaw)
	out.AutoProvisioned = boolValue(autoRaw)
	out.LastSeenAt = parseTimeValue(lastSeenRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	if out.MetadataJSON == "" {
		out.MetadataJSON = "{}"
	}
	return out, nil
}

func scanTDEKey(scanner interface {
	Scan(dest ...interface{}) error
}) (TDEKeyRecord, error) {
	var (
		out           TDEKeyRecord
		autoRaw       interface{}
		createdRaw    interface{}
		updatedRaw    interface{}
		rotatedRaw    interface{}
		lastAccessRaw interface{}
	)
	err := scanner.Scan(
		&out.TenantID, &out.ID, &out.KeyCoreKeyID, &out.Name, &out.Algorithm, &out.Status, &out.CurrentVersion,
		&out.PublicKey, &out.PublicKeyFormat, &out.CreatedBy, &autoRaw, &out.MetadataJSON,
		&createdRaw, &updatedRaw, &rotatedRaw, &lastAccessRaw,
	)
	if err != nil {
		return TDEKeyRecord{}, err
	}
	out.AutoProvisioned = boolValue(autoRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	out.RotatedAt = parseTimeValue(rotatedRaw)
	out.LastAccessedAt = parseTimeValue(lastAccessRaw)
	if out.MetadataJSON == "" {
		out.MetadataJSON = "{}"
	}
	if out.KeyCoreKeyID == "" {
		out.KeyCoreKeyID = out.ID
	}
	return out, nil
}

func scanKeyAccess(scanner interface {
	Scan(dest ...interface{}) error
}) (KeyAccessLog, error) {
	var (
		out        KeyAccessLog
		createdRaw interface{}
	)
	err := scanner.Scan(
		&out.TenantID,
		&out.ID,
		&out.KeyID,
		&out.AgentID,
		&out.DatabaseID,
		&out.Operation,
		&out.Status,
		&out.ErrorMessage,
		&createdRaw,
	)
	if err != nil {
		return KeyAccessLog{}, err
	}
	out.CreatedAt = parseTimeValue(createdRaw)
	return out, nil
}
