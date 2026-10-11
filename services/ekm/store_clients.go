package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// checkInsKept is how many check-ins are kept per client.
const checkInsKept = 120

const clientColumns = `tenant_id, id, name, db_engine, host, version, status, tde_state,
	   heartbeat_interval_sec, last_heartbeat_at, assigned_key_id, assigned_key_version, metadata_json,
	   created_at, registration, registered_at, source_ip, enroll_token_hash, enroll_token_expires_at, credential_hash`

func scanClient(scanner interface {
	Scan(dest ...interface{}) error
}) (clientRecord, error) {
	var (
		out                                   clientRecord
		lastRaw, createdRaw, regRaw, tokenRaw interface{}
	)
	err := scanner.Scan(
		&out.TenantID, &out.ID, &out.Name, &out.DBEngine, &out.Host, &out.Version, &out.Status, &out.TDEState,
		&out.HeartbeatIntervalSec, &lastRaw, &out.AssignedKeyID, &out.AssignedKeyVersion, &out.MetadataJSON,
		&createdRaw, &out.Registration, &regRaw, &out.SourceIP, &out.TokenHash, &tokenRaw, &out.CredentialHash,
	)
	if err != nil {
		return clientRecord{}, err
	}
	out.LastSeenAt = parseTimeValue(lastRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.RegisteredAt = parseTimeValue(regRaw)
	out.TokenExpiresAt = parseTimeValue(tokenRaw)
	return out, nil
}

func (s *SQLStore) ListClients(ctx context.Context, tenantID string) ([]clientRecord, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT `+clientColumns+`
FROM ekm_agents
WHERE tenant_id = $1
ORDER BY name, id
LIMIT 1000
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]clientRecord, 0)
	for rows.Next() {
		item, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetClient(ctx context.Context, tenantID, clientID string) (clientRecord, error) {
	out, err := scanClient(s.db.SQL().QueryRowContext(ctx, `
SELECT `+clientColumns+`
FROM ekm_agents
WHERE tenant_id = $1 AND id = $2
`, tenantID, clientID))
	if errors.Is(err, sql.ErrNoRows) {
		return clientRecord{}, errNotFound
	}
	return out, err
}

// CreatePendingClient inserts a client that no agent has contacted yet: no
// heartbeat, no credential, and a status that is not "connected".
func (s *SQLStore) CreatePendingClient(ctx context.Context, c clientRecord) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_agents (
	tenant_id, id, name, role, db_engine, host, status, tde_state,
	heartbeat_interval_sec, metadata_json, registration, created_at, updated_at
) VALUES ($1,$2,$3,'ekm-agent',$4,$5,$6,'unknown',$7,$8,$9,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
`, c.TenantID, c.ID, c.Name, c.DBEngine, c.Host, clientStatusPending,
		defaultInt(c.HeartbeatIntervalSec, DefaultHeartbeatSec), validJSONOr(c.MetadataJSON, "{}"), registrationPending)
	return err
}

// SetClientToken stores the hash of a new registration token, replacing any
// earlier unused one.
func (s *SQLStore) SetClientToken(ctx context.Context, tenantID, clientID, tokenHash string, expires time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_agents
SET enroll_token_hash = $1, enroll_token_expires_at = $2, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $3 AND id = $4
`, tokenHash, expires.UTC(), tenantID, clientID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// ConsumeClientToken registers the client if tokenHash is still its unused
// token, and reports whether it did. The token is cleared in the same
// statement, so of two agents presenting one token only one is registered.
func (s *SQLStore) ConsumeClientToken(ctx context.Context, tenantID, clientID, tokenHash, credentialHash, sourceIP, version, host string, at time.Time) (bool, error) {
	if tokenHash == "" {
		return false, nil
	}
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_agents
SET registration = $1,
	registered_at = $2,
	last_heartbeat_at = $2,
	status = $3,
	credential_hash = $4,
	source_ip = $5,
	version = CASE WHEN $6 = '' THEN version ELSE $6 END,
	host = CASE WHEN host = '' THEN $7 ELSE host END,
	enroll_token_hash = '',
	enroll_token_expires_at = NULL,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $8 AND id = $9 AND enroll_token_hash = $10
`, registrationRegistered, at.UTC(), AgentStatusConnected, credentialHash, sourceIP, strings.TrimSpace(version), strings.TrimSpace(host),
		tenantID, clientID, tokenHash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// RecordClientCheckIn appends one verified contact, records where it came
// from on the client, and drops check-ins beyond the newest checkInsKept.
func (s *SQLStore) RecordClientCheckIn(ctx context.Context, in ClientCheckIn) error {
	return s.db.WithTenantTx(ctx, in.TenantID, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
UPDATE ekm_agents
SET source_ip = $1, version = CASE WHEN $2 = '' THEN version ELSE $2 END
WHERE tenant_id = $3 AND id = $4
`, in.SourceIP, strings.TrimSpace(in.Version), in.TenantID, in.ClientID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO ekm_agent_checkins (tenant_id, id, agent_id, at, source_ip, version, status)
VALUES ($1,$2,$3,$4,$5,$6,$7)
`, in.TenantID, newID("chk"), in.ClientID, in.At.UTC(), in.SourceIP, strings.TrimSpace(in.Version), in.Status); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
DELETE FROM ekm_agent_checkins
WHERE tenant_id = $1 AND agent_id = $2 AND at < (
	SELECT MIN(at) FROM (
		SELECT at FROM ekm_agent_checkins
		WHERE tenant_id = $1 AND agent_id = $2
		ORDER BY at DESC LIMIT $3
	) newest
)
`, in.TenantID, in.ClientID, checkInsKept)
		return err
	})
}

// ListClientCheckIns returns the newest limit check-ins, oldest first.
func (s *SQLStore) ListClientCheckIns(ctx context.Context, tenantID, clientID string, limit int) ([]ClientCheckIn, error) {
	if limit <= 0 || limit > checkInsKept {
		limit = checkInsKept
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT at, source_ip, version, status
FROM ekm_agent_checkins
WHERE tenant_id = $1 AND agent_id = $2
ORDER BY at DESC
LIMIT $3
`, tenantID, clientID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ClientCheckIn, 0, limit)
	for rows.Next() {
		var (
			item  ClientCheckIn
			atRaw interface{}
		)
		if err := rows.Scan(&atRaw, &item.SourceIP, &item.Version, &item.Status); err != nil {
			return nil, err
		}
		item.At = parseTimeValue(atRaw)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}
