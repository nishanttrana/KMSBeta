package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

func (s *SQLStore) UpsertBitLockerClient(ctx context.Context, client BitLockerClient) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_bitlocker_clients (
	tenant_id, id, name, host, os_version, status, health, protection_status,
	encryption_percentage, mount_point, heartbeat_interval_sec, last_heartbeat_at,
	tpm_present, tpm_ready, jwt_subject, tls_client_cn, metadata_json, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,
	$9,$10,$11,$12,
	$13,$14,$15,$16,$17,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, id) DO UPDATE SET
	name = excluded.name,
	host = excluded.host,
	os_version = excluded.os_version,
	status = excluded.status,
	health = excluded.health,
	protection_status = excluded.protection_status,
	encryption_percentage = excluded.encryption_percentage,
	mount_point = excluded.mount_point,
	heartbeat_interval_sec = excluded.heartbeat_interval_sec,
	last_heartbeat_at = excluded.last_heartbeat_at,
	tpm_present = excluded.tpm_present,
	tpm_ready = excluded.tpm_ready,
	jwt_subject = excluded.jwt_subject,
	tls_client_cn = excluded.tls_client_cn,
	metadata_json = excluded.metadata_json,
	updated_at = CURRENT_TIMESTAMP
`, client.TenantID, client.ID, client.Name, client.Host, client.OSVersion, client.Status, client.Health, client.ProtectionStatus,
		client.EncryptionPercentage, client.MountPoint, defaultInt(client.HeartbeatIntervalSec, DefaultHeartbeatSec), nullableTime(client.LastHeartbeatAt),
		client.TPMPresent, client.TPMReady, client.JWTSubject, client.TLSClientCN, validJSONOr(client.MetadataJSON, "{}"))
	return err
}

func (s *SQLStore) GetBitLockerClient(ctx context.Context, tenantID string, clientID string) (BitLockerClient, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, name, host, os_version, status, health, protection_status,
	   encryption_percentage, mount_point, heartbeat_interval_sec, last_heartbeat_at,
	   tpm_present, tpm_ready, jwt_subject, tls_client_cn, metadata_json, created_at, updated_at
FROM ekm_bitlocker_clients
WHERE tenant_id = $1 AND id = $2
`, tenantID, clientID)
	out, err := scanBitLockerClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return BitLockerClient{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListBitLockerClients(ctx context.Context, tenantID string, limit int) ([]BitLockerClient, error) {
	max := limit
	if max <= 0 {
		max = 1000
	}
	if max > 100000 {
		max = 100000
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, name, host, os_version, status, health, protection_status,
	   encryption_percentage, mount_point, heartbeat_interval_sec, last_heartbeat_at,
	   tpm_present, tpm_ready, jwt_subject, tls_client_cn, metadata_json, created_at, updated_at
FROM ekm_bitlocker_clients
WHERE tenant_id = $1
ORDER BY updated_at DESC
LIMIT $2
`, tenantID, max)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]BitLockerClient, 0, max)
	for rows.Next() {
		item, scanErr := scanBitLockerClient(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateBitLockerHeartbeat(
	ctx context.Context,
	tenantID string,
	clientID string,
	status string,
	health string,
	protectionStatus string,
	encryptionPct float64,
	mountPoint string,
	tpmPresent bool,
	tpmReady bool,
	metadataJSON string,
	at time.Time,
) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_bitlocker_clients
SET status = $1,
	health = $2,
	protection_status = $3,
	encryption_percentage = $4,
	mount_point = CASE WHEN $5 = '' THEN mount_point ELSE $5 END,
	tpm_present = $6,
	tpm_ready = $7,
	metadata_json = $8,
	last_heartbeat_at = $9,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $10 AND id = $11
`, status, health, protectionStatus, encryptionPct, strings.TrimSpace(mountPoint), tpmPresent, tpmReady, validJSONOr(metadataJSON, "{}"), at.UTC(), tenantID, clientID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) MarkBitLockerClientDisconnected(ctx context.Context, tenantID string, clientID string, at time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_bitlocker_clients
SET status = $1, health = $2, updated_at = $3
WHERE tenant_id = $4 AND id = $5
`, AgentStatusDisconnected, "down", at.UTC(), tenantID, clientID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateBitLockerJob(ctx context.Context, job BitLockerJob) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_bitlocker_jobs (
	tenant_id, id, client_id, operation, params_json, status, requested_by, request_id,
	requested_at, dispatched_at, completed_at, result_json, error_message, recovery_key_ref
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,
	$9,$10,$11,$12,$13,$14
)
`, job.TenantID, job.ID, job.ClientID, job.Operation, validJSONOr(job.ParamsJSON, "{}"), normalizeBitLockerJobStatus(job.Status), strings.TrimSpace(job.RequestedBy),
		strings.TrimSpace(job.RequestID), nullableTime(job.RequestedAt), nullableTime(job.DispatchedAt), nullableTime(job.CompletedAt), validJSONOr(job.ResultJSON, "{}"),
		strings.TrimSpace(job.ErrorMessage), strings.TrimSpace(job.RecoveryKeyRef))
	return err
}

func (s *SQLStore) GetBitLockerJob(ctx context.Context, tenantID string, clientID string, jobID string) (BitLockerJob, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, client_id, operation, params_json, status, requested_by, request_id,
	   requested_at, dispatched_at, completed_at, result_json, error_message, recovery_key_ref
FROM ekm_bitlocker_jobs
WHERE tenant_id = $1 AND client_id = $2 AND id = $3
`, tenantID, clientID, jobID)
	out, err := scanBitLockerJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return BitLockerJob{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListBitLockerJobs(ctx context.Context, tenantID string, clientID string, limit int) ([]BitLockerJob, error) {
	max := limit
	if max <= 0 {
		max = 100
	}
	if max > 5000 {
		max = 5000
	}
	q := `
SELECT tenant_id, id, client_id, operation, params_json, status, requested_by, request_id,
	   requested_at, dispatched_at, completed_at, result_json, error_message, recovery_key_ref
FROM ekm_bitlocker_jobs
WHERE tenant_id = $1
`
	args := []interface{}{tenantID}
	if strings.TrimSpace(clientID) != "" {
		q += " AND client_id = $2"
		args = append(args, strings.TrimSpace(clientID))
	}
	q += " ORDER BY requested_at DESC LIMIT $" + strconvItoa(len(args)+1)
	args = append(args, max)
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]BitLockerJob, 0, max)
	for rows.Next() {
		item, scanErr := scanBitLockerJob(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) DispatchNextBitLockerJob(ctx context.Context, tenantID string, clientID string, at time.Time) (BitLockerJob, error) {
	var out BitLockerJob
	err := s.db.WithTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
SELECT tenant_id, id, client_id, operation, params_json, status, requested_by, request_id,
	   requested_at, dispatched_at, completed_at, result_json, error_message, recovery_key_ref
FROM ekm_bitlocker_jobs
WHERE tenant_id = $1 AND client_id = $2 AND status = 'pending'
ORDER BY requested_at ASC
LIMIT 1
`, tenantID, clientID)
		item, scanErr := scanBitLockerJob(row)
		if errors.Is(scanErr, sql.ErrNoRows) {
			return errNotFound
		}
		if scanErr != nil {
			return scanErr
		}
		res, updErr := tx.ExecContext(ctx, `
UPDATE ekm_bitlocker_jobs
SET status = 'dispatched',
	dispatched_at = $1
WHERE tenant_id = $2 AND client_id = $3 AND id = $4 AND status = 'pending'
`, at.UTC(), tenantID, clientID, item.ID)
		if updErr != nil {
			return updErr
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return errNotFound
		}
		item.Status = "dispatched"
		item.DispatchedAt = at.UTC()
		out = item
		return nil
	})
	if err != nil {
		return BitLockerJob{}, err
	}
	return out, nil
}

func (s *SQLStore) CompleteBitLockerJob(
	ctx context.Context,
	tenantID string,
	clientID string,
	jobID string,
	status string,
	resultJSON string,
	errMessage string,
	recoveryRef string,
	completedAt time.Time,
) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_bitlocker_jobs
SET status = $1,
	completed_at = $2,
	result_json = $3,
	error_message = $4,
	recovery_key_ref = CASE WHEN $5 = '' THEN recovery_key_ref ELSE $5 END
WHERE tenant_id = $6 AND client_id = $7 AND id = $8
`, normalizeBitLockerJobStatus(status), completedAt.UTC(), validJSONOr(resultJSON, "{}"), strings.TrimSpace(errMessage), strings.TrimSpace(recoveryRef), tenantID, clientID, jobID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) SaveBitLockerRecoveryKey(ctx context.Context, rec BitLockerRecoveryKeyRecord) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_bitlocker_recovery_keys (
	tenant_id, id, client_id, job_id, volume_mount_point, protector_id, key_fingerprint, key_masked,
	wrapped_dek, wrapped_dek_iv, ciphertext, data_iv, source, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,
	$9,$10,$11,$12,$13,$14
)
`, rec.TenantID, rec.ID, rec.ClientID, rec.JobID, rec.VolumeMountPoint, rec.ProtectorID, rec.KeyFingerprint, rec.KeyMasked,
		rec.WrappedDEK, rec.WrappedDEKIV, rec.Ciphertext, rec.DataIV, defaultString(rec.Source, "agent"), nullableTime(rec.CreatedAt))
	return err
}

func (s *SQLStore) ListBitLockerRecoveryKeys(ctx context.Context, tenantID string, clientID string, limit int) ([]BitLockerRecoveryKeyRecord, error) {
	max := limit
	if max <= 0 {
		max = 200
	}
	if max > 20000 {
		max = 20000
	}
	q := `
SELECT tenant_id, id, client_id, job_id, volume_mount_point, protector_id, key_fingerprint, key_masked,
	   wrapped_dek, wrapped_dek_iv, ciphertext, data_iv, source, created_at
FROM ekm_bitlocker_recovery_keys
WHERE tenant_id = $1
`
	args := []interface{}{tenantID}
	if strings.TrimSpace(clientID) != "" {
		q += " AND client_id = $2"
		args = append(args, strings.TrimSpace(clientID))
	}
	q += " ORDER BY created_at DESC LIMIT $" + strconvItoa(len(args)+1)
	args = append(args, max)
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]BitLockerRecoveryKeyRecord, 0, max)
	for rows.Next() {
		item, scanErr := scanBitLockerRecovery(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanBitLockerClient(scanner interface {
	Scan(dest ...interface{}) error
}) (BitLockerClient, error) {
	var (
		out        BitLockerClient
		lastRaw    interface{}
		tpmRaw     interface{}
		tpmReady   interface{}
		createdRaw interface{}
		updatedRaw interface{}
	)
	err := scanner.Scan(
		&out.TenantID, &out.ID, &out.Name, &out.Host, &out.OSVersion, &out.Status, &out.Health, &out.ProtectionStatus,
		&out.EncryptionPercentage, &out.MountPoint, &out.HeartbeatIntervalSec, &lastRaw,
		&tpmRaw, &tpmReady, &out.JWTSubject, &out.TLSClientCN, &out.MetadataJSON, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return BitLockerClient{}, err
	}
	out.TPMPresent = boolValue(tpmRaw)
	out.TPMReady = boolValue(tpmReady)
	out.LastHeartbeatAt = parseTimeValue(lastRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	if out.MetadataJSON == "" {
		out.MetadataJSON = "{}"
	}
	return out, nil
}

func scanBitLockerJob(scanner interface {
	Scan(dest ...interface{}) error
}) (BitLockerJob, error) {
	var (
		out           BitLockerJob
		requestedRaw  interface{}
		dispatchedRaw interface{}
		completedRaw  interface{}
	)
	err := scanner.Scan(
		&out.TenantID, &out.ID, &out.ClientID, &out.Operation, &out.ParamsJSON, &out.Status, &out.RequestedBy, &out.RequestID,
		&requestedRaw, &dispatchedRaw, &completedRaw, &out.ResultJSON, &out.ErrorMessage, &out.RecoveryKeyRef,
	)
	if err != nil {
		return BitLockerJob{}, err
	}
	out.RequestedAt = parseTimeValue(requestedRaw)
	out.DispatchedAt = parseTimeValue(dispatchedRaw)
	out.CompletedAt = parseTimeValue(completedRaw)
	if out.ParamsJSON == "" {
		out.ParamsJSON = "{}"
	}
	if out.ResultJSON == "" {
		out.ResultJSON = "{}"
	}
	return out, nil
}

func scanBitLockerRecovery(scanner interface {
	Scan(dest ...interface{}) error
}) (BitLockerRecoveryKeyRecord, error) {
	var (
		out        BitLockerRecoveryKeyRecord
		createdRaw interface{}
	)
	err := scanner.Scan(
		&out.TenantID, &out.ID, &out.ClientID, &out.JobID, &out.VolumeMountPoint, &out.ProtectorID, &out.KeyFingerprint, &out.KeyMasked,
		&out.WrappedDEK, &out.WrappedDEKIV, &out.Ciphertext, &out.DataIV, &out.Source, &createdRaw,
	)
	if err != nil {
		return BitLockerRecoveryKeyRecord{}, err
	}
	out.CreatedAt = parseTimeValue(createdRaw)
	return out, nil
}
