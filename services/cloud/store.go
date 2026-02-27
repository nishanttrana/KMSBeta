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
	CreateAccount(ctx context.Context, account CloudAccount) error
	GetAccount(ctx context.Context, tenantID string, accountID string) (CloudAccount, error)
	ListAccounts(ctx context.Context, tenantID string, provider string) ([]CloudAccount, error)
	DeleteAccountCascade(ctx context.Context, tenantID string, accountID string) (DeleteCloudAccountResult, error)
	UpdateAccountStatus(ctx context.Context, tenantID string, accountID string, status string) error

	SetRegionMapping(ctx context.Context, mapping RegionMapping) error
	ListRegionMappings(ctx context.Context, tenantID string, provider string) ([]RegionMapping, error)
	GetRegionMapping(ctx context.Context, tenantID string, provider string, vectaRegion string) (RegionMapping, error)

	CreateBinding(ctx context.Context, binding CloudKeyBinding) error
	UpdateBinding(ctx context.Context, binding CloudKeyBinding) error
	GetBinding(ctx context.Context, tenantID string, bindingID string) (CloudKeyBinding, error)
	ListBindings(ctx context.Context, tenantID string, provider string, accountID string, keyID string, limit int, offset int) ([]CloudKeyBinding, error)

	CreateSyncJob(ctx context.Context, job SyncJob) error
	CompleteSyncJob(ctx context.Context, tenantID string, jobID string, status string, summaryJSON string, errMessage string) error
	GetSyncJob(ctx context.Context, tenantID string, jobID string) (SyncJob, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) CreateAccount(ctx context.Context, account CloudAccount) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cloud_accounts (
	id, tenant_id, provider, name, default_region, status,
	creds_wrapped_dek, creds_wrapped_dek_iv, creds_ciphertext, creds_data_iv,
	created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,
	$7,$8,$9,$10,
	CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
`, account.ID, account.TenantID, account.Provider, account.Name, account.DefaultRegion, account.Status,
		account.CredentialsWrappedDEK, account.CredentialsWrappedDEKIV, account.CredentialsCiphertext, account.CredentialsDataIV)
	return err
}

func (s *SQLStore) GetAccount(ctx context.Context, tenantID string, accountID string) (CloudAccount, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, provider, name, default_region, status,
	   creds_wrapped_dek, creds_wrapped_dek_iv, creds_ciphertext, creds_data_iv,
	   created_at, updated_at
FROM cloud_accounts
WHERE tenant_id = $1 AND id = $2
`, tenantID, accountID)
	out, err := scanAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudAccount{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListAccounts(ctx context.Context, tenantID string, provider string) ([]CloudAccount, error) {
	q := `
SELECT id, tenant_id, provider, name, default_region, status,
	   creds_wrapped_dek, creds_wrapped_dek_iv, creds_ciphertext, creds_data_iv,
	   created_at, updated_at
FROM cloud_accounts
WHERE tenant_id = $1
`
	args := []interface{}{tenantID}
	if strings.TrimSpace(provider) != "" {
		q += " AND provider = $2"
		args = append(args, strings.TrimSpace(provider))
	}
	q += " ORDER BY created_at DESC"
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]CloudAccount, 0)
	for rows.Next() {
		item, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteAccountCascade(ctx context.Context, tenantID string, accountID string) (DeleteCloudAccountResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	accountID = strings.TrimSpace(accountID)
	if tenantID == "" || accountID == "" {
		return DeleteCloudAccountResult{}, errors.New("tenant_id and account_id are required")
	}

	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return DeleteCloudAccountResult{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	var provider string
	if err := tx.QueryRowContext(ctx, `
SELECT provider
FROM cloud_accounts
WHERE tenant_id = $1 AND id = $2
`, tenantID, accountID).Scan(&provider); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeleteCloudAccountResult{}, errNotFound
		}
		return DeleteCloudAccountResult{}, err
	}

	bindRes, err := tx.ExecContext(ctx, `
DELETE FROM cloud_key_bindings
WHERE tenant_id = $1 AND account_id = $2
`, tenantID, accountID)
	if err != nil {
		return DeleteCloudAccountResult{}, err
	}
	deletedBindings, _ := bindRes.RowsAffected()

	jobRes, err := tx.ExecContext(ctx, `
DELETE FROM cloud_sync_jobs
WHERE tenant_id = $1 AND account_id = $2
`, tenantID, accountID)
	if err != nil {
		return DeleteCloudAccountResult{}, err
	}
	deletedJobs, _ := jobRes.RowsAffected()

	acctRes, err := tx.ExecContext(ctx, `
DELETE FROM cloud_accounts
WHERE tenant_id = $1 AND id = $2
`, tenantID, accountID)
	if err != nil {
		return DeleteCloudAccountResult{}, err
	}
	deletedAccounts, _ := acctRes.RowsAffected()
	if deletedAccounts == 0 {
		return DeleteCloudAccountResult{}, errNotFound
	}

	var remainingForProvider int64
	if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM cloud_accounts
WHERE tenant_id = $1 AND provider = $2
`, tenantID, provider).Scan(&remainingForProvider); err != nil {
		return DeleteCloudAccountResult{}, err
	}

	var deletedMappings int64
	if remainingForProvider == 0 {
		mapRes, err := tx.ExecContext(ctx, `
DELETE FROM cloud_region_mappings
WHERE tenant_id = $1 AND provider = $2
`, tenantID, provider)
		if err != nil {
			return DeleteCloudAccountResult{}, err
		}
		deletedMappings, _ = mapRes.RowsAffected()
	}

	if err := tx.Commit(); err != nil {
		return DeleteCloudAccountResult{}, err
	}
	return DeleteCloudAccountResult{
		TenantID:              tenantID,
		AccountID:             accountID,
		Provider:              provider,
		DeletedBindings:       deletedBindings,
		DeletedSyncJobs:       deletedJobs,
		DeletedRegionMappings: deletedMappings,
	}, nil
}

func (s *SQLStore) UpdateAccountStatus(ctx context.Context, tenantID string, accountID string, status string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE cloud_accounts
SET status = $1, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $2 AND id = $3
`, strings.TrimSpace(status), tenantID, accountID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) SetRegionMapping(ctx context.Context, mapping RegionMapping) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cloud_region_mappings (
	tenant_id, provider, vecta_region, cloud_region, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, provider, vecta_region) DO UPDATE SET
	cloud_region = excluded.cloud_region,
	updated_at = excluded.updated_at
`, mapping.TenantID, mapping.Provider, mapping.VectaRegion, mapping.CloudRegion)
	return err
}

func (s *SQLStore) ListRegionMappings(ctx context.Context, tenantID string, provider string) ([]RegionMapping, error) {
	q := `
SELECT tenant_id, provider, vecta_region, cloud_region, created_at, updated_at
FROM cloud_region_mappings
WHERE tenant_id = $1
`
	args := []interface{}{tenantID}
	if strings.TrimSpace(provider) != "" {
		q += " AND provider = $2"
		args = append(args, strings.TrimSpace(provider))
	}
	q += " ORDER BY provider, vecta_region"
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]RegionMapping, 0)
	for rows.Next() {
		item, err := scanRegionMapping(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetRegionMapping(ctx context.Context, tenantID string, provider string, vectaRegion string) (RegionMapping, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, provider, vecta_region, cloud_region, created_at, updated_at
FROM cloud_region_mappings
WHERE tenant_id = $1 AND provider = $2 AND vecta_region = $3
`, tenantID, provider, vectaRegion)
	out, err := scanRegionMapping(row)
	if errors.Is(err, sql.ErrNoRows) {
		return RegionMapping{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) CreateBinding(ctx context.Context, binding CloudKeyBinding) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cloud_key_bindings (
	id, tenant_id, key_id, provider, account_id, cloud_key_id, cloud_key_ref,
	region, sync_status, last_synced_at, metadata_json, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,
	$8,$9,$10,$11,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
`, binding.ID, binding.TenantID, binding.KeyID, binding.Provider, binding.AccountID, binding.CloudKeyID, binding.CloudKeyRef,
		binding.Region, binding.SyncStatus, nullableTime(binding.LastSyncedAt), validJSONOr(binding.MetadataJSON, "{}"))
	return err
}

func (s *SQLStore) UpdateBinding(ctx context.Context, binding CloudKeyBinding) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE cloud_key_bindings
SET key_id = $1,
	provider = $2,
	account_id = $3,
	cloud_key_id = $4,
	cloud_key_ref = $5,
	region = $6,
	sync_status = $7,
	last_synced_at = $8,
	metadata_json = $9,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $10 AND id = $11
`, binding.KeyID, binding.Provider, binding.AccountID, binding.CloudKeyID, binding.CloudKeyRef,
		binding.Region, binding.SyncStatus, nullableTime(binding.LastSyncedAt), validJSONOr(binding.MetadataJSON, "{}"),
		binding.TenantID, binding.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetBinding(ctx context.Context, tenantID string, bindingID string) (CloudKeyBinding, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, key_id, provider, account_id, cloud_key_id, cloud_key_ref,
	   region, sync_status, last_synced_at, metadata_json, created_at, updated_at
FROM cloud_key_bindings
WHERE tenant_id = $1 AND id = $2
`, tenantID, bindingID)
	out, err := scanBinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudKeyBinding{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListBindings(ctx context.Context, tenantID string, provider string, accountID string, keyID string, limit int, offset int) ([]CloudKeyBinding, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `
SELECT id, tenant_id, key_id, provider, account_id, cloud_key_id, cloud_key_ref,
	   region, sync_status, last_synced_at, metadata_json, created_at, updated_at
FROM cloud_key_bindings
WHERE tenant_id = $1
`
	args := []interface{}{tenantID}
	idx := 2
	if strings.TrimSpace(provider) != "" {
		q += " AND provider = $" + itoa(idx)
		args = append(args, strings.TrimSpace(provider))
		idx++
	}
	if strings.TrimSpace(accountID) != "" {
		q += " AND account_id = $" + itoa(idx)
		args = append(args, strings.TrimSpace(accountID))
		idx++
	}
	if strings.TrimSpace(keyID) != "" {
		q += " AND key_id = $" + itoa(idx)
		args = append(args, strings.TrimSpace(keyID))
		idx++
	}
	q += " ORDER BY updated_at DESC LIMIT $" + itoa(idx) + " OFFSET $" + itoa(idx+1)
	args = append(args, limit, offset)
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]CloudKeyBinding, 0)
	for rows.Next() {
		item, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateSyncJob(ctx context.Context, job SyncJob) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cloud_sync_jobs (
	id, tenant_id, provider, account_id, mode, status, summary_json, error_message,
	started_at, completed_at, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,
	$9,$10,CURRENT_TIMESTAMP
)
`, job.ID, job.TenantID, job.Provider, job.AccountID, job.Mode, job.Status, validJSONOr(job.SummaryJSON, "{}"), job.ErrorMessage,
		job.StartedAt, nullableTime(job.CompletedAt))
	return err
}

func (s *SQLStore) CompleteSyncJob(ctx context.Context, tenantID string, jobID string, status string, summaryJSON string, errMessage string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE cloud_sync_jobs
SET status = $1, summary_json = $2, error_message = $3, completed_at = $4
WHERE tenant_id = $5 AND id = $6
`, status, validJSONOr(summaryJSON, "{}"), errMessage, nowUTC(), tenantID, jobID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetSyncJob(ctx context.Context, tenantID string, jobID string) (SyncJob, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, provider, account_id, mode, status, summary_json, error_message,
	   started_at, completed_at, created_at
FROM cloud_sync_jobs
WHERE tenant_id = $1 AND id = $2
`, tenantID, jobID)
	out, err := scanSyncJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SyncJob{}, errNotFound
	}
	return out, err
}

func scanAccount(scanner interface {
	Scan(dest ...interface{}) error
}) (CloudAccount, error) {
	var (
		out        CloudAccount
		createdRaw interface{}
		updatedRaw interface{}
	)
	err := scanner.Scan(
		&out.ID, &out.TenantID, &out.Provider, &out.Name, &out.DefaultRegion, &out.Status,
		&out.CredentialsWrappedDEK, &out.CredentialsWrappedDEKIV, &out.CredentialsCiphertext, &out.CredentialsDataIV,
		&createdRaw, &updatedRaw,
	)
	if err != nil {
		return CloudAccount{}, err
	}
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func scanRegionMapping(scanner interface {
	Scan(dest ...interface{}) error
}) (RegionMapping, error) {
	var (
		out        RegionMapping
		createdRaw interface{}
		updatedRaw interface{}
	)
	if err := scanner.Scan(&out.TenantID, &out.Provider, &out.VectaRegion, &out.CloudRegion, &createdRaw, &updatedRaw); err != nil {
		return RegionMapping{}, err
	}
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func scanBinding(scanner interface {
	Scan(dest ...interface{}) error
}) (CloudKeyBinding, error) {
	var (
		out           CloudKeyBinding
		lastSyncedRaw interface{}
		createdRaw    interface{}
		updatedRaw    interface{}
	)
	if err := scanner.Scan(
		&out.ID, &out.TenantID, &out.KeyID, &out.Provider, &out.AccountID, &out.CloudKeyID, &out.CloudKeyRef,
		&out.Region, &out.SyncStatus, &lastSyncedRaw, &out.MetadataJSON, &createdRaw, &updatedRaw,
	); err != nil {
		return CloudKeyBinding{}, err
	}
	out.LastSyncedAt = parseTimeValue(lastSyncedRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	if out.MetadataJSON == "" {
		out.MetadataJSON = "{}"
	}
	return out, nil
}

func scanSyncJob(scanner interface {
	Scan(dest ...interface{}) error
}) (SyncJob, error) {
	var (
		out          SyncJob
		startedRaw   interface{}
		completedRaw interface{}
		createdRaw   interface{}
	)
	if err := scanner.Scan(
		&out.ID, &out.TenantID, &out.Provider, &out.AccountID, &out.Mode, &out.Status, &out.SummaryJSON, &out.ErrorMessage,
		&startedRaw, &completedRaw, &createdRaw,
	); err != nil {
		return SyncJob{}, err
	}
	out.StartedAt = parseTimeValue(startedRaw)
	out.CompletedAt = parseTimeValue(completedRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	if out.SummaryJSON == "" {
		out.SummaryJSON = "{}"
	}
	return out, nil
}

func parseTimeValue(v interface{}) time.Time {
	switch x := v.(type) {
	case time.Time:
		return x.UTC()
	case string:
		return parseTimeString(x)
	case []byte:
		return parseTimeString(string(x))
	default:
		return time.Time{}
	}
}

func parseTimeString(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, f := range formats {
		if ts, err := time.Parse(f, v); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func nullableTime(v time.Time) interface{} {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := false
	if v < 0 {
		neg = true
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
