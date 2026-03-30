package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func (s *SQLStore) CreateGoogleCSEConfig(ctx context.Context, cfg GoogleCSEConfig) error {
	domainsJSON, _ := json.Marshal(cfg.AllowedDomains)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_google_cse_configs (
	tenant_id, id, google_workspace_customer_id, service_account_email,
	service_account_key_json, allowed_domains, kacls_endpoint,
	status, key_count, last_activity_at, created_at
) VALUES (
	$1,$2,$3,$4,
	$5,$6,$7,
	$8,$9,$10,CURRENT_TIMESTAMP
)
`, cfg.TenantID, cfg.ID, cfg.GoogleWorkspaceCustomerID, cfg.ServiceAccountEmail,
		cfg.ServiceAccountKeyJSON, string(domainsJSON), cfg.KACLSEndpoint,
		cfg.Status, cfg.KeyCount, nullableTime(cfg.LastActivityAt))
	return err
}

func (s *SQLStore) GetGoogleCSEConfig(ctx context.Context, tenantID, configID string) (GoogleCSEConfig, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, google_workspace_customer_id, service_account_email,
       service_account_key_json, allowed_domains, kacls_endpoint,
       status, key_count, last_activity_at, created_at
FROM ekm_google_cse_configs
WHERE tenant_id = $1 AND id = $2
`, tenantID, configID)
	out, err := scanGoogleCSEConfig(row)
	if errors.Is(err, sql.ErrNoRows) {
		return GoogleCSEConfig{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListGoogleCSEConfigs(ctx context.Context, tenantID string) ([]GoogleCSEConfig, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, google_workspace_customer_id, service_account_email,
       service_account_key_json, allowed_domains, kacls_endpoint,
       status, key_count, last_activity_at, created_at
FROM ekm_google_cse_configs
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT 500
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]GoogleCSEConfig, 0)
	for rows.Next() {
		item, scanErr := scanGoogleCSEConfig(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateGoogleCSEConfig(ctx context.Context, cfg GoogleCSEConfig) error {
	domainsJSON, _ := json.Marshal(cfg.AllowedDomains)
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_google_cse_configs
SET google_workspace_customer_id = $1,
    service_account_email = $2,
    service_account_key_json = CASE WHEN $3 = '' THEN service_account_key_json ELSE $3 END,
    allowed_domains = $4,
    kacls_endpoint = $5,
    status = $6,
    key_count = $7,
    last_activity_at = CASE WHEN $8::TEXT = '' THEN last_activity_at ELSE $8 END
WHERE tenant_id = $9 AND id = $10
`, cfg.GoogleWorkspaceCustomerID, cfg.ServiceAccountEmail, cfg.ServiceAccountKeyJSON,
		string(domainsJSON), cfg.KACLSEndpoint, cfg.Status, cfg.KeyCount,
		nullableTime(cfg.LastActivityAt), cfg.TenantID, cfg.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) DeleteGoogleCSEConfig(ctx context.Context, tenantID, configID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM ekm_google_cse_configs
WHERE tenant_id = $1 AND id = $2
`, tenantID, configID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateGoogleCSEKey(ctx context.Context, key GoogleCSEKey) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_google_cse_keys (
	tenant_id, id, config_id, key_name, vecta_key_id,
	google_key_uri, purpose, status, wrap_count, unwrap_count,
	last_used_at, created_at
) VALUES (
	$1,$2,$3,$4,$5,
	$6,$7,$8,$9,$10,
	$11,CURRENT_TIMESTAMP
)
`, key.TenantID, key.ID, key.ConfigID, key.KeyName, key.VectaKeyID,
		key.GoogleKeyURI, key.Purpose, key.Status, key.WrapCount, key.UnwrapCount,
		nullableTime(key.LastUsedAt))
	return err
}

func (s *SQLStore) GetGoogleCSEKey(ctx context.Context, tenantID, keyID string) (GoogleCSEKey, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, config_id, key_name, vecta_key_id,
       google_key_uri, purpose, status, wrap_count, unwrap_count,
       last_used_at, created_at
FROM ekm_google_cse_keys
WHERE tenant_id = $1 AND id = $2
`, tenantID, keyID)
	out, err := scanGoogleCSEKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return GoogleCSEKey{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) GetGoogleCSEKeyByURI(ctx context.Context, tenantID, keyURI string) (GoogleCSEKey, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, config_id, key_name, vecta_key_id,
       google_key_uri, purpose, status, wrap_count, unwrap_count,
       last_used_at, created_at
FROM ekm_google_cse_keys
WHERE tenant_id = $1 AND google_key_uri = $2
`, tenantID, keyURI)
	out, err := scanGoogleCSEKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return GoogleCSEKey{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListGoogleCSEKeys(ctx context.Context, tenantID, configID string) ([]GoogleCSEKey, error) {
	q := `
SELECT tenant_id, id, config_id, key_name, vecta_key_id,
       google_key_uri, purpose, status, wrap_count, unwrap_count,
       last_used_at, created_at
FROM ekm_google_cse_keys
WHERE tenant_id = $1
`
	args := []interface{}{tenantID}
	if strings.TrimSpace(configID) != "" {
		q += " AND config_id = $2"
		args = append(args, strings.TrimSpace(configID))
	}
	q += " ORDER BY created_at DESC LIMIT 1000"
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]GoogleCSEKey, 0)
	for rows.Next() {
		item, scanErr := scanGoogleCSEKey(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateGoogleCSEKeyStatus(ctx context.Context, tenantID, keyID, status string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_google_cse_keys
SET status = $1
WHERE tenant_id = $2 AND id = $3
`, status, tenantID, keyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) IncrementGoogleCSEKeyUsage(ctx context.Context, tenantID, keyID, operation string) error {
	var q string
	switch operation {
	case "wrap":
		q = `UPDATE ekm_google_cse_keys SET wrap_count = wrap_count + 1, last_used_at = $1 WHERE tenant_id = $2 AND id = $3`
	case "unwrap":
		q = `UPDATE ekm_google_cse_keys SET unwrap_count = unwrap_count + 1, last_used_at = $1 WHERE tenant_id = $2 AND id = $3`
	default:
		return errors.New("invalid operation: must be wrap or unwrap")
	}
	_, err := s.db.SQL().ExecContext(ctx, q, time.Now().UTC(), tenantID, keyID)
	return err
}

func (s *SQLStore) DeleteGoogleCSEKey(ctx context.Context, tenantID, keyID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM ekm_google_cse_keys
WHERE tenant_id = $1 AND id = $2
`, tenantID, keyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func scanGoogleCSEConfig(scanner interface {
	Scan(dest ...interface{}) error
}) (GoogleCSEConfig, error) {
	var (
		out            GoogleCSEConfig
		domainsRaw     string
		lastActivityAt interface{}
		createdRaw     interface{}
	)
	err := scanner.Scan(
		&out.TenantID, &out.ID, &out.GoogleWorkspaceCustomerID, &out.ServiceAccountEmail,
		&out.ServiceAccountKeyJSON, &domainsRaw, &out.KACLSEndpoint,
		&out.Status, &out.KeyCount, &lastActivityAt, &createdRaw,
	)
	if err != nil {
		return GoogleCSEConfig{}, err
	}
	out.LastActivityAt = parseTimeValue(lastActivityAt)
	out.CreatedAt = parseTimeValue(createdRaw)
	if domainsRaw != "" {
		_ = json.Unmarshal([]byte(domainsRaw), &out.AllowedDomains)
	}
	if out.AllowedDomains == nil {
		out.AllowedDomains = []string{}
	}
	return out, nil
}

func scanGoogleCSEKey(scanner interface {
	Scan(dest ...interface{}) error
}) (GoogleCSEKey, error) {
	var (
		out        GoogleCSEKey
		lastUsed   interface{}
		createdRaw interface{}
	)
	err := scanner.Scan(
		&out.TenantID, &out.ID, &out.ConfigID, &out.KeyName, &out.VectaKeyID,
		&out.GoogleKeyURI, &out.Purpose, &out.Status, &out.WrapCount, &out.UnwrapCount,
		&lastUsed, &createdRaw,
	)
	if err != nil {
		return GoogleCSEKey{}, err
	}
	out.LastUsedAt = parseTimeValue(lastUsed)
	out.CreatedAt = parseTimeValue(createdRaw)
	return out, nil
}
