package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

func (s *SQLStore) CreateAzureEKMConfig(ctx context.Context, cfg AzureEKMConfig) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_azure_configs (
	tenant_id, id, azure_tenant_id, subscription_id, resource_group,
	vault_name, vault_url, managed_hsm_name, managed_hsm_url,
	client_id, client_secret, auth_mode, status, key_mappings, last_sync_at, created_at
) VALUES (
	$1,$2,$3,$4,$5,
	$6,$7,$8,$9,
	$10,$11,$12,$13,$14,$15,CURRENT_TIMESTAMP
)
`, cfg.TenantID, cfg.ID, cfg.AzureTenantID, cfg.SubscriptionID, cfg.ResourceGroup,
		cfg.VaultName, cfg.VaultURL, cfg.ManagedHSMName, cfg.ManagedHSMURL,
		cfg.ClientID, cfg.ClientSecret, cfg.AuthMode, cfg.Status, cfg.KeyMappings, nullableTime(cfg.LastSyncAt))
	return err
}

func (s *SQLStore) GetAzureEKMConfig(ctx context.Context, tenantID, configID string) (AzureEKMConfig, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, azure_tenant_id, subscription_id, resource_group,
       vault_name, vault_url, managed_hsm_name, managed_hsm_url,
       client_id, client_secret, auth_mode, status, key_mappings, last_sync_at, created_at
FROM ekm_azure_configs
WHERE tenant_id = $1 AND id = $2
`, tenantID, configID)
	out, err := scanAzureEKMConfig(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AzureEKMConfig{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListAzureEKMConfigs(ctx context.Context, tenantID string) ([]AzureEKMConfig, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, azure_tenant_id, subscription_id, resource_group,
       vault_name, vault_url, managed_hsm_name, managed_hsm_url,
       client_id, client_secret, auth_mode, status, key_mappings, last_sync_at, created_at
FROM ekm_azure_configs
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT 500
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]AzureEKMConfig, 0)
	for rows.Next() {
		item, scanErr := scanAzureEKMConfig(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateAzureEKMConfig(ctx context.Context, cfg AzureEKMConfig) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_azure_configs
SET azure_tenant_id = $1,
    subscription_id = $2,
    resource_group = $3,
    vault_name = $4,
    vault_url = $5,
    managed_hsm_name = $6,
    managed_hsm_url = $7,
    client_id = $8,
    client_secret = CASE WHEN $9 = '' THEN client_secret ELSE $9 END,
    auth_mode = $10,
    status = $11,
    key_mappings = $12,
    last_sync_at = CASE WHEN $13::TEXT = '' THEN last_sync_at ELSE $13 END
WHERE tenant_id = $14 AND id = $15
`, cfg.AzureTenantID, cfg.SubscriptionID, cfg.ResourceGroup,
		cfg.VaultName, cfg.VaultURL, cfg.ManagedHSMName, cfg.ManagedHSMURL,
		cfg.ClientID, cfg.ClientSecret, cfg.AuthMode, cfg.Status, cfg.KeyMappings,
		nullableTime(cfg.LastSyncAt), cfg.TenantID, cfg.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) DeleteAzureEKMConfig(ctx context.Context, tenantID, configID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM ekm_azure_configs
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

func (s *SQLStore) CreateAzureKeyMapping(ctx context.Context, m AzureKeyMapping) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ekm_azure_key_mappings (
	tenant_id, id, config_id, vecta_key_id, azure_key_name,
	azure_key_version, azure_key_id, purpose, sync_status, last_sync_at, created_at
) VALUES (
	$1,$2,$3,$4,$5,
	$6,$7,$8,$9,$10,CURRENT_TIMESTAMP
)
`, m.TenantID, m.ID, m.ConfigID, m.VectaKeyID, m.AzureKeyName,
		m.AzureKeyVersion, m.AzureKeyID, m.Purpose, m.SyncStatus, nullableTime(m.LastSyncAt))
	return err
}

func (s *SQLStore) ListAzureKeyMappings(ctx context.Context, tenantID, configID string) ([]AzureKeyMapping, error) {
	q := `
SELECT tenant_id, id, config_id, vecta_key_id, azure_key_name,
       azure_key_version, azure_key_id, purpose, sync_status, last_sync_at, created_at
FROM ekm_azure_key_mappings
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
	out := make([]AzureKeyMapping, 0)
	for rows.Next() {
		item, scanErr := scanAzureKeyMapping(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateAzureKeyMappingSync(ctx context.Context, tenantID, mappingID, azureKeyID, azureKeyVersion, syncStatus string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ekm_azure_key_mappings
SET azure_key_id = CASE WHEN $1 = '' THEN azure_key_id ELSE $1 END,
    azure_key_version = CASE WHEN $2 = '' THEN azure_key_version ELSE $2 END,
    sync_status = $3,
    last_sync_at = CURRENT_TIMESTAMP
WHERE tenant_id = $4 AND id = $5
`, strings.TrimSpace(azureKeyID), strings.TrimSpace(azureKeyVersion), syncStatus, tenantID, mappingID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) DeleteAzureKeyMapping(ctx context.Context, tenantID, mappingID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM ekm_azure_key_mappings
WHERE tenant_id = $1 AND id = $2
`, tenantID, mappingID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func scanAzureEKMConfig(scanner interface {
	Scan(dest ...interface{}) error
}) (AzureEKMConfig, error) {
	var (
		out        AzureEKMConfig
		lastSync   interface{}
		createdRaw interface{}
	)
	err := scanner.Scan(
		&out.TenantID, &out.ID, &out.AzureTenantID, &out.SubscriptionID, &out.ResourceGroup,
		&out.VaultName, &out.VaultURL, &out.ManagedHSMName, &out.ManagedHSMURL,
		&out.ClientID, &out.ClientSecret, &out.AuthMode, &out.Status, &out.KeyMappings, &lastSync, &createdRaw,
	)
	if err != nil {
		return AzureEKMConfig{}, err
	}
	out.LastSyncAt = parseTimeValue(lastSync)
	out.CreatedAt = parseTimeValue(createdRaw)
	return out, nil
}

func scanAzureKeyMapping(scanner interface {
	Scan(dest ...interface{}) error
}) (AzureKeyMapping, error) {
	var (
		out        AzureKeyMapping
		lastSync   interface{}
		createdRaw interface{}
	)
	err := scanner.Scan(
		&out.TenantID, &out.ID, &out.ConfigID, &out.VectaKeyID, &out.AzureKeyName,
		&out.AzureKeyVersion, &out.AzureKeyID, &out.Purpose, &out.SyncStatus, &lastSync, &createdRaw,
	)
	if err != nil {
		return AzureKeyMapping{}, err
	}
	out.LastSyncAt = parseTimeValue(lastSync)
	out.CreatedAt = parseTimeValue(createdRaw)
	return out, nil
}
