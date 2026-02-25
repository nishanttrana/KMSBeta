package main

import (
	"context"
	"database/sql"
	"encoding/json"
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

func (s *SQLStore) CreateTokenVault(ctx context.Context, item TokenVault) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO token_vaults (
	tenant_id, id, name, mode, token_type, format, key_id, custom_regex, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.Name, item.Mode, item.TokenType, item.Format, item.KeyID, item.CustomRegex)
	return err
}

func (s *SQLStore) ListTokenVaults(ctx context.Context, tenantID string, limit int, offset int) ([]TokenVault, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, name, mode, token_type, format, key_id, custom_regex, created_at
FROM token_vaults
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3
`, strings.TrimSpace(tenantID), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]TokenVault, 0)
	for rows.Next() {
		item, err := scanTokenVault(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetTokenVault(ctx context.Context, tenantID string, id string) (TokenVault, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, name, mode, token_type, format, key_id, custom_regex, created_at
FROM token_vaults
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanTokenVault(row)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenVault{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) DeleteTokenVault(ctx context.Context, tenantID string, id string) error {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, `
DELETE FROM tokens
WHERE tenant_id = $1 AND vault_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id)); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
DELETE FROM token_vaults
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return tx.Commit()
}

func (s *SQLStore) CountTokensByVault(ctx context.Context, tenantID string, vaultID string) (int, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*)
FROM tokens
WHERE tenant_id = $1 AND vault_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(vaultID))
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *SQLStore) CreateToken(ctx context.Context, item TokenRecord) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO tokens (
	tenant_id, id, vault_id, token, original_enc, original_hash, format_metadata_json, use_count, use_limit, renew_count, metadata_tags_json, created_at, expires_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP,$12
)
`, item.TenantID, item.ID, item.VaultID, item.Token, item.OriginalEnc, item.OriginalHash, mustJSON(item.FormatMetadata, "{}"), item.UseCount, item.UseLimit, item.RenewCount, mustJSON(item.MetadataTags, "{}"), nullableTime(item.ExpiresAt))
	return err
}

func (s *SQLStore) GetTokenByValue(ctx context.Context, tenantID string, token string) (TokenRecord, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, vault_id, token, original_enc, original_hash, format_metadata_json, use_count, use_limit, renew_count, metadata_tags_json, created_at, expires_at
FROM tokens
WHERE tenant_id = $1 AND token = $2
ORDER BY created_at DESC
LIMIT 1
`, strings.TrimSpace(tenantID), strings.TrimSpace(token))
	item, err := scanTokenRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenRecord{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) GetTokenByHash(ctx context.Context, tenantID string, vaultID string, hash string) (TokenRecord, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, vault_id, token, original_enc, original_hash, format_metadata_json, use_count, use_limit, renew_count, metadata_tags_json, created_at, expires_at
FROM tokens
WHERE tenant_id = $1 AND vault_id = $2 AND original_hash = $3
ORDER BY created_at DESC
LIMIT 1
`, strings.TrimSpace(tenantID), strings.TrimSpace(vaultID), strings.TrimSpace(hash))
	item, err := scanTokenRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenRecord{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ConsumeTokenUse(ctx context.Context, tenantID string, id string) (TokenRecord, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
UPDATE tokens
SET use_count = use_count + 1
WHERE tenant_id = $1
  AND id = $2
  AND (use_limit = 0 OR use_count < use_limit)
RETURNING tenant_id, id, vault_id, token, original_enc, original_hash, format_metadata_json, use_count, use_limit, renew_count, metadata_tags_json, created_at, expires_at
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanTokenRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenRecord{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) RenewTokenLease(ctx context.Context, tenantID string, id string, expiresAt time.Time, maxRenewals int) (TokenRecord, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
UPDATE tokens
SET expires_at = $3,
    renew_count = renew_count + 1
WHERE tenant_id = $1
  AND id = $2
  AND ($4 <= 0 OR renew_count < $4)
RETURNING tenant_id, id, vault_id, token, original_enc, original_hash, format_metadata_json, use_count, use_limit, renew_count, metadata_tags_json, created_at, expires_at
`, strings.TrimSpace(tenantID), strings.TrimSpace(id), nullableTime(expiresAt), maxRenewals)
	item, err := scanTokenRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenRecord{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) CreateMaskingPolicy(ctx context.Context, item MaskingPolicy) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO masking_policies (
	tenant_id, id, name, target_type, field_path, mask_pattern, roles_full_json, roles_partial_json, roles_redacted_json, consistent, key_id, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.Name, item.TargetType, item.FieldPath, item.MaskPattern, mustJSON(item.RolesFull, "[]"), mustJSON(item.RolesPartial, "[]"), mustJSON(item.RolesRedacted, "[]"), item.Consistent, item.KeyID)
	return err
}

func (s *SQLStore) UpdateMaskingPolicy(ctx context.Context, item MaskingPolicy) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE masking_policies
SET name = $3,
	target_type = $4,
	field_path = $5,
	mask_pattern = $6,
	roles_full_json = $7,
	roles_partial_json = $8,
	roles_redacted_json = $9,
	consistent = $10,
	key_id = $11
WHERE tenant_id = $1 AND id = $2
`, item.TenantID, item.ID, item.Name, item.TargetType, item.FieldPath, item.MaskPattern, mustJSON(item.RolesFull, "[]"), mustJSON(item.RolesPartial, "[]"), mustJSON(item.RolesRedacted, "[]"), item.Consistent, item.KeyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) DeleteMaskingPolicy(ctx context.Context, tenantID string, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM masking_policies
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) ListMaskingPolicies(ctx context.Context, tenantID string) ([]MaskingPolicy, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, name, target_type, field_path, mask_pattern, roles_full_json, roles_partial_json, roles_redacted_json, consistent, key_id, created_at
FROM masking_policies
WHERE tenant_id = $1
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MaskingPolicy, 0)
	for rows.Next() {
		item, err := scanMaskingPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetMaskingPolicy(ctx context.Context, tenantID string, id string) (MaskingPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, name, target_type, field_path, mask_pattern, roles_full_json, roles_partial_json, roles_redacted_json, consistent, key_id, created_at
FROM masking_policies
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanMaskingPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return MaskingPolicy{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) CreateRedactionPolicy(ctx context.Context, item RedactionPolicy) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO redaction_policies (
	tenant_id, id, name, patterns_json, scope, action, placeholder, applies_to_json, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.Name, mustJSON(item.Patterns, "[]"), item.Scope, item.Action, item.Placeholder, mustJSON(item.AppliesTo, "[]"))
	return err
}

func (s *SQLStore) ListRedactionPolicies(ctx context.Context, tenantID string) ([]RedactionPolicy, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, name, patterns_json, scope, action, placeholder, applies_to_json, created_at
FROM redaction_policies
WHERE tenant_id = $1
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]RedactionPolicy, 0)
	for rows.Next() {
		item, err := scanRedactionPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetRedactionPolicy(ctx context.Context, tenantID string, id string) (RedactionPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, name, patterns_json, scope, action, placeholder, applies_to_json, created_at
FROM redaction_policies
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanRedactionPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return RedactionPolicy{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) CreateFLEMetadata(ctx context.Context, item FLEMetadata) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO fle_metadata (
	tenant_id, id, document_id, field_path, key_id, key_version, algorithm, iv, searchable, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.DocumentID, item.FieldPath, item.KeyID, item.KeyVersion, item.Algorithm, item.IV, item.Searchable)
	return err
}

func (s *SQLStore) ListFLEMetadataByDocument(ctx context.Context, tenantID string, documentID string) ([]FLEMetadata, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, document_id, field_path, key_id, key_version, algorithm, iv, searchable, created_at
FROM fle_metadata
WHERE tenant_id = $1 AND document_id = $2
ORDER BY created_at ASC
`, strings.TrimSpace(tenantID), strings.TrimSpace(documentID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]FLEMetadata, 0)
	for rows.Next() {
		item, err := scanFLEMetadata(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetDataProtectionPolicy(ctx context.Context, tenantID string) (DataProtectionPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id,
       allowed_data_algorithms_json,
       algorithm_profile_policy_json,
       require_aad_for_aead,
       required_aad_claims_json,
       enforce_aad_tenant_binding,
       allowed_aad_environments_json,
       max_fields_per_operation,
       max_document_bytes,
       max_app_crypto_request_bytes,
       max_app_crypto_batch_size,
       require_symmetric_keys,
       require_fips_keys,
       min_key_size_bits,
       allowed_encrypt_field_paths_json,
       allowed_decrypt_field_paths_json,
       denied_decrypt_field_paths_json,
       block_wildcard_field_paths,
       allow_deterministic_encryption,
       allow_searchable_encryption,
       allow_range_search,
       envelope_kek_allowlist_json,
       max_wrapped_dek_age_minutes,
       require_rewrap_on_dek_age_exceeded,
       allow_vaultless_tokenization,
       tokenization_mode_policy_json,
       token_format_policy_json,
       require_token_ttl,
       max_token_ttl_hours,
       allow_token_renewal,
       max_token_renewals,
       allow_one_time_tokens,
       detokenize_allowed_purposes_json,
       detokenize_allowed_workflows_json,
       require_detokenize_justification,
       allow_bulk_tokenize,
       allow_bulk_detokenize,
       allow_redaction_detect_only,
       allowed_redaction_detectors_json,
       allowed_redaction_actions_json,
       allow_custom_regex_tokens,
       max_custom_regex_length,
       max_custom_regex_groups,
       max_token_batch,
       max_detokenize_batch,
       require_token_context_tags,
       required_token_context_keys_json,
       masking_role_policy_json,
       token_metadata_retention_days,
       redaction_event_retention_days,
       COALESCE(updated_by,''),
       updated_at
FROM data_protection_policy
WHERE tenant_id = $1
`, strings.TrimSpace(tenantID))
	var (
		out                  DataProtectionPolicy
		algorithmsJSON       string
		algorithmProfileJSON string
		requiredAADJSON      string
		allowedAADEEnvJSON   string
		encryptPathsJSON     string
		decryptPathsJSON     string
		deniedDecryptJSON    string
		envelopeKEKJSON      string
		modeJSON             string
		formatJSON           string
		purposeJSON          string
		workflowJSON         string
		detectorsJSON        string
		actionsJSON          string
		contextJSON          string
		maskingJSON          string
		updatedRaw           interface{}
	)
	if err := row.Scan(
		&out.TenantID,
		&algorithmsJSON,
		&algorithmProfileJSON,
		&out.RequireAADForAEAD,
		&requiredAADJSON,
		&out.EnforceAADTenantBinding,
		&allowedAADEEnvJSON,
		&out.MaxFieldsPerOperation,
		&out.MaxDocumentBytes,
		&out.MaxAppCryptoRequestBytes,
		&out.MaxAppCryptoBatchSize,
		&out.RequireSymmetricKeys,
		&out.RequireFIPSKeys,
		&out.MinKeySizeBits,
		&encryptPathsJSON,
		&decryptPathsJSON,
		&deniedDecryptJSON,
		&out.BlockWildcardFieldPaths,
		&out.AllowDeterministicEncryption,
		&out.AllowSearchableEncryption,
		&out.AllowRangeSearch,
		&envelopeKEKJSON,
		&out.MaxWrappedDEKAgeMinutes,
		&out.RequireRewrapOnDEKAgeExceeded,
		&out.AllowVaultlessTokenization,
		&modeJSON,
		&formatJSON,
		&out.RequireTokenTTL,
		&out.MaxTokenTTLHours,
		&out.AllowTokenRenewal,
		&out.MaxTokenRenewals,
		&out.AllowOneTimeTokens,
		&purposeJSON,
		&workflowJSON,
		&out.RequireDetokenizeJustification,
		&out.AllowBulkTokenize,
		&out.AllowBulkDetokenize,
		&out.AllowRedactionDetectOnly,
		&detectorsJSON,
		&actionsJSON,
		&out.AllowCustomRegexTokens,
		&out.MaxCustomRegexLength,
		&out.MaxCustomRegexGroups,
		&out.MaxTokenBatch,
		&out.MaxDetokenizeBatch,
		&out.RequireTokenContextTags,
		&contextJSON,
		&maskingJSON,
		&out.TokenMetadataRetentionDays,
		&out.RedactionEventRetentionDays,
		&out.UpdatedBy,
		&updatedRaw,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DataProtectionPolicy{}, errNotFound
		}
		return DataProtectionPolicy{}, err
	}
	out.AllowedDataAlgorithms = parseJSONArrayString(algorithmsJSON)
	out.AlgorithmProfilePolicy = parseStringSliceMap(algorithmProfileJSON)
	out.RequiredAADClaims = parseJSONArrayString(requiredAADJSON)
	out.AllowedAADEvironments = parseJSONArrayString(allowedAADEEnvJSON)
	out.AllowedEncryptFieldPaths = parseJSONArrayString(encryptPathsJSON)
	out.AllowedDecryptFieldPaths = parseJSONArrayString(decryptPathsJSON)
	out.DeniedDecryptFieldPaths = parseJSONArrayString(deniedDecryptJSON)
	out.EnvelopeKEKAllowlist = parseJSONArrayString(envelopeKEKJSON)
	out.TokenizationModePolicy = parseStringSliceMap(modeJSON)
	out.TokenFormatPolicy = parseStringSliceMap(formatJSON)
	out.DetokenizeAllowedPurposes = parseJSONArrayString(purposeJSON)
	out.DetokenizeAllowedWorkflows = parseJSONArrayString(workflowJSON)
	out.AllowedRedactionDetectors = parseJSONArrayString(detectorsJSON)
	out.AllowedRedactionActions = parseJSONArrayString(actionsJSON)
	out.RequiredTokenContextKeys = parseJSONArrayString(contextJSON)
	out.MaskingRolePolicy = parseStringMap(maskingJSON)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func (s *SQLStore) UpsertDataProtectionPolicy(ctx context.Context, item DataProtectionPolicy) (DataProtectionPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO data_protection_policy (
    tenant_id,
    allowed_data_algorithms_json,
    algorithm_profile_policy_json,
    require_aad_for_aead,
    required_aad_claims_json,
    enforce_aad_tenant_binding,
    allowed_aad_environments_json,
    max_fields_per_operation,
    max_document_bytes,
    max_app_crypto_request_bytes,
    max_app_crypto_batch_size,
    require_symmetric_keys,
    require_fips_keys,
    min_key_size_bits,
    allowed_encrypt_field_paths_json,
    allowed_decrypt_field_paths_json,
    denied_decrypt_field_paths_json,
    block_wildcard_field_paths,
    allow_deterministic_encryption,
    allow_searchable_encryption,
    allow_range_search,
    envelope_kek_allowlist_json,
    max_wrapped_dek_age_minutes,
    require_rewrap_on_dek_age_exceeded,
    allow_vaultless_tokenization,
    tokenization_mode_policy_json,
    token_format_policy_json,
    require_token_ttl,
    max_token_ttl_hours,
    allow_token_renewal,
    max_token_renewals,
    allow_one_time_tokens,
    detokenize_allowed_purposes_json,
    detokenize_allowed_workflows_json,
    require_detokenize_justification,
    allow_bulk_tokenize,
    allow_bulk_detokenize,
    allow_redaction_detect_only,
    allowed_redaction_detectors_json,
    allowed_redaction_actions_json,
    allow_custom_regex_tokens,
    max_custom_regex_length,
    max_custom_regex_groups,
    max_token_batch,
    max_detokenize_batch,
    require_token_context_tags,
    required_token_context_keys_json,
    masking_role_policy_json,
    token_metadata_retention_days,
    redaction_event_retention_days,
    updated_by,
    updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,$43,$44,$45,$46,$47,$48,$49,$50,$51,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id) DO UPDATE SET
    allowed_data_algorithms_json = EXCLUDED.allowed_data_algorithms_json,
    algorithm_profile_policy_json = EXCLUDED.algorithm_profile_policy_json,
    require_aad_for_aead = EXCLUDED.require_aad_for_aead,
    required_aad_claims_json = EXCLUDED.required_aad_claims_json,
    enforce_aad_tenant_binding = EXCLUDED.enforce_aad_tenant_binding,
    allowed_aad_environments_json = EXCLUDED.allowed_aad_environments_json,
    max_fields_per_operation = EXCLUDED.max_fields_per_operation,
    max_document_bytes = EXCLUDED.max_document_bytes,
    max_app_crypto_request_bytes = EXCLUDED.max_app_crypto_request_bytes,
    max_app_crypto_batch_size = EXCLUDED.max_app_crypto_batch_size,
    require_symmetric_keys = EXCLUDED.require_symmetric_keys,
    require_fips_keys = EXCLUDED.require_fips_keys,
    min_key_size_bits = EXCLUDED.min_key_size_bits,
    allowed_encrypt_field_paths_json = EXCLUDED.allowed_encrypt_field_paths_json,
    allowed_decrypt_field_paths_json = EXCLUDED.allowed_decrypt_field_paths_json,
    denied_decrypt_field_paths_json = EXCLUDED.denied_decrypt_field_paths_json,
    block_wildcard_field_paths = EXCLUDED.block_wildcard_field_paths,
    allow_deterministic_encryption = EXCLUDED.allow_deterministic_encryption,
    allow_searchable_encryption = EXCLUDED.allow_searchable_encryption,
    allow_range_search = EXCLUDED.allow_range_search,
    envelope_kek_allowlist_json = EXCLUDED.envelope_kek_allowlist_json,
    max_wrapped_dek_age_minutes = EXCLUDED.max_wrapped_dek_age_minutes,
    require_rewrap_on_dek_age_exceeded = EXCLUDED.require_rewrap_on_dek_age_exceeded,
    allow_vaultless_tokenization = EXCLUDED.allow_vaultless_tokenization,
    tokenization_mode_policy_json = EXCLUDED.tokenization_mode_policy_json,
    token_format_policy_json = EXCLUDED.token_format_policy_json,
    require_token_ttl = EXCLUDED.require_token_ttl,
    max_token_ttl_hours = EXCLUDED.max_token_ttl_hours,
    allow_token_renewal = EXCLUDED.allow_token_renewal,
    max_token_renewals = EXCLUDED.max_token_renewals,
    allow_one_time_tokens = EXCLUDED.allow_one_time_tokens,
    detokenize_allowed_purposes_json = EXCLUDED.detokenize_allowed_purposes_json,
    detokenize_allowed_workflows_json = EXCLUDED.detokenize_allowed_workflows_json,
    require_detokenize_justification = EXCLUDED.require_detokenize_justification,
    allow_bulk_tokenize = EXCLUDED.allow_bulk_tokenize,
    allow_bulk_detokenize = EXCLUDED.allow_bulk_detokenize,
    allow_redaction_detect_only = EXCLUDED.allow_redaction_detect_only,
    allowed_redaction_detectors_json = EXCLUDED.allowed_redaction_detectors_json,
    allowed_redaction_actions_json = EXCLUDED.allowed_redaction_actions_json,
    allow_custom_regex_tokens = EXCLUDED.allow_custom_regex_tokens,
    max_custom_regex_length = EXCLUDED.max_custom_regex_length,
    max_custom_regex_groups = EXCLUDED.max_custom_regex_groups,
    max_token_batch = EXCLUDED.max_token_batch,
    max_detokenize_batch = EXCLUDED.max_detokenize_batch,
    require_token_context_tags = EXCLUDED.require_token_context_tags,
    required_token_context_keys_json = EXCLUDED.required_token_context_keys_json,
    masking_role_policy_json = EXCLUDED.masking_role_policy_json,
    token_metadata_retention_days = EXCLUDED.token_metadata_retention_days,
    redaction_event_retention_days = EXCLUDED.redaction_event_retention_days,
    updated_by = EXCLUDED.updated_by,
    updated_at = CURRENT_TIMESTAMP
RETURNING tenant_id,
          allowed_data_algorithms_json,
          algorithm_profile_policy_json,
          require_aad_for_aead,
          required_aad_claims_json,
          enforce_aad_tenant_binding,
          allowed_aad_environments_json,
          max_fields_per_operation,
          max_document_bytes,
          max_app_crypto_request_bytes,
          max_app_crypto_batch_size,
          require_symmetric_keys,
          require_fips_keys,
          min_key_size_bits,
          allowed_encrypt_field_paths_json,
          allowed_decrypt_field_paths_json,
          denied_decrypt_field_paths_json,
          block_wildcard_field_paths,
          allow_deterministic_encryption,
          allow_searchable_encryption,
          allow_range_search,
          envelope_kek_allowlist_json,
          max_wrapped_dek_age_minutes,
          require_rewrap_on_dek_age_exceeded,
          allow_vaultless_tokenization,
          tokenization_mode_policy_json,
          token_format_policy_json,
          require_token_ttl,
          max_token_ttl_hours,
          allow_token_renewal,
          max_token_renewals,
          allow_one_time_tokens,
          detokenize_allowed_purposes_json,
          detokenize_allowed_workflows_json,
          require_detokenize_justification,
          allow_bulk_tokenize,
          allow_bulk_detokenize,
          allow_redaction_detect_only,
          allowed_redaction_detectors_json,
          allowed_redaction_actions_json,
          allow_custom_regex_tokens,
          max_custom_regex_length,
          max_custom_regex_groups,
          max_token_batch,
          max_detokenize_batch,
          require_token_context_tags,
          required_token_context_keys_json,
          masking_role_policy_json,
          token_metadata_retention_days,
          redaction_event_retention_days,
          COALESCE(updated_by,''),
          updated_at
`, item.TenantID,
		mustJSON(item.AllowedDataAlgorithms, "[]"),
		mustJSON(item.AlgorithmProfilePolicy, "{}"),
		item.RequireAADForAEAD,
		mustJSON(item.RequiredAADClaims, "[]"),
		item.EnforceAADTenantBinding,
		mustJSON(item.AllowedAADEvironments, "[]"),
		item.MaxFieldsPerOperation,
		item.MaxDocumentBytes,
		item.MaxAppCryptoRequestBytes,
		item.MaxAppCryptoBatchSize,
		item.RequireSymmetricKeys,
		item.RequireFIPSKeys,
		item.MinKeySizeBits,
		mustJSON(item.AllowedEncryptFieldPaths, "[]"),
		mustJSON(item.AllowedDecryptFieldPaths, "[]"),
		mustJSON(item.DeniedDecryptFieldPaths, "[]"),
		item.BlockWildcardFieldPaths,
		item.AllowDeterministicEncryption,
		item.AllowSearchableEncryption,
		item.AllowRangeSearch,
		mustJSON(item.EnvelopeKEKAllowlist, "[]"),
		item.MaxWrappedDEKAgeMinutes,
		item.RequireRewrapOnDEKAgeExceeded,
		item.AllowVaultlessTokenization,
		mustJSON(item.TokenizationModePolicy, "{}"),
		mustJSON(item.TokenFormatPolicy, "{}"),
		item.RequireTokenTTL,
		item.MaxTokenTTLHours,
		item.AllowTokenRenewal,
		item.MaxTokenRenewals,
		item.AllowOneTimeTokens,
		mustJSON(item.DetokenizeAllowedPurposes, "[]"),
		mustJSON(item.DetokenizeAllowedWorkflows, "[]"),
		item.RequireDetokenizeJustification,
		item.AllowBulkTokenize,
		item.AllowBulkDetokenize,
		item.AllowRedactionDetectOnly,
		mustJSON(item.AllowedRedactionDetectors, "[]"),
		mustJSON(item.AllowedRedactionActions, "[]"),
		item.AllowCustomRegexTokens,
		item.MaxCustomRegexLength,
		item.MaxCustomRegexGroups,
		item.MaxTokenBatch,
		item.MaxDetokenizeBatch,
		item.RequireTokenContextTags,
		mustJSON(item.RequiredTokenContextKeys, "[]"),
		mustJSON(item.MaskingRolePolicy, "{}"),
		item.TokenMetadataRetentionDays,
		item.RedactionEventRetentionDays,
		item.UpdatedBy)
	var (
		out                  DataProtectionPolicy
		algorithmsJSON       string
		algorithmProfileJSON string
		requiredAADJSON      string
		allowedAADEEnvJSON   string
		encryptPathsJSON     string
		decryptPathsJSON     string
		deniedDecryptJSON    string
		envelopeKEKJSON      string
		modeJSON             string
		formatJSON           string
		purposeJSON          string
		workflowJSON         string
		detectorsJSON        string
		actionsJSON          string
		contextJSON          string
		maskingJSON          string
		updatedRaw           interface{}
	)
	if err := row.Scan(
		&out.TenantID,
		&algorithmsJSON,
		&algorithmProfileJSON,
		&out.RequireAADForAEAD,
		&requiredAADJSON,
		&out.EnforceAADTenantBinding,
		&allowedAADEEnvJSON,
		&out.MaxFieldsPerOperation,
		&out.MaxDocumentBytes,
		&out.MaxAppCryptoRequestBytes,
		&out.MaxAppCryptoBatchSize,
		&out.RequireSymmetricKeys,
		&out.RequireFIPSKeys,
		&out.MinKeySizeBits,
		&encryptPathsJSON,
		&decryptPathsJSON,
		&deniedDecryptJSON,
		&out.BlockWildcardFieldPaths,
		&out.AllowDeterministicEncryption,
		&out.AllowSearchableEncryption,
		&out.AllowRangeSearch,
		&envelopeKEKJSON,
		&out.MaxWrappedDEKAgeMinutes,
		&out.RequireRewrapOnDEKAgeExceeded,
		&out.AllowVaultlessTokenization,
		&modeJSON,
		&formatJSON,
		&out.RequireTokenTTL,
		&out.MaxTokenTTLHours,
		&out.AllowTokenRenewal,
		&out.MaxTokenRenewals,
		&out.AllowOneTimeTokens,
		&purposeJSON,
		&workflowJSON,
		&out.RequireDetokenizeJustification,
		&out.AllowBulkTokenize,
		&out.AllowBulkDetokenize,
		&out.AllowRedactionDetectOnly,
		&detectorsJSON,
		&actionsJSON,
		&out.AllowCustomRegexTokens,
		&out.MaxCustomRegexLength,
		&out.MaxCustomRegexGroups,
		&out.MaxTokenBatch,
		&out.MaxDetokenizeBatch,
		&out.RequireTokenContextTags,
		&contextJSON,
		&maskingJSON,
		&out.TokenMetadataRetentionDays,
		&out.RedactionEventRetentionDays,
		&out.UpdatedBy,
		&updatedRaw,
	); err != nil {
		return DataProtectionPolicy{}, err
	}
	out.AllowedDataAlgorithms = parseJSONArrayString(algorithmsJSON)
	out.AlgorithmProfilePolicy = parseStringSliceMap(algorithmProfileJSON)
	out.RequiredAADClaims = parseJSONArrayString(requiredAADJSON)
	out.AllowedAADEvironments = parseJSONArrayString(allowedAADEEnvJSON)
	out.AllowedEncryptFieldPaths = parseJSONArrayString(encryptPathsJSON)
	out.AllowedDecryptFieldPaths = parseJSONArrayString(decryptPathsJSON)
	out.DeniedDecryptFieldPaths = parseJSONArrayString(deniedDecryptJSON)
	out.EnvelopeKEKAllowlist = parseJSONArrayString(envelopeKEKJSON)
	out.TokenizationModePolicy = parseStringSliceMap(modeJSON)
	out.TokenFormatPolicy = parseStringSliceMap(formatJSON)
	out.DetokenizeAllowedPurposes = parseJSONArrayString(purposeJSON)
	out.DetokenizeAllowedWorkflows = parseJSONArrayString(workflowJSON)
	out.AllowedRedactionDetectors = parseJSONArrayString(detectorsJSON)
	out.AllowedRedactionActions = parseJSONArrayString(actionsJSON)
	out.RequiredTokenContextKeys = parseJSONArrayString(contextJSON)
	out.MaskingRolePolicy = parseStringMap(maskingJSON)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func scanTokenVault(scanner interface {
	Scan(dest ...interface{}) error
}) (TokenVault, error) {
	var (
		item       TokenVault
		createdRaw interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.ID, &item.Name, &item.Mode, &item.TokenType, &item.Format, &item.KeyID, &item.CustomRegex, &createdRaw); err != nil {
		return TokenVault{}, err
	}
	item.Mode = normalizeTokenMode(item.Mode)
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}

func scanTokenRecord(scanner interface {
	Scan(dest ...interface{}) error
}) (TokenRecord, error) {
	var (
		item         TokenRecord
		metaJS       string
		metadataTags string
		createdRaw   interface{}
		expiresAtRaw interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.ID, &item.VaultID, &item.Token, &item.OriginalEnc, &item.OriginalHash, &metaJS, &item.UseCount, &item.UseLimit, &item.RenewCount, &metadataTags, &createdRaw, &expiresAtRaw); err != nil {
		return TokenRecord{}, err
	}
	item.FormatMetadata = parseJSONObject(metaJS)
	item.MetadataTags = parseStringMap(metadataTags)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.ExpiresAt = parseTimeValue(expiresAtRaw)
	return item, nil
}

func scanMaskingPolicy(scanner interface {
	Scan(dest ...interface{}) error
}) (MaskingPolicy, error) {
	var (
		item        MaskingPolicy
		rolesFullJS string
		rolesPartJS string
		rolesRedJS  string
		createdRaw  interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.ID, &item.Name, &item.TargetType, &item.FieldPath, &item.MaskPattern, &rolesFullJS, &rolesPartJS, &rolesRedJS, &item.Consistent, &item.KeyID, &createdRaw); err != nil {
		return MaskingPolicy{}, err
	}
	item.RolesFull = parseJSONArrayString(rolesFullJS)
	item.RolesPartial = parseJSONArrayString(rolesPartJS)
	item.RolesRedacted = parseJSONArrayString(rolesRedJS)
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}

func scanRedactionPolicy(scanner interface {
	Scan(dest ...interface{}) error
}) (RedactionPolicy, error) {
	var (
		item       RedactionPolicy
		patternsJS string
		appliesJS  string
		createdRaw interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.ID, &item.Name, &patternsJS, &item.Scope, &item.Action, &item.Placeholder, &appliesJS, &createdRaw); err != nil {
		return RedactionPolicy{}, err
	}
	item.AppliesTo = parseJSONArrayString(appliesJS)
	_ = json.Unmarshal([]byte(strings.TrimSpace(patternsJS)), &item.Patterns)
	if item.Patterns == nil {
		item.Patterns = []RedactionPattern{}
	}
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}

func scanFLEMetadata(scanner interface {
	Scan(dest ...interface{}) error
}) (FLEMetadata, error) {
	var (
		item       FLEMetadata
		createdRaw interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.ID, &item.DocumentID, &item.FieldPath, &item.KeyID, &item.KeyVersion, &item.Algorithm, &item.IV, &item.Searchable, &createdRaw); err != nil {
		return FLEMetadata{}, err
	}
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}
