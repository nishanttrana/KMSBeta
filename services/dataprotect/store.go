package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
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
	tenant_id, id, name, mode, storage_type, external_provider, external_config_json, external_schema_version, token_type, format, custom_token_format, key_id, custom_regex, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.Name, item.Mode, item.StorageType, item.ExternalProvider, mustJSON(item.ExternalConfig, "{}"), item.ExternalSchemaVersion, item.TokenType, item.Format, item.CustomTokenFormat, item.KeyID, item.CustomRegex)
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
SELECT tenant_id, id, name, mode, storage_type, external_provider, external_config_json, external_schema_version, token_type, format, custom_token_format, key_id, custom_regex, created_at
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
SELECT tenant_id, id, name, mode, storage_type, external_provider, external_config_json, external_schema_version, token_type, format, custom_token_format, key_id, custom_regex, created_at
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
       custom_token_formats_json,
       reuse_existing_token_for_same_input,
       enforce_unique_token_per_vault,
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
		customFormatsJSON    string
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
		&customFormatsJSON,
		&out.ReuseExistingTokenForSameInput,
		&out.EnforceUniqueTokenPerVault,
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
	out.CustomTokenFormats = parseStringMap(customFormatsJSON)
	out.DetokenizeAllowedPurposes = parseJSONArrayString(purposeJSON)
	out.DetokenizeAllowedWorkflows = parseJSONArrayString(workflowJSON)
	out.AllowedRedactionDetectors = parseJSONArrayString(detectorsJSON)
	out.AllowedRedactionActions = parseJSONArrayString(actionsJSON)
	out.RequiredTokenContextKeys = parseJSONArrayString(contextJSON)
	out.MaskingRolePolicy = parseStringMap(maskingJSON)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	var (
		allowedLocalAlgorithmsJSON string
		allowedKeyClassesJSON      string
		forceRemoteOpsJSON         string
		attestationAKAllowlistJSON string
		attestationAllowedPCRsJSON string
	)
	rowRuntime := s.db.SQL().QueryRowContext(ctx, `
SELECT require_registered_wrapper,
       local_crypto_allowed,
       cache_enabled,
       cache_ttl_sec,
       lease_max_ops,
       max_cached_keys,
       allowed_local_algorithms_json,
       allowed_key_classes_for_local_export_json,
       force_remote_ops_json,
       require_mtls,
       require_signed_nonce,
       anti_replay_window_sec,
       attested_wrapper_only,
       revoke_on_policy_change,
       rekey_on_policy_change,
       receipt_reconciliation_enabled,
       receipt_heartbeat_sec,
       receipt_missing_grace_sec,
       require_tpm_attestation,
       require_non_exportable_wrapper_keys,
       attestation_ak_allowlist_json,
       attestation_allowed_pcrs_json
FROM data_protection_policy
WHERE tenant_id = $1
`, strings.TrimSpace(tenantID))
	if err := rowRuntime.Scan(
		&out.RequireRegisteredWrapper,
		&out.LocalCryptoAllowed,
		&out.CacheEnabled,
		&out.CacheTTLSeconds,
		&out.LeaseMaxOps,
		&out.MaxCachedKeys,
		&allowedLocalAlgorithmsJSON,
		&allowedKeyClassesJSON,
		&forceRemoteOpsJSON,
		&out.RequireMTLS,
		&out.RequireSignedNonce,
		&out.AntiReplayWindowSeconds,
		&out.AttestedWrapperOnly,
		&out.RevokeOnPolicyChange,
		&out.RekeyOnPolicyChange,
		&out.ReceiptReconciliationEnabled,
		&out.ReceiptHeartbeatSec,
		&out.ReceiptMissingGraceSec,
		&out.RequireTPMAttestation,
		&out.RequireNonExportableWrapperKey,
		&attestationAKAllowlistJSON,
		&attestationAllowedPCRsJSON,
	); err != nil {
		return DataProtectionPolicy{}, err
	}
	out.AllowedLocalAlgorithms = parseJSONArrayString(allowedLocalAlgorithmsJSON)
	out.AllowedKeyClassesForLocal = parseJSONArrayString(allowedKeyClassesJSON)
	out.ForceRemoteOps = parseJSONArrayString(forceRemoteOpsJSON)
	out.AttestationAKAllowlist = parseJSONArrayString(attestationAKAllowlistJSON)
	out.AttestationAllowedPCRs = parseStringSliceMap(attestationAllowedPCRsJSON)
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
    custom_token_formats_json,
    reuse_existing_token_for_same_input,
    enforce_unique_token_per_vault,
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
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,$43,$44,$45,$46,$47,$48,$49,$50,$51,$52,$53,$54,CURRENT_TIMESTAMP
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
    custom_token_formats_json = EXCLUDED.custom_token_formats_json,
    reuse_existing_token_for_same_input = EXCLUDED.reuse_existing_token_for_same_input,
    enforce_unique_token_per_vault = EXCLUDED.enforce_unique_token_per_vault,
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
          custom_token_formats_json,
          reuse_existing_token_for_same_input,
          enforce_unique_token_per_vault,
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
		mustJSON(item.CustomTokenFormats, "{}"),
		item.ReuseExistingTokenForSameInput,
		item.EnforceUniqueTokenPerVault,
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
		customFormatsJSON    string
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
		&customFormatsJSON,
		&out.ReuseExistingTokenForSameInput,
		&out.EnforceUniqueTokenPerVault,
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
	out.CustomTokenFormats = parseStringMap(customFormatsJSON)
	out.DetokenizeAllowedPurposes = parseJSONArrayString(purposeJSON)
	out.DetokenizeAllowedWorkflows = parseJSONArrayString(workflowJSON)
	out.AllowedRedactionDetectors = parseJSONArrayString(detectorsJSON)
	out.AllowedRedactionActions = parseJSONArrayString(actionsJSON)
	out.RequiredTokenContextKeys = parseJSONArrayString(contextJSON)
	out.MaskingRolePolicy = parseStringMap(maskingJSON)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	if _, err := s.db.SQL().ExecContext(ctx, `
UPDATE data_protection_policy
SET require_registered_wrapper = $2,
    local_crypto_allowed = $3,
    cache_enabled = $4,
    cache_ttl_sec = $5,
    lease_max_ops = $6,
    max_cached_keys = $7,
    allowed_local_algorithms_json = $8,
    allowed_key_classes_for_local_export_json = $9,
    force_remote_ops_json = $10,
    require_mtls = $11,
    require_signed_nonce = $12,
    anti_replay_window_sec = $13,
    attested_wrapper_only = $14,
    revoke_on_policy_change = $15,
    rekey_on_policy_change = $16,
    receipt_reconciliation_enabled = $17,
    receipt_heartbeat_sec = $18,
    receipt_missing_grace_sec = $19,
    require_tpm_attestation = $20,
    require_non_exportable_wrapper_keys = $21,
    attestation_ak_allowlist_json = $22,
    attestation_allowed_pcrs_json = $23
WHERE tenant_id = $1
`, out.TenantID,
		item.RequireRegisteredWrapper,
		item.LocalCryptoAllowed,
		item.CacheEnabled,
		item.CacheTTLSeconds,
		item.LeaseMaxOps,
		item.MaxCachedKeys,
		mustJSON(item.AllowedLocalAlgorithms, "[]"),
		mustJSON(item.AllowedKeyClassesForLocal, "[]"),
		mustJSON(item.ForceRemoteOps, "[]"),
		item.RequireMTLS,
		item.RequireSignedNonce,
		item.AntiReplayWindowSeconds,
		item.AttestedWrapperOnly,
		item.RevokeOnPolicyChange,
		item.RekeyOnPolicyChange,
		item.ReceiptReconciliationEnabled,
		item.ReceiptHeartbeatSec,
		item.ReceiptMissingGraceSec,
		item.RequireTPMAttestation,
		item.RequireNonExportableWrapperKey,
		mustJSON(item.AttestationAKAllowlist, "[]"),
		mustJSON(item.AttestationAllowedPCRs, "{}"),
	); err != nil {
		return DataProtectionPolicy{}, err
	}
	out.RequireRegisteredWrapper = item.RequireRegisteredWrapper
	out.LocalCryptoAllowed = item.LocalCryptoAllowed
	out.CacheEnabled = item.CacheEnabled
	out.CacheTTLSeconds = item.CacheTTLSeconds
	out.LeaseMaxOps = item.LeaseMaxOps
	out.MaxCachedKeys = item.MaxCachedKeys
	out.AllowedLocalAlgorithms = append([]string{}, item.AllowedLocalAlgorithms...)
	out.AllowedKeyClassesForLocal = append([]string{}, item.AllowedKeyClassesForLocal...)
	out.ForceRemoteOps = append([]string{}, item.ForceRemoteOps...)
	out.RequireMTLS = item.RequireMTLS
	out.RequireSignedNonce = item.RequireSignedNonce
	out.AntiReplayWindowSeconds = item.AntiReplayWindowSeconds
	out.AttestedWrapperOnly = item.AttestedWrapperOnly
	out.RevokeOnPolicyChange = item.RevokeOnPolicyChange
	out.RekeyOnPolicyChange = item.RekeyOnPolicyChange
	out.ReceiptReconciliationEnabled = item.ReceiptReconciliationEnabled
	out.ReceiptHeartbeatSec = item.ReceiptHeartbeatSec
	out.ReceiptMissingGraceSec = item.ReceiptMissingGraceSec
	out.RequireTPMAttestation = item.RequireTPMAttestation
	out.RequireNonExportableWrapperKey = item.RequireNonExportableWrapperKey
	out.AttestationAKAllowlist = append([]string{}, item.AttestationAKAllowlist...)
	out.AttestationAllowedPCRs = map[string][]string{}
	for k, v := range item.AttestationAllowedPCRs {
		out.AttestationAllowedPCRs[k] = append([]string{}, v...)
	}
	return out, nil
}

func (s *SQLStore) CreateFieldEncryptionWrapperChallenge(ctx context.Context, item FieldEncryptionWrapperChallenge) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO field_encryption_wrapper_challenges (
	tenant_id, challenge_id, wrapper_id, app_id, challenge_b64, nonce,
	signing_public_key_b64, encryption_public_key_b64, metadata_json, expires_at, used, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ChallengeID, item.WrapperID, item.AppID, item.ChallengeB64, item.Nonce, item.SigningPublicKeyB64, item.EncryptionPublicKey, mustJSON(item.Metadata, "{}"), nullableTime(item.ExpiresAt), item.Used)
	return err
}

func (s *SQLStore) GetFieldEncryptionWrapperChallenge(ctx context.Context, tenantID string, challengeID string) (FieldEncryptionWrapperChallenge, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, challenge_id, wrapper_id, app_id, challenge_b64, nonce, signing_public_key_b64, encryption_public_key_b64, metadata_json, expires_at, used, created_at
FROM field_encryption_wrapper_challenges
WHERE tenant_id = $1 AND challenge_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(challengeID))
	item, err := scanFieldEncryptionWrapperChallenge(row)
	if errors.Is(err, sql.ErrNoRows) {
		return FieldEncryptionWrapperChallenge{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) MarkFieldEncryptionWrapperChallengeUsed(ctx context.Context, tenantID string, challengeID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE field_encryption_wrapper_challenges
SET used = TRUE
WHERE tenant_id = $1 AND challenge_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(challengeID))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) UpsertFieldEncryptionWrapper(ctx context.Context, item FieldEncryptionWrapper) (FieldEncryptionWrapper, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO field_encryption_wrappers (
	tenant_id, wrapper_id, app_id, display_name, signing_public_key_b64, encryption_public_key_b64,
	transport, status, cert_fingerprint, metadata_json, approved_by, approved_at, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, wrapper_id) DO UPDATE SET
	app_id = EXCLUDED.app_id,
	display_name = EXCLUDED.display_name,
	signing_public_key_b64 = EXCLUDED.signing_public_key_b64,
	encryption_public_key_b64 = EXCLUDED.encryption_public_key_b64,
	transport = EXCLUDED.transport,
	status = EXCLUDED.status,
	cert_fingerprint = EXCLUDED.cert_fingerprint,
	metadata_json = EXCLUDED.metadata_json,
	approved_by = EXCLUDED.approved_by,
	approved_at = EXCLUDED.approved_at,
	updated_at = CURRENT_TIMESTAMP
RETURNING tenant_id, wrapper_id, app_id, display_name, signing_public_key_b64, encryption_public_key_b64, transport, status, cert_fingerprint, metadata_json, approved_by, approved_at, created_at, updated_at
`, item.TenantID, item.WrapperID, item.AppID, item.DisplayName, item.SigningPublicKeyB64, item.EncryptionPublicKey, item.Transport, item.Status, item.CertFingerprint, mustJSON(item.Metadata, "{}"), item.ApprovedBy, nullableTime(item.ApprovedAt))
	out, err := scanFieldEncryptionWrapper(row)
	if err != nil {
		return FieldEncryptionWrapper{}, err
	}
	return out, nil
}

func (s *SQLStore) GetFieldEncryptionWrapper(ctx context.Context, tenantID string, wrapperID string) (FieldEncryptionWrapper, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, wrapper_id, app_id, display_name, signing_public_key_b64, encryption_public_key_b64, transport, status, cert_fingerprint, metadata_json, approved_by, approved_at, created_at, updated_at
FROM field_encryption_wrappers
WHERE tenant_id = $1 AND wrapper_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(wrapperID))
	item, err := scanFieldEncryptionWrapper(row)
	if errors.Is(err, sql.ErrNoRows) {
		return FieldEncryptionWrapper{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListFieldEncryptionWrappers(ctx context.Context, tenantID string, limit int, offset int) ([]FieldEncryptionWrapper, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, wrapper_id, app_id, display_name, signing_public_key_b64, encryption_public_key_b64, transport, status, cert_fingerprint, metadata_json, approved_by, approved_at, created_at, updated_at
FROM field_encryption_wrappers
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3
`, strings.TrimSpace(tenantID), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]FieldEncryptionWrapper, 0)
	for rows.Next() {
		item, err := scanFieldEncryptionWrapper(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateFieldEncryptionLease(ctx context.Context, item FieldEncryptionLease) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO field_encryption_leases (
	tenant_id, lease_id, wrapper_id, key_id, operation, lease_package_json, policy_hash, revocation_counter,
	max_ops, used_ops, expires_at, revoked, revoke_reason, issued_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
)
`, item.TenantID, item.LeaseID, item.WrapperID, item.KeyID, item.Operation, mustJSON(item.LeasePackage, "{}"), item.PolicyHash, item.RevocationCounter, item.MaxOps, item.UsedOps, nullableTime(item.ExpiresAt), item.Revoked, item.RevokeReason, nullableTime(item.IssuedAt), nullableTime(item.UpdatedAt))
	return err
}

func (s *SQLStore) GetFieldEncryptionLease(ctx context.Context, tenantID string, leaseID string) (FieldEncryptionLease, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, lease_id, wrapper_id, key_id, operation, lease_package_json, policy_hash, revocation_counter, max_ops, used_ops, expires_at, revoked, revoke_reason, issued_at, updated_at
FROM field_encryption_leases
WHERE tenant_id = $1 AND lease_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(leaseID))
	item, err := scanFieldEncryptionLease(row)
	if errors.Is(err, sql.ErrNoRows) {
		return FieldEncryptionLease{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListFieldEncryptionLeases(ctx context.Context, tenantID string, wrapperID string, limit int, offset int) ([]FieldEncryptionLease, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	base := `
SELECT tenant_id, lease_id, wrapper_id, key_id, operation, lease_package_json, policy_hash, revocation_counter, max_ops, used_ops, expires_at, revoked, revoke_reason, issued_at, updated_at
FROM field_encryption_leases
WHERE tenant_id = $1`
	var (
		rows *sql.Rows
		err  error
	)
	if strings.TrimSpace(wrapperID) != "" {
		rows, err = s.db.SQL().QueryContext(ctx, base+` AND wrapper_id = $2 ORDER BY issued_at DESC LIMIT $3 OFFSET $4`, strings.TrimSpace(tenantID), strings.TrimSpace(wrapperID), limit, offset)
	} else {
		rows, err = s.db.SQL().QueryContext(ctx, base+` ORDER BY issued_at DESC LIMIT $2 OFFSET $3`, strings.TrimSpace(tenantID), limit, offset)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]FieldEncryptionLease, 0)
	for rows.Next() {
		item, err := scanFieldEncryptionLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ConsumeFieldEncryptionLeaseOps(ctx context.Context, tenantID string, leaseID string, ops int) (FieldEncryptionLease, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
UPDATE field_encryption_leases
SET used_ops = used_ops + $3,
    updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1
  AND lease_id = $2
  AND revoked = FALSE
  AND expires_at > CURRENT_TIMESTAMP
  AND (max_ops <= 0 OR used_ops + $3 <= max_ops)
RETURNING tenant_id, lease_id, wrapper_id, key_id, operation, lease_package_json, policy_hash, revocation_counter, max_ops, used_ops, expires_at, revoked, revoke_reason, issued_at, updated_at
`, strings.TrimSpace(tenantID), strings.TrimSpace(leaseID), ops)
	item, err := scanFieldEncryptionLease(row)
	if errors.Is(err, sql.ErrNoRows) {
		return FieldEncryptionLease{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) RevokeFieldEncryptionLease(ctx context.Context, tenantID string, leaseID string, reason string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE field_encryption_leases
SET revoked = TRUE,
    revoke_reason = $3,
    updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1 AND lease_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(leaseID), strings.TrimSpace(reason))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateFieldEncryptionUsageReceipt(ctx context.Context, item FieldEncryptionUsageReceipt) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO field_encryption_usage_receipts (
	tenant_id, receipt_id, lease_id, wrapper_id, key_id, operation, op_count, nonce, ts, signature_b64, payload_hash, accepted, reject_reason, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
)
`, item.TenantID, item.ReceiptID, item.LeaseID, item.WrapperID, item.KeyID, item.Operation, item.OpCount, item.Nonce, nullableTime(item.Timestamp), item.SignatureB64, item.PayloadHash, item.Accepted, item.RejectReason, nullableTime(item.CreatedAt))
	return err
}

func (s *SQLStore) GetFieldEncryptionUsageReceiptByNonce(ctx context.Context, tenantID string, wrapperID string, nonce string) (FieldEncryptionUsageReceipt, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, receipt_id, lease_id, wrapper_id, key_id, operation, op_count, nonce, ts, signature_b64, payload_hash, accepted, reject_reason, created_at
FROM field_encryption_usage_receipts
WHERE tenant_id = $1 AND wrapper_id = $2 AND nonce = $3
`, strings.TrimSpace(tenantID), strings.TrimSpace(wrapperID), strings.TrimSpace(nonce))
	item, err := scanFieldEncryptionUsageReceipt(row)
	if errors.Is(err, sql.ErrNoRows) {
		return FieldEncryptionUsageReceipt{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListFieldEncryptionLeaseReceiptStates(ctx context.Context, limit int) ([]FieldEncryptionLeaseReceiptState, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT l.tenant_id,
       l.lease_id,
       l.wrapper_id,
       l.policy_hash,
       l.issued_at,
       l.expires_at,
       COALESCE(MAX(r.created_at), NULL) AS last_receipt_at,
       COUNT(r.receipt_id) AS receipt_count
FROM field_encryption_leases l
LEFT JOIN field_encryption_usage_receipts r
  ON r.tenant_id = l.tenant_id
 AND r.lease_id = l.lease_id
WHERE l.revoked = FALSE
  AND l.expires_at > CURRENT_TIMESTAMP
GROUP BY l.tenant_id, l.lease_id, l.wrapper_id, l.policy_hash, l.issued_at, l.expires_at
ORDER BY l.issued_at ASC
LIMIT $1
`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]FieldEncryptionLeaseReceiptState, 0)
	for rows.Next() {
		var (
			item           FieldEncryptionLeaseReceiptState
			issuedRaw      interface{}
			expiresRaw     interface{}
			lastReceiptRaw interface{}
		)
		if err := rows.Scan(
			&item.TenantID,
			&item.LeaseID,
			&item.WrapperID,
			&item.PolicyHash,
			&issuedRaw,
			&expiresRaw,
			&lastReceiptRaw,
			&item.ReceiptCount,
		); err != nil {
			return nil, err
		}
		item.IssuedAt = parseTimeValue(issuedRaw)
		item.ExpiresAt = parseTimeValue(expiresRaw)
		item.LastReceiptAt = parseTimeValue(lastReceiptRaw)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertFieldProtectionProfile(ctx context.Context, item FieldProtectionProfile) (FieldProtectionProfile, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO field_protection_profiles (
	tenant_id, profile_id, name, app_id, wrapper_id, status, priority, cache_ttl_sec, policy_hash, rules_json, metadata_json, updated_by, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, profile_id) DO UPDATE SET
	name = EXCLUDED.name,
	app_id = EXCLUDED.app_id,
	wrapper_id = EXCLUDED.wrapper_id,
	status = EXCLUDED.status,
	priority = EXCLUDED.priority,
	cache_ttl_sec = EXCLUDED.cache_ttl_sec,
	policy_hash = EXCLUDED.policy_hash,
	rules_json = EXCLUDED.rules_json,
	metadata_json = EXCLUDED.metadata_json,
	updated_by = EXCLUDED.updated_by,
	updated_at = CURRENT_TIMESTAMP
RETURNING tenant_id, profile_id, name, app_id, wrapper_id, status, priority, cache_ttl_sec, policy_hash, rules_json, metadata_json, updated_by, created_at, updated_at
`, strings.TrimSpace(item.TenantID), strings.TrimSpace(item.ProfileID), strings.TrimSpace(item.Name), strings.TrimSpace(item.AppID), strings.TrimSpace(item.WrapperID), strings.TrimSpace(item.Status), item.Priority, item.CacheTTLSeconds, strings.TrimSpace(item.PolicyHash), mustJSON(item.Rules, "[]"), mustJSON(item.Metadata, "{}"), strings.TrimSpace(item.UpdatedBy))
	out, err := scanFieldProtectionProfile(row)
	if err != nil {
		return FieldProtectionProfile{}, err
	}
	return out, nil
}

func (s *SQLStore) GetFieldProtectionProfile(ctx context.Context, tenantID string, profileID string) (FieldProtectionProfile, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, profile_id, name, app_id, wrapper_id, status, priority, cache_ttl_sec, policy_hash, rules_json, metadata_json, updated_by, created_at, updated_at
FROM field_protection_profiles
WHERE tenant_id = $1 AND profile_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(profileID))
	item, err := scanFieldProtectionProfile(row)
	if errors.Is(err, sql.ErrNoRows) {
		return FieldProtectionProfile{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListFieldProtectionProfiles(ctx context.Context, tenantID string, appID string, wrapperID string, status string, limit int, offset int) ([]FieldProtectionProfile, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	tenantID = strings.TrimSpace(tenantID)
	appID = strings.TrimSpace(appID)
	wrapperID = strings.TrimSpace(wrapperID)
	status = strings.TrimSpace(status)
	query := `
SELECT tenant_id, profile_id, name, app_id, wrapper_id, status, priority, cache_ttl_sec, policy_hash, rules_json, metadata_json, updated_by, created_at, updated_at
FROM field_protection_profiles
WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	next := 2
	if appID != "" {
		query += " AND app_id = $" + strconv.Itoa(next)
		args = append(args, appID)
		next++
	}
	if wrapperID != "" {
		query += " AND wrapper_id = $" + strconv.Itoa(next)
		args = append(args, wrapperID)
		next++
	}
	if status != "" {
		query += " AND LOWER(status) = LOWER($" + strconv.Itoa(next) + ")"
		args = append(args, status)
		next++
	}
	query += " ORDER BY priority ASC, updated_at DESC LIMIT $" + strconv.Itoa(next) + " OFFSET $" + strconv.Itoa(next+1)
	args = append(args, limit, offset)
	rows, err := s.db.SQL().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]FieldProtectionProfile, 0)
	for rows.Next() {
		item, err := scanFieldProtectionProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ResolveFieldProtectionProfiles(ctx context.Context, tenantID string, appID string, wrapperID string, limit int) ([]FieldProtectionProfile, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	tenantID = strings.TrimSpace(tenantID)
	appID = strings.TrimSpace(appID)
	wrapperID = strings.TrimSpace(wrapperID)
	if appID == "" {
		appID = "*"
	}
	if wrapperID == "" {
		wrapperID = "*"
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, profile_id, name, app_id, wrapper_id, status, priority, cache_ttl_sec, policy_hash, rules_json, metadata_json, updated_by, created_at, updated_at
FROM field_protection_profiles
WHERE tenant_id = $1
  AND LOWER(status) = 'active'
  AND (app_id = $2 OR app_id = '*' OR app_id = '')
  AND (wrapper_id = $3 OR wrapper_id = '*' OR wrapper_id = '')
ORDER BY priority ASC, updated_at DESC
LIMIT $4
`, tenantID, appID, wrapperID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]FieldProtectionProfile, 0)
	for rows.Next() {
		item, err := scanFieldProtectionProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteFieldProtectionProfile(ctx context.Context, tenantID string, profileID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM field_protection_profiles
WHERE tenant_id = $1 AND profile_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(profileID))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func scanFieldEncryptionWrapperChallenge(scanner interface {
	Scan(dest ...interface{}) error
}) (FieldEncryptionWrapperChallenge, error) {
	var (
		item       FieldEncryptionWrapperChallenge
		metadataJS string
		expiresRaw interface{}
		createdRaw interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.ChallengeID, &item.WrapperID, &item.AppID, &item.ChallengeB64, &item.Nonce, &item.SigningPublicKeyB64, &item.EncryptionPublicKey, &metadataJS, &expiresRaw, &item.Used, &createdRaw); err != nil {
		return FieldEncryptionWrapperChallenge{}, err
	}
	item.Metadata = parseStringMap(metadataJS)
	item.ExpiresAt = parseTimeValue(expiresRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}

func scanFieldEncryptionWrapper(scanner interface {
	Scan(dest ...interface{}) error
}) (FieldEncryptionWrapper, error) {
	var (
		item       FieldEncryptionWrapper
		metadataJS string
		approvedAt interface{}
		createdRaw interface{}
		updatedRaw interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.WrapperID, &item.AppID, &item.DisplayName, &item.SigningPublicKeyB64, &item.EncryptionPublicKey, &item.Transport, &item.Status, &item.CertFingerprint, &metadataJS, &item.ApprovedBy, &approvedAt, &createdRaw, &updatedRaw); err != nil {
		return FieldEncryptionWrapper{}, err
	}
	item.Metadata = parseStringMap(metadataJS)
	item.ApprovedAt = parseTimeValue(approvedAt)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanFieldEncryptionLease(scanner interface {
	Scan(dest ...interface{}) error
}) (FieldEncryptionLease, error) {
	var (
		item         FieldEncryptionLease
		leasePackage string
		expiresRaw   interface{}
		issuedRaw    interface{}
		updatedRaw   interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.LeaseID, &item.WrapperID, &item.KeyID, &item.Operation, &leasePackage, &item.PolicyHash, &item.RevocationCounter, &item.MaxOps, &item.UsedOps, &expiresRaw, &item.Revoked, &item.RevokeReason, &issuedRaw, &updatedRaw); err != nil {
		return FieldEncryptionLease{}, err
	}
	item.LeasePackage = parseJSONObject(leasePackage)
	item.ExpiresAt = parseTimeValue(expiresRaw)
	item.IssuedAt = parseTimeValue(issuedRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanFieldEncryptionUsageReceipt(scanner interface {
	Scan(dest ...interface{}) error
}) (FieldEncryptionUsageReceipt, error) {
	var (
		item       FieldEncryptionUsageReceipt
		tsRaw      interface{}
		createdRaw interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.ReceiptID, &item.LeaseID, &item.WrapperID, &item.KeyID, &item.Operation, &item.OpCount, &item.Nonce, &tsRaw, &item.SignatureB64, &item.PayloadHash, &item.Accepted, &item.RejectReason, &createdRaw); err != nil {
		return FieldEncryptionUsageReceipt{}, err
	}
	item.Timestamp = parseTimeValue(tsRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}

func scanFieldProtectionProfile(scanner interface {
	Scan(dest ...interface{}) error
}) (FieldProtectionProfile, error) {
	var (
		item       FieldProtectionProfile
		rulesJSON  string
		metadataJS string
		createdRaw interface{}
		updatedRaw interface{}
	)
	if err := scanner.Scan(
		&item.TenantID,
		&item.ProfileID,
		&item.Name,
		&item.AppID,
		&item.WrapperID,
		&item.Status,
		&item.Priority,
		&item.CacheTTLSeconds,
		&item.PolicyHash,
		&rulesJSON,
		&metadataJS,
		&item.UpdatedBy,
		&createdRaw,
		&updatedRaw,
	); err != nil {
		return FieldProtectionProfile{}, err
	}
	item.Rules = parseFieldProtectionRules(rulesJSON)
	item.Metadata = parseStringMap(metadataJS)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func parseFieldProtectionRules(v string) []FieldProtectionRule {
	v = strings.TrimSpace(v)
	if v == "" {
		return []FieldProtectionRule{}
	}
	out := make([]FieldProtectionRule, 0)
	_ = json.Unmarshal([]byte(v), &out)
	if out == nil {
		return []FieldProtectionRule{}
	}
	return out
}

func scanTokenVault(scanner interface {
	Scan(dest ...interface{}) error
}) (TokenVault, error) {
	var (
		item               TokenVault
		externalConfigJSON string
		createdRaw         interface{}
	)
	if err := scanner.Scan(
		&item.TenantID,
		&item.ID,
		&item.Name,
		&item.Mode,
		&item.StorageType,
		&item.ExternalProvider,
		&externalConfigJSON,
		&item.ExternalSchemaVersion,
		&item.TokenType,
		&item.Format,
		&item.CustomTokenFormat,
		&item.KeyID,
		&item.CustomRegex,
		&createdRaw,
	); err != nil {
		return TokenVault{}, err
	}
	item.Mode = normalizeTokenMode(item.Mode)
	item.StorageType = normalizeTokenStorageType(item.StorageType)
	item.ExternalProvider = normalizeExternalVaultProvider(item.ExternalProvider)
	item.ExternalConfig = parseStringMap(externalConfigJSON)
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
