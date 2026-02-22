package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

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
	tenant_id, id, vault_id, token, original_enc, original_hash, format_metadata_json, created_at, expires_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP,$8
)
`, item.TenantID, item.ID, item.VaultID, item.Token, item.OriginalEnc, item.OriginalHash, mustJSON(item.FormatMetadata, "{}"), nullableTime(item.ExpiresAt))
	return err
}

func (s *SQLStore) GetTokenByValue(ctx context.Context, tenantID string, token string) (TokenRecord, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, vault_id, token, original_enc, original_hash, format_metadata_json, created_at, expires_at
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
SELECT tenant_id, id, vault_id, token, original_enc, original_hash, format_metadata_json, created_at, expires_at
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
		createdRaw   interface{}
		expiresAtRaw interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.ID, &item.VaultID, &item.Token, &item.OriginalEnc, &item.OriginalHash, &metaJS, &createdRaw, &expiresAtRaw); err != nil {
		return TokenRecord{}, err
	}
	item.FormatMetadata = parseJSONObject(metaJS)
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
