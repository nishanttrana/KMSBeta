package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Persistence for working-key derivation versioning (see kdf.go).

type KeyKDFState struct {
	TenantID        string    `json:"tenant_id"`
	KeyID           string    `json:"key_id"`
	State           string    `json:"state"`
	KeyVersion      int       `json:"key_version"`
	LegacyUses      int64     `json:"legacy_uses"`
	LastLegacyUseAt time.Time `json:"last_legacy_use_at,omitempty"`
	UpdatedBy       string    `json:"updated_by"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	// LegacyVaultTokens is filled by the service for status views.
	LegacyVaultTokens int `json:"legacy_vault_tokens"`
}

func kdfVersionOrLegacy(v string) string {
	if strings.TrimSpace(v) == kdfV2 {
		return kdfV2
	}
	return kdfV1
}

func (s *SQLStore) GetKDFCutoff(ctx context.Context) (time.Time, error) {
	var raw interface{}
	err := s.db.SQL().QueryRowContext(ctx, `SELECT v2_cutoff FROM dataprotect_kdf_meta WHERE id = 1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, errNotFound
	}
	if err != nil {
		return time.Time{}, err
	}
	return parseTimeValue(raw), nil
}

const keyKDFColumns = `tenant_id, key_id, state, key_version, legacy_uses, last_legacy_use_at, updated_by, created_at, updated_at`

func scanKeyKDF(scanner interface {
	Scan(dest ...interface{}) error
}) (KeyKDFState, error) {
	var (
		item                        KeyKDFState
		lastRaw, createdRaw, updRaw interface{}
	)
	if err := scanner.Scan(&item.TenantID, &item.KeyID, &item.State, &item.KeyVersion, &item.LegacyUses, &lastRaw, &item.UpdatedBy, &createdRaw, &updRaw); err != nil {
		return KeyKDFState{}, err
	}
	item.LastLegacyUseAt = parseTimeValue(lastRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updRaw)
	return item, nil
}

func (s *SQLStore) GetKeyKDF(ctx context.Context, tenantID string, keyID string) (KeyKDFState, error) {
	item, err := scanKeyKDF(s.db.SQL().QueryRowContext(ctx, `SELECT `+keyKDFColumns+` FROM dataprotect_key_kdf WHERE tenant_id = $1 AND key_id = $2`,
		strings.TrimSpace(tenantID), strings.TrimSpace(keyID)))
	if errors.Is(err, sql.ErrNoRows) {
		return KeyKDFState{}, errNotFound
	}
	return item, err
}

// InsertKeyKDFIfAbsent records a key's initial state; a concurrent first use
// that already inserted wins, and the caller re-reads.
func (s *SQLStore) InsertKeyKDFIfAbsent(ctx context.Context, item KeyKDFState) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO dataprotect_key_kdf (tenant_id, key_id, state, key_version, updated_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id, key_id) DO NOTHING
`, item.TenantID, item.KeyID, item.State, item.KeyVersion, item.UpdatedBy)
	return err
}

// TransitionKeyKDF moves a key from one state to another; errNotFound when the
// key is not currently in fromState (so concurrent transitions cannot race).
func (s *SQLStore) TransitionKeyKDF(ctx context.Context, tenantID, keyID, fromState, toState string, keyVersion int, actor string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE dataprotect_key_kdf SET state = $1, key_version = $2, updated_by = $3, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $4 AND key_id = $5 AND state = $6
`, toState, keyVersion, actor, strings.TrimSpace(tenantID), strings.TrimSpace(keyID), fromState)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) AddKeyKDFLegacyUses(ctx context.Context, tenantID, keyID string, n int64, at time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE dataprotect_key_kdf SET legacy_uses = legacy_uses + $1, last_legacy_use_at = $2
WHERE tenant_id = $3 AND key_id = $4
`, n, at.UTC(), strings.TrimSpace(tenantID), strings.TrimSpace(keyID))
	return err
}

func (s *SQLStore) ListKeyKDF(ctx context.Context, tenantID string) ([]KeyKDFState, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+keyKDFColumns+` FROM dataprotect_key_kdf WHERE tenant_id = $1 ORDER BY state, key_id`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []KeyKDFState{}
	for rows.Next() {
		item, err := scanKeyKDF(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ListLegacyTokensForKey returns stored vault tokens of vaults bound to keyID
// that are still protected with the legacy (v1) derivation.
func (s *SQLStore) ListLegacyTokensForKey(ctx context.Context, tenantID, keyID string, limit int) ([]TokenRecord, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT t.tenant_id, t.id, t.vault_id, t.token, t.original_enc, t.original_hash, t.format_metadata_json, t.use_count, t.use_limit, t.renew_count, t.metadata_tags_json, t.created_at, t.expires_at, t.kdf_version, t.kdf_key_version
FROM tokens t JOIN token_vaults v ON v.tenant_id = t.tenant_id AND v.id = t.vault_id
WHERE t.tenant_id = $1 AND v.key_id = $2 AND t.kdf_version = 'v1'
ORDER BY t.id
LIMIT $3
`, strings.TrimSpace(tenantID), strings.TrimSpace(keyID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []TokenRecord{}
	for rows.Next() {
		item, err := scanTokenRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CountLegacyTokensForKey(ctx context.Context, tenantID, keyID string) (int, error) {
	var n int
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(1) FROM tokens t JOIN token_vaults v ON v.tenant_id = t.tenant_id AND v.id = t.vault_id
WHERE t.tenant_id = $1 AND v.key_id = $2 AND t.kdf_version = 'v1'
`, strings.TrimSpace(tenantID), strings.TrimSpace(keyID)).Scan(&n)
	return n, err
}

// ReprotectToken rewrites one token's protected original and lookup hash under
// a new derivation, only if it is still at expectVersion (idempotent re-runs).
func (s *SQLStore) ReprotectToken(ctx context.Context, tenantID, id string, enc []byte, hash, expectVersion, newVersion string, keyVersion int) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE tokens SET original_enc = $1, original_hash = $2, kdf_version = $3, kdf_key_version = $4
WHERE tenant_id = $5 AND id = $6 AND kdf_version = $7
`, enc, hash, newVersion, keyVersion, strings.TrimSpace(tenantID), strings.TrimSpace(id), expectVersion)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}
