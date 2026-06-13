package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// CredentialBinding records that an external credential (identified only by a
// non-reversible fingerprint) is protected by a KMS key. It is the join key
// the unified Threat & Exposure console uses to correlate a leaked credential
// with anomalous usage of the key that wraps it.
type CredentialBinding struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Fingerprint    string    `json:"fingerprint"`
	CredentialType string    `json:"credential_type"`
	KeyID          string    `json:"key_id"`
	Label          string    `json:"label"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}

// credentialFingerprint MUST match the posture leak scanner's formula:
// lowercase hex SHA-256 of the raw credential value.
func credentialFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *SQLStore) UpsertCredentialBinding(ctx context.Context, b CredentialBinding) (CredentialBinding, error) {
	if b.ID == "" {
		b.ID = newID("crb")
	}
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO external_credential_bindings (id, tenant_id, fingerprint, credential_type, key_id, label, created_by, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (tenant_id, fingerprint)
DO UPDATE SET credential_type=EXCLUDED.credential_type, key_id=EXCLUDED.key_id, label=EXCLUDED.label`,
		b.ID, b.TenantID, b.Fingerprint, b.CredentialType, b.KeyID, b.Label, b.CreatedBy, b.CreatedAt)
	if err != nil {
		return CredentialBinding{}, err
	}
	return b, nil
}

func (s *SQLStore) ListCredentialBindingsByKey(ctx context.Context, tenantID, keyID string) ([]CredentialBinding, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, fingerprint, credential_type, key_id, label, created_by, created_at
FROM external_credential_bindings WHERE tenant_id=$1 AND key_id=$2
ORDER BY created_at DESC`, tenantID, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []CredentialBinding
	for rows.Next() {
		b, err := scanCredentialBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteCredentialBinding(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx,
		`DELETE FROM external_credential_bindings WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

// ResolveCredentialBindings returns the bindings matching any of the supplied
// fingerprints, keyed by fingerprint.
func (s *SQLStore) ResolveCredentialBindings(ctx context.Context, tenantID string, fingerprints []string) (map[string]CredentialBinding, error) {
	out := map[string]CredentialBinding{}
	if len(fingerprints) == 0 {
		return out, nil
	}
	// Build an IN clause with positional params ($2..$N); $1 is the tenant.
	args := make([]any, 0, len(fingerprints)+1)
	args = append(args, tenantID)
	placeholders := make([]byte, 0, len(fingerprints)*5)
	for i, fp := range fingerprints {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '$')
		placeholders = append(placeholders, []byte(itoaSmall(i+2))...)
		args = append(args, fp)
	}
	q := `SELECT id, tenant_id, fingerprint, credential_type, key_id, label, created_by, created_at
FROM external_credential_bindings WHERE tenant_id=$1 AND fingerprint IN (` + string(placeholders) + `)`
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		b, err := scanCredentialBinding(rows)
		if err != nil {
			return nil, err
		}
		out[b.Fingerprint] = b
	}
	return out, rows.Err()
}

func scanCredentialBinding(s interface{ Scan(...any) error }) (CredentialBinding, error) {
	var b CredentialBinding
	err := s.Scan(&b.ID, &b.TenantID, &b.Fingerprint, &b.CredentialType, &b.KeyID, &b.Label, &b.CreatedBy, &b.CreatedAt)
	return b, err
}

func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
