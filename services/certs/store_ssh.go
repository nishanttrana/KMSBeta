package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// SSH certificate authorities and their certificates (migration 017,
// ssh_ca.go).

const sshCAColumns = `id, tenant_id, name, algorithm, key_backend, key_ref, public_key, public_key_pem, fingerprint,
	   cert_types, allowed_principals, max_validity_seconds, default_extensions, status,
	   signer_wrapped_dek, signer_wrapped_dek_iv, signer_ciphertext, signer_data_iv,
	   COALESCE(signer_kek_version,'legacy-v1'), COALESCE(signer_fingerprint_sha256,''),
	   created_by, created_at, updated_at`

func (s *SQLStore) CreateSSHCA(ctx context.Context, ca SSHCA) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_ssh_cas (id, tenant_id, name, algorithm, key_backend, key_ref, public_key, public_key_pem, fingerprint,
	cert_types, allowed_principals, max_validity_seconds, default_extensions, status,
	signer_wrapped_dek, signer_wrapped_dek_iv, signer_ciphertext, signer_data_iv, signer_kek_version, signer_fingerprint_sha256,
	created_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$22)
`, ca.ID, ca.TenantID, ca.Name, ca.Algorithm, ca.KeyBackend, ca.KeyRef, ca.PublicKey, ca.PublicKeyPEM, ca.Fingerprint,
		mustJSONList(ca.CertTypes), mustJSONList(ca.AllowedPrincipals), ca.MaxValiditySeconds, mustJSONList(ca.DefaultExtensions), ca.Status,
		ca.signer.WrappedDEK, ca.signer.WrappedDEKIV, ca.signer.Ciphertext, ca.signer.DataIV,
		defaultString(ca.signer.KeyVersion, "legacy-v1"), ca.signer.Fingerprint,
		ca.CreatedBy, ca.CreatedAt.UTC())
	return err
}

func (s *SQLStore) GetSSHCA(ctx context.Context, tenantID, id string) (SSHCA, error) {
	ca, err := scanSSHCA(s.db.SQL().QueryRowContext(ctx, `SELECT `+sshCAColumns+` FROM cert_ssh_cas WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return SSHCA{}, errStoreNotFound
	}
	return ca, err
}

func (s *SQLStore) ListSSHCAs(ctx context.Context, tenantID string) ([]SSHCA, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+sshCAColumns+` FROM cert_ssh_cas WHERE tenant_id = $1 ORDER BY created_at ASC, id ASC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []SSHCA{}
	for rows.Next() {
		ca, err := scanSSHCA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ca)
	}
	return out, rows.Err()
}

// UpdateSSHCAPolicy changes what a CA signs; its key never changes.
func (s *SQLStore) UpdateSSHCAPolicy(ctx context.Context, ca SSHCA) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE cert_ssh_cas SET cert_types = $1, allowed_principals = $2, max_validity_seconds = $3, default_extensions = $4,
	status = $5, updated_at = $6
WHERE tenant_id = $7 AND id = $8
`, mustJSONList(ca.CertTypes), mustJSONList(ca.AllowedPrincipals), ca.MaxValiditySeconds, mustJSONList(ca.DefaultExtensions),
		ca.Status, time.Now().UTC().Truncate(time.Microsecond), ca.TenantID, ca.ID)
	return oneRow(res, err)
}

func (s *SQLStore) UpdateSSHCASignerEncryption(ctx context.Context, tenantID, id string, enc EncryptedSigner) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE cert_ssh_cas SET signer_wrapped_dek = $1, signer_wrapped_dek_iv = $2, signer_ciphertext = $3, signer_data_iv = $4,
	signer_kek_version = $5, signer_fingerprint_sha256 = $6, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $7 AND id = $8
`, enc.WrappedDEK, enc.WrappedDEKIV, enc.Ciphertext, enc.DataIV, defaultString(enc.KeyVersion, "legacy-v1"), enc.Fingerprint, tenantID, id)
	return oneRow(res, err)
}

const sshCertColumns = `id, tenant_id, ca_id, serial, cert_type, key_id, principals, key_type, key_fingerprint,
	   extensions, critical_options, valid_after, valid_before, issued_by, issued_at, revoked_at, revoked_by, revoke_reason`

func (s *SQLStore) CreateSSHCertificate(ctx context.Context, c SSHCertificate) error {
	opts, _ := json.Marshal(c.CriticalOptions)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_ssh_certificates (`+strings.ReplaceAll(sshCertColumns, "\n\t   ", " ")+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NULL,'','')
`, c.ID, c.TenantID, c.CAID, c.Serial, c.CertType, c.KeyID, mustJSONList(c.Principals), c.KeyType, c.KeyFingerprint,
		mustJSONList(c.Extensions), string(opts), c.ValidAfter.UTC(), c.ValidBefore.UTC(), c.IssuedBy, c.IssuedAt.UTC())
	return err
}

func (s *SQLStore) GetSSHCertificate(ctx context.Context, tenantID, id string) (SSHCertificate, error) {
	c, err := scanSSHCertificate(s.db.SQL().QueryRowContext(ctx, `SELECT `+sshCertColumns+` FROM cert_ssh_certificates WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return SSHCertificate{}, errStoreNotFound
	}
	return c, err
}

// ListSSHCertificates lists a CA's certificates, newest first; revokedOnly
// is what its KRL needs.
func (s *SQLStore) ListSSHCertificates(ctx context.Context, tenantID, caID string, revokedOnly bool, limit int) ([]SSHCertificate, error) {
	q := `SELECT ` + sshCertColumns + ` FROM cert_ssh_certificates WHERE tenant_id = $1 AND ca_id = $2`
	if revokedOnly {
		q += ` AND revoked_at IS NOT NULL`
	}
	q += ` ORDER BY issued_at DESC, id DESC LIMIT $3`
	rows, err := s.db.SQL().QueryContext(ctx, q, tenantID, caID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []SSHCertificate{}
	for rows.Next() {
		c, err := scanSSHCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RevokeSSHCertificate marks a certificate revoked once; a second call
// changes nothing and reports errStoreNotFound.
func (s *SQLStore) RevokeSSHCertificate(ctx context.Context, tenantID, id, by, reason string, at time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE cert_ssh_certificates SET revoked_at = $1, revoked_by = $2, revoke_reason = $3
WHERE tenant_id = $4 AND id = $5 AND revoked_at IS NULL
`, at.UTC(), by, reason, tenantID, id)
	return oneRow(res, err)
}

func oneRow(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func mustJSONList(v []string) string {
	if v == nil {
		v = []string{}
	}
	raw, _ := json.Marshal(v)
	return string(raw)
}

func jsonList(raw string) []string {
	out := []string{}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func scanSSHCA(scanner interface {
	Scan(dest ...interface{}) error
}) (SSHCA, error) {
	var (
		ca                      SSHCA
		types, principals, exts string
		createdRaw, updatedRaw  interface{}
	)
	err := scanner.Scan(&ca.ID, &ca.TenantID, &ca.Name, &ca.Algorithm, &ca.KeyBackend, &ca.KeyRef, &ca.PublicKey, &ca.PublicKeyPEM, &ca.Fingerprint,
		&types, &principals, &ca.MaxValiditySeconds, &exts, &ca.Status,
		&ca.signer.WrappedDEK, &ca.signer.WrappedDEKIV, &ca.signer.Ciphertext, &ca.signer.DataIV, &ca.signer.KeyVersion, &ca.signer.Fingerprint,
		&ca.CreatedBy, &createdRaw, &updatedRaw)
	if err != nil {
		return SSHCA{}, err
	}
	ca.CertTypes, ca.AllowedPrincipals, ca.DefaultExtensions = jsonList(types), jsonList(principals), jsonList(exts)
	ca.CreatedAt, ca.UpdatedAt = parseTimeValue(createdRaw), parseTimeValue(updatedRaw)
	return ca, nil
}

func scanSSHCertificate(scanner interface {
	Scan(dest ...interface{}) error
}) (SSHCertificate, error) {
	var (
		c                                 SSHCertificate
		principals, exts, opts            string
		after, before, issued, revokedRaw interface{}
	)
	err := scanner.Scan(&c.ID, &c.TenantID, &c.CAID, &c.Serial, &c.CertType, &c.KeyID, &principals, &c.KeyType, &c.KeyFingerprint,
		&exts, &opts, &after, &before, &c.IssuedBy, &issued, &revokedRaw, &c.RevokedBy, &c.RevokeReason)
	if err != nil {
		return SSHCertificate{}, err
	}
	c.Principals, c.Extensions = jsonList(principals), jsonList(exts)
	c.CriticalOptions = map[string]string{}
	_ = json.Unmarshal([]byte(opts), &c.CriticalOptions)
	c.ValidAfter, c.ValidBefore, c.IssuedAt = parseTimeValue(after), parseTimeValue(before), parseTimeValue(issued)
	if t := parseTimeValue(revokedRaw); !t.IsZero() {
		c.RevokedAt = &t
	}
	return c, nil
}
