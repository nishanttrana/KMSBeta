package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errStoreNotFound = errors.New("not found")

type Store interface {
	ListTenants(ctx context.Context) ([]string, error)

	CreateCA(ctx context.Context, ca CA) error
	GetCA(ctx context.Context, tenantID string, caID string) (CA, error)
	ListCAs(ctx context.Context, tenantID string) ([]CA, error)
	DeleteCA(ctx context.Context, tenantID string, caID string) error
	CountChildCAs(ctx context.Context, tenantID string, caID string) (int64, error)
	CountCertificatesByCA(ctx context.Context, tenantID string, caID string) (int64, error)
	UpdateCASignerEncryption(ctx context.Context, tenantID string, caID string, enc EncryptedSigner) error
	ReserveOTSIndex(ctx context.Context, tenantID string, caID string) (int64, error)

	CreateProfile(ctx context.Context, profile CertificateProfile) error
	ListProfiles(ctx context.Context, tenantID string) ([]CertificateProfile, error)
	GetProfile(ctx context.Context, tenantID string, profileID string) (CertificateProfile, error)
	GetProfileByName(ctx context.Context, tenantID string, name string) (CertificateProfile, error)

	CreateCertificate(ctx context.Context, cert Certificate) error
	GetCertificate(ctx context.Context, tenantID string, certID string) (Certificate, error)
	GetCertificateBySerial(ctx context.Context, tenantID string, serial string) (Certificate, error)
	ListCertificates(ctx context.Context, tenantID string, status string, certClass string, limit int, offset int) ([]Certificate, error)
	RevokeCertificate(ctx context.Context, tenantID string, certID string, reason string) error
	DeleteCertificate(ctx context.Context, tenantID string, certID string) error
	UpdateCertificateStatus(ctx context.Context, tenantID string, certID string, status string) error

	ListRevokedByCA(ctx context.Context, tenantID string, caID string) ([]Certificate, error)
	GetPQCReadiness(ctx context.Context, tenantID string) (PQCReadiness, error)
	GetInventory(ctx context.Context, tenantID string) ([]InventoryCertificateItem, error)
	GetProtocolConfig(ctx context.Context, tenantID string, protocol string) (ProtocolConfig, error)
	ListProtocolConfigs(ctx context.Context, tenantID string) ([]ProtocolConfig, error)
	UpsertProtocolConfig(ctx context.Context, cfg ProtocolConfig) error
	GetCertExpiryAlertPolicy(ctx context.Context, tenantID string) (CertExpiryAlertPolicy, error)
	UpsertCertExpiryAlertPolicy(ctx context.Context, item CertExpiryAlertPolicy) error
	ListCertExpiryAlertStates(ctx context.Context, tenantID string) ([]CertExpiryAlertState, error)
	UpsertCertExpiryAlertState(ctx context.Context, item CertExpiryAlertState) error
	DeleteCertExpiryAlertState(ctx context.Context, tenantID string, certID string) error
	GetCertRenewalInfo(ctx context.Context, tenantID string, certID string) (CertRenewalInfo, error)
	GetCertRenewalInfoByARIID(ctx context.Context, tenantID string, ariID string) (CertRenewalInfo, error)
	ListCertRenewalInfo(ctx context.Context, tenantID string, limit int) ([]CertRenewalInfo, error)
	UpsertCertRenewalInfo(ctx context.Context, item CertRenewalInfo) error
	DeleteCertRenewalInfo(ctx context.Context, tenantID string, certID string) error
	GetACMESTARSubscription(ctx context.Context, tenantID string, id string) (ACMESTARSubscription, error)
	ListACMESTARSubscriptions(ctx context.Context, tenantID string, limit int) ([]ACMESTARSubscription, error)
	UpsertACMESTARSubscription(ctx context.Context, item ACMESTARSubscription) error
	DeleteACMESTARSubscription(ctx context.Context, tenantID string, id string) error

	CreateACMEAccount(ctx context.Context, account AcmeAccount) error
	CreateACMEOrder(ctx context.Context, order AcmeOrder) error
	GetACMEOrder(ctx context.Context, tenantID string, orderID string) (AcmeOrder, error)
	UpdateACMEOrder(ctx context.Context, tenantID string, orderID string, status string, csrPEM string, certID string) error

	// Certificate Transparency (Merkle)
	BuildCertMerkleEpoch(ctx context.Context, tenantID string, maxLeaves int) (*CertMerkleEpochResult, error)
	ListCertMerkleEpochs(ctx context.Context, tenantID string, limit int) ([]CertMerkleEpoch, error)
	GetCertMerkleEpoch(ctx context.Context, tenantID string, epochID string) (CertMerkleEpoch, error)
	GetCertMerkleProof(ctx context.Context, tenantID string, certID string) (*CertMerkleProofResponse, error)

	// CT Log Monitor
	ListWatchedDomains(ctx context.Context, tenantID string) ([]WatchedDomain, error)
	AddWatchedDomain(ctx context.Context, d WatchedDomain) (WatchedDomain, error)
	UpdateWatchedDomain(ctx context.Context, tenantID, id string, enabled bool) (WatchedDomain, error)
	DeleteWatchedDomain(ctx context.Context, tenantID, id string) error
	ListCTLogEntries(ctx context.Context, tenantID, domain string, limit int) ([]CTLogEntry, error)
	AddCTLogEntry(ctx context.Context, e CTLogEntry) (CTLogEntry, error)
	ListCTAlerts(ctx context.Context, tenantID string) ([]CTAlert, error)
	CreateCTAlert(ctx context.Context, a CTAlert) (CTAlert, error)
	AcknowledgeCTAlert(ctx context.Context, tenantID, id string) (CTAlert, error)
	BumpCTDomainCertCount(ctx context.Context, tenantID, domain string)
	BumpCTDomainAlertCount(ctx context.Context, tenantID, domain string)

	// mTLS Mesh
	ListMeshServices(ctx context.Context, tenantID string) ([]MeshService, error)
	GetMeshService(ctx context.Context, tenantID, id string) (MeshService, error)
	CreateMeshService(ctx context.Context, svc MeshService) (MeshService, error)
	UpdateMeshServiceCert(ctx context.Context, tenantID, id, certID, certCN string, certExpiry time.Time) error
	CreateMeshCertificate(ctx context.Context, cert MeshCertificate) (MeshCertificate, error)
	ListMeshCertificates(ctx context.Context, tenantID string) ([]MeshCertificate, error)
	ListTrustAnchors(ctx context.Context, tenantID string) ([]TrustAnchor, error)
	CreateTrustAnchor(ctx context.Context, ta TrustAnchor) (TrustAnchor, error)
	GetMeshTopology(ctx context.Context, tenantID string) ([]MeshTopologyEdge, error)
	UpsertTopologyEdge(ctx context.Context, edge MeshTopologyEdge) error
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) ListTenants(ctx context.Context) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id FROM cert_cas
UNION
SELECT tenant_id FROM cert_certificates
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]string, 0)
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		tenantID = strings.TrimSpace(tenantID)
		if tenantID != "" {
			out = append(out, tenantID)
		}
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateCA(ctx context.Context, ca CA) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_cas (
	id, tenant_id, name, parent_ca_id, ca_level, algorithm, ca_type, key_backend, key_ref,
	cert_pem, subject, status, ots_current, ots_max, ots_alert_threshold,
	signer_wrapped_dek, signer_wrapped_dek_iv, signer_ciphertext, signer_data_iv, signer_kek_version, signer_fingerprint_sha256,
	created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,
	$10,$11,$12,$13,$14,$15,
	$16,$17,$18,$19,$20,$21,
	CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
`, ca.ID, ca.TenantID, ca.Name, nullableString(ca.ParentCAID), ca.CALevel, ca.Algorithm, ca.CAType, ca.KeyBackend, ca.KeyRef,
		ca.CertPEM, ca.Subject, ca.Status, ca.OTSCurrent, ca.OTSMax, ca.OTSAlertThreshold,
		ca.SignerWrappedDEK, ca.SignerWrappedDEKIV, ca.SignerCiphertext, ca.SignerDataIV, defaultString(ca.SignerKeyVersion, "legacy-v1"), ca.SignerFingerprint)
	return err
}

func (s *SQLStore) GetCA(ctx context.Context, tenantID string, caID string) (CA, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, COALESCE(parent_ca_id,''), ca_level, algorithm, ca_type, key_backend, key_ref,
	   cert_pem, subject, status, ots_current, ots_max, ots_alert_threshold,
	   signer_wrapped_dek, signer_wrapped_dek_iv, signer_ciphertext, signer_data_iv,
	   COALESCE(signer_kek_version,'legacy-v1'), COALESCE(signer_fingerprint_sha256,''),
	   created_at, updated_at
FROM cert_cas
WHERE tenant_id = $1 AND id = $2
`, tenantID, caID)
	ca, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CA{}, errStoreNotFound
	}
	return ca, err
}

func (s *SQLStore) ListCAs(ctx context.Context, tenantID string) ([]CA, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, COALESCE(parent_ca_id,''), ca_level, algorithm, ca_type, key_backend, key_ref,
	   cert_pem, subject, status, ots_current, ots_max, ots_alert_threshold,
	   signer_wrapped_dek, signer_wrapped_dek_iv, signer_ciphertext, signer_data_iv,
	   COALESCE(signer_kek_version,'legacy-v1'), COALESCE(signer_fingerprint_sha256,''),
	   created_at, updated_at
FROM cert_cas
WHERE tenant_id = $1
ORDER BY created_at ASC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]CA, 0)
	for rows.Next() {
		ca, err := scanCA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ca)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteCA(ctx context.Context, tenantID string, caID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM cert_cas
WHERE tenant_id = $1 AND id = $2
`, tenantID, caID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) CountChildCAs(ctx context.Context, tenantID string, caID string) (int64, error) {
	var count int64
	if err := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(1)
FROM cert_cas
WHERE tenant_id = $1 AND parent_ca_id = $2
`, tenantID, caID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *SQLStore) CountCertificatesByCA(ctx context.Context, tenantID string, caID string) (int64, error) {
	var count int64
	if err := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(1)
FROM cert_certificates
WHERE tenant_id = $1 AND ca_id = $2
`, tenantID, caID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *SQLStore) UpdateCASignerEncryption(ctx context.Context, tenantID string, caID string, enc EncryptedSigner) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE cert_cas
SET signer_wrapped_dek = $1,
    signer_wrapped_dek_iv = $2,
    signer_ciphertext = $3,
    signer_data_iv = $4,
    signer_kek_version = $5,
    signer_fingerprint_sha256 = $6,
    updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $7 AND id = $8
`, enc.WrappedDEK, enc.WrappedDEKIV, enc.Ciphertext, enc.DataIV, defaultString(enc.KeyVersion, "legacy-v1"), enc.Fingerprint, tenantID, caID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) CreateProfile(ctx context.Context, profile CertificateProfile) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_profiles (
	id, tenant_id, name, cert_type, algorithm, cert_class, profile_json, is_default, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP
)
`, profile.ID, profile.TenantID, profile.Name, profile.CertType, profile.Algorithm, profile.CertClass, profile.ProfileJSON, boolToInt(profile.IsDefault))
	return err
}

func (s *SQLStore) ListProfiles(ctx context.Context, tenantID string) ([]CertificateProfile, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, cert_type, algorithm, cert_class, profile_json, is_default, created_at
FROM cert_profiles
WHERE tenant_id = $1
ORDER BY name ASC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]CertificateProfile, 0)
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetProfile(ctx context.Context, tenantID string, profileID string) (CertificateProfile, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, cert_type, algorithm, cert_class, profile_json, is_default, created_at
FROM cert_profiles
WHERE tenant_id = $1 AND id = $2
`, tenantID, profileID)
	p, err := scanProfile(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CertificateProfile{}, errStoreNotFound
	}
	return p, err
}

func (s *SQLStore) GetProfileByName(ctx context.Context, tenantID string, name string) (CertificateProfile, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, cert_type, algorithm, cert_class, profile_json, is_default, created_at
FROM cert_profiles
WHERE tenant_id = $1 AND name = $2
`, tenantID, name)
	p, err := scanProfile(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CertificateProfile{}, errStoreNotFound
	}
	return p, err
}

func (s *SQLStore) CreateCertificate(ctx context.Context, cert Certificate) error {
	sansJSON, _ := json.Marshal(cert.SANs)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_certificates (
	id, tenant_id, ca_id, serial_number, subject_cn, sans_json, cert_type, algorithm,
	profile_id, protocol, cert_class, cert_pem, status, not_before, not_after,
	revoked_at, revocation_reason, key_ref, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,
	$9,$10,$11,$12,$13,$14,$15,
	$16,$17,$18,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
`, cert.ID, cert.TenantID, cert.CAID, cert.SerialNumber, cert.SubjectCN, string(sansJSON), cert.CertType, cert.Algorithm,
		cert.ProfileID, cert.Protocol, cert.CertClass, cert.CertPEM, cert.Status, cert.NotBefore, cert.NotAfter,
		nullableTime(cert.RevokedAt), cert.RevocationReason, cert.KeyRef)
	return err
}

func (s *SQLStore) ReserveOTSIndex(ctx context.Context, tenantID string, caID string) (int64, error) {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.ExecContext(ctx, `
UPDATE cert_cas
SET ots_current = ots_current + 1, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1 AND id = $2 AND (ots_max = 0 OR ots_current < ots_max)
`, tenantID, caID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return 0, errors.New("ots budget exhausted")
	}
	var idx int64
	if err := tx.QueryRowContext(ctx, `SELECT ots_current FROM cert_cas WHERE tenant_id = $1 AND id = $2`, tenantID, caID).Scan(&idx); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return idx, nil
}

func (s *SQLStore) GetCertificate(ctx context.Context, tenantID string, certID string) (Certificate, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, ca_id, serial_number, subject_cn, sans_json, cert_type, algorithm,
	   COALESCE(profile_id,''), protocol, cert_class, cert_pem, status, not_before, not_after,
	   revoked_at, COALESCE(revocation_reason,''), created_at, updated_at, COALESCE(key_ref,'')
FROM cert_certificates
WHERE tenant_id = $1 AND id = $2
`, tenantID, certID)
	c, err := scanCertificate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, errStoreNotFound
	}
	return c, err
}

func (s *SQLStore) GetCertificateBySerial(ctx context.Context, tenantID string, serial string) (Certificate, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, ca_id, serial_number, subject_cn, sans_json, cert_type, algorithm,
	   COALESCE(profile_id,''), protocol, cert_class, cert_pem, status, not_before, not_after,
	   revoked_at, COALESCE(revocation_reason,''), created_at, updated_at, COALESCE(key_ref,'')
FROM cert_certificates
WHERE tenant_id = $1 AND serial_number = $2
`, tenantID, serial)
	c, err := scanCertificate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, errStoreNotFound
	}
	return c, err
}

func (s *SQLStore) ListCertificates(ctx context.Context, tenantID string, status string, certClass string, limit int, offset int) ([]Certificate, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	status = strings.TrimSpace(status)
	certClass = strings.TrimSpace(certClass)
	if strings.EqualFold(status, CertStatusDeleted) {
		// Deleted certificates are fully purged from DB; only audit logs retain references.
		return []Certificate{}, nil
	}

	if status == "" && certClass == "" {
		rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, ca_id, serial_number, subject_cn, sans_json, cert_type, algorithm,
       COALESCE(profile_id,''), protocol, cert_class, cert_pem, status, not_before, not_after,
       revoked_at, COALESCE(revocation_reason,''), created_at, updated_at, COALESCE(key_ref,'')
FROM cert_certificates
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3
`, tenantID, limit, offset)
		if err != nil {
			return nil, err
		}
		defer rows.Close() //nolint:errcheck
		out := make([]Certificate, 0)
		for rows.Next() {
			c, scanErr := scanCertificate(rows)
			if scanErr != nil {
				return nil, scanErr
			}
			out = append(out, c)
		}
		return out, rows.Err()
	}

	qb := strings.Builder{}
	qb.WriteString(`
SELECT id, tenant_id, ca_id, serial_number, subject_cn, sans_json, cert_type, algorithm,
	   COALESCE(profile_id,''), protocol, cert_class, cert_pem, status, not_before, not_after,
	   revoked_at, COALESCE(revocation_reason,''), created_at, updated_at, COALESCE(key_ref,'')
FROM cert_certificates
WHERE tenant_id = $1
`)
	args := []interface{}{tenantID}
	idx := 2
	if status != "" {
		qb.WriteString(" AND status = $" + itoa(idx))
		args = append(args, status)
		idx++
	}
	if certClass != "" {
		qb.WriteString(" AND cert_class = $" + itoa(idx))
		args = append(args, certClass)
		idx++
	}
	qb.WriteString(" ORDER BY created_at DESC LIMIT $" + itoa(idx) + " OFFSET $" + itoa(idx+1))
	args = append(args, limit, offset)

	rows, err := s.db.SQL().QueryContext(ctx, qb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]Certificate, 0)
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLStore) RevokeCertificate(ctx context.Context, tenantID string, certID string, reason string) error {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	row := tx.QueryRowContext(ctx, `
SELECT ca_id, serial_number, status
FROM cert_certificates
WHERE tenant_id = $1 AND id = $2
`, tenantID, certID)
	var caID, serial, status string
	if err := row.Scan(&caID, &serial, &status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errStoreNotFound
		}
		return err
	}
	if status == CertStatusRevoked {
		return nil
	}
	if status == CertStatusDeleted {
		return errors.New("certificate is deleted")
	}
	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx, `
UPDATE cert_certificates
SET status = $1, revoked_at = $2, revocation_reason = $3, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $4 AND id = $5
`, CertStatusRevoked, now, reason, tenantID, certID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errStoreNotFound
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO cert_revocations (tenant_id, cert_id, ca_id, serial_number, reason, revoked_at)
VALUES ($1,$2,$3,$4,$5,$6)
`, tenantID, certID, caID, serial, reason, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) DeleteCertificate(ctx context.Context, tenantID string, certID string) error {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// Verify the certificate exists before deleting
	var exists int
	if err := tx.QueryRowContext(ctx, `
SELECT 1 FROM cert_certificates WHERE tenant_id = $1 AND id = $2
`, tenantID, certID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errStoreNotFound
		}
		return err
	}

	// Clean up related records
	if _, err := tx.ExecContext(ctx, `
DELETE FROM cert_revocations
WHERE tenant_id = $1 AND cert_id = $2
`, tenantID, certID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM cert_expiry_alert_state
WHERE tenant_id = $1 AND cert_id = $2
`, tenantID, certID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE cert_acme_orders
SET cert_id = NULL, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1 AND cert_id = $2
`, tenantID, certID); err != nil {
		return err
	}
	// Also remove from deleted refs if any stale entry exists
	if _, err := tx.ExecContext(ctx, `
DELETE FROM cert_deleted_refs
WHERE tenant_id = $1 AND cert_id = $2
`, tenantID, certID); err != nil {
		return err
	}

	// Hard-delete the certificate from DB
	res, err := tx.ExecContext(ctx, `
DELETE FROM cert_certificates
WHERE tenant_id = $1 AND id = $2
`, tenantID, certID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errStoreNotFound
	}
	return tx.Commit()
}

func (s *SQLStore) UpdateCertificateStatus(ctx context.Context, tenantID string, certID string, status string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE cert_certificates
SET status = $1, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $2 AND id = $3
`, status, tenantID, certID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) ListRevokedByCA(ctx context.Context, tenantID string, caID string) ([]Certificate, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, ca_id, serial_number, subject_cn, sans_json, cert_type, algorithm,
	   COALESCE(profile_id,''), protocol, cert_class, cert_pem, status, not_before, not_after,
	   revoked_at, COALESCE(revocation_reason,''), created_at, updated_at, COALESCE(key_ref,'')
FROM cert_certificates
WHERE tenant_id = $1 AND ca_id = $2 AND status = $3
ORDER BY revoked_at DESC
`, tenantID, caID, CertStatusRevoked)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]Certificate, 0)
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetPQCReadiness(ctx context.Context, tenantID string) (PQCReadiness, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT cert_class, COUNT(1)
FROM cert_certificates
WHERE tenant_id = $1
GROUP BY cert_class
`, tenantID)
	if err != nil {
		return PQCReadiness{}, err
	}
	defer rows.Close() //nolint:errcheck
	out := PQCReadiness{}
	for rows.Next() {
		var class string
		var n int64
		if err := rows.Scan(&class, &n); err != nil {
			return PQCReadiness{}, err
		}
		out.Total += n
		switch strings.ToLower(strings.TrimSpace(class)) {
		case "pqc":
			out.PQC += n
		case "hybrid":
			out.Hybrid += n
		default:
			out.Classical += n
		}
	}
	return out, rows.Err()
}

func (s *SQLStore) GetInventory(ctx context.Context, tenantID string) ([]InventoryCertificateItem, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, ca_id, cert_type, cert_class, status, not_after, COALESCE(profile_id,'')
FROM cert_certificates
WHERE tenant_id = $1
ORDER BY not_after ASC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]InventoryCertificateItem, 0)
	for rows.Next() {
		var (
			it          InventoryCertificateItem
			notAfterRaw interface{}
		)
		if err := rows.Scan(&it.CertID, &it.CAID, &it.CertType, &it.CertClass, &it.Status, &notAfterRaw, &it.ProfileID); err != nil {
			return nil, err
		}
		it.NotAfter = parseTimeValue(notAfterRaw).UTC().Format(time.RFC3339)
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetProtocolConfig(ctx context.Context, tenantID string, protocol string) (ProtocolConfig, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, protocol, enabled, config_json, updated_by, updated_at
FROM cert_protocol_configs
WHERE tenant_id = $1 AND protocol = $2
`, tenantID, protocol)
	cfg, err := scanProtocolConfig(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ProtocolConfig{}, errStoreNotFound
	}
	return cfg, err
}

func (s *SQLStore) ListProtocolConfigs(ctx context.Context, tenantID string) ([]ProtocolConfig, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, protocol, enabled, config_json, updated_by, updated_at
FROM cert_protocol_configs
WHERE tenant_id = $1
ORDER BY protocol ASC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ProtocolConfig, 0)
	for rows.Next() {
		cfg, err := scanProtocolConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cfg)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertProtocolConfig(ctx context.Context, cfg ProtocolConfig) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_protocol_configs (
	tenant_id, protocol, enabled, config_json, updated_by, updated_at
) VALUES (
	$1,$2,$3,$4,$5,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, protocol)
DO UPDATE SET
	enabled = EXCLUDED.enabled,
	config_json = EXCLUDED.config_json,
	updated_by = EXCLUDED.updated_by,
	updated_at = CURRENT_TIMESTAMP
`, cfg.TenantID, cfg.Protocol, boolToInt(cfg.Enabled), defaultString(cfg.ConfigJSON, "{}"), strings.TrimSpace(cfg.UpdatedBy))
	return err
}

func (s *SQLStore) GetCertExpiryAlertPolicy(ctx context.Context, tenantID string) (CertExpiryAlertPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, days_before, include_external, updated_by, updated_at
FROM cert_expiry_alert_policies
WHERE tenant_id = $1
`, tenantID)
	var (
		item         CertExpiryAlertPolicy
		includeRaw   interface{}
		updatedAtRaw interface{}
	)
	if err := row.Scan(
		&item.TenantID,
		&item.DaysBefore,
		&includeRaw,
		&item.UpdatedBy,
		&updatedAtRaw,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CertExpiryAlertPolicy{}, errStoreNotFound
		}
		return CertExpiryAlertPolicy{}, err
	}
	item.IncludeExternal = parseBool(includeRaw)
	item.UpdatedAt = parseTimeValue(updatedAtRaw)
	return item, nil
}

func (s *SQLStore) UpsertCertExpiryAlertPolicy(ctx context.Context, item CertExpiryAlertPolicy) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_expiry_alert_policies (
	tenant_id, days_before, include_external, updated_by, updated_at
) VALUES (
	$1, $2, $3, $4, CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id)
DO UPDATE SET
	days_before = EXCLUDED.days_before,
	include_external = EXCLUDED.include_external,
	updated_by = EXCLUDED.updated_by,
	updated_at = CURRENT_TIMESTAMP
`, item.TenantID, item.DaysBefore, boolToInt(item.IncludeExternal), strings.TrimSpace(item.UpdatedBy))
	return err
}

func (s *SQLStore) ListCertExpiryAlertStates(ctx context.Context, tenantID string) ([]CertExpiryAlertState, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, cert_id, last_days_left, updated_at
FROM cert_expiry_alert_state
WHERE tenant_id = $1
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]CertExpiryAlertState, 0)
	for rows.Next() {
		var (
			item         CertExpiryAlertState
			updatedAtRaw interface{}
		)
		if err := rows.Scan(&item.TenantID, &item.CertID, &item.LastDaysLeft, &updatedAtRaw); err != nil {
			return nil, err
		}
		item.UpdatedAt = parseTimeValue(updatedAtRaw)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertCertExpiryAlertState(ctx context.Context, item CertExpiryAlertState) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_expiry_alert_state (
	tenant_id, cert_id, last_days_left, updated_at
) VALUES (
	$1, $2, $3, CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, cert_id)
DO UPDATE SET
	last_days_left = EXCLUDED.last_days_left,
	updated_at = CURRENT_TIMESTAMP
`, item.TenantID, item.CertID, item.LastDaysLeft)
	return err
}

func (s *SQLStore) DeleteCertExpiryAlertState(ctx context.Context, tenantID string, certID string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM cert_expiry_alert_state
WHERE tenant_id = $1 AND cert_id = $2
`, tenantID, certID)
	return err
}

func (s *SQLStore) CreateACMEAccount(ctx context.Context, account AcmeAccount) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_acme_accounts (id, tenant_id, email, status, created_at)
VALUES ($1,$2,$3,$4,CURRENT_TIMESTAMP)
`, account.ID, account.TenantID, account.Email, account.Status)
	return err
}

func (s *SQLStore) CreateACMEOrder(ctx context.Context, order AcmeOrder) error {
	sansJSON, _ := json.Marshal(order.SANs)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_acme_orders (
	id, tenant_id, account_id, ca_id, subject_cn, sans_json, challenge_id,
	status, csr_pem, cert_id, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,
	$8,$9,$10,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
`, order.ID, order.TenantID, order.AccountID, order.CAID, order.SubjectCN, string(sansJSON), order.ChallengeID,
		order.Status, order.CSRPem, nullableString(order.CertID))
	return err
}

func (s *SQLStore) GetACMEOrder(ctx context.Context, tenantID string, orderID string) (AcmeOrder, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, account_id, ca_id, subject_cn, sans_json, challenge_id,
	   status, COALESCE(csr_pem,''), COALESCE(cert_id,''), created_at, updated_at
FROM cert_acme_orders
WHERE tenant_id = $1 AND id = $2
`, tenantID, orderID)
	var (
		o        AcmeOrder
		sansJSON []byte
		created  interface{}
		updated  interface{}
	)
	if err := row.Scan(&o.ID, &o.TenantID, &o.AccountID, &o.CAID, &o.SubjectCN, &sansJSON, &o.ChallengeID,
		&o.Status, &o.CSRPem, &o.CertID, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AcmeOrder{}, errStoreNotFound
		}
		return AcmeOrder{}, err
	}
	_ = json.Unmarshal(sansJSON, &o.SANs)
	o.CreatedAt = parseTimeValue(created)
	o.UpdatedAt = parseTimeValue(updated)
	return o, nil
}

func (s *SQLStore) UpdateACMEOrder(ctx context.Context, tenantID string, orderID string, status string, csrPEM string, certID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE cert_acme_orders
SET status = $1, csr_pem = $2, cert_id = $3, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $4 AND id = $5
`, status, csrPEM, nullableString(certID), tenantID, orderID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errStoreNotFound
	}
	return nil
}

func scanCA(scanner interface {
	Scan(dest ...interface{}) error
}) (CA, error) {
	var (
		ca                     CA
		createdRaw, updatedRaw interface{}
	)
	err := scanner.Scan(
		&ca.ID, &ca.TenantID, &ca.Name, &ca.ParentCAID, &ca.CALevel, &ca.Algorithm, &ca.CAType, &ca.KeyBackend, &ca.KeyRef,
		&ca.CertPEM, &ca.Subject, &ca.Status, &ca.OTSCurrent, &ca.OTSMax, &ca.OTSAlertThreshold,
		&ca.SignerWrappedDEK, &ca.SignerWrappedDEKIV, &ca.SignerCiphertext, &ca.SignerDataIV,
		&ca.SignerKeyVersion, &ca.SignerFingerprint,
		&createdRaw, &updatedRaw,
	)
	if err != nil {
		return CA{}, err
	}
	ca.CreatedAt = parseTimeValue(createdRaw)
	ca.UpdatedAt = parseTimeValue(updatedRaw)
	return ca, nil
}

func scanProfile(scanner interface {
	Scan(dest ...interface{}) error
}) (CertificateProfile, error) {
	var (
		p       CertificateProfile
		rawDef  interface{}
		created interface{}
	)
	if err := scanner.Scan(&p.ID, &p.TenantID, &p.Name, &p.CertType, &p.Algorithm, &p.CertClass, &p.ProfileJSON, &rawDef, &created); err != nil {
		return CertificateProfile{}, err
	}
	p.IsDefault = parseBool(rawDef)
	p.CreatedAt = parseTimeValue(created)
	return p, nil
}

func scanCertificate(scanner interface {
	Scan(dest ...interface{}) error
}) (Certificate, error) {
	var (
		c          Certificate
		sansJSON   []byte
		notBefore  interface{}
		notAfter   interface{}
		revokedRaw interface{}
		createdRaw interface{}
		updatedRaw interface{}
	)
	if err := scanner.Scan(
		&c.ID, &c.TenantID, &c.CAID, &c.SerialNumber, &c.SubjectCN, &sansJSON, &c.CertType, &c.Algorithm,
		&c.ProfileID, &c.Protocol, &c.CertClass, &c.CertPEM, &c.Status, &notBefore, &notAfter,
		&revokedRaw, &c.RevocationReason, &createdRaw, &updatedRaw, &c.KeyRef,
	); err != nil {
		return Certificate{}, err
	}
	_ = json.Unmarshal(sansJSON, &c.SANs)
	if c.SANs == nil {
		c.SANs = []string{}
	}
	c.NotBefore = parseTimeValue(notBefore)
	c.NotAfter = parseTimeValue(notAfter)
	c.RevokedAt = parseTimeValue(revokedRaw)
	c.CreatedAt = parseTimeValue(createdRaw)
	c.UpdatedAt = parseTimeValue(updatedRaw)
	return c, nil
}

func scanProtocolConfig(scanner interface {
	Scan(dest ...interface{}) error
}) (ProtocolConfig, error) {
	var (
		cfg        ProtocolConfig
		enabledRaw interface{}
		updatedRaw interface{}
	)
	if err := scanner.Scan(
		&cfg.TenantID,
		&cfg.Protocol,
		&enabledRaw,
		&cfg.ConfigJSON,
		&cfg.UpdatedBy,
		&updatedRaw,
	); err != nil {
		return ProtocolConfig{}, err
	}
	cfg.Enabled = parseBool(enabledRaw)
	cfg.UpdatedAt = parseTimeValue(updatedRaw)
	if strings.TrimSpace(cfg.ConfigJSON) == "" {
		cfg.ConfigJSON = "{}"
	}
	return cfg, nil
}

func nullableString(v string) interface{} {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return strings.TrimSpace(v)
}

func nullableTime(v time.Time) interface{} {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func parseBool(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case int:
		return x != 0
	case []byte:
		return string(x) == "1" || strings.EqualFold(string(x), "true")
	case string:
		return x == "1" || strings.EqualFold(x, "true")
	default:
		return false
	}
}

func parseTimeValue(v interface{}) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t.UTC()
	case []byte:
		return parseTimeString(string(t))
	case string:
		return parseTimeString(t)
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
		"2006-01-02T15:04:05",
	}
	for _, f := range formats {
		if ts, err := time.Parse(f, v); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
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
	buf := [20]byte{}
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ── Certificate Transparency (Merkle) ────────────────────────

func certLeafHash(certPEM string) string {
	h := sha256.Sum256([]byte(certPEM))
	return hex.EncodeToString(h[:])
}

func (s *SQLStore) BuildCertMerkleEpoch(ctx context.Context, tenantID string, maxLeaves int) (*CertMerkleEpochResult, error) {
	if maxLeaves <= 0 {
		maxLeaves = 500
	}

	// Find certificates not yet logged in any Merkle epoch
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT c.id, c.serial_number, c.subject_cn, c.cert_pem
FROM cert_certificates c
WHERE c.tenant_id=$1
  AND NOT EXISTS (
    SELECT 1 FROM cert_merkle_leaves ml
    WHERE ml.tenant_id=c.tenant_id AND ml.cert_id=c.id
  )
ORDER BY c.created_at ASC
LIMIT $2
`, tenantID, maxLeaves)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type leafData struct {
		certID       string
		serialNumber string
		subjectCN    string
		certPEM      string
	}
	var leaves []leafData
	for rows.Next() {
		var l leafData
		if err := rows.Scan(&l.certID, &l.serialNumber, &l.subjectCN, &l.certPEM); err != nil {
			return nil, err
		}
		leaves = append(leaves, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(leaves) == 0 {
		return nil, nil
	}

	// Hash each certificate PEM to produce leaf hashes
	hashes := make([]string, len(leaves))
	for i, l := range leaves {
		hashes[i] = certLeafHash(l.certPEM)
	}

	tree := BuildMerkleTree(hashes)
	root := tree.Root()

	// Next epoch number
	var epochNum int
	err = s.db.SQL().QueryRowContext(ctx, `
SELECT COALESCE(MAX(epoch_number), 0) + 1 FROM cert_merkle_epochs WHERE tenant_id=$1
`, tenantID).Scan(&epochNum)
	if err != nil {
		return nil, err
	}

	epochID := newID("cme")

	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
INSERT INTO cert_merkle_epochs (id, tenant_id, epoch_number, leaf_count, tree_root, created_at)
VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
`, epochID, tenantID, epochNum, len(leaves), root)
	if err != nil {
		return nil, err
	}

	for i, l := range leaves {
		_, err = tx.ExecContext(ctx, `
INSERT INTO cert_merkle_leaves (epoch_id, tenant_id, leaf_index, cert_id, serial_number, subject_cn, leaf_hash, logged_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
`, epochID, tenantID, i, l.certID, l.serialNumber, l.subjectCN, hashes[i])
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	epoch := CertMerkleEpoch{
		ID:          epochID,
		TenantID:    tenantID,
		EpochNumber: epochNum,
		LeafCount:   len(leaves),
		TreeRoot:    root,
	}
	return &CertMerkleEpochResult{Epoch: epoch, Leaves: len(leaves)}, nil
}

func (s *SQLStore) ListCertMerkleEpochs(ctx context.Context, tenantID string, limit int) ([]CertMerkleEpoch, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, epoch_number, leaf_count, tree_root, created_at
FROM cert_merkle_epochs
WHERE tenant_id=$1
ORDER BY epoch_number DESC
LIMIT $2
`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CertMerkleEpoch
	for rows.Next() {
		var e CertMerkleEpoch
		var createdRaw interface{}
		if err := rows.Scan(&e.ID, &e.TenantID, &e.EpochNumber, &e.LeafCount, &e.TreeRoot, &createdRaw); err != nil {
			return nil, err
		}
		e.CreatedAt = parseTimeValue(createdRaw)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetCertMerkleEpoch(ctx context.Context, tenantID string, epochID string) (CertMerkleEpoch, error) {
	var e CertMerkleEpoch
	var createdRaw interface{}
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, epoch_number, leaf_count, tree_root, created_at
FROM cert_merkle_epochs
WHERE tenant_id=$1 AND id=$2
`, tenantID, epochID).Scan(&e.ID, &e.TenantID, &e.EpochNumber, &e.LeafCount, &e.TreeRoot, &createdRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return CertMerkleEpoch{}, errStoreNotFound
	}
	if err != nil {
		return CertMerkleEpoch{}, err
	}
	e.CreatedAt = parseTimeValue(createdRaw)
	return e, nil
}

func (s *SQLStore) GetCertMerkleProof(ctx context.Context, tenantID string, certID string) (*CertMerkleProofResponse, error) {
	// Find which epoch contains this certificate
	var leaf CertMerkleLeaf
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT epoch_id, tenant_id, leaf_index, cert_id, serial_number, subject_cn, leaf_hash
FROM cert_merkle_leaves
WHERE tenant_id=$1 AND cert_id=$2
`, tenantID, certID).Scan(&leaf.EpochID, &leaf.TenantID, &leaf.LeafIndex, &leaf.CertID, &leaf.SerialNumber, &leaf.SubjectCN, &leaf.LeafHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errStoreNotFound
	}
	if err != nil {
		return nil, err
	}

	// Fetch all leaves in this epoch to rebuild tree
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT leaf_hash FROM cert_merkle_leaves
WHERE tenant_id=$1 AND epoch_id=$2
ORDER BY leaf_index ASC
`, tenantID, leaf.EpochID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	tree := BuildMerkleTree(hashes)
	proof, ok := GenerateProof(tree, leaf.LeafIndex)
	if !ok {
		return nil, fmt.Errorf("failed to generate proof for leaf %d", leaf.LeafIndex)
	}

	return &CertMerkleProofResponse{
		CertID:       leaf.CertID,
		SerialNumber: leaf.SerialNumber,
		SubjectCN:    leaf.SubjectCN,
		EpochID:      leaf.EpochID,
		LeafHash:     leaf.LeafHash,
		LeafIndex:    leaf.LeafIndex,
		Siblings:     proof.Siblings,
		Root:         proof.Root,
	}, nil
}
