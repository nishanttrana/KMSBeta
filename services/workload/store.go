package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/mek"
)

type Store interface {
	GetSettings(ctx context.Context, tenantID string) (WorkloadIdentitySettings, error)
	UpsertSettings(ctx context.Context, item WorkloadIdentitySettings) (WorkloadIdentitySettings, error)
	ListRegistrations(ctx context.Context, tenantID string) ([]WorkloadRegistration, error)
	GetRegistration(ctx context.Context, tenantID string, id string) (WorkloadRegistration, error)
	GetRegistrationBySPIFFEID(ctx context.Context, tenantID string, spiffeID string) (WorkloadRegistration, error)
	UpsertRegistration(ctx context.Context, item WorkloadRegistration) (WorkloadRegistration, error)
	DeleteRegistration(ctx context.Context, tenantID string, id string) error
	TouchRegistrationIssued(ctx context.Context, tenantID string, id string, ts time.Time) error
	TouchRegistrationUsed(ctx context.Context, tenantID string, id string, ts time.Time) error
	ListFederationBundles(ctx context.Context, tenantID string) ([]WorkloadFederationBundle, error)
	GetFederationBundleByTrustDomain(ctx context.Context, tenantID string, trustDomain string) (WorkloadFederationBundle, error)
	UpsertFederationBundle(ctx context.Context, item WorkloadFederationBundle) (WorkloadFederationBundle, error)
	DeleteFederationBundle(ctx context.Context, tenantID string, id string) error
	InsertIssuanceRecord(ctx context.Context, item WorkloadIssuanceRecord) error
	ListIssuanceRecords(ctx context.Context, tenantID string, limit int) ([]WorkloadIssuanceRecord, error)
}

type SQLStore struct {
	db   *pkgdb.DB
	keys *mek.Keyring // seals the tenant signing keys (signing_keys.go)
}

func NewSQLStore(db *pkgdb.DB, keys *mek.Keyring) *SQLStore {
	return &SQLStore{db: db, keys: keys}
}

// settingsColumns are read by GetSettings. The private keys come from the
// sealed envelope, or from the plaintext columns of a row an earlier release
// wrote that the primary hasn't sealed yet.
const settingsColumns = `tenant_id, enabled, trust_domain, federation_enabled, token_exchange_enabled,
       default_x509_ttl_sec, default_jwt_ttl_sec, rotation_window_sec, allowed_audiences_json,
       local_bundle_jwks, local_ca_cert_pem, jwt_signer_public_pem, jwt_signer_kid,
       COALESCE(updated_by,''), updated_at,
       local_ca_key_pem, jwt_signer_private_pem,
       signing_ciphertext, signing_data_iv, signing_wrapped_dek, signing_wrapped_dek_iv`

func (s *SQLStore) GetSettings(ctx context.Context, tenantID string) (WorkloadIdentitySettings, error) {
	row := s.db.SQL().QueryRowContext(ctx, `SELECT `+settingsColumns+`
FROM workload_identity_settings
WHERE tenant_id = $1
`, strings.TrimSpace(tenantID))

	var (
		item                     WorkloadIdentitySettings
		allowedAudiencesJSON     string
		updatedRaw               interface{}
		ct, dataIV, dek, dekIV   []byte
		plainCAKey, plainJWTPriv string
	)
	if err := row.Scan(
		&item.TenantID,
		&item.Enabled,
		&item.TrustDomain,
		&item.FederationEnabled,
		&item.TokenExchangeEnabled,
		&item.DefaultX509TTLSeconds,
		&item.DefaultJWTTTLSeconds,
		&item.RotationWindowSeconds,
		&allowedAudiencesJSON,
		&item.LocalBundleJWKS,
		&item.LocalCACertificatePEM,
		&item.JWTSignerPublicPEM,
		&item.JWTSignerKeyID,
		&item.UpdatedBy,
		&updatedRaw,
		&plainCAKey,
		&plainJWTPriv,
		&ct, &dataIV, &dek, &dekIV,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WorkloadIdentitySettings{}, errNotFound
		}
		return WorkloadIdentitySettings{}, err
	}
	item.AllowedAudiences = parseJSONArrayString(allowedAudiencesJSON)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	switch env := envelopeFromColumns(ct, dataIV, dek, dekIV); {
	case plainCAKey != "" || plainJWTPriv != "":
		// Not sealed yet: the primary seals exactly these values.
		item.LocalCAKeyPEM, item.JWTSignerPrivatePEM = plainCAKey, plainJWTPriv
	case env != nil:
		caKey, jwtPriv, err := openSigningKeys(s.keys, item.TenantID, env)
		if err != nil {
			return WorkloadIdentitySettings{}, err
		}
		item.LocalCAKeyPEM, item.JWTSignerPrivatePEM = caKey, jwtPriv
	}
	return item, nil
}

// UpsertSettings stores item with its private keys sealed; the plaintext
// columns are always written empty.
func (s *SQLStore) UpsertSettings(ctx context.Context, item WorkloadIdentitySettings) (WorkloadIdentitySettings, error) {
	env, err := sealSigningKeys(s.keys, item.TenantID, item.LocalCAKeyPEM, item.JWTSignerPrivatePEM)
	if err != nil {
		return WorkloadIdentitySettings{}, err
	}
	var ct, dataIV, dek, dekIV []byte
	if env != nil {
		ct, dataIV, dek, dekIV = env.Ciphertext, env.DataIV, env.WrappedDEK, env.WrappedDEKIV
	}
	var updatedRaw interface{}
	if err := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO workload_identity_settings (
  tenant_id, enabled, trust_domain, federation_enabled, token_exchange_enabled,
  default_x509_ttl_sec, default_jwt_ttl_sec, rotation_window_sec, allowed_audiences_json,
  local_bundle_jwks, local_ca_cert_pem, jwt_signer_public_pem, jwt_signer_kid,
  local_ca_key_pem, jwt_signer_private_pem,
  signing_ciphertext, signing_data_iv, signing_wrapped_dek, signing_wrapped_dek_iv,
  updated_by, updated_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'','',$14,$15,$16,$17,$18,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id) DO UPDATE SET
  enabled = EXCLUDED.enabled,
  trust_domain = EXCLUDED.trust_domain,
  federation_enabled = EXCLUDED.federation_enabled,
  token_exchange_enabled = EXCLUDED.token_exchange_enabled,
  default_x509_ttl_sec = EXCLUDED.default_x509_ttl_sec,
  default_jwt_ttl_sec = EXCLUDED.default_jwt_ttl_sec,
  rotation_window_sec = EXCLUDED.rotation_window_sec,
  allowed_audiences_json = EXCLUDED.allowed_audiences_json,
  local_bundle_jwks = EXCLUDED.local_bundle_jwks,
  local_ca_cert_pem = EXCLUDED.local_ca_cert_pem,
  jwt_signer_public_pem = EXCLUDED.jwt_signer_public_pem,
  jwt_signer_kid = EXCLUDED.jwt_signer_kid,
  local_ca_key_pem = '',
  jwt_signer_private_pem = '',
  signing_ciphertext = EXCLUDED.signing_ciphertext,
  signing_data_iv = EXCLUDED.signing_data_iv,
  signing_wrapped_dek = EXCLUDED.signing_wrapped_dek,
  signing_wrapped_dek_iv = EXCLUDED.signing_wrapped_dek_iv,
  updated_by = EXCLUDED.updated_by,
  updated_at = CURRENT_TIMESTAMP
RETURNING updated_at
`, item.TenantID,
		item.Enabled,
		item.TrustDomain,
		item.FederationEnabled,
		item.TokenExchangeEnabled,
		item.DefaultX509TTLSeconds,
		item.DefaultJWTTTLSeconds,
		item.RotationWindowSeconds,
		validJSONOr(mustJSON(item.AllowedAudiences), "[]"),
		item.LocalBundleJWKS,
		item.LocalCACertificatePEM,
		item.JWTSignerPublicPEM,
		item.JWTSignerKeyID,
		ct, dataIV, dek, dekIV,
		item.UpdatedBy,
	).Scan(&updatedRaw); err != nil {
		return WorkloadIdentitySettings{}, err
	}
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

// plaintextSigningRow is a row an earlier release stored in plaintext.
type plaintextSigningRow struct {
	TenantID            string
	CAKeyPEM            string
	JWTSignerPrivatePEM string
}

func (s *SQLStore) listPlaintextSigningKeys(ctx context.Context) ([]plaintextSigningRow, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, local_ca_key_pem, jwt_signer_private_pem
FROM workload_identity_settings
WHERE local_ca_key_pem <> '' OR jwt_signer_private_pem <> ''
ORDER BY tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []plaintextSigningRow
	for rows.Next() {
		var r plaintextSigningRow
		if err := rows.Scan(&r.TenantID, &r.CAKeyPEM, &r.JWTSignerPrivatePEM); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// replacePlaintextSigningKeys writes env and empties the plaintext columns,
// only if the row still holds the plaintext that was read.
func (s *SQLStore) replacePlaintextSigningKeys(ctx context.Context, r plaintextSigningRow, env *pkgcrypto.EnvelopeCiphertext) (bool, error) {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE workload_identity_settings
SET signing_ciphertext = $1, signing_data_iv = $2, signing_wrapped_dek = $3, signing_wrapped_dek_iv = $4,
    local_ca_key_pem = '', jwt_signer_private_pem = ''
WHERE tenant_id = $5 AND local_ca_key_pem = $6 AND jwt_signer_private_pem = $7`,
		env.Ciphertext, env.DataIV, env.WrappedDEK, env.WrappedDEKIV, r.TenantID, r.CAKeyPEM, r.JWTSignerPrivatePEM)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *SQLStore) ListRegistrations(ctx context.Context, tenantID string) ([]WorkloadRegistration, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, spiffe_id, selectors_json, allowed_interfaces_json, allowed_key_ids_json,
       permissions_json, issue_x509_svid, issue_jwt_svid, default_ttl_sec, enabled,
       last_issued_at, last_used_at, created_at, updated_at
FROM workload_identity_registrations
WHERE tenant_id = $1
ORDER BY name ASC, spiffe_id ASC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []WorkloadRegistration{}
	for rows.Next() {
		item, err := scanRegistration(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLStore) GetRegistration(ctx context.Context, tenantID string, id string) (WorkloadRegistration, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, spiffe_id, selectors_json, allowed_interfaces_json, allowed_key_ids_json,
       permissions_json, issue_x509_svid, issue_jwt_svid, default_ttl_sec, enabled,
       last_issued_at, last_used_at, created_at, updated_at
FROM workload_identity_registrations
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanRegistration(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WorkloadRegistration{}, errNotFound
		}
		return WorkloadRegistration{}, err
	}
	return item, nil
}

func (s *SQLStore) GetRegistrationBySPIFFEID(ctx context.Context, tenantID string, spiffeID string) (WorkloadRegistration, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, spiffe_id, selectors_json, allowed_interfaces_json, allowed_key_ids_json,
       permissions_json, issue_x509_svid, issue_jwt_svid, default_ttl_sec, enabled,
       last_issued_at, last_used_at, created_at, updated_at
FROM workload_identity_registrations
WHERE tenant_id = $1 AND spiffe_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(spiffeID))
	item, err := scanRegistration(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WorkloadRegistration{}, errNotFound
		}
		return WorkloadRegistration{}, err
	}
	return item, nil
}

func (s *SQLStore) UpsertRegistration(ctx context.Context, item WorkloadRegistration) (WorkloadRegistration, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO workload_identity_registrations (
  id, tenant_id, name, spiffe_id, selectors_json, allowed_interfaces_json, allowed_key_ids_json,
  permissions_json, issue_x509_svid, issue_jwt_svid, default_ttl_sec, enabled,
  last_issued_at, last_used_at, created_at, updated_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,COALESCE($15,CURRENT_TIMESTAMP),CURRENT_TIMESTAMP
)
ON CONFLICT (id) DO UPDATE SET
  tenant_id = EXCLUDED.tenant_id,
  name = EXCLUDED.name,
  spiffe_id = EXCLUDED.spiffe_id,
  selectors_json = EXCLUDED.selectors_json,
  allowed_interfaces_json = EXCLUDED.allowed_interfaces_json,
  allowed_key_ids_json = EXCLUDED.allowed_key_ids_json,
  permissions_json = EXCLUDED.permissions_json,
  issue_x509_svid = EXCLUDED.issue_x509_svid,
  issue_jwt_svid = EXCLUDED.issue_jwt_svid,
  default_ttl_sec = EXCLUDED.default_ttl_sec,
  enabled = EXCLUDED.enabled,
  last_issued_at = EXCLUDED.last_issued_at,
  last_used_at = EXCLUDED.last_used_at,
  updated_at = CURRENT_TIMESTAMP
RETURNING id, tenant_id, name, spiffe_id, selectors_json, allowed_interfaces_json, allowed_key_ids_json,
          permissions_json, issue_x509_svid, issue_jwt_svid, default_ttl_sec, enabled,
          last_issued_at, last_used_at, created_at, updated_at
`, item.ID,
		item.TenantID,
		item.Name,
		item.SpiffeID,
		validJSONOr(mustJSON(item.Selectors), "[]"),
		validJSONOr(mustJSON(item.AllowedInterfaces), "[]"),
		validJSONOr(mustJSON(item.AllowedKeyIDs), "[]"),
		validJSONOr(mustJSON(item.Permissions), "[]"),
		item.IssueX509SVID,
		item.IssueJWTSVID,
		item.DefaultTTLSeconds,
		item.Enabled,
		nullableTime(item.LastIssuedAt),
		nullableTime(item.LastUsedAt),
		nullableTime(item.CreatedAt),
	)
	return scanRegistration(row)
}

func (s *SQLStore) DeleteRegistration(ctx context.Context, tenantID string, id string) error {
	result, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM workload_identity_registrations WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) TouchRegistrationIssued(ctx context.Context, tenantID string, id string, ts time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE workload_identity_registrations
SET last_issued_at = $3, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id), nullableTime(ts))
	return err
}

func (s *SQLStore) TouchRegistrationUsed(ctx context.Context, tenantID string, id string, ts time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE workload_identity_registrations
SET last_used_at = $3, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id), nullableTime(ts))
	return err
}

func (s *SQLStore) ListFederationBundles(ctx context.Context, tenantID string) ([]WorkloadFederationBundle, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, trust_domain, bundle_endpoint, jwks_json, ca_bundle_pem, enabled, updated_at
FROM workload_identity_federation
WHERE tenant_id = $1
ORDER BY trust_domain ASC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []WorkloadFederationBundle{}
	for rows.Next() {
		item, err := scanFederationBundle(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLStore) GetFederationBundleByTrustDomain(ctx context.Context, tenantID string, trustDomain string) (WorkloadFederationBundle, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, trust_domain, bundle_endpoint, jwks_json, ca_bundle_pem, enabled, updated_at
FROM workload_identity_federation
WHERE tenant_id = $1 AND trust_domain = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(trustDomain))
	item, err := scanFederationBundle(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WorkloadFederationBundle{}, errNotFound
		}
		return WorkloadFederationBundle{}, err
	}
	return item, nil
}

func (s *SQLStore) UpsertFederationBundle(ctx context.Context, item WorkloadFederationBundle) (WorkloadFederationBundle, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO workload_identity_federation (
  id, tenant_id, trust_domain, bundle_endpoint, jwks_json, ca_bundle_pem, enabled, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP)
ON CONFLICT (id) DO UPDATE SET
  tenant_id = EXCLUDED.tenant_id,
  trust_domain = EXCLUDED.trust_domain,
  bundle_endpoint = EXCLUDED.bundle_endpoint,
  jwks_json = EXCLUDED.jwks_json,
  ca_bundle_pem = EXCLUDED.ca_bundle_pem,
  enabled = EXCLUDED.enabled,
  updated_at = CURRENT_TIMESTAMP
RETURNING id, tenant_id, trust_domain, bundle_endpoint, jwks_json, ca_bundle_pem, enabled, updated_at
`, item.ID, item.TenantID, item.TrustDomain, item.BundleEndpoint, item.JWKSJSON, item.CABundlePEM, item.Enabled)
	return scanFederationBundle(row)
}

func (s *SQLStore) DeleteFederationBundle(ctx context.Context, tenantID string, id string) error {
	result, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM workload_identity_federation WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) InsertIssuanceRecord(ctx context.Context, item WorkloadIssuanceRecord) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO workload_identity_issuance (
  id, tenant_id, registration_id, spiffe_id, svid_type, audiences_json, serial_or_key_id,
  document_hash, expires_at, rotation_due_at, status, issued_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
`, item.ID,
		item.TenantID,
		item.RegistrationID,
		item.SpiffeID,
		item.SVIDType,
		validJSONOr(mustJSON(item.Audiences), "[]"),
		item.SerialOrKeyID,
		item.DocumentHash,
		item.ExpiresAt.UTC(),
		nullableTime(item.RotationDueAt),
		item.Status,
		item.IssuedAt.UTC(),
	)
	return err
}

func (s *SQLStore) ListIssuanceRecords(ctx context.Context, tenantID string, limit int) ([]WorkloadIssuanceRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, registration_id, spiffe_id, svid_type, audiences_json, serial_or_key_id,
       document_hash, expires_at, rotation_due_at, status, issued_at
FROM workload_identity_issuance
WHERE tenant_id = $1
ORDER BY issued_at DESC
LIMIT $2
`, strings.TrimSpace(tenantID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []WorkloadIssuanceRecord{}
	for rows.Next() {
		item, err := scanIssuanceRecord(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type registrationScanner interface {
	Scan(dest ...interface{}) error
}

func scanRegistration(scanner registrationScanner) (WorkloadRegistration, error) {
	var (
		item            WorkloadRegistration
		selectorsJSON   string
		interfacesJSON  string
		allowedKeysJSON string
		permissionsJSON string
		lastIssuedRaw   interface{}
		lastUsedRaw     interface{}
		createdRaw      interface{}
		updatedRaw      interface{}
	)
	if err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.Name,
		&item.SpiffeID,
		&selectorsJSON,
		&interfacesJSON,
		&allowedKeysJSON,
		&permissionsJSON,
		&item.IssueX509SVID,
		&item.IssueJWTSVID,
		&item.DefaultTTLSeconds,
		&item.Enabled,
		&lastIssuedRaw,
		&lastUsedRaw,
		&createdRaw,
		&updatedRaw,
	); err != nil {
		return WorkloadRegistration{}, err
	}
	item.Selectors = parseJSONArrayString(selectorsJSON)
	item.AllowedInterfaces = parseJSONArrayString(interfacesJSON)
	item.AllowedKeyIDs = parseJSONArrayString(allowedKeysJSON)
	item.Permissions = parseJSONArrayString(permissionsJSON)
	item.LastIssuedAt = parseTimeValue(lastIssuedRaw)
	item.LastUsedAt = parseTimeValue(lastUsedRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

type federationScanner interface {
	Scan(dest ...interface{}) error
}

func scanFederationBundle(scanner federationScanner) (WorkloadFederationBundle, error) {
	var (
		item      WorkloadFederationBundle
		updatedAt interface{}
	)
	if err := scanner.Scan(&item.ID, &item.TenantID, &item.TrustDomain, &item.BundleEndpoint, &item.JWKSJSON, &item.CABundlePEM, &item.Enabled, &updatedAt); err != nil {
		return WorkloadFederationBundle{}, err
	}
	item.UpdatedAt = parseTimeValue(updatedAt)
	return item, nil
}

type issuanceScanner interface {
	Scan(dest ...interface{}) error
}

func scanIssuanceRecord(scanner issuanceScanner) (WorkloadIssuanceRecord, error) {
	var (
		item          WorkloadIssuanceRecord
		audiencesJSON string
		rotationRaw   interface{}
		issuedRaw     interface{}
	)
	if err := scanner.Scan(
		&item.ID,
		&item.TenantID,
		&item.RegistrationID,
		&item.SpiffeID,
		&item.SVIDType,
		&audiencesJSON,
		&item.SerialOrKeyID,
		&item.DocumentHash,
		&item.ExpiresAt,
		&rotationRaw,
		&item.Status,
		&issuedRaw,
	); err != nil {
		return WorkloadIssuanceRecord{}, err
	}
	item.Audiences = parseJSONArrayString(audiencesJSON)
	item.RotationDueAt = parseTimeValue(rotationRaw)
	item.IssuedAt = parseTimeValue(issuedRaw)
	return item, nil
}
