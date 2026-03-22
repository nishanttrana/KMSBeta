package main

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	pkgdb "vecta-kms/pkg/db"
)

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore { return &SQLStore{db: db} }

func (s *SQLStore) GetSettings(ctx context.Context, tenantID string) (SigningSettings, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, enabled, COALESCE(default_profile_id,''), require_transparency, allowed_identity_modes_json,
       COALESCE(updated_by,''), updated_at
FROM signing_settings
WHERE tenant_id=$1
`, strings.TrimSpace(tenantID))
	item, err := scanSettings(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SigningSettings{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) UpsertSettings(ctx context.Context, item SigningSettings) (SigningSettings, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO signing_settings (
  tenant_id, enabled, default_profile_id, require_transparency, allowed_identity_modes_json, updated_by, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id) DO UPDATE SET
  enabled=EXCLUDED.enabled,
  default_profile_id=EXCLUDED.default_profile_id,
  require_transparency=EXCLUDED.require_transparency,
  allowed_identity_modes_json=EXCLUDED.allowed_identity_modes_json,
  updated_by=EXCLUDED.updated_by,
  updated_at=CURRENT_TIMESTAMP
RETURNING tenant_id, enabled, COALESCE(default_profile_id,''), require_transparency, allowed_identity_modes_json, COALESCE(updated_by,''), updated_at
`, item.TenantID, item.Enabled, item.DefaultProfileID, item.RequireTransparency, mustJSON(item.AllowedIdentityModes, "[]"), item.UpdatedBy)
	return scanSettings(row)
}

func (s *SQLStore) ListProfiles(ctx context.Context, tenantID string) ([]SigningProfile, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, artifact_type, key_id, signing_algorithm, identity_mode,
       allowed_workload_patterns_json, allowed_oidc_issuers_json, allowed_subject_patterns_json, allowed_repositories_json,
       transparency_required, enabled, COALESCE(description,''), COALESCE(updated_by,''), updated_at
FROM signing_profiles
WHERE tenant_id=$1
ORDER BY name ASC, id ASC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []SigningProfile{}
	for rows.Next() {
		item, scanErr := scanProfile(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetProfile(ctx context.Context, tenantID string, id string) (SigningProfile, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, artifact_type, key_id, signing_algorithm, identity_mode,
       allowed_workload_patterns_json, allowed_oidc_issuers_json, allowed_subject_patterns_json, allowed_repositories_json,
       transparency_required, enabled, COALESCE(description,''), COALESCE(updated_by,''), updated_at
FROM signing_profiles
WHERE tenant_id=$1 AND id=$2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanProfile(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SigningProfile{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) UpsertProfile(ctx context.Context, item SigningProfile) (SigningProfile, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO signing_profiles (
  id, tenant_id, name, artifact_type, key_id, signing_algorithm, identity_mode,
  allowed_workload_patterns_json, allowed_oidc_issuers_json, allowed_subject_patterns_json, allowed_repositories_json,
  transparency_required, enabled, description, updated_by, updated_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,
  $8,$9,$10,$11,
  $12,$13,$14,$15,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, id) DO UPDATE SET
  name=EXCLUDED.name,
  artifact_type=EXCLUDED.artifact_type,
  key_id=EXCLUDED.key_id,
  signing_algorithm=EXCLUDED.signing_algorithm,
  identity_mode=EXCLUDED.identity_mode,
  allowed_workload_patterns_json=EXCLUDED.allowed_workload_patterns_json,
  allowed_oidc_issuers_json=EXCLUDED.allowed_oidc_issuers_json,
  allowed_subject_patterns_json=EXCLUDED.allowed_subject_patterns_json,
  allowed_repositories_json=EXCLUDED.allowed_repositories_json,
  transparency_required=EXCLUDED.transparency_required,
  enabled=EXCLUDED.enabled,
  description=EXCLUDED.description,
  updated_by=EXCLUDED.updated_by,
  updated_at=CURRENT_TIMESTAMP
RETURNING id, tenant_id, name, artifact_type, key_id, signing_algorithm, identity_mode,
          allowed_workload_patterns_json, allowed_oidc_issuers_json, allowed_subject_patterns_json, allowed_repositories_json,
          transparency_required, enabled, COALESCE(description,''), COALESCE(updated_by,''), updated_at
`, item.ID, item.TenantID, item.Name, item.ArtifactType, item.KeyID, item.SigningAlgorithm, item.IdentityMode,
		mustJSON(item.AllowedWorkloadPatterns, "[]"), mustJSON(item.AllowedOIDCIssuers, "[]"), mustJSON(item.AllowedSubjectPatterns, "[]"), mustJSON(item.AllowedRepositories, "[]"),
		item.TransparencyRequired, item.Enabled, item.Description, item.UpdatedBy)
	return scanProfile(row)
}

func (s *SQLStore) DeleteProfile(ctx context.Context, tenantID string, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM signing_profiles WHERE tenant_id=$1 AND id=$2`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateRecord(ctx context.Context, item SigningRecord) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO signing_records (
  id, tenant_id, profile_id, artifact_type, artifact_name, digest_sha256, signature_b64, key_id, signing_algorithm,
  identity_mode, oidc_issuer, oidc_subject, workload_identity, repository, commit_sha, oci_reference,
  transparency_entry_id, transparency_hash, transparency_index, verification_status, metadata_json, created_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,$9,
  $10,$11,$12,$13,$14,$15,$16,
  $17,$18,$19,$20,$21,CURRENT_TIMESTAMP
)
`, item.ID, item.TenantID, item.ProfileID, item.ArtifactType, item.ArtifactName, item.DigestSHA256, item.SignatureB64, item.KeyID, item.SigningAlgorithm,
		item.IdentityMode, item.OIDCIssuer, item.OIDCSubject, item.WorkloadIdentity, item.Repository, item.CommitSHA, item.OCIReference,
		item.TransparencyEntryID, item.TransparencyHash, item.TransparencyIndex, item.VerificationStatus, mustJSON(item.Metadata, "{}"))
	return err
}

func (s *SQLStore) GetRecord(ctx context.Context, tenantID string, id string) (SigningRecord, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, profile_id, artifact_type, artifact_name, digest_sha256, signature_b64, key_id, signing_algorithm,
       identity_mode, COALESCE(oidc_issuer,''), COALESCE(oidc_subject,''), COALESCE(workload_identity,''), COALESCE(repository,''), COALESCE(commit_sha,''), COALESCE(oci_reference,''),
       COALESCE(transparency_entry_id,''), COALESCE(transparency_hash,''), COALESCE(transparency_index,0), COALESCE(verification_status,''), metadata_json, created_at
FROM signing_records
WHERE tenant_id=$1 AND id=$2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SigningRecord{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListRecords(ctx context.Context, tenantID string, profileID string, artifactType string, limit int) ([]SigningRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `
SELECT id, tenant_id, profile_id, artifact_type, artifact_name, digest_sha256, signature_b64, key_id, signing_algorithm,
       identity_mode, COALESCE(oidc_issuer,''), COALESCE(oidc_subject,''), COALESCE(workload_identity,''), COALESCE(repository,''), COALESCE(commit_sha,''), COALESCE(oci_reference,''),
       COALESCE(transparency_entry_id,''), COALESCE(transparency_hash,''), COALESCE(transparency_index,0), COALESCE(verification_status,''), metadata_json, created_at
FROM signing_records
WHERE tenant_id=$1
`
	args := []interface{}{strings.TrimSpace(tenantID)}
	index := 2
	if strings.TrimSpace(profileID) != "" {
		query += " AND profile_id=$" + strconv.Itoa(index)
		args = append(args, strings.TrimSpace(profileID))
		index++
	}
	if strings.TrimSpace(artifactType) != "" {
		query += " AND artifact_type=$" + strconv.Itoa(index)
		args = append(args, strings.TrimSpace(artifactType))
		index++
	}
	query += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(index)
	args = append(args, limit)
	rows, err := s.db.SQL().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []SigningRecord{}
	for rows.Next() {
		item, scanErr := scanRecord(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) NextTransparencyIndex(ctx context.Context, tenantID string) (int, error) {
	row := s.db.SQL().QueryRowContext(ctx, `SELECT COALESCE(MAX(transparency_index),0)+1 FROM signing_records WHERE tenant_id=$1`, strings.TrimSpace(tenantID))
	var out int
	if err := row.Scan(&out); err != nil {
		return 0, err
	}
	if out <= 0 {
		out = 1
	}
	return out, nil
}

func scanSettings(scanner interface{ Scan(dest ...interface{}) error }) (SigningSettings, error) {
	var out SigningSettings
	var enabledRaw, transparencyRaw interface{}
	var modesRaw string
	var updatedRaw interface{}
	err := scanner.Scan(&out.TenantID, &enabledRaw, &out.DefaultProfileID, &transparencyRaw, &modesRaw, &out.UpdatedBy, &updatedRaw)
	if err != nil {
		return SigningSettings{}, err
	}
	out.Enabled = boolValue(enabledRaw)
	out.RequireTransparency = boolValue(transparencyRaw)
	out.AllowedIdentityModes = normalizeStringList(parseJSONArrayString(modesRaw))
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return normalizeSettings(out), nil
}

func scanProfile(scanner interface{ Scan(dest ...interface{}) error }) (SigningProfile, error) {
	var out SigningProfile
	var transparencyRaw, enabledRaw interface{}
	var workloadsRaw, issuersRaw, subjectsRaw, reposRaw string
	var updatedRaw interface{}
	err := scanner.Scan(&out.ID, &out.TenantID, &out.Name, &out.ArtifactType, &out.KeyID, &out.SigningAlgorithm, &out.IdentityMode,
		&workloadsRaw, &issuersRaw, &subjectsRaw, &reposRaw,
		&transparencyRaw, &enabledRaw, &out.Description, &out.UpdatedBy, &updatedRaw)
	if err != nil {
		return SigningProfile{}, err
	}
	out.AllowedWorkloadPatterns = normalizeStringList(parseJSONArrayString(workloadsRaw))
	out.AllowedOIDCIssuers = normalizeStringList(parseJSONArrayString(issuersRaw))
	out.AllowedSubjectPatterns = normalizeStringList(parseJSONArrayString(subjectsRaw))
	out.AllowedRepositories = normalizeStringList(parseJSONArrayString(reposRaw))
	out.TransparencyRequired = boolValue(transparencyRaw)
	out.Enabled = boolValue(enabledRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return normalizeProfile(out), nil
}

func scanRecord(scanner interface{ Scan(dest ...interface{}) error }) (SigningRecord, error) {
	var out SigningRecord
	var metadataRaw string
	var createdRaw interface{}
	err := scanner.Scan(&out.ID, &out.TenantID, &out.ProfileID, &out.ArtifactType, &out.ArtifactName, &out.DigestSHA256, &out.SignatureB64, &out.KeyID, &out.SigningAlgorithm,
		&out.IdentityMode, &out.OIDCIssuer, &out.OIDCSubject, &out.WorkloadIdentity, &out.Repository, &out.CommitSHA, &out.OCIReference,
		&out.TransparencyEntryID, &out.TransparencyHash, &out.TransparencyIndex, &out.VerificationStatus, &metadataRaw, &createdRaw)
	if err != nil {
		return SigningRecord{}, err
	}
	out.Metadata = parseJSONObjectString(metadataRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	return out, nil
}

func boolValue(value interface{}) bool {
	switch v := value.(type) {
	case bool:
		return v
	case int64:
		return v != 0
	case int:
		return v != 0
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true") || strings.TrimSpace(v) == "1"
	default:
		return false
	}
}
