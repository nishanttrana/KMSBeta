package main

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	GetAttestationPolicy(ctx context.Context, tenantID string) (AttestationPolicy, error)
	UpsertAttestationPolicy(ctx context.Context, item AttestationPolicy) (AttestationPolicy, error)
	InsertReleaseRecord(ctx context.Context, item AttestedReleaseRecord) error
	ListReleaseRecords(ctx context.Context, tenantID string, limit int) ([]AttestedReleaseRecord, error)
	GetReleaseRecord(ctx context.Context, tenantID string, id string) (AttestedReleaseRecord, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) GetAttestationPolicy(ctx context.Context, tenantID string) (AttestationPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id,
       enabled,
       provider,
       mode,
       key_scopes_json,
       approved_images_json,
       approved_subjects_json,
       allowed_attesters_json,
       required_measurements_json,
       required_claims_json,
       require_secure_boot,
       require_debug_disabled,
       max_evidence_age_sec,
       cluster_scope,
       allowed_cluster_nodes_json,
       fallback_action,
       COALESCE(updated_by,''),
       updated_at
FROM confidential_attestation_policy
WHERE tenant_id = $1
`, strings.TrimSpace(tenantID))

	var (
		item                 AttestationPolicy
		keyScopesJSON        string
		approvedImagesJSON   string
		approvedSubjectsJSON string
		allowedAttestersJSON string
		requiredMeasuresJSON string
		requiredClaimsJSON   string
		allowedClusterJSON   string
		updatedRaw           interface{}
	)
	if err := row.Scan(
		&item.TenantID,
		&item.Enabled,
		&item.Provider,
		&item.Mode,
		&keyScopesJSON,
		&approvedImagesJSON,
		&approvedSubjectsJSON,
		&allowedAttestersJSON,
		&requiredMeasuresJSON,
		&requiredClaimsJSON,
		&item.RequireSecureBoot,
		&item.RequireDebugDisabled,
		&item.MaxEvidenceAgeSec,
		&item.ClusterScope,
		&allowedClusterJSON,
		&item.FallbackAction,
		&item.UpdatedBy,
		&updatedRaw,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AttestationPolicy{}, errNotFound
		}
		return AttestationPolicy{}, err
	}
	item.KeyScopes = parseJSONArrayString(keyScopesJSON)
	item.ApprovedImages = parseJSONArrayString(approvedImagesJSON)
	item.ApprovedSubjects = parseJSONArrayString(approvedSubjectsJSON)
	item.AllowedAttesters = parseJSONArrayString(allowedAttestersJSON)
	item.RequiredMeasurements = parseJSONObjectString(requiredMeasuresJSON)
	item.RequiredClaims = parseJSONObjectString(requiredClaimsJSON)
	item.AllowedClusterNodes = parseJSONArrayString(allowedClusterJSON)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func (s *SQLStore) UpsertAttestationPolicy(ctx context.Context, item AttestationPolicy) (AttestationPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO confidential_attestation_policy (
    tenant_id,
    enabled,
    provider,
    mode,
    key_scopes_json,
    approved_images_json,
    approved_subjects_json,
    allowed_attesters_json,
    required_measurements_json,
    required_claims_json,
    require_secure_boot,
    require_debug_disabled,
    max_evidence_age_sec,
    cluster_scope,
    allowed_cluster_nodes_json,
    fallback_action,
    updated_by,
    updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id) DO UPDATE SET
    enabled = EXCLUDED.enabled,
    provider = EXCLUDED.provider,
    mode = EXCLUDED.mode,
    key_scopes_json = EXCLUDED.key_scopes_json,
    approved_images_json = EXCLUDED.approved_images_json,
    approved_subjects_json = EXCLUDED.approved_subjects_json,
    allowed_attesters_json = EXCLUDED.allowed_attesters_json,
    required_measurements_json = EXCLUDED.required_measurements_json,
    required_claims_json = EXCLUDED.required_claims_json,
    require_secure_boot = EXCLUDED.require_secure_boot,
    require_debug_disabled = EXCLUDED.require_debug_disabled,
    max_evidence_age_sec = EXCLUDED.max_evidence_age_sec,
    cluster_scope = EXCLUDED.cluster_scope,
    allowed_cluster_nodes_json = EXCLUDED.allowed_cluster_nodes_json,
    fallback_action = EXCLUDED.fallback_action,
    updated_by = EXCLUDED.updated_by,
    updated_at = CURRENT_TIMESTAMP
RETURNING tenant_id,
          enabled,
          provider,
          mode,
          key_scopes_json,
          approved_images_json,
          approved_subjects_json,
          allowed_attesters_json,
          required_measurements_json,
          required_claims_json,
          require_secure_boot,
          require_debug_disabled,
          max_evidence_age_sec,
          cluster_scope,
          allowed_cluster_nodes_json,
          fallback_action,
          COALESCE(updated_by,''),
          updated_at
`, item.TenantID,
		item.Enabled,
		item.Provider,
		item.Mode,
		validJSONOr(mustJSON(item.KeyScopes), "[]"),
		validJSONOr(mustJSON(item.ApprovedImages), "[]"),
		validJSONOr(mustJSON(item.ApprovedSubjects), "[]"),
		validJSONOr(mustJSON(item.AllowedAttesters), "[]"),
		validJSONOr(mustJSON(item.RequiredMeasurements), "{}"),
		validJSONOr(mustJSON(item.RequiredClaims), "{}"),
		item.RequireSecureBoot,
		item.RequireDebugDisabled,
		item.MaxEvidenceAgeSec,
		item.ClusterScope,
		validJSONOr(mustJSON(item.AllowedClusterNodes), "[]"),
		item.FallbackAction,
		item.UpdatedBy,
	)

	var (
		out                  AttestationPolicy
		keyScopesJSON        string
		approvedImagesJSON   string
		approvedSubjectsJSON string
		allowedAttestersJSON string
		requiredMeasuresJSON string
		requiredClaimsJSON   string
		allowedClusterJSON   string
		updatedRaw           interface{}
	)
	if err := row.Scan(
		&out.TenantID,
		&out.Enabled,
		&out.Provider,
		&out.Mode,
		&keyScopesJSON,
		&approvedImagesJSON,
		&approvedSubjectsJSON,
		&allowedAttestersJSON,
		&requiredMeasuresJSON,
		&requiredClaimsJSON,
		&out.RequireSecureBoot,
		&out.RequireDebugDisabled,
		&out.MaxEvidenceAgeSec,
		&out.ClusterScope,
		&allowedClusterJSON,
		&out.FallbackAction,
		&out.UpdatedBy,
		&updatedRaw,
	); err != nil {
		return AttestationPolicy{}, err
	}
	out.KeyScopes = parseJSONArrayString(keyScopesJSON)
	out.ApprovedImages = parseJSONArrayString(approvedImagesJSON)
	out.ApprovedSubjects = parseJSONArrayString(approvedSubjectsJSON)
	out.AllowedAttesters = parseJSONArrayString(allowedAttestersJSON)
	out.RequiredMeasurements = parseJSONObjectString(requiredMeasuresJSON)
	out.RequiredClaims = parseJSONObjectString(requiredClaimsJSON)
	out.AllowedClusterNodes = parseJSONArrayString(allowedClusterJSON)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func (s *SQLStore) InsertReleaseRecord(ctx context.Context, item AttestedReleaseRecord) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO confidential_release_history (
    tenant_id,
    id,
    key_id,
    key_scope,
    provider,
    workload_identity,
    attester,
    image_ref,
    image_digest,
    audience,
    nonce,
    evidence_issued_at,
    claims_json,
    measurements_json,
    secure_boot,
    debug_disabled,
    cluster_node_id,
    requester,
    release_reason,
    decision,
    allowed,
    reasons_json,
    matched_claims_json,
    matched_measurements_json,
    missing_claims_json,
    missing_measurements_json,
    missing_attributes_json,
    measurement_hash,
    claims_hash,
    policy_version,
    cryptographically_verified,
    verification_mode,
    verification_issuer,
    verification_key_id,
    attestation_document_hash,
    attestation_document_format,
    expires_at,
    created_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38
)
`, item.TenantID,
		item.ID,
		item.KeyID,
		item.KeyScope,
		item.Provider,
		item.WorkloadIdentity,
		item.Attester,
		item.ImageRef,
		item.ImageDigest,
		item.Audience,
		item.Nonce,
		nullableTime(item.EvidenceIssuedAt),
		validJSONOr(mustJSON(item.Claims), "{}"),
		validJSONOr(mustJSON(item.Measurements), "{}"),
		item.SecureBoot,
		item.DebugDisabled,
		item.ClusterNodeID,
		item.Requester,
		item.ReleaseReason,
		item.Decision,
		item.Allowed,
		validJSONOr(mustJSON(item.Reasons), "[]"),
		validJSONOr(mustJSON(item.MatchedClaims), "[]"),
		validJSONOr(mustJSON(item.MatchedMeasurements), "[]"),
		validJSONOr(mustJSON(item.MissingClaims), "[]"),
		validJSONOr(mustJSON(item.MissingMeasurements), "[]"),
		validJSONOr(mustJSON(item.MissingAttributes), "[]"),
		item.MeasurementHash,
		item.ClaimsHash,
		item.PolicyVersion,
		item.CryptographicallyVerified,
		item.VerificationMode,
		item.VerificationIssuer,
		item.VerificationKeyID,
		item.AttestationDocumentHash,
		item.AttestationDocumentFormat,
		nullableTime(item.ExpiresAt),
		item.CreatedAt.UTC(),
	)
	return err
}

func (s *SQLStore) ListReleaseRecords(ctx context.Context, tenantID string, limit int) ([]AttestedReleaseRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id,
       id,
       key_id,
       key_scope,
       provider,
       workload_identity,
       attester,
       image_ref,
       image_digest,
       audience,
       nonce,
       evidence_issued_at,
       claims_json,
       measurements_json,
       secure_boot,
       debug_disabled,
       cluster_node_id,
       requester,
       release_reason,
       decision,
       allowed,
       reasons_json,
       matched_claims_json,
       matched_measurements_json,
       missing_claims_json,
       missing_measurements_json,
       missing_attributes_json,
       measurement_hash,
       claims_hash,
       policy_version,
       cryptographically_verified,
       verification_mode,
       verification_issuer,
       verification_key_id,
       attestation_document_hash,
       attestation_document_format,
       expires_at,
       created_at
FROM confidential_release_history
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT `+strconv.Itoa(limit), strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	items := make([]AttestedReleaseRecord, 0, limit)
	for rows.Next() {
		item, err := scanReleaseRecord(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLStore) GetReleaseRecord(ctx context.Context, tenantID string, id string) (AttestedReleaseRecord, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id,
       id,
       key_id,
       key_scope,
       provider,
       workload_identity,
       attester,
       image_ref,
       image_digest,
       audience,
       nonce,
       evidence_issued_at,
       claims_json,
       measurements_json,
       secure_boot,
       debug_disabled,
       cluster_node_id,
       requester,
       release_reason,
       decision,
       allowed,
       reasons_json,
       matched_claims_json,
       matched_measurements_json,
       missing_claims_json,
       missing_measurements_json,
       missing_attributes_json,
       measurement_hash,
       claims_hash,
       policy_version,
       cryptographically_verified,
       verification_mode,
       verification_issuer,
       verification_key_id,
       attestation_document_hash,
       attestation_document_format,
       expires_at,
       created_at
FROM confidential_release_history
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanReleaseRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AttestedReleaseRecord{}, errNotFound
	}
	if err != nil {
		return AttestedReleaseRecord{}, err
	}
	return item, nil
}

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanReleaseRecord(row scanner) (AttestedReleaseRecord, error) {
	var (
		item                  AttestedReleaseRecord
		evidenceIssuedRaw     interface{}
		expiresRaw            interface{}
		createdRaw            interface{}
		claimsJSON            string
		measurementsJSON      string
		reasonsJSON           string
		matchedClaimsJSON     string
		matchedMeasuresJSON   string
		missingClaimsJSON     string
		missingMeasuresJSON   string
		missingAttributesJSON string
	)
	if err := row.Scan(
		&item.TenantID,
		&item.ID,
		&item.KeyID,
		&item.KeyScope,
		&item.Provider,
		&item.WorkloadIdentity,
		&item.Attester,
		&item.ImageRef,
		&item.ImageDigest,
		&item.Audience,
		&item.Nonce,
		&evidenceIssuedRaw,
		&claimsJSON,
		&measurementsJSON,
		&item.SecureBoot,
		&item.DebugDisabled,
		&item.ClusterNodeID,
		&item.Requester,
		&item.ReleaseReason,
		&item.Decision,
		&item.Allowed,
		&reasonsJSON,
		&matchedClaimsJSON,
		&matchedMeasuresJSON,
		&missingClaimsJSON,
		&missingMeasuresJSON,
		&missingAttributesJSON,
		&item.MeasurementHash,
		&item.ClaimsHash,
		&item.PolicyVersion,
		&item.CryptographicallyVerified,
		&item.VerificationMode,
		&item.VerificationIssuer,
		&item.VerificationKeyID,
		&item.AttestationDocumentHash,
		&item.AttestationDocumentFormat,
		&expiresRaw,
		&createdRaw,
	); err != nil {
		return AttestedReleaseRecord{}, err
	}
	item.EvidenceIssuedAt = parseTimeValue(evidenceIssuedRaw)
	item.Claims = parseJSONObjectString(claimsJSON)
	item.Measurements = parseJSONObjectString(measurementsJSON)
	item.Reasons = parseJSONArrayString(reasonsJSON)
	item.MatchedClaims = parseJSONArrayString(matchedClaimsJSON)
	item.MatchedMeasurements = parseJSONArrayString(matchedMeasuresJSON)
	item.MissingClaims = parseJSONArrayString(missingClaimsJSON)
	item.MissingMeasurements = parseJSONArrayString(missingMeasuresJSON)
	item.MissingAttributes = parseJSONArrayString(missingAttributesJSON)
	item.ExpiresAt = parseTimeValue(expiresRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}
