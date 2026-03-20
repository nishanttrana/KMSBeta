package main

import (
	"context"
	"database/sql"
	"errors"
	"encoding/json"
)

func (s *SQLStore) GetCertRenewalInfo(ctx context.Context, tenantID string, certID string) (CertRenewalInfo, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, cert_id, ari_id, ca_id, ca_name, subject_cn, protocol, not_after,
       window_start, window_end, scheduled_renewal_at, explanation_url, retry_after_seconds,
       next_poll_at, renewal_state, risk_level, missed_window_at, emergency_rotation_at,
       mass_renewal_bucket, window_source, metadata_json, updated_at
FROM cert_renewal_intelligence
WHERE tenant_id = $1 AND cert_id = $2
`, tenantID, certID)
	item, err := scanCertRenewalInfo(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CertRenewalInfo{}, errStoreNotFound
	}
	return item, err
}

func (s *SQLStore) GetCertRenewalInfoByARIID(ctx context.Context, tenantID string, ariID string) (CertRenewalInfo, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, cert_id, ari_id, ca_id, ca_name, subject_cn, protocol, not_after,
       window_start, window_end, scheduled_renewal_at, explanation_url, retry_after_seconds,
       next_poll_at, renewal_state, risk_level, missed_window_at, emergency_rotation_at,
       mass_renewal_bucket, window_source, metadata_json, updated_at
FROM cert_renewal_intelligence
WHERE tenant_id = $1 AND ari_id = $2
`, tenantID, ariID)
	item, err := scanCertRenewalInfo(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CertRenewalInfo{}, errStoreNotFound
	}
	return item, err
}

func (s *SQLStore) ListCertRenewalInfo(ctx context.Context, tenantID string, limit int) ([]CertRenewalInfo, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, cert_id, ari_id, ca_id, ca_name, subject_cn, protocol, not_after,
       window_start, window_end, scheduled_renewal_at, explanation_url, retry_after_seconds,
       next_poll_at, renewal_state, risk_level, missed_window_at, emergency_rotation_at,
       mass_renewal_bucket, window_source, metadata_json, updated_at
FROM cert_renewal_intelligence
WHERE tenant_id = $1
ORDER BY scheduled_renewal_at ASC, cert_id ASC
LIMIT $2
`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]CertRenewalInfo, 0)
	for rows.Next() {
		item, scanErr := scanCertRenewalInfo(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertCertRenewalInfo(ctx context.Context, item CertRenewalInfo) error {
	if stringsTrim(item.MetadataJSON) == "" {
		item.MetadataJSON = "{}"
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_renewal_intelligence (
	tenant_id, cert_id, ari_id, ca_id, ca_name, subject_cn, protocol, not_after,
	window_start, window_end, scheduled_renewal_at, explanation_url, retry_after_seconds,
	next_poll_at, renewal_state, risk_level, missed_window_at, emergency_rotation_at,
	mass_renewal_bucket, window_source, metadata_json, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,
	$9,$10,$11,$12,$13,
	$14,$15,$16,$17,$18,
	$19,$20,$21,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, cert_id)
DO UPDATE SET
	ari_id = EXCLUDED.ari_id,
	ca_id = EXCLUDED.ca_id,
	ca_name = EXCLUDED.ca_name,
	subject_cn = EXCLUDED.subject_cn,
	protocol = EXCLUDED.protocol,
	not_after = EXCLUDED.not_after,
	window_start = EXCLUDED.window_start,
	window_end = EXCLUDED.window_end,
	scheduled_renewal_at = EXCLUDED.scheduled_renewal_at,
	explanation_url = EXCLUDED.explanation_url,
	retry_after_seconds = EXCLUDED.retry_after_seconds,
	next_poll_at = EXCLUDED.next_poll_at,
	renewal_state = EXCLUDED.renewal_state,
	risk_level = EXCLUDED.risk_level,
	missed_window_at = EXCLUDED.missed_window_at,
	emergency_rotation_at = EXCLUDED.emergency_rotation_at,
	mass_renewal_bucket = EXCLUDED.mass_renewal_bucket,
	window_source = EXCLUDED.window_source,
	metadata_json = EXCLUDED.metadata_json,
	updated_at = CURRENT_TIMESTAMP
`, item.TenantID, item.CertID, item.ARIID, item.CAID, item.CAName, item.SubjectCN, item.Protocol, item.NotAfter.UTC(),
		nullableTime(item.WindowStart), nullableTime(item.WindowEnd), nullableTime(item.ScheduledRenewalAt), item.ExplanationURL, item.RetryAfterSeconds,
		nullableTime(item.NextPollAt), item.RenewalState, item.RiskLevel, nullableTime(item.MissedWindowAt), nullableTime(item.EmergencyRotationAt),
		item.MassRenewalBucket, item.WindowSource, item.MetadataJSON)
	return err
}

func (s *SQLStore) DeleteCertRenewalInfo(ctx context.Context, tenantID string, certID string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM cert_renewal_intelligence
WHERE tenant_id = $1 AND cert_id = $2
`, tenantID, certID)
	return err
}

func scanCertRenewalInfo(scanner interface {
	Scan(dest ...interface{}) error
}) (CertRenewalInfo, error) {
	var (
		item               CertRenewalInfo
		notAfterRaw        interface{}
		windowStartRaw     interface{}
		windowEndRaw       interface{}
		scheduledRaw       interface{}
		nextPollRaw        interface{}
		missedWindowRaw    interface{}
		emergencyRaw       interface{}
		updatedAtRaw       interface{}
	)
	if err := scanner.Scan(
		&item.TenantID,
		&item.CertID,
		&item.ARIID,
		&item.CAID,
		&item.CAName,
		&item.SubjectCN,
		&item.Protocol,
		&notAfterRaw,
		&windowStartRaw,
		&windowEndRaw,
		&scheduledRaw,
		&item.ExplanationURL,
		&item.RetryAfterSeconds,
		&nextPollRaw,
		&item.RenewalState,
		&item.RiskLevel,
		&missedWindowRaw,
		&emergencyRaw,
		&item.MassRenewalBucket,
		&item.WindowSource,
		&item.MetadataJSON,
		&updatedAtRaw,
	); err != nil {
		return CertRenewalInfo{}, err
	}
	item.NotAfter = parseTimeValue(notAfterRaw)
	item.WindowStart = parseTimeValue(windowStartRaw)
	item.WindowEnd = parseTimeValue(windowEndRaw)
	item.ScheduledRenewalAt = parseTimeValue(scheduledRaw)
	item.NextPollAt = parseTimeValue(nextPollRaw)
	item.MissedWindowAt = parseTimeValue(missedWindowRaw)
	item.EmergencyRotationAt = parseTimeValue(emergencyRaw)
	item.UpdatedAt = parseTimeValue(updatedAtRaw)
	if stringsTrim(item.MetadataJSON) == "" {
		item.MetadataJSON = "{}"
	}
	return item, nil
}

func stringsTrim(v string) string {
	return defaultString(v, "")
}

func marshalRenewalMetadata(meta map[string]interface{}) string {
	raw, err := json.Marshal(meta)
	if err != nil {
		return "{}"
	}
	return string(raw)
}
