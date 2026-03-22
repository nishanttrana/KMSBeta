package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

func (s *SQLStore) GetACMESTARSubscription(ctx context.Context, tenantID string, id string) (ACMESTARSubscription, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, account_id, ca_id, COALESCE(profile_id,''), subject_cn, sans_json,
       cert_type, cert_class, algorithm, validity_hours, renew_before_minutes, auto_renew,
       allow_delegation, COALESCE(delegated_subscriber,''), COALESCE(latest_cert_id,''), issuance_count,
       status, COALESCE(rollout_group,''), last_issued_at, next_renewal_at, COALESCE(last_error,''),
       COALESCE(created_by,''), COALESCE(metadata_json,'{}'), created_at, updated_at
FROM cert_acme_star_subscriptions
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanACMESTARSubscription(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ACMESTARSubscription{}, errStoreNotFound
	}
	return item, err
}

func (s *SQLStore) ListACMESTARSubscriptions(ctx context.Context, tenantID string, limit int) ([]ACMESTARSubscription, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, account_id, ca_id, COALESCE(profile_id,''), subject_cn, sans_json,
       cert_type, cert_class, algorithm, validity_hours, renew_before_minutes, auto_renew,
       allow_delegation, COALESCE(delegated_subscriber,''), COALESCE(latest_cert_id,''), issuance_count,
       status, COALESCE(rollout_group,''), last_issued_at, next_renewal_at, COALESCE(last_error,''),
       COALESCE(created_by,''), COALESCE(metadata_json,'{}'), created_at, updated_at
FROM cert_acme_star_subscriptions
WHERE tenant_id = $1
ORDER BY updated_at DESC, created_at DESC
LIMIT $2
`, strings.TrimSpace(tenantID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ACMESTARSubscription, 0)
	for rows.Next() {
		item, scanErr := scanACMESTARSubscription(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertACMESTARSubscription(ctx context.Context, item ACMESTARSubscription) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_acme_star_subscriptions (
  id, tenant_id, name, account_id, ca_id, profile_id, subject_cn, sans_json,
  cert_type, cert_class, algorithm, validity_hours, renew_before_minutes, auto_renew,
  allow_delegation, delegated_subscriber, latest_cert_id, issuance_count, status,
  rollout_group, last_issued_at, next_renewal_at, last_error, created_by, metadata_json, created_at, updated_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,
  $9,$10,$11,$12,$13,$14,
  $15,$16,$17,$18,$19,
  $20,$21,$22,$23,$24,$25,$26,$27
)
ON CONFLICT (tenant_id, id) DO UPDATE SET
  name = EXCLUDED.name,
  account_id = EXCLUDED.account_id,
  ca_id = EXCLUDED.ca_id,
  profile_id = EXCLUDED.profile_id,
  subject_cn = EXCLUDED.subject_cn,
  sans_json = EXCLUDED.sans_json,
  cert_type = EXCLUDED.cert_type,
  cert_class = EXCLUDED.cert_class,
  algorithm = EXCLUDED.algorithm,
  validity_hours = EXCLUDED.validity_hours,
  renew_before_minutes = EXCLUDED.renew_before_minutes,
  auto_renew = EXCLUDED.auto_renew,
  allow_delegation = EXCLUDED.allow_delegation,
  delegated_subscriber = EXCLUDED.delegated_subscriber,
  latest_cert_id = EXCLUDED.latest_cert_id,
  issuance_count = EXCLUDED.issuance_count,
  status = EXCLUDED.status,
  rollout_group = EXCLUDED.rollout_group,
  last_issued_at = EXCLUDED.last_issued_at,
  next_renewal_at = EXCLUDED.next_renewal_at,
  last_error = EXCLUDED.last_error,
  created_by = EXCLUDED.created_by,
  metadata_json = EXCLUDED.metadata_json,
  updated_at = EXCLUDED.updated_at
`,
		item.ID, item.TenantID, item.Name, item.AccountID, item.CAID, nullableString(item.ProfileID), item.SubjectCN, mustJSON(item.SANs),
		item.CertType, item.CertClass, item.Algorithm, item.ValidityHours, item.RenewBeforeMinutes, boolToInt(item.AutoRenew),
		boolToInt(item.AllowDelegation), nullableString(item.DelegatedSubscriber), nullableString(item.LatestCertID), item.IssuanceCount, item.Status,
		nullableString(item.RolloutGroup), nullableTime(item.LastIssuedAt), nullableTime(item.NextRenewalAt), nullableString(item.LastError),
		item.CreatedBy, defaultString(item.MetadataJSON, "{}"), nullableTime(item.CreatedAt), nullableTime(item.UpdatedAt),
	)
	return err
}

func (s *SQLStore) DeleteACMESTARSubscription(ctx context.Context, tenantID string, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM cert_acme_star_subscriptions WHERE tenant_id = $1 AND id = $2`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errStoreNotFound
	}
	return nil
}

func scanACMESTARSubscription(scanner interface {
	Scan(dest ...interface{}) error
}) (ACMESTARSubscription, error) {
	var item ACMESTARSubscription
	var sansJSON string
	var lastIssuedAt sql.NullTime
	var nextRenewalAt sql.NullTime
	if err := scanner.Scan(
		&item.ID, &item.TenantID, &item.Name, &item.AccountID, &item.CAID, &item.ProfileID, &item.SubjectCN, &sansJSON,
		&item.CertType, &item.CertClass, &item.Algorithm, &item.ValidityHours, &item.RenewBeforeMinutes, &item.AutoRenew,
		&item.AllowDelegation, &item.DelegatedSubscriber, &item.LatestCertID, &item.IssuanceCount, &item.Status,
		&item.RolloutGroup, &lastIssuedAt, &nextRenewalAt, &item.LastError, &item.CreatedBy, &item.MetadataJSON, &item.CreatedAt, &item.UpdatedAt,
	); err != nil {
		return ACMESTARSubscription{}, err
	}
	_ = json.Unmarshal([]byte(sansJSON), &item.SANs)
	if lastIssuedAt.Valid {
		item.LastIssuedAt = lastIssuedAt.Time
	}
	if nextRenewalAt.Valid {
		item.NextRenewalAt = nextRenewalAt.Time
	}
	item.MetadataJSON = defaultString(strings.TrimSpace(item.MetadataJSON), "{}")
	return item, nil
}
