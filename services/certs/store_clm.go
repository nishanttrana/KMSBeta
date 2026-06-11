package main

import (
	"context"
	"database/sql"
	"errors"
)

func (s *SQLStore) GetCLMPolicy(ctx context.Context, tenantID string) (CLMPolicy, bool, error) {
	var (
		p          CLMPolicy
		schedule   interface{}
		updatedRaw interface{}
	)
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, mode, max_validity_days, schedule_aware, renew_before_days, updated_by, updated_at
FROM cert_clm_policies WHERE tenant_id=$1
`, tenantID).Scan(&p.TenantID, &p.Mode, &p.MaxValidityDays, &schedule, &p.RenewBeforeDays, &p.UpdatedBy, &updatedRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return CLMPolicy{}, false, nil
	}
	if err != nil {
		return CLMPolicy{}, false, err
	}
	p.ScheduleAware = parseBool(schedule)
	p.UpdatedAt = parseTimeValue(updatedRaw)
	return p, true, nil
}

func (s *SQLStore) UpsertCLMPolicy(ctx context.Context, p CLMPolicy) error {
	schedule := 0
	if p.ScheduleAware {
		schedule = 1
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cert_clm_policies (tenant_id, mode, max_validity_days, schedule_aware, renew_before_days, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (tenant_id) DO UPDATE SET
  mode=EXCLUDED.mode,
  max_validity_days=EXCLUDED.max_validity_days,
  schedule_aware=EXCLUDED.schedule_aware,
  renew_before_days=EXCLUDED.renew_before_days,
  updated_by=EXCLUDED.updated_by,
  updated_at=EXCLUDED.updated_at
`, p.TenantID, p.Mode, p.MaxValidityDays, schedule, p.RenewBeforeDays, p.UpdatedBy, p.UpdatedAt)
	return err
}

// CertValidityStats returns, for active TLS leaf certificates: the total
// count, how many have a lifetime longer than maxDays, and the longest
// lifetime in days.
func (s *SQLStore) CertValidityStats(ctx context.Context, tenantID string, maxDays int64) (total int64, over int64, longest int64, err error) {
	rows, qerr := s.db.SQL().QueryContext(ctx, `
SELECT not_before, not_after FROM cert_certificates
WHERE tenant_id=$1 AND status='active' AND cert_type LIKE 'tls%'
`, tenantID)
	if qerr != nil {
		return 0, 0, 0, qerr
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var notBeforeRaw, notAfterRaw interface{}
		if err := rows.Scan(&notBeforeRaw, &notAfterRaw); err != nil {
			return 0, 0, 0, err
		}
		days := int64(parseTimeValue(notAfterRaw).Sub(parseTimeValue(notBeforeRaw)).Hours() / 24)
		total++
		if days > maxDays {
			over++
		}
		if days > longest {
			longest = days
		}
	}
	return total, over, longest, rows.Err()
}
