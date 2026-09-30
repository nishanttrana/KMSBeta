package main

import (
	"context"
	"time"
)

// ListCryptoperiodOverrides returns the tenant's cryptoperiods by category.
func (s *SQLStore) ListCryptoperiodOverrides(ctx context.Context, tenantID string) (map[string]time.Duration, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT category, days FROM cryptoperiod_overrides WHERE tenant_id=$1`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := map[string]time.Duration{}
	for rows.Next() {
		var (
			cat  string
			days int
		)
		if err := rows.Scan(&cat, &days); err != nil {
			return nil, err
		}
		out[cat] = time.Duration(days) * 24 * time.Hour
	}
	return out, rows.Err()
}

// SetCryptoperiodOverride stores the tenant's period for one category.
func (s *SQLStore) SetCryptoperiodOverride(ctx context.Context, tenantID, category string, days int, actor string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cryptoperiod_overrides (tenant_id, category, days, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (tenant_id, category) DO UPDATE SET days=EXCLUDED.days, updated_by=EXCLUDED.updated_by, updated_at=EXCLUDED.updated_at`,
		tenantID, category, days, actor, time.Now().UTC())
	return err
}

// DeleteCryptoperiodOverride returns a category to the built-in default.
func (s *SQLStore) DeleteCryptoperiodOverride(ctx context.Context, tenantID, category string) (bool, error) {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM cryptoperiod_overrides WHERE tenant_id=$1 AND category=$2`, tenantID, category)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
