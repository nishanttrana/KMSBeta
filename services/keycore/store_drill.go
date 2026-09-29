package main

import (
	"context"
	"encoding/json"
)

type drillMeasurements struct {
	From       DrillMeasure    `json:"from"`
	To         DrillMeasure    `json:"to"`
	Comparison DrillComparison `json:"comparison"`
}

func (s *SQLStore) ListAgilityDrills(ctx context.Context, tenantID string, limit int) ([]AgilityDrill, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, iterations, result, error, measurements, run_by, created_at
FROM agility_drills WHERE tenant_id=$1 ORDER BY created_at DESC, id DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []AgilityDrill{}
	for rows.Next() {
		var (
			d    AgilityDrill
			meas string
		)
		if err := rows.Scan(&d.ID, &d.TenantID, &d.Iterations, &d.Result, &d.Error, &meas, &d.RunBy, &d.CreatedAt); err != nil {
			return nil, err
		}
		var m drillMeasurements
		if err := json.Unmarshal([]byte(meas), &m); err != nil {
			return nil, err
		}
		d.From, d.To, d.Comparison = m.From, m.To, m.Comparison
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateAgilityDrill(ctx context.Context, d AgilityDrill) (AgilityDrill, error) {
	meas, err := json.Marshal(drillMeasurements{From: d.From, To: d.To, Comparison: d.Comparison})
	if err != nil {
		return AgilityDrill{}, err
	}
	err = s.db.SQL().QueryRowContext(ctx, `
INSERT INTO agility_drills (id, tenant_id, from_algorithm, to_algorithm, iterations, result, error, measurements, run_by, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP)
RETURNING created_at`, d.ID, d.TenantID, d.From.Algorithm, d.To.Algorithm, d.Iterations, d.Result, d.Error, string(meas), d.RunBy).Scan(&d.CreatedAt)
	return d, err
}
