package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// ---- CARAF threats ----

const carafThreatColumns = `id, tenant_id, name, category, match_kind, match_value, years_to_threat, note, created_by, created_at, updated_at`

func (s *SQLStore) ListCarafThreats(ctx context.Context, tenantID string) ([]CarafThreat, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+carafThreatColumns+` FROM caraf_threats WHERE tenant_id=$1 ORDER BY years_to_threat, name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []CarafThreat{}
	for rows.Next() {
		t, err := scanCarafThreat(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateCarafThreat(ctx context.Context, t CarafThreat) (CarafThreat, error) {
	return scanCarafThreat(s.db.SQL().QueryRowContext(ctx, `
INSERT INTO caraf_threats (id, tenant_id, name, category, match_kind, match_value, years_to_threat, note, created_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
RETURNING `+carafThreatColumns, t.ID, t.TenantID, t.Name, t.Category, t.MatchKind, t.MatchValue, t.YearsToThreat, t.Note, t.CreatedBy))
}

func (s *SQLStore) UpdateCarafThreat(ctx context.Context, t CarafThreat) (CarafThreat, error) {
	out, err := scanCarafThreat(s.db.SQL().QueryRowContext(ctx, `
UPDATE caraf_threats SET name=$3, category=$4, match_kind=$5, match_value=$6, years_to_threat=$7, note=$8, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$1 AND id=$2
RETURNING `+carafThreatColumns, t.TenantID, t.ID, t.Name, t.Category, t.MatchKind, t.MatchValue, t.YearsToThreat, t.Note))
	if err == sql.ErrNoRows {
		return CarafThreat{}, errStoreNotFound
	}
	return out, err
}

func (s *SQLStore) DeleteCarafThreat(ctx context.Context, tenantID, id string) error {
	return deleteOne(ctx, s, `DELETE FROM caraf_threats WHERE tenant_id=$1 AND id=$2`, tenantID, id)
}

func scanCarafThreat(row interface{ Scan(dest ...any) error }) (CarafThreat, error) {
	var t CarafThreat
	err := row.Scan(&t.ID, &t.TenantID, &t.Name, &t.Category, &t.MatchKind, &t.MatchValue, &t.YearsToThreat, &t.Note, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}

// ---- CARAF assets ----

const carafAssetColumns = `id, tenant_id, name, description, owner, ownership, implementation, pqc_support, location, jurisdiction,
       sensitivity, shelf_life_years, migration_years, cost, algorithms, key_ids,
       decision, decision_owner, decision_due, decision_review_by, decision_status, decision_note, decided_by, decided_at,
       created_by, created_at, updated_at`

func (s *SQLStore) ListCarafAssets(ctx context.Context, tenantID string) ([]CarafAsset, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+carafAssetColumns+` FROM caraf_assets WHERE tenant_id=$1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []CarafAsset{}
	for rows.Next() {
		a, err := scanCarafAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetCarafAsset(ctx context.Context, tenantID, id string) (CarafAsset, error) {
	a, err := scanCarafAsset(s.db.SQL().QueryRowContext(ctx, `SELECT `+carafAssetColumns+` FROM caraf_assets WHERE tenant_id=$1 AND id=$2`, tenantID, id))
	if err == sql.ErrNoRows {
		return CarafAsset{}, errStoreNotFound
	}
	return a, err
}

func (s *SQLStore) CreateCarafAsset(ctx context.Context, a CarafAsset) (CarafAsset, error) {
	algs, keys := jsonList(a.Algorithms), jsonList(a.KeyIDs)
	return scanCarafAsset(s.db.SQL().QueryRowContext(ctx, `
INSERT INTO caraf_assets (id, tenant_id, name, description, owner, ownership, implementation, pqc_support, location, jurisdiction,
  sensitivity, shelf_life_years, migration_years, cost, algorithms, key_ids, created_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
RETURNING `+carafAssetColumns,
		a.ID, a.TenantID, a.Name, a.Description, a.Owner, a.Ownership, a.Implementation, a.PQCSupport, a.Location, a.Jurisdiction,
		a.Sensitivity, optionalInt(a.ShelfLifeYears), optionalInt(a.MigrationYears), a.Cost, algs, keys, a.CreatedBy))
}

// UpdateCarafAsset changes the profile; the decision is set separately.
func (s *SQLStore) UpdateCarafAsset(ctx context.Context, a CarafAsset) (CarafAsset, error) {
	out, err := scanCarafAsset(s.db.SQL().QueryRowContext(ctx, `
UPDATE caraf_assets SET name=$3, description=$4, owner=$5, ownership=$6, implementation=$7, pqc_support=$8, location=$9,
  jurisdiction=$10, sensitivity=$11, shelf_life_years=$12, migration_years=$13, cost=$14, algorithms=$15, key_ids=$16,
  updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$1 AND id=$2
RETURNING `+carafAssetColumns,
		a.TenantID, a.ID, a.Name, a.Description, a.Owner, a.Ownership, a.Implementation, a.PQCSupport, a.Location,
		a.Jurisdiction, a.Sensitivity, optionalInt(a.ShelfLifeYears), optionalInt(a.MigrationYears), a.Cost, jsonList(a.Algorithms), jsonList(a.KeyIDs)))
	if err == sql.ErrNoRows {
		return CarafAsset{}, errStoreNotFound
	}
	return out, err
}

func (s *SQLStore) SetCarafDecision(ctx context.Context, tenantID, id string, d CarafDecision) (CarafAsset, error) {
	out, err := scanCarafAsset(s.db.SQL().QueryRowContext(ctx, `
UPDATE caraf_assets SET decision=$3, decision_owner=$4, decision_due=$5, decision_review_by=$6, decision_status=$7,
  decision_note=$8, decided_by=$9, decided_at=$10, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$1 AND id=$2
RETURNING `+carafAssetColumns,
		tenantID, id, d.Decision, d.Owner, nullableTime(d.Due), nullableTime(d.ReviewBy), d.Status, d.Note, d.DecidedBy, nullableTime(d.DecidedAt)))
	if err == sql.ErrNoRows {
		return CarafAsset{}, errStoreNotFound
	}
	return out, err
}

func (s *SQLStore) DeleteCarafAsset(ctx context.Context, tenantID, id string) error {
	return deleteOne(ctx, s, `DELETE FROM caraf_assets WHERE tenant_id=$1 AND id=$2`, tenantID, id)
}

func scanCarafAsset(row interface{ Scan(dest ...any) error }) (CarafAsset, error) {
	var (
		a                      CarafAsset
		shelf, migrate         sql.NullInt64
		algs, keys             string
		due, review, decidedAt sql.NullTime
	)
	err := row.Scan(&a.ID, &a.TenantID, &a.Name, &a.Description, &a.Owner, &a.Ownership, &a.Implementation, &a.PQCSupport,
		&a.Location, &a.Jurisdiction, &a.Sensitivity, &shelf, &migrate, &a.Cost, &algs, &keys,
		&a.Decision.Decision, &a.Decision.Owner, &due, &review, &a.Decision.Status, &a.Decision.Note, &a.Decision.DecidedBy, &decidedAt,
		&a.CreatedBy, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return CarafAsset{}, err
	}
	a.ShelfLifeYears, a.MigrationYears = intPtr(shelf), intPtr(migrate)
	a.Decision.Due, a.Decision.ReviewBy, a.Decision.DecidedAt = timePtr(due), timePtr(review), timePtr(decidedAt)
	_ = json.Unmarshal([]byte(algs), &a.Algorithms)
	_ = json.Unmarshal([]byte(keys), &a.KeyIDs)
	if a.Algorithms == nil {
		a.Algorithms = []string{}
	}
	if a.KeyIDs == nil {
		a.KeyIDs = []string{}
	}
	return a, nil
}

func deleteOne(ctx context.Context, s *SQLStore, query, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, query, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func jsonList(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func optionalInt(v *int) interface{} {
	if v == nil {
		return nil
	}
	return *v
}

func intPtr(v sql.NullInt64) *int {
	if !v.Valid {
		return nil
	}
	n := int(v.Int64)
	return &n
}

func timePtr(v sql.NullTime) *time.Time {
	if !v.Valid {
		return nil
	}
	t := v.Time.UTC()
	return &t
}
