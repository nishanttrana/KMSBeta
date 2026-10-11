package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// BYOKStore holds BYOK keys, their material custody and their runs
// (migrations/004_byok.sql). The tables are replicated under the byok
// component (pkg/clustercatalog); writes go to the primary.
type BYOKStore interface {
	CreateBYOKKey(ctx context.Context, k BYOKKey) error
	UpdateBYOKKey(ctx context.Context, k BYOKKey) error
	GetBYOKKey(ctx context.Context, tenantID, id string) (BYOKKey, error)
	ListBYOKKeys(ctx context.Context, tenantID string) ([]BYOKKey, error)
	PutBYOKMaterial(ctx context.Context, m BYOKMaterial) error
	ListBYOKMaterials(ctx context.Context, tenantID, byokID string) ([]BYOKMaterial, error)
	PutBYOKRun(ctx context.Context, r BYOKRun) error
	ListBYOKRuns(ctx context.Context, tenantID, byokID string, limit int) ([]BYOKRun, error)
}

func nullTime(t *time.Time) interface{} {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC()
}

func timePtr(raw interface{}) *time.Time {
	t := parseTimeValue(raw)
	if t.IsZero() {
		return nil
	}
	return &t
}

const byokKeyColumns = `id, tenant_id, account_id, provider, region, key_id, source, origin, key_spec, usage,
	cloud_key_id, cloud_key_ref, alias, cloud_state, material_state, current_material_id, settings_json,
	expires_at, created_by, created_at, updated_at`

func (s *SQLStore) CreateBYOKKey(ctx context.Context, k BYOKKey) error {
	settings, _ := json.Marshal(k.Settings)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cloud_byok_keys (`+byokKeyColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		k.ID, k.TenantID, k.AccountID, k.Provider, k.Region, k.KeyID, k.Source, k.Origin, k.KeySpec, k.Usage,
		k.CloudKeyID, k.CloudKeyRef, k.Alias, k.CloudState, k.MaterialState, k.CurrentMatID, string(settings),
		nullTime(k.ExpiresAt), k.CreatedBy)
	return err
}

func (s *SQLStore) UpdateBYOKKey(ctx context.Context, k BYOKKey) error {
	settings, _ := json.Marshal(k.Settings)
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE cloud_byok_keys SET cloud_key_id=$3, cloud_key_ref=$4, alias=$5, cloud_state=$6, material_state=$7,
	current_material_id=$8, settings_json=$9, expires_at=$10, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$1 AND id=$2`,
		k.TenantID, k.ID, k.CloudKeyID, k.CloudKeyRef, k.Alias, k.CloudState, k.MaterialState, k.CurrentMatID,
		string(settings), nullTime(k.ExpiresAt))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func scanBYOKKey(sc interface{ Scan(...interface{}) error }) (BYOKKey, error) {
	var k BYOKKey
	var settings string
	var expires, created, updated interface{}
	if err := sc.Scan(&k.ID, &k.TenantID, &k.AccountID, &k.Provider, &k.Region, &k.KeyID, &k.Source, &k.Origin, &k.KeySpec, &k.Usage,
		&k.CloudKeyID, &k.CloudKeyRef, &k.Alias, &k.CloudState, &k.MaterialState, &k.CurrentMatID, &settings,
		&expires, &k.CreatedBy, &created, &updated); err != nil {
		return BYOKKey{}, err
	}
	_ = json.Unmarshal([]byte(settings), &k.Settings)
	if k.Settings == nil {
		k.Settings = map[string]string{}
	}
	k.ExpiresAt, k.CreatedAt, k.UpdatedAt = timePtr(expires), parseTimeValue(created), parseTimeValue(updated)
	return k, nil
}

func (s *SQLStore) GetBYOKKey(ctx context.Context, tenantID, id string) (BYOKKey, error) {
	k, err := scanBYOKKey(s.db.SQL().QueryRowContext(ctx, `SELECT `+byokKeyColumns+` FROM cloud_byok_keys WHERE tenant_id=$1 AND id=$2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return BYOKKey{}, errNotFound
	}
	return k, err
}

func (s *SQLStore) ListBYOKKeys(ctx context.Context, tenantID string) ([]BYOKKey, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+byokKeyColumns+` FROM cloud_byok_keys WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []BYOKKey{}
	for rows.Next() {
		k, err := scanBYOKKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// PutBYOKMaterial inserts a material record or updates its state.
func (s *SQLStore) PutBYOKMaterial(ctx context.Context, m BYOKMaterial) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE cloud_byok_materials SET cloud_material_id=$3, state=$4, expires_at=$5, revoked_at=$6
WHERE tenant_id=$1 AND id=$2`, m.TenantID, m.ID, m.CloudMaterialID, m.State, nullTime(m.ExpiresAt), nullTime(m.RevokedAt))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	_, err = s.db.SQL().ExecContext(ctx, `
INSERT INTO cloud_byok_materials (tenant_id, id, byok_id, kms_version, kcv, cloud_material_id, state, scheme, source,
	wrapping_key_sha256, imported_at, expires_at, revoked_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		m.TenantID, m.ID, m.BYOKID, m.KMSVersion, m.KCV, m.CloudMaterialID, m.State, m.Scheme, m.Source,
		m.WrappingKeySHA256, m.ImportedAt.UTC(), nullTime(m.ExpiresAt), nullTime(m.RevokedAt))
	return err
}

func (s *SQLStore) ListBYOKMaterials(ctx context.Context, tenantID, byokID string) ([]BYOKMaterial, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, byok_id, kms_version, kcv, cloud_material_id, state, scheme, source, wrapping_key_sha256,
	imported_at, expires_at, revoked_at
FROM cloud_byok_materials WHERE tenant_id=$1 AND byok_id=$2 ORDER BY imported_at DESC`, tenantID, byokID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []BYOKMaterial{}
	for rows.Next() {
		var m BYOKMaterial
		var imported, expires, revoked interface{}
		if err := rows.Scan(&m.TenantID, &m.ID, &m.BYOKID, &m.KMSVersion, &m.KCV, &m.CloudMaterialID, &m.State, &m.Scheme,
			&m.Source, &m.WrappingKeySHA256, &imported, &expires, &revoked); err != nil {
			return nil, err
		}
		m.ImportedAt, m.ExpiresAt, m.RevokedAt = parseTimeValue(imported), timePtr(expires), timePtr(revoked)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *SQLStore) PutBYOKRun(ctx context.Context, r BYOKRun) error {
	steps, _ := json.Marshal(r.Steps)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cloud_byok_runs (tenant_id, id, byok_id, operation, status, steps_json, actor, error_message, started_at, finished_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		r.TenantID, r.ID, r.BYOKID, r.Operation, r.Status, string(steps), r.Actor, r.Error, r.StartedAt.UTC(), r.FinishedAt.UTC())
	return err
}

func (s *SQLStore) ListBYOKRuns(ctx context.Context, tenantID, byokID string, limit int) ([]BYOKRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `SELECT tenant_id, id, byok_id, operation, status, steps_json, actor, error_message, started_at, finished_at
FROM cloud_byok_runs WHERE tenant_id=$1`
	args := []interface{}{tenantID}
	if byokID != "" {
		q += ` AND byok_id=$2`
		args = append(args, byokID)
	}
	q += ` ORDER BY started_at DESC LIMIT ` + itoa(limit)
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []BYOKRun{}
	for rows.Next() {
		var r BYOKRun
		var steps string
		var started, finished interface{}
		if err := rows.Scan(&r.TenantID, &r.ID, &r.BYOKID, &r.Operation, &r.Status, &steps, &r.Actor, &r.Error, &started, &finished); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(steps), &r.Steps)
		r.StartedAt, r.FinishedAt = parseTimeValue(started), parseTimeValue(finished)
		out = append(out, r)
	}
	return out, rows.Err()
}
