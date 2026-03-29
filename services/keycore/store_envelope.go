package main

import (
	"context"
	"database/sql"
	"time"
)

// ---- KEKs ----

func (s *SQLStore) ListKEKs(ctx context.Context, tenantID string) ([]KEK, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, algorithm, version, status, created_at, last_rotated_at
FROM envelope_keks
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []KEK
	for rows.Next() {
		var k KEK
		var lastRotated sql.NullTime
		if err := rows.Scan(
			&k.ID, &k.TenantID, &k.Name, &k.Algorithm, &k.Version,
			&k.Status, &k.CreatedAt, &lastRotated,
		); err != nil {
			return nil, err
		}
		if lastRotated.Valid {
			t := lastRotated.Time.UTC()
			k.LastRotatedAt = &t
		}
		out = append(out, k)
	}
	if out == nil {
		out = []KEK{}
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateKEK(ctx context.Context, kek KEK) (KEK, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO envelope_keks (id, tenant_id, name, algorithm, version, status, created_at)
VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
RETURNING id, tenant_id, name, algorithm, version, status, created_at, last_rotated_at
`, kek.ID, kek.TenantID, kek.Name, kek.Algorithm, kek.Version, kek.Status)

	var out KEK
	var lastRotated sql.NullTime
	if err := row.Scan(
		&out.ID, &out.TenantID, &out.Name, &out.Algorithm, &out.Version,
		&out.Status, &out.CreatedAt, &lastRotated,
	); err != nil {
		return KEK{}, err
	}
	if lastRotated.Valid {
		t := lastRotated.Time.UTC()
		out.LastRotatedAt = &t
	}
	return out, nil
}

func (s *SQLStore) RotateKEK(ctx context.Context, tenantID, kekID string) (KEK, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
UPDATE envelope_keks
SET version = version + 1, last_rotated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1 AND id = $2
RETURNING id, tenant_id, name, algorithm, version, status, created_at, last_rotated_at
`, tenantID, kekID)

	var out KEK
	var lastRotated sql.NullTime
	if err := row.Scan(
		&out.ID, &out.TenantID, &out.Name, &out.Algorithm, &out.Version,
		&out.Status, &out.CreatedAt, &lastRotated,
	); err != nil {
		if err == sql.ErrNoRows {
			return KEK{}, errStoreNotFound
		}
		return KEK{}, err
	}
	if lastRotated.Valid {
		t := lastRotated.Time.UTC()
		out.LastRotatedAt = &t
	}
	return out, nil
}

// ---- DEKs ----

func (s *SQLStore) ListDEKs(ctx context.Context, tenantID string, kekID string) ([]DEK, error) {
	query := `
SELECT id, tenant_id, kek_id, kek_name, name, algorithm, purpose, owner_service, status, created_at, last_used_at
FROM envelope_deks
WHERE tenant_id = $1
`
	args := []any{tenantID}
	if kekID != "" {
		query += ` AND kek_id = $2`
		args = append(args, kekID)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := s.db.SQL().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []DEK
	for rows.Next() {
		var d DEK
		var lastUsed sql.NullTime
		if err := rows.Scan(
			&d.ID, &d.TenantID, &d.KEKID, &d.KEKName, &d.Name, &d.Algorithm,
			&d.Purpose, &d.OwnerService, &d.Status, &d.CreatedAt, &lastUsed,
		); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			t := lastUsed.Time.UTC()
			d.LastUsedAt = &t
		}
		out = append(out, d)
	}
	if out == nil {
		out = []DEK{}
	}
	return out, rows.Err()
}

// ---- Hierarchy ----

func (s *SQLStore) GetEnvelopeHierarchy(ctx context.Context, tenantID string) ([]EnvelopeHierarchyNode, error) {
	keks, err := s.ListKEKs(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]EnvelopeHierarchyNode, 0, len(keks))
	for _, kek := range keks {
		deks, err := s.ListDEKs(ctx, tenantID, kek.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, EnvelopeHierarchyNode{KEK: kek, DEKs: deks})
	}
	return out, nil
}

// ---- Rewrap jobs ----

func (s *SQLStore) CreateRewrapJob(ctx context.Context, job RewrapJob) (RewrapJob, error) {
	// Count DEKs for the old KEK so the caller knows the total upfront.
	var total int
	row := s.db.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM envelope_deks WHERE tenant_id=$1 AND kek_id=$2`,
		job.TenantID, job.OldKEKID)
	if err := row.Scan(&total); err != nil {
		return RewrapJob{}, err
	}
	job.TotalDEKs = total

	now := time.Now().UTC()
	job.StartedAt = &now

	row = s.db.SQL().QueryRowContext(ctx, `
INSERT INTO envelope_rewrap_jobs
  (id, tenant_id, old_kek_id, new_kek_id, total_deks, processed_deks, status, started_at, created_at)
VALUES ($1,$2,$3,$4,$5,0,'running',$6,CURRENT_TIMESTAMP)
RETURNING id, tenant_id, old_kek_id, new_kek_id, total_deks, processed_deks, status,
          started_at, completed_at, COALESCE(error,''), created_at
`, job.ID, job.TenantID, job.OldKEKID, job.NewKEKID, job.TotalDEKs, now)

	return scanRewrapJob(row)
}

func (s *SQLStore) ListRewrapJobs(ctx context.Context, tenantID string) ([]RewrapJob, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, old_kek_id, new_kek_id, total_deks, processed_deks, status,
       started_at, completed_at, COALESCE(error,''), created_at
FROM envelope_rewrap_jobs
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []RewrapJob
	for rows.Next() {
		j, err := scanRewrapJobRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	if out == nil {
		out = []RewrapJob{}
	}
	return out, rows.Err()
}

func scanRewrapJob(row *sql.Row) (RewrapJob, error) {
	var j RewrapJob
	var startedAt sql.NullTime
	var completedAt sql.NullTime
	if err := row.Scan(
		&j.ID, &j.TenantID, &j.OldKEKID, &j.NewKEKID,
		&j.TotalDEKs, &j.ProcessedDEKs, &j.Status,
		&startedAt, &completedAt, &j.Error, &j.CreatedAt,
	); err != nil {
		return RewrapJob{}, err
	}
	if startedAt.Valid {
		t := startedAt.Time.UTC()
		j.StartedAt = &t
	}
	if completedAt.Valid {
		t := completedAt.Time.UTC()
		j.CompletedAt = &t
	}
	return j, nil
}

func scanRewrapJobRow(rows interface {
	Scan(dest ...any) error
}) (RewrapJob, error) {
	var j RewrapJob
	var startedAt sql.NullTime
	var completedAt sql.NullTime
	if err := rows.Scan(
		&j.ID, &j.TenantID, &j.OldKEKID, &j.NewKEKID,
		&j.TotalDEKs, &j.ProcessedDEKs, &j.Status,
		&startedAt, &completedAt, &j.Error, &j.CreatedAt,
	); err != nil {
		return RewrapJob{}, err
	}
	if startedAt.Valid {
		t := startedAt.Time.UTC()
		j.StartedAt = &t
	}
	if completedAt.Valid {
		t := completedAt.Time.UTC()
		j.CompletedAt = &t
	}
	return j, nil
}
