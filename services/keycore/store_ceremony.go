package main

import (
	"context"
	"database/sql"
	"time"
)

// ListCeremonyGuardians returns all guardians for a tenant.
func (s *SQLStore) ListCeremonyGuardians(ctx context.Context, tenantID string) ([]CeremonyGuardian, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, email, role, status, joined_at, created_at
FROM ceremony_guardians
WHERE tenant_id = $1
ORDER BY name ASC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]CeremonyGuardian, 0)
	for rows.Next() {
		var g CeremonyGuardian
		if err := rows.Scan(
			&g.ID,
			&g.TenantID,
			&g.Name,
			&g.Email,
			&g.Role,
			&g.Status,
			&g.JoinedAt,
			&g.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// CreateCeremonyGuardian inserts a new guardian record.
func (s *SQLStore) CreateCeremonyGuardian(ctx context.Context, g CeremonyGuardian) (CeremonyGuardian, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO ceremony_guardians (id, tenant_id, name, email, role, status, joined_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
RETURNING id, tenant_id, name, email, role, status, joined_at, created_at
`, g.ID, g.TenantID, g.Name, g.Email, g.Role, g.Status)

	var out CeremonyGuardian
	if err := row.Scan(
		&out.ID,
		&out.TenantID,
		&out.Name,
		&out.Email,
		&out.Role,
		&out.Status,
		&out.JoinedAt,
		&out.CreatedAt,
	); err != nil {
		return CeremonyGuardian{}, err
	}
	return out, nil
}

// DeleteCeremonyGuardian removes a guardian by tenant and id.
func (s *SQLStore) DeleteCeremonyGuardian(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM ceremony_guardians WHERE tenant_id = $1 AND id = $2
`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

// ListCeremonies returns all ceremonies for a tenant, with their shares.
func (s *SQLStore) ListCeremonies(ctx context.Context, tenantID string) ([]Ceremony, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, type, threshold, total_shares, status,
       COALESCE(key_id,''), COALESCE(key_name,''), notes, created_by, created_at, completed_at
FROM ceremonies
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []Ceremony
	for rows.Next() {
		c, err := scanCeremony(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Load shares for each ceremony.
	for i := range out {
		shares, err := s.loadCeremonyShares(ctx, tenantID, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Shares = shares
	}
	return out, nil
}

// GetCeremony fetches a single ceremony by id, populating shares.
func (s *SQLStore) GetCeremony(ctx context.Context, tenantID, id string) (Ceremony, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, type, threshold, total_shares, status,
       COALESCE(key_id,''), COALESCE(key_name,''), notes, created_by, created_at, completed_at
FROM ceremonies
WHERE tenant_id = $1 AND id = $2
`, tenantID, id)

	c, err := scanCeremony(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return Ceremony{}, errStoreNotFound
		}
		return Ceremony{}, err
	}

	shares, err := s.loadCeremonyShares(ctx, tenantID, id)
	if err != nil {
		return Ceremony{}, err
	}
	c.Shares = shares
	return c, nil
}

// CreateCeremony inserts a ceremony and its guardian shares in a transaction.
func (s *SQLStore) CreateCeremony(ctx context.Context, c Ceremony, guardianIDs []string, guardians []CeremonyGuardian) (Ceremony, error) {
	// Build a lookup map from id -> guardian for name resolution.
	guardianByID := make(map[string]CeremonyGuardian, len(guardians))
	for _, g := range guardians {
		guardianByID[g.ID] = g
	}

	err := s.withTenantTx(ctx, c.TenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
INSERT INTO ceremonies (id, tenant_id, name, type, threshold, total_shares, status, key_id, key_name, notes, created_by, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CURRENT_TIMESTAMP)
`, c.ID, c.TenantID, c.Name, c.Type, c.Threshold, c.TotalShares, c.Status,
			nullable(c.KeyID), nullable(c.KeyName), c.Notes, c.CreatedBy)
		if err != nil {
			return err
		}

		for _, gid := range guardianIDs {
			g := guardianByID[gid]
			gName := g.Name
			if gName == "" {
				gName = gid
			}
			_, err := tx.ExecContext(ctx, `
INSERT INTO ceremony_shares (ceremony_id, tenant_id, guardian_id, guardian_name, status)
VALUES ($1, $2, $3, $4, 'pending')
`, c.ID, c.TenantID, gid, gName)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Ceremony{}, err
	}

	return s.GetCeremony(ctx, c.TenantID, c.ID)
}

// UpdateCeremonyStatus updates the ceremony status and optionally sets completed_at.
func (s *SQLStore) UpdateCeremonyStatus(ctx context.Context, tenantID, id, status string, completedAt *time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ceremonies SET status = $1, completed_at = $2 WHERE tenant_id = $3 AND id = $4
`, status, nullableTime(completedAt), tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

// SubmitCeremonyShare marks a guardian's share as submitted.
func (s *SQLStore) SubmitCeremonyShare(ctx context.Context, tenantID, ceremonyID, guardianID string) error {
	now := time.Now().UTC()
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ceremony_shares
SET status = 'submitted', submitted_at = $1
WHERE tenant_id = $2 AND ceremony_id = $3 AND guardian_id = $4
`, now, tenantID, ceremonyID, guardianID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

// loadCeremonyShares fetches all shares for a given ceremony.
func (s *SQLStore) loadCeremonyShares(ctx context.Context, tenantID, ceremonyID string) ([]CeremonyShare, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT ceremony_id, tenant_id, guardian_id, guardian_name, status, submitted_at
FROM ceremony_shares
WHERE tenant_id = $1 AND ceremony_id = $2
ORDER BY guardian_name ASC
`, tenantID, ceremonyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []CeremonyShare
	for rows.Next() {
		var sh CeremonyShare
		var submittedAt sql.NullTime
		if err := rows.Scan(
			&sh.CeremonyID,
			&sh.TenantID,
			&sh.GuardianID,
			&sh.GuardianName,
			&sh.Status,
			&submittedAt,
		); err != nil {
			return nil, err
		}
		if submittedAt.Valid {
			t := submittedAt.Time.UTC()
			sh.SubmittedAt = &t
		}
		out = append(out, sh)
	}
	return out, rows.Err()
}

// scanCeremony scans a ceremony row (without shares).
func scanCeremony(scanner interface {
	Scan(dest ...interface{}) error
}) (Ceremony, error) {
	var (
		c           Ceremony
		completedAt sql.NullTime
	)
	if err := scanner.Scan(
		&c.ID,
		&c.TenantID,
		&c.Name,
		&c.Type,
		&c.Threshold,
		&c.TotalShares,
		&c.Status,
		&c.KeyID,
		&c.KeyName,
		&c.Notes,
		&c.CreatedBy,
		&c.CreatedAt,
		&completedAt,
	); err != nil {
		return Ceremony{}, err
	}
	if completedAt.Valid {
		t := completedAt.Time.UTC()
		c.CompletedAt = &t
	}
	c.Shares = []CeremonyShare{}
	return c, nil
}
