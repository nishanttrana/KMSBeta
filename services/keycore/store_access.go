package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

func (s *SQLStore) ListAccessGroups(ctx context.Context, tenantID string) ([]AccessGroup, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT g.id, g.tenant_id, g.name, COALESCE(g.description,''), COALESCE(g.created_by,''), COUNT(m.user_id) AS member_count, g.created_at, g.updated_at
FROM key_access_groups g
LEFT JOIN key_access_group_members m
  ON m.tenant_id = g.tenant_id AND m.group_id = g.id
WHERE g.tenant_id = $1
GROUP BY g.id, g.tenant_id, g.name, g.description, g.created_by, g.created_at, g.updated_at
ORDER BY g.name ASC
`, tenantID)
	if err != nil {
		if isMissingKeyAccessTableError(err) {
			return []AccessGroup{}, nil
		}
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]AccessGroup, 0)
	for rows.Next() {
		var item AccessGroup
		if err := rows.Scan(
			&item.ID,
			&item.TenantID,
			&item.Name,
			&item.Description,
			&item.CreatedBy,
			&item.MemberCount,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateAccessGroup(ctx context.Context, group AccessGroup) (AccessGroup, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO key_access_groups (tenant_id, id, name, description, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
RETURNING id, tenant_id, name, COALESCE(description,''), COALESCE(created_by,''), created_at, updated_at
`, group.TenantID, group.ID, group.Name, nullable(group.Description), group.CreatedBy)

	var out AccessGroup
	if err := row.Scan(
		&out.ID,
		&out.TenantID,
		&out.Name,
		&out.Description,
		&out.CreatedBy,
		&out.CreatedAt,
		&out.UpdatedAt,
	); err != nil {
		if isMissingKeyAccessTableError(err) {
			return AccessGroup{}, errors.New("key access control schema is not initialized")
		}
		return AccessGroup{}, err
	}
	out.MemberCount = 0
	return out, nil
}

func (s *SQLStore) DeleteAccessGroup(ctx context.Context, tenantID string, groupID string) error {
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM key_access_group_members WHERE tenant_id=$1 AND group_id=$2`, tenantID, groupID)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM key_access_grants WHERE tenant_id=$1 AND subject_type='group' AND subject_id=$2`, tenantID, groupID)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM key_access_groups WHERE tenant_id=$1 AND id=$2`, tenantID, groupID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errStoreNotFound
		}
		return nil
	})
}

func (s *SQLStore) ReplaceAccessGroupMembers(ctx context.Context, tenantID string, groupID string, userIDs []string) error {
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM key_access_groups WHERE tenant_id=$1 AND id=$2`, tenantID, groupID).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errStoreNotFound
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM key_access_group_members WHERE tenant_id=$1 AND group_id=$2`, tenantID, groupID); err != nil {
			return err
		}
		for _, userID := range userIDs {
			trimmed := strings.TrimSpace(userID)
			if trimmed == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, `
INSERT INTO key_access_group_members (tenant_id, group_id, user_id, created_at)
VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
`, tenantID, groupID, trimmed); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLStore) ListAccessGroupIDsForUser(ctx context.Context, tenantID string, userID string) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT group_id
FROM key_access_group_members
WHERE tenant_id=$1 AND user_id=$2
`, tenantID, userID)
	if err != nil {
		if isMissingKeyAccessTableError(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]string, 0)
	for rows.Next() {
		var groupID string
		if err := rows.Scan(&groupID); err != nil {
			return nil, err
		}
		out = append(out, strings.TrimSpace(groupID))
	}
	return out, rows.Err()
}

func (s *SQLStore) ListKeyAccessGrants(ctx context.Context, tenantID string, keyID string) ([]KeyAccessGrant, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT subject_type, subject_id, operations
FROM key_access_grants
WHERE tenant_id=$1 AND key_id=$2
ORDER BY subject_type ASC, subject_id ASC
`, tenantID, keyID)
	if err != nil {
		if isMissingKeyAccessTableError(err) {
			return []KeyAccessGrant{}, nil
		}
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]KeyAccessGrant, 0)
	for rows.Next() {
		var (
			subjectType string
			subjectID   string
			rawOps      []byte
		)
		if err := rows.Scan(&subjectType, &subjectID, &rawOps); err != nil {
			return nil, err
		}
		ops := make([]string, 0)
		if len(rawOps) > 0 {
			_ = json.Unmarshal(rawOps, &ops)
		}
		out = append(out, KeyAccessGrant{
			SubjectType: AccessSubjectType(subjectType),
			SubjectID:   subjectID,
			Operations:  ops,
		})
	}
	return out, rows.Err()
}

func isMissingKeyAccessTableError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if msg == "" {
		return false
	}
	return strings.Contains(msg, "no such table: key_access_grants") ||
		strings.Contains(msg, "no such table: key_access_group_members") ||
		strings.Contains(msg, "no such table: key_access_groups") ||
		strings.Contains(msg, "relation \"key_access_grants\" does not exist") ||
		strings.Contains(msg, "relation \"key_access_group_members\" does not exist") ||
		strings.Contains(msg, "relation \"key_access_groups\" does not exist")
}

func (s *SQLStore) ReplaceKeyAccessGrants(ctx context.Context, tenantID string, keyID string, grants []KeyAccessGrant, createdBy string) error {
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM keys WHERE tenant_id=$1 AND id=$2`, tenantID, keyID).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errStoreNotFound
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM key_access_grants WHERE tenant_id=$1 AND key_id=$2`, tenantID, keyID); err != nil {
			return err
		}
		for _, grant := range grants {
			rawOps, _ := json.Marshal(grant.Operations)
			if _, err := tx.ExecContext(ctx, `
INSERT INTO key_access_grants (
	tenant_id, key_id, subject_type, subject_id, operations, created_by, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
`, tenantID, keyID, string(grant.SubjectType), grant.SubjectID, rawOps, createdBy); err != nil {
				return err
			}
		}
		return nil
	})
}
