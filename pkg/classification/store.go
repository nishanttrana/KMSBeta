package classification

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

const createClassificationTablesSQL = `
CREATE TABLE IF NOT EXISTS classification_labels (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    key_id         TEXT NOT NULL,
    level          INTEGER NOT NULL,
    categories     TEXT,
    applied_by     TEXT NOT NULL,
    applied_at     DATETIME NOT NULL,
    justification  TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cl_tenant_key ON classification_labels(tenant_id, key_id);
CREATE INDEX IF NOT EXISTS idx_cl_level ON classification_labels(level);

CREATE TABLE IF NOT EXISTS classification_policies (
    tenant_id                  TEXT PRIMARY KEY,
    min_level_for_hsm          INTEGER NOT NULL DEFAULT 2,
    min_level_for_rotation_days TEXT,
    min_level_for_mfa          INTEGER NOT NULL DEFAULT 3,
    denied_operations_by_level TEXT
);
`

// SQLStore implements Store with a SQL database backend.
type SQLStore struct {
	db *sql.DB
}

// NewSQLStore creates a SQLStore and ensures tables exist.
func NewSQLStore(db *sql.DB) (*SQLStore, error) {
	if _, err := db.Exec(createClassificationTablesSQL); err != nil {
		return nil, fmt.Errorf("classification: create tables: %w", err)
	}
	return &SQLStore{db: db}, nil
}

// UpsertLabel inserts or updates a classification label.
func (s *SQLStore) UpsertLabel(ctx context.Context, label Label) error {
	categoriesJSON, err := json.Marshal(label.Categories)
	if err != nil {
		return fmt.Errorf("classification: marshal categories: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO classification_labels (id, tenant_id, key_id, level, categories, applied_by, applied_at, justification)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(tenant_id, key_id) DO UPDATE SET
		     level = excluded.level,
		     categories = excluded.categories,
		     applied_by = excluded.applied_by,
		     applied_at = excluded.applied_at,
		     justification = excluded.justification`,
		label.ID, label.TenantID, label.KeyID, int(label.Level),
		string(categoriesJSON), label.AppliedBy, label.AppliedAt, label.Justification,
	)
	if err != nil {
		return fmt.Errorf("classification: upsert label: %w", err)
	}
	return nil
}

// GetLabel retrieves the label for a key in a tenant.
func (s *SQLStore) GetLabel(ctx context.Context, keyID, tenantID string) (*Label, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, key_id, level, categories, applied_by, applied_at, justification
		 FROM classification_labels WHERE key_id = ? AND tenant_id = ?`,
		keyID, tenantID,
	)

	var label Label
	var levelInt int
	var categoriesJSON string

	err := row.Scan(&label.ID, &label.TenantID, &label.KeyID, &levelInt,
		&categoriesJSON, &label.AppliedBy, &label.AppliedAt, &label.Justification)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("classification: scan label: %w", err)
	}

	label.Level = Level(levelInt)
	if categoriesJSON != "" {
		_ = json.Unmarshal([]byte(categoriesJSON), &label.Categories)
	}

	return &label, nil
}

// GetPolicy retrieves the classification policy for a tenant.
func (s *SQLStore) GetPolicy(ctx context.Context, tenantID string) (*Policy, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT tenant_id, min_level_for_hsm, min_level_for_rotation_days, min_level_for_mfa, denied_operations_by_level
		 FROM classification_policies WHERE tenant_id = ?`,
		tenantID,
	)

	var policy Policy
	var rotationJSON, deniedJSON sql.NullString
	var hsmLevel, mfaLevel int

	err := row.Scan(&policy.TenantID, &hsmLevel, &rotationJSON, &mfaLevel, &deniedJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("classification: scan policy: %w", err)
	}

	policy.MinLevelForHSM = Level(hsmLevel)
	policy.MinLevelForMFA = Level(mfaLevel)

	if rotationJSON.Valid && rotationJSON.String != "" {
		// Stored as JSON: {"2": 90, "3": 30, "4": 7}
		raw := make(map[string]int)
		if err := json.Unmarshal([]byte(rotationJSON.String), &raw); err == nil {
			policy.MinLevelForRotationDays = make(map[Level]int)
			for k, v := range raw {
				var lvl int
				fmt.Sscanf(k, "%d", &lvl)
				policy.MinLevelForRotationDays[Level(lvl)] = v
			}
		}
	}

	if deniedJSON.Valid && deniedJSON.String != "" {
		// Stored as JSON: {"0": ["export", "decrypt"], "1": ["export"]}
		raw := make(map[string][]string)
		if err := json.Unmarshal([]byte(deniedJSON.String), &raw); err == nil {
			policy.DeniedOperationsByLevel = make(map[Level][]string)
			for k, v := range raw {
				var lvl int
				fmt.Sscanf(k, "%d", &lvl)
				policy.DeniedOperationsByLevel[Level(lvl)] = v
			}
		}
	}

	return &policy, nil
}

// ListKeysByTenant returns minimal key info for all keys in a tenant.
// This queries a hypothetical 'keys' table that would exist in the KMS schema.
func (s *SQLStore) ListKeysByTenant(ctx context.Context, tenantID string) ([]KeyInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT key_id, algorithm, key_size FROM keys WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("classification: list keys: %w", err)
	}
	defer rows.Close()

	var keys []KeyInfo
	for rows.Next() {
		var k KeyInfo
		if err := rows.Scan(&k.KeyID, &k.Algorithm, &k.KeySize); err != nil {
			return nil, fmt.Errorf("classification: scan key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}
