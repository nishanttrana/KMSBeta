package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	CreatePolicy(ctx context.Context, policy Policy, ver PolicyVersion) error
	UpdatePolicy(ctx context.Context, policy Policy, ver PolicyVersion) error
	DeletePolicy(ctx context.Context, tenantID string, policyID string, actor string, ver PolicyVersion) error
	GetPolicy(ctx context.Context, tenantID string, policyID string) (Policy, error)
	ListPolicies(ctx context.Context, tenantID string, status string, limit int, offset int) ([]Policy, error)
	ListActiveForEval(ctx context.Context, tenantID string) ([]Policy, error)
	ListPolicyVersions(ctx context.Context, tenantID string, policyID string) ([]PolicyVersion, error)
	GetPolicyVersion(ctx context.Context, tenantID string, policyID string, version int) (PolicyVersion, error)
	InsertEvaluation(ctx context.Context, rec EvaluationRecord) error
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) CreatePolicy(ctx context.Context, policy Policy, ver PolicyVersion) error {
	return s.withTenantTx(ctx, policy.TenantID, func(tx *sql.Tx) error {
		labels, _ := json.Marshal(policy.Labels)
		parsedPolicy, _ := json.Marshal(policy.ParsedJSON)
		parsedVersion, _ := json.Marshal(ver.ParsedJSON)

		_, err := tx.ExecContext(ctx, `
INSERT INTO policies (
    id, tenant_id, name, description, status, spec_type, labels, yaml_document, parsed_json,
    current_version, current_commit, created_by, updated_by, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
`, policy.ID, policy.TenantID, policy.Name, nullable(policy.Description), policy.Status, policy.SpecType, labels,
			policy.RawYAML, parsedPolicy, policy.CurrentVersion, policy.CurrentCommit, policy.CreatedBy, policy.UpdatedBy)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO policy_versions (
    id, tenant_id, policy_id, version, commit_hash, parent_commit_hash, change_type, change_message,
    yaml_document, parsed_json, created_by, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP)
`, ver.ID, ver.TenantID, ver.PolicyID, ver.Version, ver.CommitHash, nullable(ver.ParentCommitHash), ver.ChangeType,
			nullable(ver.ChangeMessage), ver.RawYAML, parsedVersion, ver.CreatedBy)
		return err
	})
}

func (s *SQLStore) UpdatePolicy(ctx context.Context, policy Policy, ver PolicyVersion) error {
	return s.withTenantTx(ctx, policy.TenantID, func(tx *sql.Tx) error {
		labels, _ := json.Marshal(policy.Labels)
		parsedPolicy, _ := json.Marshal(policy.ParsedJSON)
		parsedVersion, _ := json.Marshal(ver.ParsedJSON)

		res, err := tx.ExecContext(ctx, `
UPDATE policies
SET description=$1, status=$2, spec_type=$3, labels=$4, yaml_document=$5, parsed_json=$6,
    current_version=$7, current_commit=$8, updated_by=$9, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$10 AND id=$11
`, nullable(policy.Description), policy.Status, policy.SpecType, labels, policy.RawYAML, parsedPolicy,
			policy.CurrentVersion, policy.CurrentCommit, policy.UpdatedBy, policy.TenantID, policy.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errNotFound
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO policy_versions (
    id, tenant_id, policy_id, version, commit_hash, parent_commit_hash, change_type, change_message,
    yaml_document, parsed_json, created_by, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP)
`, ver.ID, ver.TenantID, ver.PolicyID, ver.Version, ver.CommitHash, nullable(ver.ParentCommitHash), ver.ChangeType,
			nullable(ver.ChangeMessage), ver.RawYAML, parsedVersion, ver.CreatedBy)
		return err
	})
}

func (s *SQLStore) DeletePolicy(ctx context.Context, tenantID string, policyID string, actor string, ver PolicyVersion) error {
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		var version int
		var commit string
		if err := tx.QueryRowContext(ctx, `
SELECT current_version, current_commit FROM policies WHERE tenant_id=$1 AND id=$2
`, tenantID, policyID).Scan(&version, &commit); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errNotFound
			}
			return err
		}

		res, err := tx.ExecContext(ctx, `
UPDATE policies
SET status='deleted', updated_by=$1, current_version=$2, current_commit=$3, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$4 AND id=$5
`, actor, ver.Version, ver.CommitHash, tenantID, policyID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errNotFound
		}
		parsedVersion, _ := json.Marshal(ver.ParsedJSON)
		_, err = tx.ExecContext(ctx, `
INSERT INTO policy_versions (
    id, tenant_id, policy_id, version, commit_hash, parent_commit_hash, change_type, change_message,
    yaml_document, parsed_json, created_by, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP)
`, ver.ID, tenantID, policyID, ver.Version, ver.CommitHash, nullable(commit), "delete",
			nullable(ver.ChangeMessage), ver.RawYAML, parsedVersion, actor)
		return err
	})
}

func (s *SQLStore) GetPolicy(ctx context.Context, tenantID string, policyID string) (Policy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, COALESCE(description,''), status, spec_type, labels, yaml_document, parsed_json,
       current_version, current_commit, created_by, updated_by, created_at, updated_at
FROM policies
WHERE tenant_id=$1 AND id=$2
`, tenantID, policyID)
	p, err := scanPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, errNotFound
	}
	return p, err
}

func (s *SQLStore) ListPolicies(ctx context.Context, tenantID string, status string, limit int, offset int) ([]Policy, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, COALESCE(description,''), status, spec_type, labels, yaml_document, parsed_json,
       current_version, current_commit, created_by, updated_by, created_at, updated_at
FROM policies
WHERE tenant_id=$1
  AND ($2='' OR status=$2)
ORDER BY updated_at DESC
LIMIT $3 OFFSET $4
`, tenantID, strings.TrimSpace(status), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]Policy, 0)
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListActiveForEval(ctx context.Context, tenantID string) ([]Policy, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, COALESCE(description,''), status, spec_type, labels, yaml_document, parsed_json,
       current_version, current_commit, created_by, updated_by, created_at, updated_at
FROM policies
WHERE status='active' AND (tenant_id=$1 OR tenant_id='*')
ORDER BY CASE WHEN tenant_id='*' THEN 1 ELSE 0 END, updated_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]Policy, 0)
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListPolicyVersions(ctx context.Context, tenantID string, policyID string) ([]PolicyVersion, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, policy_id, version, commit_hash, COALESCE(parent_commit_hash,''), change_type,
       COALESCE(change_message,''), yaml_document, parsed_json, created_by, created_at
FROM policy_versions
WHERE tenant_id=$1 AND policy_id=$2
ORDER BY version DESC
`, tenantID, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]PolicyVersion, 0)
	for rows.Next() {
		v, err := scanPolicyVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetPolicyVersion(ctx context.Context, tenantID string, policyID string, version int) (PolicyVersion, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, policy_id, version, commit_hash, COALESCE(parent_commit_hash,''), change_type,
       COALESCE(change_message,''), yaml_document, parsed_json, created_by, created_at
FROM policy_versions
WHERE tenant_id=$1 AND policy_id=$2 AND version=$3
`, tenantID, policyID, version)
	v, err := scanPolicyVersion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyVersion{}, errNotFound
	}
	return v, err
}

func (s *SQLStore) InsertEvaluation(ctx context.Context, rec EvaluationRecord) error {
	reqRaw, _ := json.Marshal(rec.Request)
	outRaw, _ := json.Marshal(rec.Outcomes)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO policy_evaluations (
    id, tenant_id, policy_id, operation, key_id, decision, reason, request_json, outcomes_json, occurred_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP)
`, rec.ID, rec.TenantID, nullable(rec.PolicyID), rec.Operation, nullable(rec.KeyID), string(rec.Decision),
		nullable(rec.Reason), reqRaw, outRaw)
	return err
}

func (s *SQLStore) withTenantTx(ctx context.Context, tenantID string, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	_, _ = tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func scanPolicy(scanner interface {
	Scan(dest ...any) error
}) (Policy, error) {
	var p Policy
	var labelsRaw []byte
	var parsedRaw []byte
	var createdRaw any
	var updatedRaw any
	err := scanner.Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &p.Status, &p.SpecType, &labelsRaw, &p.RawYAML, &parsedRaw,
		&p.CurrentVersion, &p.CurrentCommit, &p.CreatedBy, &p.UpdatedBy, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return Policy{}, err
	}
	_ = json.Unmarshal(labelsRaw, &p.Labels)
	_ = json.Unmarshal(parsedRaw, &p.ParsedJSON)
	if p.Labels == nil {
		p.Labels = map[string]any{}
	}
	if p.ParsedJSON == nil {
		p.ParsedJSON = map[string]any{}
	}
	p.CreatedAt = parseTimeValue(createdRaw)
	p.UpdatedAt = parseTimeValue(updatedRaw)
	return p, nil
}

func scanPolicyVersion(scanner interface {
	Scan(dest ...any) error
}) (PolicyVersion, error) {
	var v PolicyVersion
	var parsedRaw []byte
	var createdRaw any
	err := scanner.Scan(
		&v.ID, &v.TenantID, &v.PolicyID, &v.Version, &v.CommitHash, &v.ParentCommitHash, &v.ChangeType,
		&v.ChangeMessage, &v.RawYAML, &parsedRaw, &v.CreatedBy, &createdRaw,
	)
	if err != nil {
		return PolicyVersion{}, err
	}
	_ = json.Unmarshal(parsedRaw, &v.ParsedJSON)
	if v.ParsedJSON == nil {
		v.ParsedJSON = map[string]any{}
	}
	v.CreatedAt = parseTimeValue(createdRaw)
	return v, nil
}

func nullable(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return strings.TrimSpace(v)
}

func parseTimeValue(v any) time.Time {
	switch x := v.(type) {
	case nil:
		return time.Time{}
	case time.Time:
		return x
	case string:
		return parseTimeString(x)
	case []byte:
		return parseTimeString(string(x))
	default:
		return time.Time{}
	}
}

func parseTimeString(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, v); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}
