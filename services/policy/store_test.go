package main

import (
	"context"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

func newPolicyStore(t *testing.T) *SQLStore {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{
		UseSQLite:  true,
		SQLitePath: ":memory:",
		MaxOpen:    1,
		MaxIdle:    1,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createPolicySchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return NewSQLStore(conn)
}

func createPolicySchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE policies (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			status TEXT NOT NULL DEFAULT 'active',
			spec_type TEXT NOT NULL,
			labels TEXT NOT NULL,
			yaml_document TEXT NOT NULL,
			parsed_json TEXT NOT NULL,
			current_version INTEGER NOT NULL,
			current_commit TEXT NOT NULL,
			created_by TEXT NOT NULL,
			updated_by TEXT NOT NULL,
			created_at TEXT DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE policy_versions (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			version INTEGER NOT NULL,
			commit_hash TEXT NOT NULL,
			parent_commit_hash TEXT,
			change_type TEXT NOT NULL,
			change_message TEXT,
			yaml_document TEXT NOT NULL,
			parsed_json TEXT NOT NULL,
			created_by TEXT NOT NULL,
			created_at TEXT DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE policy_evaluations (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			policy_id TEXT,
			operation TEXT NOT NULL,
			key_id TEXT,
			decision TEXT NOT NULL,
			reason TEXT,
			request_json TEXT NOT NULL,
			outcomes_json TEXT NOT NULL,
			occurred_at TEXT DEFAULT CURRENT_TIMESTAMP
		);`,
	}
	for _, q := range stmts {
		if _, err := conn.SQL().Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func TestPolicyStoreCreateUpdateVersionFlow(t *testing.T) {
	store := newPolicyStore(t)
	ctx := context.Background()
	raw := `
apiVersion: kms.vecta.com/v1
kind: CryptoPolicy
metadata:
  name: algo-restrict
  tenant: tenant-a
spec:
  type: algorithm
  targets:
    selector: {}
  rules:
    - name: allow-only-aes
      condition: "key.algorithm in [AES-256, AES-192]"
      action: enforce
      message: "Only AES is allowed"
`
	doc, parsed, err := parsePolicyYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{
		ID:             "pol1",
		TenantID:       "tenant-a",
		Name:           doc.Metadata.Name,
		Status:         "active",
		SpecType:       doc.Spec.Type,
		Labels:         doc.Metadata.Labels,
		RawYAML:        raw,
		ParsedJSON:     parsed,
		CurrentVersion: 1,
		CurrentCommit:  "c1",
		CreatedBy:      "alice",
		UpdatedBy:      "alice",
	}
	v1 := PolicyVersion{
		ID:         "v1",
		TenantID:   "tenant-a",
		PolicyID:   "pol1",
		Version:    1,
		CommitHash: "c1",
		ChangeType: "create",
		RawYAML:    raw,
		ParsedJSON: parsed,
		CreatedBy:  "alice",
	}
	if err := store.CreatePolicy(ctx, p, v1); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetPolicy(ctx, "tenant-a", "pol1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentVersion != 1 || got.Name != "algo-restrict" {
		t.Fatalf("unexpected policy %+v", got)
	}

	p.CurrentVersion = 2
	p.CurrentCommit = "c2"
	p.UpdatedBy = "bob"
	v2 := PolicyVersion{
		ID:               "v2",
		TenantID:         "tenant-a",
		PolicyID:         "pol1",
		Version:          2,
		CommitHash:       "c2",
		ParentCommitHash: "c1",
		ChangeType:       "update",
		RawYAML:          raw,
		ParsedJSON:       parsed,
		CreatedBy:        "bob",
	}
	if err := store.UpdatePolicy(ctx, p, v2); err != nil {
		t.Fatal(err)
	}
	versions, err := store.ListPolicyVersions(ctx, "tenant-a", "pol1")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}
}
