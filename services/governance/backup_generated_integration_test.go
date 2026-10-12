package main

import (
	"testing"
)

// A table with a generated column restores: the restore writes the stored
// columns and Postgres computes the rest. Until 12.2.0-beta the restore named
// every column, Postgres refused a value for the generated one, and the whole
// restore failed. auth_users has had such a column since 2026-03, so this was
// every real database; the tests here passed because they ran alone, on a
// database without auth's tables.
func TestBackupRestoresGeneratedColumnsPostgres(t *testing.T) {
	svc, _ := newIntegrationGovernance(t)
	db := svc.store.(*SQLStore).db.SQL()
	exec := func(query string, args ...interface{}) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`DROP TABLE IF EXISTS governance_generated_probe`)
	exec(`CREATE TABLE governance_generated_probe (
		tenant_id TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL,
		name_lower TEXT GENERATED ALWAYS AS (lower(name)) STORED,
		PRIMARY KEY (tenant_id, id))`)
	t.Cleanup(func() { _, _ = db.Exec(`DROP TABLE IF EXISTS governance_generated_probe`) })
	exec(`INSERT INTO governance_generated_probe (tenant_id, id, name) VALUES ('t-gen', '1', 'Alice')`)
	createNamedPolicy(t, svc, "t-gen", "kept")

	_, files := takeBackup(t, svc, systemBackup())

	exec(`DELETE FROM governance_generated_probe`)
	exec(`INSERT INTO governance_generated_probe (tenant_id, id, name) VALUES ('t-gen', '2', 'Bob')`)

	if _, err := files.restore(svc, "root"); err != nil {
		t.Fatalf("a backup holding a generated column must restore: %v", err)
	}
	rows, err := db.Query(`SELECT id, name, name_lower FROM governance_generated_probe ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() //nolint:errcheck
	var got []string
	for rows.Next() {
		var id, name, lower string
		if err := rows.Scan(&id, &name, &lower); err != nil {
			t.Fatal(err)
		}
		got = append(got, id+" "+name+" "+lower)
	}
	if len(got) != 1 || got[0] != "1 Alice alice" {
		t.Fatalf("the restored table must hold the backup's row, with its generated value: %q", got)
	}
}
