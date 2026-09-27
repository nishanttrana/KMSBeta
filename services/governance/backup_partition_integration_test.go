package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// keycore's keys (64 hash partitions) and audit's audit_events (monthly
// partitions) are partitioned. A backup captures them through the parent
// only, so a restore brings every row back exactly once; a backup from before
// the fix, which also holds the partitions, restores the same.
func TestBackupPartitionedTablesPostgres(t *testing.T) {
	svc, _ := newIntegrationGovernance(t)
	store := svc.store.(*SQLStore)
	db := store.db.SQL()
	ctx := context.Background()
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`DROP TABLE IF EXISTS gov_part_probe CASCADE`)
	exec(`CREATE TABLE gov_part_probe (tenant_id TEXT NOT NULL, id TEXT NOT NULL, v TEXT NOT NULL, PRIMARY KEY (tenant_id, id)) PARTITION BY HASH (tenant_id)`)
	for i := 0; i < 4; i++ {
		exec(fmt.Sprintf(`CREATE TABLE gov_part_probe_p%d PARTITION OF gov_part_probe FOR VALUES WITH (MODULUS 4, REMAINDER %d)`, i, i))
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS gov_part_probe CASCADE`) })
	for i := 0; i < 20; i++ {
		exec(`INSERT INTO gov_part_probe (tenant_id, id, v) VALUES ($1, $2, 'x')`, fmt.Sprintf("tenant-%d", i%5), fmt.Sprintf("k%d", i))
	}
	count := func() int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM gov_part_probe`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	tables, err := store.listBackupTables(ctx)
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, name := range tables {
		listed[name] = true
	}
	if !listed["gov_part_probe"] || listed["gov_part_probe_p0"] {
		t.Fatalf("a backup reads the parent, never a partition: parent=%v p0=%v", listed["gov_part_probe"], listed["gov_part_probe_p0"])
	}

	_, files := takeBackup(t, svc, systemBackup())
	exec(`DELETE FROM gov_part_probe`)
	if _, err := files.restore(svc, "root"); err != nil {
		t.Fatalf("restore of a partitioned table: %v", err)
	}
	if n := count(); n != 20 {
		t.Fatalf("every row back exactly once: got %d, want 20", n)
	}

	// A backup taken before the fix: the parent's rows and a partition's.
	var parentRows, partRows string
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(json_agg(row_to_json(t)),'[]'::json)::text FROM (SELECT * FROM gov_part_probe) t`).Scan(&parentRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(json_agg(row_to_json(t)),'[]'::json)::text FROM (SELECT * FROM gov_part_probe_p0) t`).Scan(&partRows); err != nil {
		t.Fatal(err)
	}
	_, _, skipped, _, err := store.restoreSnapshot(ctx, backupScopeSystem, "", map[string]json.RawMessage{
		"gov_part_probe": json.RawMessage(parentRows), "gov_part_probe_p0": json.RawMessage(partRows),
	})
	if err != nil {
		t.Fatalf("an old backup with partitions must restore: %v", err)
	}
	if n := count(); n != 20 {
		t.Fatalf("old backup: every row back exactly once, got %d", n)
	}
	partitionSkipped := false
	for _, s := range skipped {
		partitionSkipped = partitionSkipped || s == "gov_part_probe_p0"
	}
	if !partitionSkipped {
		t.Fatalf("the partition must be reported as skipped: %v", skipped)
	}
}
