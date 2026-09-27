package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// The playbook store on real Postgres (CI integration-postgres): migrations
// 004 + 005 (re-runnable), a row saved before 005 read with its legacy action
// names mapped, authorization and category round-trips, run actor, and the
// summary for a tenant with no playbooks (SUM over no rows is NULL).
func TestPlaybookStorePostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	for i := 0; i < 2; i++ {
		if err := conn.RunMigrations(ctx, "migrations"); err != nil {
			t.Fatalf("migrations (pass %d): %v", i+1, err)
		}
	}
	db := conn.SQL()
	tenant := "t-pg-" + time.Now().UTC().Format("150405.000000")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM compliance_playbook_runs WHERE tenant_id=$1`, tenant)
		_, _ = db.Exec(`DELETE FROM compliance_playbooks WHERE tenant_id=$1`, tenant)
	})
	store := NewSQLStore(conn)

	sum, err := store.GetPlaybookSummary(ctx, tenant)
	if err != nil || sum["total_playbooks"] != 0 || sum["enabled_count"] != 0 {
		t.Fatalf("empty summary: %v %v", sum, err)
	}

	// A row as 004 wrote it: no category, no authorization, legacy action.
	if _, err := db.Exec(`INSERT INTO compliance_playbooks (id, tenant_id, name, trigger_json, actions_json, enabled)
		VALUES ('pb-old', $1, 'old', '{"type":"canary_tripped","threshold":3}', '[{"type":"suspend_key","parameters":{"key_id":"k1"}}]', TRUE)`, tenant); err != nil {
		t.Fatal(err)
	}
	old, err := store.GetPlaybook(ctx, tenant, "pb-old")
	if err != nil {
		t.Fatal(err)
	}
	if old.AuthorizedBy != "" || old.Category != "incident_response" || old.Actions[0].Type != "disable_key" || old.Trigger.Type != "canary_tripped" {
		t.Fatalf("pre-005 row read as %+v", old)
	}

	pb, err := store.CreatePlaybook(ctx, Playbook{
		ID: "pb-new", TenantID: tenant, Name: "new", Category: "key_lifecycle", Enabled: true, AuthorizedBy: "u-admin",
		Trigger: PlaybookTrigger{Type: "key_rotated"},
		Actions: []PlaybookAction{{Type: "rotate_key", Parameters: map[string]string{"key_id": "k1"}}},
	})
	if err != nil || pb.Category != "key_lifecycle" || pb.AuthorizedBy != "u-admin" {
		t.Fatalf("create: %+v %v", pb, err)
	}
	pb.Enabled, pb.AuthorizedBy = false, ""
	if pb, err = store.UpdatePlaybook(ctx, pb); err != nil || pb.Enabled || pb.AuthorizedBy != "" {
		t.Fatalf("update: %+v %v", pb, err)
	}

	run, err := store.CreatePlaybookRun(ctx, PlaybookRun{ID: "pbrun-pg", PlaybookID: "pb-new", TenantID: tenant, TriggerEvent: "manual", Actor: "u-admin", Status: runRunning})
	if err != nil || run.Actor != "u-admin" {
		t.Fatalf("run: %+v %v", run, err)
	}
	now := time.Now().UTC()
	run.Status, run.ActionsRun, run.CompletedAt = runPendingApproval, 1, &now
	if run, err = store.UpdatePlaybookRun(ctx, run); err != nil || run.Status != runPendingApproval || run.Actor != "u-admin" {
		t.Fatalf("run update: %+v %v", run, err)
	}
	if runs, err := store.ListPlaybookRuns(ctx, tenant, "pb-new", 5); err != nil || len(runs) != 1 {
		t.Fatalf("runs: %v %v", runs, err)
	}
	sum, err = store.GetPlaybookSummary(ctx, tenant)
	if err != nil || sum["total_playbooks"] != 2 || sum["enabled_count"] != 1 || sum["runs_today"] != 1 || sum["last_run_status"] != runPendingApproval {
		t.Fatalf("summary: %v %v", sum, err)
	}
}
