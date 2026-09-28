package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
)

// The playbook store on real Postgres (CI integration-postgres): migrations
// 004-008 (re-runnable), a row saved before 005 read with its legacy action
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

	run, err := store.CreatePlaybookRun(ctx, PlaybookRun{ID: "pbrun-pg", PlaybookID: "pb-new", TenantID: tenant, TriggerEvent: "incident_opened", Actor: "u-admin", ActorType: "user", Status: runRunning,
		Context: RunEvent{Subject: "audit.reporting.incident_opened", TargetType: "incident", TargetID: "inc_pg", Details: map[string]string{"severity": "high"}}, IncidentID: "inc_pg", ApprovedIndex: -1})
	if err != nil || run.Actor != "u-admin" || run.Context.Details["severity"] != "high" || run.ApprovedIndex != -1 {
		t.Fatalf("run: %+v %v", run, err)
	}
	now := time.Now().UTC()
	run.Status, run.ApprovalRequestID, run.ResumeIndex = runAwaitingApproval, "apr_pg", 1
	run.Results = []ActionResult{{Index: 1, Type: "rotate_key", Status: outcomeDone, At: now}}
	if run, err = store.UpdatePlaybookRun(ctx, run); err != nil || len(run.Results) != 1 || run.ResumeIndex != 1 {
		t.Fatalf("run update: %+v %v", run, err)
	}
	if got, err := store.GetPlaybookRunByApproval(ctx, tenant, "apr_pg"); err != nil || got.ID != run.ID {
		t.Fatalf("run by approval: %+v %v", got, err)
	}
	run.Status, run.ApprovalRequestID, run.CompletedAt = runPendingApproval, "", &now
	if run, err = store.UpdatePlaybookRun(ctx, run); err != nil || run.Status != runPendingApproval {
		t.Fatalf("run finish: %+v %v", run, err)
	}
	for _, q := range []RunQuery{{PlaybookID: "pb-new"}, {IncidentID: "inc_pg"}, {Status: runPendingApproval}} {
		if runs, err := store.ListPlaybookRuns(ctx, tenant, q); err != nil || len(runs) != 1 {
			t.Fatalf("runs %+v: %v %v", q, runs, err)
		}
	}

	// A sealed connection round-trips through BYTEA.
	env := &pkgcrypto.EnvelopeCiphertext{Ciphertext: []byte{1, 2}, DataIV: []byte{3}, WrappedDEK: []byte{4, 5}, WrappedDEKIV: []byte{6}}
	stored, err := store.CreateConnection(ctx, Connection{ID: "pbconn-pg", TenantID: tenant, Name: "soc", Type: "slack", Endpoint: "hooks.slack.com", FieldSet: []string{"webhook_url"}, Sealed: env})
	if err != nil || stored.Endpoint != "hooks.slack.com" || stored.Sealed != nil {
		t.Fatalf("connection: %+v %v", stored, err)
	}
	if got, err := store.GetConnection(ctx, tenant, "pbconn-pg"); err != nil || got.Sealed == nil || string(got.Sealed.WrappedDEK) != string(env.WrappedDEK) {
		t.Fatalf("sealed connection read: %+v %v", got, err)
	}
	_, _ = db.Exec(`DELETE FROM compliance_playbook_connections WHERE tenant_id=$1`, tenant)

	// Threshold counts: per group, inside the window, reset per group or all.
	hitAt := time.Now().UTC()
	for i, want := range []int{1, 2} {
		if n, err := store.CountThresholdHit(ctx, tenant, "pb-old", "mallory", hitAt.Add(time.Duration(i)*time.Second), time.Minute); err != nil || n != want {
			t.Fatalf("threshold hit %d: %d %v", i, n, err)
		}
	}
	if n, err := store.CountThresholdHit(ctx, tenant, "pb-old", "alice", hitAt, time.Minute); err != nil || n != 1 {
		t.Fatalf("other group: %d %v", n, err)
	}
	if n, err := store.CountThresholdHit(ctx, tenant, "pb-old", "mallory", hitAt.Add(2*time.Minute), time.Minute); err != nil || n != 1 {
		t.Fatalf("outside the window: %d %v", n, err)
	}
	if err := store.ResetThresholdHits(ctx, tenant, "pb-old", "*"); err != nil {
		t.Fatal(err)
	}
	// Cooldown claim: once per window, then again after it.
	for i, c := range []struct {
		at   time.Time
		want bool
	}{{hitAt, true}, {hitAt.Add(30 * time.Second), false}, {hitAt.Add(61 * time.Second), true}} {
		if ok, err := store.ClaimPlaybookFire(ctx, tenant, "pb-old", c.at, time.Minute); err != nil || ok != c.want {
			t.Fatalf("claim %d: %v %v, want %v", i, ok, err, c.want)
		}
	}
	var left int
	if err := db.QueryRow(`SELECT COUNT(*) FROM compliance_playbook_threshold_hits WHERE tenant_id=$1`, tenant).Scan(&left); err != nil || left != 0 {
		t.Fatalf("after reset: %d %v", left, err)
	}
	sum, err = store.GetPlaybookSummary(ctx, tenant)
	if err != nil || sum["total_playbooks"] != 2 || sum["enabled_count"] != 1 || sum["runs_today"] != 1 || sum["last_run_status"] != runPendingApproval {
		t.Fatalf("summary: %v %v", sum, err)
	}
}
