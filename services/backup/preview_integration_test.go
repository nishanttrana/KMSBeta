package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/features"
)

// The backup service is a preview (pkg/features "backup.scheduler"): it keeps
// policies but must never report a backup or restore it did not perform.
// Runs against real Postgres when VECTA_TEST_POSTGRES_DSN is set.

type backupEvents struct {
	mu       sync.Mutex
	subjects []string
}

func (b *backupEvents) Publish(_ context.Context, subject string, _ []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subjects = append(b.subjects, subject)
	return nil
}

func (b *backupEvents) has(subject string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.subjects {
		if s == subject {
			return true
		}
	}
	return false
}

var lastBackupEvents *backupEvents

func newBackupFixture(t *testing.T) (*Handler, *pkgdb.DB) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database to run backup service tests")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	if _, err := conn.SQL().ExecContext(ctx, `TRUNCATE backup_policies, backup_runs, backup_restore_points`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	lastBackupEvents = &backupEvents{}
	return NewHandler(NewBackupService(NewSQLStore(conn), lastBackupEvents)), conn
}

func backupCall(h *Handler, method, path string, body any) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("X-Tenant-ID", "t-bk")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestBackupSchedulerIsHonestPreview(t *testing.T) {
	h, conn := newBackupFixture(t)

	rr := backupCall(h, http.MethodPost, "/backup/policies", map[string]any{
		"tenant_id": "t-bk", "name": "nightly", "scope": "all", "cron_expr": "0 2 * * *", "retention_days": 30,
		"encrypt_backup": true, "destination": "local",
	})
	if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
		t.Fatalf("policies are still stored: %d %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get(features.HeaderStatus) != features.StatusPreview {
		t.Fatal("every backup scheduler response must be labelled preview")
	}
	var created map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	policyID, _ := created["id"].(string)
	if policyID == "" {
		if p, ok := created["policy"].(map[string]any); ok {
			policyID, _ = p["id"].(string)
		}
	}
	if policyID == "" {
		t.Fatalf("no policy id in %s", rr.Body.String())
	}

	rr = backupCall(h, http.MethodPost, "/backup/policies/"+policyID+"/trigger", nil)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "feature_preview") {
		t.Fatalf("triggering a backup must be refused as a preview, got %d %s", rr.Code, rr.Body.String())
	}
	rr = backupCall(h, http.MethodPost, "/backup/restore-points/rp_any/restore", nil)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "feature_preview") {
		t.Fatalf("restoring must be refused as a preview, got %d %s", rr.Code, rr.Body.String())
	}

	for _, ev := range []string{"audit.backup.policy_created", "audit.backup.run_refused_preview", "audit.backup.restore_refused_preview"} {
		if !lastBackupEvents.has(ev) {
			t.Fatalf("missing audit event %s (got %v)", ev, lastBackupEvents.subjects)
		}
	}

	var runs, points int
	_ = conn.SQL().QueryRow(`SELECT COUNT(1) FROM backup_runs`).Scan(&runs)
	_ = conn.SQL().QueryRow(`SELECT COUNT(1) FROM backup_restore_points`).Scan(&points)
	if runs != 0 || points != 0 {
		t.Fatalf("no run or restore point may be fabricated, got runs=%d points=%d", runs, points)
	}
}

// Runs fabricated before this release are relabelled "simulated" and no longer
// count as successful backups.
func TestSimulatedHistoryIsRelabelled(t *testing.T) {
	h, conn := newBackupFixture(t)
	ctx := context.Background()
	if _, err := conn.SQL().ExecContext(ctx, `INSERT INTO backup_runs (id, tenant_id, policy_id, policy_name, status, scope, destination, triggered_by)
		VALUES ('run_old', 't-bk', 'p', 'nightly', 'completed', 'all', 'local', 'manual')`); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("migrations/002_mark_simulated.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.SQL().ExecContext(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	rr := backupCall(h, http.MethodGet, "/backup/metrics", nil)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	metrics, _ := out["metrics"].(map[string]any)
	if metrics == nil {
		metrics = out
	}
	if n, _ := metrics["successful_runs"].(float64); n != 0 {
		t.Fatalf("a simulated run must not count as a successful backup: %s", rr.Body.String())
	}
	var status string
	_ = conn.SQL().QueryRow(`SELECT status FROM backup_runs WHERE id = 'run_old'`).Scan(&status)
	if status != "simulated" {
		t.Fatalf("old run must be relabelled simulated, got %q", status)
	}
}
