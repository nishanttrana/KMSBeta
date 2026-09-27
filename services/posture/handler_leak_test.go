package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/route/routetest"
)

func newLeakHandler(t *testing.T) (*Handler, *SQLStore) {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{UseSQLite: true, SQLitePath: ":memory:", MaxOpen: 1, MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	for _, stmt := range []string{
		`CREATE TABLE leak_scan_targets (id TEXT NOT NULL, tenant_id TEXT NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL, uri TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE, last_scanned_at TIMESTAMP, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, scan_count INT NOT NULL DEFAULT 0, open_findings INT NOT NULL DEFAULT 0, PRIMARY KEY (tenant_id, id))`,
		`CREATE TABLE leak_scan_jobs (id TEXT NOT NULL, tenant_id TEXT NOT NULL, target_id TEXT NOT NULL, target_name TEXT NOT NULL, target_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued', started_at TIMESTAMP, completed_at TIMESTAMP, findings_count INT NOT NULL DEFAULT 0, error TEXT, progress_pct INT NOT NULL DEFAULT 0, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (tenant_id, id))`,
		`CREATE TABLE leak_findings (id TEXT NOT NULL, tenant_id TEXT NOT NULL, job_id TEXT NOT NULL, target_id TEXT NOT NULL, target_name TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'medium', type TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', location TEXT NOT NULL DEFAULT '', context_preview TEXT NOT NULL DEFAULT '', entropy DOUBLE PRECISION NOT NULL DEFAULT 0, secret_fingerprint TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open', detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, resolved_at TIMESTAMP, resolved_by TEXT, notes TEXT, PRIMARY KEY (tenant_id, id))`,
	} {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	store := NewSQLStore(conn)
	return NewHandler(NewService(store, nil, nil)), store
}

func leakCall(t *testing.T, h *Handler, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	claims := &pkgauth.Claims{UserID: "alice", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	claims.Subject = "alice"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims)))
	out := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

// A scan of submitted content finds the real secrets in it; resolving a
// finding records the verified caller, and a client-supplied resolved_by is
// rejected.
func TestLeakScanFindsSecretsAndResolverIsTheCaller(t *testing.T) {
	h, store := newLeakHandler(t)
	rec := &routetest.Recorder{}
	h.audit = rec

	rr, out := leakCall(t, h, http.MethodPost, "/leaks/targets", `{"name":"ci","type":"env_file","uri":"inline"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body)
	}
	tid := out["target"].(map[string]any)["id"].(string)
	body, _ := json.Marshal(map[string]string{"content": "aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n", "filename": ".env"})
	if rr, _ := leakCall(t, h, http.MethodPost, "/leaks/targets/"+tid+"/scan", string(body)); rr.Code != http.StatusAccepted {
		t.Fatalf("scan: %d %s", rr.Code, rr.Body)
	}
	// The scan runs in the background and may already have emitted
	// leak_scan_completed, so look for the start event rather than the last.
	started := false
	for _, e := range rec.Events() {
		started = started || (e.Action == "leak_scan_started" && e.Event.Result == "success")
	}
	if !started {
		t.Fatalf("no successful leak_scan_started event: %+v", rec.Events())
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if jobs, _ := store.ListLeakScanJobs(context.Background(), "t1", tid, 1); len(jobs) == 1 && jobs[0].Status == "completed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	var completed *routetest.Recorded
	for _, e := range rec.Events() {
		if e.Action == "leak_scan_completed" {
			e := e
			completed = &e
		}
	}
	if completed == nil || completed.Event.Details["findings"].(int) < 1 || completed.Event.Details["severity"] != "warning" || completed.Event.ActorID != "alice" {
		t.Fatalf("scan completion not audited: %+v", completed)
	}
	findings, _ := store.ListLeakFindings(context.Background(), "t1", "", "", 10)
	id := ""
	for _, f := range findings {
		if f.Type == "aws_secret_access_key" && f.Severity == "critical" && !strings.Contains(f.ContextPreview, "K7MDENG") {
			id = f.ID
		}
	}
	if id == "" {
		t.Fatalf("aws secret not found (or preview not redacted): %+v", findings)
	}
	if rr, _ := leakCall(t, h, http.MethodPatch, "/leaks/findings/"+id, `{"status":"resolved","resolved_by":"mallory"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("client resolved_by accepted: %d", rr.Code)
	}
	if rr, _ := leakCall(t, h, http.MethodPatch, "/leaks/findings/"+id, `{"status":"resolved","notes":"rotated"}`); rr.Code != http.StatusOK {
		t.Fatalf("resolve: %d %s", rr.Code, rr.Body)
	}
	findings, _ = store.ListLeakFindings(context.Background(), "t1", "resolved", "", 10)
	if len(findings) != 1 || findings[0].ResolvedBy != "alice" {
		t.Fatalf("resolved_by %+v", findings)
	}
	if e := rec.Last(t); e.Action != "leak_finding_updated" || e.Event.Details["status"] != "resolved" {
		t.Fatalf("update event %+v", e)
	}
}

// A scan with no content source fails with the reason, never with made-up
// findings.
func TestLeakScanWithoutSourceFailsHonestly(t *testing.T) {
	t.Setenv("LEAK_SCAN_ROOT", "")
	h, store := newLeakHandler(t)
	_, out := leakCall(t, h, http.MethodPost, "/leaks/targets", `{"name":"repo","type":"git_repo","uri":"https://github.com/example/repo"}`)
	tid := out["target"].(map[string]any)["id"].(string)
	leakCall(t, h, http.MethodPost, "/leaks/targets/"+tid+"/scan", "")
	var jobs []LeakScanJob
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		jobs, _ = store.ListLeakScanJobs(context.Background(), "t1", tid, 10)
		if len(jobs) == 1 && jobs[0].Status == "failed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(jobs) != 1 || jobs[0].Status != "failed" || jobs[0].Error == "" || jobs[0].FindingsCount != 0 {
		t.Fatalf("jobs %+v", jobs)
	}
}
