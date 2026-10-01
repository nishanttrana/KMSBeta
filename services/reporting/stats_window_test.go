package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

func TestAlertStatsWindows(t *testing.T) {
	svc, store, audit, _, _, _ := newReportingService(t)
	checkAlertStatsWindows(t, svc, store, audit, "t-win")
}

// The same on real Postgres (CI integration-postgres): TIMESTAMPTZ window
// bounds and the drill-down filters.
func TestAlertStatsWindowsPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 2, MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	store := NewSQLStore(conn)
	audit := &fakeReportingAudit{events: map[string][]map[string]interface{}{}}
	svc := NewService(store, audit, nil, nil, &nopReportingPublisher{})
	checkAlertStatsWindows(t, svc, store, audit, "t-win-pg-"+strconv.FormatInt(time.Now().UnixNano(), 36))
}

// Every count on the Alert Center charts equals the number of alerts its
// drill-down filter lists, for a day, a year and since uptime.
func checkAlertStatsWindows(t *testing.T, svc *Service, store *SQLStore, audit *fakeReportingAudit, tenant string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	type row struct {
		ago                time.Duration
		sev, status        string
		actor, ip, svcName string
		resolved, linked   bool
	}
	rows := []row{
		{300 * 24 * time.Hour, "critical", "resolved", "mallory", "10.0.0.9", "keycore", true, true},
		{40 * 24 * time.Hour, "high", "new", "mallory", "10.0.0.9", "keycore", false, true},
		{5 * time.Hour, "critical", "new", "bob", "10.0.0.2", "auth", false, true},
		{2 * time.Hour, "warning", "acknowledged", "bob", "10.0.0.2", "auth", false, false},
		{time.Hour, "", "resolved", "alice", "", "policy", true, false}, // unknown severity counts as info
	}
	for i, r := range rows {
		id := fmt.Sprintf("a%d", i)
		evID := ""
		if r.linked {
			evID = "ev" + id
			audit.events[tenant] = append(audit.events[tenant], map[string]interface{}{"id": evID, "timestamp": now.Add(-r.ago - 10*time.Minute).Format(time.RFC3339)})
		}
		if err := store.CreateAlert(ctx, Alert{ID: id, TenantID: tenant, AuditEventID: evID, AuditAction: "audit.x", Severity: r.sev,
			Title: "t", Status: r.status, ActorID: r.actor, SourceIP: r.ip, Service: r.svcName, DedupCount: 1}); err != nil {
			t.Fatal(err)
		}
		created := now.Add(-r.ago)
		var resolved interface{}
		if r.resolved {
			resolved = created.Add(30 * time.Minute)
		}
		if _, err := store.db.SQL().Exec(`UPDATE reporting_alerts SET created_at=$1, resolved_at=$2 WHERE tenant_id=$3 AND id=$4`, created, resolved, tenant, id); err != nil {
			t.Fatal(err)
		}
	}

	list := func(q AlertQuery) int {
		t.Helper()
		q.Limit = alertPageLimit
		items, err := store.ListAlerts(ctx, tenant, q)
		if err != nil {
			t.Fatal(err)
		}
		return len(items)
	}
	for _, c := range []struct {
		name  string
		w     AlertWindow
		total int
	}{
		{"day", AlertWindow{From: now.Add(-24 * time.Hour), To: now}, 3},
		{"month", AlertWindow{From: now.Add(-30 * 24 * time.Hour), To: now}, 3},
		{"year", AlertWindow{From: now.Add(-365 * 24 * time.Hour), To: now}, 5},
		{"uptime", AlertWindow{To: now}, 5},
	} {
		st, err := svc.AlertStats(ctx, tenant, c.w)
		if err != nil {
			t.Fatal(err)
		}
		if st["total"] != c.total {
			t.Fatalf("%s: total %v, want %d", c.name, st["total"], c.total)
		}
		from, to := st["from"].(time.Time), st["to"].(time.Time)
		win := AlertQuery{From: from, To: to}
		width := time.Duration(st["bucket_seconds"].(int64)) * time.Second
		sum := 0
		for _, p := range st["series"].([]map[string]interface{}) {
			start, n := p["start"].(time.Time), p["count"].(int)
			sum += n
			q := win
			if start.After(from) {
				q.From = start
			}
			if end := start.Add(width).Add(-time.Microsecond); end.Before(to) {
				q.To = end
			}
			if got := list(q); got != n {
				t.Fatalf("%s bucket %v: chart %d, drill-down %d", c.name, start, n, got)
			}
		}
		if sum != c.total {
			t.Fatalf("%s: series sums to %d, want %d", c.name, sum, c.total)
		}
		for sev, n := range st["by_severity"].(map[string]int) {
			q := win
			q.Severity = sev
			if got := list(q); got != n {
				t.Fatalf("%s severity %s: chart %d, drill-down %d", c.name, sev, n, got)
			}
		}
		for status, n := range st["by_status"].(map[string]int) {
			q := win
			q.Status = status
			if got := list(q); got != n {
				t.Fatalf("%s status %s: chart %d, drill-down %d", c.name, status, n, got)
			}
		}
		top, err := svc.TopSources(ctx, tenant, c.w)
		if err != nil {
			t.Fatal(err)
		}
		for field, set := range map[string]func(*AlertQuery, string){
			"actors": func(q *AlertQuery, k string) { q.ActorID = k }, "ips": func(q *AlertQuery, k string) { q.SourceIP = k },
			"services": func(q *AlertQuery, k string) { q.Service = k },
		} {
			for _, kc := range top[field].([]kv) {
				q := win
				set(&q, kc.Key)
				if got := list(q); got != kc.Count {
					t.Fatalf("%s %s %s: chart %d, drill-down %d", c.name, field, kc.Key, kc.Count, got)
				}
			}
		}
		mttr, err := svc.MTTRStats(ctx, tenant, c.w)
		if err != nil {
			t.Fatal(err)
		}
		mttd, measured, truncated, err := svc.MTTDStats(ctx, tenant, c.w)
		if err != nil || truncated {
			t.Fatalf("mttd: %v truncated=%v", err, truncated)
		}
		q := win
		q.Linked = true
		if got := list(q); got != measured {
			t.Fatalf("%s: mttd measured %d, linked drill-down %d", c.name, measured, got)
		}
		for sev, v := range mttd {
			if v < 9 || v > 11 {
				t.Fatalf("%s: mttd %s = %v minutes, want 10", c.name, sev, v)
			}
		}
		for sev, v := range mttr {
			q := win
			q.Resolved, q.Severity = true, sev
			if v < 29 || v > 31 || list(q) == 0 {
				t.Fatalf("%s: mttr %s = %v minutes over %d alerts", c.name, sev, v, list(q))
			}
		}
	}
}
