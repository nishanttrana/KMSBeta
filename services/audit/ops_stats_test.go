package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/route/routetest"
)

func TestOpsStatsWindows(t *testing.T) {
	checkOpsStats(t, newAuditStore(t), "t-ops")
}

// The same on real Postgres (CI integration-postgres): the details->>
// filters, TIMESTAMPTZ hour bounds and the grouped sums.
func TestOpsStatsWindowsPostgres(t *testing.T) {
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
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	checkOpsStats(t, NewSQLStore(conn), "t-ops-pg-"+strconv.FormatInt(time.Now().UnixNano(), 36))
}

// Every number on the Operation metrics charts equals the number of events
// its drill-down filter lists, for a day, a year and since uptime.
func checkOpsStats(t *testing.T, s *SQLStore, tenant string) {
	t.Helper()
	ctx := context.Background()
	walPath := filepath.Join(t.TempDir(), "audit-wal.log")
	key := []byte("0123456789abcdef0123456789abcdef")
	svc := NewService(s, AuditConfig{WALPath: walPath, WALMaxSizeMB: 8, WALHMACKey: key}, NewWALBuffer(walPath, 8, key), mockPublisher{})
	now := time.Now().UTC()
	put := func(ago time.Duration, service, op, result string, ms float64, details map[string]interface{}) {
		t.Helper()
		e := keyOpEvent(tenant, op, result, ms)
		e.Service, e.Timestamp = service, now.Add(-ago)
		for k, v := range details {
			e.Details[k] = v
		}
		if _, err := svc.ProcessEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	put(200*24*time.Hour, "keycore", "wrap", "failure", 30, nil)
	put(3*time.Hour, "keycore", "encrypt", "success", 0.2, nil)
	put(3*time.Hour, "keycore", "encrypt", "refused", 0.05, nil)
	put(2*time.Hour, "dataprotect", "tokenize", "success", 2, map[string]interface{}{"count": 5})
	// A legacy publisher's result in its details is the one counted.
	put(time.Hour, "keycore", "sign", "success", 1, map[string]interface{}{"result": "failure"})
	put(time.Hour, "keycore", "sign", "pending_approval", 1, nil) // never ran
	if _, err := svc.ProcessEvent(ctx, AuditEvent{TenantID: tenant, Service: "keycore", Action: "audit.key.encrypt", ActorID: "u1", Result: "success", Timestamp: now}); err != nil {
		t.Fatal(err) // not metered
	}

	day, err := s.OpsStats(ctx, tenant, now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if day.Total.Ops != 4 || day.Total.Errors != 2 || day.TotalValues != 8 || day.BucketSeconds != 3600 || !day.From.Equal(now.Add(-24*time.Hour).Truncate(time.Hour)) {
		t.Fatalf("day stats: %+v", day)
	}
	year, err := s.OpsStats(ctx, tenant, now.Add(-365*24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	uptime, err := s.OpsStats(ctx, tenant, time.Time{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if year.Total.Ops != 5 || uptime.Total.Ops != 5 || uptime.RecordedSince == nil || !uptime.From.Equal(*uptime.RecordedSince) {
		t.Fatalf("year %+v, uptime %+v", year.Total, uptime)
	}
	if p := year.Total.P99Ms; p == nil || *p != 50 {
		t.Fatalf("p99 over the year: %v", p)
	}

	list := func(q EventQuery) int64 {
		t.Helper()
		q.Limit = 1000
		items, err := s.QueryEvents(ctx, tenant, q)
		if err != nil {
			t.Fatal(err)
		}
		return int64(len(items))
	}
	for _, st := range []OpsStats{day, year, uptime} {
		win := EventQuery{From: st.From, To: st.To, MeteredOp: "*"}
		if got := list(win); got != st.Total.Ops {
			t.Fatalf("window: chart %d, drill-down %d", st.Total.Ops, got)
		}
		errs := win
		errs.Outcome = "error"
		if got := list(errs); got != st.Total.Errors {
			t.Fatalf("errors: chart %d, drill-down %d", st.Total.Errors, got)
		}
		var series int64
		for _, p := range st.Series {
			series += p.Ops
			q := win
			q.From = maxTime(p.Start, st.From)
			q.To = minTime(p.Start.Add(time.Duration(st.BucketSeconds)*time.Second).Add(-time.Microsecond), st.To)
			if got := list(q); got != p.Ops {
				t.Fatalf("bucket %v: chart %d, drill-down %d", p.Start, p.Ops, got)
			}
			q.Outcome = "error"
			if got := list(q); got != p.Errors {
				t.Fatalf("bucket %v errors: chart %d, drill-down %d", p.Start, p.Errors, got)
			}
		}
		if series != st.Total.Ops {
			t.Fatalf("series sums to %d, total %d", series, st.Total.Ops)
		}
		for _, g := range st.ByOp {
			q := win
			q.MeteredOp = g.Key
			if got := list(q); got != g.Ops {
				t.Fatalf("op %s: chart %d, drill-down %d", g.Key, g.Ops, got)
			}
			q.Outcome = "error"
			if got := list(q); got != g.Errors {
				t.Fatalf("op %s errors: chart %d, drill-down %d", g.Key, g.Errors, got)
			}
		}
		for _, g := range st.ByService {
			q := win
			q.Service = g.Key
			if got := list(q); got != g.Ops {
				t.Fatalf("service %s: chart %d, drill-down %d", g.Key, g.Ops, got)
			}
		}
		for _, g := range st.ByNode {
			q := win
			q.Node, q.HasNode = g.Key, true
			if got := list(q); got != g.Ops {
				t.Fatalf("node %q: chart %d, drill-down %d", g.Key, g.Ops, got)
			}
		}
	}
	if len(day.ByOp) != 3 || day.ByOp[0].Key != "encrypt" || day.ByOp[0].Errors != 1 {
		t.Fatalf("by op %+v", day.ByOp)
	}
}

func TestOpsStatsRouteAudited(t *testing.T) {
	h, svc, _, _ := newAuditHandler(t, false, false)
	if _, err := svc.ProcessEvent(context.Background(), keyOpEvent("t1", "encrypt", "success", 0.3)); err != nil {
		t.Fatal(err)
	}
	rec := &routetest.Recorder{}
	router := h.opsStatsRouter(rec)
	routetest.RefusalsAudited(t, router, rec)
	get := func(query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/ops-metrics/stats?tenant_id=t1"+query, nil)
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{UserID: "operator", TenantID: "t1", Permissions: []string{"audit.events.read"}}))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	w := get("&from=" + time.Now().Add(-24*time.Hour).UTC().Format(time.RFC3339))
	var body struct {
		Stats OpsStats `json:"stats"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Stats.Total.Ops != 1 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if ev := rec.Last(t); ev.Action != "ops_stats_read" || ev.Event.Details["total"] != int64(1) {
		t.Fatalf("audited %+v", ev)
	}
	if w := get("&from=yesterday"); w.Code != http.StatusBadRequest {
		t.Fatalf("bad window: status %d", w.Code)
	}
	if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "bad_window" {
		t.Fatalf("refusal audited as %+v", ev)
	}
}

// An outcome means nothing without metered_op, and only error or success
// are outcomes: the event list refuses the rest rather than ignoring them.
func TestEventListRefusesAnOutcomeItCannotApply(t *testing.T) {
	h, _, _, _ := newAuditHandler(t, false, false)
	for _, q := range []string{"outcome=error", "metered_op=*&outcome=refused"} {
		req := httptest.NewRequest(http.MethodGet, "/audit/events?tenant_id=t1&"+q, nil)
		req.Header.Set("X-Tenant-ID", "t1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "bad_outcome") {
			t.Fatalf("%s: status %d %s", q, w.Code, w.Body)
		}
	}
}
