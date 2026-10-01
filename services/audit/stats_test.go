package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/route/routetest"
)

func TestAuditStatsWindows(t *testing.T) {
	checkAuditStats(t, newAuditStore(t), "t-stats")
}

// The same on real Postgres (CI integration-postgres): TIMESTAMPTZ window
// bounds, GROUP BY and the SUM(CASE) series.
func TestAuditStatsWindowsPostgres(t *testing.T) {
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
	checkAuditStats(t, NewSQLStore(conn), "t-stats-pg-"+strconv.FormatInt(time.Now().UnixNano(), 36))
}

// Every count on the Activity charts equals the number of events its
// drill-down filter returns, for a day, a year and since uptime.
func checkAuditStats(t *testing.T, s *SQLStore, tenant string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	put := func(ago time.Duration, service, action, actor, result string, risk int) {
		t.Helper()
		if _, err := s.PersistEvent(ctx, AuditEvent{TenantID: tenant, Timestamp: now.Add(-ago), Service: service,
			Action: action, ActorID: actor, ActorType: "user", Result: result, RiskScore: risk}); err != nil {
			t.Fatal(err)
		}
	}
	put(200*24*time.Hour, "kms-keycore", "audit.key.decrypt", "mallory", "denied", 75)
	put(200*24*time.Hour, "kms-keycore", "audit.key.decrypt", "mallory", "denied", 90)
	put(3*time.Hour, "kms-keycore", "audit.key.create", "alice", "success", 10)
	put(2*time.Hour, "kms-auth", "audit.auth.login", "alice", "success", 5)
	put(time.Hour, "kms-auth", "audit.auth.login_failed", "bob", "failure", 45)
	put(time.Minute, "kms-auth", "audit.auth.http_request", "alice", "success", 0) // excluded

	day, err := s.AuditStats(ctx, tenant, now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if day.Total != 3 || day.Actors != 2 || day.Services != 2 || day.BucketSeconds != 3600 {
		t.Fatalf("day stats: %+v", day)
	}
	year, err := s.AuditStats(ctx, tenant, now.Add(-365*24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	uptime, err := s.AuditStats(ctx, tenant, time.Time{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if year.Total != 5 || uptime.Total != 5 || uptime.From.After(now.Add(-199*24*time.Hour)) {
		t.Fatalf("year %d, uptime %d from %v", year.Total, uptime.Total, uptime.From)
	}

	list := func(q EventQuery) int64 {
		t.Helper()
		q.Limit, q.ExcludeHTTPRequests = 1000, true
		items, err := s.QueryEvents(ctx, tenant, q)
		if err != nil {
			t.Fatal(err)
		}
		return int64(len(items))
	}
	for _, st := range []AuditStats{day, year, uptime} {
		win := EventQuery{From: st.From, To: st.To}
		var series int64
		for i, p := range st.Series {
			series += p.Count
			q := win
			q.From = p.Start
			if i > 0 || p.Start.Before(st.From) {
				q.From = maxTime(p.Start, st.From)
			}
			q.To = minTime(p.Start.Add(time.Duration(st.BucketSeconds)*time.Second).Add(-time.Microsecond), st.To)
			if got := list(q); got != p.Count {
				t.Fatalf("bucket %v: chart %d, drill-down %d", p.Start, p.Count, got)
			}
		}
		if series != st.Total {
			t.Fatalf("series sums to %d, total %d", series, st.Total)
		}
		for _, r := range st.ByResult {
			q := win
			q.Result = r.Key
			if got := list(q); got != r.Count {
				t.Fatalf("result %s: chart %d, drill-down %d", r.Key, r.Count, got)
			}
		}
		for _, sv := range st.TopServices {
			q := win
			q.Service = sv.Key
			if got := list(q); got != sv.Count {
				t.Fatalf("service %s: chart %d, drill-down %d", sv.Key, sv.Count, got)
			}
		}
		for _, a := range st.TopActors {
			q := win
			q.ActorID = a.Key
			if got := list(q); got != a.Count {
				t.Fatalf("actor %s: chart %d, drill-down %d", a.Key, a.Count, got)
			}
		}
		for i, rb := range st.RiskBuckets {
			q := win
			q.RiskMin, q.RiskMax = RiskRanges[i][0], RiskRanges[i][1]
			if got := list(q); got != rb.Count {
				t.Fatalf("risk %s: chart %d, drill-down %d", rb.Key, rb.Count, got)
			}
		}
	}
	if year.RiskBuckets[3].Count != 1 || year.RiskBuckets[4].Count != 1 || year.RiskBuckets[0].Count != 2 {
		t.Fatalf("risk buckets %+v", year.RiskBuckets)
	}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func TestActivityStatsRouteAudited(t *testing.T) {
	h, _, store, _ := newAuditHandler(t, false, false)
	if _, err := store.PersistEvent(context.Background(), AuditEvent{TenantID: "t1", Timestamp: time.Now().UTC(), Service: "kms-auth",
		Action: "audit.auth.login", ActorID: "alice", ActorType: "user", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	rec := &routetest.Recorder{}
	router := h.statsRouter(rec)
	get := func(query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/audit/activity/stats?tenant_id=t1"+query, nil)
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{UserID: "auditor", TenantID: "t1", Permissions: []string{"audit.events.read"}}))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	w := get("&from=" + time.Now().Add(-24*time.Hour).UTC().Format(time.RFC3339))
	var body struct {
		Stats AuditStats `json:"stats"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Stats.Total != 1 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if ev := rec.Last(t); ev.Action != "activity_stats_read" || ev.Event.Details["total"] != int64(1) {
		t.Fatalf("audited %+v", ev)
	}

	if w := get("&from=yesterday"); w.Code != http.StatusBadRequest {
		t.Fatalf("bad window: status %d", w.Code)
	}
	if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "bad_window" {
		t.Fatalf("refusal audited as %+v", ev)
	}
}

func TestActivityStatsRouteRefusalsAudited(t *testing.T) {
	h, _, _, _ := newAuditHandler(t, false, false)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.statsRouter(rec), rec)
}

// order=asc pages oldest first with a stable tiebreak, so a cursor reader
// (posture's audit sync) sees every event exactly once.
func TestQueryEventsAscending(t *testing.T) {
	s := newAuditStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		if _, err := s.PersistEvent(ctx, AuditEvent{TenantID: "t-asc", Timestamp: base.Add(time.Duration(i) * time.Minute), Service: "auth",
			Action: "audit.auth.login", ActorID: "a" + strconv.Itoa(i), ActorType: "user", Result: "success"}); err != nil {
			t.Fatal(err)
		}
	}
	var seen []string
	for off := 0; ; off += 2 {
		page, err := s.QueryEvents(ctx, "t-asc", EventQuery{From: base, Ascending: true, Limit: 2, Offset: off})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page {
			seen = append(seen, e.ActorID)
		}
		if len(page) < 2 {
			break
		}
	}
	if strings.Join(seen, ",") != "a0,a1,a2,a3,a4" {
		t.Fatalf("ascending pages: %v", seen)
	}
}
