package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

func seedTrend(t *testing.T, store *SQLStore, tenant string, now time.Time) {
	t.Helper()
	for i, ago := range []time.Duration{30 * time.Minute, 90 * time.Minute, 150 * time.Minute, 300 * 24 * time.Hour} {
		if err := store.CreateRiskSnapshot(context.Background(), RiskSnapshot{TenantID: tenant, ID: "risk-" + strconv.Itoa(i),
			Risk24h: 10 * (i + 1), CapturedAt: now.Add(-ago)}); err != nil {
			t.Fatal(err)
		}
	}
}

// The risk trend over a window is the latest snapshot in each bucket.
func checkRiskTrend(t *testing.T, svc *Service, tenant string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	day, w, err := svc.RiskTrend(ctx, tenant, now.Add(-24*time.Hour), now)
	if err != nil || w != time.Hour || len(day) != 3 || day[0].ID != "risk-0" {
		t.Fatalf("day trend: %d points, width %v, err %v", len(day), w, err)
	}
	year, w, err := svc.RiskTrend(ctx, tenant, now.Add(-365*24*time.Hour), now)
	if err != nil || w != 7*24*time.Hour || len(year) != 2 || year[0].ID != "risk-0" || year[1].ID != "risk-3" {
		t.Fatalf("year trend: %+v width %v err %v", year, w, err)
	}
	uptime, _, err := svc.RiskTrend(ctx, tenant, time.Time{}, now)
	if err != nil || len(uptime) != 2 || uptime[1].ID != "risk-3" {
		t.Fatalf("uptime trend: %+v err %v", uptime, err)
	}
}

func TestRiskTrendWindows(t *testing.T) {
	h, store, rec := newPostureHandler(t, nil)
	now := time.Now().UTC()
	seedTrend(t, store, "t1", now)
	checkRiskTrend(t, h.svc, "t1", now)

	from := now.Add(-24 * time.Hour).Format(time.RFC3339)
	rr := postureCall(h, userClaims("u1", "t1"), http.MethodGet, "/posture/risk/history?tenant_id=t1&trend=true&from="+from, "")
	var body struct {
		Items         []RiskSnapshot `json:"items"`
		BucketSeconds int64          `json:"bucket_seconds"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &body) != nil || len(body.Items) != 3 || body.BucketSeconds != 3600 {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if ev := rec.Last(t); ev.Action != "risk_history_read" || ev.Event.Details["count"] != 3 {
		t.Fatalf("audited %+v", ev)
	}
	if rr := postureCall(h, userClaims("u1", "t1"), http.MethodGet, "/posture/risk/history?tenant_id=t1&trend=true&from=yesterday", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad window: status %d", rr.Code)
	}
	if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "bad_window" {
		t.Fatalf("refusal audited as %+v", ev)
	}
}

// The same on real Postgres (CI integration-postgres): TIMESTAMPTZ bounds.
func TestRiskTrendWindowsPostgres(t *testing.T) {
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
	tenant := "t-trend-pg-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	now := time.Now().UTC()
	seedTrend(t, store, tenant, now)
	checkRiskTrend(t, NewService(store, nil, nil), tenant, now)
}
