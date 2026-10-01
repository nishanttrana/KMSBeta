package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// Every subject and prefix the signal catalogue counts is emitted somewhere
// in the platform. A signal whose subject nothing emits would sit at zero
// forever and still be shown as monitored.
func TestSignalSubjectsAreEmitted(t *testing.T) {
	var src strings.Builder
	for _, root := range []string{"../../services", "../../pkg"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
				strings.Contains(path, "services/posture/") {
				return err
			}
			b, err := os.ReadFile(path)
			src.Write(b)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	code := src.String()
	for _, subject := range signalCatalogueSubjects() {
		if !strings.Contains(code, `"`+subject+`"`) {
			t.Errorf("signal subject %s is not emitted by any service", subject)
		}
	}
	for _, prefix := range signalCataloguePrefixes() {
		if !strings.Contains(code, `"`+prefix) {
			t.Errorf("no service emits a subject starting with %s", prefix)
		}
	}
}

func trailEvent(id, service, action, result string, ts time.Time) map[string]interface{} {
	return map[string]interface{}{"id": id, "service": service, "action": action, "result": result, "tenant_id": "t1",
		"timestamp": ts.UTC().Format(time.RFC3339Nano)}
}

// midday is 12:00 UTC, the given number of days before today.
func midday(daysAgo int) time.Time {
	return time.Now().UTC().Truncate(24 * time.Hour).Add(-time.Duration(daysAgo)*24*time.Hour + 12*time.Hour)
}

// The summary counts the subjects services really publish. Most arrive with
// the default result "success" (login_failed included), so matching on the
// result, as the old patterns did, counted none of them.
func checkSignalSummary(t *testing.T, store *SQLStore, tenant string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	ev := func(id, service, action, result, code string, latency float64) NormalizedEvent {
		return NormalizedEvent{ID: tenant + id, TenantID: tenant, Timestamp: now.Add(-time.Hour), Service: service, Action: action,
			Result: result, Severity: "info", ErrorCode: code, LatencyMS: latency}
	}
	if _, err := store.IngestEvents(ctx, []NormalizedEvent{
		ev("1", "auth", "audit.auth.login_failed", "success", "", 0),
		ev("2", "auth", "audit.auth.mfa_failed", "success", "", 0),
		ev("3", "auth", "audit.auth.login", "success", "", 0),
		ev("4", "keycore", "audit.key.destroyed", "success", "", 0),
		ev("5", "certs", "audit.cert.deleted", "success", "", 0),
		ev("6", "keycore", "audit.key.access_refused", "refused", "permission_denied", 0),
		ev("6b", "dataprotect", "audit.dataprotect.tokenize_refused", "success", "", 0),
		ev("7", "governance", "audit.governance.vote_denied", "success", "", 0),
		ev("8", "reporting", "audit.reporting.alerts_listed", "refused", codeTenantMismatch, 0),
		ev("9", "cloud", "audit.cloud.sync_failed", "success", "", 0),
		ev("10", "cloud", "audit.cloud.key_synced", "success", "", 0),
		ev("11", "hsm", "audit.hsm.encrypt", "success", "", 40),
		ev("12", "hsm", "audit.hsm.encrypt", "success", "", 0), // not measured: not "instant"
		ev("13", "kmip", "audit.kmip.interop_validated", "success", codeInteropFailed, 0),
		ev("14", "certs", "audit.cert.expiring", "success", "", 0),
		ev("15", "keycore", "audit.key.fips.violation_blocked", "success", "", 0),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetSignalSummary(ctx, tenant, now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	want := SignalSummary{TotalEvents: 16, FailedAuthCount: 2, FailedCryptoCount: 2, PolicyDenyCount: 2, KeyDeleteCount: 1, CertDeleteCount: 1,
		DeniedApprovalCount: 1, TenantMismatchCount: 1, ConnectorFailures: 1, ExpiryBacklogCount: 1, NonApprovedAlgoCount: 1, HSMLatencyAvgMS: 40,
		BYOKEvents: 2, BYOKFailures: 1, KMIPEvents: 1, KMIPFailures: 1, KMIPInteropFailures: 1}
	if got != want {
		t.Fatalf("summary\n got %+v\nwant %+v", got, want)
	}
	// The window's end is exclusive, so consecutive days never share an event.
	if edge, _ := store.GetSignalSummary(ctx, tenant, now.Add(-24*time.Hour), now.Add(-time.Hour)); edge.TotalEvents != 0 {
		t.Fatalf("end bound must be exclusive: %d", edge.TotalEvents)
	}
}

func TestSignalSummaryCountsRealSubjects(t *testing.T) {
	_, store, _ := newPostureHandler(t, nil)
	checkSignalSummary(t, store, "t-sig")
}

func postgresPostureStore(t *testing.T) *SQLStore {
	t.Helper()
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
	return NewSQLStore(conn)
}

// The same on real Postgres (CI integration-postgres): LIKE ... ESCAPE,
// TIMESTAMP bounds, and migration 005.
func TestSignalSummaryCountsRealSubjectsPostgres(t *testing.T) {
	checkSignalSummary(t, postgresPostureStore(t), "t-sig-pg-"+strconv.FormatInt(time.Now().UnixNano(), 36))
}

// The sync reads every event from its cursor, across pages, exactly once.
// It used to take the newest 500 a minute and drop the rest.
func TestSyncReadsEveryEventFromCursor(t *testing.T) {
	_, store, _ := newPostureHandler(t, nil)
	ctx := context.Background()
	trail := auditTrail{}
	for i := 0; i < 2500; i++ {
		trail = append(trail, trailEvent(fmt.Sprintf("e%04d", i), "auth", "audit.auth.login", "success", midday(3).Add(time.Duration(i)*time.Second)))
	}
	svc := NewService(store, trail, nil)
	n, err := svc.SyncFromAudit(ctx, "t1", 0)
	if err != nil || n != 2500 {
		t.Fatalf("first sync: %d %v", n, err)
	}
	st, _ := store.GetSyncState(ctx, "t1")
	if !st.BaselineFrom.Equal(midday(3)) || st.SyncedThrough.IsZero() || !st.Cursor.Equal(midday(3).Add(2499*time.Second)) {
		t.Fatalf("sync state %+v", st)
	}
	if n, err := svc.SyncFromAudit(ctx, "t1", 0); err != nil || n != 0 {
		t.Fatalf("second sync re-read events as new: %d %v", n, err)
	}
	svc.audit = append(trail, trailEvent("late", "auth", "audit.auth.login_failed", "success", time.Now().UTC().Add(-time.Minute)))
	if n, err := svc.SyncFromAudit(ctx, "t1", 0); err != nil || n != 1 {
		t.Fatalf("third sync: %d %v", n, err)
	}
	sum, _ := store.GetSignalSummary(ctx, "t1", midday(4), time.Now().UTC())
	if sum.TotalEvents != 2501 || sum.FailedAuthCount != 1 {
		t.Fatalf("posture holds %d events, %d failed logins", sum.TotalEvents, sum.FailedAuthCount)
	}
}

// history builds a tenant's audit trail: perDay events of each kind on each
// of the last `days` days, and today's as given.
func history(days, loginsPerDay, failedPerDay, loginsToday, failedToday int) auditTrail {
	trail := auditTrail{}
	add := func(prefix, action string, n int, at time.Time) {
		for i := 0; i < n; i++ {
			trail = append(trail, trailEvent(fmt.Sprintf("%s-%d-%d", prefix, at.Unix(), i), "auth", action, "success", at.Add(time.Duration(i)*time.Second)))
		}
	}
	for d := days; d >= 1; d-- {
		add("ok", "audit.auth.login", loginsPerDay, midday(d))
		add("bad", "audit.auth.login_failed", failedPerDay, midday(d))
	}
	recent := time.Now().UTC().Add(-30 * time.Minute)
	add("ok-today", "audit.auth.login", loginsToday, recent)
	add("bad-today", "audit.auth.login_failed", failedToday, recent)
	return trail
}

func findingTypes(t *testing.T, store *SQLStore, tenant string) map[string]bool {
	t.Helper()
	items, err := store.ListFindings(context.Background(), tenant, FindingQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, f := range items {
		out[f.FindingType] = true
	}
	return out
}

// Before MinBaselineDays there is no risk score and no spike finding,
// whatever today's count: with 5 days of history, 500 failed logins have
// nothing to be unusual against.
func TestScanNotAssessedWhileBaselineBuilds(t *testing.T) {
	_, store, _ := newPostureHandler(t, nil)
	bus := &recordedPublish{}
	svc := NewService(store, history(5, 20, 2, 20, 500), bus)
	snap, err := svc.RunScanTenant(context.Background(), "t1", true)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Assessed || snap.Risk24h != 0 || snap.Risk7d != 0 || snap.BaselineDays >= MinBaselineDays {
		t.Fatalf("scored without a baseline: %+v", snap)
	}
	if findingTypes(t, store, "t1")["auth_failure_spike"] {
		t.Fatal("spike finding raised without a baseline")
	}
	if bus.count("audit.posture.baseline_ready") != 0 {
		t.Fatalf("baseline_ready emitted while building: %v", bus.subjects)
	}
	st, err := svc.BaselineStatus(context.Background(), "t1")
	if err != nil || st.Ready || st.Days != snap.BaselineDays || st.RequiredDays != MinBaselineDays {
		t.Fatalf("status %+v %v", st, err)
	}
	for _, sig := range st.Signals {
		if sig.Status != "building" || sig.Unusual {
			t.Fatalf("signal %s judged while building: %+v", sig.Key, sig)
		}
	}
}

// With 20 days of history the score is assessed, a real spike is found
// against the tenant's own normal, and baseline_ready is audited once.
func checkAssessedScan(t *testing.T, store *SQLStore) {
	t.Helper()
	ctx := context.Background()
	bus := &recordedPublish{}
	svc := NewService(store, history(20, 20, 30, 20, 300), bus)
	snap, err := svc.RunScanTenant(ctx, "t1", true)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Assessed || snap.BaselineDays < MinBaselineDays || snap.Risk24h <= 0 {
		t.Fatalf("snapshot %+v", snap)
	}
	if !findingTypes(t, store, "t1")["auth_failure_spike"] {
		t.Fatal("300 failed logins against 30 a day was not found")
	}
	if _, err := svc.RunScanTenant(ctx, "t1", true); err != nil {
		t.Fatal(err)
	}
	if bus.count("audit.posture.baseline_ready") != 1 {
		t.Fatalf("baseline_ready must be audited once: %v", bus.subjects)
	}
	latest, err := store.GetLatestRiskSnapshot(ctx, "t1")
	if err != nil || !latest.Assessed || latest.BaselineDays != snap.BaselineDays {
		t.Fatalf("stored snapshot %+v %v", latest, err)
	}
	st, _ := svc.BaselineStatus(ctx, "t1")
	var auth BaselineSignal
	for _, sig := range st.Signals {
		if sig.Key == "failed_auth" {
			auth = sig
		}
	}
	if !st.Ready || auth.Status != "ready" || !auth.Unusual || auth.DailyMean != 30 || auth.Current24h < 300 {
		t.Fatalf("status %+v auth %+v", st, auth)
	}
}

func TestScanAssessedOnceBaselineReady(t *testing.T) {
	_, store, _ := newPostureHandler(t, nil)
	checkAssessedScan(t, store)
}

// A busy, healthy tenant scores zero: activity volume is not risk. The old
// score fell back to events/200 and added the week's growth in events.
func TestBusyHealthyTenantScoresZero(t *testing.T) {
	_, store, _ := newPostureHandler(t, nil)
	svc := NewService(store, history(16, 400, 3, 900, 3), nil)
	snap, err := svc.RunScanTenant(context.Background(), "t1", true)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Assessed || snap.Risk24h != 0 || snap.Risk7d != 0 {
		t.Fatalf("volume scored as risk: %+v", snap)
	}
	if got := findingTypes(t, store, "t1"); len(got) != 0 {
		t.Fatalf("findings on a healthy tenant: %v", got)
	}
}

// GET /posture/baseline is audited, and the cross-tenant snapshot averages
// only assessed tenants.
func TestBaselineRouteAndGlobalRisk(t *testing.T) {
	h, _, rec := newPostureHandler(t, nil)
	rr := postureCall(h, userClaims("u1", "t1"), http.MethodGet, "/posture/baseline?tenant_id=t1", "")
	var body struct {
		Baseline BaselineStatus `json:"baseline"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &body) != nil || body.Baseline.Ready ||
		body.Baseline.RequiredDays != MinBaselineDays || len(body.Baseline.Signals) != len(countSignals)+len(rateSignals) {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if ev := rec.Last(t); ev.Action != "baseline_read" || ev.Event.Details["ready"] != false {
		t.Fatalf("audited %+v", ev)
	}

	global := aggregateGlobalRisk([]RiskSnapshot{{TenantID: "a", Risk24h: 40, Assessed: true}, {TenantID: "b", Risk24h: 0}})
	if !global.Assessed || global.Risk24h != 40 || global.TopSignals["tenants_baseline_pending"] != 1 {
		t.Fatalf("global risk %+v", global)
	}
	if none := aggregateGlobalRisk([]RiskSnapshot{{TenantID: "b"}}); none.Assessed {
		t.Fatalf("no assessed tenant, but the global score is assessed: %+v", none)
	}
}

// The gate and the spike test on real Postgres (CI integration-postgres).
func TestScanAssessedOnceBaselineReadyPostgres(t *testing.T) {
	store := postgresPostureStore(t)
	for _, table := range []string{"posture_events_hot", "posture_events_history", "posture_findings", "posture_risk_snapshots", "posture_signal_daily", "posture_engine_state", "posture_actions"} {
		if _, err := store.db.SQL().Exec(`DELETE FROM ` + table + ` WHERE tenant_id = 't1'`); err != nil {
			t.Fatal(err)
		}
	}
	checkAssessedScan(t, store)
}
