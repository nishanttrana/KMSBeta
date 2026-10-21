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

func TestInvestigateCountsListTheirEvents(t *testing.T) {
	checkInvestigate(t, newAuditStore(t), "t-inv")
}

// The same on real Postgres (CI integration-postgres): source_ip is INET
// there, filtered and grouped by host(source_ip).
func TestInvestigateCountsListTheirEventsPostgres(t *testing.T) {
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
	checkInvestigate(t, NewSQLStore(conn), "t-inv-pg-"+strconv.FormatInt(time.Now().UnixNano(), 36))
}

// Every value the Investigate view shows is a count of the events the list
// returns with that value added to the same pivots, for each dimension.
func checkInvestigate(t *testing.T, s *SQLStore, tenant string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	put := func(ago time.Duration, actor, actorType, action, target, ip, ua, session, corr, result string) {
		t.Helper()
		if _, err := s.PersistEvent(ctx, AuditEvent{TenantID: tenant, Timestamp: now.Add(-ago), Service: "kms-" + strings.Split(action, ".")[1],
			Action: action, ActorID: actor, ActorType: actorType, TargetType: "key", TargetID: target, SourceIP: ip, UserAgent: ua,
			SessionID: session, CorrelationID: corr, Result: result}); err != nil {
			t.Fatal(err)
		}
	}
	// alice signs in from one address and works on two keys; one request
	// reaches keycore and hsm. mallory is refused from another address.
	put(5*time.Hour, "alice", "user", "audit.auth.login", "", "192.0.2.10", "Mozilla/5.0", "sess_a", "corr_1", "success")
	put(4*time.Hour, "alice", "user", "audit.key.create", "key_1", "192.0.2.10", "Mozilla/5.0", "sess_a", "corr_2", "success")
	put(4*time.Hour, "kms-keycore", "service", "audit.hsm.key_generated", "key_1", "", "Go-http-client/2.0", "", "corr_2", "success")
	put(3*time.Hour, "alice", "user", "audit.key.rotate", "key_2", "192.0.2.10", "Mozilla/5.0", "sess_a", "corr_3", "success")
	put(2*time.Hour, "mallory", "user", "audit.key.decrypt", "key_1", "2001:db8::66", "curl/8.7.1", "sess_m", "corr_4", "refused")
	put(time.Hour, "mallory", "user", "audit.key.decrypt", "key_2", "2001:db8::66", "curl/8.7.1", "sess_m", "corr_5", "refused")
	put(time.Minute, "alice", "user", "audit.key.http_request", "key_1", "192.0.2.10", "Mozilla/5.0", "sess_a", "corr_6", "success") // excluded

	list := func(q EventQuery) int64 {
		t.Helper()
		q.Limit, q.ExcludeHTTPRequests = 1000, true
		items, err := s.QueryEvents(ctx, tenant, q)
		if err != nil {
			t.Fatal(err)
		}
		return int64(len(items))
	}
	with := func(q EventQuery, param, value string) EventQuery {
		switch param {
		case "actor_id":
			q.ActorID = value
		case "action":
			q.Action = value
		case "target_id":
			q.TargetID = value
		case "source_ip":
			q.SourceIP = value
		case "user_agent":
			q.UserAgent = value
		case "service":
			q.Service = value
		case "result":
			q.Result = value
		case "session_id":
			q.SessionID = value
		case "correlation_id":
			q.CorrelationID = value
		default:
			t.Fatalf("no filter for dimension %q", param)
		}
		return q
	}
	check := func(name string, pivots EventQuery, total int64) Investigation {
		t.Helper()
		inv, err := s.Investigate(ctx, tenant, pivots)
		if err != nil {
			t.Fatal(err)
		}
		if inv.Total != total || list(pivots) != total {
			t.Fatalf("%s: total %d, list %d, want %d", name, inv.Total, list(pivots), total)
		}
		var series int64
		for _, p := range inv.Series {
			series += p.Count
		}
		if series != inv.Total {
			t.Fatalf("%s: series sums to %d, total %d", name, series, inv.Total)
		}
		if len(inv.Facets) != len(dimensions) {
			t.Fatalf("%s: %d facets, want one per dimension", name, len(inv.Facets))
		}
		for _, d := range dimensions {
			for _, f := range inv.Facets[d.param] {
				if f.Key == "" {
					t.Fatalf("%s: %s has an empty value, which no filter can list", name, d.param)
				}
				if got := list(with(pivots, d.param, f.Key)); got != f.Count {
					t.Fatalf("%s: %s=%s counted %d, the list has %d", name, d.param, f.Key, f.Count, got)
				}
			}
		}
		return inv
	}

	all := check("everything", EventQuery{}, 6)
	if all.Distinct["actor_id"] != 3 || all.Distinct["source_ip"] != 2 || all.Distinct["session_id"] != 2 {
		t.Fatalf("distinct %+v", all.Distinct)
	}
	if all.FirstSeen == nil || all.LastSeen == nil || !all.LastSeen.After(*all.FirstSeen) {
		t.Fatalf("first %v last %v", all.FirstSeen, all.LastSeen)
	}
	who := check("who: alice", EventQuery{ActorID: "alice"}, 3)
	if f := who.Facets["source_ip"]; len(f) != 1 || f[0].Key != "192.0.2.10" || f[0].Count != 3 {
		t.Fatalf("alice's addresses %+v", f)
	}
	where := check("from where: mallory's address", EventQuery{SourceIP: "2001:db8::66"}, 2)
	if f := where.Facets["result"]; len(f) != 1 || f[0].Key != "refused" {
		t.Fatalf("outcomes from the address %+v", f)
	}
	what := check("on what: key_1", EventQuery{TargetID: "key_1"}, 3)
	if f := what.Facets["actor_id"]; len(f) != 3 || f[0].Kind == "" {
		t.Fatalf("who touched key_1 %+v", f)
	}
	request := check("request corr_2", EventQuery{CorrelationID: "corr_2"}, 2)
	if f := request.Facets["service"]; len(f) != 2 {
		t.Fatalf("one request across services %+v", f)
	}
	check("session and window", EventQuery{SessionID: "sess_a", From: now.Add(-270 * time.Minute), To: now}, 2)
}

// GET /audit/investigate through the route kernel: a refused bad window and
// a read are each audited, and the read names the pivots investigated.
func TestInvestigateRouteIsAudited(t *testing.T) {
	s := newAuditStore(t)
	if _, err := s.PersistEvent(context.Background(), AuditEvent{TenantID: "t1", Timestamp: time.Now().UTC(), Service: "kms-keycore",
		Action: "audit.key.create", ActorID: "alice", ActorType: "user", Result: "success", SourceIP: "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	h := &Handler{store: s}
	rec := &routetest.Recorder{}
	r := h.investigateRouter(rec)
	routetest.RefusalsAudited(t, r, rec)

	call := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{UserID: "auditor", TenantID: "t1", Permissions: []string{"audit.events.read"}}))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	if w := call("/audit/investigate?tenant_id=t1&from=yesterday"); w.Code != http.StatusBadRequest {
		t.Fatalf("bad window: status %d", w.Code)
	}
	if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "bad_window" {
		t.Fatalf("bad window event %+v", ev.Event)
	}
	w := call("/audit/investigate?tenant_id=t1&source_ip=192.0.2.10")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var body struct {
		Investigation Investigation `json:"investigation"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Investigation.Total != 1 {
		t.Fatalf("investigation %+v err %v", body.Investigation, err)
	}
	ev := rec.Last(t)
	if ev.Action != "investigation_read" || ev.Event.Result != "success" || ev.Event.Details["source_ip"] != "192.0.2.10" {
		t.Fatalf("read event %s %+v", ev.Action, ev.Event)
	}
}
