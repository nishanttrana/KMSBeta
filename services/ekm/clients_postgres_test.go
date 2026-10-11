package main

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
	pkgkeyaccess "vecta-kms/pkg/keyaccess"
)

// Client enrolment and check-ins on real Postgres (CI integration-postgres):
// migration 010 (re-runnable), the single-use token under two agents
// presenting it at once, check-in history with its prune, and the purge.
// SQLite runs one statement at a time and can't show the race.
func TestClientEnrolmentPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 8, MaxIdle: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	for i := 0; i < 2; i++ {
		if err := conn.RunMigrations(ctx, "migrations"); err != nil {
			t.Fatalf("migrations (pass %d): %v", i+1, err)
		}
	}
	tenant := "t-ekmc-" + time.Now().UTC().Format("150405.000000")
	t.Cleanup(func() {
		for _, table := range []string{"ekm_agent_checkins", "ekm_agents", "ekm_tde_keys", "ekm_key_access_log", "ekm_databases"} {
			_, _ = conn.SQL().Exec(`DELETE FROM `+table+` WHERE tenant_id=$1`, tenant)
		}
	})

	pub := &nopEKMPublisher{}
	svc := NewService(NewSQLStore(conn), newFakeEKMKeyCore(), pub, []byte("01234567890123456789012345678901"))
	svc.SetKeyAccess(pkgkeyaccess.NotDeployed())
	h := NewHandler(svc)
	h.SetJWTParser(testEKMJWT)
	r := rigFor(t, h, svc, pub, tenant)

	id := r.create("PG-PROD-01")
	if c := r.view(id)["client"].(map[string]interface{}); c["registration"] != "pending" || c["last_seen_at"] != nil {
		t.Fatalf("new client: %+v", c)
	}

	// Two agents present one token at the same moment: one is registered.
	token := r.token(id)
	codes := make([]int, 2)
	var wg sync.WaitGroup
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w, _ := r.enroll(token)
			codes[i] = w.Code
		}(i)
	}
	wg.Wait()
	if !(codes[0] == http.StatusOK && codes[1] == http.StatusUnauthorized) && !(codes[1] == http.StatusOK && codes[0] == http.StatusUnauthorized) {
		t.Fatalf("one token, two agents: %v, want one 200 and one 401", codes)
	}
	var credentials int
	_ = conn.SQL().QueryRow(`SELECT COUNT(1) FROM ekm_agents WHERE tenant_id=$1 AND id=$2 AND credential_hash <> '' AND enroll_token_hash = '' AND registered_at IS NOT NULL`, tenant, id).Scan(&credentials)
	if credentials != 1 {
		t.Fatal("the client was not registered with a client key and its token cleared")
	}

	// Re-enrol for a key this test holds, then check in with it.
	_, out := r.enroll(r.token(id))
	key, _ := out["client_key"].(string)
	if key == "" {
		t.Fatalf("re-enrolment: %+v", out)
	}
	for i := 0; i < 2; i++ {
		if w := r.checkIn(id, key); w.Code != http.StatusOK {
			t.Fatalf("check-in: %d %s", w.Code, w.Body.String())
		}
	}
	detail := r.view(id)
	c := detail["client"].(map[string]interface{})
	// The source address is the last check-in's: httptest's peer, no proxy.
	if c["registration"] != "registered" || c["health"] != "healthy" || c["credential"] != "client_key" || c["source_ip"] != "192.0.2.1" || c["registered_at"] == nil {
		t.Fatalf("registered client: %+v", c)
	}
	// Two enrolments and two check-ins, oldest first.
	checkIns := detail["check_ins"].([]interface{})
	if len(checkIns) != 4 {
		t.Fatalf("check-ins: %d, want 4", len(checkIns))
	}
	for i := 1; i < len(checkIns); i++ {
		if checkIns[i-1].(map[string]interface{})["at"].(string) > checkIns[i].(map[string]interface{})["at"].(string) {
			t.Fatalf("check-ins out of order: %+v", checkIns)
		}
	}
	r.setLastSeen(id, 2*time.Hour)
	if c := r.view(id)["client"].(map[string]interface{}); c["health"] != "offline" {
		t.Fatalf("last seen two hours ago: %+v", c)
	}

	base := time.Now().UTC().Add(time.Minute)
	for i := 0; i < checkInsKept+10; i++ {
		if err := r.store.RecordClientCheckIn(ctx, ClientCheckIn{TenantID: tenant, ClientID: id, At: base.Add(time.Duration(i) * time.Second), SourceIP: "10.0.0.1", Status: AgentStatusConnected}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := r.store.ListClientCheckIns(ctx, tenant, id, 0)
	if err != nil || len(all) != checkInsKept || !all[len(all)-1].At.Equal(base.Add(time.Duration(checkInsKept+9)*time.Second)) {
		t.Fatalf("kept %d check-ins (%v), want the newest %d", len(all), err, checkInsKept)
	}

	if _, err := svc.DeleteAgent(ctx, tenant, id, "test"); err != nil {
		t.Fatal(err)
	}
	var left int
	_ = conn.SQL().QueryRow(`SELECT COUNT(1) FROM ekm_agent_checkins WHERE tenant_id=$1`, tenant).Scan(&left)
	if left != 0 {
		t.Fatalf("%d check-ins left after the client was deleted", left)
	}
}
