package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgcache "vecta-kms/pkg/cache"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/metering"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

var checkAdmin = &pkgauth.Claims{UserID: "tester", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}

func destructionCheck(t *testing.T, h *Handler, keyID string) (int, DestructionCheck) {
	t.Helper()
	w := callKeycore(h, http.MethodPost, "/keys/"+keyID+"/destruction-check", "", checkAdmin)
	var out struct {
		Check DestructionCheck `json:"check"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out.Check
}

func lastCheckEvent(t *testing.T, rec *routetest.Recorder) routetest.Recorded {
	t.Helper()
	ev := rec.Last(t)
	if ev.Action != "destruction_checked" {
		t.Fatalf("audited as %q, want destruction_checked", ev.Action)
	}
	return ev
}

// Before 6.5.0-beta the route answered "zeroization_verified" from the key
// cache alone, and never for a destroyed key (GetKey hides them). Now it reads
// the version rows, reports what it found and audits every answer.
func TestDestructionCheckFindsRemainingMaterial(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	key := ownedKey(t, svc)

	// A live key is refused, and the refusal is audited.
	if code, _ := destructionCheck(t, h, key.ID); code != http.StatusConflict {
		t.Fatalf("live key: %d, want 409", code)
	}
	if ev := lastCheckEvent(t, rec); ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != "key_not_destroyed" {
		t.Fatalf("live key audited as %s %+v", ev.Event.Result, ev.Event.Details)
	}

	db := svc.store.(*SQLStore).db.SQL()
	if _, err := db.ExecContext(context.Background(), `CREATE TABLE kv_saved AS SELECT * FROM key_versions WHERE key_id = $1`, key.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.DestroyKeyImmediately(adminCtx(), "t1", key.ID, "destruction check test", "tester", "", ""); err != nil {
		t.Fatal(err)
	}

	code, got := destructionCheck(t, h, key.ID)
	if code != http.StatusOK || got.Result != destructionRemoved || got.VersionRows != 0 || got.HSM != "not_configured" || got.NotCovered == "" {
		t.Fatalf("destroyed key: %d %+v", code, got)
	}
	if ev := lastCheckEvent(t, rec); ev.Event.Result != route.ResultSuccess || ev.Event.Details["result"] != destructionRemoved {
		t.Fatalf("clean check audited as %s %+v", ev.Event.Result, ev.Event.Details)
	}

	// Material left behind is reported, not waved through.
	if _, err := db.ExecContext(context.Background(), `INSERT INTO key_versions SELECT * FROM kv_saved`); err != nil {
		t.Fatal(err)
	}
	code, got = destructionCheck(t, h, key.ID)
	if code != http.StatusOK || got.Result != destructionRemains || got.VersionRows != 1 {
		t.Fatalf("leftover version row: %d %+v", code, got)
	}
	if ev := lastCheckEvent(t, rec); ev.Event.Details["result"] != destructionRemains || ev.Event.Details["severity"] != "critical" {
		t.Fatalf("leftover audited as %+v", ev.Event.Details)
	}

	// A missing key is the same 404 as before.
	if code, _ := destructionCheck(t, h, "key_does_not_exist"); code != http.StatusNotFound {
		t.Fatalf("missing key: %d", code)
	}
}

// Against a real PKCS#11 token: HSM objects that outlive the key's
// destruction are found by label, even though destroy clears the row's HSM
// labels, and an unreachable HSM makes the answer incomplete, never removed.
func TestDestructionCheckFindsHSMObjects(t *testing.T) {
	svc, _, client := newHSMService(t, "t1")
	h := NewHandler(svc)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	ctx := adminCtx()
	if _, err := svc.UpdateHSMSettings(ctx, HSMSettings{TenantID: "t1", HSMKeysEnabled: true, UpdatedBy: "tester"}); err != nil {
		t.Fatal(err)
	}
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "in-hsm", Algorithm: "AES-256", Purpose: "encrypt", Owner: "ops", HSM: true, CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}

	// Destroyed while the connector is down: the object stays on the token.
	svc.SetHSMBackend(hsm.New("https://127.0.0.1:1"))
	if err := svc.DestroyKeyImmediately(ctx, "t1", key.ID, "destroy while the HSM is unreachable", "tester", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, got := destructionCheck(t, h, key.ID); got.Result != destructionIncomplete || got.HSM != "unreachable" {
		t.Fatalf("HSM down: %+v", got)
	}

	svc.SetHSMBackend(client)
	label := hsm.KeyLabel("t1", key.ID, 1)
	_, got := destructionCheck(t, h, key.ID)
	if got.Result != destructionRemains || got.HSM != "checked" || len(got.HSMObjects) != 1 || got.HSMObjects[0] != label {
		t.Fatalf("object left on the HSM: %+v", got)
	}
	if ev := lastCheckEvent(t, rec); ev.Event.Details["hsm_objects"] != 1 || ev.Event.Details["severity"] != "critical" {
		t.Fatalf("leftover HSM object audited as %+v", ev.Event.Details)
	}

	if err := client.Destroy(context.Background(), "t1", label); err != nil {
		t.Fatal(err)
	}
	if _, got := destructionCheck(t, h, key.ID); got.Result != destructionRemoved || len(got.HSMObjects) != 0 {
		t.Fatalf("after removing the object: %+v", got)
	}
}

// The same check on real Postgres (CI integration-postgres): destroy deletes
// the version rows there, and the check reads what is actually left.
func TestDestructionCheckPostgres(t *testing.T) {
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
	tenant := "t-dc-pg-" + strings.ToLower(newID("x")[2:10])
	svc := NewService(NewSQLStore(conn), NewKeyCache(pkgcache.NewMemory(time.Minute), time.Minute), nopPublisher{},
		metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	key, err := svc.CreateKey(adminCtx(), CreateKeyRequest{TenantID: tenant, Name: "dc", Algorithm: "AES-256", Purpose: "encrypt", Owner: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CheckKeyDestruction(ctx, tenant, key.ID); !errors.Is(err, errKeyNotDestroyed) {
		t.Fatalf("live key: %v", err)
	}
	if err := svc.DestroyKeyImmediately(adminCtx(), tenant, key.ID, "destruction check on postgres", "it", "", ""); err != nil {
		t.Fatal(err)
	}
	got, err := svc.CheckKeyDestruction(ctx, tenant, key.ID)
	if err != nil || got.Result != destructionRemoved || got.VersionRows != 0 || got.Status != "deleted" {
		t.Fatalf("destroyed key: %v %+v", err, got)
	}
}
