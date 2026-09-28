package main

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/mek"
)

// rotatingKeycore is a keycore stand-in whose system key gains a version.
type rotatingKeycore struct{ versions [][]byte }

func (k *rotatingKeycore) EnsureKey(context.Context) (string, int, error) {
	return "key_audit_pg", len(k.versions), nil
}

func (k *rotatingKeycore) Derive(_ context.Context, _ string, v int) ([]byte, int, error) {
	if v == 0 {
		v = len(k.versions)
	}
	return k.versions[v-1], v, nil
}

// Webhook credentials on real Postgres (CI integration-postgres): migration
// 006, BYTEA envelope columns, sealing a plaintext row, and pkg/mek moving
// every envelope onto a rotated keycore key version.
func TestWebhookCredentialsPostgres(t *testing.T) {
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
	db := conn.SQL()
	_, _ = db.Exec(`DELETE FROM audit_mek_state`)
	v1, _ := pkgcrypto.RandomBytes(32)
	kc := &rotatingKeycore{versions: [][]byte{v1}}
	open := func() *mek.Keyring {
		k, err := mek.Open(ctx, mek.Options{Tables: mek.Catalog["audit"], Source: kc, DB: db, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	store := NewSQLStore(conn)
	svc := &Service{store: store, creds: &credVault{}}
	k := open()
	svc.creds.set(k)

	tenant := "t-wh-pg-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	wh := Webhook{ID: newID("wh"), TenantID: tenant, Name: "pg", URL: "https://example.com/h", Format: "json", Events: []string{"*"},
		Secret: "pg-secret-0123456789", Headers: map[string]string{"DD-API-KEY": "pg-dd-key"}, Enabled: true}
	if err := svc.creds.Seal(&wh); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateWebhook(ctx, wh); err != nil {
		t.Fatal(err)
	}
	legacyID := newID("wh")
	if _, err := db.Exec(`INSERT INTO webhooks (id, tenant_id, name, url, format, events_json, secret, headers_json)
		VALUES ($1, $2, 'legacy', 'https://example.com/l', 'json', '["*"]', 'legacy-pg-secret', '{"Authorization":"Splunk legacy"}')`, legacyID, tenant); err != nil {
		t.Fatal(err)
	}
	if n, err := svc.sealLegacyWebhooks(ctx, k, func(context.Context) bool { return true }, nil); err != nil || n < 1 {
		t.Fatalf("seal legacy: %d %v", n, err)
	}
	var plain int
	_ = db.QueryRow(`SELECT COUNT(*) FROM webhooks WHERE tenant_id=$1 AND (secret <> '' OR headers_json LIKE '%legacy%' OR headers_json LIKE '%pg-dd-key%')`, tenant).Scan(&plain)
	if plain != 0 {
		t.Fatalf("%d row(s) still hold plaintext", plain)
	}

	// keycore rotates the system key: the next open re-wraps every envelope.
	v2, _ := pkgcrypto.RandomBytes(32)
	kc.versions = append(kc.versions, v2)
	k2 := open()
	if k2.Version() != 2 {
		t.Fatalf("keyring on version %d", k2.Version())
	}
	svc.creds.set(k2)
	for _, id := range []string{wh.ID, legacyID} {
		stored, err := store.GetWebhook(ctx, tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		if !pkgcrypto.EnvelopeWrappedUnder(v2, stored.Sealed) {
			t.Fatalf("%s not re-wrapped onto the rotated key", id)
		}
		if opened, err := svc.creds.Open(stored); err != nil || opened.Secret == "" {
			t.Fatalf("%s does not open after rotation: %v", id, err)
		}
	}
	if e, _ := k2.Exposures(ctx, tenant, true); len(e) != 1 || e[0].ItemID != legacyID {
		t.Fatalf("exposure %+v", e)
	}

	// 2.10.0-beta: migration 010 and the move into compliance connections on
	// Postgres. Both streams map (json → webhook); the exposed one carries
	// its register entry over and the stream rows keep no credential.
	conns := &testConns{conns: map[string]streamConnection{}}
	n, err := svc.migrateLegacyStreams(ctx, k2, conns, &streamMigrator{reported: map[string]bool{}}, func(context.Context) bool { return true }, nil)
	if err != nil || n < 2 {
		t.Fatalf("migrate streams: %d %v", n, err)
	}
	for _, id := range []string{wh.ID, legacyID} {
		got, err := store.GetWebhook(ctx, tenant, id)
		if err != nil || got.ConnectionID != "pbconn_audit_"+id || got.ConnectionType != "webhook" || got.Sealed != nil || got.URL != "" || got.Legacy {
			t.Fatalf("%s after migration: %+v %v", id, got, err)
		}
	}
	exposed := map[string]bool{}
	for _, in := range conns.imports {
		exposed[in.SourceID] = in.Exposed
	}
	if !exposed[legacyID] || exposed[wh.ID] {
		t.Fatalf("exposure carried over wrongly: %v", exposed)
	}
	if e, _ := k2.Exposures(ctx, tenant, true); len(e) != 0 {
		t.Fatalf("audit register still open after the move: %+v", e)
	}
	var creds int
	_ = db.QueryRow(`SELECT COUNT(*) FROM webhooks WHERE tenant_id=$1 AND (creds_wrapped_dek IS NOT NULL OR url <> '')`, tenant).Scan(&creds)
	if creds != 0 {
		t.Fatalf("%d stream row(s) still hold their own endpoint or credentials", creds)
	}
}
