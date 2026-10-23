package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// Edge devices on real Postgres (CI integration-postgres): migration 012
// (re-runnable), a registration token used by two devices at once, and two
// receipt batches racing for one device: only one of each wins.
func TestEdgeDevicesPostgres(t *testing.T) {
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
	tenant := "t-edge-" + time.Now().UTC().Format("150405.000000")
	t.Cleanup(func() {
		for _, table := range []string{"ekm_edge_devices", "ekm_edge_leases", "ekm_edge_receipts"} {
			_, _ = conn.SQL().Exec(`DELETE FROM `+table+` WHERE tenant_id=$1`, tenant)
		}
	})
	st := NewSQLStore(conn)
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := edgeDevice{TenantID: tenant, ID: "edge_pg", Name: "pg-device", Status: edgePending, AllowedKeyIDs: []string{"k1"}, MaxLeaseSeconds: 3600, CreatedBy: "u", CreatedAt: now}
	if err := st.CreateEdgeDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEdgeDeviceToken(ctx, tenant, d.ID, "tokhash", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var wins int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e := d
			e.CredentialHash, e.SigningPublicKey, e.KEMPublicKey, e.EnrolledAt = "cred"+string(rune('a'+i)), "pem", "kem", &now
			if ok, err := st.ConsumeEdgeDeviceToken(ctx, e, "tokhash"); err == nil && ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	got, err := st.GetEdgeDevice(ctx, tenant, d.ID)
	if wins != 1 || err != nil || got.Status != edgeActive || got.TokenHash != "" || got.EnrolledAt == nil || got.AllowedKeyIDs[0] != "k1" {
		t.Fatalf("one enrolment: wins=%d %+v %v", wins, got, err)
	}
	l := edgeLease{TenantID: tenant, ID: "lease_pg", DeviceID: d.ID, KeyID: "k1", KeyVersion: 2, WrappedDEK: "w", WrappedDEKIV: "iv", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := st.CreateEdgeLease(ctx, l); err != nil {
		t.Fatal(err)
	}
	batch := func(seq int64) []edgeReceipt {
		return []edgeReceipt{{Seq: seq, LeaseID: l.ID, Operation: "encrypt", Bytes: 1, At: now}}
	}
	wins = 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if ok, err := st.AddEdgeReceipts(ctx, tenant, d.ID, 0, batch(int64(1+i)), now); err == nil && ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if rs, _ := st.ListEdgeReceipts(ctx, tenant, d.ID, 10); wins != 1 || len(rs) != 1 {
		t.Fatalf("one batch from seq 0: wins=%d receipts=%d", wins, len(rs))
	}
	if err := st.RevokeEdgeDevice(ctx, tenant, d.ID, "u", "test", now); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetEdgeLease(ctx, tenant, l.ID); got.RevokedAt == nil {
		t.Fatal("revoking the device left its lease")
	}
	if dev, _ := st.GetEdgeDevice(ctx, tenant, d.ID); dev.CredentialHash != "" || dev.RevokedAt == nil {
		t.Fatalf("revoked: %+v", dev)
	}
}
