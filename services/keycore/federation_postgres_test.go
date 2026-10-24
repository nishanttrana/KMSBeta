package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/metering"
)

// Federation storage on Postgres (CI integration-postgres): migration 038,
// the identity created once, a replica applied in one transaction (key,
// versions, state) and read back with its epoch and times.
func TestFederationStorePostgres(t *testing.T) {
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
	store := NewSQLStore(conn)
	svc := NewService(store, NewKeyCache(pkgcache.NewMemory(time.Minute), time.Minute), nopPublisher{},
		metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	tenant := "t-fed-pg-" + strings.ToLower(newID("x")[2:10])

	first, err := svc.federationIdentity(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	again, err := svc.federationIdentity(ctx, tenant)
	if err != nil || again.fingerprint != first.fingerprint {
		t.Fatalf("the identity changed: %v", err)
	}

	src, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: tenant, Name: "src", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", ExportAllowed: true, CreatedBy: "u"})
	if err != nil {
		t.Fatal(err)
	}
	vers, err := store.ListVersions(ctx, tenant, src.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := svc.decryptMaterial(vers[0])
	if err != nil {
		t.Fatal(err)
	}
	replicaID := newID("key")
	ver := KeyVersion{ID: newID("kv"), TenantID: tenant, KeyID: replicaID, Version: 1, KCV: vers[0].KCV, Status: "active"}
	if err := svc.protectMaterial(ctx, &ver, raw); err != nil {
		t.Fatal(err)
	}
	applied := time.Now().UTC().Truncate(time.Microsecond)
	key := Key{ID: replicaID, TenantID: tenant, Name: "replica", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Status: "active", CurrentVersion: 1, KCV: vers[0].KCV, IVMode: "internal", Labels: KeyLabels{"site": "b"}, CreatedBy: "federation:a"}
	st := FederationKeyState{TenantID: tenant, KeyID: replicaID, Role: fedRoleReplica, Epoch: 3, SourcePeerID: "fedp_a", PrimaryFingerprint: "fp", LastAppliedAt: &applied}
	if err := store.ApplyFederatedKey(ctx, key, true, []KeyVersion{ver}, nil, st); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetFederationKeyState(ctx, tenant, replicaID)
	if err != nil || got.Role != fedRoleReplica || got.Epoch != 3 || got.LastAppliedAt == nil || !got.LastAppliedAt.Equal(applied) {
		t.Fatalf("state: %+v %v", got, err)
	}
	// Status changes apply to existing versions; the key's metadata follows.
	key.Name, key.Status = "replica-renamed", "deactivated"
	st.Epoch = 4
	if err := store.ApplyFederatedKey(ctx, key, false, nil, map[int]string{1: "deactivated"}, st); err != nil {
		t.Fatal(err)
	}
	k, err := store.GetKey(ctx, tenant, replicaID)
	v, verr := store.GetVersion(ctx, tenant, replicaID, 1)
	if err != nil || verr != nil || k.Name != "replica-renamed" || k.Status != "deactivated" || v.Status != "deactivated" {
		t.Fatalf("after the second apply: %+v %+v %v %v", k, v, err, verr)
	}
	if again, err := svc.decryptMaterial(v); err != nil || string(again) != string(raw) {
		t.Fatalf("the replica's material: %v", err)
	}
	link := FederationLink{TenantID: tenant, ID: newID("fedl"), KeyID: src.ID, PeerID: "fedp_b", Status: linkPending, CreatedBy: "u"}
	if err := store.CreateFederationLink(ctx, link); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateFederationLink(ctx, link); err != errFederationLinkExists {
		t.Fatalf("a second link to the same peer: %v", err)
	}
	if err := store.UpdateFederationLinkSync(ctx, tenant, link.ID, linkInSync, "d", "", applied); err != nil {
		t.Fatal(err)
	}
	if l, err := store.GetFederationLink(ctx, tenant, link.ID); err != nil || l.Status != linkInSync || l.LastSyncAt == nil {
		t.Fatalf("link: %+v %v", l, err)
	}
}
