package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// Migration 005 on real Postgres (CI integration-postgres): targets carry a
// protocol, rows from before read as tls, ranges are stored as CIDR text,
// the summary's counts equal the filtered, paged list, a review survives
// an upsert, and a removed asset is gone.
func TestTargetsAndAssetRemovalPostgres(t *testing.T) {
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
	tenant := "t-disc-pg-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, err := conn.SQL().Exec(`INSERT INTO discovery_scan_targets (tenant_id, id, host, port) VALUES ($1, 'legacy', 'old.example.com', 443)`, tenant); err != nil {
		t.Fatal(err)
	}
	store := NewSQLStore(conn)
	svc := NewService(store, nil, nil, nil)
	if _, err := svc.AddTarget(ctx, tenant, "10.20.30.0/24", 22, "ssh", "w"); err != nil {
		t.Fatal(err)
	}
	got, err := store.ListTargets(ctx, tenant)
	if err != nil || len(got) != 2 {
		t.Fatalf("targets %+v, %v", got, err)
	}
	for _, tg := range got {
		if want := map[string]string{"old.example.com": "tls", "10.20.30.0/24": "ssh"}[tg.Host]; tg.Protocol != want {
			t.Fatalf("%s protocol %q, want %q", tg.Host, tg.Protocol, want)
		}
	}
	soon := time.Now().UTC().Add(5 * 24 * time.Hour).Format(time.RFC3339)
	for _, a := range []CryptoAsset{
		{ID: "a1", Source: "upload", AssetType: "certificate", Algorithm: "ECDSA-P256", Metadata: map[string]interface{}{"not_after": soon}},
		{ID: "a2", Source: "upload", AssetType: "private_key_material", Algorithm: "RSA-2048", Metadata: map[string]interface{}{}},
		{ID: "a3", Source: "network", AssetType: "tls_certificate", Algorithm: "RSA-1024", Metadata: map[string]interface{}{}},
	} {
		a.TenantID, a.Name, a.Status = tenant, a.ID, "active"
		if err := store.UpsertAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := svc.Summary(ctx, tenant)
	if err != nil || sum.TotalAssets != 3 || sum.Expiring30 != 1 || sum.ClassificationCounts["exposed"] != 1 || sum.SourceClassification["network"]["weak"] != 1 {
		t.Fatalf("summary %+v, %v", sum, err)
	}
	items, total, err := svc.FindAssets(ctx, tenant, 1, 1, AssetFilter{Classes: []string{"weak", "exposed"}})
	if err != nil || total != 2 || len(items) != 1 {
		t.Fatalf("paged filter: %d items, total %d, %v", len(items), total, err)
	}
	if _, err := svc.ClassifyAsset(ctx, tenant, "a1", ClassifyRequest{Status: "accepted_risk", Notes: "n"}, "alice"); err != nil {
		t.Fatal(err)
	}
	if n := svc.storeAssets(ctx, tenant, []CryptoAsset{{ID: "a1", TenantID: tenant, Source: "upload", AssetType: "certificate", Name: "a1", Algorithm: "ECDSA-P256", Status: "active", Metadata: map[string]interface{}{"not_after": soon}}}, map[string]bool{}); n != 1 {
		t.Fatalf("re-store: %d", n)
	}
	if a, _ := svc.GetAsset(ctx, tenant, "a1"); a.Metadata["review_status"] != "accepted_risk" || a.Metadata["reviewed_by"] != "alice" {
		t.Fatalf("review lost on Postgres: %+v", a.Metadata)
	}
	// Migration 006: repositories and the schedule.
	if _, err := svc.AddRepository(ctx, tenant, "https://github.com/acme/app.git", "main", "", "", "w"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddRepository(ctx, tenant, "https://github.com/acme/app", "main", "", "", "w"); !errors.Is(err, errRepoExists) {
		t.Fatalf("duplicate repository: %v", err)
	}
	if repos, err := store.ListRepositories(ctx, tenant); err != nil || len(repos) != 1 || repos[0].URL != "https://github.com/acme/app" || repos[0].Provider != "github" {
		t.Fatalf("repositories %+v, %v", repos, err)
	}
	if _, err := svc.SaveSchedule(ctx, tenant, true, 6, []string{"certs", "git"}, "alice"); err != nil {
		t.Fatal(err)
	}
	sch, err := svc.GetSchedule(ctx, tenant)
	if err != nil || !sch.Enabled || sch.IntervalHours != 6 || strings.Join(sch.Sources, ",") != "certs,git" || sch.AuthorizedBy != "alice" || time.Until(sch.NextRunAt) < 5*time.Hour {
		t.Fatalf("schedule %+v, %v", sch, err)
	}
	if due, err := store.DueSchedules(ctx, time.Now().UTC()); err != nil || containsTenant(due, tenant) {
		t.Fatalf("due before its time: %+v, %v", due, err)
	}
	if due, err := store.DueSchedules(ctx, time.Now().UTC().Add(7*time.Hour)); err != nil || !containsTenant(due, tenant) {
		t.Fatalf("not due after its interval: %+v, %v", due, err)
	}
	sch.PausedReason = "authority lost"
	if err := store.PutSchedule(ctx, sch); err != nil {
		t.Fatal(err)
	}
	if due, _ := store.DueSchedules(ctx, time.Now().UTC().Add(7*time.Hour)); containsTenant(due, tenant) {
		t.Fatal("a paused schedule is due")
	}
	// Migration 007: buckets. The same bucket under another prefix is a
	// different row; the same prefix is a duplicate.
	in := BucketInput{Provider: "s3", Name: "acme-artifacts", Prefix: "releases/", Region: "eu-west-1"}
	added, err := svc.AddBucket(ctx, tenant, in, "w")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddBucket(ctx, tenant, in, "w"); !errors.Is(err, errBucketExists) {
		t.Fatalf("duplicate bucket: %v", err)
	}
	in.Prefix = ""
	if _, err := svc.AddBucket(ctx, tenant, in, "w"); err != nil {
		t.Fatalf("same bucket, no prefix: %v", err)
	}
	if _, err := svc.AddBucket(ctx, tenant, BucketInput{Provider: "azure", Endpoint: "https://acme.blob.core.windows.net", Name: "configs"}, "w"); err != nil {
		t.Fatal(err)
	}
	bs, err := store.ListBuckets(ctx, tenant)
	if err != nil || len(bs) != 3 || bs[0].Provider != "azure" || bs[2].Prefix != "releases/" || bs[2].Region != "eu-west-1" || bs[2].Endpoint != "https://s3.eu-west-1.amazonaws.com" || bs[2].CreatedAt.IsZero() {
		t.Fatalf("buckets %+v, %v", bs, err)
	}
	if src, err := svc.Sources(ctx, tenant); err != nil || src[4].ID != "storage" || src[4].Detail["buckets"] != 3 {
		t.Fatalf("storage source %+v, %v", src, err)
	}
	if _, err := svc.RemoveBucket(ctx, tenant, added.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteBucket(ctx, tenant, added.ID); !errors.Is(err, errNotFound) {
		t.Fatalf("second bucket delete: %v", err)
	}
	if _, err := svc.RemoveAsset(ctx, tenant, "a1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAsset(ctx, tenant, "a1"); !errors.Is(err, errNotFound) {
		t.Fatalf("removed asset readable: %v", err)
	}
	if err := store.DeleteAsset(ctx, tenant, "a1"); !errors.Is(err, errNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func containsTenant(items []Schedule, tenant string) bool {
	for _, s := range items {
		if s.TenantID == tenant {
			return true
		}
	}
	return false
}
