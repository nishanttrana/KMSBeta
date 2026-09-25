package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	"vecta-kms/pkg/metering"
)

func newMEKTestService(t *testing.T, mek []byte) *Service {
	t.Helper()
	svc := NewService(newStoreForTest(t), NewKeyCache(pkgcache.NewMemory(5*time.Minute), 5*time.Minute), nopPublisher{}, metering.NewMeter(0, time.Hour), mek, nil, false)
	svc.restartSelf = func() {}
	return svc
}

func clusterManagerCtx() context.Context { return serviceCtx(clusterManagerID) }

// A joining member receives the primary's master key sealed to its own
// one-time join key, and can then decrypt key material the primary created.
func TestClusterMEKTransfer(t *testing.T) {
	primaryMEK := []byte("PRIMARY-MEK-0123456789abcdef0123")
	memberMEK := []byte("MEMBER--MEK-0123456789abcdef0123")
	primary := newMEKTestService(t, primaryMEK)
	member := newMEKTestService(t, memberMEK)
	file := filepath.Join(t.TempDir(), "cluster-mek.b64")
	t.Setenv("KEYCORE_CLUSTER_MEK_FILE", file)
	restarted := make(chan struct{}, 1)
	member.restartSelf = func() { restarted <- struct{}{} }

	key, err := primary.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "shared", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	joinID, ek, err := member.CreateClusterJoinKey(clusterManagerCtx())
	if err != nil {
		t.Fatal(err)
	}
	const joinCtx = "cluster-join|tok_1|node-2"
	sealed, fp, err := primary.ExportClusterMEK(clusterManagerCtx(), ek, joinCtx, "node-2")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(sealed), primaryMEK) {
		t.Fatal("the exported value must not contain the master key")
	}
	if err := member.ImportClusterMEK(clusterManagerCtx(), joinID, sealed, joinCtx, fp, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-restarted:
	case <-time.After(3 * time.Second):
		t.Fatal("keycore must restart to run on the cluster master key")
	}
	loaded, err := loadMEK()
	if err != nil || !bytes.Equal(loaded, primaryMEK) {
		t.Fatalf("after import keycore must load the primary's master key: %v", err)
	}
	// The member, now on the primary's MEK, decrypts the primary's key material.
	ver, err := primary.GetVersion(context.Background(), "t1", key.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	onClusterMEK := newMEKTestService(t, loaded)
	if _, err := onClusterMEK.decryptMaterial(ver); err != nil {
		t.Fatalf("replicated key material must decrypt under the cluster master key: %v", err)
	}
	if _, err := member.decryptMaterial(ver); err == nil {
		t.Fatal("sanity: the member's original master key must not decrypt it")
	}
	// The join key is single-use.
	if err := member.ImportClusterMEK(clusterManagerCtx(), joinID, sealed, joinCtx, fp, false); !errors.Is(err, errClusterJoinKey) {
		t.Fatalf("a join key must not be reusable, got %v", err)
	}
}

func TestClusterMEKTransferRefusals(t *testing.T) {
	primary := newMEKTestService(t, []byte("PRIMARY-MEK-0123456789abcdef0123"))
	member := newMEKTestService(t, []byte("MEMBER--MEK-0123456789abcdef0123"))
	t.Setenv("KEYCORE_CLUSTER_MEK_FILE", filepath.Join(t.TempDir(), "cluster-mek.b64"))

	for name, ctx := range map[string]context.Context{
		"anonymous":     context.Background(),
		"other service": serviceCtx("kms-dataprotect"),
		"admin user":    contextWithAccessActor(context.Background(), AccessActor{UserID: "u1", Role: "admin", Authenticated: true}),
	} {
		if _, _, err := member.CreateClusterJoinKey(ctx); !errors.Is(err, errClusterCaller) {
			t.Fatalf("%s: join key must require the cluster-manager identity, got %v", name, err)
		}
		if _, _, err := primary.ExportClusterMEK(ctx, "AAAA", "c", "n"); !errors.Is(err, errClusterCaller) {
			t.Fatalf("%s: export must require the cluster-manager identity, got %v", name, err)
		}
	}

	joinID, ek, _ := member.CreateClusterJoinKey(clusterManagerCtx())
	sealed, fp, _ := primary.ExportClusterMEK(clusterManagerCtx(), ek, "ctx-a", "node-2")
	if err := member.ImportClusterMEK(clusterManagerCtx(), joinID, sealed, "ctx-b", fp, true); err == nil {
		t.Fatal("a sealed key must not open under a different join context")
	}

	joinID, ek, _ = member.CreateClusterJoinKey(clusterManagerCtx())
	sealed, _, _ = primary.ExportClusterMEK(clusterManagerCtx(), ek, "ctx-a", "node-2")
	if err := member.ImportClusterMEK(clusterManagerCtx(), joinID, sealed, "ctx-a", "0000000000000000", true); !errors.Is(err, errClusterMEKMismatch) {
		t.Fatalf("a fingerprint mismatch must be refused, got %v", err)
	}

	// A member that already holds keys needs explicit confirmation.
	if _, err := member.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "local", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "tester",
	}); err != nil {
		t.Fatal(err)
	}
	joinID, ek, _ = member.CreateClusterJoinKey(clusterManagerCtx())
	sealed, fp, _ = primary.ExportClusterMEK(clusterManagerCtx(), ek, "ctx-a", "node-2")
	if err := member.ImportClusterMEK(clusterManagerCtx(), joinID, sealed, "ctx-a", fp, false); !errors.Is(err, errClusterHasKeys) {
		t.Fatalf("importing over existing keys must need confirm_replace, got %v", err)
	}
}
