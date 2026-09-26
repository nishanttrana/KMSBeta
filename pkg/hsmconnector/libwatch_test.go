package hsmconnector

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgcrypto "vecta-kms/pkg/crypto"
)

type libEvents struct {
	mu     sync.Mutex
	events []struct {
		action string
		evt    pkgaudit.Event
	}
}

func (l *libEvents) Emit(_ context.Context, action string, evt pkgaudit.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, struct {
		action string
		evt    pkgaudit.Event
	}{action, evt})
	return nil
}

func (l *libEvents) take() map[string]pkgaudit.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]pkgaudit.Event{}
	for _, e := range l.events {
		out[e.action] = e.evt
	}
	l.events = nil
	return out
}

// Every library that lands in, changes in or leaves the provider workspace
// is audited with its SHA-256 and tenant, starting from an inventory.
func TestLibraryWatcherAuditsUploads(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir()) // roots are resolved paths
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HSM_LIBRARY_ROOTS", root)
	dir := filepath.Join(root, "acme", "provider")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(dir, "libvendor.so")
	if err := os.WriteFile(existing, []byte("first build"), 0o640); err != nil {
		t.Fatal(err)
	}
	em := &libEvents{}
	w := &libraryWatcher{roots: libraryRoots(), emit: em, logf: t.Logf}
	ctx := context.Background()

	w.scan(ctx)
	got := em.take()
	inv, ok := got["provider_library_inventory"]
	if !ok || inv.TenantID != "acme" || inv.Details["file_count"] != 1 {
		t.Fatalf("start must audit an inventory: %+v", got)
	}

	added := filepath.Join(dir, "libnew.so")
	if err := os.WriteFile(added, []byte("uploaded over sftp"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existing, []byte("second build, different"), 0o640); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(existing, later, later)
	w.scan(ctx)
	got = em.take()
	want := hex.EncodeToString(pkgcrypto.SHA256([]byte("uploaded over sftp")))
	if ev, ok := got["provider_library_added"]; !ok || ev.TargetID != added || ev.Details["sha256"] != want || ev.TenantID != "acme" {
		t.Fatalf("an upload must be audited with its hash: %+v", got)
	}
	if ev, ok := got["provider_library_changed"]; !ok || ev.TargetID != existing || ev.Details["previous_sha256"] == ev.Details["sha256"] {
		t.Fatalf("a replaced library must be audited: %+v", got)
	}

	if err := os.Remove(added); err != nil {
		t.Fatal(err)
	}
	w.scan(ctx)
	if ev, ok := em.take()["provider_library_removed"]; !ok || ev.TargetID != added {
		t.Fatal("a removed library must be audited")
	}
	w.scan(ctx)
	if got := em.take(); len(got) != 0 {
		t.Fatalf("nothing changed, nothing audited: %+v", got)
	}
}
