package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Governance writes the platform FIPS mode to the file every service reads
// before any cryptography, and follows later changes.
func TestSyncPlatformFIPSModeFile(t *testing.T) {
	store := newGovernanceStore(t)
	svc := NewService(store, nil, &mockEmailSender{}, &mockCallbackExecutor{}, "http://localhost:8050")
	path := filepath.Join(t.TempDir(), "platform", "fips-mode")
	read := func() string {
		raw, _ := os.ReadFile(path)
		return strings.TrimSpace(string(raw))
	}
	waitFor := func(want string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for read() != want {
			if time.Now().After(deadline) {
				t.Fatalf("mode file = %q, want %q", read(), want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := store.SetPlatformFIPSMode(ctx, PlatformFIPSMode{Mode: "only", Reason: "t", RequestedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	go svc.SyncPlatformFIPSModeFile(ctx, path, 10*time.Millisecond)
	waitFor("only")
	if err := store.SetPlatformFIPSMode(ctx, PlatformFIPSMode{Mode: "on", Previous: "only", Reason: "t", RequestedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	waitFor("on")
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode file must be world-readable (it holds no secret): %v %v", info, err)
	}
}
