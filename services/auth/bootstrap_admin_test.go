package main

import (
	"context"
	"io"
	"log"
	"testing"
)

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// adminLoginWorks reports whether username "admin" authenticates with the given
// password and whether it is currently flagged for a forced change.
func adminLoginState(t *testing.T, store Store, password string) (ok bool, mustChange bool) {
	t.Helper()
	u, err := store.GetUserByUsername(context.Background(), "root", "admin")
	if err != nil {
		t.Fatalf("read admin: %v", err)
	}
	return VerifyPassword(u.Password, password), u.MustChangePassword
}

func TestBootstrapSeedsDefaultAdminAdmin(t *testing.T) {
	store := newTestStore(t)
	bootstrapDefaultAdmin(context.Background(), store, quietLogger())

	ok, mustChange := adminLoginState(t, store, "admin")
	if !ok {
		t.Fatal("expected default admin/admin to authenticate after fresh bootstrap")
	}
	if !mustChange {
		t.Fatal("expected freshly seeded admin to require a password change")
	}
}

func TestBootstrapDoesNotClobberExistingAdminWithoutReset(t *testing.T) {
	store := newTestStore(t)
	bootstrapDefaultAdmin(context.Background(), store, quietLogger())

	// Simulate an older deployment: admin already rotated to a real password.
	u, _ := store.GetUserByUsername(context.Background(), "root", "admin")
	rotated, _ := HashPassword("RotatedStr0ng!Pass")
	if err := store.UpdateUserPassword(context.Background(), "root", u.ID, rotated, false); err != nil {
		t.Fatal(err)
	}

	// Re-running bootstrap must NOT reset the rotated password back to default.
	bootstrapDefaultAdmin(context.Background(), store, quietLogger())
	if ok, _ := adminLoginState(t, store, "admin"); ok {
		t.Fatal("bootstrap must not clobber an existing rotated admin password")
	}
	if ok, _ := adminLoginState(t, store, "RotatedStr0ng!Pass"); !ok {
		t.Fatal("rotated admin password must survive a bootstrap restart")
	}
}

func TestBootstrapResetAdminReappliesDefault(t *testing.T) {
	store := newTestStore(t)
	bootstrapDefaultAdmin(context.Background(), store, quietLogger())

	// Older deployment: rotated password, cleared must-change, disabled.
	u, _ := store.GetUserByUsername(context.Background(), "root", "admin")
	rotated, _ := HashPassword("RotatedStr0ng!Pass")
	if err := store.UpdateUserPassword(context.Background(), "root", u.ID, rotated, false); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateUserStatus(context.Background(), "root", u.ID, "disabled"); err != nil {
		t.Fatal(err)
	}

	// Operator opts into the factory reset.
	t.Setenv("AUTH_BOOTSTRAP_RESET_ADMIN", "true")
	bootstrapDefaultAdmin(context.Background(), store, quietLogger())

	ok, mustChange := adminLoginState(t, store, "admin")
	if !ok {
		t.Fatal("reset must restore admin/admin")
	}
	if !mustChange {
		t.Fatal("reset must re-arm the forced password change")
	}
	if reloaded, _ := store.GetUserByUsername(context.Background(), "root", "admin"); normalizeUserStatus(reloaded.Status) != "active" {
		t.Fatal("reset must re-activate the admin account")
	}
}
