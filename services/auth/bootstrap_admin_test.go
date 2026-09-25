package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log"
	"strings"
	"testing"

	"vecta-kms/pkg/servicetoken"
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

func TestBootstrapSeedsDefaultAdminChangeit(t *testing.T) {
	store := newTestStore(t)
	bootstrapDefaultAdmin(context.Background(), store, quietLogger())

	ok, mustChange := adminLoginState(t, store, "changeit")
	if !ok {
		t.Fatal("expected default admin/changeit to authenticate after fresh bootstrap")
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
	if ok, _ := adminLoginState(t, store, "changeit"); ok {
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

	ok, mustChange := adminLoginState(t, store, "changeit")
	if !ok {
		t.Fatal("reset must restore admin/changeit")
	}
	if !mustChange {
		t.Fatal("reset must re-arm the forced password change")
	}
	if reloaded, _ := store.GetUserByUsername(context.Background(), "root", "admin"); normalizeUserStatus(reloaded.Status) != "active" {
		t.Fatal("reset must re-activate the admin account")
	}
}

func TestBootstrapRevokesKeysDerivedFromPublicDefaultSecret(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	bootstrapDefaultAdmin(ctx, store, quietLogger())

	// Simulate an older deployment seeded from the public default secret.
	sum := sha256.Sum256([]byte(servicetoken.InsecureDefaultAPIKey("kms-keycore")))
	if err := store.CreateAPIKey(ctx, APIKey{
		ID: "akey_legacy", TenantID: "root", ClientID: "kms-keycore", KeyHash: sum[:],
		Name: "kms-keycore service identity", Permissions: []string{"service.internal"},
	}); err != nil {
		t.Fatal(err)
	}

	t.Setenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET", strings.Repeat("ef", 32))
	bootstrapInternalServiceClients(ctx, store, quietLogger())

	if _, err := store.GetAPIKeyByHash(ctx, "root", sum[:]); !errors.Is(err, errNotFound) {
		t.Fatalf("legacy default-derived key must be revoked, got err=%v", err)
	}
	fresh := sha256.Sum256([]byte(servicetoken.DeriveAPIKey(strings.Repeat("ef", 32), "kms-keycore")))
	if _, err := store.GetAPIKeyByHash(ctx, "root", fresh[:]); err != nil {
		t.Fatalf("key derived from the configured secret must be provisioned: %v", err)
	}
}

func TestBootstrapRetiresServiceKeysFromRotatedSecret(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	bootstrapDefaultAdmin(ctx, store, quietLogger())

	oldSecret, newSecret := strings.Repeat("01", 32), strings.Repeat("23", 32)
	t.Setenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET", oldSecret)
	bootstrapInternalServiceClients(ctx, store, quietLogger())
	oldSum := sha256.Sum256([]byte(servicetoken.DeriveAPIKey(oldSecret, "kms-keycore")))
	if _, err := store.GetAPIKeyByHash(ctx, "root", oldSum[:]); err != nil {
		t.Fatalf("old key must exist before rotation: %v", err)
	}

	t.Setenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET", newSecret)
	bootstrapInternalServiceClients(ctx, store, quietLogger())

	if _, err := store.GetAPIKeyByHash(ctx, "root", oldSum[:]); !errors.Is(err, errNotFound) {
		t.Fatalf("key from the rotated-out secret must be retired, got err=%v", err)
	}
	newSum := sha256.Sum256([]byte(servicetoken.DeriveAPIKey(newSecret, "kms-keycore")))
	if _, err := store.GetAPIKeyByHash(ctx, "root", newSum[:]); err != nil {
		t.Fatalf("key from the current secret must exist: %v", err)
	}

	// Idempotent: a restart with the same secret keeps the current key.
	bootstrapInternalServiceClients(ctx, store, quietLogger())
	if _, err := store.GetAPIKeyByHash(ctx, "root", newSum[:]); err != nil {
		t.Fatalf("restart must keep the current key: %v", err)
	}
}
