package main

import (
	"context"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	"vecta-kms/pkg/metering"
)

func newServiceWithStoreForTest(t *testing.T) (*Service, *SQLStore) {
	t.Helper()
	store := newStoreForTest(t)
	mek := []byte("0123456789ABCDEF0123456789ABCDEF")
	svc := NewService(store, NewKeyCache(pkgcache.NewMemory(5*time.Minute), 5*time.Minute), nopPublisher{}, metering.NewMeter(0, time.Hour), mek, nil, false)
	return svc, store
}

func TestVerifyKeyIntegrityPassesForIntactKey(t *testing.T) {
	svc, _ := newServiceWithStoreForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "intact", Algorithm: "AES-256", KeyType: "symmetric",
		Purpose: "encrypt", Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.VerifyKeyIntegrity(context.Background(), "t1", key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !res.MaterialDecrypts || !res.KCVChecked || !res.KCVMatch || !res.Verified {
		t.Fatalf("intact AES key should verify cleanly: %+v", res)
	}
}

func TestVerifyKeyIntegrityFailsOnCorruptedMaterial(t *testing.T) {
	svc, store := newServiceWithStoreForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "corrupt-me", Algorithm: "AES-256", KeyType: "symmetric",
		Purpose: "encrypt", Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Tamper the stored ciphertext of the current version. The AES-GCM auth tag
	// on the envelope must then fail to authenticate on decrypt.
	if _, err := store.db.SQL().ExecContext(context.Background(),
		`UPDATE key_versions SET encrypted_material = X'00010203040506070809' WHERE tenant_id=$1 AND key_id=$2`,
		"t1", key.ID); err != nil {
		t.Fatal(err)
	}
	res, err := svc.VerifyKeyIntegrity(context.Background(), "t1", key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.MaterialDecrypts || res.Verified {
		t.Fatalf("corrupted material must fail verification, got: %+v", res)
	}
}
