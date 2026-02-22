package main

import (
	"context"
	"testing"
	"time"
)

func TestStoreSessionAndOperation(t *testing.T) {
	_, store, _ := newKMIPHandler(t)
	ctx := context.Background()
	sess := newTestSession("tenant-a")
	if err := store.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordOperation(ctx, OperationRecord{
		ID:            newID("op"),
		TenantID:      "tenant-a",
		SessionID:     sess.ID,
		RequestID:     "req-1",
		Operation:     "Query",
		ObjectID:      "",
		Status:        "success",
		ErrorMessage:  "OK",
		RequestBytes:  128,
		ResponseBytes: 160,
		CreatedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CloseSession(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
}

func TestStoreObjectUpsertGetLocateDelete(t *testing.T) {
	_, store, _ := newKMIPHandler(t)
	ctx := context.Background()
	obj := ObjectMapping{
		TenantID:       "tenant-b",
		ObjectID:       "obj-1",
		KeyID:          "key-1",
		ObjectType:     "SymmetricKey",
		Name:           "db-tde-key",
		State:          "active",
		Algorithm:      "AES-256",
		AttributesJSON: `{"kcv":"abc123"}`,
	}
	if err := store.UpsertObject(ctx, obj); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetObject(ctx, "tenant-b", "obj-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != "key-1" || got.Algorithm != "AES-256" {
		t.Fatalf("unexpected object %+v", got)
	}
	items, err := store.LocateObjects(ctx, "tenant-b", LocateRequest{
		Name:       "db-tde-key",
		ObjectType: "SymmetricKey",
		State:      "active",
		Limit:      10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item got %d", len(items))
	}
	if err := store.DeleteObject(ctx, "tenant-b", "obj-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetObject(ctx, "tenant-b", "obj-1"); err == nil {
		t.Fatalf("expected not found after delete")
	}
}

func TestStoreClientProfilesAndClients(t *testing.T) {
	_, store, _ := newKMIPHandler(t)
	ctx := context.Background()

	profile := KMIPClientProfile{
		ID:                      "kpf_1",
		TenantID:                "tenant-c",
		Name:                    "default-profile",
		CAID:                    "ca_1",
		UsernameLocation:        "cn",
		SubjectFieldToModify:    "uid",
		DoNotModifySubjectDN:    false,
		CertificateDurationDays: 365,
		Role:                    "kmip-client",
		MetadataJSON:            `{"organization":"Bank Corp"}`,
	}
	if err := store.CreateClientProfile(ctx, profile); err != nil {
		t.Fatal(err)
	}
	profiles, err := store.ListClientProfiles(ctx, "tenant-c")
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].Name != profile.Name {
		t.Fatalf("unexpected profiles: %+v", profiles)
	}

	client := KMIPClient{
		ID:                    "kmipc_1",
		TenantID:              "tenant-c",
		ProfileID:             "kpf_1",
		Name:                  "edge-client-01",
		Role:                  "kmip-client",
		Status:                "active",
		EnrollmentMode:        "internal",
		RegistrationToken:     "tok_123",
		CertID:                "crt_1",
		CertSubject:           "CN=tenant-c:kmip-client",
		CertIssuer:            "CN=vecta-root",
		CertSerial:            "ABC123",
		CertFingerprintSHA256: "AABBCC",
		CertificatePEM:        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		MetadataJSON:          `{"source":"test"}`,
	}
	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	clients, err := store.ListClients(ctx, "tenant-c")
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].ID != client.ID {
		t.Fatalf("unexpected clients: %+v", clients)
	}
	found, err := store.GetClientByFingerprint(ctx, "aabbcc")
	if err != nil {
		t.Fatal(err)
	}
	if found.ID != client.ID {
		t.Fatalf("unexpected fingerprint lookup: %+v", found)
	}
}
