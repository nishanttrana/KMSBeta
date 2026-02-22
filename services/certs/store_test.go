package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestStoreCAAndProfileRoundTrip(t *testing.T) {
	_, store := newCertsService(t)
	ctx := context.Background()
	ca := CA{
		ID:                 "ca1",
		TenantID:           "t1",
		Name:               "root",
		CALevel:            "root",
		Algorithm:          "ECDSA-P384",
		CAType:             "classical",
		KeyBackend:         "software",
		KeyRef:             "",
		CertPEM:            "pem",
		Subject:            "CN=root",
		Status:             "active",
		SignerWrappedDEK:   []byte("w1"),
		SignerWrappedDEKIV: []byte("w2"),
		SignerCiphertext:   []byte("w3"),
		SignerDataIV:       []byte("w4"),
	}
	if err := store.CreateCA(ctx, ca); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetCA(ctx, "t1", "ca1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "root" || got.Algorithm != "ECDSA-P384" {
		t.Fatalf("unexpected ca: %+v", got)
	}
	p := CertificateProfile{
		ID:          "p1",
		TenantID:    "t1",
		Name:        "hybrid-tls",
		CertType:    "tls-server",
		Algorithm:   "ECDSA-P384+ML-DSA-65",
		CertClass:   "hybrid",
		ProfileJSON: "{}",
		IsDefault:   true,
	}
	if err := store.CreateProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	pOut, err := store.GetProfileByName(ctx, "t1", "hybrid-tls")
	if err != nil {
		t.Fatal(err)
	}
	if !pOut.IsDefault {
		t.Fatalf("expected default profile")
	}
}

func TestStoreReserveOTSAndCertificateLifecycle(t *testing.T) {
	_, store := newCertsService(t)
	ctx := context.Background()
	ca := CA{
		ID:                 "ca2",
		TenantID:           "t2",
		Name:               "xmss-root",
		CALevel:            "root",
		Algorithm:          "XMSS",
		CAType:             "pqc",
		KeyBackend:         "software",
		CertPEM:            "pem",
		Subject:            "CN=xmss",
		Status:             "active",
		OTSCurrent:         0,
		OTSMax:             1,
		OTSAlertThreshold:  1,
		SignerWrappedDEK:   []byte("w1"),
		SignerWrappedDEKIV: []byte("w2"),
		SignerCiphertext:   []byte("w3"),
		SignerDataIV:       []byte("w4"),
	}
	if err := store.CreateCA(ctx, ca); err != nil {
		t.Fatal(err)
	}
	idx, err := store.ReserveOTSIndex(ctx, "t2", "ca2")
	if err != nil {
		t.Fatal(err)
	}
	if idx != 1 {
		t.Fatalf("expected ots index=1 got %d", idx)
	}
	if _, err := store.ReserveOTSIndex(ctx, "t2", "ca2"); err == nil {
		t.Fatalf("expected ots exhaustion error")
	}
	c := Certificate{
		ID:           "c1",
		TenantID:     "t2",
		CAID:         "ca2",
		SerialNumber: "abc123",
		SubjectCN:    "host1",
		SANs:         []string{"host1"},
		CertType:     "device",
		Algorithm:    "XMSS",
		ProfileID:    "",
		Protocol:     "scep",
		CertClass:    "pqc",
		CertPEM:      "pem",
		Status:       "active",
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().UTC().Add(24 * time.Hour),
	}
	if err := store.CreateCertificate(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeCertificate(ctx, "t2", "c1", "test"); err != nil {
		t.Fatal(err)
	}
	out, err := store.GetCertificate(ctx, "t2", "c1")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "revoked" || !strings.Contains(out.RevocationReason, "test") {
		t.Fatalf("expected revoked cert, got %+v", out)
	}
	if err := store.DeleteCertificate(ctx, "t2", "c1"); err != nil {
		t.Fatalf("delete cert: %v", err)
	}
	afterDelete, err := store.GetCertificate(ctx, "t2", "c1")
	if err != nil {
		t.Fatalf("get cert after delete: %v", err)
	}
	if strings.ToLower(afterDelete.Status) != CertStatusDeleted {
		t.Fatalf("expected deleted status, got %+v", afterDelete)
	}
}

func TestStoreACMEOrder(t *testing.T) {
	_, store := newCertsService(t)
	ctx := context.Background()
	if err := store.CreateACMEAccount(ctx, AcmeAccount{
		ID:       "a1",
		TenantID: "t3",
		Email:    "ops@example.com",
		Status:   "valid",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateACMEOrder(ctx, AcmeOrder{
		ID:          "o1",
		TenantID:    "t3",
		AccountID:   "a1",
		CAID:        "ca-x",
		SubjectCN:   "svc",
		SANs:        []string{"svc"},
		ChallengeID: "ch1",
		Status:      "pending",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateACMEOrder(ctx, "t3", "o1", "ready", "csr", ""); err != nil {
		t.Fatal(err)
	}
	o, err := store.GetACMEOrder(ctx, "t3", "o1")
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != "ready" || o.CSRPem != "csr" {
		t.Fatalf("unexpected order: %+v", o)
	}
}
