package main

import (
	"context"
	"testing"

	"vecta-kms/pkg/mek/mektest"
)

// A CA signing key stored by an earlier release under the public dev key
// ("legacy" format) is re-wrapped under the keycore master key, still signs,
// and stays listed as exposed until the CA is deleted.
func TestUpgradeMovesCASignerOffPublicKey(t *testing.T) {
	ctx := context.Background()
	_, store := newCertsService(t)
	old := NewService(store, nopCertPublisher{}, NoopKeyCoreSigner{}, mektest.PublicDevKey("certs"), false, false)
	ca, err := old.CreateCA(ctx, CreateCARequest{TenantID: "t1", Name: "root-ca", CALevel: "root", Algorithm: "ECDSA-P384", KeyBackend: "software", Subject: "CN=Root CA,O=Vecta"})
	if err != nil {
		t.Fatal(err)
	}

	mektest.ApplySchema(t, store.db.SQL(), "certs")
	k := mektest.Open(t, store.db.SQL(), "certs", mektest.NewKeycore(t))
	svc := NewService(store, nopCertPublisher{}, NoopKeyCoreSigner{}, k.Current(), false, false)
	svc.SetKeyring(k)

	row, err := store.GetCA(ctx, "t1", ca.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.loadCASigner(row); err != nil {
		t.Fatalf("CA signer after upgrade: %v", err)
	}
	if _, err := old.loadCASigner(row); err == nil {
		t.Fatal("the public dev key still opens a CA signing key")
	}
	if open, _ := k.Exposures(ctx, "t1", true); len(open) != 1 || open[0].ItemType != "ca_signing_key" {
		t.Fatalf("exposure register: %+v", open)
	}
	if err := svc.DeleteCA(ctx, "t1", ca.ID, true); err != nil {
		t.Fatal(err)
	}
	if open, _ := k.Exposures(ctx, "t1", true); len(open) != 0 {
		t.Fatalf("still exposed after delete: %+v", open)
	}
}
