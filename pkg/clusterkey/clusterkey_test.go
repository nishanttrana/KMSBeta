package clusterkey

import (
	"errors"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

func TestTransferRoundTripAndRefusals(t *testing.T) {
	var member JoinKeys
	id, ek, err := member.Create()
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	sealed, fp, err := Seal(ek, secret, "cluster-join|tok|node-2", "audit-signing-key")
	if err != nil {
		t.Fatal(err)
	}
	// A wrong label (another secret's transfer) must not open.
	if _, err := member.Open(id, sealed, "cluster-join|tok|node-2", "certs-crwk", fp); err == nil {
		t.Fatal("a secret sealed for one label must not open under another")
	}
	// The join key is one-use, even after a failed open.
	if _, err := member.Open(id, sealed, "cluster-join|tok|node-2", "audit-signing-key", fp); !errors.Is(err, ErrJoinKey) {
		t.Fatalf("a consumed join key must be refused: %v", err)
	}

	id, ek, _ = member.Create()
	sealed, fp, _ = Seal(ek, secret, "ctx", "audit-signing-key")
	if _, err := member.Open(id, sealed, "ctx", "audit-signing-key", "0000000000000000"); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("a fingerprint mismatch must be refused: %v", err)
	}
	id, ek, _ = member.Create()
	sealed, fp, _ = Seal(ek, secret, "ctx", "audit-signing-key")
	got, err := member.Open(id, sealed, "ctx", "audit-signing-key", fp)
	if err != nil || string(got) != string(secret) {
		t.Fatalf("round trip: %q %v", got, err)
	}
}

func TestCallerIsClusterManagerOnly(t *testing.T) {
	svc := func(client string) *pkgauth.Claims {
		return &pkgauth.Claims{Role: "client-service", ClientID: client, TenantID: "root", Permissions: []string{"service.internal"}}
	}
	if err := Caller(svc(ClusterManager)); err != nil {
		t.Fatalf("cluster-manager must be accepted: %v", err)
	}
	for _, c := range []*pkgauth.Claims{nil, svc("kms-keycore"), {Role: "admin", UserID: "u", ClientID: ClusterManager, TenantID: "root"}} {
		if Caller(c) == nil {
			t.Fatalf("must refuse %+v", c)
		}
	}
}
