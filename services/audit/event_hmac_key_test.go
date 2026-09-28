package main

import (
	"context"
	"errors"
	"testing"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/mek"
	"vecta-kms/pkg/mek/mektest"
)

// versionedKeycore is a keycore system key with several versions.
type versionedKeycore struct{ versions map[int][]byte }

func newVersionedKeycore(t *testing.T, n int) *versionedKeycore {
	kc := &versionedKeycore{versions: map[int][]byte{}}
	for v := 1; v <= n; v++ {
		k, err := pkgcrypto.RandomBytes(32)
		if err != nil {
			t.Fatal(err)
		}
		kc.versions[v] = k
	}
	return kc
}

func (k *versionedKeycore) EnsureKey(context.Context) (string, int, error) {
	return "key_system_audit", len(k.versions), nil
}

func (k *versionedKeycore) Derive(_ context.Context, _ string, v int) ([]byte, int, error) {
	if v == 0 {
		v = len(k.versions)
	}
	key, ok := k.versions[v]
	if !ok {
		return nil, 0, errors.New("no such version")
	}
	return append([]byte(nil), key...), v, nil
}

func openAuditKeyring(t *testing.T, s *SQLStore, src mek.Source) *mek.Keyring {
	t.Helper()
	k, err := mek.Open(context.Background(), mek.Options{Tables: mek.Catalog["audit"], Source: src, DB: s.db.SQL(), Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Before the master key opens events are stored unsigned; after it opens
// they are signed with a key derived from it, and a restarted service that
// derives the key again verifies them (no hmac_key_unknown).
func TestEventHMACKeyFromMasterKeySurvivesRestart(t *testing.T) {
	s := newAuditStore(t)
	mektest.ApplySchema(t, s.db.SQL(), "audit")
	ctx := context.Background()
	write := func(store *SQLStore) AuditEvent {
		ev, err := store.PersistEvent(ctx, AuditEvent{TenantID: "t1", Service: "keycore", Action: "audit.key.encrypt", ActorID: "alice", ActorType: "user", Result: "success"})
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	if ev := write(s); ev.HMACSig != "" {
		t.Fatalf("signed before the master key opened: %+v", ev)
	}
	kc := newVersionedKeycore(t, 1)
	svc := NewService(s, AuditConfig{}, nil, nil)
	if err := svc.installEventHMACKeys(ctx, openAuditKeyring(t, s, kc), kc.Derive); err != nil {
		t.Fatal(err)
	}
	signed := write(s)
	if signed.HMACSig == "" {
		t.Fatal("event not signed after the master key opened")
	}
	installed, err := s.QueryEvents(ctx, "root", EventQuery{Action: actionEventHMACInstalled, Limit: 5})
	if err != nil || len(installed) != 1 || installed[0].TargetID != signed.HMACKeyID {
		t.Fatalf("install events %+v %v", installed, err)
	}

	restarted := NewSQLStore(s.db)
	if err := NewService(restarted, AuditConfig{}, nil, nil).installEventHMACKeys(ctx, openAuditKeyring(t, restarted, kc), kc.Derive); err != nil {
		t.Fatal(err)
	}
	if ok, breaks, err := restarted.VerifyChain(ctx, "t1"); err != nil || !ok {
		t.Fatalf("after restart: %v %v", breaks, err)
	}
}

// Events signed under an earlier master-key version still verify; a version
// keycore can't derive is named in the install event.
func TestEventHMACKeyCoversEarlierMasterKeyVersions(t *testing.T) {
	ctx := context.Background()
	kc := newVersionedKeycore(t, 2)
	s := newAuditStore(t)
	mektest.ApplySchema(t, s.db.SQL(), "audit")
	v1, _, _ := kc.Derive(ctx, "", 1)
	old, err := eventHMACKey(v1)
	if err != nil {
		t.Fatal(err)
	}
	s.SetEventSigningKey(old) // as a node on version 1 signed
	if _, err := s.PersistEvent(ctx, AuditEvent{TenantID: "t1", Service: "keycore", Action: "audit.key.encrypt", ActorID: "alice", ActorType: "user", Result: "success"}); err != nil {
		t.Fatal(err)
	}

	fresh := NewSQLStore(s.db)
	if err := NewService(fresh, AuditConfig{}, nil, nil).installEventHMACKeys(ctx, openAuditKeyring(t, fresh, kc), kc.Derive); err != nil {
		t.Fatal(err)
	}
	if ok, breaks, err := fresh.VerifyChain(ctx, "t1"); err != nil || !ok {
		t.Fatalf("version-1 event after install: %v %v", breaks, err)
	}

	broken := NewSQLStore(s.db)
	failV1 := func(ctx context.Context, id string, v int) ([]byte, int, error) {
		if v == 1 {
			return nil, 0, errors.New("keycore unavailable")
		}
		return kc.Derive(ctx, id, v)
	}
	if err := NewService(broken, AuditConfig{}, nil, nil).installEventHMACKeys(ctx, openAuditKeyring(t, broken, kc), failV1); err != nil {
		t.Fatal(err)
	}
	evs, _ := broken.QueryEvents(ctx, "root", EventQuery{Action: actionEventHMACInstalled, Limit: 5})
	if len(evs) == 0 {
		t.Fatal("no install event")
	}
	un, _ := evs[0].Details["unavailable_mek_versions"].([]interface{})
	if len(un) != 1 || un[0] != float64(1) {
		t.Fatalf("unavailable versions not reported: %+v", evs[0].Details)
	}
}
