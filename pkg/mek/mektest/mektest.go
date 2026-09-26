// Package mektest supports service tests of pkg/mek: a keycore stand-in and
// the master-key tables for services whose tests build their schema by hand.
package mektest

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/mek"
)

// Keycore is a stand-in for keycore's system key: one random version.
type Keycore struct{ key []byte }

// NewKeycore returns a stand-in holding a fresh random key.
func NewKeycore(t testing.TB) *Keycore {
	t.Helper()
	k, err := pkgcrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	return &Keycore{key: k}
}

func (k *Keycore) EnsureKey(context.Context) (string, int, error) { return "key_system_test", 1, nil }

func (k *Keycore) Derive(context.Context, string, int) ([]byte, int, error) { return k.key, 1, nil }

// ApplySchema creates the state and exposure tables for a Catalog service.
func ApplySchema(t testing.TB, db *sql.DB, service string) {
	t.Helper()
	for _, stmt := range strings.Split(mek.SchemaSQL(mek.Catalog[service]), ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("mek schema for %s: %v", service, err)
		}
	}
}

// PublicDevKey is the public key earlier releases of service fell back to.
func PublicDevKey(service string) []byte {
	return mek.Catalog[service].LegacyKeysFromEnv()[0].Key
}

// Open opens a keyring for service on db, backed by kc.
func Open(t testing.TB, db *sql.DB, service string, kc *Keycore) *mek.Keyring {
	t.Helper()
	k, err := mek.Open(context.Background(), mek.Options{Tables: mek.Catalog[service], Source: kc, DB: db, Logf: t.Logf})
	if err != nil {
		t.Fatalf("open %s keyring: %v", service, err)
	}
	return k
}
