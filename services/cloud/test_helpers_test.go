package main

import (
	"context"
	"errors"
	"sync"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

type nopCloudPublisher struct {
	mu       sync.Mutex
	subjects []string
}

func (p *nopCloudPublisher) Publish(_ context.Context, subject string, _ []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	return nil
}

func (p *nopCloudPublisher) Count(subject string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	for _, s := range p.subjects {
		if s == subject {
			total++
		}
	}
	return total
}

type fakeCloudKeyCore struct {
	mu       sync.Mutex
	keys     map[string]map[string]interface{}
	versions map[string]int
}

func newFakeCloudKeyCore() *fakeCloudKeyCore {
	return &fakeCloudKeyCore{
		keys:     map[string]map[string]interface{}{},
		versions: map[string]int{},
	}
}

func (f *fakeCloudKeyCore) Seed(tenantID string, keyID string, algorithm string) {
	if algorithm == "" {
		algorithm = "AES-256"
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	scope := tenantID + ":" + keyID
	f.keys[scope] = map[string]interface{}{
		"id":        keyID,
		"tenant_id": tenantID,
		"algorithm": algorithm,
		"status":    "active",
	}
	if f.versions[scope] == 0 {
		f.versions[scope] = 1
	}
}

func (f *fakeCloudKeyCore) GetKey(_ context.Context, tenantID string, keyID string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	scope := tenantID + ":" + keyID
	k, ok := f.keys[scope]
	if !ok {
		return nil, errors.New("key not found")
	}
	out := map[string]interface{}{}
	for kk, vv := range k {
		out[kk] = vv
	}
	return out, nil
}

func (f *fakeCloudKeyCore) ExportKey(_ context.Context, tenantID string, keyID string) (map[string]interface{}, error) {
	if _, err := f.GetKey(context.Background(), tenantID, keyID); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"key_id":           keyID,
		"wrapped_material": "QUJDREVGR0g=",
		"material_iv":      "SVYxMjM0NTY3ODk=",
		"wrapped_dek":      "V1JBUFBFRA==",
	}, nil
}

func (f *fakeCloudKeyCore) RotateKey(_ context.Context, tenantID string, keyID string, _ string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	scope := tenantID + ":" + keyID
	if _, ok := f.keys[scope]; !ok {
		return nil, errors.New("key not found")
	}
	f.versions[scope]++
	return map[string]interface{}{
		"key_id":     keyID,
		"version_id": "v" + itoa(f.versions[scope]),
		"status":     "rotated",
	}, nil
}

func newCloudService(t *testing.T) (*Service, *SQLStore, *fakeCloudKeyCore, *nopCloudPublisher) {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{
		UseSQLite:  true,
		SQLitePath: ":memory:",
		MaxOpen:    1,
		MaxIdle:    1,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createCloudSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	keycore := newFakeCloudKeyCore()
	publisher := &nopCloudPublisher{}
	mek := []byte("0123456789ABCDEF0123456789ABCDEF")
	svc := NewService(store, keycore, newMockProviderRegistry(), publisher, mek)
	return svc, store, keycore, publisher
}

func newCloudHandler(t *testing.T) (*Handler, *Service, *fakeCloudKeyCore, *nopCloudPublisher) {
	t.Helper()
	svc, _, keycore, pub := newCloudService(t)
	return NewHandler(svc), svc, keycore, pub
}

func createCloudSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE cloud_accounts (
			tenant_id TEXT NOT NULL, id TEXT NOT NULL, provider TEXT NOT NULL, name TEXT NOT NULL,
			default_region TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active',
			creds_wrapped_dek BLOB NOT NULL, creds_wrapped_dek_iv BLOB NOT NULL,
			creds_ciphertext BLOB NOT NULL, creds_data_iv BLOB NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id), UNIQUE (tenant_id, provider, name)
		);`,
		`CREATE TABLE cloud_region_mappings (
			tenant_id TEXT NOT NULL, provider TEXT NOT NULL, vecta_region TEXT NOT NULL, cloud_region TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, provider, vecta_region)
		);`,
		`CREATE TABLE cloud_key_bindings (
			tenant_id TEXT NOT NULL, id TEXT NOT NULL, key_id TEXT NOT NULL, provider TEXT NOT NULL, account_id TEXT NOT NULL,
			cloud_key_id TEXT NOT NULL, cloud_key_ref TEXT NOT NULL DEFAULT '', region TEXT NOT NULL DEFAULT '',
			sync_status TEXT NOT NULL DEFAULT 'pending', last_synced_at TIMESTAMP, metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE cloud_sync_jobs (
			tenant_id TEXT NOT NULL, id TEXT NOT NULL, provider TEXT NOT NULL DEFAULT '', account_id TEXT NOT NULL DEFAULT '',
			mode TEXT NOT NULL DEFAULT 'full', status TEXT NOT NULL, summary_json TEXT NOT NULL DEFAULT '{}',
			error_message TEXT NOT NULL DEFAULT '', started_at TIMESTAMP NOT NULL, completed_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}
