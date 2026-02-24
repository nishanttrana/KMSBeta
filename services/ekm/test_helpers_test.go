package main

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

type nopEKMPublisher struct {
	mu       sync.Mutex
	subjects []string
}

func (p *nopEKMPublisher) Publish(_ context.Context, subject string, _ []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	return nil
}

func (p *nopEKMPublisher) Count(subject string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.subjects {
		if s == subject {
			n++
		}
	}
	return n
}

type fakeEKMKeyCore struct {
	mu      sync.Mutex
	counter int
	keys    map[string]*fakeEKMKey
}

type fakeEKMKey struct {
	TenantID  string
	KeyID     string
	Algorithm string
	Version   int
	PublicKey string
}

func newFakeEKMKeyCore() *fakeEKMKeyCore {
	return &fakeEKMKeyCore{
		keys: map[string]*fakeEKMKey{},
	}
}

func (f *fakeEKMKeyCore) CreateAsymmetricKey(_ context.Context, tenantID string, _ string, algorithm string, _ map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counter++
	keyID := "tde_key_" + strconvItoa(f.counter)
	if strings.TrimSpace(algorithm) == "" {
		algorithm = DefaultTDEAlgorithm
	}
	f.keys[tenantID+":"+keyID] = &fakeEKMKey{
		TenantID:  tenantID,
		KeyID:     keyID,
		Algorithm: algorithm,
		Version:   1,
		PublicKey: "-----BEGIN PUBLIC KEY-----\nFAKE-" + keyID + "\n-----END PUBLIC KEY-----",
	}
	return keyID, nil
}

func (f *fakeEKMKeyCore) GetKey(_ context.Context, tenantID string, keyID string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[tenantID+":"+keyID]
	if !ok {
		return nil, errors.New("key not found")
	}
	return map[string]interface{}{
		"id":              k.KeyID,
		"tenant_id":       k.TenantID,
		"algorithm":       k.Algorithm,
		"current_version": k.Version,
		"public_key_pem":  k.PublicKey,
	}, nil
}

func (f *fakeEKMKeyCore) RotateKey(_ context.Context, tenantID string, keyID string, _ string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[tenantID+":"+keyID]
	if !ok {
		return nil, errors.New("key not found")
	}
	k.Version++
	return map[string]interface{}{
		"key_id":     k.KeyID,
		"version_id": "v" + strconvItoa(k.Version),
		"version":    k.Version,
	}, nil
}

func (f *fakeEKMKeyCore) DestroyKeyImmediately(_ context.Context, tenantID string, keyID string, _ string, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.keys[tenantID+":"+keyID]
	if !ok {
		return errors.New("key not found")
	}
	delete(f.keys, tenantID+":"+keyID)
	return nil
}

func (f *fakeEKMKeyCore) Wrap(_ context.Context, tenantID string, keyID string, plaintextB64 string, ivB64 string, _ string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[tenantID+":"+keyID]
	if !ok {
		return nil, errors.New("key not found")
	}
	if strings.TrimSpace(ivB64) == "" {
		ivB64 = base64.StdEncoding.EncodeToString([]byte("fake-ekm-iv-01"))
	}
	wrapped := base64.StdEncoding.EncodeToString([]byte("wrap:" + plaintextB64))
	return map[string]interface{}{
		"key_id":     keyID,
		"version":    k.Version,
		"ciphertext": wrapped,
		"iv":         ivB64,
	}, nil
}

func (f *fakeEKMKeyCore) Unwrap(_ context.Context, tenantID string, keyID string, ciphertextB64 string, _ string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[tenantID+":"+keyID]
	if !ok {
		return nil, errors.New("key not found")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ciphertextB64))
	if err != nil {
		return nil, err
	}
	value := strings.TrimPrefix(string(raw), "wrap:")
	return map[string]interface{}{
		"key_id":    keyID,
		"version":   k.Version,
		"plaintext": value,
	}, nil
}

func newEKMService(t *testing.T) (*Service, *SQLStore, *fakeEKMKeyCore, *nopEKMPublisher) {
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
	if err := createEKMSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	keycore := newFakeEKMKeyCore()
	pub := &nopEKMPublisher{}
	svc := NewService(store, keycore, pub, []byte("01234567890123456789012345678901"))
	return svc, store, keycore, pub
}

func newEKMHandler(t *testing.T) (*Handler, *Service, *fakeEKMKeyCore, *nopEKMPublisher) {
	t.Helper()
	svc, _, keycore, pub := newEKMService(t)
	return NewHandler(svc), svc, keycore, pub
}

func createEKMSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE ekm_agents (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			name TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'ekm-agent',
			db_engine TEXT NOT NULL DEFAULT 'mssql',
			host TEXT NOT NULL DEFAULT '',
			version TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'connected',
			tde_state TEXT NOT NULL DEFAULT 'unknown',
			heartbeat_interval_sec INTEGER NOT NULL DEFAULT 30,
			last_heartbeat_at TIMESTAMP,
			assigned_key_id TEXT NOT NULL DEFAULT '',
			assigned_key_version TEXT NOT NULL DEFAULT '',
			config_version INTEGER NOT NULL DEFAULT 1,
			config_version_ack INTEGER NOT NULL DEFAULT 0,
			metadata_json TEXT NOT NULL DEFAULT '{}',
			tls_client_cn TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE ekm_tde_keys (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			keycore_key_id TEXT NOT NULL,
			name TEXT NOT NULL,
			algorithm TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			current_version TEXT NOT NULL DEFAULT 'v1',
			public_key_cache TEXT NOT NULL DEFAULT '',
			public_key_format TEXT NOT NULL DEFAULT 'opaque',
			created_by TEXT NOT NULL DEFAULT 'ekm',
			auto_provisioned BOOLEAN NOT NULL DEFAULT 0,
			metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			rotated_at TIMESTAMP,
			last_accessed_at TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE ekm_databases (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			agent_id TEXT NOT NULL,
			name TEXT NOT NULL,
			engine TEXT NOT NULL DEFAULT 'mssql',
			host TEXT NOT NULL DEFAULT '',
			port INTEGER NOT NULL DEFAULT 1433,
			database_name TEXT NOT NULL DEFAULT '',
			tde_enabled BOOLEAN NOT NULL DEFAULT 0,
			tde_state TEXT NOT NULL DEFAULT 'disabled',
			key_id TEXT NOT NULL DEFAULT '',
			auto_provisioned BOOLEAN NOT NULL DEFAULT 0,
			metadata_json TEXT NOT NULL DEFAULT '{}',
			last_seen_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE ekm_key_access_log (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			key_id TEXT NOT NULL,
			agent_id TEXT NOT NULL DEFAULT '',
			database_id TEXT NOT NULL DEFAULT '',
			operation TEXT NOT NULL,
			status TEXT NOT NULL,
			error_message TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE ekm_bitlocker_clients (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			name TEXT NOT NULL,
			host TEXT NOT NULL DEFAULT '',
			os_version TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'connected',
			health TEXT NOT NULL DEFAULT 'unknown',
			protection_status TEXT NOT NULL DEFAULT 'unknown',
			encryption_percentage REAL NOT NULL DEFAULT 0,
			mount_point TEXT NOT NULL DEFAULT 'C:',
			heartbeat_interval_sec INTEGER NOT NULL DEFAULT 30,
			last_heartbeat_at TIMESTAMP,
			tpm_present BOOLEAN NOT NULL DEFAULT 0,
			tpm_ready BOOLEAN NOT NULL DEFAULT 0,
			jwt_subject TEXT NOT NULL DEFAULT '',
			tls_client_cn TEXT NOT NULL DEFAULT '',
			metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE ekm_bitlocker_jobs (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			operation TEXT NOT NULL,
			params_json TEXT NOT NULL DEFAULT '{}',
			status TEXT NOT NULL DEFAULT 'pending',
			requested_by TEXT NOT NULL DEFAULT '',
			request_id TEXT NOT NULL DEFAULT '',
			requested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			dispatched_at TIMESTAMP,
			completed_at TIMESTAMP,
			result_json TEXT NOT NULL DEFAULT '{}',
			error_message TEXT NOT NULL DEFAULT '',
			recovery_key_ref TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE ekm_bitlocker_recovery_keys (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			job_id TEXT NOT NULL DEFAULT '',
			volume_mount_point TEXT NOT NULL DEFAULT 'C:',
			protector_id TEXT NOT NULL DEFAULT '',
			key_fingerprint TEXT NOT NULL DEFAULT '',
			key_masked TEXT NOT NULL DEFAULT '',
			wrapped_dek TEXT NOT NULL,
			wrapped_dek_iv TEXT NOT NULL,
			ciphertext TEXT NOT NULL,
			data_iv TEXT NOT NULL,
			source TEXT NOT NULL DEFAULT 'agent',
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
