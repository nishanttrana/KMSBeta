package main

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

type nopKMIPPublisher struct{}

func (nopKMIPPublisher) Publish(_ context.Context, _ string, _ []byte) error { return nil }

type fakeKeyCore struct {
	mu      sync.Mutex
	keys    map[string]map[string]interface{}
	counter int
}

func newFakeKeyCore() *fakeKeyCore {
	return &fakeKeyCore{
		keys: map[string]map[string]interface{}{},
	}
}

func (f *fakeKeyCore) CreateKey(_ context.Context, tenantID string, req CreateRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counter++
	id := "key_" + itoa(f.counter)
	f.keys[tenantID+":"+id] = map[string]interface{}{
		"id":        id,
		"tenant_id": tenantID,
		"name":      defaultString(req.Name, "kmip-key"),
		"algorithm": defaultString(req.Algorithm, "AES-256"),
		"status":    "active",
	}
	return id, nil
}

func (f *fakeKeyCore) ImportKey(ctx context.Context, tenantID string, req RegisterRequest) (string, error) {
	return f.CreateKey(ctx, tenantID, CreateRequest{
		Name:      req.Name,
		Algorithm: req.Algorithm,
		KeyType:   req.KeyType,
		Purpose:   req.Purpose,
	})
}

func (f *fakeKeyCore) GetKey(_ context.Context, tenantID string, keyID string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[tenantID+":"+keyID]
	if !ok {
		return nil, errors.New("key not found")
	}
	out := map[string]interface{}{}
	for kk, vv := range k {
		out[kk] = vv
	}
	return out, nil
}

func (f *fakeKeyCore) RotateKey(_ context.Context, tenantID string, keyID string, reason string) (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[tenantID+":"+keyID]
	if !ok {
		return nil, errors.New("key not found")
	}
	k["rotation_reason"] = reason
	return map[string]interface{}{"key_id": keyID, "status": "rotated"}, nil
}

func (f *fakeKeyCore) SetKeyStatus(_ context.Context, tenantID string, keyID string, status string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[tenantID+":"+keyID]
	if !ok {
		return errors.New("key not found")
	}
	k["status"] = status
	return nil
}

func (f *fakeKeyCore) Encrypt(_ context.Context, tenantID string, keyID string, plaintextB64 string, ivB64 string, referenceID string) (map[string]interface{}, error) {
	_, err := f.GetKey(context.Background(), tenantID, keyID)
	if err != nil {
		return nil, err
	}
	cipherRaw := base64.StdEncoding.EncodeToString([]byte("enc:" + plaintextB64))
	outIV := ivB64
	if outIV == "" {
		outIV = base64.StdEncoding.EncodeToString([]byte("fake-iv-123456"))
	}
	return map[string]interface{}{
		"key_id":     keyID,
		"ciphertext": cipherRaw,
		"iv":         outIV,
		"reference":  referenceID,
	}, nil
}

func (f *fakeKeyCore) Decrypt(_ context.Context, tenantID string, keyID string, ciphertextB64 string, ivB64 string) (map[string]interface{}, error) {
	_, err := f.GetKey(context.Background(), tenantID, keyID)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, err
	}
	plain := string(decoded)
	if len(plain) >= 4 && plain[:4] == "enc:" {
		plain = plain[4:]
	}
	return map[string]interface{}{
		"key_id":    keyID,
		"plaintext": plain,
		"iv":        ivB64,
	}, nil
}

func (f *fakeKeyCore) Sign(_ context.Context, tenantID string, keyID string, dataB64 string, _ string) (map[string]interface{}, error) {
	_, err := f.GetKey(context.Background(), tenantID, keyID)
	if err != nil {
		return nil, err
	}
	sig := base64.StdEncoding.EncodeToString([]byte("sig:" + dataB64))
	return map[string]interface{}{
		"key_id":    keyID,
		"signature": sig,
	}, nil
}

func (f *fakeKeyCore) Verify(_ context.Context, tenantID string, keyID string, dataB64 string, signatureB64 string, _ string) (map[string]interface{}, error) {
	_, err := f.GetKey(context.Background(), tenantID, keyID)
	if err != nil {
		return nil, err
	}
	expected := base64.StdEncoding.EncodeToString([]byte("sig:" + dataB64))
	return map[string]interface{}{
		"key_id":   keyID,
		"verified": expected == signatureB64,
	}, nil
}

func newKMIPHandler(t *testing.T) (*Handler, *SQLStore, *fakeKeyCore) {
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
	if err := createKMIPSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	kc := newFakeKeyCore()
	return NewHandler(store, kc, nil, nopKMIPPublisher{}, false), store, kc
}

func createKMIPSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE kmip_sessions (
			id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, client_cn TEXT NOT NULL, role TEXT NOT NULL,
			remote_addr TEXT NOT NULL, tls_subject TEXT NOT NULL DEFAULT '', tls_issuer TEXT NOT NULL DEFAULT '',
			connected_at TIMESTAMP NOT NULL, disconnected_at TIMESTAMP
		);`,
		`CREATE TABLE kmip_operations (
			id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, session_id TEXT NOT NULL, request_id TEXT NOT NULL,
			operation TEXT NOT NULL, object_id TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, error_message TEXT NOT NULL DEFAULT '',
			request_bytes INTEGER NOT NULL DEFAULT 0, response_bytes INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMP NOT NULL
		);`,
		`CREATE TABLE kmip_objects (
			tenant_id TEXT NOT NULL, object_id TEXT NOT NULL, key_id TEXT NOT NULL, object_type TEXT NOT NULL, name TEXT NOT NULL,
			state TEXT NOT NULL, algorithm TEXT NOT NULL, attributes_json TEXT NOT NULL DEFAULT '{}', created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL, PRIMARY KEY (tenant_id, object_id)
		);`,
		`CREATE TABLE kmip_client_profiles (
			id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL, ca_id TEXT NOT NULL DEFAULT '',
			username_location TEXT NOT NULL DEFAULT 'cn', subject_field_to_modify TEXT NOT NULL DEFAULT 'uid',
			do_not_modify_subject_dn INTEGER NOT NULL DEFAULT 0, certificate_duration_days INTEGER NOT NULL DEFAULT 365,
			role TEXT NOT NULL DEFAULT 'kmip-client', metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL
		);`,
		`CREATE TABLE kmip_clients (
			id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, profile_id TEXT NOT NULL DEFAULT '', name TEXT NOT NULL,
			role TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', enrollment_mode TEXT NOT NULL DEFAULT 'internal',
			registration_token TEXT NOT NULL DEFAULT '', cert_id TEXT NOT NULL DEFAULT '', cert_subject TEXT NOT NULL DEFAULT '',
			cert_issuer TEXT NOT NULL DEFAULT '', cert_serial TEXT NOT NULL DEFAULT '', cert_fingerprint_sha256 TEXT NOT NULL,
			cert_not_before TIMESTAMP, cert_not_after TIMESTAMP, certificate_pem TEXT NOT NULL DEFAULT '',
			ca_bundle_pem TEXT NOT NULL DEFAULT '', metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL
		);`,
		`CREATE UNIQUE INDEX idx_kmip_client_fingerprint ON kmip_clients(cert_fingerprint_sha256);`,
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func newTestSession(tenant string) Session {
	return Session{
		ID:          newID("sess"),
		TenantID:    tenant,
		ClientCN:    tenant + ":kmip-client",
		Role:        "kmip-client",
		RemoteAddr:  "127.0.0.1:9999",
		ConnectedAt: time.Now().UTC(),
	}
}
