package main

import (
	"context"
	"sync"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

type nopPQCPublisher struct {
	mu       sync.Mutex
	subjects []string
}

func (p *nopPQCPublisher) Publish(_ context.Context, subject string, _ []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	return nil
}

func (p *nopPQCPublisher) Count(subject string) int {
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

type fakePQCKeyCore struct {
	mu            sync.Mutex
	rotateCalls   []string
	failRotateFor map[string]bool
}

func (f *fakePQCKeyCore) ListKeys(_ context.Context, _ string, _ int) ([]map[string]interface{}, error) {
	return []map[string]interface{}{
		{"id": "k1", "name": "legacy-rsa", "algorithm": "RSA-2048", "status": "active"},
		{"id": "k2", "name": "hybrid-kem", "algorithm": "ML-KEM-768-HYBRID", "status": "active"},
		{"id": "k3", "name": "pqc-sign", "algorithm": "ML-DSA-65", "status": "active"},
	}, nil
}

func (f *fakePQCKeyCore) RotateKey(_ context.Context, _ string, keyID string, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRotateFor != nil && f.failRotateFor[keyID] {
		return newServiceError(500, "rotate_failed", "rotation failed")
	}
	f.rotateCalls = append(f.rotateCalls, keyID)
	return nil
}

func (f *fakePQCKeyCore) ListInterfacePorts(_ context.Context, _ string) ([]map[string]interface{}, error) {
	return []map[string]interface{}{
		{"interface_name": "rest", "description": "REST API", "bind_address": "0.0.0.0", "port": 443, "protocol": "https", "pqc_mode": "inherit", "certificate_source": "internal_ca", "enabled": true},
		{"interface_name": "kmip", "description": "KMIP", "bind_address": "0.0.0.0", "port": 5696, "protocol": "mtls", "pqc_mode": "hybrid", "certificate_source": "internal_ca", "enabled": true},
		{"interface_name": "dashboard-ui", "description": "Dashboard", "bind_address": "0.0.0.0", "port": 5173, "protocol": "http", "pqc_mode": "classical", "certificate_source": "none", "enabled": true},
	}, nil
}

type fakePQCDiscovery struct{}

func (f *fakePQCDiscovery) ListCryptoAssets(_ context.Context, _ string, _ int) ([]map[string]interface{}, error) {
	return []map[string]interface{}{
		{"id": "a1", "asset_type": "tls_endpoint", "name": "api.vecta.local", "source": "network", "algorithm": "RSA-2048", "classification": "weak", "qsl_score": 50, "status": "active"},
		{"id": "a2", "asset_type": "certificate", "name": "pqc.vecta.local", "source": "certs", "algorithm": "ML-DSA-65", "classification": "strong", "qsl_score": 100, "status": "active"},
		{"id": "a3", "asset_type": "kms_key", "name": "aws/kms/key1", "source": "cloud", "algorithm": "RSA-3072", "classification": "weak", "qsl_score": 78, "status": "active"},
	}, nil
}

type fakePQCCerts struct{}

func (f *fakePQCCerts) ListCertificates(_ context.Context, _ string, _ int) ([]map[string]interface{}, error) {
	return []map[string]interface{}{
		{"id": "c1", "subject_cn": "api.vecta.local", "algorithm": "RSA-3072", "cert_class": "classical", "status": "active"},
		{"id": "c2", "subject_cn": "hybrid.vecta.local", "algorithm": "ECDSA-P384 + ML-DSA-65", "cert_class": "hybrid", "status": "active"},
		{"id": "c3", "subject_cn": "pqc.vecta.local", "algorithm": "ML-DSA-65", "cert_class": "pqc", "status": "active"},
	}, nil
}

func newPQCService(t *testing.T) (*Service, *SQLStore, *nopPQCPublisher, *fakePQCKeyCore) {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{UseSQLite: true, SQLitePath: ":memory:", MaxOpen: 1, MaxIdle: 1})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createPQCSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	pub := &nopPQCPublisher{}
	keycore := &fakePQCKeyCore{}
	svc := NewService(store, keycore, &fakePQCCerts{}, &fakePQCDiscovery{}, pub)
	return svc, store, pub, keycore
}

func newPQCHandler(t *testing.T) (*Handler, *Service, *nopPQCPublisher) {
	t.Helper()
	svc, _, pub, _ := newPQCService(t)
	return NewHandler(svc), svc, pub
}

func createPQCSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE pqc_readiness_scans (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			status TEXT NOT NULL,
			total_assets INTEGER NOT NULL DEFAULT 0,
			pqc_ready_assets INTEGER NOT NULL DEFAULT 0,
			hybrid_assets INTEGER NOT NULL DEFAULT 0,
			classical_assets INTEGER NOT NULL DEFAULT 0,
			average_qsl REAL NOT NULL DEFAULT 0,
			readiness_score INTEGER NOT NULL DEFAULT 0,
			algorithm_summary_json TEXT NOT NULL DEFAULT '{}',
			timeline_status_json TEXT NOT NULL DEFAULT '{}',
			risk_items_json TEXT NOT NULL DEFAULT '[]',
			metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE pqc_policies (
			tenant_id TEXT NOT NULL PRIMARY KEY,
			profile_id TEXT NOT NULL DEFAULT 'balanced_hybrid',
			default_kem TEXT NOT NULL DEFAULT 'ML-KEM-768',
			default_signature TEXT NOT NULL DEFAULT 'ML-DSA-65',
			interface_default_mode TEXT NOT NULL DEFAULT 'hybrid',
			certificate_default_mode TEXT NOT NULL DEFAULT 'hybrid',
			hqc_backup_enabled BOOLEAN NOT NULL DEFAULT TRUE,
			flag_classical_usage BOOLEAN NOT NULL DEFAULT TRUE,
			flag_classical_certificates BOOLEAN NOT NULL DEFAULT TRUE,
			flag_non_migrated_interfaces BOOLEAN NOT NULL DEFAULT TRUE,
			require_pqc_for_new_keys BOOLEAN NOT NULL DEFAULT FALSE,
			updated_by TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE pqc_migration_plans (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			name TEXT NOT NULL,
			status TEXT NOT NULL,
			target_profile TEXT NOT NULL,
			timeline_standard TEXT NOT NULL,
			deadline TIMESTAMP,
			summary_json TEXT NOT NULL DEFAULT '{}',
			steps_json TEXT NOT NULL DEFAULT '[]',
			created_by TEXT NOT NULL DEFAULT 'system',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			executed_at TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE pqc_migration_runs (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			plan_id TEXT NOT NULL,
			status TEXT NOT NULL,
			dry_run BOOLEAN NOT NULL DEFAULT FALSE,
			summary_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP,
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
