package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
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
	mu              sync.Mutex
	rotateCalls     []string
	failRotateFor   map[string]bool
	created         []map[string]interface{}
	deactivateCalls []string
}

func (f *fakePQCKeyCore) CreateKey(_ context.Context, _ string, req map[string]interface{}) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, req)
	return fmt.Sprintf("new-%d", len(f.created)), nil
}

func (f *fakePQCKeyCore) DeactivateKey(_ context.Context, _ string, keyID string, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deactivateCalls = append(f.deactivateCalls, keyID)
	return nil
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

// newPQCHandler serves the handler as if pkg/jwtauth had verified an admin
// token for tenant-h1.
func newPQCHandler(t *testing.T) (http.Handler, *Service, *nopPQCPublisher) {
	t.Helper()
	svc, _, pub, _ := newPQCService(t)
	return asCaller(NewHandler(svc, nil, nil), adminOf("tenant-h1")), svc, pub
}

// asCaller serves h as if pkg/jwtauth had verified a token carrying claims.
func asCaller(h http.Handler, claims *pkgauth.Claims) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), claims)))
	})
}

func adminOf(tenant string) *pkgauth.Claims {
	c := &pkgauth.Claims{UserID: "u-" + tenant, TenantID: tenant, Role: "admin", Permissions: []string{"*"}}
	c.Subject = c.UserID
	return c
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
			algorithm_summary_json TEXT NOT NULL DEFAULT '{}',
			timeline_status_json TEXT NOT NULL DEFAULT '{}',
			risk_items_json TEXT NOT NULL DEFAULT '[]',
			metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
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
