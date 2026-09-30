package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	pkgdb "vecta-kms/pkg/db"
)

type nopDiscoveryPublisher struct {
	mu       sync.Mutex
	subjects []string
}

func (p *nopDiscoveryPublisher) Publish(_ context.Context, subject string, _ []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	return nil
}

func (p *nopDiscoveryPublisher) Count(subject string) int {
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

type fakeDiscoveryKeyCore struct{}

func (f *fakeDiscoveryKeyCore) ListKeys(_ context.Context, _ string, _ int) ([]map[string]interface{}, error) {
	return []map[string]interface{}{
		{"id": "k1", "name": "legacy", "algorithm": "RSA-2048", "status": "active", "provider": "aws"},
		{"id": "k2", "name": "hybrid", "algorithm": "ML-KEM-768-HYBRID", "status": "active", "provider": "azure"},
	}, nil
}

type fakeDiscoveryCerts struct{}

func (f *fakeDiscoveryCerts) ListCertificates(_ context.Context, _ string, _ int) ([]map[string]interface{}, error) {
	return []map[string]interface{}{
		{"id": "c1", "subject_cn": "api.vecta.local", "algorithm": "RSA-3072", "status": "active"},
		{"id": "c2", "subject_cn": "pqc.vecta.local", "algorithm": "ML-DSA-65", "status": "active", "cert_class": "pqc"},
	}, nil
}

func newDiscoveryService(t *testing.T) (*Service, *SQLStore, *nopDiscoveryPublisher) {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{UseSQLite: true, SQLitePath: ":memory:", MaxOpen: 1, MaxIdle: 1})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createDiscoverySchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	pub := &nopDiscoveryPublisher{}
	svc := NewService(store, &fakeDiscoveryKeyCore{}, &fakeDiscoveryCerts{}, pub)
	svc.cloud = &testCloud{}
	// A real TLS endpoint: the network scan handshakes with it.
	tlsSrv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(tlsSrv.Close)
	t.Setenv("DISCOVERY_TLS_ENDPOINTS", strings.TrimPrefix(tlsSrv.URL, "https://"))
	return svc, store, pub
}

// newDiscoveryHandler serves requests as a verified tenant-less admin token,
// so each test names its own tenant; handler_routes_test.go covers
// authentication, permissions and tenancy.
func newDiscoveryHandler(t *testing.T) (http.Handler, *Service, *nopDiscoveryPublisher) {
	t.Helper()
	svc, _, pub := newDiscoveryService(t)
	h := NewHandler(svc, nil, nil)
	admin := &pkgauth.Claims{UserID: "test-admin", Role: "admin", Permissions: []string{"*"}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), admin)))
	}), svc, pub
}

func createDiscoverySchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE discovery_scans (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			scan_type TEXT NOT NULL,
			status TEXT NOT NULL,
			trigger TEXT NOT NULL DEFAULT 'manual',
			stats_json TEXT NOT NULL DEFAULT '{}',
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE discovery_assets (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			scan_id TEXT NOT NULL DEFAULT '',
			asset_type TEXT NOT NULL,
			name TEXT NOT NULL,
			location TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL,
			algorithm TEXT NOT NULL DEFAULT 'UNKNOWN',
			strength_bits INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'active',
			classification TEXT NOT NULL DEFAULT 'unknown',
			pqc_ready BOOLEAN NOT NULL DEFAULT FALSE,
			qsl_score REAL NOT NULL DEFAULT 0,
			metadata_json TEXT NOT NULL DEFAULT '{}',
			first_seen TIMESTAMP,
			last_seen TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
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

// testCloud stands in for the cloud service's accounts and inventory API.
type testCloud struct{ err error }

func (c *testCloud) ListAccounts(context.Context, string) ([]map[string]interface{}, error) {
	return []map[string]interface{}{{"id": "acct-1", "provider": "aws"}}, nil
}

func (c *testCloud) Inventory(context.Context, string, string) ([]map[string]interface{}, error) {
	if c.err != nil {
		return nil, c.err
	}
	return []map[string]interface{}{{"cloud_key_id": "k-1", "region": "us-east-1", "state": "enabled", "algorithm": "SYMMETRIC_DEFAULT"}}, nil
}
