package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	pkgaudit "vecta-kms/pkg/audit"

	pkgauth "vecta-kms/pkg/auth"
	pkgdb "vecta-kms/pkg/db"
)

type nopSBOMPublisher struct {
	mu       sync.Mutex
	subjects []string
	last     map[string][]byte
}

func (p *nopSBOMPublisher) Publish(_ context.Context, subject string, payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	if p.last == nil {
		p.last = map[string][]byte{}
	}
	p.last[subject] = payload
	return nil
}

// Emit records a pkg/audit event under its full subject (audit.sbom.<action>).
func (p *nopSBOMPublisher) Emit(ctx context.Context, action string, evt pkgaudit.Event) error {
	raw, _ := json.Marshal(evt)
	return p.Publish(ctx, "audit.sbom."+action, raw)
}

func (p *nopSBOMPublisher) Count(subject string) int {
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

type fakeSBOMKeyCore struct {
	keys map[string][]map[string]interface{}
}

func (f *fakeSBOMKeyCore) ListKeys(_ context.Context, tenantID string, _ int) ([]map[string]interface{}, error) {
	items := f.keys[tenantID]
	if items == nil {
		return []map[string]interface{}{}, nil
	}
	return items, nil
}

type fakeSBOMCerts struct {
	items map[string][]map[string]interface{}
}

func (f *fakeSBOMCerts) ListCertificates(_ context.Context, tenantID string, _ int) ([]map[string]interface{}, error) {
	items := f.items[tenantID]
	if items == nil {
		return []map[string]interface{}{}, nil
	}
	return items, nil
}

type fakeSBOMDiscovery struct {
	items map[string][]map[string]interface{}
}

func (f *fakeSBOMDiscovery) ListCryptoAssets(_ context.Context, tenantID string, _ int) ([]map[string]interface{}, error) {
	items := f.items[tenantID]
	if items == nil {
		return []map[string]interface{}{}, nil
	}
	return items, nil
}

func newSBOMService(t *testing.T) (*Service, *SQLStore, *fakeSBOMKeyCore, *fakeSBOMCerts, *fakeSBOMDiscovery, *nopSBOMPublisher) {
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
	if err := createSBOMSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	keycore := &fakeSBOMKeyCore{keys: map[string][]map[string]interface{}{}}
	certs := &fakeSBOMCerts{items: map[string][]map[string]interface{}{}}
	discovery := &fakeSBOMDiscovery{items: map[string][]map[string]interface{}{}}
	pub := &nopSBOMPublisher{}
	svc := NewService(store, keycore, certs, discovery, pub)
	return svc, store, keycore, certs, discovery, pub
}

func newSBOMHandler(t *testing.T) (*Handler, *Service, *fakeSBOMKeyCore, *fakeSBOMCerts, *fakeSBOMDiscovery, *nopSBOMPublisher) {
	t.Helper()
	svc, _, keycore, certs, discovery, pub := newSBOMService(t)
	return NewHandler(svc, nil, nil), svc, keycore, certs, discovery, pub
}

// asCaller serves h as if pkg/jwtauth had verified a token carrying claims.
func asCaller(h http.Handler, claims *pkgauth.Claims) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), claims)))
	})
}

func adminOf(tenant string) *pkgauth.Claims {
	return &pkgauth.Claims{UserID: "u-" + tenant, TenantID: tenant, Role: "admin", Permissions: []string{"*"}}
}

func createSBOMSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE sbom_snapshots (
			id TEXT PRIMARY KEY,
			appliance_id TEXT NOT NULL DEFAULT 'vecta-kms',
			format TEXT NOT NULL DEFAULT 'cyclonedx',
			spec_version TEXT NOT NULL DEFAULT '1.6',
			source_hash TEXT NOT NULL DEFAULT '',
			summary_json TEXT NOT NULL DEFAULT '{}',
			document_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE cbom_snapshots (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			format TEXT NOT NULL DEFAULT 'cyclonedx-crypto',
			spec_version TEXT NOT NULL DEFAULT '1.6',
			source_hash TEXT NOT NULL DEFAULT '',
			summary_json TEXT NOT NULL DEFAULT '{}',
			document_json TEXT NOT NULL DEFAULT '{}',
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
