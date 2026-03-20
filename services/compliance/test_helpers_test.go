package main

import (
	"context"
	"sync"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

type nopCompliancePublisher struct {
	mu       sync.Mutex
	subjects []string
}

func (p *nopCompliancePublisher) Publish(_ context.Context, subject string, _ []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	return nil
}

func (p *nopCompliancePublisher) Count(subject string) int {
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

type fakeComplianceKeyCore struct {
	keys map[string][]map[string]interface{}
}

func (f *fakeComplianceKeyCore) ListKeys(_ context.Context, tenantID string, _ int) ([]map[string]interface{}, error) {
	if f.keys == nil {
		return []map[string]interface{}{}, nil
	}
	items, ok := f.keys[tenantID]
	if !ok {
		return []map[string]interface{}{}, nil
	}
	out := make([]map[string]interface{}, 0, len(items))
	for _, it := range items {
		cp := map[string]interface{}{}
		for k, v := range it {
			cp[k] = v
		}
		out = append(out, cp)
	}
	return out, nil
}

type fakeCompliancePolicy struct {
	policies map[string][]map[string]interface{}
}

func (f *fakeCompliancePolicy) ListPolicies(_ context.Context, tenantID string, _ int) ([]map[string]interface{}, error) {
	if f.policies == nil {
		return []map[string]interface{}{}, nil
	}
	items, ok := f.policies[tenantID]
	if !ok {
		return []map[string]interface{}{}, nil
	}
	return items, nil
}

type fakeComplianceCerts struct {
	certs map[string][]map[string]interface{}
}

func (f *fakeComplianceCerts) ListCertificates(_ context.Context, tenantID string, _ int) ([]map[string]interface{}, error) {
	if f.certs == nil {
		return []map[string]interface{}{}, nil
	}
	items, ok := f.certs[tenantID]
	if !ok {
		return []map[string]interface{}{}, nil
	}
	out := make([]map[string]interface{}, 0, len(items))
	for _, it := range items {
		cp := map[string]interface{}{}
		for k, v := range it {
			cp[k] = v
		}
		out = append(out, cp)
	}
	return out, nil
}

func (f *fakeComplianceCerts) GetRenewalSummary(_ context.Context, _ string) (CertRenewalSummary, error) {
	return CertRenewalSummary{}, nil
}

type fakeComplianceAudit struct {
	events map[string][]map[string]interface{}
	stats  map[string]map[string]interface{}
}

func (f *fakeComplianceAudit) ListEvents(_ context.Context, tenantID string, _ int) ([]map[string]interface{}, error) {
	if f.events == nil {
		return []map[string]interface{}{}, nil
	}
	items, ok := f.events[tenantID]
	if !ok {
		return []map[string]interface{}{}, nil
	}
	return items, nil
}

func (f *fakeComplianceAudit) AlertStats(_ context.Context, tenantID string) (map[string]interface{}, error) {
	if f.stats == nil {
		return map[string]interface{}{}, nil
	}
	stats, ok := f.stats[tenantID]
	if !ok {
		return map[string]interface{}{}, nil
	}
	return stats, nil
}

func newComplianceService(t *testing.T) (*Service, *SQLStore, *fakeComplianceKeyCore, *fakeCompliancePolicy, *fakeComplianceAudit, *fakeComplianceCerts, *nopCompliancePublisher) {
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
	if err := createComplianceSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	keycore := &fakeComplianceKeyCore{keys: map[string][]map[string]interface{}{}}
	policy := &fakeCompliancePolicy{policies: map[string][]map[string]interface{}{}}
	audit := &fakeComplianceAudit{
		events: map[string][]map[string]interface{}{},
		stats:  map[string]map[string]interface{}{},
	}
	certs := &fakeComplianceCerts{
		certs: map[string][]map[string]interface{}{},
	}
	pub := &nopCompliancePublisher{}
	svc := NewService(store, keycore, policy, audit, certs, pub)
	return svc, store, keycore, policy, audit, certs, pub
}

func newComplianceHandler(t *testing.T) (*Handler, *Service, *fakeComplianceKeyCore, *fakeCompliancePolicy, *fakeComplianceAudit, *fakeComplianceCerts, *nopCompliancePublisher) {
	t.Helper()
	svc, _, keycore, policy, audit, certs, pub := newComplianceService(t)
	return NewHandler(svc), svc, keycore, policy, audit, certs, pub
}

func createComplianceSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE compliance_posture_snapshots (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			overall_score INTEGER NOT NULL,
			key_hygiene INTEGER NOT NULL,
			policy_compliance INTEGER NOT NULL,
			access_security INTEGER NOT NULL,
			crypto_posture INTEGER NOT NULL,
			pqc_readiness INTEGER NOT NULL,
			framework_scores TEXT NOT NULL DEFAULT '{}',
			metrics_json TEXT NOT NULL DEFAULT '{}',
			gap_count INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE compliance_framework_assessments (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			framework_id TEXT NOT NULL,
			score INTEGER NOT NULL,
			status TEXT NOT NULL,
			controls_json TEXT NOT NULL DEFAULT '[]',
			gaps_json TEXT NOT NULL DEFAULT '[]',
			pqc_ready INTEGER NOT NULL DEFAULT 0,
			qsl_avg REAL NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE UNIQUE INDEX uq_compliance_framework_assessments_tenant_framework
		   ON compliance_framework_assessments (tenant_id, framework_id);`,
		`CREATE TABLE compliance_gaps (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			framework_id TEXT NOT NULL,
			control_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT NOT NULL,
			resource_id TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'open',
			detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			resolved_at TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE compliance_cbom_snapshots (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			summary_json TEXT NOT NULL DEFAULT '{}',
			document_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE compliance_assessment_runs (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			trigger TEXT NOT NULL DEFAULT 'manual',
			template_id TEXT NOT NULL DEFAULT '',
			template_name TEXT NOT NULL DEFAULT '',
			overall_score INTEGER NOT NULL,
			framework_scores TEXT NOT NULL DEFAULT '{}',
			findings_json TEXT NOT NULL DEFAULT '[]',
			pqc_json TEXT NOT NULL DEFAULT '{}',
			cert_metrics_json TEXT NOT NULL DEFAULT '{}',
			posture_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE compliance_assessment_schedules (
			tenant_id TEXT PRIMARY KEY,
			enabled INTEGER NOT NULL DEFAULT 0,
			frequency TEXT NOT NULL DEFAULT 'daily',
			last_run_at TIMESTAMP,
			next_run_at TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE compliance_templates (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1,
			frameworks_json TEXT NOT NULL DEFAULT '[]',
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
