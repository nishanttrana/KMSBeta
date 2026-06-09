package main

import (
	"context"
	"errors"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

func newStoreForTest(t *testing.T) *SQLStore {
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
	if err := createSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return NewSQLStore(conn)
}

func createSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE keys (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, name TEXT NOT NULL, algorithm TEXT NOT NULL, key_type TEXT NOT NULL,
			purpose TEXT NOT NULL, status TEXT NOT NULL, current_version INTEGER NOT NULL, kcv BLOB, kcv_algorithm TEXT,
			iv_mode TEXT, owner TEXT NOT NULL, cloud TEXT, region TEXT, compliance BLOB, labels BLOB,
			tags BLOB, export_allowed BOOLEAN NOT NULL DEFAULT 0,
			activation_date TIMESTAMP, expiry_date TIMESTAMP,
			destroy_date TIMESTAMP,
			ops_total INTEGER DEFAULT 0, ops_encrypt INTEGER DEFAULT 0, ops_decrypt INTEGER DEFAULT 0, ops_sign INTEGER DEFAULT 0,
			ops_limit INTEGER DEFAULT 0, ops_limit_window TEXT, ops_last_reset TIMESTAMP, approval_required BOOLEAN DEFAULT 0,
			approval_policy_id TEXT, created_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE key_versions (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, key_id TEXT NOT NULL, version INTEGER NOT NULL,
			encrypted_material BLOB NOT NULL, material_iv BLOB NOT NULL, wrapped_dek BLOB NOT NULL, public_key BLOB, kcv BLOB,
			rotated_from INTEGER, rotation_reason TEXT, status TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE key_iv_log (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, key_id TEXT NOT NULL, key_version INTEGER NOT NULL,
			iv BLOB NOT NULL, operation TEXT NOT NULL, reference_id TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE key_tags (
			tenant_id TEXT NOT NULL, name TEXT NOT NULL, color TEXT NOT NULL, is_system BOOLEAN NOT NULL DEFAULT 0,
			created_by TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, name)
		);`,
		`CREATE TABLE key_access_grants (
			tenant_id TEXT NOT NULL, key_id TEXT NOT NULL, subject_type TEXT NOT NULL, subject_id TEXT NOT NULL,
			operations BLOB, created_by TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			not_before TIMESTAMP, expires_at TIMESTAMP, justification TEXT, ticket_id TEXT,
			PRIMARY KEY (tenant_id, key_id, subject_type, subject_id)
		);`,
		`CREATE TABLE key_interface_ports (
			tenant_id TEXT NOT NULL,
			interface_name TEXT NOT NULL,
			bind_address TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL DEFAULT '',
			pqc_mode TEXT NOT NULL DEFAULT 'inherit',
			certificate_source TEXT NOT NULL DEFAULT '',
			ca_id TEXT,
			certificate_id TEXT,
			enabled BOOLEAN NOT NULL DEFAULT 1,
			description TEXT,
			updated_by TEXT,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, interface_name)
		);`,
		`CREATE TABLE key_interface_tls_defaults (
			tenant_id TEXT PRIMARY KEY,
			certificate_source TEXT NOT NULL DEFAULT 'internal_ca',
			ca_id TEXT,
			certificate_id TEXT,
			updated_by TEXT,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE key_rotation_metrics (
			rotation_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			key_id TEXT NOT NULL,
			scheduled_date TIMESTAMP NOT NULL,
			actual_date TIMESTAMP,
			status TEXT NOT NULL DEFAULT 'scheduled',
			duration_ms INTEGER,
			reason TEXT,
			initiated_by TEXT,
			completed_by TEXT,
			error_details TEXT,
			old_version INTEGER,
			new_version INTEGER,
			rollback_attempted BOOLEAN DEFAULT 0,
			metadata_json BLOB DEFAULT '{}',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, rotation_id)
		);`,
		`CREATE TABLE key_analytics_metrics (
			metric_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			key_id TEXT NOT NULL,
			metric_type TEXT NOT NULL,
			value REAL NOT NULL,
			aggregation_period TEXT NOT NULL DEFAULT 'hourly',
			timestamp TIMESTAMP NOT NULL,
			metadata_json BLOB DEFAULT '{}',
			PRIMARY KEY (tenant_id, metric_id)
		);`,
		`CREATE TABLE key_health_scores (
			key_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			health_score INTEGER NOT NULL DEFAULT 100,
			entropy_score INTEGER NOT NULL DEFAULT 100,
			age_score INTEGER NOT NULL DEFAULT 100,
			usage_score INTEGER NOT NULL DEFAULT 100,
			algorithm_score INTEGER NOT NULL DEFAULT 100,
			backup_status TEXT NOT NULL DEFAULT 'unknown',
			rotation_overdue BOOLEAN DEFAULT 0,
			expiry_imminent BOOLEAN DEFAULT 0,
			compliance_warnings BLOB DEFAULT '[]',
			recommended_actions BLOB DEFAULT '[]',
			last_audit_date TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, key_id)
		);`,
		`CREATE TABLE key_inventory (
			key_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			key_name TEXT NOT NULL,
			key_type TEXT NOT NULL,
			algorithm TEXT NOT NULL,
			owner TEXT NOT NULL,
			status TEXT NOT NULL,
			created_date TIMESTAMP NOT NULL,
			last_used TIMESTAMP,
			last_rotated TIMESTAMP,
			rotation_frequency TEXT,
			next_rotation TIMESTAMP,
			expiry_date TIMESTAMP,
			backup_verified_at TIMESTAMP,
			hsm_stored BOOLEAN DEFAULT 0,
			cloud_provider TEXT,
			region TEXT,
			compliance_tags BLOB DEFAULT '[]',
			metadata_json BLOB DEFAULT '{}',
			discovered_via TEXT,
			discovery_timestamp TIMESTAMP,
			PRIMARY KEY (tenant_id, key_id)
		);`,
		`CREATE TABLE key_dependencies (
			dependency_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			key_id TEXT NOT NULL,
			service_id TEXT NOT NULL,
			app_id TEXT,
			dependency_type TEXT NOT NULL,
			criticality TEXT NOT NULL DEFAULT 'medium',
			last_verified TIMESTAMP,
			verification_status TEXT DEFAULT 'unknown',
			usage_frequency TEXT DEFAULT 'unknown',
			last_access_log_id TEXT,
			metadata_json BLOB DEFAULT '{}',
			discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, dependency_id)
		);`,
		`CREATE TABLE compromise_events (
			event_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			key_id TEXT NOT NULL,
			cve_id TEXT,
			threat_type TEXT NOT NULL,
			severity TEXT NOT NULL,
			detection_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			confirmed_date TIMESTAMP,
			status TEXT NOT NULL DEFAULT 'pending',
			remediation_plan TEXT,
			remediation_status TEXT DEFAULT 'not_started',
			remediation_date TIMESTAMP,
			affected_systems BLOB DEFAULT '[]',
			notifications_sent BLOB DEFAULT '[]',
			root_cause TEXT,
			detection_source TEXT,
			metadata_json BLOB DEFAULT '{}',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, event_id)
		);`,
		`CREATE TABLE enterprise_control_records (
			record_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			category TEXT NOT NULL,
			key_id TEXT,
			name TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			severity TEXT,
			risk_score INTEGER NOT NULL DEFAULT 0,
			expires_at TIMESTAMP,
			metadata_json BLOB DEFAULT '{}',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, category, record_id)
		);`,
		`CREATE TABLE key_dspm_findings (
			finding_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			source TEXT NOT NULL DEFAULT 'keycore',
			finding_type TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			severity TEXT NOT NULL DEFAULT 'info',
			risk_score INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'open',
			key_id TEXT,
			recommended_action TEXT NOT NULL DEFAULT '',
			evidence_json BLOB DEFAULT '{}',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, finding_id)
		);`,
		`CREATE TABLE key_audit_chain_anchors (
			anchor_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			anchor_type TEXT NOT NULL,
			merkle_root TEXT NOT NULL,
			previous_hash TEXT,
			anchor_hash TEXT NOT NULL,
			external_reference TEXT,
			status TEXT NOT NULL DEFAULT 'anchored',
			metadata_json BLOB DEFAULT '{}',
			anchored_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			verified_at TIMESTAMP,
			PRIMARY KEY (tenant_id, anchor_id)
		);`,
	}
	for _, s := range stmts {
		if _, err := conn.SQL().Exec(s); err != nil {
			return err
		}
	}
	return nil
}

func TestStoreCreateAndGetKey(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	k := Key{
		ID: "k1", TenantID: "t1", Name: "key1", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Status: "active", CurrentVersion: 1, KCV: []byte{0x01, 0x02, 0x03}, KCVAlgorithm: "aes-ecb-zero", IVMode: "internal",
		Owner: "ops", Labels: map[string]string{"env": "dev"}, CreatedBy: "tester",
	}
	v := KeyVersion{
		ID: "kv1", TenantID: "t1", KeyID: "k1", Version: 1, EncryptedMaterial: []byte("enc"),
		MaterialIV: []byte("123456789012"), WrappedDEK: []byte("1234567890123456wrapped"), KCV: []byte{0x01, 0x02, 0x03}, Status: "active",
	}
	if err := s.CreateKeyWithVersion(ctx, k, v); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetKey(ctx, "t1", "k1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "key1" || got.Algorithm != "AES-256" {
		t.Fatalf("unexpected key: %+v", got)
	}
}

func TestEnterpriseAuditStoreOperations(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	k := Key{
		ID: "audit-k1", TenantID: "t1", Name: "audit-key", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Status: "active", CurrentVersion: 1, KCV: []byte{0xaa, 0xbb, 0xcc}, KCVAlgorithm: "aes-ecb-zero", IVMode: "internal",
		Owner: "security", CreatedBy: "tester",
	}
	v := KeyVersion{
		ID: "audit-kv1", TenantID: "t1", KeyID: "audit-k1", Version: 1, EncryptedMaterial: []byte("enc"),
		MaterialIV: []byte("123456789012"), WrappedDEK: []byte("1234567890123456wrapped"), KCV: []byte{0xaa, 0xbb, 0xcc}, Status: "active",
	}
	if err := s.CreateKeyWithVersion(ctx, k, v); err != nil {
		t.Fatal(err)
	}

	if err := s.RecordRotationMetric(ctx, RotationMetric{
		RotationID:    "rot-1",
		TenantID:      "t1",
		KeyID:         "audit-k1",
		ScheduledDate: now.Add(-time.Minute),
		ActualDate:    &now,
		Status:        "completed",
		DurationMs:    1200,
		Reason:        "manual",
		OldVersion:    1,
		NewVersion:    2,
	}); err != nil {
		t.Fatal(err)
	}
	rotation, err := s.GetRotationAnalyticsSummary(ctx, "t1", 30)
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Completed != 1 || rotation.SuccessRate != 100 {
		t.Fatalf("unexpected rotation summary: %+v", rotation)
	}

	if err := s.RecordKeyAnalyticsMetric(ctx, KeyAnalyticsMetric{
		MetricID: "met-1", TenantID: "t1", KeyID: "audit-k1", MetricType: "usage_encrypt",
		Value: 1, AggregationPeriod: "realtime", Timestamp: now,
	}); err != nil {
		t.Fatal(err)
	}
	usage, err := s.GetKeyUsageMetricSummary(ctx, "t1", "audit-k1", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(usage.Metrics) != 1 || usage.Metrics[0].Count != 1 {
		t.Fatalf("unexpected usage metrics: %+v", usage)
	}
	hotspots, err := s.ListKeyHotspots(ctx, "t1", now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hotspots) != 1 || hotspots[0].KeyID != "audit-k1" {
		t.Fatalf("unexpected hotspots: %+v", hotspots)
	}

	if err := s.UpsertInventoryItem(ctx, KeyInventoryItem{
		KeyID: "audit-k1", TenantID: "t1", KeyName: "audit-key", KeyType: "symmetric", Algorithm: "AES-256",
		Owner: "security", Status: "active", CreatedDate: now, ComplianceTags: []string{"PCI-DSS"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertKeyDependencyRecord(ctx, KeyDependencyRecord{
		DependencyID: "dep-1", TenantID: "t1", KeyID: "audit-k1", ServiceID: "payments",
		DependencyType: "encryption", Criticality: "critical", VerificationStatus: "verified",
	}); err != nil {
		t.Fatal(err)
	}
	deps, err := s.ListKeyDependencies(ctx, "t1", "audit-k1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].ServiceID != "payments" {
		t.Fatalf("unexpected dependencies: %+v", deps)
	}
	inventory, err := s.GetInventorySummary(ctx, "t1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.TotalKeys != 1 || inventory.OrphanedKeys != 0 {
		t.Fatalf("unexpected inventory summary: %+v", inventory)
	}

	if err := s.UpsertKeyHealthScore(ctx, KeyHealthScore{
		KeyID: "audit-k1", TenantID: "t1", HealthScore: 88, EntropyScore: 100, AgeScore: 90,
		UsageScore: 80, AlgorithmScore: 100, BackupStatus: "verified", UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	health, err := s.GetKeyHealthSummary(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if health.TotalKeys != 1 || health.HealthyKeys != 1 {
		t.Fatalf("unexpected health summary: %+v", health)
	}

	if err := s.RecordCompromiseEvent(ctx, CompromiseEvent{
		EventID: "cmp-1", TenantID: "t1", KeyID: "audit-k1", ThreatType: "cve", Severity: "high",
		Status: "pending", RemediationStatus: "not_started", DetectionDate: now,
	}); err != nil {
		t.Fatal(err)
	}
	updated, err := s.UpdateCompromiseEventStatus(ctx, "t1", "cmp-1", "confirmed", "in_progress", "vendor advisory confirmed", []string{"security-oncall"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "confirmed" || updated.RemediationStatus != "in_progress" {
		t.Fatalf("unexpected compromise update: %+v", updated)
	}
	compromise, err := s.GetCompromiseSummary(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if compromise.OpenEvents != 1 || compromise.HighEvents != 1 {
		t.Fatalf("unexpected compromise summary: %+v", compromise)
	}

	control, err := s.UpsertEnterpriseControlRecord(ctx, EnterpriseControlRecord{
		RecordID: "ctrl-1", TenantID: "t1", Category: controlCategoryFederationProvider,
		Name: "aws-kms", Status: "active", Severity: "info", Metadata: map[string]any{"region": "us-east-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if control.RecordID != "ctrl-1" || control.Metadata["region"] != "us-east-1" {
		t.Fatalf("unexpected enterprise control: %+v", control)
	}
	controls, err := s.ListEnterpriseControlRecords(ctx, "t1", EnterpriseControlQuery{Category: controlCategoryFederationProvider, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(controls) != 1 {
		t.Fatalf("unexpected controls: %+v", controls)
	}

	finding, err := s.UpsertDSPMFinding(ctx, DSPMFinding{
		FindingID: "dspm-1", TenantID: "t1", Source: "keycore", FindingType: "inventory_dependency_gap",
		Title: "dependency gap", Severity: "high", RiskScore: 80, Status: "open", KeyID: "audit-k1",
		RecommendedAction: "map dependency", Evidence: map[string]any{"key_id": "audit-k1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if finding.RiskScore != 80 || finding.KeyID != "audit-k1" {
		t.Fatalf("unexpected dspm finding: %+v", finding)
	}
	findings, err := s.ListDSPMFindings(ctx, "t1", DSPMFindingQuery{Status: "open", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].FindingID != "dspm-1" {
		t.Fatalf("unexpected dspm findings: %+v", findings)
	}

	anchor, err := s.RecordAuditChainAnchor(ctx, AuditChainAnchor{
		AnchorID: "anch-1", TenantID: "t1", AnchorType: "internal_merkle", MerkleRoot: "sha256:abc",
		AnchorHash: "sha256:def", ExternalReference: "notary://example/1", Status: "anchored",
	})
	if err != nil {
		t.Fatal(err)
	}
	if anchor.AnchorHash != "sha256:def" {
		t.Fatalf("unexpected anchor: %+v", anchor)
	}
	anchors, err := s.ListAuditChainAnchors(ctx, "t1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 1 || anchors[0].AnchorID != "anch-1" {
		t.Fatalf("unexpected anchors: %+v", anchors)
	}
}

func TestStoreRunCryptoTxOpsLimit(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	k := Key{
		ID: "k2", TenantID: "t1", Name: "key2", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Status: "active", CurrentVersion: 1, KCV: []byte{0x01, 0x02, 0x03}, KCVAlgorithm: "aes-ecb-zero", IVMode: "internal",
		Owner: "ops", CreatedBy: "tester", OpsLimit: 2, OpsLimitWindow: "total", OpsLastReset: time.Now().UTC(),
	}
	v := KeyVersion{
		ID: "kv2", TenantID: "t1", KeyID: "k2", Version: 1, EncryptedMaterial: []byte("enc"),
		MaterialIV: []byte("123456789012"), WrappedDEK: []byte("1234567890123456wrapped"), KCV: []byte{0x01, 0x02, 0x03}, Status: "active",
	}
	if err := s.CreateKeyWithVersion(ctx, k, v); err != nil {
		t.Fatal(err)
	}
	cb := func(_ Key, _ KeyVersion) (CryptoTxResult, error) {
		return CryptoTxResult{Payload: []byte("ok"), IV: []byte("123456789012"), StoreIV: true}, nil
	}
	if _, err := s.RunCryptoTx(ctx, "t1", "k2", "encrypt", cb); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunCryptoTx(ctx, "t1", "k2", "encrypt", cb); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunCryptoTx(ctx, "t1", "k2", "encrypt", cb); !errors.Is(err, errOpsLimit) {
		t.Fatalf("expected errOpsLimit, got %v", err)
	}
	usage, err := s.GetUsage(ctx, "t1", "k2")
	if err != nil {
		t.Fatal(err)
	}
	if usage.OpsTotal != 2 || usage.OpsEncrypt != 2 {
		t.Fatalf("unexpected usage: %+v", usage)
	}
}

func TestStoreScheduleDestroyAndPurge(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	k := Key{
		ID: "k3", TenantID: "t1", Name: "key3", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Status: "active", CurrentVersion: 1, KCV: []byte{0x01, 0x02, 0x03}, KCVAlgorithm: "aes-ecb-zero", IVMode: "internal",
		Owner: "ops", CreatedBy: "tester",
	}
	v := KeyVersion{
		ID: "kv3", TenantID: "t1", KeyID: "k3", Version: 1, EncryptedMaterial: []byte("enc"),
		MaterialIV: []byte("123456789012"), WrappedDEK: []byte("1234567890123456wrapped"), KCV: []byte{0x01, 0x02, 0x03}, Status: "active",
	}
	if err := s.CreateKeyWithVersion(ctx, k, v); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_access_grants (tenant_id, key_id, subject_type, subject_id, operations, created_by)
VALUES ('t1','k3','user','u1','["encrypt"]','tester')
`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_iv_log (id, tenant_id, key_id, key_version, iv, operation, reference_id)
VALUES ('iv1','t1','k3',1,?, 'encrypt', 'ref-1')
`, []byte("123456789012")); err != nil {
		t.Fatal(err)
	}
	if err := s.ScheduleDestroy(ctx, "t1", "k3", time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	deleted, err := s.PurgeDueDestroyed(ctx, "t1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0].KeyID != "k3" {
		t.Fatalf("unexpected deleted keys: %+v", deleted)
	}
	if deleted[0].DeletedVersionCount != 1 || deleted[0].DeletedIVLogCount != 1 || deleted[0].DeletedAccessGrants != 1 {
		t.Fatalf("unexpected deleted artifact counts: %+v", deleted[0])
	}
	got, err := s.GetKey(ctx, "t1", "k3")
	if err != nil {
		t.Fatalf("expected key metadata to remain, got err=%v", err)
	}
	if got.Status != "deleted" {
		t.Fatalf("expected status deleted, got %s", got.Status)
	}
	if got.CurrentVersion != 0 {
		t.Fatalf("expected current_version=0, got %d", got.CurrentVersion)
	}
	if got.Purpose != "deleted" || got.Owner != "deleted" {
		t.Fatalf("expected scrubbed tombstone purpose/owner, got purpose=%q owner=%q", got.Purpose, got.Owner)
	}
	if got.ExportAllowed || got.ApprovalRequired || got.ApprovalPolicyID != "" {
		t.Fatalf("expected export/approval metadata reset, got export=%v approval_required=%v policy=%q", got.ExportAllowed, got.ApprovalRequired, got.ApprovalPolicyID)
	}
	if len(got.Tags) != 0 || len(got.Compliance) != 0 || len(got.Labels) != 0 {
		t.Fatalf("expected tags/compliance/labels scrubbed, got tags=%v compliance=%v labels=%v", got.Tags, got.Compliance, got.Labels)
	}
	versions, err := s.ListVersions(ctx, "t1", "k3")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 0 {
		t.Fatalf("expected versions to be removed, found %d", len(versions))
	}
	var grants int
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(1) FROM key_access_grants WHERE tenant_id='t1' AND key_id='k3'`).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 0 {
		t.Fatalf("expected key access grants to be removed, found %d", grants)
	}
}

func TestStoreHardDeleteKey(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	k := Key{
		ID: "k4", TenantID: "t1", Name: "key4", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Status: "active", CurrentVersion: 1, KCV: []byte{0x01, 0x02, 0x03}, KCVAlgorithm: "aes-ecb-zero", IVMode: "internal",
		Owner: "ops", CreatedBy: "tester",
	}
	v := KeyVersion{
		ID: "kv4", TenantID: "t1", KeyID: "k4", Version: 1, EncryptedMaterial: []byte("enc"),
		MaterialIV: []byte("123456789012"), WrappedDEK: []byte("1234567890123456wrapped"), KCV: []byte{0x01, 0x02, 0x03}, Status: "active",
	}
	if err := s.CreateKeyWithVersion(ctx, k, v); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_access_grants (tenant_id, key_id, subject_type, subject_id, operations, created_by)
VALUES ('t1','k4','user','u2','["encrypt"]','tester')
`); err != nil {
		t.Fatal(err)
	}
	if err := s.HardDeleteKey(ctx, "t1", "k4"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetKey(ctx, "t1", "k4"); !errors.Is(err, errStoreNotFound) {
		t.Fatalf("expected key to be removed, got err=%v", err)
	}
	versions, err := s.ListVersions(ctx, "t1", "k4")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 0 {
		t.Fatalf("expected versions to be removed, found %d", len(versions))
	}
	var grants int
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(1) FROM key_access_grants WHERE tenant_id='t1' AND key_id='k4'`).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 0 {
		t.Fatalf("expected key access grants to be removed, found %d", grants)
	}
}

func TestStoreActivateDueKeys(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	when := time.Now().UTC().Add(-5 * time.Minute)
	k := Key{
		ID: "k5", TenantID: "t1", Name: "key5", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Status: "pre-active", ActivationDate: &when, CurrentVersion: 1, KCV: []byte{0x0a, 0x0b, 0x0c}, KCVAlgorithm: "aes-ecb-zero", IVMode: "internal",
		Owner: "ops", CreatedBy: "tester",
	}
	v := KeyVersion{
		ID: "kv5", TenantID: "t1", KeyID: "k5", Version: 1, EncryptedMaterial: []byte("enc"),
		MaterialIV: []byte("123456789012"), WrappedDEK: []byte("1234567890123456wrapped"), KCV: []byte{0x0a, 0x0b, 0x0c}, Status: "pre-active",
	}
	if err := s.CreateKeyWithVersion(ctx, k, v); err != nil {
		t.Fatal(err)
	}
	ids, err := s.ActivateDueKeys(ctx, "t1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "k5" {
		t.Fatalf("unexpected activated IDs: %+v", ids)
	}
	got, err := s.GetKey(ctx, "t1", "k5")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "active" {
		t.Fatalf("expected active status, got %s", got.Status)
	}
	if got.ActivationDate != nil {
		t.Fatalf("expected activation_date cleared, got %v", got.ActivationDate)
	}
}

func TestStoreInterfaceTLSDefaultsRoundTrip(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()

	cfg, err := s.GetKeyInterfaceTLSConfig(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CertSource != "internal_ca" {
		t.Fatalf("expected default internal_ca, got %q", cfg.CertSource)
	}

	out, err := s.UpsertKeyInterfaceTLSConfig(ctx, KeyInterfaceTLSConfig{
		TenantID:   "t1",
		CertSource: "pki_ca",
		CAID:       "ca_ops",
		UpdatedBy:  "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.CertSource != "pki_ca" || out.CAID != "ca_ops" {
		t.Fatalf("unexpected stored tls config: %+v", out)
	}

	got, err := s.GetKeyInterfaceTLSConfig(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CertSource != "pki_ca" || got.CAID != "ca_ops" || got.CertificateID != "" {
		t.Fatalf("unexpected fetched tls config: %+v", got)
	}
}
