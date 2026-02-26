package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

type mockEmailSender struct {
	msgs []EmailMessage
}

func (m *mockEmailSender) Send(_ context.Context, msg EmailMessage) error {
	m.msgs = append(m.msgs, msg)
	return nil
}

type mockCallbackExecutor struct {
	count int
	last  ApprovalRequest
}

func (m *mockCallbackExecutor) Execute(_ context.Context, req ApprovalRequest) error {
	m.count++
	m.last = req
	return nil
}

func newGovernanceStore(t *testing.T) *SQLStore {
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
	if err := createGovernanceSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return NewSQLStore(conn)
}

func createGovernanceSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE approval_policies (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			scope TEXT NOT NULL,
			trigger_actions TEXT NOT NULL,
			quorum_mode TEXT NOT NULL DEFAULT 'threshold',
			required_approvals INTEGER NOT NULL,
			total_approvers INTEGER NOT NULL,
			approver_roles TEXT NOT NULL,
			approver_users TEXT,
			timeout_hours INTEGER DEFAULT 48,
			escalation_hours INTEGER,
			escalation_to TEXT,
			retention_days INTEGER DEFAULT 90,
			notification_channels TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			created_at TEXT DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE approval_requests (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			action TEXT NOT NULL,
			target_type TEXT NOT NULL,
			target_id TEXT NOT NULL,
			target_details TEXT NOT NULL,
			requester_id TEXT NOT NULL,
			requester_email TEXT,
			requester_ip TEXT,
			status TEXT NOT NULL,
			required_approvals INTEGER NOT NULL,
			current_approvals INTEGER NOT NULL DEFAULT 0,
			current_denials INTEGER NOT NULL DEFAULT 0,
			created_at TEXT DEFAULT CURRENT_TIMESTAMP,
			expires_at TEXT NOT NULL,
			resolved_at TEXT,
			retain_until TEXT,
			callback_service TEXT NOT NULL,
			callback_action TEXT NOT NULL,
			callback_payload TEXT
		);`,
		`CREATE TABLE approval_votes (
			id TEXT PRIMARY KEY,
			request_id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			approver_id TEXT NOT NULL,
			approver_email TEXT NOT NULL,
			vote TEXT NOT NULL,
			vote_method TEXT NOT NULL,
			comment TEXT,
			token_hash BLOB,
			voted_at TEXT DEFAULT CURRENT_TIMESTAMP,
			ip_address TEXT
		);`,
		`CREATE TABLE approval_tokens (
			id TEXT PRIMARY KEY,
			request_id TEXT NOT NULL,
			approver_email TEXT NOT NULL,
			token_hash BLOB NOT NULL,
			action TEXT NOT NULL,
			used INTEGER NOT NULL DEFAULT 0,
			expires_at TEXT NOT NULL,
			created_at TEXT DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE governance_settings (
				tenant_id TEXT PRIMARY KEY,
				approval_expiry_minutes INTEGER NOT NULL DEFAULT 60,
				expiry_check_interval_seconds INTEGER NOT NULL DEFAULT 60,
				approval_delivery_mode TEXT NOT NULL DEFAULT 'notify',
				smtp_host TEXT,
				smtp_port TEXT,
				smtp_username TEXT,
				smtp_password TEXT,
				smtp_from TEXT,
				smtp_starttls INTEGER NOT NULL DEFAULT 1,
				notify_dashboard INTEGER NOT NULL DEFAULT 1,
				notify_email INTEGER NOT NULL DEFAULT 1,
				notify_slack INTEGER NOT NULL DEFAULT 0,
				notify_teams INTEGER NOT NULL DEFAULT 0,
				slack_webhook_url TEXT,
				teams_webhook_url TEXT,
				delivery_webhook_timeout_seconds INTEGER NOT NULL DEFAULT 5,
				challenge_response_enabled INTEGER NOT NULL DEFAULT 0,
				updated_by TEXT,
				updated_at TEXT DEFAULT CURRENT_TIMESTAMP
			);`,
		`CREATE TABLE governance_system_state (
			tenant_id TEXT PRIMARY KEY,
			fips_mode TEXT NOT NULL DEFAULT 'disabled',
			hsm_mode TEXT NOT NULL DEFAULT 'software',
			cluster_mode TEXT NOT NULL DEFAULT 'standalone',
			license_key TEXT,
			license_status TEXT NOT NULL DEFAULT 'inactive',
			mgmt_ip TEXT,
			cluster_ip TEXT,
			dns_servers TEXT,
			ntp_servers TEXT,
			tls_mode TEXT NOT NULL DEFAULT 'internal_ca',
			tls_cert_pem TEXT,
			tls_key_pem TEXT,
			tls_ca_bundle_pem TEXT,
			backup_schedule TEXT NOT NULL DEFAULT 'daily@02:00',
			backup_target TEXT NOT NULL DEFAULT 'local',
			backup_retention_days INTEGER NOT NULL DEFAULT 30,
			backup_encrypted INTEGER NOT NULL DEFAULT 1,
			proxy_endpoint TEXT,
			snmp_target TEXT,
			updated_by TEXT,
			updated_at TEXT DEFAULT CURRENT_TIMESTAMP
		);`,
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func createTestPolicy(t *testing.T, svc *Service, tenantID string, required int, total int, approvers []string) ApprovalPolicy {
	t.Helper()
	p, err := svc.CreatePolicy(context.Background(), ApprovalPolicy{
		TenantID:          tenantID,
		Name:              "key-ops-approval",
		Scope:             "key_operation",
		TriggerActions:    []string{"key.destroy", "key.encrypt"},
		RequiredApprovals: required,
		TotalApprovers:    total,
		ApproverRoles:     []string{"admin"},
		ApproverUsers:     approvers,
		Status:            "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSingleApprovalEmailLinkFlow(t *testing.T) {
	store := newGovernanceStore(t)
	mailer := &mockEmailSender{}
	callback := &mockCallbackExecutor{}
	svc := NewService(store, nil, mailer, callback, "http://localhost:8050")
	h := NewHandler(svc)

	_, err := svc.UpdateSettings(context.Background(), GovernanceSettings{
		TenantID:                   "t1",
		ApprovalExpiryMinutes:      30,
		ExpiryCheckIntervalSeconds: 15,
		UpdatedBy:                  "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	createTestPolicy(t, svc, "t1", 1, 1, []string{"alice@example.com"})

	req, err := svc.CreateApprovalRequest(context.Background(), CreateApprovalRequestInput{
		TenantID:       "t1",
		Action:         "key.destroy",
		TargetType:     "key",
		TargetID:       "key-1",
		RequesterID:    "u1",
		RequesterEmail: "u1@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.ExpiresAt.Sub(time.Now().UTC()) < 29*time.Minute {
		t.Fatalf("expected ~30 minute expiry, got %v", req.ExpiresAt.Sub(time.Now().UTC()))
	}
	if len(mailer.msgs) != 1 {
		t.Fatalf("expected 1 email, got %d", len(mailer.msgs))
	}
	approveToken := extractToken(t, mailer.msgs[0].Body, "approve")

	getReq := httptest.NewRequest(http.MethodGet, "/governance/approve/"+req.ID+"?tenant_id=t1&token="+url.QueryEscape(approveToken), nil)
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK || !strings.Contains(getRR.Body.String(), "Approve") {
		t.Fatalf("approval page status=%d body=%s", getRR.Code, getRR.Body.String())
	}

	form := url.Values{}
	form.Set("tenant_id", "t1")
	form.Set("token", approveToken)
	form.Set("vote", "approved")
	form.Set("comment", "approved")
	postReq := httptest.NewRequest(http.MethodPost, "/governance/approve/"+req.ID, strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRR := httptest.NewRecorder()
	h.ServeHTTP(postRR, postReq)
	if postRR.Code != http.StatusOK {
		t.Fatalf("vote status=%d body=%s", postRR.Code, postRR.Body.String())
	}

	details, err := svc.GetApprovalRequest(context.Background(), "t1", req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if details.Request.Status != "approved" {
		t.Fatalf("expected approved, got %s", details.Request.Status)
	}
	if callback.count != 1 {
		t.Fatalf("expected callback executed once, got %d", callback.count)
	}
}

func TestMultiQuorumApproval(t *testing.T) {
	store := newGovernanceStore(t)
	mailer := &mockEmailSender{}
	callback := &mockCallbackExecutor{}
	svc := NewService(store, nil, mailer, callback, "http://localhost:8050")
	createTestPolicy(t, svc, "t2", 2, 3, []string{"a@example.com", "b@example.com", "c@example.com"})

	req, err := svc.CreateApprovalRequest(context.Background(), CreateApprovalRequestInput{
		TenantID:       "t2",
		Action:         "key.destroy",
		TargetType:     "key",
		TargetID:       "key-2",
		RequesterID:    "u2",
		RequesterEmail: "u2@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(mailer.msgs) != 3 {
		t.Fatalf("expected 3 emails, got %d", len(mailer.msgs))
	}
	tokenA := extractToken(t, mailer.msgs[0].Body, "approve")
	tokenB := extractToken(t, mailer.msgs[1].Body, "approve")

	out1, err := svc.Vote(context.Background(), VoteInput{
		TenantID:  "t2",
		RequestID: req.ID,
		Token:     tokenA,
		Vote:      "approved",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out1.Status != "pending" {
		t.Fatalf("after first vote expected pending, got %s", out1.Status)
	}
	out2, err := svc.Vote(context.Background(), VoteInput{
		TenantID:  "t2",
		RequestID: req.ID,
		Token:     tokenB,
		Vote:      "approved",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out2.Status != "approved" {
		t.Fatalf("after second vote expected approved, got %s", out2.Status)
	}
	if callback.count != 1 {
		t.Fatalf("expected callback executed once, got %d", callback.count)
	}
}

func TestQuorumModeORApprovesOnFirstVote(t *testing.T) {
	store := newGovernanceStore(t)
	mailer := &mockEmailSender{}
	svc := NewService(store, nil, mailer, &mockCallbackExecutor{}, "http://localhost:8050")
	_, err := svc.CreatePolicy(context.Background(), ApprovalPolicy{
		TenantID:          "tor",
		Name:              "or-policy",
		Scope:             "key_operation",
		TriggerActions:    []string{"key.encrypt"},
		QuorumMode:        "or",
		RequiredApprovals: 2,
		TotalApprovers:    2,
		ApproverRoles:     []string{"admin"},
		ApproverUsers:     []string{"or1@example.com", "or2@example.com"},
		Status:            "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := svc.CreateApprovalRequest(context.Background(), CreateApprovalRequestInput{
		TenantID:       "tor",
		Action:         "key.encrypt",
		TargetType:     "key",
		TargetID:       "key-or",
		RequesterID:    "u-or",
		RequesterEmail: "u-or@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.RequiredApprovals != 1 {
		t.Fatalf("expected OR mode to require 1 approval, got %d", req.RequiredApprovals)
	}
	token := extractToken(t, mailer.msgs[0].Body, "approve")
	out, err := svc.Vote(context.Background(), VoteInput{
		TenantID:  "tor",
		RequestID: req.ID,
		Token:     token,
		Vote:      "approved",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "approved" {
		t.Fatalf("expected approved after first vote in OR mode, got %s", out.Status)
	}
}

func TestQuorumModeANDDeniesOnAnyDenial(t *testing.T) {
	store := newGovernanceStore(t)
	mailer := &mockEmailSender{}
	svc := NewService(store, nil, mailer, &mockCallbackExecutor{}, "http://localhost:8050")
	_, err := svc.CreatePolicy(context.Background(), ApprovalPolicy{
		TenantID:          "tand",
		Name:              "and-policy",
		Scope:             "key_operation",
		TriggerActions:    []string{"key.encrypt"},
		QuorumMode:        "and",
		RequiredApprovals: 1,
		TotalApprovers:    2,
		ApproverRoles:     []string{"admin"},
		ApproverUsers:     []string{"and1@example.com", "and2@example.com"},
		Status:            "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := svc.CreateApprovalRequest(context.Background(), CreateApprovalRequestInput{
		TenantID:       "tand",
		Action:         "key.encrypt",
		TargetType:     "key",
		TargetID:       "key-and",
		RequesterID:    "u-and",
		RequesterEmail: "u-and@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.RequiredApprovals != 2 {
		t.Fatalf("expected AND mode to require all approvals, got %d", req.RequiredApprovals)
	}
	token := extractToken(t, mailer.msgs[0].Body, "deny")
	out, err := svc.Vote(context.Background(), VoteInput{
		TenantID:  "tand",
		RequestID: req.ID,
		Token:     token,
		Vote:      "denied",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "denied" {
		t.Fatalf("expected denied after first denial in AND mode, got %s", out.Status)
	}
}

func TestActionMatchSupportsHyphenUnderscore(t *testing.T) {
	store := newGovernanceStore(t)
	mailer := &mockEmailSender{}
	svc := NewService(store, nil, mailer, &mockCallbackExecutor{}, "http://localhost:8050")
	_, err := svc.CreatePolicy(context.Background(), ApprovalPolicy{
		TenantID:          "tact",
		Name:              "action-alias-policy",
		Scope:             "key_operation",
		TriggerActions:    []string{"key.kem_encapsulate"},
		QuorumMode:        "or",
		RequiredApprovals: 1,
		TotalApprovers:    1,
		ApproverRoles:     []string{"admin"},
		ApproverUsers:     []string{"ops@example.com"},
		Status:            "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := svc.CreateApprovalRequest(context.Background(), CreateApprovalRequestInput{
		TenantID:       "tact",
		Action:         "key.kem-encapsulate",
		TargetType:     "key",
		TargetID:       "key-kem",
		RequesterID:    "u-kem",
		RequesterEmail: "u-kem@example.com",
	})
	if err != nil {
		t.Fatalf("expected action alias to match, got err=%v", err)
	}
	if strings.TrimSpace(req.ID) == "" {
		t.Fatal("expected approval request id")
	}
}

func TestExpireWorkerTick(t *testing.T) {
	store := newGovernanceStore(t)
	mailer := &mockEmailSender{}
	svc := NewService(store, nil, mailer, &mockCallbackExecutor{}, "http://localhost:8050")
	createTestPolicy(t, svc, "t3", 1, 1, []string{"a@example.com"})

	req, err := svc.CreateApprovalRequest(context.Background(), CreateApprovalRequestInput{
		TenantID:       "t3",
		Action:         "key.destroy",
		TargetType:     "key",
		TargetID:       "key-3",
		RequesterID:    "u3",
		RequesterEmail: "u3@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.db.SQL().Exec(`UPDATE approval_requests SET expires_at = DATETIME('now', '-5 minute') WHERE tenant_id='t3' AND id=?`, req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ExpireWorkerTick(context.Background()); err != nil {
		t.Fatal(err)
	}
	details, err := svc.GetApprovalRequest(context.Background(), "t3", req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if details.Request.Status != "expired" {
		t.Fatalf("expected expired, got %s", details.Request.Status)
	}
}

func TestSystemStatePersistenceAndIntegrity(t *testing.T) {
	store := newGovernanceStore(t)
	svc := NewService(store, nil, &mockEmailSender{}, &mockCallbackExecutor{}, "http://localhost:8050")

	updated, err := svc.UpdateSystemState(context.Background(), GovernanceSystemState{
		TenantID:            "t4",
		FIPSMode:            "enabled",
		HSMMode:             "hardware",
		ClusterMode:         "ha",
		LicenseKey:          "SEC-KMS-ENT-2026-XXXX",
		MgmtIP:              "10.0.1.100",
		ClusterIP:           "172.16.0.100",
		DNSServers:          "10.0.0.2,10.0.0.3",
		NTPServers:          "ntp.bank.local",
		TLSMode:             "uploaded",
		BackupSchedule:      "daily@02:00",
		BackupTarget:        "s3",
		BackupRetentionDays: 90,
		BackupEncrypted:     true,
		ProxyEndpoint:       "http://proxy.bank.local:8080",
		SNMPTarget:          "udp://snmp.bank.local:162",
		UpdatedBy:           "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.LicenseStatus != "active" {
		t.Fatalf("expected active license status, got %s", updated.LicenseStatus)
	}

	_, err = svc.UpdateSettings(context.Background(), GovernanceSettings{
		TenantID:              "t4",
		SMTPHost:              "smtp.bank.local",
		SMTPPort:              "587",
		SMTPStartTLS:          true,
		ApprovalExpiryMinutes: 60,
		UpdatedBy:             "admin",
	})
	if err != nil {
		t.Fatal(err)
	}

	integrity, err := svc.SystemIntegrity(context.Background(), "t4")
	if err != nil {
		t.Fatal(err)
	}
	if integrity.Status != "healthy" {
		t.Fatalf("expected healthy integrity, got %s with checks=%v", integrity.Status, integrity.Checks)
	}
}

func TestApprovalRequestSendsSlackWebhookNotification(t *testing.T) {
	store := newGovernanceStore(t)
	mailer := &mockEmailSender{}
	svc := NewService(store, nil, mailer, &mockCallbackExecutor{}, "http://localhost:8050")
	webhookHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST webhook call, got %s", r.Method)
		}
		webhookHits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	_, err := svc.UpdateSettings(context.Background(), GovernanceSettings{
		TenantID:                  "tw1",
		ApprovalDeliveryMode:      "notify",
		NotifyEmail:               false,
		NotifySlack:               true,
		SlackWebhookURL:           server.URL,
		DeliveryWebhookTimeoutSec: 2,
		UpdatedBy:                 "admin",
	})
	if err != nil {
		t.Fatal(err)
	}

	createTestPolicy(t, svc, "tw1", 1, 1, []string{"ops@example.com"})
	_, err = svc.CreateApprovalRequest(context.Background(), CreateApprovalRequestInput{
		TenantID:       "tw1",
		Action:         "key.destroy",
		TargetType:     "key",
		TargetID:       "key-webhook",
		RequesterID:    "u-webhook",
		RequesterEmail: "u-webhook@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if webhookHits != 1 {
		t.Fatalf("expected exactly 1 slack webhook notification, got %d", webhookHits)
	}
	if len(mailer.msgs) != 0 {
		t.Fatalf("expected email delivery disabled, got %d emails", len(mailer.msgs))
	}
}

func extractToken(t *testing.T, body string, action string) string {
	t.Helper()
	re := regexp.MustCompile(`token=([^&\s]+)&action=` + action)
	m := re.FindStringSubmatch(body)
	if len(m) != 2 {
		t.Fatalf("failed to extract %s token from body: %s", action, body)
	}
	return m[1]
}
