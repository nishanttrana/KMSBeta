package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/credstore"
)

// mailCreds is the credential store as governance sees it.
type mailCreds struct {
	mu      sync.Mutex
	creds   map[string]credstore.Credential
	exposed map[string]bool
	err     error
}

func newMailCreds() *mailCreds {
	return &mailCreds{exposed: map[string]bool{}, creds: map[string]credstore.Credential{
		"cred-smtp":  {ID: "cred-smtp", Type: "smtp", Fields: map[string]string{"host": "smtp.example.com", "port": "587", "from": "kms@example.com", "username": "kms", "password": "from-the-store"}},
		"cred-slack": {ID: "cred-slack", Type: "slack", Fields: map[string]string{"webhook_url": "https://hooks.slack.com/x"}},
	}}
}

func (c *mailCreds) Resolve(_ context.Context, _, id string) (credstore.Credential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return credstore.Credential{}, c.err
	}
	cred, ok := c.creds[id]
	if !ok {
		return credstore.Credential{}, credstore.ErrNotFound
	}
	return cred, nil
}

func (c *mailCreds) Import(_ context.Context, tenantID, sourceID, name, typ string, fields map[string]string, exposed bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return "", c.err
	}
	id := "pbconn_governance_" + sourceID + "_" + tenantID
	c.creds[id], c.exposed[id] = credstore.Credential{ID: id, Name: name, Type: typ, Fields: fields}, exposed
	return id, nil
}

func (c *mailCreds) ReportTest(context.Context, string, string, error) error { return nil }

func mailAdmin(tenant string) context.Context {
	return pkgauth.ContextWithClaims(context.Background(), &pkgauth.Claims{UserID: "root-admin", TenantID: tenant, Role: "admin", Permissions: []string{"*"}})
}

// The mail relay is chosen by naming an SMTP credential. Its address,
// account and password are never taken with the settings, and the row then
// holds none of them.
func TestMailRelayIsAnSMTPCredential(t *testing.T) {
	store := newGovernanceStore(t)
	pub := &capturePublisher{}
	creds := newMailCreds()
	svc := NewService(store, pub, nil, &mockCallbackExecutor{}, "https://kms.example", WithCredentials(creds))
	ctx := mailAdmin("root")
	base := GovernanceSettings{TenantID: "root", ApprovalExpiryMinutes: 60, ApprovalDeliveryMode: "notify", NotifyEmail: true}
	refused := func(step string, ctx context.Context, mutate func(*GovernanceSettings), reason string) {
		t.Helper()
		in := base
		mutate(&in)
		if _, err := svc.UpdateSettings(ctx, in); err == nil {
			t.Fatalf("%s: accepted", step)
		}
		ev := pub.last("audit.governance.mail_settings_refused")
		if ev == nil || ev["reason"] != reason || ev["result"] != "refused" {
			t.Fatalf("%s audit: %+v", step, ev)
		}
	}
	refused("inline password", ctx, func(g *GovernanceSettings) { g.SMTPConnectionID, g.SMTPPassword = "cred-smtp", "inline-password" }, "inline_credentials_not_accepted")
	refused("inline relay", ctx, func(g *GovernanceSettings) { g.SMTPHost, g.SMTPPort = "smtp.evil.test", "25" }, "mail_relay_is_a_credential")
	refused("unknown credential", ctx, func(g *GovernanceSettings) { g.SMTPConnectionID = "pbconn_nope" }, "credential_not_found")
	refused("a Slack credential", ctx, func(g *GovernanceSettings) { g.SMTPConnectionID = "cred-slack" }, "credential_wrong_type")
	noUse := pkgauth.ContextWithClaims(context.Background(), &pkgauth.Claims{UserID: "u", TenantID: "root", Role: "ops", Permissions: []string{"governance.write"}})
	refused("caller without the use permission", noUse, func(g *GovernanceSettings) { g.SMTPConnectionID = "cred-smtp" }, "credential_use_not_permitted")
	if got, _ := store.GetSettings(context.Background(), "root"); mailConfigured(got) {
		t.Fatalf("a refused update configured mail: %+v", got)
	}
	if _, err := svc.mailer(context.Background(), base); !errors.Is(err, errMailNotConfigured) {
		t.Fatalf("mail without a relay: %v", err)
	}

	in := base
	in.SMTPConnectionID = "cred-smtp"
	out, err := svc.UpdateSettings(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if out.SMTPConnectionID != "cred-smtp" || out.SMTPHost != "" || out.SMTPPassword != "" || out.SMTPUsername != "" {
		t.Fatalf("settings after choosing a credential: %+v", out)
	}
	sender, err := svc.mailer(context.Background(), out)
	m, ok := sender.(*SMTPMailer)
	if err != nil || !ok || m.cfg.Host != "smtp.example.com" || m.cfg.Password != "from-the-store" || m.cfg.From != "kms@example.com" || m.dial == nil {
		t.Fatalf("mailer from the credential: %v %+v", err, sender)
	}
	// A later update that names no relay keeps the credential.
	again := base
	again.ApprovalExpiryMinutes = 30
	if out, err := svc.UpdateSettings(noUse, again); err != nil || out.SMTPConnectionID != "cred-smtp" || out.ApprovalExpiryMinutes != 30 {
		t.Fatalf("unrelated update: %v %+v", err, out)
	}
	// A credential that is gone, or a store that is down, sends nothing.
	delete(creds.creds, "cred-smtp")
	if _, err := svc.mailer(context.Background(), out); err == nil {
		t.Fatal("mail with a deleted credential")
	}
}

// A relay an earlier release stored in the settings row keeps working until
// the primary moves it into the store, recorded as exposed when a password
// was stored. A member moves nothing; a refused relay is reported once.
func TestPlaintextMailRelayMovesIntoTheStore(t *testing.T) {
	store := newGovernanceStore(t)
	pub := &capturePublisher{}
	creds := newMailCreds()
	svc := NewService(store, pub, nil, &mockCallbackExecutor{}, "https://kms.example", WithCredentials(creds))
	ctx := context.Background()
	legacy := func(tenant, user, pass string) {
		if err := store.UpsertSettings(ctx, GovernanceSettings{TenantID: tenant, SMTPHost: "smtp." + tenant + ".test", SMTPPort: "587", SMTPUsername: user,
			SMTPPassword: pass, ApprovalExpiryMinutes: 60, ExpiryCheckIntervalSeconds: 60, ApprovalDeliveryMode: "notify", DeliveryWebhookTimeoutSec: 5}); err != nil {
			t.Fatal(err)
		}
	}
	legacy("root", "kms", "plaintext-password")
	legacy("t2", "", "")
	got, _ := store.GetSettings(ctx, "root")
	if sender, err := svc.mailer(ctx, got); err != nil || sender.(*SMTPMailer).cfg.Password != "plaintext-password" {
		t.Fatalf("a legacy relay stopped working before migration: %v", err)
	}
	primary, member := func(context.Context) bool { return true }, func(context.Context) bool { return false }
	if n, _ := svc.migrateSMTP(ctx, member); n != 0 {
		t.Fatal("a cluster member migrated a relay")
	}
	creds.err = errors.New("10.0.0.5 is a blocked address")
	for i := 0; i < 2; i++ {
		if n, err := svc.migrateSMTP(ctx, primary); n != 0 || err == nil {
			t.Fatalf("migration with the store refusing: %d %v", n, err)
		}
	}
	if pub.count("audit.governance.smtp_migration_refused") != 2 { // one per tenant, not per attempt
		t.Fatalf("refusal events: %d", pub.count("audit.governance.smtp_migration_refused"))
	}
	creds.err = nil
	n, err := svc.migrateSMTP(ctx, primary)
	if err != nil || n != 2 {
		t.Fatalf("migration: %d %v", n, err)
	}
	got, _ = store.GetSettings(ctx, "root")
	if got.SMTPConnectionID == "" || got.SMTPHost != "" || got.SMTPPassword != "" || got.SMTPUsername != "" {
		t.Fatalf("after migration the row still holds the relay: %+v", got)
	}
	var plain string
	_ = store.db.SQL().QueryRow(`SELECT COALESCE(smtp_password,'') FROM governance_settings WHERE tenant_id='root'`).Scan(&plain)
	if plain != "" {
		t.Fatal("the plaintext password is still in the table")
	}
	moved := creds.creds[got.SMTPConnectionID]
	if moved.Type != "smtp" || moved.Fields["host"] != "smtp.root.test" || moved.Fields["password"] != "plaintext-password" || moved.Fields["from"] != legacyFrom || !creds.exposed[got.SMTPConnectionID] {
		t.Fatalf("migrated relay: %+v exposed=%v", moved.Fields, creds.exposed[got.SMTPConnectionID])
	}
	t2, _ := store.GetSettings(ctx, "t2")
	if creds.exposed[t2.SMTPConnectionID] || creds.creds[t2.SMTPConnectionID].Fields["username"] != "" {
		t.Fatal("a relay without a password was recorded as exposed")
	}
	if ev := pub.last("audit.governance.smtp_migrated"); ev == nil || ev["connection_id"] == "" {
		t.Fatalf("migration audit: %+v", ev)
	}
	if n, _ := svc.migrateSMTP(ctx, primary); n != 0 {
		t.Fatal("a relay was migrated twice")
	}
	if sender, err := svc.mailer(ctx, got); err != nil || !strings.HasPrefix(sender.(*SMTPMailer).cfg.Host, "smtp.root") {
		t.Fatalf("mailer after migration: %v", err)
	}
}

// last returns the data of the newest event on subject, or nil.
func (p *capturePublisher) last(subject string) map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	evs := p.events[subject]
	if len(evs) == 0 {
		return nil
	}
	data, _ := evs[len(evs)-1]["data"].(map[string]interface{})
	return data
}

func (p *capturePublisher) count(subject string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.events[subject])
}
