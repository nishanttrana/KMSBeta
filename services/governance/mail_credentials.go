package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"vecta-kms/pkg/credstore"
	"vecta-kms/pkg/smtpmail"
	"vecta-kms/pkg/ssrfguard"
)

// The mail relay governance sends through is an "smtp" credential in the
// platform's store (Playbooks → Credentials, docs/SECURITY/CONNECTIONS.md).
// Settings hold its ID; each send opens it as the kms-governance identity
// and keeps the password in memory for that send. Mail is always sent over
// TLS (pkg/smtpmail). Before 8.0.0-beta the relay and its password were
// plaintext columns in governance_settings, and TLS was optional;
// migrateSMTP moves them out.

const smtpCredentialType = "smtp"

// WithCredentials wires the credential store.
func WithCredentials(c credstore.Store) ServiceOption {
	return func(s *Service) { s.creds = c }
}

// errMailNotConfigured: the tenant has no mail relay.
var errMailNotConfigured = errors.New("no mail relay is configured: add an SMTP credential in Playbooks, Credentials and choose it in Governance settings")

// mailer returns the sender for settings: the relay its credential names,
// or the relay an earlier release stored in the settings row until the
// migration has moved it.
func (s *Service) mailer(ctx context.Context, settings GovernanceSettings) (EmailSender, error) {
	if s.email != nil {
		return s.email, nil
	}
	if id := strings.TrimSpace(settings.SMTPConnectionID); id != "" {
		if s.creds == nil {
			return nil, credstore.ErrNotDeployed
		}
		cred, err := s.creds.Resolve(ctx, settings.TenantID, id)
		if err != nil {
			return nil, fmt.Errorf("mail relay credential %s: %w", id, err)
		}
		if cred.Type != smtpCredentialType {
			return nil, fmt.Errorf("credential %s is %s, not an SMTP relay", id, cred.Type)
		}
		// The relay may be on a private range a root administrator approved
		// for the tenant; any other private address is refused at the dial.
		allow, _ := ssrfguard.ParseAllow(cred.PrivateRanges)
		f := cred.Fields
		return &SMTPMailer{cfg: smtpmail.Config{Host: f["host"], Port: f["port"], Username: f["username"], Password: f["password"], From: f["from"], CAPEM: f["ca_pem"]},
			dial: allow.DialContext}, nil
	}
	if strings.TrimSpace(settings.SMTPHost) == "" || strings.TrimSpace(settings.SMTPPort) == "" {
		return nil, errMailNotConfigured
	}
	return &SMTPMailer{cfg: smtpmail.Config{Host: settings.SMTPHost, Port: settings.SMTPPort, Username: settings.SMTPUsername,
		Password: settings.SMTPPassword, From: firstNonEmptyStr(settings.SMTPFrom, legacyFrom)}}, nil
}

// mailConfigured reports whether the tenant has a relay at all.
func mailConfigured(settings GovernanceSettings) bool {
	return strings.TrimSpace(settings.SMTPConnectionID) != "" ||
		(strings.TrimSpace(settings.SMTPHost) != "" && strings.TrimSpace(settings.SMTPPort) != "")
}

// legacyFrom is the sender an earlier release used when none was set.
const legacyFrom = "noreply@vecta.local"

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// applyMailSettings decides what an update may do to the mail relay. A
// relay is chosen only by naming an SMTP credential the caller may attach;
// the relay's address, account and password are never taken inline. Until
// the migration has run, a row's own relay is kept as it is.
func (s *Service) applyMailSettings(ctx context.Context, settings *GovernanceSettings, existing GovernanceSettings) error {
	refuse := func(reason, msg string) error {
		_ = s.publishAudit(ctx, "audit.governance.mail_settings_refused", settings.TenantID, map[string]interface{}{
			"result": "refused", "reason": reason, "severity": "warning", "description": msg, "smtp_connection_id": settings.SMTPConnectionID,
		})
		return errors.New(msg)
	}
	settings.SMTPConnectionID = strings.TrimSpace(settings.SMTPConnectionID)
	if strings.TrimSpace(settings.SMTPPassword) != "" {
		return refuse("inline_credentials_not_accepted", "the SMTP password is no longer sent with the settings: add the mail relay in Playbooks, Credentials and pass its smtp_connection_id")
	}
	inline := func(in, was string) bool { return strings.TrimSpace(in) != "" && strings.TrimSpace(in) != strings.TrimSpace(was) }
	if inline(settings.SMTPHost, existing.SMTPHost) || inline(settings.SMTPUsername, existing.SMTPUsername) || inline(settings.SMTPFrom, existing.SMTPFrom) ||
		(inline(settings.SMTPPort, existing.SMTPPort) && strings.TrimSpace(settings.SMTPHost) != "") {
		return refuse("mail_relay_is_a_credential", "the mail relay is no longer set here: add it in Playbooks, Credentials and pass its smtp_connection_id")
	}
	if settings.SMTPConnectionID == "" {
		// No credential named: keep the relay the row already has.
		settings.SMTPConnectionID = existing.SMTPConnectionID
		settings.SMTPHost, settings.SMTPPort, settings.SMTPUsername = existing.SMTPHost, existing.SMTPPort, existing.SMTPUsername
		settings.SMTPPassword, settings.SMTPFrom = existing.SMTPPassword, existing.SMTPFrom
		return nil
	}
	if settings.SMTPConnectionID != existing.SMTPConnectionID {
		if !credstore.MayAttach(ctx) {
			return refuse("credential_use_not_permitted", "choosing the mail relay needs the compliance.connection.use permission")
		}
		if s.creds == nil {
			return refuse("credentials_not_deployed", credstore.ErrNotDeployed.Error())
		}
		cred, err := s.creds.Resolve(ctx, settings.TenantID, settings.SMTPConnectionID)
		switch {
		case errors.Is(err, credstore.ErrNotFound):
			return refuse("credential_not_found", "smtp_connection_id "+settings.SMTPConnectionID+" does not exist: add it in Playbooks, Credentials")
		case err != nil:
			return refuse("credentials_unavailable", "smtp_connection_id: "+err.Error())
		case cred.Type != smtpCredentialType:
			return refuse("credential_wrong_type", "smtp_connection_id names a "+cred.Type+" credential, not an SMTP relay")
		}
	}
	// The credential is the relay now: the row keeps none of its own.
	settings.SMTPHost, settings.SMTPPort, settings.SMTPUsername, settings.SMTPPassword, settings.SMTPFrom = "", "", "", "", ""
	return nil
}

// migrateSMTP moves each plaintext mail relay into the credential store,
// points the settings at it and clears the smtp_* columns. Primary only: the
// table is replicated. A relay the store won't take (one on a private
// network no root administrator has approved, say) keeps working from the
// row and is reported once.
func (s *Service) migrateSMTP(ctx context.Context, primary func(context.Context) bool) (int, error) {
	if !primary(ctx) || s.creds == nil {
		return 0, nil
	}
	rows, err := s.store.ListLegacySMTP(ctx)
	if err != nil {
		return 0, err
	}
	moved := 0
	var failed []string
	for _, g := range rows {
		fields := map[string]string{"host": g.SMTPHost, "port": firstNonEmptyStr(g.SMTPPort, "587"), "from": firstNonEmptyStr(g.SMTPFrom, legacyFrom)}
		if g.SMTPUsername != "" {
			fields["username"], fields["password"] = g.SMTPUsername, g.SMTPPassword
		}
		// exposed: a password was stored in plaintext; old database copies
		// and backups still hold it.
		id, err := s.creds.Import(ctx, g.TenantID, "governance_smtp", "Governance mail relay (migrated)", smtpCredentialType, fields, g.SMTPPassword != "")
		if err == nil {
			err = s.store.SetSMTPConnection(ctx, g.TenantID, id)
		}
		if err != nil {
			failed = append(failed, g.TenantID)
			s.smtpMu.Lock()
			reported := s.smtpReported[g.TenantID]
			s.smtpReported[g.TenantID] = true
			s.smtpMu.Unlock()
			if !reported {
				_ = s.publishAudit(ctx, "audit.governance.smtp_migration_refused", g.TenantID, map[string]interface{}{
					"result": "refused", "reason": "credential_store_refused", "severity": "warning", "error": err.Error(), "smtp_host": g.SMTPHost,
					"description": "mail keeps going through the relay stored in governance settings; add an SMTP credential in Playbooks, Credentials and choose it",
				})
			}
			continue
		}
		moved++
		details := map[string]interface{}{"connection_id": id, "smtp_host": g.SMTPHost, "result": "success"}
		if g.SMTPPassword != "" {
			details["severity"] = "warning"
			details["exposure"] = "the SMTP password was stored in plaintext by an earlier release; change it on the mail relay and enter the new one on the credential"
		}
		_ = s.publishAudit(ctx, "audit.governance.smtp_migrated", g.TenantID, details)
	}
	if len(failed) > 0 {
		return moved, errors.New("mail relays not moved yet, retrying: " + strings.Join(failed, ", "))
	}
	return moved, nil
}

func (s *Service) migrateSMTPLoop(ctx context.Context, primary func(context.Context) bool, interval time.Duration, logf func(string, ...interface{})) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := s.migrateSMTP(ctx, primary); err != nil {
			logf("mail relay: %v", err)
		} else if n > 0 {
			logf("mail relay: moved %d plaintext SMTP setting(s) into the credential store", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
