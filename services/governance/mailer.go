package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"vecta-kms/pkg/smtpmail"
)

type EmailMessage struct {
	To      string
	Subject string
	Body    string
}

type EmailSender interface {
	Send(ctx context.Context, msg EmailMessage) error
}

// SMTPMailer sends through one relay, always over TLS (pkg/smtpmail):
// implicit TLS on port 465, STARTTLS on any other, and a relay that offers
// neither is refused before the password or the message is sent. dial is
// the outbound guard for a relay taken from a credential; nil dials
// directly (a relay an earlier release stored in the settings row).
type SMTPMailer struct {
	cfg  smtpmail.Config
	dial smtpmail.DialFunc
}

func (m *SMTPMailer) Send(ctx context.Context, msg EmailMessage) error {
	return smtpmail.Send(ctx, m.cfg, m.dial, smtpmail.Message{To: msg.To, Subject: msg.Subject, Body: msg.Body})
}

func buildApprovalEmailBody(baseURL string, request ApprovalRequest, approveToken string, denyToken string, challengeCode string, challengeEnabled bool) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	approveURL := fmt.Sprintf("%s/governance/approve/%s?token=%s&action=approve", base, request.ID, approveToken)
	denyURL := fmt.Sprintf("%s/governance/approve/%s?token=%s&action=deny", base, request.ID, denyToken)
	body := "Approval request received.\n\n" +
		"Tenant: " + request.TenantID + "\n" +
		"Action: " + request.Action + "\n" +
		"Target: " + request.TargetType + ":" + request.TargetID + "\n" +
		"Requester: " + request.RequesterEmail + "\n" +
		"Expires: " + request.ExpiresAt.UTC().Format(time.RFC3339) + "\n\n" +
		"Approve: " + approveURL + "\n" +
		"Deny: " + denyURL + "\n"
	if challengeEnabled && strings.TrimSpace(challengeCode) != "" {
		body += "\nChallenge Code (for dashboard approve/deny): " + challengeCode + "\n"
	}
	return body
}
