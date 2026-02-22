package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type EmailMessage struct {
	To      string
	Subject string
	Body    string
}

type EmailSender interface {
	Send(ctx context.Context, msg EmailMessage) error
}

type SMTPConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
	StartTLS bool
}

type SMTPMailer struct {
	cfg SMTPConfig
}

func NewSMTPMailer(cfg SMTPConfig) *SMTPMailer {
	return &SMTPMailer{cfg: cfg}
}

func (m *SMTPMailer) Send(ctx context.Context, msg EmailMessage) error {
	if strings.TrimSpace(msg.To) == "" {
		return errors.New("recipient email is required")
	}
	host := strings.TrimSpace(m.cfg.Host)
	port := strings.TrimSpace(m.cfg.Port)
	if host == "" || port == "" {
		return errors.New("smtp host/port not configured")
	}
	from := strings.TrimSpace(m.cfg.From)
	if from == "" {
		from = "noreply@vecta.local"
	}
	addr := net.JoinHostPort(host, port)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer c.Quit() //nolint:errcheck

	if m.cfg.StartTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			tlsCfg := &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS12,
			}
			if err := c.StartTLS(tlsCfg); err != nil {
				return err
			}
		}
	}
	if strings.TrimSpace(m.cfg.Username) != "" {
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, host)
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(msg.To); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	raw := buildRFC822Message(from, msg.To, msg.Subject, msg.Body)
	if _, err := w.Write([]byte(raw)); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}

func buildRFC822Message(from string, to string, subject string, body string) string {
	headers := []string{
		"From: " + from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body + "\r\n"
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
