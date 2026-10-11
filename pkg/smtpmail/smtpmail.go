// Package smtpmail sends mail through a customer's SMTP relay, always over
// TLS: implicit TLS on port 465, STARTTLS on any other port. A relay that
// offers neither is refused before any credential or message is sent.
package smtpmail

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Config is a relay and the account to sign in with (Username may be empty
// for a relay that accepts by source address).
type Config struct {
	Host, Port, Username, Password, From string
	// CAPEM, when set, is the CA the relay's certificate must chain to (a
	// relay with a certificate from a private CA); otherwise the system
	// roots apply.
	CAPEM string
}

// DialFunc opens the TCP connection; the caller passes its outbound guard.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// ErrNoTLS is a relay that does not offer TLS.
var ErrNoTLS = errors.New("the mail relay does not offer TLS (STARTTLS, or implicit TLS on port 465); mail is never sent in the clear")

// Message is one plain-text mail.
type Message struct {
	To, Subject, Body string
}

// connect opens an authenticated TLS session with the relay.
func connect(ctx context.Context, cfg Config, dial DialFunc) (*smtp.Client, error) {
	host, port := strings.TrimSpace(cfg.Host), strings.TrimSpace(cfg.Port)
	if host == "" || port == "" {
		return nil, errors.New("smtp host and port are required")
	}
	if dial == nil {
		d := net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	// FIPS exception: external protocol mandate. Mail relays in common use
	// still negotiate TLS 1.2; TLS 1.3 is used whenever the relay offers it.
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if pem := strings.TrimSpace(cfg.CAPEM); pem != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			_ = conn.Close()
			return nil, errors.New("ca_pem holds no certificate")
		}
		tlsCfg.RootCAs = pool
	}
	if port == "465" {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("TLS handshake with %s: %w", host, err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if port != "465" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			_ = c.Close()
			return nil, ErrNoTLS
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("STARTTLS with %s: %w", host, err)
		}
	}
	if strings.TrimSpace(cfg.Username) != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, host)); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("%s refused the sign-in: %w", host, err)
		}
	}
	return c, nil
}

// Check signs in to the relay over TLS and leaves without sending anything.
func Check(ctx context.Context, cfg Config, dial DialFunc) error {
	c, err := connect(ctx, cfg, dial)
	if err != nil {
		return err
	}
	return c.Quit()
}

// Send delivers msg.
func Send(ctx context.Context, cfg Config, dial DialFunc, msg Message) error {
	to, from := strings.TrimSpace(msg.To), strings.TrimSpace(cfg.From)
	if to == "" {
		return errors.New("recipient email is required")
	}
	if from == "" {
		return errors.New("a from address is required")
	}
	if strings.ContainsAny(to+from+msg.Subject, "\r\n") {
		return errors.New("addresses and subject can't contain line breaks")
	}
	c, err := connect(ctx, cfg, dial)
	if err != nil {
		return err
	}
	defer c.Close() //nolint:errcheck
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	headers := []string{"From: " + from, "To: " + to, "Subject: " + msg.Subject, "MIME-Version: 1.0", "Content-Type: text/plain; charset=UTF-8"}
	if _, err := w.Write([]byte(strings.Join(headers, "\r\n") + "\r\n\r\n" + msg.Body + "\r\n")); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
