package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"vecta-kms/pkg/ssrfguard"
)

// syslogTLS sends CEF records over syslog on TLS (RFC 5425), the input
// QRadar, ArcSight and most collectors accept on port 6514. Plain UDP or TCP
// syslog is not offered: every connection the platform makes is TLS.
// Syslog has no application acknowledgement, so success means every frame
// was written to an established TLS 1.3 session.
type syslogTLS struct {
	addr, serverName string
	roots            *x509.CertPool
	dial             func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newSyslog(f map[string]string, opt Options) (*syslogTLS, error) {
	host, port, err := net.SplitHostPort(f["address"])
	if err != nil || host == "" || port == "" {
		return nil, errors.New("address must be host:port (TLS syslog is usually port 6514)")
	}
	s := &syslogTLS{addr: f["address"], serverName: f["server_name"], dial: opt.Dial}
	if s.serverName == "" {
		s.serverName = host
	}
	if s.dial == nil {
		s.dial = ssrfguard.DialContext
	}
	if pemData := f["ca_pem"]; pemData != "" {
		s.roots = x509.NewCertPool()
		if !s.roots.AppendCertsFromPEM([]byte(pemData)) {
			return nil, errors.New("ca_pem holds no PEM certificate")
		}
	}
	return s, nil
}

func (s *syslogTLS) Send(ctx context.Context, events []Event) (int, error) {
	raw, err := s.dial(ctx, "tcp", s.addr)
	if err != nil {
		return 0, fmt.Errorf("syslog %s: %v", s.serverName, err)
	}
	conn := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: s.serverName, RootCAs: s.roots})
	defer conn.Close() //nolint:errcheck
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return 0, fmt.Errorf("syslog %s: TLS handshake: %v", s.serverName, err)
	}
	var buf bytes.Buffer
	for _, e := range events {
		msg := syslogMessage(e)
		fmt.Fprintf(&buf, "%d %s", len(msg), msg) // RFC 5425 octet counting
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return 0, fmt.Errorf("syslog %s: write: %v", s.serverName, err)
	}
	return 0, nil
}

// syslogMessage is an RFC 5424 message (facility authpriv) whose MSG is CEF.
func syslogMessage(e Event) string {
	sev := map[int]int{10: 2, 8: 3, 5: 4}[cefSeverity(e.Severity, e.Result)]
	if sev == 0 {
		sev = 6
	}
	host := strings.Map(func(r rune) rune {
		if r <= ' ' || r > '~' {
			return -1
		}
		return r
	}, e.NodeID)
	if host == "" {
		host = "-"
	}
	return fmt.Sprintf("<%d>1 %s %s vecta-kms - audit - %s", 10*8+sev, e.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z"), host, CEF(e))
}

// CEF renders an event in ArcSight Common Event Format, which QRadar and
// ArcSight parse natively: the action is the signature ID and name.
func CEF(e Event) string {
	ext := []string{
		"rt=" + fmt.Sprint(e.Timestamp.UnixMilli()),
		"act=" + cefExt(e.Action),
		"outcome=" + cefExt(e.Result),
		"suser=" + cefExt(e.ActorID),
		"externalId=" + cefExt(e.ID),
		"cs1Label=tenant", "cs1=" + cefExt(e.TenantID),
		"cs2Label=service", "cs2=" + cefExt(e.Service),
		"cs3Label=target", "cs3=" + cefExt(strings.TrimSpace(e.TargetType+" "+e.TargetID)),
	}
	if ip := net.ParseIP(e.SourceIP); ip != nil {
		ext = append(ext, "src="+ip.String())
	}
	if e.NodeID != "" {
		ext = append(ext, "dvchost="+cefExt(e.NodeID))
	}
	return fmt.Sprintf("CEF:0|Vecta|KMS||%s|%s|%d|%s", cefHeader(e.Action), cefHeader(e.Action), cefSeverity(e.Severity, e.Result), strings.Join(ext, " "))
}

// cefSeverity maps the event's severity (and a refusal) onto CEF 0-10.
func cefSeverity(severity, result string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 10
	case "high", "error":
		return 8
	case "warning", "medium":
		return 5
	}
	if result == "refused" || result == "failure" {
		return 5
	}
	return 3
}

// CEF escaping: header fields escape \ and |; extension values escape \, =
// and line breaks.
func cefHeader(s string) string {
	return strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\n", " ", "\r", " ").Replace(s)
}

func cefExt(s string) string {
	return strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`).Replace(s)
}
