package siem

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// QRadarExporter sends audit events to IBM QRadar via syslog in CEF format.
type QRadarExporter struct {
	syslogAddr string
	protocol   string // "udp" or "tcp"
	conn       net.Conn
}

// NewQRadarExporter creates a QRadar destination. Protocol should be "udp" or "tcp".
func NewQRadarExporter(syslogAddr, protocol string) *QRadarExporter {
	if protocol == "" {
		protocol = "udp"
	}
	return &QRadarExporter{
		syslogAddr: syslogAddr,
		protocol:   protocol,
	}
}

func (q *QRadarExporter) Name() string { return "qradar" }

// Send formats events as CEF (Common Event Format) and sends via syslog.
func (q *QRadarExporter) Send(ctx context.Context, events []AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	conn, err := net.DialTimeout(q.protocol, q.syslogAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("qradar: dial %s/%s: %w", q.syslogAddr, q.protocol, err)
	}
	defer conn.Close()

	for _, evt := range events {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		cef := formatCEF(evt)
		if q.protocol == "tcp" {
			// TCP syslog uses newline as message delimiter
			cef += "\n"
		}

		if _, err := conn.Write([]byte(cef)); err != nil {
			return fmt.Errorf("qradar: write event %s: %w", evt.ID, err)
		}
	}

	return nil
}

// formatCEF builds a CEF-formatted syslog message per ArcSight CEF spec.
// Format: CEF:Version|Device Vendor|Device Product|Device Version|Event ID|Event Name|Severity|Extensions
func formatCEF(evt AuditEvent) string {
	// Map severity 0-10 to CEF 0-10 (they align)
	severity := evt.Severity
	if severity > 10 {
		severity = 10
	}
	if severity < 0 {
		severity = 0
	}

	// Build extension key-value pairs
	extensions := []string{
		fmt.Sprintf("src=%s", escapeCEF(evt.SourceIP)),
		fmt.Sprintf("suser=%s", escapeCEF(evt.Actor)),
		fmt.Sprintf("cs1=%s", escapeCEF(evt.TenantID)),
		fmt.Sprintf("cs1Label=TenantID"),
		fmt.Sprintf("cs2=%s", escapeCEF(evt.KeyID)),
		fmt.Sprintf("cs2Label=KeyID"),
		fmt.Sprintf("outcome=%s", escapeCEF(evt.Outcome)),
		fmt.Sprintf("rt=%d", evt.Timestamp.UnixMilli()),
	}

	// Add metadata as custom string fields
	idx := 3
	for k, v := range evt.Metadata {
		if idx > 6 {
			break // CEF supports cs1-cs6
		}
		extensions = append(extensions,
			fmt.Sprintf("cs%d=%s", idx, escapeCEF(v)),
			fmt.Sprintf("cs%dLabel=%s", idx, escapeCEF(k)),
		)
		idx++
	}

	return fmt.Sprintf("CEF:0|Vecta|KMS|3.0|%s|%s|%d|%s",
		escapeCEF(evt.ID),
		escapeCEF(evt.Action),
		severity,
		strings.Join(extensions, " "),
	)
}

// escapeCEF escapes characters that have special meaning in CEF format.
func escapeCEF(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
