package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// ListWatchedDomains returns all watched domains for a tenant.
func (s *SQLStore) ListWatchedDomains(ctx context.Context, tenantID string) ([]WatchedDomain, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, domain, include_subdomains, alert_on_unknown_ca,
       alert_on_expiring_days, enabled, added_at, last_checked_at, cert_count, alert_count
FROM ct_watched_domains
WHERE tenant_id = $1
ORDER BY added_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]WatchedDomain, 0)
	for rows.Next() {
		d, err := scanWatchedDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AddWatchedDomain inserts a new watched domain record.
func (s *SQLStore) AddWatchedDomain(ctx context.Context, d WatchedDomain) (WatchedDomain, error) {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ct_watched_domains (
    id, tenant_id, domain, include_subdomains, alert_on_unknown_ca,
    alert_on_expiring_days, enabled, added_at, cert_count, alert_count
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, 0)
`,
		strings.TrimSpace(d.ID),
		strings.TrimSpace(d.TenantID),
		strings.TrimSpace(d.Domain),
		d.IncludeSubdomains,
		d.AlertOnUnknownCA,
		d.AlertOnExpiringDay,
		d.Enabled,
		d.AddedAt.UTC(),
	)
	if err != nil {
		return WatchedDomain{}, err
	}
	return s.getWatchedDomain(ctx, d.TenantID, d.ID)
}

// UpdateWatchedDomain toggles the enabled state of a watched domain.
func (s *SQLStore) UpdateWatchedDomain(ctx context.Context, tenantID, id string, enabled bool) (WatchedDomain, error) {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ct_watched_domains SET enabled = $1
WHERE tenant_id = $2 AND id = $3
`, enabled, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return WatchedDomain{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return WatchedDomain{}, errStoreNotFound
	}
	return s.getWatchedDomain(ctx, tenantID, id)
}

// DeleteWatchedDomain removes a watched domain record.
func (s *SQLStore) DeleteWatchedDomain(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM ct_watched_domains WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errStoreNotFound
	}
	return nil
}

// ListCTLogEntries returns CT log entries for a tenant, optionally filtered by domain.
func (s *SQLStore) ListCTLogEntries(ctx context.Context, tenantID, domain string, limit int) ([]CTLogEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var rows *sql.Rows
	var err error
	if strings.TrimSpace(domain) != "" {
		rows, err = s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, domain, subject_cn, san_json, issuer, issuer_fingerprint,
       not_before, not_after, serial, ct_log, logged_at, is_known_ca, is_revoked,
       alert_triggered, alert_reason
FROM ct_log_entries
WHERE tenant_id = $1 AND domain = $2
ORDER BY logged_at DESC
LIMIT $3
`, strings.TrimSpace(tenantID), strings.TrimSpace(domain), limit)
	} else {
		rows, err = s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, domain, subject_cn, san_json, issuer, issuer_fingerprint,
       not_before, not_after, serial, ct_log, logged_at, is_known_ca, is_revoked,
       alert_triggered, alert_reason
FROM ct_log_entries
WHERE tenant_id = $1
ORDER BY logged_at DESC
LIMIT $2
`, strings.TrimSpace(tenantID), limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]CTLogEntry, 0)
	for rows.Next() {
		e, scanErr := scanCTLogEntry(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddCTLogEntry inserts a new CT log entry.
func (s *SQLStore) AddCTLogEntry(ctx context.Context, e CTLogEntry) (CTLogEntry, error) {
	sanJSON := mustJSON(e.SANs)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ct_log_entries (
    id, tenant_id, domain, subject_cn, san_json, issuer, issuer_fingerprint,
    not_before, not_after, serial, ct_log, logged_at, is_known_ca, is_revoked,
    alert_triggered, alert_reason
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
`,
		strings.TrimSpace(e.ID),
		strings.TrimSpace(e.TenantID),
		strings.TrimSpace(e.Domain),
		strings.TrimSpace(e.SubjectCN),
		sanJSON,
		strings.TrimSpace(e.Issuer),
		strings.TrimSpace(e.IssuerFingerprint),
		e.NotBefore.UTC(),
		e.NotAfter.UTC(),
		strings.TrimSpace(e.Serial),
		strings.TrimSpace(e.CTLog),
		e.LoggedAt.UTC(),
		e.IsKnownCA,
		e.IsRevoked,
		e.AlertTriggered,
		strings.TrimSpace(e.AlertReason),
	)
	if err != nil {
		return CTLogEntry{}, err
	}
	return e, nil
}

// ListCTAlerts returns all CT alerts for a tenant.
func (s *SQLStore) ListCTAlerts(ctx context.Context, tenantID string) ([]CTAlert, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, domain, entry_id, reason, severity, status, triggered_at, cert_summary
FROM ct_alerts
WHERE tenant_id = $1
ORDER BY triggered_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]CTAlert, 0)
	for rows.Next() {
		a, scanErr := scanCTAlert(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CreateCTAlert inserts a new CT alert.
func (s *SQLStore) CreateCTAlert(ctx context.Context, a CTAlert) (CTAlert, error) {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ct_alerts (
    id, tenant_id, domain, entry_id, reason, severity, status, triggered_at, cert_summary
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
`,
		strings.TrimSpace(a.ID),
		strings.TrimSpace(a.TenantID),
		strings.TrimSpace(a.Domain),
		strings.TrimSpace(a.EntryID),
		strings.TrimSpace(a.Reason),
		strings.TrimSpace(a.Severity),
		strings.TrimSpace(a.Status),
		a.TriggeredAt.UTC(),
		strings.TrimSpace(a.CertSummary),
	)
	if err != nil {
		return CTAlert{}, err
	}
	return a, nil
}

// AcknowledgeCTAlert sets the status of a CT alert to "acknowledged".
func (s *SQLStore) AcknowledgeCTAlert(ctx context.Context, tenantID, id string) (CTAlert, error) {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE ct_alerts SET status = 'acknowledged'
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return CTAlert{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return CTAlert{}, errStoreNotFound
	}
	return s.getCTAlert(ctx, tenantID, id)
}

// --- internal helpers ---

type scannerCT interface {
	Scan(dest ...interface{}) error
}

func (s *SQLStore) getWatchedDomain(ctx context.Context, tenantID, id string) (WatchedDomain, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, domain, include_subdomains, alert_on_unknown_ca,
       alert_on_expiring_days, enabled, added_at, last_checked_at, cert_count, alert_count
FROM ct_watched_domains
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	d, err := scanWatchedDomain(row)
	if errors.Is(err, sql.ErrNoRows) {
		return WatchedDomain{}, errStoreNotFound
	}
	return d, err
}

func (s *SQLStore) getCTAlert(ctx context.Context, tenantID, id string) (CTAlert, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, domain, entry_id, reason, severity, status, triggered_at, cert_summary
FROM ct_alerts
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	a, err := scanCTAlert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CTAlert{}, errStoreNotFound
	}
	return a, err
}

func scanWatchedDomain(row interface {
	Scan(...interface{}) error
}) (WatchedDomain, error) {
	var d WatchedDomain
	var lastCheckedRaw interface{}
	var addedAtRaw interface{}
	err := row.Scan(
		&d.ID, &d.TenantID, &d.Domain,
		&d.IncludeSubdomains, &d.AlertOnUnknownCA, &d.AlertOnExpiringDay,
		&d.Enabled, &addedAtRaw, &lastCheckedRaw,
		&d.CertCount, &d.AlertCount,
	)
	if err != nil {
		return WatchedDomain{}, err
	}
	d.AddedAt = parseTimeValue(addedAtRaw)
	if lastCheckedRaw != nil {
		t := parseTimeValue(lastCheckedRaw)
		if !t.IsZero() {
			d.LastCheckedAt = &t
		}
	}
	return d, nil
}

func scanCTLogEntry(row interface {
	Scan(...interface{}) error
}) (CTLogEntry, error) {
	var e CTLogEntry
	var sanJSON string
	var notBeforeRaw, notAfterRaw, loggedAtRaw interface{}
	err := row.Scan(
		&e.ID, &e.TenantID, &e.Domain, &e.SubjectCN, &sanJSON,
		&e.Issuer, &e.IssuerFingerprint,
		&notBeforeRaw, &notAfterRaw,
		&e.Serial, &e.CTLog, &loggedAtRaw,
		&e.IsKnownCA, &e.IsRevoked, &e.AlertTriggered, &e.AlertReason,
	)
	if err != nil {
		return CTLogEntry{}, err
	}
	e.NotBefore = parseTimeValue(notBeforeRaw)
	e.NotAfter = parseTimeValue(notAfterRaw)
	e.LoggedAt = parseTimeValue(loggedAtRaw)
	e.SANs = parseJSONArrayStringCT(sanJSON)
	return e, nil
}

func scanCTAlert(row interface {
	Scan(...interface{}) error
}) (CTAlert, error) {
	var a CTAlert
	var triggeredAtRaw interface{}
	err := row.Scan(
		&a.ID, &a.TenantID, &a.Domain, &a.EntryID,
		&a.Reason, &a.Severity, &a.Status, &triggeredAtRaw, &a.CertSummary,
	)
	if err != nil {
		return CTAlert{}, err
	}
	a.TriggeredAt = parseTimeValue(triggeredAtRaw)
	return a, nil
}

// parseJSONArrayStringCT parses a JSON array of strings stored in a DB column.
func parseJSONArrayStringCT(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return []string{}
	}
	var raw []interface{}
	_ = json.Unmarshal([]byte(v), &raw)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// BumpCTDomainCertCount increments cert_count and updates last_checked_at for a watched domain.
func (s *SQLStore) BumpCTDomainCertCount(ctx context.Context, tenantID, domain string) {
	_, _ = s.db.SQL().ExecContext(ctx, `
UPDATE ct_watched_domains
SET cert_count = cert_count + 1, last_checked_at = CURRENT_TIMESTAMP
WHERE tenant_id = $1 AND domain = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(domain))
}

// BumpCTDomainAlertCount increments alert_count for a watched domain.
func (s *SQLStore) BumpCTDomainAlertCount(ctx context.Context, tenantID, domain string) {
	_, _ = s.db.SQL().ExecContext(ctx, `
UPDATE ct_watched_domains
SET alert_count = alert_count + 1
WHERE tenant_id = $1 AND domain = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(domain))
}

