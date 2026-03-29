package main

import "time"

// WatchedDomain represents a domain being monitored in CT logs.
type WatchedDomain struct {
	ID                 string     `json:"id"`
	TenantID           string     `json:"tenant_id"`
	Domain             string     `json:"domain"`
	IncludeSubdomains  bool       `json:"include_subdomains"`
	AlertOnUnknownCA   bool       `json:"alert_on_unknown_ca"`
	AlertOnExpiringDay int        `json:"alert_on_expiring_days"`
	Enabled            bool       `json:"enabled"`
	AddedAt            time.Time  `json:"added_at"`
	LastCheckedAt      *time.Time `json:"last_checked_at,omitempty"`
	CertCount          int        `json:"cert_count"`
	AlertCount         int        `json:"alert_count"`
}

// CTLogEntry represents a certificate observed in a Certificate Transparency log.
type CTLogEntry struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	Domain           string    `json:"domain"`
	SubjectCN        string    `json:"subject_cn"`
	SANs             []string  `json:"sans"`
	Issuer           string    `json:"issuer"`
	IssuerFingerprint string   `json:"issuer_fingerprint"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	Serial           string    `json:"serial"`
	CTLog            string    `json:"ct_log"`
	LoggedAt         time.Time `json:"logged_at"`
	IsKnownCA        bool      `json:"is_known_ca"`
	IsRevoked        bool      `json:"is_revoked"`
	AlertTriggered   bool      `json:"alert_triggered"`
	AlertReason      string    `json:"alert_reason"`
}

// CTAlert represents an alert triggered by a CT log observation.
type CTAlert struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Domain      string    `json:"domain"`
	EntryID     string    `json:"entry_id"`
	Reason      string    `json:"reason"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	TriggeredAt time.Time `json:"triggered_at"`
	CertSummary string    `json:"cert_summary"`
}

// AddWatchedDomainRequest is the request body for adding a watched domain.
type AddWatchedDomainRequest struct {
	TenantID           string `json:"tenant_id"`
	Domain             string `json:"domain"`
	IncludeSubdomains  bool   `json:"include_subdomains"`
	AlertOnUnknownCA   bool   `json:"alert_on_unknown_ca"`
	AlertOnExpiringDay int    `json:"alert_on_expiring_days"`
}

// ToggleWatchedDomainRequest is the request body for enabling/disabling a watched domain.
type ToggleWatchedDomainRequest struct {
	Enabled bool `json:"enabled"`
}
