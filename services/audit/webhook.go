package main

import (
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Webhook is an event stream: the tenant's audit events that match Events,
// delivered through a compliance connection (ConnectionID). URL, Format,
// Secret, Headers and Sealed are set only on a stream an earlier release
// stored with its own credentials (Legacy) until the migration job moves
// them into a connection (stream_migration.go).
type Webhook struct {
	ID             string   `json:"id"`
	TenantID       string   `json:"tenant_id"`
	Name           string   `json:"name"`
	ConnectionID   string   `json:"connection_id"`
	ConnectionType string   `json:"connection_type"`
	Legacy         bool     `json:"legacy"`
	URL            string   `json:"url,omitempty"`
	Format         string   `json:"format,omitempty"`
	Events         []string `json:"events"`
	// Secret and Headers hold plaintext only in memory, after credVault.Open
	// (or for a row an earlier release stored in plaintext, until it is
	// sealed). The store writes header names only and never the secret.
	Secret    string            `json:"-"`
	HasSecret bool              `json:"has_secret"`
	Headers   map[string]string `json:"headers"`
	// Sealed holds the secret and header values under the audit service
	// master key (webhook_creds.go).
	Sealed             *pkgcrypto.EnvelopeCiphertext `json:"-"`
	Enabled            bool                          `json:"enabled"`
	FailureCount       int                           `json:"failure_count"`
	LastDeliveryAt     *time.Time                    `json:"last_delivery_at,omitempty"`
	LastDeliveryStatus string                        `json:"last_delivery_status,omitempty"`
	CreatedAt          time.Time                     `json:"created_at"`
	UpdatedAt          time.Time                     `json:"updated_at"`
}

// WebhookDelivery records a single delivery attempt for a webhook.
type WebhookDelivery struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	WebhookID      string    `json:"webhook_id"`
	EventType      string    `json:"event_type"`
	PayloadPreview string    `json:"payload_preview"`
	Status         string    `json:"status"`
	HTTPStatus     int       `json:"http_status"`
	DeliveredAt    time.Time `json:"delivered_at"`
	LatencyMs      int       `json:"latency_ms"`
	Error          string    `json:"error"`
	Attempt        int       `json:"attempt"`
}

// CreateWebhookRequest creates an event stream. URL, Format, Secret and
// Headers are refused: streams send through a connection.
type CreateWebhookRequest struct {
	TenantID     string            `json:"tenant_id"` // enforced by the kernel
	Name         string            `json:"name"`
	ConnectionID string            `json:"connection_id"`
	URL          string            `json:"url"`
	Format       string            `json:"format"`
	Events       []string          `json:"events"`
	Secret       string            `json:"secret"`
	Headers      map[string]string `json:"headers"`
	Enabled      *bool             `json:"enabled"`
}

// UpdateWebhookRequest is the request body for updating an existing webhook.
// A header sent with an empty value keeps its stored value (values are never
// returned); clear_secret removes the signing secret.
type UpdateWebhookRequest struct {
	TenantID     string             `json:"tenant_id"` // enforced by the kernel
	Name         *string            `json:"name"`
	ConnectionID *string            `json:"connection_id"`
	URL          *string            `json:"url"`
	Format       *string            `json:"format"`
	Events       []string           `json:"events"`
	Secret       *string            `json:"secret"`
	ClearSecret  bool               `json:"clear_secret"`
	Headers      *map[string]string `json:"headers"`
	Enabled      *bool              `json:"enabled"`
}
