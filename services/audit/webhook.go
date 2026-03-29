package main

import "time"

// Webhook represents a registered webhook endpoint for event delivery.
type Webhook struct {
	ID                 string            `json:"id"`
	TenantID           string            `json:"tenant_id"`
	Name               string            `json:"name"`
	URL                string            `json:"url"`
	Format             string            `json:"format"`
	Events             []string          `json:"events"`
	Secret             string            `json:"secret"`
	Headers            map[string]string `json:"headers"`
	Enabled            bool              `json:"enabled"`
	FailureCount       int               `json:"failure_count"`
	LastDeliveryAt     *time.Time        `json:"last_delivery_at,omitempty"`
	LastDeliveryStatus string            `json:"last_delivery_status,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
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

// CreateWebhookRequest is the request body for creating a new webhook.
type CreateWebhookRequest struct {
	Name    string            `json:"name"`
	URL     string            `json:"url"`
	Format  string            `json:"format"`
	Events  []string          `json:"events"`
	Secret  string            `json:"secret"`
	Headers map[string]string `json:"headers"`
	Enabled *bool             `json:"enabled"`
}

// UpdateWebhookRequest is the request body for updating an existing webhook.
type UpdateWebhookRequest struct {
	Name    *string            `json:"name"`
	URL     *string            `json:"url"`
	Format  *string            `json:"format"`
	Events  []string           `json:"events"`
	Secret  *string            `json:"secret"`
	Headers *map[string]string `json:"headers"`
	Enabled *bool              `json:"enabled"`
}
