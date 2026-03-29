package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ListWebhooks returns all webhooks for a tenant.
func (s *SQLStore) ListWebhooks(ctx context.Context, tenantID string) ([]Webhook, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, url, format, events_json, secret, headers_json,
       enabled, failure_count, last_delivery_at, COALESCE(last_delivery_status,''),
       created_at, updated_at
FROM webhooks
WHERE tenant_id=$1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []Webhook
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// GetWebhook retrieves a single webhook by tenant and id.
func (s *SQLStore) GetWebhook(ctx context.Context, tenantID, id string) (Webhook, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, url, format, events_json, secret, headers_json,
       enabled, failure_count, last_delivery_at, COALESCE(last_delivery_status,''),
       created_at, updated_at
FROM webhooks
WHERE tenant_id=$1 AND id=$2
`, tenantID, id)
	w, err := scanWebhook(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Webhook{}, errNotFound
	}
	return w, err
}

// CreateWebhook inserts a new webhook record.
func (s *SQLStore) CreateWebhook(ctx context.Context, w Webhook) (Webhook, error) {
	if w.ID == "" {
		w.ID = newID("wh")
	}
	now := time.Now().UTC()
	w.CreatedAt = now
	w.UpdatedAt = now
	if w.Format == "" {
		w.Format = "json"
	}
	if w.Events == nil {
		w.Events = []string{}
	}
	if w.Headers == nil {
		w.Headers = map[string]string{}
	}
	eventsJSON, _ := json.Marshal(w.Events)
	headersJSON, _ := json.Marshal(w.Headers)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO webhooks (id, tenant_id, name, url, format, events_json, secret, headers_json,
                      enabled, failure_count, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
`, w.ID, w.TenantID, w.Name, w.URL, w.Format, string(eventsJSON), w.Secret, string(headersJSON),
		w.Enabled, w.FailureCount, w.CreatedAt, w.UpdatedAt)
	if err != nil {
		return Webhook{}, err
	}
	return w, nil
}

// UpdateWebhook applies changes to an existing webhook.
func (s *SQLStore) UpdateWebhook(ctx context.Context, tenantID, id string, w Webhook) (Webhook, error) {
	w.UpdatedAt = time.Now().UTC()
	if w.Events == nil {
		w.Events = []string{}
	}
	if w.Headers == nil {
		w.Headers = map[string]string{}
	}
	eventsJSON, _ := json.Marshal(w.Events)
	headersJSON, _ := json.Marshal(w.Headers)
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE webhooks
SET name=$1, url=$2, format=$3, events_json=$4, secret=$5, headers_json=$6,
    enabled=$7, updated_at=$8
WHERE tenant_id=$9 AND id=$10
`, w.Name, w.URL, w.Format, string(eventsJSON), w.Secret, string(headersJSON),
		w.Enabled, w.UpdatedAt, tenantID, id)
	if err != nil {
		return Webhook{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return Webhook{}, errNotFound
	}
	return s.GetWebhook(ctx, tenantID, id)
}

// DeleteWebhook removes a webhook by tenant and id.
func (s *SQLStore) DeleteWebhook(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM webhooks WHERE tenant_id=$1 AND id=$2
`, tenantID, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

// RecordDelivery inserts a delivery record for a webhook.
func (s *SQLStore) RecordDelivery(ctx context.Context, d WebhookDelivery) error {
	if d.ID == "" {
		d.ID = newID("wd")
	}
	if d.DeliveredAt.IsZero() {
		d.DeliveredAt = time.Now().UTC()
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO webhook_deliveries (id, tenant_id, webhook_id, event_type, payload_preview,
                                status, http_status, delivered_at, latency_ms, error, attempt)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (tenant_id, id) DO NOTHING
`, d.ID, d.TenantID, d.WebhookID, d.EventType, d.PayloadPreview,
		d.Status, d.HTTPStatus, d.DeliveredAt, d.LatencyMs, d.Error, d.Attempt)
	return err
}

// ListDeliveries returns recent delivery records for a webhook.
func (s *SQLStore) ListDeliveries(ctx context.Context, tenantID, webhookID string, limit int) ([]WebhookDelivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, webhook_id, event_type, payload_preview, status,
       COALESCE(http_status,0), delivered_at, latency_ms, error, attempt
FROM webhook_deliveries
WHERE tenant_id=$1 AND webhook_id=$2
ORDER BY delivered_at DESC
LIMIT $3
`, tenantID, webhookID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []WebhookDelivery
	for rows.Next() {
		var d WebhookDelivery
		var deliveredRaw interface{}
		err := rows.Scan(
			&d.ID, &d.TenantID, &d.WebhookID, &d.EventType, &d.PayloadPreview,
			&d.Status, &d.HTTPStatus, &deliveredRaw, &d.LatencyMs, &d.Error, &d.Attempt,
		)
		if err != nil {
			return nil, err
		}
		d.DeliveredAt = parseTimeValue(deliveredRaw)
		out = append(out, d)
	}
	return out, rows.Err()
}

// IncrementFailureCount increments the failure_count for a webhook by 1.
func (s *SQLStore) IncrementFailureCount(ctx context.Context, tenantID, id string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE webhooks
SET failure_count = failure_count + 1, updated_at = CURRENT_TIMESTAMP
WHERE tenant_id=$1 AND id=$2
`, tenantID, id)
	return err
}

// UpdateLastDelivery records the time and status of the last delivery attempt.
func (s *SQLStore) UpdateLastDelivery(ctx context.Context, tenantID, id, status string, at time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE webhooks
SET last_delivery_at=$1, last_delivery_status=$2, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$3 AND id=$4
`, at, status, tenantID, id)
	return err
}

// scanWebhook scans a row into a Webhook struct.
func scanWebhook(scanner interface {
	Scan(dest ...interface{}) error
}) (Webhook, error) {
	var w Webhook
	var eventsRaw string
	var headersRaw string
	var lastDeliveryRaw interface{}
	var createdRaw interface{}
	var updatedRaw interface{}
	err := scanner.Scan(
		&w.ID, &w.TenantID, &w.Name, &w.URL, &w.Format,
		&eventsRaw, &w.Secret, &headersRaw,
		&w.Enabled, &w.FailureCount, &lastDeliveryRaw, &w.LastDeliveryStatus,
		&createdRaw, &updatedRaw,
	)
	if err != nil {
		return Webhook{}, err
	}
	w.CreatedAt = parseTimeValue(createdRaw)
	w.UpdatedAt = parseTimeValue(updatedRaw)
	t := parseTimeValue(lastDeliveryRaw)
	if !t.IsZero() {
		w.LastDeliveryAt = &t
	}
	eventsRaw = strings.TrimSpace(eventsRaw)
	if eventsRaw == "" {
		eventsRaw = "[]"
	}
	_ = json.Unmarshal([]byte(eventsRaw), &w.Events)
	if w.Events == nil {
		w.Events = []string{}
	}
	headersRaw = strings.TrimSpace(headersRaw)
	if headersRaw == "" {
		headersRaw = "{}"
	}
	_ = json.Unmarshal([]byte(headersRaw), &w.Headers)
	if w.Headers == nil {
		w.Headers = map[string]string{}
	}
	return w, nil
}
