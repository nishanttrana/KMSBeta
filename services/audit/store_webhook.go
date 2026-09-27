package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

const webhookColumns = `id, tenant_id, name, url, format, events_json, secret, headers_json,
       enabled, failure_count, last_delivery_at, COALESCE(last_delivery_status,''),
       created_at, updated_at, has_secret, creds_ciphertext, creds_data_iv,
       creds_wrapped_dek, creds_wrapped_dek_iv`

// errPlaintextCredentials: credentials reach the store only sealed.
var errPlaintextCredentials = errors.New("webhook credentials must be sealed before they are stored")

// storedCreds returns the columns a webhook is written with: header names
// only, no secret, and the sealed envelope (NULLs when there is none).
func storedCreds(w Webhook) (string, []interface{}, error) {
	if hasCredentials(w.Secret, w.Headers) {
		return "", nil, errPlaintextCredentials
	}
	names, _ := json.Marshal(headerNames(w.Headers))
	if w.Sealed == nil {
		return string(names), []interface{}{nil, nil, nil, nil}, nil
	}
	return string(names), []interface{}{w.Sealed.Ciphertext, w.Sealed.DataIV, w.Sealed.WrappedDEK, w.Sealed.WrappedDEKIV}, nil
}

// ListWebhooks returns all webhooks for a tenant.
func (s *SQLStore) ListWebhooks(ctx context.Context, tenantID string) ([]Webhook, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+webhookColumns+`
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
	row := s.db.SQL().QueryRowContext(ctx, `SELECT `+webhookColumns+`
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
	headersJSON, creds, err := storedCreds(w)
	if err != nil {
		return Webhook{}, err
	}
	args := append([]interface{}{w.ID, w.TenantID, w.Name, w.URL, w.Format, string(eventsJSON), headersJSON,
		w.Enabled, w.FailureCount, w.CreatedAt, w.UpdatedAt, w.HasSecret}, creds...)
	if _, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO webhooks (id, tenant_id, name, url, format, events_json, secret, headers_json,
                      enabled, failure_count, created_at, updated_at, has_secret,
                      creds_ciphertext, creds_data_iv, creds_wrapped_dek, creds_wrapped_dek_iv)
VALUES ($1,$2,$3,$4,$5,$6,'',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
`, args...); err != nil {
		return Webhook{}, err
	}
	return s.GetWebhook(ctx, w.TenantID, w.ID)
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
	headersJSON, creds, err := storedCreds(w)
	if err != nil {
		return Webhook{}, err
	}
	args := append([]interface{}{w.Name, w.URL, w.Format, string(eventsJSON), headersJSON,
		w.Enabled, w.UpdatedAt, w.HasSecret}, creds...)
	args = append(args, tenantID, id)
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE webhooks
SET name=$1, url=$2, format=$3, events_json=$4, secret='', headers_json=$5,
    enabled=$6, updated_at=$7, has_secret=$8,
    creds_ciphertext=$9, creds_data_iv=$10, creds_wrapped_dek=$11, creds_wrapped_dek_iv=$12
WHERE tenant_id=$13 AND id=$14
`, args...)
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

// ListPlaintextWebhooks returns rows an earlier release wrote with the
// secret or header values in plaintext (all tenants; the seal job's input).
func (s *SQLStore) ListPlaintextWebhooks(ctx context.Context) ([]Webhook, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+webhookColumns+`
FROM webhooks
WHERE creds_wrapped_dek IS NULL AND (secret <> '' OR headers_json NOT IN ('', '{}'))
ORDER BY tenant_id, id`)
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

// SealPlaintextWebhook replaces a plaintext row's credentials with w's
// envelope, only if the row is still unsealed. It reports whether it did.
func (s *SQLStore) SealPlaintextWebhook(ctx context.Context, w Webhook) (bool, error) {
	headersJSON, creds, err := storedCreds(w)
	if err != nil {
		return false, err
	}
	args := append([]interface{}{headersJSON, w.HasSecret}, creds...)
	args = append(args, w.TenantID, w.ID)
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE webhooks
SET secret='', headers_json=$1, has_secret=$2,
    creds_ciphertext=$3, creds_data_iv=$4, creds_wrapped_dek=$5, creds_wrapped_dek_iv=$6
WHERE tenant_id=$7 AND id=$8 AND creds_wrapped_dek IS NULL`, args...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
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
	var ct, dataIV, wrappedDEK, wrappedIV []byte
	err := scanner.Scan(
		&w.ID, &w.TenantID, &w.Name, &w.URL, &w.Format,
		&eventsRaw, &w.Secret, &headersRaw,
		&w.Enabled, &w.FailureCount, &lastDeliveryRaw, &w.LastDeliveryStatus,
		&createdRaw, &updatedRaw, &w.HasSecret, &ct, &dataIV, &wrappedDEK, &wrappedIV,
	)
	if err != nil {
		return Webhook{}, err
	}
	if len(wrappedDEK) > 0 {
		w.Sealed = &pkgcrypto.EnvelopeCiphertext{Ciphertext: ct, DataIV: dataIV, WrappedDEK: wrappedDEK, WrappedDEKIV: wrappedIV}
	}
	if w.Secret != "" {
		w.HasSecret = true // an earlier release's plaintext row, until it is sealed
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
