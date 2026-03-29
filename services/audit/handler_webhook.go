package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (h *Handler) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.store.ListWebhooks(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

func (h *Handler) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	var req CreateWebhookRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "validation_error", "name is required", reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.URL) == "" {
		writeErr(w, http.StatusBadRequest, "validation_error", "url is required", reqID, tenantID)
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	format := strings.TrimSpace(req.Format)
	if format == "" {
		format = "json"
	}
	headers := req.Headers
	if headers == nil {
		headers = map[string]string{}
	}
	events := req.Events
	if events == nil {
		events = []string{}
	}
	wh := Webhook{
		TenantID: tenantID,
		Name:     strings.TrimSpace(req.Name),
		URL:      strings.TrimSpace(req.URL),
		Format:   format,
		Events:   events,
		Secret:   req.Secret,
		Headers:  headers,
		Enabled:  enabled,
	}
	created, err := h.store.CreateWebhook(r.Context(), wh)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"webhook":    created,
		"request_id": reqID,
	})
}

func (h *Handler) handleUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := r.PathValue("id")
	existing, err := h.store.GetWebhook(r.Context(), tenantID, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "webhook not found", reqID, tenantID)
		return
	}
	var req UpdateWebhookRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if req.Name != nil {
		existing.Name = strings.TrimSpace(*req.Name)
	}
	if req.URL != nil {
		existing.URL = strings.TrimSpace(*req.URL)
	}
	if req.Format != nil {
		existing.Format = strings.TrimSpace(*req.Format)
	}
	if req.Events != nil {
		existing.Events = req.Events
	}
	if req.Secret != nil {
		existing.Secret = *req.Secret
	}
	if req.Headers != nil {
		existing.Headers = *req.Headers
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	updated, err := h.store.UpdateWebhook(r.Context(), tenantID, id, existing)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "update_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"webhook":    updated,
		"request_id": reqID,
	})
}

func (h *Handler) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := r.PathValue("id")
	if err := h.store.DeleteWebhook(r.Context(), tenantID, id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "webhook not found", reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"deleted":    true,
		"id":         id,
		"request_id": reqID,
	})
}

func (h *Handler) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := r.PathValue("id")
	wh, err := h.store.GetWebhook(r.Context(), tenantID, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "webhook not found", reqID, tenantID)
		return
	}

	testPayload := map[string]interface{}{
		"event_type": "test",
		"tenant_id":  tenantID,
		"webhook_id": wh.ID,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"data": map[string]interface{}{
			"message": "This is a test delivery from Vecta KMS",
		},
	}
	payloadBytes, _ := json.Marshal(testPayload)

	var sig string
	if wh.Secret != "" {
		mac := hmac.New(sha256.New, []byte(wh.Secret))
		mac.Write(payloadBytes)
		sig = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, wh.URL, bytes.NewReader(payloadBytes))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_url", fmt.Sprintf("cannot build request: %s", err.Error()), reqID, tenantID)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VectaKMS-Webhook/1.0")
	if sig != "" {
		req.Header.Set("X-KMS-Signature", sig)
	}
	for k, v := range wh.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, deliveryErr := client.Do(req)
	latencyMs := int(time.Since(start).Milliseconds())

	delivery := WebhookDelivery{
		ID:             newID("wd"),
		TenantID:       tenantID,
		WebhookID:      wh.ID,
		EventType:      "test",
		PayloadPreview: truncateString(string(payloadBytes), 512),
		DeliveredAt:    time.Now().UTC(),
		LatencyMs:      latencyMs,
		Attempt:        1,
	}

	success := false
	httpStatus := 0
	var errMsg string

	if deliveryErr != nil {
		delivery.Status = "failure"
		delivery.Error = deliveryErr.Error()
		errMsg = deliveryErr.Error()
	} else {
		defer resp.Body.Close() //nolint:errcheck
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		httpStatus = resp.StatusCode
		delivery.HTTPStatus = httpStatus
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			delivery.Status = "success"
			success = true
		} else {
			delivery.Status = "failure"
			errMsg = fmt.Sprintf("non-2xx response: %d", resp.StatusCode)
			delivery.Error = errMsg
		}
	}

	_ = h.store.RecordDelivery(r.Context(), delivery)
	_ = h.store.UpdateLastDelivery(r.Context(), tenantID, wh.ID, delivery.Status, delivery.DeliveredAt)
	if !success {
		_ = h.store.IncrementFailureCount(r.Context(), tenantID, wh.ID)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":    success,
		"status":     delivery.Status,
		"http_status": httpStatus,
		"latency_ms": latencyMs,
		"error":      errMsg,
		"request_id": reqID,
	})
}

func (h *Handler) handleListDeliveries(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := r.PathValue("id")
	limit := atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	items, err := h.store.ListDeliveries(r.Context(), tenantID, id, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
