package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/route"
)

// selfEmitter records the audit service's own kernel events straight into
// its chain (it is the pipeline's sink, so it does not publish to itself).
type selfEmitter struct{ svc *Service }

func (e selfEmitter) Emit(ctx context.Context, action string, evt pkgaudit.Event) error {
	_, _, err := e.svc.ProcessEvent(ctx, AuditEvent{
		TenantID: evt.TenantID, Service: "audit", Action: "audit.audit." + action,
		ActorID: evt.ActorID, ActorType: evt.ActorType, TargetType: evt.TargetType, TargetID: evt.TargetID,
		Result: evt.Result, StatusCode: evt.StatusCode, ErrorMessage: evt.ErrorMessage,
		SourceIP: evt.SourceIP, UserAgent: evt.UserAgent, Method: evt.Method, Endpoint: evt.Endpoint,
		CorrelationID: evt.CorrelationID, DurationMS: evt.DurationMS, Details: evt.Details,
		Timestamp: time.Now().UTC(),
	})
	return err
}

// webhookRouter serves webhook management through the pkg/route kernel.
func (h *Handler) webhookRouter(audit route.Emitter) *route.Router {
	r := route.New("audit", audit, nil)
	r.Handle("GET /webhooks", route.Spec{Action: "webhooks_listed", Permission: "audit.webhook.read", Resource: "webhook"}, h.listWebhooks)
	r.Handle("POST /webhooks", route.Spec{Action: "webhook_created", Permission: "audit.webhook.write", Resource: "webhook", Severity: "warning"}, h.createWebhook)
	r.Handle("PATCH /webhooks/{id}", route.Spec{Action: "webhook_updated", Permission: "audit.webhook.write", Resource: "webhook", TargetParam: "id", Severity: "warning"}, h.updateWebhook)
	r.Handle("DELETE /webhooks/{id}", route.Spec{Action: "webhook_deleted", Permission: "audit.webhook.write", Resource: "webhook", TargetParam: "id", Severity: "warning"}, h.deleteWebhook)
	r.Handle("POST /webhooks/{id}/test", route.Spec{Action: "webhook_tested", Permission: "audit.webhook.write", Resource: "webhook", TargetParam: "id"}, h.testWebhook)
	r.Handle("GET /webhooks/{id}/deliveries", route.Spec{Action: "webhook_deliveries_listed", Permission: "audit.webhook.read", Resource: "webhook", TargetParam: "id"}, h.listDeliveries)
	return r
}

func (h *Handler) fanout() *webhookFanout { return h.svc.webhooks }

func (h *Handler) listWebhooks(c *route.Call) {
	items, err := h.store.ListWebhooks(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "query_failed", "failed to list webhooks")
		return
	}
	out := make([]Webhook, 0, len(items))
	for _, w := range items {
		out = append(out, publicWebhook(w))
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": out})
}

// errInlineEndpoint: streams send through a connection; the URL and
// credentials live in compliance's sealed connections, not here.
const errInlineEndpoint = "event streams send through a connection: create one under Playbooks → Connections and pass connection_id (url, format, secret and headers are no longer accepted)"

func (h *Handler) createWebhook(c *route.Call) {
	var req CreateWebhookRequest
	if !c.Decode(&req) {
		return
	}
	if req.URL != "" || req.Format != "" || req.Secret != "" || len(req.Headers) > 0 {
		c.Error(http.StatusBadRequest, "validation_error", errInlineEndpoint)
		return
	}
	wh := Webhook{
		TenantID: c.Tenant, Name: strings.TrimSpace(req.Name), Events: req.Events,
		Headers: map[string]string{}, Enabled: req.Enabled == nil || *req.Enabled,
	}
	if !h.validStream(c, wh) || !h.attachConnection(c, &wh, req.ConnectionID) {
		return
	}
	wh.ID = newID("wh")
	created, err := h.store.CreateWebhook(c.R.Context(), wh)
	if err != nil {
		c.Error(http.StatusInternalServerError, "create_failed", "failed to create event stream")
		return
	}
	h.webhookChanged(c, created)
	c.JSON(http.StatusCreated, map[string]interface{}{"webhook": publicWebhook(created)})
}

func (h *Handler) validStream(c *route.Call, wh Webhook) bool {
	if wh.Name == "" {
		c.Error(http.StatusBadRequest, "validation_error", "name is required")
		return false
	}
	if err := validateWebhookEvents(wh.Events); err != nil {
		c.Error(http.StatusBadRequest, "validation_error", err.Error())
		return false
	}
	return true
}

// attachConnection points wh at connection id after compliance confirms it
// exists in the tenant and can carry a stream. A legacy stream's own URL and
// credentials are dropped.
func (h *Handler) attachConnection(c *route.Call, wh *Webhook, id string) bool {
	id = strings.TrimSpace(id)
	c.Detail("connection_id", id)
	if id == "" {
		c.Error(http.StatusBadRequest, "validation_error", "connection_id is required")
		return false
	}
	f := h.fanout()
	if f == nil {
		c.Error(http.StatusServiceUnavailable, "webhooks_unavailable", "event stream delivery is not running")
		return false
	}
	conn, _, err := f.conns.get(c.R.Context(), wh.TenantID, id, f.disp.client)
	var ce connError
	switch {
	case errors.As(err, &ce) && ce.Status == http.StatusNotFound:
		c.Error(http.StatusBadRequest, "validation_error", "connection "+id+" not found in this tenant")
		return false
	case errors.As(err, &ce) && ce.Status == http.StatusConflict:
		c.Refuse(http.StatusBadRequest, "connection_not_streamable", ce.Error())
		return false
	case err != nil:
		c.Error(http.StatusServiceUnavailable, "connections_unavailable", err.Error())
		return false
	}
	wh.ConnectionID, wh.ConnectionType, wh.Legacy = conn.ID, conn.Type, false
	wh.URL, wh.Format, wh.Secret, wh.Headers, wh.Sealed, wh.HasSecret = "", "", "", map[string]string{}, nil, false
	return true
}

func (h *Handler) webhookChanged(c *route.Call, wh Webhook) {
	c.Target(wh.ID)
	c.Detail("connection_id", wh.ConnectionID)
	c.Detail("connection_type", wh.ConnectionType)
	c.Detail("legacy", wh.Legacy)
	c.Detail("events", wh.Events)
	c.Detail("enabled", wh.Enabled)
	if f := h.fanout(); f != nil {
		f.Invalidate(wh.TenantID)
	}
}

// retireExposure closes a webhook's exposure register entry (if any) when its
// credentials were replaced or it was deleted.
func (h *Handler) retireExposure(c *route.Call, id, how string) {
	if k, err := h.svc.creds.current(); err == nil {
		k.Retire(c.R.Context(), c.Tenant, webhookCredsItemType, id, how)
	}
}

func hostOf(raw string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}

func (h *Handler) updateWebhook(c *route.Call) {
	var req UpdateWebhookRequest
	if !c.Decode(&req) {
		return
	}
	if req.URL != nil || req.Format != nil || req.Secret != nil || req.ClearSecret || req.Headers != nil {
		c.Error(http.StatusBadRequest, "validation_error", errInlineEndpoint)
		return
	}
	stored, err := h.store.GetWebhook(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		c.Error(http.StatusNotFound, "not_found", "event stream not found")
		return
	}
	wh := stored
	if req.Name != nil {
		wh.Name = strings.TrimSpace(*req.Name)
	}
	if req.Events != nil {
		wh.Events = req.Events
	}
	if req.Enabled != nil {
		wh.Enabled = *req.Enabled
	}
	if !h.validStream(c, wh) {
		return
	}
	repointed := req.ConnectionID != nil && strings.TrimSpace(*req.ConnectionID) != stored.ConnectionID
	if repointed && !h.attachConnection(c, &wh, *req.ConnectionID) {
		return
	}
	if wh.Legacy && hasCredentials(wh.Secret, wh.Headers) {
		// An earlier release's plaintext row edited before the startup job
		// sealed it: register the exposure and seal, as that job would.
		k, err := h.svc.creds.current()
		if err == nil {
			err = k.RecordExposure(c.R.Context(), c.Tenant, webhookCredsItemType, stored.ID, "plaintext_storage")
		}
		if err == nil {
			err = h.svc.creds.Seal(&wh)
		}
		if err != nil {
			c.Error(http.StatusServiceUnavailable, "credentials_key_unavailable", err.Error())
			return
		}
	}
	updated, err := h.store.UpdateWebhook(c.R.Context(), c.Tenant, wh.ID, wh)
	if err != nil {
		c.Error(http.StatusInternalServerError, "update_failed", "failed to update event stream")
		return
	}
	if repointed && stored.Legacy {
		// The platform no longer holds or uses the stream's own credentials.
		h.retireExposure(c, wh.ID, "replaced_by_connection")
		c.Detail("legacy_credentials_dropped", true)
	}
	h.webhookChanged(c, updated)
	c.JSON(http.StatusOK, map[string]interface{}{"webhook": publicWebhook(updated)})
}

func (h *Handler) deleteWebhook(c *route.Call) {
	if err := h.store.DeleteWebhook(c.R.Context(), c.Tenant, c.R.PathValue("id")); err != nil {
		c.Error(http.StatusNotFound, "not_found", "webhook not found")
		return
	}
	h.retireExposure(c, c.R.PathValue("id"), "deleted")
	if f := h.fanout(); f != nil {
		f.Invalidate(c.Tenant)
	}
	c.JSON(http.StatusOK, map[string]interface{}{"deleted": true, "id": c.R.PathValue("id")})
}

// testWebhook sends a labelled test event (action audit.audit.webhook_test)
// through the same delivery path as real events and records the result.
func (h *Handler) testWebhook(c *route.Call) {
	wh, err := h.store.GetWebhook(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		c.Error(http.StatusNotFound, "not_found", "webhook not found")
		return
	}
	f := h.fanout()
	if f == nil {
		c.Error(http.StatusServiceUnavailable, "webhooks_unavailable", "webhook delivery is not running")
		return
	}
	ev := AuditEvent{
		ID: newID("test"), TenantID: c.Tenant, Service: "audit", Action: webhookSelfPrefix + "test",
		ActorID: c.Actor(), Result: "success", Timestamp: time.Now().UTC(),
		Details: map[string]interface{}{"message": "Test delivery from Vecta KMS"},
	}
	d := f.deliver(c.R.Context(), wh, ev)
	c.Detail("delivery_status", d.Status)
	c.Detail("http_status", d.HTTPStatus)
	c.JSON(http.StatusOK, map[string]interface{}{
		"success": d.Status == "success", "status": d.Status, "http_status": d.HTTPStatus,
		"latency_ms": d.LatencyMs, "error": d.Error,
	})
}

func (h *Handler) listDeliveries(c *route.Call) {
	limit := atoi(c.R.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	items, err := h.store.ListDeliveries(c.R.Context(), c.Tenant, c.R.PathValue("id"), limit)
	if err != nil {
		c.Error(http.StatusInternalServerError, "query_failed", "failed to list deliveries")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
