package main

import (
	"context"
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

func validateWebhookSecret(s string) bool { return s == "" || len(s) >= minWebhookSecret }

func (h *Handler) createWebhook(c *route.Call) {
	var req CreateWebhookRequest
	if !c.Decode(&req) {
		return
	}
	wh := Webhook{
		TenantID: c.Tenant, Name: strings.TrimSpace(req.Name), URL: strings.TrimSpace(req.URL),
		Format: strings.TrimSpace(req.Format), Events: req.Events, Secret: req.Secret,
		Headers: req.Headers, Enabled: req.Enabled == nil || *req.Enabled,
	}
	if wh.Format == "" {
		wh.Format = "json"
	}
	if wh.Headers == nil {
		wh.Headers = map[string]string{}
	}
	if !h.validWebhook(c, wh) {
		return
	}
	wh.ID = newID("wh") // the sealed credentials are bound to it
	if !h.sealCreds(c, &wh) {
		return
	}
	created, err := h.store.CreateWebhook(c.R.Context(), wh)
	if err != nil {
		c.Error(http.StatusInternalServerError, "create_failed", "failed to create webhook")
		return
	}
	h.webhookChanged(c, created)
	c.JSON(http.StatusCreated, map[string]interface{}{"webhook": publicWebhook(created)})
}

func (h *Handler) validWebhook(c *route.Call, wh Webhook) bool {
	fail := func(msg string) bool { c.Error(http.StatusBadRequest, "validation_error", msg); return false }
	switch {
	case wh.Name == "":
		return fail("name is required")
	case !webhookFormats[wh.Format]:
		return fail("format must be json, splunk_hec, datadog or slack")
	case !validateWebhookSecret(wh.Secret):
		return fail("secret must be at least 16 characters (HMAC keys under 112 bits are not approved)")
	}
	check := validateWebhookURL
	if f := h.fanout(); f != nil {
		check = f.disp.validate // the same check delivery applies
	}
	if err := check(wh.URL); err != nil {
		c.Detail("url_refused", err.Error())
		c.Refuse(http.StatusBadRequest, "url_blocked", err.Error())
		return false
	}
	if err := validateWebhookEvents(wh.Events); err != nil {
		return fail(err.Error())
	}
	if err := validateWebhookHeaders(wh.Headers); err != nil {
		return fail(err.Error())
	}
	return true
}

func (h *Handler) webhookChanged(c *route.Call, wh Webhook) {
	c.Target(wh.ID)
	c.Detail("url_host", hostOf(wh.URL))
	c.Detail("format", wh.Format)
	c.Detail("events", wh.Events)
	c.Detail("enabled", wh.Enabled)
	c.Detail("signed", wh.HasSecret)
	c.Detail("credentials_sealed", wh.Sealed != nil)
	if f := h.fanout(); f != nil {
		f.Invalidate(wh.TenantID)
	}
}

// sealCreds seals the secret and header values under the audit master key,
// answering 503 while the key is unavailable. Nothing is stored in plaintext.
func (h *Handler) sealCreds(c *route.Call, wh *Webhook) bool {
	if err := h.svc.creds.Seal(wh); err != nil {
		c.Error(http.StatusServiceUnavailable, "credentials_key_unavailable", err.Error())
		return false
	}
	return true
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
	stored, err := h.store.GetWebhook(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		c.Error(http.StatusNotFound, "not_found", "webhook not found")
		return
	}
	// Open the stored credentials so values the caller leaves blank are kept.
	wh, err := h.svc.creds.Open(stored)
	if err != nil {
		c.Error(http.StatusServiceUnavailable, "credentials_key_unavailable", err.Error())
		return
	}
	var sentHeaders map[string]string
	if req.Headers != nil {
		sentHeaders = *req.Headers
	}
	replaced := credsReplaced(stored, req.Secret != nil && *req.Secret != "", req.ClearSecret, sentHeaders)
	if req.Name != nil {
		wh.Name = strings.TrimSpace(*req.Name)
	}
	if req.URL != nil {
		wh.URL = strings.TrimSpace(*req.URL)
	}
	if req.Format != nil {
		wh.Format = strings.TrimSpace(*req.Format)
	}
	if req.Events != nil {
		wh.Events = req.Events
	}
	if req.ClearSecret {
		wh.Secret = ""
	} else if req.Secret != nil && *req.Secret != "" {
		wh.Secret = *req.Secret
	}
	if req.Headers != nil {
		next := make(map[string]string, len(*req.Headers))
		for k, v := range *req.Headers {
			if v == "" {
				v = wh.Headers[k] // values are write-only; empty keeps the stored one
			}
			next[k] = v
		}
		wh.Headers = next
	}
	if req.Enabled != nil {
		wh.Enabled = *req.Enabled
	}
	if !h.validWebhook(c, wh) {
		return
	}
	if stored.Sealed == nil && hasCredentials(stored.Secret, stored.Headers) {
		// An earlier release's plaintext row: register the exposure before
		// sealing, as the startup job would have.
		k, err := h.svc.creds.current()
		if err == nil {
			err = k.RecordExposure(c.R.Context(), c.Tenant, webhookCredsItemType, stored.ID, "plaintext_storage")
		}
		if err != nil {
			c.Error(http.StatusServiceUnavailable, "credentials_key_unavailable", err.Error())
			return
		}
	}
	if !h.sealCreds(c, &wh) {
		return
	}
	updated, err := h.store.UpdateWebhook(c.R.Context(), c.Tenant, wh.ID, wh)
	if err != nil {
		c.Error(http.StatusInternalServerError, "update_failed", "failed to update webhook")
		return
	}
	if replaced {
		h.retireExposure(c, wh.ID, "rotated")
	}
	c.Detail("credentials_replaced", replaced)
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
