package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/clustersync"
)

type Handler struct {
	svc      *Service
	store    Store
	cluster  clustersync.Publisher
	channels map[string]interface{}
	mux      *http.ServeMux
}

func NewHandler(svc *Service, store Store) *Handler {
	h := &Handler{
		svc:   svc,
		store: store,
		channels: map[string]interface{}{
			"email":     map[string]interface{}{"enabled": true},
			"sms":       map[string]interface{}{"enabled": true, "min_severity": "CRITICAL"},
			"pagerduty": map[string]interface{}{"enabled": true, "min_severity": "CRITICAL"},
			"siem":      map[string]interface{}{"enabled": true},
			"webhook":   map[string]interface{}{"enabled": true, "min_severity": "MEDIUM"},
			"dashboard": map[string]interface{}{"enabled": true},
		},
	}
	h.mux = h.routes()
	return h
}

func (h *Handler) SetClusterSyncPublisher(pub clustersync.Publisher) {
	if pub == nil {
		return
	}
	h.cluster = pub
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /audit/publish", h.handlePublish)
	mux.HandleFunc("GET /audit/events", h.handleEvents)
	mux.HandleFunc("GET /audit/events/{id}", h.handleEvent)
	mux.HandleFunc("GET /audit/timeline/{target_id}", h.handleTimeline)
	mux.HandleFunc("GET /audit/session/{session_id}", h.handleSession)
	mux.HandleFunc("GET /audit/correlation/{id}", h.handleCorrelation)
	mux.HandleFunc("POST /audit/search", h.handleSearch)
	mux.HandleFunc("GET /audit/chain/verify", h.handleChainVerify)
	mux.HandleFunc("GET /audit/stats", h.handleAuditStats)
	mux.HandleFunc("GET /audit/stream", h.handleNotImplemented)
	mux.HandleFunc("GET /audit/config", h.handleAuditConfig)

	mux.HandleFunc("GET /alerts", h.handleAlerts)
	mux.HandleFunc("GET /alerts/{id}", h.handleAlert)
	mux.HandleFunc("PUT /alerts/{id}/{action}", h.handleAlertActionPath)
	mux.HandleFunc("GET /alerts/stats", h.handleAlertStats)
	mux.HandleFunc("GET /alerts/stream", h.handleNotImplemented)
	mux.HandleFunc("POST /alerts/rules", h.handleCreateRule)
	mux.HandleFunc("GET /alerts/rules", h.handleListRules)
	mux.HandleFunc("PUT /alerts/rules/{id}", h.handleUpdateRule)
	mux.HandleFunc("DELETE /alerts/rules/{id}", h.handleDeleteRule)
	mux.HandleFunc("POST /alerts/test-rule", h.handleTestRule)
	mux.HandleFunc("GET /alerts/channels", h.handleGetChannels)
	mux.HandleFunc("PUT /alerts/channels", h.handleUpdateChannels)
	mux.HandleFunc("POST /alerts/channels/test", h.handleTestChannel)

	// Merkle tree integrity routes
	mux.HandleFunc("POST /audit/merkle/build", h.handleMerkleBuild)
	mux.HandleFunc("GET /audit/merkle/epochs", h.handleMerkleEpochs)
	mux.HandleFunc("GET /audit/merkle/epochs/{id}", h.handleMerkleEpoch)
	mux.HandleFunc("GET /audit/events/{id}/proof", h.handleEventProof)
	mux.HandleFunc("POST /audit/merkle/verify", h.handleMerkleVerify)

	// Webhook routes
	mux.HandleFunc("GET /webhooks", h.handleListWebhooks)
	mux.HandleFunc("POST /webhooks", h.handleCreateWebhook)
	mux.HandleFunc("PATCH /webhooks/{id}", h.handleUpdateWebhook)
	mux.HandleFunc("DELETE /webhooks/{id}", h.handleDeleteWebhook)
	mux.HandleFunc("POST /webhooks/{id}/test", h.handleTestWebhook)
	mux.HandleFunc("GET /webhooks/{id}/deliveries", h.handleListDeliveries)

	// Ops metrics routes
	mux.HandleFunc("GET /ops-metrics/overview", h.handleGetOpsOverview)
	mux.HandleFunc("GET /ops-metrics/timeseries", h.handleGetOpsTimeSeries)
	mux.HandleFunc("GET /ops-metrics/latency", h.handleGetLatencyPercentiles)
	mux.HandleFunc("GET /ops-metrics/by-service", h.handleGetServiceStats)
	mux.HandleFunc("GET /ops-metrics/errors", h.handleGetErrorBreakdown)
	mux.HandleFunc("POST /ops-metrics/record", h.handleRecordOp)

	// Prometheus metrics scrape endpoint
	mux.HandleFunc("GET /metrics", h.handlePrometheusMetrics)

	return mux
}

func (h *Handler) handlePublish(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		Subject string     `json:"subject"`
		Event   AuditEvent `json:"event"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if req.Subject == "" {
		req.Subject = req.Event.Action
	}
	buffered, err := h.svc.PublishAudit(r.Context(), req.Subject, req.Event)
	if err != nil {
		if h.svc.cfg.FailClosed {
			writeErr(w, http.StatusServiceUnavailable, "audit_unavailable", "audit publish failed and fail_closed=true", reqID, req.Event.TenantID)
			return
		}
		writeErr(w, http.StatusServiceUnavailable, "audit_buffer_failed", err.Error(), reqID, req.Event.TenantID)
		return
	}
	if buffered {
		writeJSON(w, http.StatusAccepted, map[string]interface{}{"status": "buffered", "request_id": reqID})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "published", "request_id": reqID})
}

func (h *Handler) handleEvents(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	q := EventQuery{
		Action:        strings.TrimSpace(r.URL.Query().Get("action")),
		ActorID:       strings.TrimSpace(r.URL.Query().Get("actor_id")),
		Result:        strings.TrimSpace(r.URL.Query().Get("result")),
		TargetID:      strings.TrimSpace(r.URL.Query().Get("target_id")),
		SessionID:     strings.TrimSpace(r.URL.Query().Get("session_id")),
		CorrelationID: strings.TrimSpace(r.URL.Query().Get("correlation_id")),
		RiskMin:       atoi(r.URL.Query().Get("risk_min")),
		Limit:         atoi(r.URL.Query().Get("limit")),
		Offset:        atoi(r.URL.Query().Get("offset")),
	}
	q.From = parseTS(r.URL.Query().Get("from"))
	q.To = parseTS(r.URL.Query().Get("to"))
	items, err := h.store.QueryEvents(r.Context(), tenantID, q)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleEvent(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	item, err := h.store.GetEvent(r.Context(), tenantID, r.PathValue("id"))
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "event not found", reqID, tenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"event": item, "request_id": reqID})
}

func (h *Handler) handleTimeline(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.store.QueryEvents(r.Context(), tenantID, EventQuery{
		TargetID: r.PathValue("target_id"),
		Limit:    atoi(r.URL.Query().Get("limit")),
		Offset:   atoi(r.URL.Query().Get("offset")),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleSession(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.store.QueryEvents(r.Context(), tenantID, EventQuery{
		SessionID: r.PathValue("session_id"),
		Limit:     atoi(r.URL.Query().Get("limit")),
		Offset:    atoi(r.URL.Query().Get("offset")),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCorrelation(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.store.QueryEvents(r.Context(), tenantID, EventQuery{
		CorrelationID: r.PathValue("id"),
		Limit:         atoi(r.URL.Query().Get("limit")),
		Offset:        atoi(r.URL.Query().Get("offset")),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleSearch(w http.ResponseWriter, r *http.Request) {
	// Scope: alias to event query with supplied filters.
	h.handleEvents(w, r)
}

func (h *Handler) handleChainVerify(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	ok, breaks, err := h.svc.VerifyChain(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "verify_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": ok, "breaks": breaks, "request_id": reqID})
}

func (h *Handler) handleAuditStats(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	stats, err := h.store.AlertStats(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "stats_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"alerts": stats, "request_id": reqID})
}

func (h *Handler) handleAuditConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"fail_closed":            h.svc.cfg.FailClosed,
		"wal_path":               h.svc.cfg.WALPath,
		"wal_max_size_mb":        h.svc.cfg.WALMaxSizeMB,
		"dedup_window_seconds":   h.svc.cfg.DedupWindowSeconds,
		"escalation_threshold":   h.svc.cfg.EscalationThreshold,
		"escalation_window_mins": h.svc.cfg.EscalationMinutes,
		"request_id":             reqID,
	})
}

func (h *Handler) handleAlerts(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	q := AlertQuery{
		Severity: strings.TrimSpace(r.URL.Query().Get("severity")),
		Category: strings.TrimSpace(r.URL.Query().Get("category")),
		Status:   strings.TrimSpace(r.URL.Query().Get("status")),
		From:     parseTS(r.URL.Query().Get("from")),
		To:       parseTS(r.URL.Query().Get("to")),
		Limit:    atoi(r.URL.Query().Get("limit")),
		Offset:   atoi(r.URL.Query().Get("offset")),
	}
	items, err := h.store.QueryAlerts(r.Context(), tenantID, q)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleAlert(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	item, err := h.store.GetAlert(r.Context(), tenantID, r.PathValue("id"))
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "alert not found", reqID, tenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"alert": item, "request_id": reqID})
}

func (h *Handler) handleAlertActionPath(w http.ResponseWriter, r *http.Request) {
	action := strings.ToLower(strings.TrimSpace(r.PathValue("action")))
	switch action {
	case "acknowledge", "resolve", "suppress":
		h.alertAction(w, r, action)
	default:
		reqID := requestID(r)
		writeErr(w, http.StatusNotFound, "not_found", "unsupported alert action", reqID, "")
	}
}

func (h *Handler) alertAction(w http.ResponseWriter, r *http.Request, action string) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	var req struct {
		Actor          string `json:"actor"`
		Note           string `json:"note"`
		ResolutionNote string `json:"resolution_note"`
		SuppressUntil  string `json:"suppress_until"`
	}
	_ = decodeJSON(r, &req)
	note := req.Note
	if req.ResolutionNote != "" {
		note = req.ResolutionNote
	}
	var suppressUntil *time.Time
	if ts := parseTS(req.SuppressUntil); !ts.IsZero() {
		suppressUntil = &ts
	}
	if req.Actor == "" {
		req.Actor = "system"
	}
	if err := h.store.UpdateAlertStatus(r.Context(), tenantID, r.PathValue("id"), action, req.Actor, note, suppressUntil); err != nil {
		writeErr(w, http.StatusInternalServerError, "update_failed", err.Error(), reqID, tenantID)
		return
	}
	payload := map[string]interface{}{
		"alert_id": r.PathValue("id"),
		"actor":    req.Actor,
		"action":   action,
		"note":     note,
	}
	if suppressUntil != nil {
		payload["suppress_until"] = suppressUntil.UTC().Format(time.RFC3339)
	}
	h.publishClusterSync(r, tenantID, "alert", r.PathValue("id"), "alert_"+action, payload)
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	stats, err := h.store.AlertStats(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "stats_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"stats": stats, "request_id": reqID})
}

func (h *Handler) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	var rule AlertRule
	if err := decodeJSON(r, &rule); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	rule.ID = strings.TrimSpace(rule.ID)
	if rule.ID == "" {
		rule.ID = newID("rule")
	}
	if err := h.store.CreateRule(r.Context(), tenantID, rule); err != nil {
		writeErr(w, http.StatusInternalServerError, "create_failed", err.Error(), reqID, tenantID)
		return
	}
	h.publishClusterSync(r, tenantID, "alert_rule", rule.ID, "rule_created", map[string]interface{}{
		"rule_id":    rule.ID,
		"name":       rule.Name,
		"severity":   rule.Severity,
		"title":      rule.Title,
		"condition":  rule.Condition,
		"tenant_id":  tenantID,
		"request_id": reqID,
	})
	writeJSON(w, http.StatusCreated, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleListRules(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.store.ListRules(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	var rule AlertRule
	if err := decodeJSON(r, &rule); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	rule.ID = strings.TrimSpace(r.PathValue("id"))
	if rule.ID == "" {
		rule.ID = strings.TrimSpace(r.URL.Query().Get("id"))
	}
	if rule.ID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "rule id is required", reqID, tenantID)
		return
	}
	if err := h.store.UpdateRule(r.Context(), tenantID, rule); err != nil {
		writeErr(w, http.StatusInternalServerError, "update_failed", err.Error(), reqID, tenantID)
		return
	}
	h.publishClusterSync(r, tenantID, "alert_rule", rule.ID, "rule_updated", map[string]interface{}{
		"rule_id":    rule.ID,
		"name":       rule.Name,
		"severity":   rule.Severity,
		"title":      rule.Title,
		"condition":  rule.Condition,
		"tenant_id":  tenantID,
		"request_id": reqID,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		id = strings.TrimSpace(r.URL.Query().Get("id"))
	}
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "rule id is required", reqID, tenantID)
		return
	}
	if err := h.store.DeleteRule(r.Context(), tenantID, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete_failed", err.Error(), reqID, tenantID)
		return
	}
	h.publishClusterSync(r, tenantID, "alert_rule", id, "rule_deleted", map[string]interface{}{
		"rule_id":    id,
		"tenant_id":  tenantID,
		"request_id": reqID,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleTestRule(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	// scope: validate parse shape and return dry-run accepted.
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "dry-run-ok", "request_id": reqID})
}

func (h *Handler) handleGetChannels(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{"channels": h.channels, "request_id": reqID})
}

func (h *Handler) handleUpdateChannels(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body map[string]interface{}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	for k, v := range body {
		h.channels[k] = v
	}
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	h.publishClusterSync(r, tenantID, "alert_channel_config", tenantID, "channels_updated", map[string]interface{}{
		"channels": body,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleTestChannel(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "test-sent", "request_id": reqID})
}

func (h *Handler) handleNotImplemented(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	writeErr(w, http.StatusNotImplemented, "not_implemented", "stream endpoint is not implemented in Sprint 1", reqID, "")
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func mustTenant(r *http.Request, w http.ResponseWriter, requestID string) string {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", requestID, "")
		return ""
	}
	return tenantID
}

func parseTS(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, v)
	return t
}

func atoi(v string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code string, message string, requestID string, tenantID string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":       code,
			"message":    message,
			"request_id": requestID,
			"tenant_id":  tenantID,
		},
	})
}

func (h *Handler) publishClusterSync(r *http.Request, tenantID string, entityType string, entityID string, operation string, payload map[string]interface{}) {
	if h == nil || h.cluster == nil {
		return
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return
	}
	entityID = strings.TrimSpace(entityID)
	if entityID == "" {
		entityID = tenantID
	}
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return
	}
	_ = h.cluster.Publish(r.Context(), clustersync.PublishRequest{
		TenantID:   tenantID,
		Component:  "audit",
		EntityType: strings.TrimSpace(entityType),
		EntityID:   entityID,
		Operation:  operation,
		Payload:    payload,
	})
}

// ── Merkle Tree Handlers ─────────────────────────────────────

func (h *Handler) handleMerkleBuild(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	maxLeaves := atoi(r.URL.Query().Get("max_leaves"))
	if maxLeaves <= 0 {
		maxLeaves = 1000
	}
	result, err := h.store.BuildMerkleEpoch(r.Context(), tenantID, maxLeaves)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "build_failed", err.Error(), reqID, tenantID)
		return
	}
	if result == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":     "no_new_events",
			"request_id": reqID,
		})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"epoch":      result.Epoch,
		"leaves":     result.Leaves,
		"request_id": reqID,
	})
}

func (h *Handler) handleMerkleEpochs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	limit := atoi(r.URL.Query().Get("limit"))
	items, err := h.store.ListMerkleEpochs(r.Context(), tenantID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleMerkleEpoch(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	epoch, err := h.store.GetMerkleEpoch(r.Context(), tenantID, r.PathValue("id"))
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "epoch not found", reqID, tenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"epoch": epoch, "request_id": reqID})
}

func (h *Handler) handleEventProof(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	proof, err := h.store.GetEventMerkleProof(r.Context(), tenantID, r.PathValue("id"))
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "event not in any merkle epoch", reqID, tenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "proof_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"proof": proof, "request_id": reqID})
}

func (h *Handler) handleMerkleVerify(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		LeafHash  string         `json:"leaf_hash"`
		LeafIndex int            `json:"leaf_index"`
		Siblings  []ProofSibling `json:"siblings"`
		Root      string         `json:"root"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	proof := MerkleProof{
		LeafHash:  req.LeafHash,
		LeafIndex: req.LeafIndex,
		Siblings:  req.Siblings,
		Root:      req.Root,
	}
	valid := VerifyProof(proof)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":      valid,
		"root":       req.Root,
		"request_id": reqID,
	})
}
