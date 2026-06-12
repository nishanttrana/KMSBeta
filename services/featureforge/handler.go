package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/tenantcheck"
)

// Handler exposes FeatureForge over HTTP. Mounted by the dashboard at
// /svc/featureforge/... Routes:
//
//	GET  /catalog                       -> allow-listed config actions
//	GET  /intents?tenant_id=...         -> list intents for a tenant
//	POST /intents                       -> submit an intent (runs to staging)
//	GET  /intents/{id}                  -> intent + guardrail trail
//	POST /intents/{id}/promote          -> attempt prod promotion (gated)
//	GET  /healthz                       -> liveness
type Handler struct {
	svc *Service
	mux *http.ServeMux
}

func NewHandler(svc *Service) *Handler {
	h := &Handler{svc: svc}
	h.mux = h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /catalog", h.handleCatalog)
	mux.HandleFunc("GET /intents", h.handleListIntents)
	mux.HandleFunc("POST /intents", h.handleSubmit)
	mux.HandleFunc("GET /intents/{id}", h.handleGetIntent)
	mux.HandleFunc("POST /intents/{id}/approve", h.handleApprove)
	mux.HandleFunc("POST /intents/{id}/promote", h.handlePromote)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "featureforge"})
	})
	return mux
}

func (h *Handler) handleCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"actions": h.svc.Catalog()})
}

func (h *Handler) handleListIntents(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"intents": h.svc.List(r.Context(), tenantID), "request_id": reqID})
}

type submitReq struct {
	TenantID string `json:"tenant_id"`
	Actor    string `json:"actor"`
	Text     string `json:"text"`
}

func (h *Handler) handleSubmit(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req submitReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid request body", reqID, "")
		return
	}
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if err := tenantcheck.Enforce(r, tenantID); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant_id does not match authenticated token", reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.Text) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "text is required", reqID, tenantID)
		return
	}
	actor := strings.TrimSpace(req.Actor)
	if actor == "" {
		actor = strings.TrimSpace(r.Header.Get("X-Actor"))
	}
	ctx := WithRequestID(r.Context(), reqID)
	in, err := h.svc.Submit(ctx, tenantID, actor, req.Text)
	status := http.StatusOK
	if err != nil {
		// Rejection is an expected outcome; return the intent + trail with 422.
		status = http.StatusUnprocessableEntity
	}
	_, trail, _ := h.svc.Get(ctx, in.ID)
	writeJSON(w, status, map[string]any{"intent": in, "trail": trail, "request_id": reqID})
}

func (h *Handler) handleGetIntent(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	in, trail, ok := h.svc.Get(r.Context(), r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "intent not found", reqID, "")
		return
	}
	if err := tenantcheck.Enforce(r, in.TenantID); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant mismatch", reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"intent": in, "trail": trail,
		"approvals": h.svc.Approvals(r.Context(), in.ID), "request_id": reqID,
	})
}

// actorReq is the body for approve/promote: who is performing the action.
type actorReq struct {
	Actor   string `json:"actor"`
	Comment string `json:"comment,omitempty"`
}

// requireIntent loads the intent and enforces the tenant boundary; returns
// nil (after writing the error) when the caller may not act on it.
func (h *Handler) requireIntent(w http.ResponseWriter, r *http.Request, reqID string) *Intent {
	in, _, ok := h.svc.Get(r.Context(), r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "intent not found", reqID, "")
		return nil
	}
	if err := tenantcheck.Enforce(r, in.TenantID); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant mismatch", reqID, in.TenantID)
		return nil
	}
	return in
}

func actorFrom(r *http.Request, req actorReq) string {
	if a := strings.TrimSpace(req.Actor); a != "" {
		return a
	}
	return strings.TrimSpace(r.Header.Get("X-Actor"))
}

func (h *Handler) handleApprove(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	if h.requireIntent(w, r, reqID) == nil {
		return
	}
	var req actorReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid request body", reqID, "")
		return
	}
	approver := actorFrom(r, req)
	if approver == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "actor is required", reqID, "")
		return
	}
	ctx := WithRequestID(r.Context(), reqID)
	in, err := h.svc.Approve(ctx, r.PathValue("id"), approver, req.Comment)
	status := http.StatusOK
	if err != nil {
		status = http.StatusUnprocessableEntity
	}
	_, trail, _ := h.svc.Get(ctx, in.ID)
	writeJSON(w, status, map[string]any{
		"intent": in, "trail": trail,
		"approvals": h.svc.Approvals(ctx, in.ID), "request_id": reqID,
	})
}

func (h *Handler) handlePromote(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	if h.requireIntent(w, r, reqID) == nil {
		return
	}
	var req actorReq
	_ = decodeJSON(r, &req) // body is optional; actor may come from X-Actor
	ctx := WithRequestID(r.Context(), reqID)
	in, err := h.svc.PromoteToProd(ctx, r.PathValue("id"), actorFrom(r, req))
	status := http.StatusOK
	if err != nil {
		status = http.StatusUnprocessableEntity
	}
	_, trail, _ := h.svc.Get(ctx, in.ID)
	writeJSON(w, status, map[string]any{
		"intent": in, "trail": trail,
		"approvals": h.svc.Approvals(ctx, in.ID), "request_id": reqID,
	})
}

// --- shared helpers (same style as other services) -----------------------

func decodeJSON(r *http.Request, out any) error {
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
	return "req-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
}

func mustTenant(r *http.Request, reqID string, w http.ResponseWriter) string {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return ""
	}
	if err := tenantcheck.Enforce(r, tenantID); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant_id does not match authenticated token", reqID, tenantID)
		return ""
	}
	return tenantID
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code, message, reqID, tenantID string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":       code,
			"message":    message,
			"request_id": reqID,
			"tenant_id":  tenantID,
		},
	})
}
