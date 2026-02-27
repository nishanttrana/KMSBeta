package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type Handler struct {
	svc *Service
	mux *http.ServeMux
}

func NewHandler(svc *Service) *Handler {
	h := &Handler{svc: svc}
	h.mux = h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.handleHealth)

	mux.HandleFunc("GET /cluster/overview", h.handleOverview)
	mux.HandleFunc("GET /cluster/members", h.handleMembers)
	mux.HandleFunc("GET /cluster/nodes", h.handleNodes)

	mux.HandleFunc("GET /cluster/profiles", h.handleListProfiles)
	mux.HandleFunc("POST /cluster/profiles", h.handleUpsertProfile)
	mux.HandleFunc("DELETE /cluster/profiles/{id}", h.handleDeleteProfile)

	mux.HandleFunc("POST /cluster/join/request", h.handleJoinRequest)
	mux.HandleFunc("POST /cluster/join/complete", h.handleJoinComplete)

	mux.HandleFunc("POST /cluster/nodes", h.handleUpsertNode)
	mux.HandleFunc("POST /cluster/nodes/{id}/heartbeat", h.handleNodeHeartbeat)
	mux.HandleFunc("POST /cluster/nodes/{id}/role", h.handleNodeRoleUpdate)
	mux.HandleFunc("DELETE /cluster/nodes/{id}", h.handleRemoveNode)

	mux.HandleFunc("POST /cluster/sync/events", h.handlePublishSyncEvent)
	mux.HandleFunc("GET /cluster/sync/events", h.handleListSyncEvents)
	mux.HandleFunc("POST /cluster/sync/ack", h.handleSyncAck)
	mux.HandleFunc("GET /cluster/sync/checkpoint", h.handleSyncCheckpoint)
	mux.HandleFunc("GET /cluster/logs", h.handleClusterLogs)

	return mux
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (h *Handler) handleOverview(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	overview, err := h.svc.GetOverview(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"overview": overview, "request_id": reqID})
}

func (h *Handler) handleMembers(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	nodes, err := h.svc.ListMembers(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": nodes, "request_id": reqID})
}

func (h *Handler) handleNodes(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	overview, err := h.svc.GetOverview(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": overview.Nodes, "request_id": reqID})
}

func (h *Handler) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListProfiles(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleUpsertProfile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var in UpsertProfileInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	in.TenantID = firstTenant(in.TenantID, tenantFromRequest(r))
	item, err := h.svc.UpsertProfile(r.Context(), in)
	if err != nil {
		h.writeServiceError(w, err, reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"profile": item, "request_id": reqID})
}

func (h *Handler) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	profileID := strings.TrimSpace(r.PathValue("id"))
	if profileID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "profile id is required", reqID, tenantID)
		return
	}
	if err := h.svc.DeleteProfile(r.Context(), tenantID, profileID); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "request_id": reqID})
}

func (h *Handler) handleJoinRequest(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var in CreateJoinTokenInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	in.TenantID = firstTenant(in.TenantID, tenantFromRequest(r))
	if strings.TrimSpace(in.RequestedBy) == "" {
		in.RequestedBy = firstActor(r)
	}
	token, err := h.svc.CreateJoinToken(r.Context(), in)
	if err != nil {
		h.writeServiceError(w, err, reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"join": token, "request_id": reqID})
}

func (h *Handler) handleJoinComplete(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var in CompleteJoinInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	in.TenantID = firstTenant(in.TenantID, tenantFromRequest(r))
	node, err := h.svc.CompleteJoin(r.Context(), in)
	if err != nil {
		h.writeServiceError(w, err, reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"node": node, "request_id": reqID})
}

func (h *Handler) handleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var in HeartbeatInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	in.TenantID = firstTenant(in.TenantID, tenantFromRequest(r))
	nodeID := strings.TrimSpace(r.PathValue("id"))
	node, err := h.svc.UpdateHeartbeat(r.Context(), nodeID, in)
	if err != nil {
		h.writeServiceError(w, err, reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"node": node, "request_id": reqID})
}

func (h *Handler) handleUpsertNode(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var in UpsertNodeInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	in.TenantID = firstTenant(in.TenantID, tenantFromRequest(r))
	if strings.TrimSpace(in.RequestedBy) == "" {
		in.RequestedBy = firstActor(r)
	}
	node, err := h.svc.UpsertNode(r.Context(), in)
	if err != nil {
		h.writeServiceError(w, err, reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"node": node, "request_id": reqID})
}

func (h *Handler) handleNodeRoleUpdate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	nodeID := strings.TrimSpace(r.PathValue("id"))
	if nodeID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "node id is required", reqID, "")
		return
	}
	var in UpdateNodeRoleInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	in.TenantID = firstTenant(in.TenantID, tenantFromRequest(r))
	if strings.TrimSpace(in.RequestedBy) == "" {
		in.RequestedBy = firstActor(r)
	}
	node, err := h.svc.UpdateNodeRole(r.Context(), nodeID, in)
	if err != nil {
		h.writeServiceError(w, err, reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"node": node, "request_id": reqID})
}

func (h *Handler) handleRemoveNode(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	nodeID := strings.TrimSpace(r.PathValue("id"))
	if nodeID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "node id is required", reqID, "")
		return
	}
	var in RemoveNodeInput
	if err := decodeJSONOptional(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	in.TenantID = firstTenant(in.TenantID, tenantFromRequest(r))
	if strings.TrimSpace(in.RequestedBy) == "" {
		in.RequestedBy = firstActor(r)
	}
	result, err := h.svc.RemoveNode(r.Context(), nodeID, in)
	if err != nil {
		h.writeServiceError(w, err, reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": result, "request_id": reqID})
}

func (h *Handler) handlePublishSyncEvent(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	rawBody, err := readRequestBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	var in PublishSyncEventInput
	if err := decodeJSONBytes(rawBody, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	in.TenantID = firstTenant(in.TenantID, tenantFromRequest(r))
	if strings.TrimSpace(in.TenantID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query, header or body)", reqID, "")
		return
	}
	sourceNodeID := firstTenant(strings.TrimSpace(in.SourceNodeID), strings.TrimSpace(r.Header.Get("X-Cluster-Source-Node")))
	if sourceNodeID != "" {
		in.SourceNodeID = sourceNodeID
	}
	if err := h.svc.ValidateSignedSyncRequest(
		r.Context(),
		r.Method,
		r.URL.Path,
		in.TenantID,
		sourceNodeID,
		strings.TrimSpace(r.Header.Get("X-Cluster-Timestamp")),
		strings.TrimSpace(r.Header.Get("X-Cluster-Nonce")),
		strings.TrimSpace(r.Header.Get("X-Cluster-Signature")),
		rawBody,
		r.TLS != nil && len(r.TLS.VerifiedChains) > 0,
	); err != nil {
		h.writeServiceError(w, err, reqID, in.TenantID)
		return
	}
	event, err := h.svc.PublishSyncEvent(r.Context(), in)
	if err != nil {
		h.writeServiceError(w, err, reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"event": event, "request_id": reqID})
}

func (h *Handler) handleListSyncEvents(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	profileID := strings.TrimSpace(r.URL.Query().Get("profile_id"))
	afterID := int64(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("after_id")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			afterID = v
		}
	}
	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			limit = v
		}
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	items, err := h.svc.ListSyncEvents(r.Context(), tenantID, profileID, afterID, limit, nodeID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleSyncAck(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var in SyncAckInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	in.TenantID = firstTenant(in.TenantID, tenantFromRequest(r))
	checkpoint, err := h.svc.AckSync(r.Context(), in)
	if err != nil {
		h.writeServiceError(w, err, reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"checkpoint": checkpoint, "request_id": reqID})
}

func (h *Handler) handleSyncCheckpoint(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	profileID := strings.TrimSpace(r.URL.Query().Get("profile_id"))
	checkpoint, err := h.svc.GetSyncCheckpoint(r.Context(), tenantID, nodeID, profileID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"checkpoint": checkpoint, "request_id": reqID})
}

func (h *Handler) handleClusterLogs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	eventType := strings.TrimSpace(r.URL.Query().Get("event_type"))
	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			limit = v
		}
	}
	items, err := h.svc.ListClusterLogs(r.Context(), tenantID, nodeID, eventType, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		writeErr(w, svcErr.HTTPStatus, svcErr.Code, svcErr.Message, reqID, tenantID)
		return
	}
	writeErr(w, httpStatusForErr(err), "internal_error", err.Error(), reqID, tenantID)
}

func decodeJSON(r *http.Request, out interface{}) error {
	raw, err := readRequestBody(r)
	if err != nil {
		return err
	}
	return decodeJSONBytes(raw, out)
}

func decodeJSONOptional(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	return decodeJSONBytes(raw, out)
}

func decodeJSONBytes(raw []byte, out interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("request body is required")
		}
		return err
	}
	var extra interface{}
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

func readRequestBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close() //nolint:errcheck
	raw, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("request body is required")
	}
	return raw, nil
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func tenantFromRequest(r *http.Request) string {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID != "" {
		return tenantID
	}
	return strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
}

func firstTenant(values ...string) string {
	for _, item := range values {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}

func mustTenant(r *http.Request, w http.ResponseWriter, reqID string) string {
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return ""
	}
	return tenantID
}

func firstActor(r *http.Request) string {
	for _, header := range []string{"X-User-Email", "X-User-Name", "X-User-ID", "X-Actor"} {
		if value := strings.TrimSpace(r.Header.Get(header)); value != "" {
			return value
		}
	}
	return "system"
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
