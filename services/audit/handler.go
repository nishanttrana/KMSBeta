package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/clustersync"
	"vecta-kms/pkg/tenantcheck"
)

type Handler struct {
	svc     *Service
	store   Store
	broker  *StreamBroker
	cluster clustersync.Publisher
	mux     *http.ServeMux
}

func NewHandler(svc *Service, store Store) *Handler {
	broker := newStreamBroker()
	svc.SetStreamBroker(broker)
	h := &Handler{
		svc:    svc,
		store:  store,
		broker: broker,
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

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// FIPS 140-3 security headers on every response.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("X-Audit-Immutable", "true")

	// Block any mutation attempt on audit events — they are write-once by design.
	path := strings.ToLower(r.URL.Path)
	method := strings.ToUpper(r.Method)
	if isAuditEventPath(path) && (method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete) {
		writeErr(w, http.StatusMethodNotAllowed, "immutable",
			"audit events are immutable and cannot be modified or deleted", requestID(r), "")
		return
	}

	h.mux.ServeHTTP(w, r)
}

// isAuditEventPath returns true if the path targets the audit events resource.
func isAuditEventPath(path string) bool {
	return strings.HasPrefix(path, "/audit/events") ||
		strings.HasPrefix(path, "/audit/chain") ||
		strings.HasPrefix(path, "/audit/merkle/epochs")
}

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
	mux.HandleFunc("GET /audit/stream", h.handleStream)
	mux.HandleFunc("GET /audit/config", h.handleAuditConfig)

	// Merkle tree integrity routes
	mux.HandleFunc("POST /audit/merkle/build", h.handleMerkleBuild)
	mux.HandleFunc("GET /audit/merkle/epochs", h.handleMerkleEpochs)
	mux.HandleFunc("GET /audit/merkle/epochs/{id}", h.handleMerkleEpoch)
	mux.HandleFunc("GET /audit/events/{id}/proof", h.handleEventProof)
	mux.HandleFunc("POST /audit/merkle/verify", h.handleMerkleVerify)
	h.integrityRouter(selfEmitter{h.svc}).MountOn(mux)

	// Cluster audit signing key transfer (cluster-manager only; cluster.go).
	mux.HandleFunc("POST /audit/cluster/signing-key/join-key", h.handleClusterKeyJoinKey)
	mux.HandleFunc("POST /audit/cluster/signing-key/export", h.handleClusterKeyExport)
	mux.HandleFunc("POST /audit/cluster/signing-key/import", h.handleClusterKeyImport)

	// Webhook routes
	h.webhookRouter(selfEmitter{h.svc}).MountOn(mux)

	// Ops metrics routes
	mux.HandleFunc("GET /ops-metrics/overview", h.handleGetOpsOverview)
	mux.HandleFunc("GET /ops-metrics/timeseries", h.handleGetOpsTimeSeries)
	mux.HandleFunc("GET /ops-metrics/latency", h.handleGetLatencyPercentiles)
	mux.HandleFunc("GET /ops-metrics/by-service", h.handleGetServiceStats)
	mux.HandleFunc("GET /ops-metrics/errors", h.handleGetErrorBreakdown)

	// FIPS 140-3 module boundary declaration
	mux.HandleFunc("GET /audit/fips/boundary", h.handleFIPSBoundary)

	// Cryptographic Bill of Materials (CBOM)
	mux.HandleFunc("GET /audit/cbom/inventory", h.handleCBOMInventory)
	mux.HandleFunc("GET /audit/cbom/diff", h.handleCBOMDiff)

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
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid request body", reqID, "")
		return
	}

	// Attribution is derived from the authenticated principal, never trusted
	// from the request body. Without this, any holder of a valid token could
	// forge events for another tenant or impersonate another actor in the
	// immutable audit chain. (The in-cluster NATS fan-in path is separate and
	// unaffected; this HTTP ingest is the agent/external-integration path,
	// which is always behind JWT auth.)
	if claims, ok := pkgauth.ClaimsFromContext(r.Context()); ok && claims != nil {
		claimTenant := strings.TrimSpace(claims.TenantID)
		if claimTenant != "" {
			bodyTenant := strings.TrimSpace(req.Event.TenantID)
			if bodyTenant != "" && !strings.EqualFold(bodyTenant, claimTenant) {
				writeErr(w, http.StatusForbidden, "forbidden", "tenant_id does not match authenticated token", reqID, claimTenant)
				return
			}
			// Bind the event to the token's tenant; root/super-admin tokens
			// (empty tenant claim) retain cross-tenant publish capability.
			req.Event.TenantID = claimTenant
		}
		actor := strings.TrimSpace(claims.UserID)
		if actor == "" {
			actor = strings.TrimSpace(claims.ClientID)
		}
		if actor != "" {
			req.Event.ActorID = actor
		}
		if strings.TrimSpace(req.Event.ActorType) == "" {
			if strings.TrimSpace(claims.UserID) != "" {
				req.Event.ActorType = "user"
			} else if strings.TrimSpace(claims.ClientID) != "" {
				req.Event.ActorType = "service"
			}
		}
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
		writeErr(w, http.StatusServiceUnavailable, "audit_buffer_failed", "audit buffer write failed", reqID, req.Event.TenantID)
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
		Action:         strings.TrimSpace(r.URL.Query().Get("action")),
		ActionPrefixes: r.URL.Query()["action_prefix"],
		ActorID:        strings.TrimSpace(r.URL.Query().Get("actor_id")),
		Result:         strings.TrimSpace(r.URL.Query().Get("result")),
		TargetID:       strings.TrimSpace(r.URL.Query().Get("target_id")),
		SessionID:      strings.TrimSpace(r.URL.Query().Get("session_id")),
		CorrelationID:  strings.TrimSpace(r.URL.Query().Get("correlation_id")),
		RiskMin:        atoi(r.URL.Query().Get("risk_min")),
		Limit:          atoi(r.URL.Query().Get("limit")),
		Offset:         atoi(r.URL.Query().Get("offset")),
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

func (h *Handler) handleAuditConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	// Operational settings are returned to authenticated callers, but the
	// concrete WAL filesystem path is masked: the only thing operators need
	// to know externally is that the WAL is configured, not where it lives.
	walConfigured := strings.TrimSpace(h.svc.cfg.WALPath) != ""
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"fail_closed":     h.svc.cfg.FailClosed,
		"wal_configured":  walConfigured,
		"wal_max_size_mb": h.svc.cfg.WALMaxSizeMB,
		"request_id":      reqID,
	})
}

// handleFIPSBoundary returns the FIPS 140-3 module boundary declaration for this service.
func (h *Handler) handleFIPSBoundary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"module":           "kms-audit",
		"fips_level":       "FIPS 140-3 Level 1",
		"boundary_version": "1.0",
		"approved_algorithms": []string{
			"HMAC-SHA-256",
			"SHA-256",
			"SHA-384",
			"SHA-512",
			"AES-256-GCM",
			"TLS 1.3",
		},
		"non_approved_algorithms": []string{},
		"approved_key_sizes":      map[string]int{"HMAC-SHA-256": 256, "AES": 256},
		"services_in_boundary": []string{
			"audit event ingestion",
			"audit chain HMAC signing (HMAC-SHA-256)",
			"Merkle tree construction (SHA-256)",
			"WAL integrity (HMAC-SHA-256)",
			"TLS 1.3 transport (AES-256-GCM)",
		},
		"services_outside_boundary": []string{
			"event stream delivery through compliance connections (external TLS)",
			"NATS message transport (relayed from other KMS modules)",
		},
		"zeroization_policy":      "Keys are zeroized on process termination via runtime.SetFinalizer and explicit wipe calls",
		"random_number_generator": "crypto/rand (OS-provided CSPRNG)",
		"kdf_used":                "HKDF-SHA-256 (event signing key derivation where applicable)",
		"self_test_on_startup":    true,
		"continuous_health_test":  true,
		"tamper_evidence":         "HMAC-SHA-256 per event + Merkle epoch chain with cross-epoch SHA-256 linkage",
		"request_id":              reqID,
	})
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
	// A01 fix: verify the request tenant matches the authenticated JWT tenant
	if err := tenantcheck.Enforce(r, tenantID); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant_id does not match authenticated token", requestID, tenantID)
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
