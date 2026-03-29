package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// LineageEventType identifies the kind of operation that was performed on data.
type LineageEventType string

const (
	LineageEventCreate    LineageEventType = "create"
	LineageEventRead      LineageEventType = "read"
	LineageEventTransform LineageEventType = "transform"
	LineageEventExport    LineageEventType = "export"
	LineageEventDelete    LineageEventType = "delete"
	LineageEventEncrypt   LineageEventType = "encrypt"
	LineageEventDecrypt   LineageEventType = "decrypt"
	LineageEventSign      LineageEventType = "sign"
	LineageEventShare     LineageEventType = "share"
)

// validLineageEventTypes is the set of accepted event_type values.
var validLineageEventTypes = map[LineageEventType]struct{}{
	LineageEventCreate:    {},
	LineageEventRead:      {},
	LineageEventTransform: {},
	LineageEventExport:    {},
	LineageEventDelete:    {},
	LineageEventEncrypt:   {},
	LineageEventDecrypt:   {},
	LineageEventSign:      {},
	LineageEventShare:     {},
}

// LineageEvent records a single data-lineage occurrence.
type LineageEvent struct {
	ID          string           `json:"id"`
	TenantID    string           `json:"tenant_id"`
	EventType   LineageEventType `json:"event_type"`
	// Source: where data came from
	SourceID    string           `json:"source_id"`
	SourceType  string           `json:"source_type"` // "key", "secret", "certificate", "dataset", "application"
	SourceLabel string           `json:"source_label"`
	// Destination: where data went
	DestID      string           `json:"dest_id,omitempty"`
	DestType    string           `json:"dest_type,omitempty"`
	DestLabel   string           `json:"dest_label,omitempty"`
	// Context
	ActorID     string                 `json:"actor_id"`
	ActorType   string                 `json:"actor_type"` // "user", "service", "automation"
	ServiceName string                 `json:"service_name"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	OccurredAt  time.Time              `json:"occurred_at"`
	CreatedAt   time.Time              `json:"created_at"`
}

// LineageNode is a vertex in the lineage graph (a unique source or destination).
type LineageNode struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Label    string `json:"label"`
	EventCnt int    `json:"event_count"`
}

// LineageEdge is a directed relationship between two nodes in the lineage graph.
type LineageEdge struct {
	From      string           `json:"from"`
	To        string           `json:"to"`
	EventType LineageEventType `json:"event_type"`
	Count     int              `json:"count"`
}

// LineageGraph is the full graph for a tenant within a time window.
type LineageGraph struct {
	RequestID   string        `json:"request_id"`
	TenantID    string        `json:"tenant_id"`
	Nodes       []LineageNode `json:"nodes"`
	Edges       []LineageEdge `json:"edges"`
	TotalEvents int           `json:"total_events"`
}

// LineageImpact describes the blast radius of rotating or deleting a key.
type LineageImpact struct {
	RequestID        string        `json:"request_id"`
	KeyID            string        `json:"key_id"`
	TenantID         string        `json:"tenant_id"`
	DirectUsageCount int           `json:"direct_usage_count"`
	AffectedServices []string      `json:"affected_services"`
	AffectedActors   []string      `json:"affected_actors"`
	DataFlows        []LineageEdge `json:"data_flows"`
	RiskLevel        string        `json:"risk_level"` // "low","medium","high","critical"
	RotationImpact   string        `json:"rotation_impact"`
}

// handleRecordLineageEvent records a new lineage event.
// POST /discovery/lineage/record
func (h *Handler) handleRecordLineageEvent(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)

	var req LineageEvent
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}

	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	if req.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}

	// Validate event_type.
	if _, ok := validLineageEventTypes[req.EventType]; !ok {
		writeErr(w, http.StatusBadRequest, "bad_request",
			fmt.Sprintf("event_type %q is not valid; must be one of: create, read, transform, export, delete, encrypt, decrypt, sign, share", req.EventType),
			reqID, req.TenantID)
		return
	}
	if strings.TrimSpace(req.SourceID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "source_id is required", reqID, req.TenantID)
		return
	}
	if strings.TrimSpace(req.ActorID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "actor_id is required", reqID, req.TenantID)
		return
	}

	// Server-side fields.
	req.ID = newID("lev")
	now := time.Now().UTC()
	req.CreatedAt = now
	if req.OccurredAt.IsZero() {
		req.OccurredAt = now
	}
	if req.Metadata == nil {
		req.Metadata = map[string]interface{}{}
	}

	stored, err := h.svc.store.InsertLineageEvent(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	_ = h.svc.publishAudit(r.Context(), "audit.discovery.lineage_recorded", stored.TenantID, map[string]interface{}{
		"event_id":     stored.ID,
		"event_type":   string(stored.EventType),
		"source_id":    stored.SourceID,
		"source_type":  stored.SourceType,
		"dest_id":      stored.DestID,
		"actor_id":     stored.ActorID,
		"service_name": stored.ServiceName,
	})
	writeJSON(w, http.StatusCreated, map[string]interface{}{"event": stored, "request_id": reqID})
}

// handleGetKeyLineage returns all lineage events involving a specific key.
// GET /discovery/lineage/key/{key_id}
func (h *Handler) handleGetKeyLineage(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	keyID := strings.TrimSpace(r.PathValue("key_id"))
	if keyID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "key_id path parameter is required", reqID, tenantID)
		return
	}

	events, err := h.svc.store.GetLineageByKey(r.Context(), tenantID, keyID, 500)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"key_id":     keyID,
		"events":     events,
		"request_id": reqID,
	})
}

// handleGetLineageGraph builds and returns a graph of lineage events for a tenant.
// GET /discovery/lineage/graph
func (h *Handler) handleGetLineageGraph(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}

	// Parse query params.
	since := time.Now().UTC().AddDate(0, 0, -30)
	if sv := strings.TrimSpace(r.URL.Query().Get("since")); sv != "" {
		if t, err := time.Parse(time.RFC3339, sv); err == nil {
			since = t.UTC()
		}
	}
	limit := atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 1000
	}
	if limit > 5000 {
		limit = 5000
	}

	events, err := h.svc.store.GetLineageGraph(r.Context(), tenantID, since, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	graph := buildLineageGraph(reqID, tenantID, events)
	writeJSON(w, http.StatusOK, map[string]interface{}{"graph": graph, "request_id": reqID})
}

// handleGetLineageImpact returns the blast-radius analysis for a key.
// GET /discovery/lineage/impact/{key_id}
func (h *Handler) handleGetLineageImpact(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	keyID := strings.TrimSpace(r.PathValue("key_id"))
	if keyID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "key_id path parameter is required", reqID, tenantID)
		return
	}

	events, err := h.svc.store.GetLineageByKey(r.Context(), tenantID, keyID, 500)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	impact := computeLineageImpact(reqID, tenantID, keyID, events)
	writeJSON(w, http.StatusOK, map[string]interface{}{"impact": impact, "request_id": reqID})
}

// buildLineageGraph assembles a LineageGraph from a flat list of events.
func buildLineageGraph(reqID, tenantID string, events []LineageEvent) LineageGraph {
	// Track unique nodes: id -> (type, label, count).
	type nodeAccum struct {
		typ   string
		label string
		count int
	}
	nodes := map[string]*nodeAccum{}

	ensureNode := func(id, typ, label string) {
		if id == "" {
			return
		}
		n, ok := nodes[id]
		if !ok {
			nodes[id] = &nodeAccum{typ: typ, label: label}
			return
		}
		n.count++
		// Prefer non-empty type/label if we now have more info.
		if n.typ == "" && typ != "" {
			n.typ = typ
		}
		if n.label == "" && label != "" {
			n.label = label
		}
	}

	// Track edges: (from, to, eventType) -> count.
	type edgeKey struct {
		from      string
		to        string
		eventType LineageEventType
	}
	edgeCounts := map[edgeKey]int{}

	for _, e := range events {
		ensureNode(e.SourceID, e.SourceType, e.SourceLabel)
		if e.DestID != "" {
			ensureNode(e.DestID, e.DestType, e.DestLabel)
			edgeCounts[edgeKey{from: e.SourceID, to: e.DestID, eventType: e.EventType}]++
		}
	}

	// Materialise nodes.
	nodeList := make([]LineageNode, 0, len(nodes))
	for id, n := range nodes {
		nodeList = append(nodeList, LineageNode{
			ID:       id,
			Type:     n.typ,
			Label:    n.label,
			EventCnt: n.count,
		})
	}

	// Materialise edges.
	edgeList := make([]LineageEdge, 0, len(edgeCounts))
	for k, cnt := range edgeCounts {
		edgeList = append(edgeList, LineageEdge{
			From:      k.from,
			To:        k.to,
			EventType: k.eventType,
			Count:     cnt,
		})
	}

	return LineageGraph{
		RequestID:   reqID,
		TenantID:    tenantID,
		Nodes:       nodeList,
		Edges:       edgeList,
		TotalEvents: len(events),
	}
}

// computeLineageImpact derives impact metrics for a key from its lineage events.
func computeLineageImpact(reqID, tenantID, keyID string, events []LineageEvent) LineageImpact {
	serviceSet := map[string]struct{}{}
	actorSet := map[string]struct{}{}

	type edgeKey struct {
		from      string
		to        string
		eventType LineageEventType
	}
	edgeCounts := map[edgeKey]int{}

	for _, e := range events {
		if svc := strings.TrimSpace(e.ServiceName); svc != "" {
			serviceSet[svc] = struct{}{}
		}
		if actor := strings.TrimSpace(e.ActorID); actor != "" {
			actorSet[actor] = struct{}{}
		}
		if e.DestID != "" {
			edgeCounts[edgeKey{from: e.SourceID, to: e.DestID, eventType: e.EventType}]++
		}
	}

	services := make([]string, 0, len(serviceSet))
	for svc := range serviceSet {
		services = append(services, svc)
	}
	actors := make([]string, 0, len(actorSet))
	for actor := range actorSet {
		actors = append(actors, actor)
	}

	flows := make([]LineageEdge, 0, len(edgeCounts))
	for k, cnt := range edgeCounts {
		flows = append(flows, LineageEdge{
			From:      k.from,
			To:        k.to,
			EventType: k.eventType,
			Count:     cnt,
		})
	}

	total := len(events)
	riskLevel := "low"
	switch {
	case total > 100:
		riskLevel = "critical"
	case total > 20:
		riskLevel = "high"
	case total > 5:
		riskLevel = "medium"
	}

	rotationImpact := buildRotationImpactMsg(keyID, services, actors)

	return LineageImpact{
		RequestID:        reqID,
		KeyID:            keyID,
		TenantID:         tenantID,
		DirectUsageCount: total,
		AffectedServices: services,
		AffectedActors:   actors,
		DataFlows:        flows,
		RiskLevel:        riskLevel,
		RotationImpact:   rotationImpact,
	}
}

// buildRotationImpactMsg produces a human-readable rotation impact description.
func buildRotationImpactMsg(keyID string, services, actors []string) string {
	svcCount := len(services)
	actorCount := len(actors)

	var svcPart, actorPart string
	if svcCount == 0 {
		svcPart = "no services"
	} else {
		svcPart = fmt.Sprintf("%d service%s (%s)", svcCount, pluralS(svcCount), strings.Join(services, ", "))
	}
	if actorCount == 0 {
		actorPart = "no actors"
	} else {
		actorPart = fmt.Sprintf("%d actor%s", actorCount, pluralS(actorCount))
	}

	return fmt.Sprintf("Rotating key %s will affect %s and %s.", keyID, svcPart, actorPart)
}

// pluralS returns "s" when n != 1, otherwise "".
func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
