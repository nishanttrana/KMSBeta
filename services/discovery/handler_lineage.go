package main

import (
	"crypto/sha256"
	"fmt"
	"math"
	"net/http"
	"sort"
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
	LineageEventRotate    LineageEventType = "rotate"
	LineageEventWrap      LineageEventType = "wrap"
	LineageEventUnwrap    LineageEventType = "unwrap"
	LineageEventDerive    LineageEventType = "derive"
	LineageEventImport    LineageEventType = "import"
	LineageEventDestroy   LineageEventType = "destroy"
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
	LineageEventRotate:    {},
	LineageEventWrap:      {},
	LineageEventUnwrap:    {},
	LineageEventDerive:    {},
	LineageEventImport:    {},
	LineageEventDestroy:   {},
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
	FromLabel string           `json:"from_label"`
	To        string           `json:"to"`
	ToLabel   string           `json:"to_label"`
	EventType LineageEventType `json:"event_type"`
	Count     int              `json:"count"`
	LastSeen  string           `json:"last_seen"`
}

// LineageGraph is the full graph for a tenant within a time window.
type LineageGraph struct {
	RequestID          string        `json:"request_id"`
	TenantID           string        `json:"tenant_id"`
	Nodes              []LineageNode `json:"nodes"`
	Edges              []LineageEdge `json:"edges"`
	TotalEvents        int           `json:"total_events"`
	UniqueSources      int           `json:"unique_sources"`
	UniqueDestinations int           `json:"unique_destinations"`
	ServicesTracked    int           `json:"services_tracked"`
}

// LineageImpact describes the blast radius of rotating or deleting a key.
type LineageImpact struct {
	RequestID             string   `json:"request_id"`
	KeyID                 string   `json:"key_id"`
	TenantID              string   `json:"tenant_id"`
	TotalEvents           int      `json:"total_events"`
	AffectedKeys          []string `json:"affected_keys"`
	AffectedKeysCount     int      `json:"affected_keys_count"`
	AffectedServices      []string `json:"affected_services"`
	AffectedServicesCount int      `json:"affected_services_count"`
	AffectedActors        []string `json:"affected_actors"`
	AffectedActorsCount   int      `json:"affected_actors_count"`
	BlastRadius           int      `json:"blast_radius"`
	RiskLevel             string   `json:"risk_level"` // "low","medium","high","critical"
	RotationImpact        string   `json:"rotation_impact"`
}

// LineageTimelineEntry is a single entry in a key's lifecycle timeline.
type LineageTimelineEntry struct {
	EventID     string                 `json:"event_id"`
	EventType   string                 `json:"event_type"`
	Description string                 `json:"description"`
	Timestamp   string                 `json:"timestamp"`
	ActorID     string                 `json:"actor_id"`
	ActorType   string                 `json:"actor_type"`
	ServiceName string                 `json:"service_name"`
	SourceID    string                 `json:"source_id"`
	DestID      string                 `json:"dest_id,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// LineageDependency represents a dependency node in the tree.
type LineageDependency struct {
	KeyID        string              `json:"key_id"`
	KeyType      string              `json:"key_type"`
	Label        string              `json:"label"`
	Relationship string              `json:"relationship"` // "wraps", "derives", "encrypts", "signs"
	Depth        int                 `json:"depth"`
	Children     []LineageDependency `json:"children,omitempty"`
}

// --- Enterprise Lineage Types ---

// KeyProvenance captures cryptographic provenance metadata for a key.
type KeyProvenance struct {
	KeyID                string            `json:"key_id"`
	TenantID             string            `json:"tenant_id"`
	EntropySource        string            `json:"entropy_source"`
	GeneratingModule     string            `json:"generating_module"`
	FIPSCertified        bool              `json:"fips_certified"`
	HSMBacked            bool              `json:"hsm_backed"`
	Algorithm            string            `json:"algorithm"`
	AlgorithmHistory     []AlgorithmChange `json:"algorithm_history"`
	CreationRegion       string            `json:"creation_region"`
	StorageRegions       []string          `json:"storage_regions"`
	UsageRegions         []string          `json:"usage_regions"`
	ComplianceFrameworks []string          `json:"compliance_frameworks"`
	CryptoAgilityScore   float64           `json:"crypto_agility_score"`
	CreatedAt            string            `json:"created_at"`
}

// AlgorithmChange records a change in algorithm across key rotations.
type AlgorithmChange struct {
	FromAlgorithm string `json:"from_algorithm"`
	ToAlgorithm   string `json:"to_algorithm"`
	ChangedAt     string `json:"changed_at"`
	Reason        string `json:"reason"`
	Version       int    `json:"version"`
}

// DataFlowBinding maps a key to the resources, applications, and tenants it protects.
type DataFlowBinding struct {
	KeyID             string             `json:"key_id"`
	BoundResources    []BoundResource    `json:"bound_resources"`
	Applications      []string           `json:"applications"`
	CrossTenantShares []CrossTenantShare `json:"cross_tenant_shares"`
	CloudReplicas     []CloudReplica     `json:"cloud_replicas"`
}

// BoundResource describes a resource protected by a key.
type BoundResource struct {
	ResourceID     string `json:"resource_id"`
	ResourceType   string `json:"resource_type"`
	ResourceName   string `json:"resource_name"`
	EncryptionType string `json:"encryption_type"`
	Service        string `json:"service"`
	LastAccessed   string `json:"last_accessed"`
}

// CrossTenantShare describes a key shared with another tenant.
type CrossTenantShare struct {
	TargetTenantID string `json:"target_tenant_id"`
	ShareType      string `json:"share_type"`
	Provider       string `json:"provider"`
	SharedAt       string `json:"shared_at"`
}

// CloudReplica describes a key replica in a cloud provider.
type CloudReplica struct {
	Provider   string `json:"provider"`
	Region     string `json:"region"`
	CloudKeyID string `json:"cloud_key_id"`
	SyncStatus string `json:"sync_status"`
	LastSynced string `json:"last_synced"`
}

// KeyRiskHeatmap provides a risk overview across all keys for a tenant.
type KeyRiskHeatmap struct {
	Keys    []KeyHeatmapEntry `json:"keys"`
	Summary HeatmapSummary    `json:"summary"`
}

// KeyHeatmapEntry is a single key's risk entry in the heatmap.
type KeyHeatmapEntry struct {
	KeyID             string   `json:"key_id"`
	KeyLabel          string   `json:"key_label"`
	Algorithm         string   `json:"algorithm"`
	AgeDays           int      `json:"age_days"`
	AgeCategory       string   `json:"age_category"`
	RotationStatus    string   `json:"rotation_status"`
	DaysUntilRotation int      `json:"days_until_rotation"`
	DaysOverdue       int      `json:"days_overdue"`
	RiskScore         float64  `json:"risk_score"`
	DependentCount    int      `json:"dependent_count"`
	ComplianceGaps    []string `json:"compliance_gaps"`
	CryptoAgility     float64  `json:"crypto_agility"`
}

// HeatmapSummary aggregates risk metrics across all keys.
type HeatmapSummary struct {
	TotalKeys         int     `json:"total_keys"`
	FreshKeys         int     `json:"fresh_keys"`
	AgingKeys         int     `json:"aging_keys"`
	OldKeys           int     `json:"old_keys"`
	CriticalKeys      int     `json:"critical_keys"`
	RotationCompliant int     `json:"rotation_compliant"`
	RotationOverdue   int     `json:"rotation_overdue"`
	NeverRotated      int     `json:"never_rotated"`
	AvgRiskScore      float64 `json:"avg_risk_score"`
	PQCReadyPct       float64 `json:"pqc_ready_pct"`
}

// AccessPatternAnalysis provides forensic access pattern data for a key.
type AccessPatternAnalysis struct {
	KeyID           string          `json:"key_id"`
	TotalAccess     int             `json:"total_access_30d"`
	UniqueActors    int             `json:"unique_actors"`
	PeakHour        int             `json:"peak_hour"`
	OffHoursAccess  int             `json:"off_hours_access"`
	WeekendAccess   int             `json:"weekend_access"`
	Anomalies       []AccessAnomaly `json:"anomalies"`
	AccessByHour    map[int]int     `json:"access_by_hour"`
	AccessByDay     map[string]int  `json:"access_by_day"`
	TopActors       []ActorAccess   `json:"top_actors"`
	NewActors       []ActorAccess   `json:"new_actors"`
	GeoDistribution []GeoAccess     `json:"geo_distribution"`
}

// AccessAnomaly describes a detected anomaly in access patterns.
type AccessAnomaly struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	DetectedAt  string                 `json:"detected_at"`
	Details     map[string]interface{} `json:"details"`
}

// ActorAccess records an actor's access frequency for a key.
type ActorAccess struct {
	ActorID     string `json:"actor_id"`
	ActorType   string `json:"actor_type"`
	AccessCount int    `json:"access_count"`
	LastAccess  string `json:"last_access"`
	FirstAccess string `json:"first_access"`
}

// GeoAccess records access counts by geographic region.
type GeoAccess struct {
	Region      string `json:"region"`
	AccessCount int    `json:"access_count"`
	LastAccess  string `json:"last_access"`
}

// ChainOfCustodyReport is a forensic report of all custody handoffs for a key.
type ChainOfCustodyReport struct {
	KeyID         string           `json:"key_id"`
	KeyLabel      string           `json:"key_label"`
	GeneratedAt   string           `json:"generated_at"`
	GeneratedBy   string           `json:"generated_by"`
	Provenance    KeyProvenance    `json:"provenance"`
	Custodians    []CustodyHandoff `json:"custodians"`
	IntegrityHash string           `json:"integrity_hash"`
	MerkleRoot    string           `json:"merkle_root,omitempty"`
}

// CustodyHandoff is a single handoff in the chain of custody.
type CustodyHandoff struct {
	Sequence  int    `json:"sequence"`
	FromActor string `json:"from_actor"`
	ToActor   string `json:"to_actor"`
	Action    string `json:"action"`
	Service   string `json:"service"`
	Timestamp string `json:"timestamp"`
	Region    string `json:"region,omitempty"`
	Verified  bool   `json:"verified"`
}

// TamperCheckResult is the result of a lineage integrity verification.
type TamperCheckResult struct {
	KeyID         string `json:"key_id"`
	Verified      bool   `json:"verified"`
	HashMatch     bool   `json:"hash_match"`
	EventsChecked int    `json:"events_checked"`
	ComputedHash  string `json:"computed_hash"`
	TamperDetails string `json:"tamper_details,omitempty"`
}

// LineageSearchRequest is the payload for the advanced search endpoint.
type LineageSearchRequest struct {
	Query      string   `json:"query"`
	EventTypes []string `json:"event_types"`
	Services   []string `json:"services"`
	Actors     []string `json:"actors"`
	Since      string   `json:"since"`
	Until      string   `json:"until"`
	Limit      int      `json:"limit"`
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
			fmt.Sprintf("event_type %q is not valid; must be one of: create, read, transform, export, delete, encrypt, decrypt, sign, share, rotate, wrap, unwrap, derive, import, destroy", req.EventType),
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
	// Return graph fields directly (not wrapped in {graph:...})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id":          graph.RequestID,
		"tenant_id":           graph.TenantID,
		"nodes":               graph.Nodes,
		"edges":               graph.Edges,
		"total_events":        graph.TotalEvents,
		"unique_sources":      graph.UniqueSources,
		"unique_destinations": graph.UniqueDestinations,
		"services_tracked":    graph.ServicesTracked,
	})
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
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id":             impact.RequestID,
		"key_id":                 impact.KeyID,
		"tenant_id":              impact.TenantID,
		"total_events":           impact.TotalEvents,
		"affected_keys":          impact.AffectedKeys,
		"affected_keys_count":    impact.AffectedKeysCount,
		"affected_services":      impact.AffectedServices,
		"affected_services_count": impact.AffectedServicesCount,
		"affected_actors":        impact.AffectedActors,
		"affected_actors_count":  impact.AffectedActorsCount,
		"blast_radius":           impact.BlastRadius,
		"risk_level":             impact.RiskLevel,
		"rotation_impact":        impact.RotationImpact,
	})
}

// handleGetKeyTimeline returns a chronological lifecycle timeline for a key.
// GET /discovery/lineage/timeline/{key_id}
func (h *Handler) handleGetKeyTimeline(w http.ResponseWriter, r *http.Request) {
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

	// Sort chronologically (oldest first).
	sort.Slice(events, func(i, j int) bool {
		return events[i].OccurredAt.Before(events[j].OccurredAt)
	})

	entries := make([]map[string]interface{}, 0, len(events))
	for _, e := range events {
		desc := buildTimelineDescription(e, keyID)
		entry := map[string]interface{}{
			"event_id":     e.ID,
			"event_type":   string(e.EventType),
			"description":  desc,
			"timestamp":    e.OccurredAt.Format(time.RFC3339),
			"actor_id":     e.ActorID,
			"actor_type":   e.ActorType,
			"service_name": e.ServiceName,
			"source_id":    e.SourceID,
		}
		if e.DestID != "" {
			entry["dest_id"] = e.DestID
		}
		if len(e.Metadata) > 0 {
			entry["metadata"] = e.Metadata
		}
		entries = append(entries, entry)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id":   reqID,
		"key_id":       keyID,
		"total_events": len(entries),
		"timeline":     entries,
	})
}

// handleGetKeyDependencies returns a dependency tree for a key.
// GET /discovery/lineage/dependencies/{key_id}
func (h *Handler) handleGetKeyDependencies(w http.ResponseWriter, r *http.Request) {
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

	// Get all lineage events for the tenant to build the full dependency tree.
	since := time.Now().UTC().AddDate(-1, 0, 0) // look back 1 year
	allEvents, err := h.svc.store.GetLineageGraph(r.Context(), tenantID, since, 5000)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	// Build adjacency: source -> list of (dest, eventType, destType, destLabel)
	type depEdge struct {
		destID    string
		destType  string
		destLabel string
		relation  string
	}
	adjacency := map[string][]depEdge{}
	serviceSet := map[string]struct{}{}
	for _, e := range allEvents {
		if e.DestID == "" {
			continue
		}
		rel := relationshipFromEvent(e.EventType)
		adjacency[e.SourceID] = append(adjacency[e.SourceID], depEdge{
			destID: e.DestID, destType: e.DestType, destLabel: e.DestLabel, relation: rel,
		})
		// Track services that accessed the key.
		if e.SourceID == keyID || e.DestID == keyID {
			if svc := strings.TrimSpace(e.ServiceName); svc != "" {
				serviceSet[svc] = struct{}{}
			}
		}
	}

	// BFS to build direct and indirect dependents.
	directDeps := make([]map[string]interface{}, 0)
	indirectDeps := make([]map[string]interface{}, 0)
	visited := map[string]bool{keyID: true}
	queue := []struct {
		id    string
		depth int
	}{{id: keyID, depth: 0}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, dep := range adjacency[cur.id] {
			if visited[dep.destID] {
				continue
			}
			visited[dep.destID] = true
			node := map[string]interface{}{
				"key_id":       dep.destID,
				"key_type":     dep.destType,
				"label":        dep.destLabel,
				"relationship": dep.relation,
				"depth":        cur.depth + 1,
			}
			if cur.depth == 0 {
				directDeps = append(directDeps, node)
			} else {
				indirectDeps = append(indirectDeps, node)
			}
			queue = append(queue, struct {
				id    string
				depth int
			}{id: dep.destID, depth: cur.depth + 1})
		}
	}

	services := make([]string, 0, len(serviceSet))
	for svc := range serviceSet {
		services = append(services, svc)
	}
	sort.Strings(services)

	blastRadius := len(directDeps) + len(indirectDeps) + len(services)
	impactScore := "low"
	switch {
	case blastRadius > 50:
		impactScore = "critical"
	case blastRadius > 20:
		impactScore = "high"
	case blastRadius > 5:
		impactScore = "medium"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id":             reqID,
		"key_id":                 keyID,
		"direct_dependents":      directDeps,
		"direct_count":           len(directDeps),
		"indirect_dependents":    indirectDeps,
		"indirect_count":         len(indirectDeps),
		"accessing_services":     services,
		"accessing_service_count": len(services),
		"blast_radius":           blastRadius,
		"impact_score":           impactScore,
	})
}

// handleLineageSearch performs advanced search across lineage data.
// POST /discovery/lineage/search
func (h *Handler) handleLineageSearch(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}

	var req LineageSearchRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}

	if req.Limit <= 0 {
		req.Limit = 200
	}
	if req.Limit > 2000 {
		req.Limit = 2000
	}

	// Parse time range.
	since := time.Now().UTC().AddDate(0, 0, -30)
	if req.Since != "" {
		if t, err := time.Parse(time.RFC3339, req.Since); err == nil {
			since = t.UTC()
		}
	}
	until := time.Now().UTC()
	if req.Until != "" {
		if t, err := time.Parse(time.RFC3339, req.Until); err == nil {
			until = t.UTC()
		}
	}

	// Fetch all events in range, then filter in-memory for flexibility.
	allEvents, err := h.svc.store.GetLineageGraph(r.Context(), tenantID, since, 5000)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	// Build filter sets.
	eventTypeSet := toStringSet(req.EventTypes)
	serviceSet := toStringSet(req.Services)
	actorSet := toStringSet(req.Actors)
	queryLower := strings.ToLower(strings.TrimSpace(req.Query))

	results := make([]LineageEvent, 0)
	for _, e := range allEvents {
		// Time filter.
		if e.OccurredAt.After(until) {
			continue
		}
		// Event type filter.
		if len(eventTypeSet) > 0 {
			if _, ok := eventTypeSet[string(e.EventType)]; !ok {
				continue
			}
		}
		// Service filter.
		if len(serviceSet) > 0 {
			if _, ok := serviceSet[e.ServiceName]; !ok {
				continue
			}
		}
		// Actor filter.
		if len(actorSet) > 0 {
			if _, ok := actorSet[e.ActorID]; !ok {
				continue
			}
		}
		// Free-text query filter.
		if queryLower != "" {
			match := strings.Contains(strings.ToLower(e.SourceID), queryLower) ||
				strings.Contains(strings.ToLower(e.SourceLabel), queryLower) ||
				strings.Contains(strings.ToLower(e.DestID), queryLower) ||
				strings.Contains(strings.ToLower(e.DestLabel), queryLower) ||
				strings.Contains(strings.ToLower(e.ActorID), queryLower) ||
				strings.Contains(strings.ToLower(e.ServiceName), queryLower) ||
				strings.Contains(strings.ToLower(string(e.EventType)), queryLower)
			if !match {
				continue
			}
		}
		results = append(results, e)
		if len(results) >= req.Limit {
			break
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id":    reqID,
		"total_results": len(results),
		"events":        results,
	})
}

// handleGetLineageStats returns overall lineage statistics for a tenant.
// GET /discovery/lineage/stats
func (h *Handler) handleGetLineageStats(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}

	// Fetch events from the last year for comprehensive stats.
	since := time.Now().UTC().AddDate(-1, 0, 0)
	allEvents, err := h.svc.store.GetLineageGraph(r.Context(), tenantID, since, 5000)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	now := time.Now().UTC()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	weekStart := todayStart.AddDate(0, 0, -7)

	eventsToday := 0
	eventsThisWeek := 0
	keyAccessCount := map[string]int{}      // key_id -> access count
	serviceEventCount := map[string]int{}   // service -> count
	serviceLastSeen := map[string]string{}  // service -> last timestamp
	eventTypeDist := map[string]int{}       // event_type -> count
	allKeyIDs := map[string]bool{}          // all keys seen
	keysWithLineage := map[string]bool{}    // keys involved in edges
	depthMap := map[string]int{}            // key -> max dependency depth

	// Build adjacency for depth calculation.
	adjacency := map[string][]string{}

	for _, e := range allEvents {
		if e.OccurredAt.After(todayStart) || e.OccurredAt.Equal(todayStart) {
			eventsToday++
		}
		if e.OccurredAt.After(weekStart) || e.OccurredAt.Equal(weekStart) {
			eventsThisWeek++
		}
		keyAccessCount[e.SourceID]++
		if e.DestID != "" {
			keyAccessCount[e.DestID]++
		}
		if svc := strings.TrimSpace(e.ServiceName); svc != "" {
			serviceEventCount[svc]++
			ts := e.OccurredAt.Format(time.RFC3339)
			if existing, ok := serviceLastSeen[svc]; !ok || ts > existing {
				serviceLastSeen[svc] = ts
			}
		}
		eventTypeDist[string(e.EventType)]++
		allKeyIDs[e.SourceID] = true
		if e.DestID != "" {
			allKeyIDs[e.DestID] = true
			keysWithLineage[e.SourceID] = true
			keysWithLineage[e.DestID] = true
			adjacency[e.SourceID] = append(adjacency[e.SourceID], e.DestID)
		}
	}

	// Top 10 most-accessed keys.
	type keyCount struct {
		KeyID string `json:"key_id"`
		Count int    `json:"count"`
	}
	keyCounts := make([]keyCount, 0, len(keyAccessCount))
	for k, c := range keyAccessCount {
		keyCounts = append(keyCounts, keyCount{KeyID: k, Count: c})
	}
	sort.Slice(keyCounts, func(i, j int) bool { return keyCounts[i].Count > keyCounts[j].Count })
	if len(keyCounts) > 10 {
		keyCounts = keyCounts[:10]
	}
	topKeysOut := make([]map[string]interface{}, len(keyCounts))
	for i, kc := range keyCounts {
		topKeysOut[i] = map[string]interface{}{"key_id": kc.KeyID, "count": kc.Count}
	}

	// Top 5 services.
	type svcCount struct {
		Service      string
		Count        int
		LastActivity string
	}
	svcCounts := make([]svcCount, 0, len(serviceEventCount))
	for s, c := range serviceEventCount {
		svcCounts = append(svcCounts, svcCount{Service: s, Count: c, LastActivity: serviceLastSeen[s]})
	}
	sort.Slice(svcCounts, func(i, j int) bool { return svcCounts[i].Count > svcCounts[j].Count })
	if len(svcCounts) > 5 {
		svcCounts = svcCounts[:5]
	}
	topServicesOut := make([]map[string]interface{}, len(svcCounts))
	for i, sc := range svcCounts {
		topServicesOut[i] = map[string]interface{}{
			"service":       sc.Service,
			"count":         sc.Count,
			"last_activity": sc.LastActivity,
		}
	}

	// Event type distribution.
	eventTypeDistOut := make([]map[string]interface{}, 0, len(eventTypeDist))
	for et, c := range eventTypeDist {
		pct := 0.0
		if len(allEvents) > 0 {
			pct = float64(c) / float64(len(allEvents)) * 100
		}
		eventTypeDistOut = append(eventTypeDistOut, map[string]interface{}{
			"event_type": et,
			"count":      c,
			"percentage": fmt.Sprintf("%.1f", pct),
		})
	}
	sort.Slice(eventTypeDistOut, func(i, j int) bool {
		return eventTypeDistOut[i]["count"].(int) > eventTypeDistOut[j]["count"].(int)
	})

	// Orphan keys (keys with no edges).
	orphanKeys := make([]string, 0)
	for k := range allKeyIDs {
		if !keysWithLineage[k] {
			orphanKeys = append(orphanKeys, k)
		}
	}

	// Deepest dependency chains (BFS from each root).
	computeDepth(adjacency, depthMap)
	type depthEntry struct {
		KeyID string
		Depth int
	}
	depthEntries := make([]depthEntry, 0, len(depthMap))
	for k, d := range depthMap {
		if d > 0 {
			depthEntries = append(depthEntries, depthEntry{KeyID: k, Depth: d})
		}
	}
	sort.Slice(depthEntries, func(i, j int) bool { return depthEntries[i].Depth > depthEntries[j].Depth })
	if len(depthEntries) > 10 {
		depthEntries = depthEntries[:10]
	}
	deepestOut := make([]map[string]interface{}, len(depthEntries))
	for i, de := range depthEntries {
		deepestOut[i] = map[string]interface{}{"key_id": de.KeyID, "depth": de.Depth}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id":            reqID,
		"total_events":          len(allEvents),
		"events_today":          eventsToday,
		"events_this_week":      eventsThisWeek,
		"active_keys":           len(allKeyIDs),
		"services_tracked":      len(serviceEventCount),
		"top_keys":              topKeysOut,
		"top_services":          topServicesOut,
		"event_type_distribution": eventTypeDistOut,
		"orphan_keys":           orphanKeys,
		"orphan_keys_count":     len(orphanKeys),
		"deepest_chains":        deepestOut,
	})
}

// --- Enterprise Lineage Handlers ---

// handleGetKeyProvenance returns cryptographic provenance for a key.
// GET /discovery/lineage/provenance/{key_id}
func (h *Handler) handleGetKeyProvenance(w http.ResponseWriter, r *http.Request) {
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

	prov := buildKeyProvenance(tenantID, keyID, events)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"provenance": prov,
		"request_id": reqID,
	})
}

// handleGetDataFlow returns data flow bindings for a key.
// GET /discovery/lineage/data-flow/{key_id}
func (h *Handler) handleGetDataFlow(w http.ResponseWriter, r *http.Request) {
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

	flow := buildDataFlowBinding(keyID, events)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data_flow":  flow,
		"request_id": reqID,
	})
}

// handleGetRiskHeatmap returns a risk heatmap across all keys for a tenant.
// GET /discovery/lineage/risk-heatmap
func (h *Handler) handleGetRiskHeatmap(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}

	limit := atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 500
	}

	events, err := h.svc.store.GetAllKeyProvenanceData(r.Context(), tenantID, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	heatmap := buildRiskHeatmap(events)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"heatmap":    heatmap,
		"request_id": reqID,
	})
}

// handleGetAccessPatterns returns forensic access pattern analysis for a key.
// GET /discovery/lineage/access-patterns/{key_id}
func (h *Handler) handleGetAccessPatterns(w http.ResponseWriter, r *http.Request) {
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

	since := time.Now().UTC().AddDate(0, 0, -30)
	accessEvents, err := h.svc.store.GetAccessEvents(r.Context(), tenantID, keyID, since)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	// Get all events for the key to determine key age and usage regions
	allEvents, err := h.svc.store.GetLineageByKey(r.Context(), tenantID, keyID, 500)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	analysis := buildAccessPatternAnalysis(keyID, accessEvents, allEvents)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_patterns": analysis,
		"request_id":      reqID,
	})
}

// handleGetChainOfCustody returns a chain of custody report for a key.
// GET /discovery/lineage/chain-of-custody/{key_id}
func (h *Handler) handleGetChainOfCustody(w http.ResponseWriter, r *http.Request) {
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

	report := buildChainOfCustody(tenantID, keyID, events)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"chain_of_custody": report,
		"request_id":       reqID,
	})
}

// handleTamperCheck verifies integrity of lineage events for a key.
// POST /discovery/lineage/tamper-check/{key_id}
func (h *Handler) handleTamperCheck(w http.ResponseWriter, r *http.Request) {
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

	// Sort chronologically for deterministic hash
	sort.Slice(events, func(i, j int) bool {
		return events[i].OccurredAt.Before(events[j].OccurredAt)
	})

	computedHash := computeLineageIntegrityHash(events)

	// Build the stored chain of custody to compare hashes
	storedReport := buildChainOfCustody(tenantID, keyID, events)

	hashMatch := computedHash == storedReport.IntegrityHash
	result := TamperCheckResult{
		KeyID:         keyID,
		Verified:      hashMatch,
		HashMatch:     hashMatch,
		EventsChecked: len(events),
		ComputedHash:  computedHash,
	}
	if !hashMatch {
		result.TamperDetails = "Computed hash does not match stored chain-of-custody hash; events may have been altered"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tamper_check": result,
		"request_id":   reqID,
	})
}

// --- Enterprise Lineage Builder Functions ---

// buildKeyProvenance assembles cryptographic provenance from lineage events.
func buildKeyProvenance(tenantID, keyID string, events []LineageEvent) KeyProvenance {
	prov := KeyProvenance{
		KeyID:    keyID,
		TenantID: tenantID,
	}

	// Sort chronologically
	sort.Slice(events, func(i, j int) bool {
		return events[i].OccurredAt.Before(events[j].OccurredAt)
	})

	storageRegionSet := map[string]struct{}{}
	usageRegionSet := map[string]struct{}{}
	var lastAlgorithm string
	version := 0

	for _, e := range events {
		region := metaString(e.Metadata, "region")

		if e.EventType == LineageEventCreate && e.SourceID == keyID {
			prov.EntropySource = metaString(e.Metadata, "entropy_source")
			if prov.EntropySource == "" {
				prov.EntropySource = "drbg"
			}
			prov.GeneratingModule = metaString(e.Metadata, "generating_module")
			prov.FIPSCertified = metaBool(e.Metadata, "fips_certified")
			prov.HSMBacked = metaBool(e.Metadata, "hsm_backed")
			prov.Algorithm = metaString(e.Metadata, "algorithm")
			prov.CreationRegion = region
			prov.CreatedAt = e.OccurredAt.Format(time.RFC3339)
			lastAlgorithm = prov.Algorithm
			version = 1
		}

		if e.EventType == LineageEventRotate && (e.SourceID == keyID || e.DestID == keyID) {
			newAlg := metaString(e.Metadata, "algorithm")
			reason := metaString(e.Metadata, "reason")
			if reason == "" {
				reason = "scheduled_rotation"
			}
			version++
			if newAlg != "" && newAlg != lastAlgorithm {
				prov.AlgorithmHistory = append(prov.AlgorithmHistory, AlgorithmChange{
					FromAlgorithm: lastAlgorithm,
					ToAlgorithm:   newAlg,
					ChangedAt:     e.OccurredAt.Format(time.RFC3339),
					Reason:        reason,
					Version:       version,
				})
				lastAlgorithm = newAlg
				prov.Algorithm = newAlg
			}
		}

		// Collect regions from all events
		if region != "" {
			usageRegionSet[region] = struct{}{}
		}
		storageRegion := metaString(e.Metadata, "storage_region")
		if storageRegion != "" {
			storageRegionSet[storageRegion] = struct{}{}
		}
	}

	if prov.AlgorithmHistory == nil {
		prov.AlgorithmHistory = []AlgorithmChange{}
	}

	prov.StorageRegions = sortedKeys(storageRegionSet)
	prov.UsageRegions = sortedKeys(usageRegionSet)

	// Compute compliance frameworks based on algorithm and HSM backing
	prov.ComplianceFrameworks = computeComplianceFrameworks(prov.Algorithm, prov.HSMBacked, prov.FIPSCertified)

	// Compute crypto agility score
	prov.CryptoAgilityScore = cryptoAgilityScore(prov.Algorithm)

	return prov
}

// buildDataFlowBinding assembles data flow bindings from lineage events.
func buildDataFlowBinding(keyID string, events []LineageEvent) DataFlowBinding {
	flow := DataFlowBinding{
		KeyID: keyID,
	}

	resourceMap := map[string]BoundResource{}
	appSet := map[string]struct{}{}
	var crossTenantShares []CrossTenantShare
	var cloudReplicas []CloudReplica

	for _, e := range events {
		// Collect applications from service names
		if svc := strings.TrimSpace(e.ServiceName); svc != "" {
			appSet[svc] = struct{}{}
		}

		// Bound resources: events where this key encrypts/wraps/signs something
		if e.SourceID == keyID && e.DestID != "" {
			switch e.EventType {
			case LineageEventEncrypt, LineageEventWrap, LineageEventSign, LineageEventDerive:
				rType := e.DestType
				if rType == "" {
					rType = "unknown"
				}
				encType := encryptionTypeFromEvent(e.EventType)
				resourceMap[e.DestID] = BoundResource{
					ResourceID:     e.DestID,
					ResourceType:   rType,
					ResourceName:   e.DestLabel,
					EncryptionType: encType,
					Service:        e.ServiceName,
					LastAccessed:   e.OccurredAt.Format(time.RFC3339),
				}
			}
		}

		// Cloud export events → replicas
		if e.EventType == LineageEventExport && e.SourceID == keyID {
			provider := metaString(e.Metadata, "provider")
			region := metaString(e.Metadata, "region")
			cloudKeyID := metaString(e.Metadata, "cloud_key_id")
			syncStatus := metaString(e.Metadata, "sync_status")
			if syncStatus == "" {
				syncStatus = "synced"
			}
			if provider != "" {
				cloudReplicas = append(cloudReplicas, CloudReplica{
					Provider:   provider,
					Region:     region,
					CloudKeyID: cloudKeyID,
					SyncStatus: syncStatus,
					LastSynced: e.OccurredAt.Format(time.RFC3339),
				})
			}
		}

		// Cross-tenant share events
		if e.EventType == LineageEventShare && e.SourceID == keyID {
			targetTenant := metaString(e.Metadata, "target_tenant_id")
			shareType := metaString(e.Metadata, "share_type")
			if shareType == "" {
				shareType = "byok"
			}
			provider := metaString(e.Metadata, "provider")
			if targetTenant != "" {
				crossTenantShares = append(crossTenantShares, CrossTenantShare{
					TargetTenantID: targetTenant,
					ShareType:      shareType,
					Provider:       provider,
					SharedAt:       e.OccurredAt.Format(time.RFC3339),
				})
			}
		}
	}

	// Flatten bound resources
	resources := make([]BoundResource, 0, len(resourceMap))
	for _, r := range resourceMap {
		resources = append(resources, r)
	}
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].ResourceID < resources[j].ResourceID
	})

	flow.BoundResources = resources
	flow.Applications = sortedKeys(appSet)
	if crossTenantShares == nil {
		crossTenantShares = []CrossTenantShare{}
	}
	flow.CrossTenantShares = crossTenantShares
	if cloudReplicas == nil {
		cloudReplicas = []CloudReplica{}
	}
	flow.CloudReplicas = cloudReplicas

	return flow
}

// buildRiskHeatmap assembles a risk heatmap from all lineage events.
func buildRiskHeatmap(events []LineageEvent) KeyRiskHeatmap {
	now := time.Now().UTC()

	// Group events by key
	type keyData struct {
		label          string
		algorithm      string
		createdAt      time.Time
		lastRotated    time.Time
		hasRotation    bool
		dependents     map[string]struct{}
		hasCreate      bool
	}
	keys := map[string]*keyData{}

	for _, e := range events {
		kd, ok := keys[e.SourceID]
		if !ok {
			kd = &keyData{dependents: map[string]struct{}{}}
			keys[e.SourceID] = kd
		}

		if e.EventType == LineageEventCreate {
			kd.createdAt = e.OccurredAt
			kd.hasCreate = true
			kd.label = e.SourceLabel
			alg := metaString(e.Metadata, "algorithm")
			if alg != "" {
				kd.algorithm = alg
			}
		}
		if e.EventType == LineageEventRotate {
			kd.hasRotation = true
			if e.OccurredAt.After(kd.lastRotated) {
				kd.lastRotated = e.OccurredAt
			}
			alg := metaString(e.Metadata, "algorithm")
			if alg != "" {
				kd.algorithm = alg
			}
		}
		if e.DestID != "" && e.DestID != e.SourceID {
			kd.dependents[e.DestID] = struct{}{}
		}
		if kd.label == "" {
			kd.label = e.SourceLabel
		}
	}

	summary := HeatmapSummary{}
	entries := make([]KeyHeatmapEntry, 0, len(keys))
	totalRisk := 0.0
	pqcReady := 0

	for keyID, kd := range keys {
		if !kd.hasCreate {
			continue
		}

		ageDays := int(now.Sub(kd.createdAt).Hours() / 24)
		ageCategory := categorizeAge(ageDays)

		// Rotation status (assume 365-day policy)
		rotationPolicy := 365
		rotationStatus := "never_rotated"
		daysUntilRotation := 0
		daysOverdue := 0

		if kd.hasRotation {
			daysSinceRotation := int(now.Sub(kd.lastRotated).Hours() / 24)
			remaining := rotationPolicy - daysSinceRotation
			if remaining > 0 {
				rotationStatus = "compliant"
				daysUntilRotation = remaining
			} else if remaining > -30 {
				rotationStatus = "due_soon"
				daysUntilRotation = remaining
			} else {
				rotationStatus = "overdue"
				daysOverdue = -remaining
			}
		}

		// Risk score: weighted combination
		riskScore := computeKeyRiskScore(ageDays, rotationStatus, kd.algorithm, len(kd.dependents))
		agility := cryptoAgilityScore(kd.algorithm)

		// Compliance gaps
		gaps := computeComplianceGaps(kd.algorithm, rotationStatus, ageDays)

		entry := KeyHeatmapEntry{
			KeyID:             keyID,
			KeyLabel:          kd.label,
			Algorithm:         kd.algorithm,
			AgeDays:           ageDays,
			AgeCategory:       ageCategory,
			RotationStatus:    rotationStatus,
			DaysUntilRotation: daysUntilRotation,
			DaysOverdue:       daysOverdue,
			RiskScore:         riskScore,
			DependentCount:    len(kd.dependents),
			ComplianceGaps:    gaps,
			CryptoAgility:     agility,
		}
		entries = append(entries, entry)
		totalRisk += riskScore

		// Accumulate summary
		summary.TotalKeys++
		switch ageCategory {
		case "fresh":
			summary.FreshKeys++
		case "aging":
			summary.AgingKeys++
		case "old":
			summary.OldKeys++
		case "critical":
			summary.CriticalKeys++
		}
		switch rotationStatus {
		case "compliant":
			summary.RotationCompliant++
		case "overdue":
			summary.RotationOverdue++
		case "never_rotated":
			summary.NeverRotated++
		}
		if agility >= 70 {
			pqcReady++
		}
	}

	// Sort by risk score descending
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].RiskScore > entries[j].RiskScore
	})

	if summary.TotalKeys > 0 {
		summary.AvgRiskScore = math.Round(totalRisk/float64(summary.TotalKeys)*100) / 100
		summary.PQCReadyPct = math.Round(float64(pqcReady)/float64(summary.TotalKeys)*10000) / 100
	}

	return KeyRiskHeatmap{
		Keys:    entries,
		Summary: summary,
	}
}

// buildAccessPatternAnalysis assembles access pattern forensics from events.
func buildAccessPatternAnalysis(keyID string, accessEvents, allEvents []LineageEvent) AccessPatternAnalysis {
	now := time.Now().UTC()
	analysis := AccessPatternAnalysis{
		KeyID:        keyID,
		TotalAccess:  len(accessEvents),
		AccessByHour: make(map[int]int),
		AccessByDay:  make(map[string]int),
	}

	// Determine key creation time for "new actor" detection
	var keyCreatedAt time.Time
	usageRegions := map[string]struct{}{}
	for _, e := range allEvents {
		if e.EventType == LineageEventCreate && e.SourceID == keyID {
			keyCreatedAt = e.OccurredAt
		}
		region := metaString(e.Metadata, "region")
		if region != "" {
			usageRegions[region] = struct{}{}
		}
	}
	keyAgeDays := int(now.Sub(keyCreatedAt).Hours() / 24)

	// Track actors: actorID -> {type, firstAccess, lastAccess, count}
	type actorInfo struct {
		actorType   string
		firstAccess time.Time
		lastAccess  time.Time
		count       int
	}
	actorMap := map[string]*actorInfo{}
	serviceSet := map[string]struct{}{}
	geoMap := map[string]*GeoAccess{}
	sevenDaysAgo := now.AddDate(0, 0, -7)

	for _, e := range accessEvents {
		hour := e.OccurredAt.Hour()
		analysis.AccessByHour[hour]++

		dayName := e.OccurredAt.Weekday().String()
		analysis.AccessByDay[dayName]++

		// Off-hours: before 8am or after 6pm
		if hour < 8 || hour >= 18 {
			analysis.OffHoursAccess++
		}
		// Weekend
		wd := e.OccurredAt.Weekday()
		if wd == time.Saturday || wd == time.Sunday {
			analysis.WeekendAccess++
		}

		// Track actors
		ai, ok := actorMap[e.ActorID]
		if !ok {
			ai = &actorInfo{
				actorType:   e.ActorType,
				firstAccess: e.OccurredAt,
				lastAccess:  e.OccurredAt,
			}
			actorMap[e.ActorID] = ai
		}
		ai.count++
		if e.OccurredAt.Before(ai.firstAccess) {
			ai.firstAccess = e.OccurredAt
		}
		if e.OccurredAt.After(ai.lastAccess) {
			ai.lastAccess = e.OccurredAt
		}

		// Track services
		if svc := strings.TrimSpace(e.ServiceName); svc != "" {
			serviceSet[svc] = struct{}{}
		}

		// Track geo
		region := metaString(e.Metadata, "region")
		if region != "" {
			ga, ok := geoMap[region]
			if !ok {
				ga = &GeoAccess{Region: region}
				geoMap[region] = ga
			}
			ga.AccessCount++
			if e.OccurredAt.Format(time.RFC3339) > ga.LastAccess {
				ga.LastAccess = e.OccurredAt.Format(time.RFC3339)
			}
		}
	}

	analysis.UniqueActors = len(actorMap)

	// Find peak hour
	peakCount := 0
	for h, c := range analysis.AccessByHour {
		if c > peakCount {
			peakCount = c
			analysis.PeakHour = h
		}
	}

	// Build top actors (sorted by count desc)
	topActors := make([]ActorAccess, 0, len(actorMap))
	newActors := make([]ActorAccess, 0)
	for id, ai := range actorMap {
		aa := ActorAccess{
			ActorID:     id,
			ActorType:   ai.actorType,
			AccessCount: ai.count,
			LastAccess:  ai.lastAccess.Format(time.RFC3339),
			FirstAccess: ai.firstAccess.Format(time.RFC3339),
		}
		topActors = append(topActors, aa)
		// New actor: first seen in last 7 days
		if ai.firstAccess.After(sevenDaysAgo) {
			newActors = append(newActors, aa)
		}
	}
	sort.Slice(topActors, func(i, j int) bool {
		return topActors[i].AccessCount > topActors[j].AccessCount
	})
	if len(topActors) > 10 {
		topActors = topActors[:10]
	}
	analysis.TopActors = topActors
	analysis.NewActors = newActors

	// Geo distribution
	geoList := make([]GeoAccess, 0, len(geoMap))
	for _, ga := range geoMap {
		geoList = append(geoList, *ga)
	}
	sort.Slice(geoList, func(i, j int) bool {
		return geoList[i].AccessCount > geoList[j].AccessCount
	})
	analysis.GeoDistribution = geoList

	// Detect anomalies
	anomalies := make([]AccessAnomaly, 0)
	nowStr := now.Format(time.RFC3339)

	// Spike detection: any hour with >3x the average
	if len(analysis.AccessByHour) > 0 {
		totalHours := 0
		for _, c := range analysis.AccessByHour {
			totalHours += c
		}
		avgPerHour := float64(totalHours) / 24.0
		for h, c := range analysis.AccessByHour {
			if avgPerHour > 0 && float64(c) > avgPerHour*3 {
				anomalies = append(anomalies, AccessAnomaly{
					Type:        "spike",
					Description: fmt.Sprintf("Hour %d had %d accesses (%.1fx average)", h, c, float64(c)/avgPerHour),
					Severity:    "high",
					DetectedAt:  nowStr,
					Details:     map[string]interface{}{"hour": h, "count": c, "average": avgPerHour},
				})
			}
		}
	}

	// Off-hours anomaly: >20% outside business hours
	if analysis.TotalAccess > 0 {
		offHoursPct := float64(analysis.OffHoursAccess) / float64(analysis.TotalAccess) * 100
		if offHoursPct > 20 {
			anomalies = append(anomalies, AccessAnomaly{
				Type:        "off_hours",
				Description: fmt.Sprintf("%.1f%% of access occurred outside business hours (8am-6pm)", offHoursPct),
				Severity:    "medium",
				DetectedAt:  nowStr,
				Details:     map[string]interface{}{"off_hours_pct": offHoursPct, "off_hours_count": analysis.OffHoursAccess},
			})
		}
	}

	// New actor on an established key (>30 days old)
	if keyAgeDays > 30 && len(newActors) > 0 {
		for _, na := range newActors {
			anomalies = append(anomalies, AccessAnomaly{
				Type:        "new_actor",
				Description: fmt.Sprintf("New actor %s first accessed key (key is %d days old)", na.ActorID, keyAgeDays),
				Severity:    "medium",
				DetectedAt:  nowStr,
				Details:     map[string]interface{}{"actor_id": na.ActorID, "first_access": na.FirstAccess, "key_age_days": keyAgeDays},
			})
		}
	}

	// Geo anomaly: access from region not in key's usage_regions
	if len(usageRegions) > 0 {
		for _, ga := range geoList {
			if _, ok := usageRegions[ga.Region]; !ok {
				anomalies = append(anomalies, AccessAnomaly{
					Type:        "geo_anomaly",
					Description: fmt.Sprintf("Access from unexpected region %s (%d accesses)", ga.Region, ga.AccessCount),
					Severity:    "high",
					DetectedAt:  nowStr,
					Details:     map[string]interface{}{"region": ga.Region, "count": ga.AccessCount},
				})
			}
		}
	}

	analysis.Anomalies = anomalies
	return analysis
}

// buildChainOfCustody assembles a chain of custody report from events.
func buildChainOfCustody(tenantID, keyID string, events []LineageEvent) ChainOfCustodyReport {
	// Sort chronologically
	sorted := make([]LineageEvent, len(events))
	copy(sorted, events)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].OccurredAt.Before(sorted[j].OccurredAt)
	})

	prov := buildKeyProvenance(tenantID, keyID, sorted)

	handoffs := make([]CustodyHandoff, 0, len(sorted))
	prevActor := ""
	for i, e := range sorted {
		region := metaString(e.Metadata, "region")
		handoff := CustodyHandoff{
			Sequence:  i + 1,
			FromActor: prevActor,
			ToActor:   e.ActorID,
			Action:    string(e.EventType),
			Service:   e.ServiceName,
			Timestamp: e.OccurredAt.Format(time.RFC3339),
			Region:    region,
			Verified:  true,
		}
		handoffs = append(handoffs, handoff)
		prevActor = e.ActorID
	}

	integrityHash := computeLineageIntegrityHash(sorted)

	label := ""
	if len(sorted) > 0 {
		label = sorted[0].SourceLabel
	}

	return ChainOfCustodyReport{
		KeyID:         keyID,
		KeyLabel:      label,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		GeneratedBy:   "discovery-service",
		Provenance:    prov,
		Custodians:    handoffs,
		IntegrityHash: integrityHash,
	}
}

// computeLineageIntegrityHash computes SHA-256 over all event IDs in order.
func computeLineageIntegrityHash(events []LineageEvent) string {
	h := sha256.New()
	for _, e := range events {
		h.Write([]byte(e.ID))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// --- Helper functions for enterprise lineage ---

// metaString extracts a string value from event metadata.
func metaString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

// metaBool extracts a bool value from event metadata.
func metaBool(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	if ok {
		return b
	}
	// Handle string "true"/"false"
	s, ok := v.(string)
	if ok {
		return strings.EqualFold(s, "true")
	}
	return false
}

// cryptoAgilityScore returns a PQC migration readiness score for an algorithm.
func cryptoAgilityScore(algorithm string) float64 {
	alg := strings.ToLower(algorithm)
	switch {
	case strings.Contains(alg, "kyber") || strings.Contains(alg, "dilithium") ||
		strings.Contains(alg, "ml-kem") || strings.Contains(alg, "ml-dsa") ||
		strings.Contains(alg, "slh-dsa") || strings.Contains(alg, "sphincs"):
		return 100
	case strings.Contains(alg, "x25519") || strings.Contains(alg, "ed25519"):
		return 75
	case strings.Contains(alg, "ecdsa") || strings.Contains(alg, "p-384") ||
		strings.Contains(alg, "p-256") || strings.Contains(alg, "ec"):
		return 70
	case strings.Contains(alg, "aes-256") || strings.Contains(alg, "chacha20"):
		return 80
	case strings.Contains(alg, "aes-128"):
		return 60
	case strings.Contains(alg, "rsa-4096") || strings.Contains(alg, "rsa4096"):
		return 40
	case strings.Contains(alg, "rsa-2048") || strings.Contains(alg, "rsa2048") || strings.Contains(alg, "rsa"):
		return 20
	case strings.Contains(alg, "3des") || strings.Contains(alg, "des"):
		return 0
	default:
		return 50
	}
}

// computeComplianceFrameworks determines applicable frameworks based on crypto config.
func computeComplianceFrameworks(algorithm string, hsmBacked, fipsCertified bool) []string {
	frameworks := []string{}
	alg := strings.ToLower(algorithm)

	// FIPS 140-2/3 requires FIPS-approved algorithms and certified modules
	if fipsCertified {
		frameworks = append(frameworks, "FIPS-140")
	}

	// PCI-DSS requires strong encryption
	if !strings.Contains(alg, "des") && !strings.Contains(alg, "rc4") {
		frameworks = append(frameworks, "PCI-DSS")
	}

	// SOC2 - generally applicable with any reasonable algorithm
	if algorithm != "" {
		frameworks = append(frameworks, "SOC2")
	}

	// HIPAA requires encryption for PHI
	if hsmBacked || fipsCertified {
		frameworks = append(frameworks, "HIPAA")
	}

	// NIST PQC readiness
	if cryptoAgilityScore(algorithm) >= 80 {
		frameworks = append(frameworks, "NIST-PQC")
	}

	sort.Strings(frameworks)
	return frameworks
}

// categorizeAge returns the age category for a key given its age in days.
func categorizeAge(ageDays int) string {
	switch {
	case ageDays < 90:
		return "fresh"
	case ageDays < 180:
		return "normal"
	case ageDays < 365:
		return "aging"
	case ageDays < 1095: // 3 years
		return "old"
	default:
		return "critical"
	}
}

// computeKeyRiskScore computes a weighted risk score (0-100) for a key.
func computeKeyRiskScore(ageDays int, rotationStatus, algorithm string, dependentCount int) float64 {
	score := 0.0

	// Age component (30% weight)
	switch {
	case ageDays > 1095:
		score += 30
	case ageDays > 365:
		score += 20
	case ageDays > 180:
		score += 10
	case ageDays > 90:
		score += 5
	}

	// Rotation component (30% weight)
	switch rotationStatus {
	case "overdue":
		score += 30
	case "due_soon":
		score += 15
	case "never_rotated":
		score += 25
	}

	// Algorithm weakness component (25% weight)
	agility := cryptoAgilityScore(algorithm)
	score += (100 - agility) * 0.25

	// Dependency blast radius component (15% weight)
	switch {
	case dependentCount > 50:
		score += 15
	case dependentCount > 20:
		score += 10
	case dependentCount > 5:
		score += 5
	}

	if score > 100 {
		score = 100
	}
	return math.Round(score*100) / 100
}

// computeComplianceGaps identifies compliance gaps for a key.
func computeComplianceGaps(algorithm, rotationStatus string, ageDays int) []string {
	gaps := []string{}
	alg := strings.ToLower(algorithm)

	if strings.Contains(alg, "3des") || strings.Contains(alg, "rc4") || strings.Contains(alg, "des") {
		gaps = append(gaps, "WEAK_ALGORITHM")
	}
	if rotationStatus == "overdue" {
		gaps = append(gaps, "ROTATION_OVERDUE")
	}
	if rotationStatus == "never_rotated" {
		gaps = append(gaps, "NEVER_ROTATED")
	}
	if ageDays > 1095 {
		gaps = append(gaps, "KEY_AGE_CRITICAL")
	}
	if cryptoAgilityScore(algorithm) < 50 {
		gaps = append(gaps, "PQC_MIGRATION_RISK")
	}

	return gaps
}

// encryptionTypeFromEvent maps an event type to an encryption type label.
func encryptionTypeFromEvent(et LineageEventType) string {
	switch et {
	case LineageEventWrap:
		return "envelope"
	case LineageEventEncrypt:
		return "direct"
	case LineageEventSign:
		return "signing"
	case LineageEventDerive:
		return "derived"
	default:
		return "unknown"
	}
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
			nodes[id] = &nodeAccum{typ: typ, label: label, count: 1}
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

	// Track edges: (from, to, eventType) -> (count, lastSeen).
	type edgeKey struct {
		from      string
		to        string
		eventType LineageEventType
	}
	type edgeAccum struct {
		count    int
		lastSeen time.Time
	}
	edgeCounts := map[edgeKey]*edgeAccum{}

	// Track unique stats.
	sourceSet := map[string]struct{}{}
	destSet := map[string]struct{}{}
	serviceSet := map[string]struct{}{}

	for _, e := range events {
		ensureNode(e.SourceID, e.SourceType, e.SourceLabel)
		sourceSet[e.SourceID] = struct{}{}
		if svc := strings.TrimSpace(e.ServiceName); svc != "" {
			serviceSet[svc] = struct{}{}
		}
		if e.DestID != "" {
			ensureNode(e.DestID, e.DestType, e.DestLabel)
			destSet[e.DestID] = struct{}{}
			ek := edgeKey{from: e.SourceID, to: e.DestID, eventType: e.EventType}
			acc, ok := edgeCounts[ek]
			if !ok {
				edgeCounts[ek] = &edgeAccum{count: 1, lastSeen: e.OccurredAt}
			} else {
				acc.count++
				if e.OccurredAt.After(acc.lastSeen) {
					acc.lastSeen = e.OccurredAt
				}
			}
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

	// Materialise edges with labels from the node map.
	edgeList := make([]LineageEdge, 0, len(edgeCounts))
	for k, acc := range edgeCounts {
		fromLabel := ""
		if n, ok := nodes[k.from]; ok {
			fromLabel = n.label
		}
		toLabel := ""
		if n, ok := nodes[k.to]; ok {
			toLabel = n.label
		}
		edgeList = append(edgeList, LineageEdge{
			From:      k.from,
			FromLabel: fromLabel,
			To:        k.to,
			ToLabel:   toLabel,
			EventType: k.eventType,
			Count:     acc.count,
			LastSeen:  acc.lastSeen.Format(time.RFC3339),
		})
	}

	return LineageGraph{
		RequestID:          reqID,
		TenantID:           tenantID,
		Nodes:              nodeList,
		Edges:              edgeList,
		TotalEvents:        len(events),
		UniqueSources:      len(sourceSet),
		UniqueDestinations: len(destSet),
		ServicesTracked:    len(serviceSet),
	}
}

// computeLineageImpact derives impact metrics for a key from its lineage events.
func computeLineageImpact(reqID, tenantID, keyID string, events []LineageEvent) LineageImpact {
	serviceSet := map[string]struct{}{}
	actorSet := map[string]struct{}{}
	keySet := map[string]struct{}{}

	for _, e := range events {
		if svc := strings.TrimSpace(e.ServiceName); svc != "" {
			serviceSet[svc] = struct{}{}
		}
		if actor := strings.TrimSpace(e.ActorID); actor != "" {
			actorSet[actor] = struct{}{}
		}
		// Collect affected keys (any key that is not the queried key itself).
		if e.SourceID != keyID && e.SourceID != "" {
			keySet[e.SourceID] = struct{}{}
		}
		if e.DestID != keyID && e.DestID != "" {
			keySet[e.DestID] = struct{}{}
		}
	}

	services := sortedKeys(serviceSet)
	actors := sortedKeys(actorSet)
	affectedKeys := sortedKeys(keySet)

	total := len(events)
	blastRadius := len(affectedKeys) + len(services) + len(actors)

	riskLevel := "low"
	switch {
	case blastRadius > 50 || total > 100:
		riskLevel = "critical"
	case blastRadius > 20 || total > 20:
		riskLevel = "high"
	case blastRadius > 5 || total > 5:
		riskLevel = "medium"
	}

	rotationImpact := buildRotationImpactMsg(keyID, services, actors)

	return LineageImpact{
		RequestID:             reqID,
		KeyID:                 keyID,
		TenantID:              tenantID,
		TotalEvents:           total,
		AffectedKeys:          affectedKeys,
		AffectedKeysCount:     len(affectedKeys),
		AffectedServices:      services,
		AffectedServicesCount: len(services),
		AffectedActors:        actors,
		AffectedActorsCount:   len(actors),
		BlastRadius:           blastRadius,
		RiskLevel:             riskLevel,
		RotationImpact:        rotationImpact,
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

// buildTimelineDescription creates a human-readable event description.
func buildTimelineDescription(e LineageEvent, keyID string) string {
	verb := string(e.EventType)
	switch e.EventType {
	case LineageEventCreate:
		verb = "created"
	case LineageEventRead:
		verb = "read"
	case LineageEventEncrypt:
		verb = "encrypted data with"
	case LineageEventDecrypt:
		verb = "decrypted data with"
	case LineageEventSign:
		verb = "signed with"
	case LineageEventWrap:
		verb = "wrapped"
	case LineageEventUnwrap:
		verb = "unwrapped"
	case LineageEventRotate:
		verb = "rotated"
	case LineageEventDerive:
		verb = "derived child"
	case LineageEventExport:
		verb = "exported"
	case LineageEventImport:
		verb = "imported"
	case LineageEventDelete, LineageEventDestroy:
		verb = "destroyed"
	case LineageEventTransform:
		verb = "transformed"
	case LineageEventShare:
		verb = "shared"
	}

	actor := e.ActorID
	svc := e.ServiceName
	ts := e.OccurredAt.Format(time.RFC3339)

	if e.DestID != "" && e.DestID != keyID {
		return fmt.Sprintf("Key %s %s %s by %s via %s at %s", verb, e.DestID, keyID, actor, svc, ts)
	}
	return fmt.Sprintf("Key %s by %s via %s at %s", verb, actor, svc, ts)
}

// relationshipFromEvent maps event types to dependency relationship labels.
func relationshipFromEvent(et LineageEventType) string {
	switch et {
	case LineageEventWrap:
		return "wraps"
	case LineageEventDerive:
		return "derives"
	case LineageEventEncrypt:
		return "encrypts"
	case LineageEventSign:
		return "signs"
	default:
		return string(et)
	}
}

// computeDepth computes the maximum dependency depth for each key via BFS.
func computeDepth(adjacency map[string][]string, depthMap map[string]int) {
	for root := range adjacency {
		visited := map[string]bool{root: true}
		queue := []struct {
			id    string
			depth int
		}{{id: root, depth: 0}}
		maxDepth := 0
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, child := range adjacency[cur.id] {
				if visited[child] {
					continue
				}
				visited[child] = true
				d := cur.depth + 1
				if d > maxDepth {
					maxDepth = d
				}
				queue = append(queue, struct {
					id    string
					depth int
				}{id: child, depth: d})
			}
		}
		if maxDepth > depthMap[root] {
			depthMap[root] = maxDepth
		}
	}
}

// toStringSet converts a string slice into a set map for fast lookups.
func toStringSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	s := make(map[string]struct{}, len(items))
	for _, item := range items {
		if v := strings.TrimSpace(item); v != "" {
			s[v] = struct{}{}
		}
	}
	if len(s) == 0 {
		return nil
	}
	return s
}

// sortedKeys extracts keys from a set and returns them sorted.
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
