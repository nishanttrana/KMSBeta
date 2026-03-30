package keylineage

import (
	"context"
	"fmt"
	"time"
)

// EventType classifies what happened to a key.
type EventType string

const (
	EventCreated   EventType = "created"
	EventDerived   EventType = "derived"
	EventWrapped   EventType = "wrapped"
	EventRewrapped EventType = "rewrapped"
	EventRotated   EventType = "rotated"
	EventExported  EventType = "exported"
	EventImported  EventType = "imported"
	EventDestroyed EventType = "destroyed"
)

// LineageEvent records a single provenance event in a key's lifecycle.
type LineageEvent struct {
	ID            string            `json:"id"`
	KeyID         string            `json:"key_id"`
	TenantID      string            `json:"tenant_id"`
	EventType     EventType         `json:"event_type"`
	ParentKeyID   string            `json:"parent_key_id,omitempty"`
	RelatedKeyIDs []string          `json:"related_key_ids,omitempty"`
	Actor         string            `json:"actor"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
}

// Relationship describes how two keys are related.
type Relationship string

const (
	RelDerivedFrom  Relationship = "derived_from"
	RelWraps        Relationship = "wraps"
	RelWrappedBy    Relationship = "wrapped_by"
	RelRotatedTo    Relationship = "rotated_to"
	RelImportedFrom Relationship = "imported_from"
)

// LineageNode represents a key in the lineage graph.
type LineageNode struct {
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
	RiskScore float64   `json:"risk_score"`
}

// LineageEdge represents a relationship between two keys.
type LineageEdge struct {
	FromKeyID    string       `json:"from_key_id"`
	ToKeyID      string       `json:"to_key_id"`
	Relationship Relationship `json:"relationship"`
}

// LineageGraph is a DAG of key relationships.
type LineageGraph struct {
	Nodes []LineageNode `json:"nodes"`
	Edges []LineageEdge `json:"edges"`
}

// ImpactReport describes the blast radius if a key is compromised.
type ImpactReport struct {
	AffectedKeys     []string `json:"affected_keys"`
	AffectedServices []string `json:"affected_services"`
	BlastRadius      int      `json:"blast_radius"`
	Severity         string   `json:"severity"` // critical, high, medium, low
}

// Store is the persistence interface for lineage events.
type Store interface {
	InsertEvent(ctx context.Context, event LineageEvent) error
	GetEventsByKeyID(ctx context.Context, keyID string) ([]LineageEvent, error)
	// GetDescendants returns all key IDs reachable from the given key via derivation, wrapping, or rotation.
	GetDescendants(ctx context.Context, keyID string, depth int) ([]LineageEvent, error)
	// GetAncestors returns all key IDs that the given key was derived/wrapped/rotated from.
	GetAncestors(ctx context.Context, keyID string, depth int) ([]LineageEvent, error)
	// GetRelatedServices returns service names from metadata of events involving the given key IDs.
	GetRelatedServices(ctx context.Context, keyIDs []string) ([]string, error)
}

// Tracker manages key lineage and provenance.
type Tracker struct {
	store Store
}

// NewTracker creates a Tracker backed by the given store.
func NewTracker(store Store) *Tracker {
	return &Tracker{store: store}
}

// RecordEvent persists a lineage event.
func (t *Tracker) RecordEvent(ctx context.Context, event LineageEvent) error {
	if event.KeyID == "" {
		return fmt.Errorf("keylineage: event must have a key_id")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return t.store.InsertEvent(ctx, event)
}

// GetLineage builds a DAG from events for the given key, traversing up to depth levels
// in both ancestor and descendant directions.
func (t *Tracker) GetLineage(ctx context.Context, keyID string, depth int) (*LineageGraph, error) {
	if depth <= 0 {
		depth = 5
	}

	graph := &LineageGraph{}
	visited := make(map[string]bool)

	// Gather descendants (keys derived from, wrapped by, rotated to this key)
	descEvents, err := t.store.GetDescendants(ctx, keyID, depth)
	if err != nil {
		return nil, fmt.Errorf("keylineage: get descendants: %w", err)
	}

	// Gather ancestors (keys this key was derived from, wrapped by, etc.)
	ancEvents, err := t.store.GetAncestors(ctx, keyID, depth)
	if err != nil {
		return nil, fmt.Errorf("keylineage: get ancestors: %w", err)
	}

	allEvents := append(descEvents, ancEvents...)

	for _, evt := range allEvents {
		// Add nodes for every key we encounter
		if !visited[evt.KeyID] {
			visited[evt.KeyID] = true
			graph.Nodes = append(graph.Nodes, LineageNode{
				KeyID:     evt.KeyID,
				Algorithm: evt.Metadata["algorithm"],
				CreatedAt: evt.Timestamp,
				Status:    evt.Metadata["status"],
			})
		}
		if evt.ParentKeyID != "" && !visited[evt.ParentKeyID] {
			visited[evt.ParentKeyID] = true
			graph.Nodes = append(graph.Nodes, LineageNode{
				KeyID: evt.ParentKeyID,
			})
		}

		// Build edges based on event type
		edge := eventToEdge(evt)
		if edge != nil {
			graph.Edges = append(graph.Edges, *edge)
		}
	}

	// Ensure the root node is present
	if !visited[keyID] {
		graph.Nodes = append(graph.Nodes, LineageNode{KeyID: keyID})
	}

	return graph, nil
}

// eventToEdge maps a LineageEvent to a graph edge.
func eventToEdge(evt LineageEvent) *LineageEdge {
	if evt.ParentKeyID == "" {
		return nil
	}

	var rel Relationship
	switch evt.EventType {
	case EventDerived:
		rel = RelDerivedFrom
	case EventWrapped:
		rel = RelWrappedBy
	case EventRewrapped:
		rel = RelWrappedBy
	case EventRotated:
		rel = RelRotatedTo
	case EventImported:
		rel = RelImportedFrom
	default:
		return nil
	}

	return &LineageEdge{
		FromKeyID:    evt.ParentKeyID,
		ToKeyID:      evt.KeyID,
		Relationship: rel,
	}
}

// GetImpactAnalysis determines the blast radius if the given key is compromised.
func (t *Tracker) GetImpactAnalysis(ctx context.Context, keyID string) (*ImpactReport, error) {
	descEvents, err := t.store.GetDescendants(ctx, keyID, 100)
	if err != nil {
		return nil, fmt.Errorf("keylineage: impact analysis: %w", err)
	}

	affectedKeySet := make(map[string]bool)
	for _, evt := range descEvents {
		affectedKeySet[evt.KeyID] = true
		for _, relID := range evt.RelatedKeyIDs {
			affectedKeySet[relID] = true
		}
	}
	// Remove the source key itself
	delete(affectedKeySet, keyID)

	affectedKeys := make([]string, 0, len(affectedKeySet))
	for k := range affectedKeySet {
		affectedKeys = append(affectedKeys, k)
	}

	// Fetch services that use any of the affected keys
	allKeyIDs := append(affectedKeys, keyID)
	services, err := t.store.GetRelatedServices(ctx, allKeyIDs)
	if err != nil {
		return nil, fmt.Errorf("keylineage: get services: %w", err)
	}

	blastRadius := len(affectedKeys) + len(services)

	severity := "low"
	switch {
	case blastRadius >= 50:
		severity = "critical"
	case blastRadius >= 20:
		severity = "high"
	case blastRadius >= 5:
		severity = "medium"
	}

	return &ImpactReport{
		AffectedKeys:     affectedKeys,
		AffectedServices: services,
		BlastRadius:      blastRadius,
		Severity:         severity,
	}, nil
}
