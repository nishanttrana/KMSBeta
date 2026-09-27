package main

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"vecta-kms/pkg/route"
)

// Who uses a key and what rotating or deleting it would affect, for the
// Keys "History & usage" panel. Consumers come from key_usage_events, which
// runCryptoTx writes on every successful crypto operation. That trail is
// node-local and pruned after usageRetention, so the response carries both
// facts rather than presenting one node's recent window as all usage.

// KeyConsumer is one caller (actor through an interface) of a key.
type KeyConsumer struct {
	ActorID    string         `json:"actor_id"`
	Interface  string         `json:"interface"`
	Operations map[string]int `json:"operations"`
	Total      int            `json:"total"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
}

// KeyImpact is what a rotation or deletion would touch, from stored state.
type KeyImpact struct {
	KeyStatus        string         `json:"key_status"`
	CurrentVersion   int            `json:"current_version"`
	VersionsByStatus map[string]int `json:"versions_by_status"`
	ActiveCallers    int            `json:"active_callers"`
	Interfaces       []string       `json:"interfaces"`
	LastUsedAt       *time.Time     `json:"last_used_at,omitempty"`
	ApprovalRequired bool           `json:"approval_required"`
}

// KeyConsumers is the response of GET /keys/{id}/consumers.
type KeyConsumers struct {
	KeyID      string        `json:"key_id"`
	Since      time.Time     `json:"since"`
	WindowDays int           `json:"window_days"`
	NodeLocal  bool          `json:"node_local"`
	Consumers  []KeyConsumer `json:"consumers"`
	Impact     KeyImpact     `json:"impact"`
}

// ListKeyConsumers groups a key's usage trail since the given time by actor
// and interface.
func (s *SQLStore) ListKeyConsumers(ctx context.Context, tenantID, keyID string, since time.Time) ([]KeyConsumer, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT actor_id, interface, operation, COUNT(*), MIN(occurred_at), MAX(occurred_at)
FROM key_usage_events
WHERE tenant_id=$1 AND key_id=$2 AND occurred_at >= $3
GROUP BY actor_id, interface, operation`, tenantID, keyID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	byCaller := map[[2]string]*KeyConsumer{}
	for rows.Next() {
		var (
			actor, iface, op  string
			n                 int
			firstRaw, lastRaw any
		)
		if err := rows.Scan(&actor, &iface, &op, &n, &firstRaw, &lastRaw); err != nil {
			return nil, err
		}
		first, _ := parseDBTime(firstRaw)
		last, _ := parseDBTime(lastRaw)
		k := [2]string{actor, iface}
		c := byCaller[k]
		if c == nil {
			c = &KeyConsumer{ActorID: actor, Interface: iface, Operations: map[string]int{}, FirstSeen: first, LastSeen: last}
			byCaller[k] = c
		}
		c.Operations[op] += n
		c.Total += n
		if first.Before(c.FirstSeen) {
			c.FirstSeen = first
		}
		if last.After(c.LastSeen) {
			c.LastSeen = last
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]KeyConsumer, 0, len(byCaller))
	for _, c := range byCaller {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].ActorID+"|"+out[i].Interface < out[j].ActorID+"|"+out[j].Interface
	})
	return out, nil
}

// KeyConsumers returns a key's callers over the retained usage window and
// the impact of rotating or deleting it.
func (s *Service) KeyConsumers(ctx context.Context, tenantID, keyID string) (KeyConsumers, error) {
	key, err := s.store.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return KeyConsumers{}, err
	}
	versions, err := s.store.ListVersions(ctx, tenantID, keyID)
	if err != nil {
		return KeyConsumers{}, err
	}
	since := time.Now().UTC().Add(-usageRetention)
	consumers, err := s.store.ListKeyConsumers(ctx, tenantID, keyID, since)
	if err != nil {
		return KeyConsumers{}, err
	}
	impact := KeyImpact{
		KeyStatus: normalizeLifecycleStatus(key.Status), CurrentVersion: key.CurrentVersion,
		VersionsByStatus: map[string]int{}, ActiveCallers: len(consumers), Interfaces: []string{},
		ApprovalRequired: key.ApprovalRequired,
	}
	for _, v := range versions {
		impact.VersionsByStatus[v.Status]++
	}
	seen := map[string]bool{}
	for i := range consumers {
		c := consumers[i]
		if c.Interface != "" && !seen[c.Interface] {
			seen[c.Interface] = true
			impact.Interfaces = append(impact.Interfaces, c.Interface)
		}
		if impact.LastUsedAt == nil || c.LastSeen.After(*impact.LastUsedAt) {
			impact.LastUsedAt = &consumers[i].LastSeen
		}
	}
	sort.Strings(impact.Interfaces)
	return KeyConsumers{
		KeyID: keyID, Since: since, WindowDays: int(usageRetention / (24 * time.Hour)), NodeLocal: true,
		Consumers: consumers, Impact: impact,
	}, nil
}

// keyConsumersRouter serves the consumers view through the route kernel.
func (h *Handler) keyConsumersRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("GET /keys/{id}/consumers", route.Spec{
		Action: "key_consumers_read", Permission: "key.usage.read", Resource: "key", TargetParam: "id",
	}, h.getKeyConsumers)
	return r
}

func (h *Handler) getKeyConsumers(c *route.Call) {
	out, err := h.svc.KeyConsumers(c.R.Context(), c.Tenant, strings.TrimSpace(c.R.PathValue("id")))
	switch {
	case errors.Is(err, errStoreNotFound):
		c.Error(http.StatusNotFound, "not_found", "key not found")
		return
	case err != nil:
		c.Error(http.StatusInternalServerError, "key_consumers_failed", "failed to read key usage")
		return
	}
	c.Detail("consumers", len(out.Consumers))
	c.JSON(http.StatusOK, map[string]interface{}{"consumers": out})
}
