// Package quota implements per-tenant operation quotas that the policy
// evaluator uses to auto-throttle and ultimately auto-deny operations
// approaching or exceeding their budget.
//
// The quota is an in-process atomic counter with periodic snapshots; a
// persistent store can sync state across replicas via the SyncReader/Writer
// interfaces so a horizontally scaled deployment shares the same view.
package quota

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Decision is the policy hint returned by Evaluate. Allow lets the
// operation proceed without modification; Warn instructs the policy
// evaluator to inject an audit warning; Deny halts the operation.
type Decision string

const (
	Allow Decision = "ALLOW"
	Warn  Decision = "WARN"
	Deny  Decision = "DENY"
)

// Budget describes a single tenant's operation budget.
type Budget struct {
	TenantID     string
	Limit        int64
	WarnAt       float64 // fraction of Limit at which Warn fires (e.g. 0.8)
	WindowStart  time.Time
	WindowLength time.Duration
}

// Tracker is the in-memory quota counter. It is safe for concurrent use.
type Tracker struct {
	mu      sync.RWMutex
	budgets map[string]*Budget
	used    map[string]*atomic.Int64
}

// New constructs an empty tracker.
func New() *Tracker {
	return &Tracker{
		budgets: make(map[string]*Budget),
		used:    make(map[string]*atomic.Int64),
	}
}

// SetBudget installs or replaces the budget for a tenant. Used counter is
// preserved across replacement so changing the cap mid-window doesn't
// reset accounting.
func (t *Tracker) SetBudget(b Budget) {
	if b.TenantID == "" || b.Limit <= 0 {
		return
	}
	if b.WindowLength <= 0 {
		b.WindowLength = 24 * time.Hour
	}
	if b.WindowStart.IsZero() {
		b.WindowStart = time.Now().UTC()
	}
	if b.WarnAt <= 0 || b.WarnAt > 1 {
		b.WarnAt = 0.8
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.budgets[b.TenantID] = &b
	if _, exists := t.used[b.TenantID]; !exists {
		t.used[b.TenantID] = &atomic.Int64{}
	}
}

// Add increments the counter and returns the post-increment decision for
// the caller. Atomic so concurrent callers cannot race past the cap.
func (t *Tracker) Add(tenantID string, n int64) Decision {
	t.mu.RLock()
	b := t.budgets[tenantID]
	used := t.used[tenantID]
	t.mu.RUnlock()
	if b == nil || used == nil {
		return Allow
	}
	t.maybeRollWindow(tenantID)
	val := used.Add(n)
	return classify(val, b)
}

// Evaluate returns the decision for a tenant without mutating the counter.
// Used by the policy dry-run pipeline.
func (t *Tracker) Evaluate(tenantID string) Decision {
	t.mu.RLock()
	defer t.mu.RUnlock()
	b := t.budgets[tenantID]
	used := t.used[tenantID]
	if b == nil || used == nil {
		return Allow
	}
	return classify(used.Load(), b)
}

// Usage returns the current counter and budget for a tenant.
func (t *Tracker) Usage(tenantID string) (int64, Budget, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	b := t.budgets[tenantID]
	used := t.used[tenantID]
	if b == nil {
		return 0, Budget{}, false
	}
	return used.Load(), *b, true
}

// Snapshot returns usage for every tenant. Used by the auto-throttle
// reconciler to publish quota signals.
func (t *Tracker) Snapshot() []TenantUsage {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]TenantUsage, 0, len(t.budgets))
	for id, b := range t.budgets {
		used := int64(0)
		if c, ok := t.used[id]; ok {
			used = c.Load()
		}
		out = append(out, TenantUsage{
			TenantID: id,
			Used:     used,
			Budget:   *b,
			Decision: classify(used, b),
		})
	}
	return out
}

// TenantUsage is a serialisable view of one tenant's quota state.
type TenantUsage struct {
	TenantID string   `json:"tenant_id"`
	Used     int64    `json:"used"`
	Budget   Budget   `json:"budget"`
	Decision Decision `json:"decision"`
}

func (t *Tracker) maybeRollWindow(tenantID string) {
	now := time.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.budgets[tenantID]
	if b == nil {
		return
	}
	if now.Sub(b.WindowStart) < b.WindowLength {
		return
	}
	b.WindowStart = now
	if c, ok := t.used[tenantID]; ok {
		c.Store(0)
	}
}

func classify(used int64, b *Budget) Decision {
	if b.Limit <= 0 {
		return Allow
	}
	frac := float64(used) / float64(b.Limit)
	switch {
	case frac >= 1.0:
		return Deny
	case frac >= b.WarnAt:
		return Warn
	default:
		return Allow
	}
}

// SyncReader/Writer are the optional persistence hooks. A reconciler can
// periodically load budgets from a store (Reader) and flush usage back
// (Writer) so quota state survives restarts and propagates across nodes.
type SyncReader interface {
	LoadBudgets(ctx context.Context) ([]Budget, error)
}

type SyncWriter interface {
	FlushUsage(ctx context.Context, snapshot []TenantUsage) error
}
