package main

import (
	"context"
	"time"

	"vecta-kms/pkg/cbom"
	"vecta-kms/pkg/migration"
)

// MigrationPlanInput is the operator-facing request shape. TargetTier is
// the desired floor (e.g., "pqc-hybrid"); RatePerHour and WindowStart
// shape the schedule. The keycore turns this into a migration.Plan via
// the pure planner in pkg/migration.
type MigrationPlanInput struct {
	TenantID    string    `json:"tenant_id"`
	TargetTier  string    `json:"target_tier"`
	WindowStart time.Time `json:"window_start"`
	RatePerHour int       `json:"rate_per_hour"`
}

// MigrationPlanner builds a per-tenant migration schedule. It enumerates
// candidates from the keys table, classifies each one against the
// requested floor, computes Y2Q scores, and delegates the actual
// scheduling to the pure planner in pkg/migration.
type MigrationPlanner struct {
	store MigrationStore
}

// MigrationStore is the minimal projection used by the planner. The
// keycore SQL store implements it; tests use an in-memory fake.
type MigrationStore interface {
	ListKeysForMigration(ctx context.Context, tenantID string, limit int) ([]Key, error)
}

// NewMigrationPlanner constructs a planner.
func NewMigrationPlanner(store MigrationStore) *MigrationPlanner {
	return &MigrationPlanner{store: store}
}

// Build returns a complete migration plan ready for review. The plan is
// inert until the reconciler is asked to execute it; that separation
// keeps "look at the plan" cheap and side-effect free.
func (m *MigrationPlanner) Build(ctx context.Context, input MigrationPlanInput) (migration.Plan, error) {
	keys, err := m.store.ListKeysForMigration(ctx, input.TenantID, 10_000)
	if err != nil {
		return migration.Plan{}, err
	}
	candidates := make([]migration.Candidate, 0, len(keys))
	for _, k := range keys {
		current := cbom.ClassifyTier(k.Algorithm, "")
		candidates = append(candidates, migration.Candidate{
			KeyID:       k.ID,
			TenantID:    k.TenantID,
			Algorithm:   k.Algorithm,
			CurrentTier: current,
			Y2QScore:    Y2QFromLabels(k.Labels),
		})
	}
	target := cbom.Tier(input.TargetTier)
	return migration.Build(candidates, migration.Options{
		TargetTier:  target,
		WindowStart: input.WindowStart,
		RatePerHour: input.RatePerHour,
		RequireApproval: func(c migration.Candidate) bool {
			// High-Y2Q candidates always require approval — they are
			// likely the ones protecting top-secret data and operators
			// must sign off on rotation timing.
			return c.Y2QScore >= 50.0
		},
	}), nil
}
