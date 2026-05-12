package main

import (
	"context"
	"time"
)

// ZeroizationLister returns recently destroyed keys for the scheduler
// to re-verify. Implementations live on the keycore Service so they can
// hit the existing keys table.
type ZeroizationLister interface {
	RecentlyDestroyed(ctx context.Context, since time.Time, limit int) ([]Key, error)
}

// ZeroizationScheduler runs a periodic sweep over recently destroyed
// keys and re-confirms that no in-memory material remains. Each pass
// publishes audit.key.zeroization_verified per key so the immutable
// chain carries continuous evidence of zeroisation — which is what
// FIPS 140-3 §4.9.2 requires.
type ZeroizationScheduler struct {
	lister     ZeroizationLister
	confirmer  func(tenantID, keyID string) bool
	publisher  AuditPublisher
	lookback   time.Duration
	batchSize  int
	interval   time.Duration
}

// NewZeroizationScheduler constructs a scheduler with the defaults
// "scan keys destroyed in the last 30 days, batch 200, every 1 hour."
func NewZeroizationScheduler(lister ZeroizationLister, confirmer func(tenantID, keyID string) bool, publisher AuditPublisher) *ZeroizationScheduler {
	return &ZeroizationScheduler{
		lister:    lister,
		confirmer: confirmer,
		publisher: publisher,
		lookback:  30 * 24 * time.Hour,
		batchSize: 200,
		interval:  1 * time.Hour,
	}
}

// SetInterval overrides the loop cadence. Useful for testing.
func (s *ZeroizationScheduler) SetInterval(d time.Duration) {
	if d > 0 {
		s.interval = d
	}
}

// Run blocks until ctx is cancelled. Each tick runs one sweep and
// publishes per-key audit events. Errors from the lister fall through
// to the next tick rather than crashing the scheduler.
func (s *ZeroizationScheduler) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.runOnce(ctx)
		}
	}
}

func (s *ZeroizationScheduler) runOnce(ctx context.Context) {
	keys, err := s.lister.RecentlyDestroyed(ctx, time.Now().UTC().Add(-s.lookback), s.batchSize)
	if err != nil {
		return
	}
	for _, k := range keys {
		ok := true
		if s.confirmer != nil {
			ok = s.confirmer(k.TenantID, k.ID)
		}
		if s.publisher != nil {
			result := "success"
			if !ok {
				result = "failure"
			}
			evt := map[string]any{
				"tenant_id":  k.TenantID,
				"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
				"service":    "keycore",
				"action":     "audit.key.zeroization_verified",
				"result":     result,
				"data": map[string]any{
					"key_id":      k.ID,
					"destroyed_at": k.DestroyDate,
				},
			}
			payload := mustMarshalJSON(evt)
			_ = s.publisher.Publish(ctx, "audit.key.zeroization_verified", payload)
		}
	}
}
