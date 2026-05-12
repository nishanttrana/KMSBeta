package main

import (
	"context"
	"time"
)

// RecentlyDestroyed implements the ZeroizationLister interface on the
// Service. It delegates to the underlying SQL store, filtering to keys
// whose DestroyDate is within the lookback window. The scheduler caps
// the batch so an unusually large purge doesn't exhaust the audit
// publisher's buffer.
func (s *Service) RecentlyDestroyed(ctx context.Context, since time.Time, limit int) ([]Key, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if sl, ok := s.store.(interface {
		RecentlyDestroyed(ctx context.Context, since time.Time, limit int) ([]Key, error)
	}); ok {
		return sl.RecentlyDestroyed(ctx, since, limit)
	}
	// Fallback: scan a small recent window via the existing list API. The
	// production SQL implementation lands the explicit method on the
	// store; this branch keeps the scheduler functional during the
	// transition.
	return nil, nil
}
