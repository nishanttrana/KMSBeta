package resilience

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// ErrBulkheadFull is returned when a bulkhead cannot acquire a concurrency
// slot within the configured maximum wait duration.
var ErrBulkheadFull = errors.New("resilience: bulkhead full, request rejected")

// Bulkhead implements a semaphore-based concurrency limiter that prevents any
// single dependency from consuming all available goroutines. Each bulkhead
// tracks active and waiting counts for observability.
type Bulkhead struct {
	name          string
	maxConcurrent int
	maxWait       time.Duration
	sem           chan struct{}
	active        atomic.Int64
	waiting       atomic.Int64
	total         atomic.Int64
	rejected      atomic.Int64
}

// NewBulkhead creates a concurrency limiter that allows at most maxConcurrent
// simultaneous executions. Additional callers wait up to maxWait before
// receiving ErrBulkheadFull. If maxWait is zero, callers that cannot
// immediately acquire a slot are rejected.
func NewBulkhead(name string, maxConcurrent int, maxWait time.Duration) *Bulkhead {
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}
	return &Bulkhead{
		name:          name,
		maxConcurrent: maxConcurrent,
		maxWait:       maxWait,
		sem:           make(chan struct{}, maxConcurrent),
	}
}

// Execute runs fn within the bulkhead's concurrency limit. It blocks up to
// maxWait for a slot. The context is checked for cancellation while waiting.
//
// Returns ErrBulkheadFull if no slot becomes available in time, or any error
// returned by fn.
func (b *Bulkhead) Execute(ctx context.Context, fn func() error) error {
	if err := b.acquire(ctx); err != nil {
		return err
	}
	defer b.release()

	b.total.Add(1)
	return fn()
}

// acquire attempts to obtain a concurrency slot within maxWait, respecting
// context cancellation.
func (b *Bulkhead) acquire(ctx context.Context) error {
	// Fast path: try non-blocking acquire first.
	select {
	case b.sem <- struct{}{}:
		b.active.Add(1)
		return nil
	default:
	}

	// Slot not immediately available; enter the waiting state.
	b.waiting.Add(1)
	defer b.waiting.Add(-1)

	if b.maxWait <= 0 {
		b.rejected.Add(1)
		return ErrBulkheadFull
	}

	timer := time.NewTimer(b.maxWait)
	defer timer.Stop()

	select {
	case b.sem <- struct{}{}:
		b.active.Add(1)
		return nil
	case <-timer.C:
		b.rejected.Add(1)
		return ErrBulkheadFull
	case <-ctx.Done():
		b.rejected.Add(1)
		return fmt.Errorf("resilience: bulkhead %q wait cancelled: %w", b.name, ctx.Err())
	}
}

// release returns a concurrency slot to the pool.
func (b *Bulkhead) release() {
	b.active.Add(-1)
	<-b.sem
}

// Name returns the bulkhead identifier.
func (b *Bulkhead) Name() string {
	return b.name
}

// ActiveCount returns the number of goroutines currently executing within
// this bulkhead.
func (b *Bulkhead) ActiveCount() int64 {
	return b.active.Load()
}

// WaitingCount returns the number of goroutines waiting for a concurrency slot.
func (b *Bulkhead) WaitingCount() int64 {
	return b.waiting.Load()
}

// TotalExecuted returns the total number of functions that have started
// execution within this bulkhead.
func (b *Bulkhead) TotalExecuted() int64 {
	return b.total.Load()
}

// RejectedCount returns the number of requests rejected because the bulkhead
// was full.
func (b *Bulkhead) RejectedCount() int64 {
	return b.rejected.Load()
}

// MaxConcurrent returns the configured concurrency limit.
func (b *Bulkhead) MaxConcurrent() int {
	return b.maxConcurrent
}

// Stats returns a snapshot of the bulkhead's metrics for monitoring.
type BulkheadStats struct {
	Name          string `json:"name"`
	MaxConcurrent int    `json:"max_concurrent"`
	Active        int64  `json:"active"`
	Waiting       int64  `json:"waiting"`
	TotalExecuted int64  `json:"total_executed"`
	Rejected      int64  `json:"rejected"`
}

// Stats returns a snapshot of the bulkhead's current metrics.
func (b *Bulkhead) Stats() BulkheadStats {
	return BulkheadStats{
		Name:          b.name,
		MaxConcurrent: b.maxConcurrent,
		Active:        b.active.Load(),
		Waiting:       b.waiting.Load(),
		TotalExecuted: b.total.Load(),
		Rejected:      b.rejected.Load(),
	}
}

// String returns a human-readable summary of the bulkhead state.
func (b *Bulkhead) String() string {
	return fmt.Sprintf("Bulkhead(%s: active=%d/%d waiting=%d rejected=%d)",
		b.name, b.active.Load(), b.maxConcurrent, b.waiting.Load(), b.rejected.Load())
}
