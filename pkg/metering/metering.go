package metering

import (
	"sync/atomic"
	"time"
)

// Meter is a simple operations counter with a windowed rate limit.
type Meter struct {
	ops       atomic.Uint64
	limit     atomic.Uint64
	windowSec int64
	windowAt  atomic.Int64
}

// NewMeter creates a simple ops-counting meter with a limit per window.
// Pass limit=0 for unlimited.
func NewMeter(limit uint64, window time.Duration) *Meter {
	m := &Meter{
		windowSec: int64(window / time.Second),
	}
	m.limit.Store(limit)
	m.windowAt.Store(time.Now().Unix())
	return m
}

// IncrementOps atomically increments the counter and returns whether the
// operation is within the configured limit.
func (m *Meter) IncrementOps() bool {
	m.MaybeResetWindow()
	next := m.ops.Add(1)
	limit := m.limit.Load()
	return limit == 0 || next <= limit
}

// Count returns the current ops count in the active window.
func (m *Meter) Count() uint64 {
	return m.ops.Load()
}

// MaybeResetWindow resets the counter if the current window has elapsed.
func (m *Meter) MaybeResetWindow() {
	if m.windowSec <= 0 {
		return
	}
	now := time.Now().Unix()
	start := m.windowAt.Load()
	if now-start >= m.windowSec {
		m.windowAt.Store(now)
		m.ops.Store(0)
	}
}

// SetLimit dynamically updates the ops limit.
func (m *Meter) SetLimit(limit uint64) {
	m.limit.Store(limit)
}
