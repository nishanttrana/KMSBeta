package metering

import (
	"sync/atomic"
	"time"
)

type Meter struct {
	ops       atomic.Uint64
	limit     atomic.Uint64
	windowSec int64
	windowAt  atomic.Int64
}

func NewMeter(limit uint64, window time.Duration) *Meter {
	m := &Meter{
		windowSec: int64(window / time.Second),
	}
	m.limit.Store(limit)
	m.windowAt.Store(time.Now().Unix())
	return m
}

func (m *Meter) IncrementOps() bool {
	m.MaybeResetWindow()
	next := m.ops.Add(1)
	limit := m.limit.Load()
	return limit == 0 || next <= limit
}

func (m *Meter) Count() uint64 {
	return m.ops.Load()
}

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

func (m *Meter) SetLimit(limit uint64) {
	m.limit.Store(limit)
}
