package metering

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Legacy Meter — backward-compatible simple ops counter with windowed limits.
// Used by existing services (keycore, auth, payment).
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Enterprise Usage Metering — tenant-level usage tracking and cost attribution.
// ---------------------------------------------------------------------------

// Default cost per operation in USD.
var defaultPricing = map[string]float64{
	"encrypt":  0.00001,
	"decrypt":  0.00001,
	"sign":     0.00002,
	"generate": 0.0001,
}

// UsageRecord represents a single metering data point.
type UsageRecord struct {
	TenantID  string
	Operation string
	Algorithm string
	KeyID     string
	Count     int64
	Timestamp time.Time
}

// TenantUsageSummary aggregates usage for a tenant over a billing period.
type TenantUsageSummary struct {
	TenantID         string
	Period           string
	TotalOps         int64
	OpsByType        map[string]int64
	OpsByAlgorithm   map[string]int64
	EstimatedCostUSD float64
	PeakRPS          float64
}

// MeterStore persists metering data to durable storage.
type MeterStore interface {
	FlushRecords(ctx context.Context, records []UsageRecord) error
	GetSummary(ctx context.Context, tenantID, period string) (*TenantUsageSummary, error)
	GetTopTenants(ctx context.Context, period string, limit int) ([]TenantUsageSummary, error)
}

// UsageMeterOption configures a UsageMeter.
type UsageMeterOption func(*UsageMeter)

// WithFlushInterval sets how often buffered records are flushed to the store.
func WithFlushInterval(d time.Duration) UsageMeterOption {
	return func(m *UsageMeter) {
		if d > 0 {
			m.flushInterval = d
		}
	}
}

// WithBufferSize sets the ring buffer capacity. When full, oldest records are
// silently overwritten to keep Record non-blocking.
func WithBufferSize(n int) UsageMeterOption {
	return func(m *UsageMeter) {
		if n > 0 {
			m.bufSize = n
		}
	}
}

// WithPricing overrides the default cost-per-operation map.
func WithPricing(pricing map[string]float64) UsageMeterOption {
	return func(m *UsageMeter) {
		if len(pricing) > 0 {
			m.pricing = pricing
		}
	}
}

// UsageMeter collects tenant usage data in a non-blocking ring buffer and
// periodically flushes to durable storage for billing and cost attribution.
type UsageMeter struct {
	store         MeterStore
	pricing       map[string]float64
	flushInterval time.Duration
	bufSize       int

	// Ring buffer: fixed-size slice with head index.
	mu    sync.Mutex
	buf   []UsageRecord
	head  int
	count int

	// RPS tracking per tenant for peak calculation.
	rpsMu     sync.Mutex
	rpsWindow map[string]*rpsTracker

	done    chan struct{}
	stopped chan struct{}
	running atomic.Bool
}

// rpsTracker counts requests in the current second.
type rpsTracker struct {
	second time.Time
	count  int64
	peak   float64
}

// NewUsageMeter creates a usage meter. Call Start to begin background flushing.
func NewUsageMeter(store MeterStore, opts ...UsageMeterOption) *UsageMeter {
	m := &UsageMeter{
		store:         store,
		pricing:       copyPricing(defaultPricing),
		flushInterval: 10 * time.Second,
		bufSize:       100_000,
		rpsWindow:     make(map[string]*rpsTracker),
		done:          make(chan struct{}),
		stopped:       make(chan struct{}),
	}
	for _, o := range opts {
		o(m)
	}
	m.buf = make([]UsageRecord, m.bufSize)
	return m
}

// Record adds a usage event to the ring buffer. It never blocks or returns
// an error; if the buffer is full the oldest record is overwritten.
func (m *UsageMeter) Record(_ context.Context, tenantID, operation, algorithm string) {
	rec := UsageRecord{
		TenantID:  tenantID,
		Operation: operation,
		Algorithm: algorithm,
		Count:     1,
		Timestamp: time.Now(),
	}

	m.mu.Lock()
	m.buf[m.head] = rec
	m.head = (m.head + 1) % m.bufSize
	if m.count < m.bufSize {
		m.count++
	}
	m.mu.Unlock()

	m.trackRPS(tenantID)
}

// Start begins the background flush loop.
func (m *UsageMeter) Start(ctx context.Context) {
	if m.running.Swap(true) {
		return // already running
	}
	ticker := time.NewTicker(m.flushInterval)
	defer ticker.Stop()
	defer close(m.stopped)

	for {
		select {
		case <-ticker.C:
			m.flush(ctx)
		case <-ctx.Done():
			m.flush(context.Background()) // final flush
			return
		case <-m.done:
			m.flush(context.Background()) // final flush
			return
		}
	}
}

// Stop signals the meter to perform a final flush and shut down.
func (m *UsageMeter) Stop() {
	select {
	case <-m.done:
	default:
		close(m.done)
	}
	<-m.stopped
}

// HTTPMiddleware records API calls per tenant, extracting the tenant ID from
// the X-Tenant-ID header or tenant_id query parameter.
func (m *UsageMeter) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			tenantID = r.URL.Query().Get("tenant_id")
		}
		if tenantID != "" {
			operation := classifyOperation(r)
			m.Record(r.Context(), tenantID, operation, "")
		}
		next.ServeHTTP(w, r)
	})
}

// GetSummary delegates to the underlying store.
func (m *UsageMeter) GetSummary(ctx context.Context, tenantID, period string) (*TenantUsageSummary, error) {
	return m.store.GetSummary(ctx, tenantID, period)
}

// GetTopTenants delegates to the underlying store.
func (m *UsageMeter) GetTopTenants(ctx context.Context, period string, limit int) ([]TenantUsageSummary, error) {
	return m.store.GetTopTenants(ctx, period, limit)
}

// EstimateCost calculates the estimated cost for a set of operations.
func (m *UsageMeter) EstimateCost(opsByType map[string]int64) float64 {
	var total float64
	for op, count := range opsByType {
		if price, ok := m.pricing[op]; ok {
			total += price * float64(count)
		}
	}
	return total
}

// PeakRPS returns the observed peak requests-per-second for a tenant.
func (m *UsageMeter) PeakRPS(tenantID string) float64 {
	m.rpsMu.Lock()
	defer m.rpsMu.Unlock()
	if t, ok := m.rpsWindow[tenantID]; ok {
		return t.peak
	}
	return 0
}

// flush drains the ring buffer and sends records to the store.
func (m *UsageMeter) flush(ctx context.Context) {
	m.mu.Lock()
	if m.count == 0 {
		m.mu.Unlock()
		return
	}

	records := make([]UsageRecord, 0, m.count)
	if m.count < m.bufSize {
		records = append(records, m.buf[:m.head]...)
	} else {
		// Buffer has wrapped; oldest records start at head.
		records = append(records, m.buf[m.head:]...)
		records = append(records, m.buf[:m.head]...)
	}
	m.count = 0
	m.head = 0
	m.mu.Unlock()

	if len(records) == 0 {
		return
	}

	// Aggregate records with the same tenant+operation+algorithm within the
	// same second to reduce store writes.
	aggregated := aggregateRecords(records)
	_ = m.store.FlushRecords(ctx, aggregated)
}

func (m *UsageMeter) trackRPS(tenantID string) {
	now := time.Now().Truncate(time.Second)

	m.rpsMu.Lock()
	defer m.rpsMu.Unlock()

	t, ok := m.rpsWindow[tenantID]
	if !ok {
		m.rpsWindow[tenantID] = &rpsTracker{second: now, count: 1, peak: 1}
		return
	}

	if t.second.Equal(now) {
		t.count++
		if float64(t.count) > t.peak {
			t.peak = float64(t.count)
		}
	} else {
		if float64(t.count) > t.peak {
			t.peak = float64(t.count)
		}
		t.second = now
		t.count = 1
	}
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// aggregateRecords combines records sharing the same key within one second.
func aggregateRecords(records []UsageRecord) []UsageRecord {
	type aggKey struct {
		TenantID  string
		Operation string
		Algorithm string
		Second    int64
	}

	agg := make(map[aggKey]*UsageRecord, len(records)/2)
	for i := range records {
		r := &records[i]
		k := aggKey{
			TenantID:  r.TenantID,
			Operation: r.Operation,
			Algorithm: r.Algorithm,
			Second:    r.Timestamp.Unix(),
		}
		if existing, ok := agg[k]; ok {
			existing.Count += r.Count
		} else {
			cp := *r
			agg[k] = &cp
		}
	}

	out := make([]UsageRecord, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	return out
}

// classifyOperation maps an HTTP request to a metering operation name.
func classifyOperation(r *http.Request) string {
	switch r.Method {
	case http.MethodPost:
		path := r.URL.Path
		switch {
		case containsSubstr(path, "/encrypt"):
			return "encrypt"
		case containsSubstr(path, "/decrypt"):
			return "decrypt"
		case containsSubstr(path, "/sign"):
			return "sign"
		case containsSubstr(path, "/generate"), containsSubstr(path, "/keys"):
			return "generate"
		default:
			return "write"
		}
	case http.MethodGet:
		return "read"
	case http.MethodDelete:
		return "delete"
	default:
		return "other"
	}
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func copyPricing(src map[string]float64) map[string]float64 {
	dst := make(map[string]float64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
