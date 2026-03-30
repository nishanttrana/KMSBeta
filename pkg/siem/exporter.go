package siem

import (
	"context"
	"log"
	"sync"
	"time"
)

// AuditEvent represents a KMS audit event to be exported to SIEM platforms.
type AuditEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	TenantID  string            `json:"tenant_id"`
	Actor     string            `json:"actor"`
	Action    string            `json:"action"`
	KeyID     string            `json:"key_id,omitempty"`
	Resource  string            `json:"resource"`
	Outcome   string            `json:"outcome"` // success, failure, denied
	Severity  int               `json:"severity"` // 0-10
	SourceIP  string            `json:"source_ip,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Destination is the interface every SIEM backend must implement.
type Destination interface {
	Send(ctx context.Context, events []AuditEvent) error
	Name() string
}

// Exporter buffers audit events and flushes them to registered destinations.
type Exporter struct {
	destinations []Destination
	buffer       []AuditEvent
	mu           sync.Mutex
	flushSize    int
	flushInterval time.Duration
	stopCh       chan struct{}
	doneCh       chan struct{}
}

// NewExporter creates an Exporter that flushes every flushInterval or when buffer reaches flushSize.
func NewExporter(flushInterval time.Duration, flushSize int) *Exporter {
	if flushInterval == 0 {
		flushInterval = 5 * time.Second
	}
	if flushSize == 0 {
		flushSize = 100
	}
	return &Exporter{
		buffer:        make([]AuditEvent, 0, flushSize),
		flushSize:     flushSize,
		flushInterval: flushInterval,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
}

// Register adds a SIEM destination.
func (e *Exporter) Register(dest Destination) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.destinations = append(e.destinations, dest)
}

// Start begins the background flush goroutine. Use the context to control lifetime,
// or call Stop() for a graceful final flush.
func (e *Exporter) Start(ctx context.Context) {
	go func() {
		defer close(e.doneCh)
		ticker := time.NewTicker(e.flushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				e.flush(context.Background())
				return
			case <-e.stopCh:
				e.flush(context.Background())
				return
			case <-ticker.C:
				e.flush(ctx)
			}
		}
	}()
}

// Ingest adds an event to the buffer in a non-blocking manner.
// If the buffer reaches flushSize, a flush is triggered asynchronously.
func (e *Exporter) Ingest(event AuditEvent) {
	e.mu.Lock()
	e.buffer = append(e.buffer, event)
	shouldFlush := len(e.buffer) >= e.flushSize
	e.mu.Unlock()

	if shouldFlush {
		go e.flush(context.Background())
	}
}

// Stop performs a final flush and shuts down the background goroutine.
func (e *Exporter) Stop() {
	close(e.stopCh)
	<-e.doneCh
}

// flush drains the buffer and sends events to all destinations.
func (e *Exporter) flush(ctx context.Context) {
	e.mu.Lock()
	if len(e.buffer) == 0 {
		e.mu.Unlock()
		return
	}
	events := make([]AuditEvent, len(e.buffer))
	copy(events, e.buffer)
	e.buffer = e.buffer[:0]
	dests := make([]Destination, len(e.destinations))
	copy(dests, e.destinations)
	e.mu.Unlock()

	for _, dest := range dests {
		if err := dest.Send(ctx, events); err != nil {
			log.Printf("siem: failed to send %d events to %s: %v", len(events), dest.Name(), err)
		}
	}
}
