// Package heartbeat provides the publisher side of the NATS health
// channel consumed by the watchdog service. Services import this
// package and call Publisher.Start once at boot; the publisher pushes a
// heartbeat every 30s for the lifetime of the context.
package heartbeat

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nats-io/nats.go"
)

// Heartbeat matches the watchdog's incoming shape. Producers fill the
// public fields; Timestamp is set automatically on publish.
type Heartbeat struct {
	Service   string         `json:"service"`
	NodeID    string         `json:"node_id,omitempty"`
	Version   string         `json:"version,omitempty"`
	State     string         `json:"state"` // "ready", "degraded", "draining"
	Timestamp time.Time      `json:"timestamp"`
	Details   map[string]any `json:"details,omitempty"`
}

// Publisher runs the publish loop. Construct with New, call Start, defer
// Stop. The interval is fixed at 30s — short enough for the watchdog
// SLO (90s), long enough to be invisible against normal NATS traffic.
type Publisher struct {
	nc       *nats.Conn
	service  string
	nodeID   string
	version  string
	interval time.Duration
	stateFn  func() string
	stop     chan struct{}
}

// New constructs a publisher bound to the given NATS connection.
func New(nc *nats.Conn, service, nodeID, version string) *Publisher {
	return &Publisher{
		nc:       nc,
		service:  service,
		nodeID:   nodeID,
		version:  version,
		interval: 30 * time.Second,
		stateFn:  func() string { return "ready" },
		stop:     make(chan struct{}),
	}
}

// SetStateFunc lets the caller plug in a health check so a degraded
// service can publish "degraded" without becoming silent.
func (p *Publisher) SetStateFunc(fn func() string) {
	if fn != nil {
		p.stateFn = fn
	}
}

// Start launches the publish goroutine. Returns immediately; callers
// should defer Stop. If nc is nil the publisher is a no-op so service
// code can call Start unconditionally even when NATS is disabled.
func (p *Publisher) Start(ctx context.Context) {
	if p == nil || p.nc == nil {
		return
	}
	go func() {
		t := time.NewTicker(p.interval)
		defer t.Stop()
		// Publish once immediately so the watchdog sees the service
		// before the first ticker fires.
		p.publishOnce()
		for {
			select {
			case <-ctx.Done():
				return
			case <-p.stop:
				return
			case <-t.C:
				p.publishOnce()
			}
		}
	}()
}

// Stop ends the publish loop. Safe to call multiple times.
func (p *Publisher) Stop() {
	if p == nil {
		return
	}
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
}

func (p *Publisher) publishOnce() {
	hb := Heartbeat{
		Service:   p.service,
		NodeID:    p.nodeID,
		Version:   p.version,
		State:     p.stateFn(),
		Timestamp: time.Now().UTC(),
	}
	raw, err := json.Marshal(hb)
	if err != nil {
		return
	}
	_ = p.nc.Publish("health."+p.service+".heartbeat", raw)
}
