package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	pkgevents "vecta-kms/pkg/events"
)

// Heartbeat is the shape every service publishes on the
// "health.<service>.heartbeat" subject. The payload is intentionally
// small so the watchdog can absorb a high heartbeat rate without
// allocating heavily.
type Heartbeat struct {
	Service    string    `json:"service"`
	NodeID     string    `json:"node_id,omitempty"`
	Version    string    `json:"version,omitempty"`
	State      string    `json:"state"` // "ready", "degraded", "draining"
	Timestamp  time.Time `json:"timestamp"`
	Details    map[string]any `json:"details,omitempty"`
}

// ServiceState is the most recent heartbeat seen for a service plus the
// derived health summary. Snapshot() emits this shape on the REST API.
type ServiceState struct {
	Service     string    `json:"service"`
	LastSeen    time.Time `json:"last_seen"`
	State       string    `json:"state"`
	SilenceSecs int64     `json:"silence_seconds"`
	Healthy     bool      `json:"healthy"`
}

// logIface is the minimal logging interface the watchdog accepts.
// *log.Logger satisfies it via Printf.
type logIface interface {
	Printf(format string, args ...any)
}

// Probe is the NATS subscriber + in-memory state table. SLO defaults are
// loose enough to absorb GC pauses but tight enough to catch a real
// process hang within a minute.
type Probe struct {
	nc           *nats.Conn
	subs         []*nats.Subscription
	natsURL      string
	logger       logIface
	slo          time.Duration

	mu     sync.Mutex
	last   map[string]Heartbeat
}

func newProbe(natsURL string, l logIface) *Probe {
	return &Probe{
		natsURL: natsURL,
		logger:  l,
		slo:     90 * time.Second,
		last:    make(map[string]Heartbeat),
	}
}

// Start opens the NATS connection and subscribes to every heartbeat
// subject. Returns an error if the connection or subscription fails.
func (p *Probe) Start(ctx context.Context) error {
	nc, err := pkgevents.Connect(p.natsURL, "kms-watchdog", p.logger.Printf)
	if err != nil {
		return err
	}
	p.nc = nc
	sub, err := nc.Subscribe("health.*.heartbeat", func(msg *nats.Msg) {
		var hb Heartbeat
		if err := json.Unmarshal(msg.Data, &hb); err != nil {
			return
		}
		if hb.Timestamp.IsZero() {
			hb.Timestamp = time.Now().UTC()
		}
		if hb.Service == "" {
			parts := strings.Split(msg.Subject, ".")
			if len(parts) >= 3 {
				hb.Service = parts[1]
			}
		}
		p.mu.Lock()
		p.last[hb.Service] = hb
		p.mu.Unlock()
	})
	if err != nil {
		return err
	}
	p.subs = append(p.subs, sub)
	return nil
}

// Close unsubscribes and drains the connection.
func (p *Probe) Close() {
	for _, s := range p.subs {
		_ = s.Unsubscribe()
	}
	if p.nc != nil {
		p.nc.Close()
	}
}

// Snapshot returns the current state of every service the probe has
// observed. Services silent longer than the SLO are marked unhealthy.
func (p *Probe) Snapshot() []ServiceState {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().UTC()
	out := make([]ServiceState, 0, len(p.last))
	for name, hb := range p.last {
		silence := now.Sub(hb.Timestamp)
		out = append(out, ServiceState{
			Service:     name,
			LastSeen:    hb.Timestamp,
			State:       hb.State,
			SilenceSecs: int64(silence.Seconds()),
			Healthy:     silence <= p.slo && hb.State != "degraded",
		})
	}
	return out
}

// UnhealthyServices is the subset of Snapshot that requires action.
func (p *Probe) UnhealthyServices() []ServiceState {
	all := p.Snapshot()
	out := make([]ServiceState, 0)
	for _, s := range all {
		if !s.Healthy {
			out = append(out, s)
		}
	}
	return out
}
