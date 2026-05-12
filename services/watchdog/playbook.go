package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	pkgevents "vecta-kms/pkg/events"
)

// Incident captures one alert produced by the playbook engine. The
// engine emits an audit event for each incident and keeps a small
// rolling buffer so the UI can show recent failures without querying
// the audit chain.
type Incident struct {
	ID        string    `json:"id"`
	Service   string    `json:"service"`
	Reason    string    `json:"reason"`
	Action    string    `json:"action"`
	Timestamp time.Time `json:"timestamp"`
}

// playbookEngine periodically inspects the probe's unhealthy list and
// fires playbooks. The mapping from signal → action is intentionally
// table-driven so adding a new playbook is a one-line change.
type playbookEngine struct {
	probe  *Probe
	logger logger

	mu        sync.Mutex
	incidents []Incident
	suppress  map[string]time.Time
	nc        *nats.Conn
}

func newPlaybookEngine(probe *Probe, l logger) *playbookEngine {
	pe := &playbookEngine{
		probe:    probe,
		logger:   l,
		suppress: make(map[string]time.Time),
	}
	// Best-effort NATS connection for emitting incidents. If NATS is
	// unavailable, the engine still functions; incidents are recorded
	// in memory and surfaced via the REST endpoint.
	if nc, err := pkgevents.Connect(probe.natsURL, "kms-watchdog-playbook", l.Printf); err == nil {
		pe.nc = nc
	}
	return pe
}

// Run loops until ctx is cancelled. Each tick (every 30s) checks for
// unhealthy services and fires the matching playbook.
func (p *playbookEngine) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if p.nc != nil {
				p.nc.Close()
			}
			return
		case <-t.C:
			p.tick(ctx)
		}
	}
}

// tick evaluates every unhealthy service and dispatches at most one
// playbook per service per cool-down window. Without the cool-down a
// flapping service would generate a storm of identical incidents.
func (p *playbookEngine) tick(ctx context.Context) {
	const coolDown = 5 * time.Minute
	for _, s := range p.probe.UnhealthyServices() {
		p.mu.Lock()
		if until, ok := p.suppress[s.Service]; ok && time.Now().Before(until) {
			p.mu.Unlock()
			continue
		}
		p.suppress[s.Service] = time.Now().Add(coolDown)
		p.mu.Unlock()

		action := playbookFor(s)
		inc := Incident{
			ID:        randomID("inc"),
			Service:   s.Service,
			Reason:    "silence_seconds=" + itoa(int(s.SilenceSecs)) + ", state=" + s.State,
			Action:    action,
			Timestamp: time.Now().UTC(),
		}
		p.recordIncident(inc)
		p.emit(ctx, inc)
	}
}

// playbookFor maps a service-level signal to an action string. The
// action is consumed by downstream systems (PagerDuty, Slack, the
// reconciler's "trigger now" endpoint) — the watchdog just publishes;
// it doesn't execute.
func playbookFor(s ServiceState) string {
	switch strings.ToLower(s.Service) {
	case "keycore":
		return "page-oncall:keycore-down"
	case "kmip":
		return "page-oncall:kmip-down"
	case "policy":
		return "trigger-reconciler:policy-restart"
	case "audit":
		return "freeze-mutations:audit-degraded"
	case "reconciler":
		return "alert-only:reconciler-down"
	default:
		return "alert-only:" + s.Service + "-down"
	}
}

func (p *playbookEngine) recordIncident(inc Incident) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.incidents = append(p.incidents, inc)
	// Keep at most 200 incidents in memory.
	if len(p.incidents) > 200 {
		p.incidents = p.incidents[len(p.incidents)-200:]
	}
}

func (p *playbookEngine) Incidents() []Incident {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Incident, len(p.incidents))
	copy(out, p.incidents)
	return out
}

func (p *playbookEngine) emit(ctx context.Context, inc Incident) {
	if p.nc == nil {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"timestamp": inc.Timestamp.Format(time.RFC3339Nano),
		"service":   "watchdog",
		"action":    "audit.health.incident",
		"result":    "warning",
		"data": map[string]any{
			"incident_id":      inc.ID,
			"affected_service": inc.Service,
			"reason":           inc.Reason,
			"playbook_action":  inc.Action,
		},
	})
	if err != nil {
		return
	}
	_ = p.nc.Publish("audit.health.incident", payload)
}

// randomID is the tiny ID generator the engine uses for incidents. It
// concatenates the prefix with a base-36 timestamp; the watchdog
// doesn't need cryptographic uniqueness because the audit chain assigns
// its own canonical event ID downstream.
func randomID(prefix string) string {
	return prefix + "_" + time.Now().UTC().Format("20060102T150405.000000")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	out := ""
	for i > 0 {
		out = string(rune('0'+i%10)) + out
		i /= 10
	}
	if neg {
		return "-" + out
	}
	return out
}

// Build-time guard: ensure http package is referenced so the watchdog
// keeps compiling even if the only usage above moves to another file.
var _ = http.StatusOK
