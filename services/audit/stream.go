package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// StreamBroker is a lightweight SSE fan-out broker.
// Events published via Broadcast are delivered to all active subscribers.
type StreamBroker struct {
	mu          sync.RWMutex
	subscribers map[string]*subscriber
}

type subscriber struct {
	ch       chan sseEvent
	tenantID string
	kind     string // "events" or "alerts"
}

type sseEvent struct {
	id   string
	data string
}

func newStreamBroker() *StreamBroker {
	return &StreamBroker{subscribers: make(map[string]*subscriber)}
}

func (b *StreamBroker) subscribe(id string, tenantID string, kind string) *subscriber {
	sub := &subscriber{
		ch:       make(chan sseEvent, 64),
		tenantID: tenantID,
		kind:     kind,
	}
	b.mu.Lock()
	b.subscribers[id] = sub
	b.mu.Unlock()
	return sub
}

func (b *StreamBroker) unsubscribe(id string) {
	b.mu.Lock()
	if sub, ok := b.subscribers[id]; ok {
		close(sub.ch)
		delete(b.subscribers, id)
	}
	b.mu.Unlock()
}

// BroadcastEvent delivers a serialised audit event to all matching subscribers.
func (b *StreamBroker) BroadcastEvent(tenantID string, eventID string, data string) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	ev := sseEvent{id: eventID, data: data}
	for _, sub := range b.subscribers {
		if sub.kind != "events" {
			continue
		}
		if sub.tenantID != "" && sub.tenantID != tenantID {
			continue
		}
		select {
		case sub.ch <- ev:
		default:
			// Slow consumer — drop rather than block.
		}
	}
}

// BroadcastAlert delivers a serialised alert to all matching subscribers.
func (b *StreamBroker) BroadcastAlert(tenantID string, alertID string, data string) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	ev := sseEvent{id: alertID, data: data}
	for _, sub := range b.subscribers {
		if sub.kind != "alerts" {
			continue
		}
		if sub.tenantID != "" && sub.tenantID != tenantID {
			continue
		}
		select {
		case sub.ch <- ev:
		default:
		}
	}
}

// ── SSE Handlers ─────────────────────────────────────────────

func (h *Handler) handleStream(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	serveSSE(w, r, h.broker, tenantID, "events")
}

func (h *Handler) handleAlertStream(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	serveSSE(w, r, h.broker, tenantID, "alerts")
}

func serveSSE(w http.ResponseWriter, r *http.Request, broker *StreamBroker, tenantID string, kind string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Connection", "keep-alive")

	subID := newID("sub")
	sub := broker.subscribe(subID, tenantID, kind)
	defer broker.unsubscribe(subID)

	// Send a connected heartbeat.
	fmt.Fprintf(w, ": connected tenant=%s kind=%s\n\n", tenantID, kind)
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat %s\n\n", time.Now().UTC().Format(time.RFC3339))
			flusher.Flush()
		case ev, open := <-sub.ch:
			if !open {
				return
			}
			id := strings.TrimSpace(ev.id)
			if id != "" {
				fmt.Fprintf(w, "id: %s\n", id)
			}
			fmt.Fprintf(w, "data: %s\n\n", ev.data)
			flusher.Flush()
		}
	}
}
