package main

import "sync"

type feedHub struct {
	mu      sync.Mutex
	streams map[string]map[chan Alert]struct{}
}

func newFeedHub() *feedHub {
	return &feedHub{streams: map[string]map[chan Alert]struct{}{}}
}

func (h *feedHub) Subscribe(tenantID string) (<-chan Alert, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan Alert, 64)
	if h.streams[tenantID] == nil {
		h.streams[tenantID] = map[chan Alert]struct{}{}
	}
	h.streams[tenantID][ch] = struct{}{}
	cancel := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, ok := h.streams[tenantID][ch]; ok {
			delete(h.streams[tenantID], ch)
			close(ch)
		}
		if len(h.streams[tenantID]) == 0 {
			delete(h.streams, tenantID)
		}
	}
	return ch, cancel
}

func (h *feedHub) Publish(tenantID string, item Alert) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.streams[tenantID] {
		select {
		case ch <- item:
		default:
		}
	}
}
