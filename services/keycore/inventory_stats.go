package main

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/timebucket"
)

// Key statistics for Overview → Operations → Key inventory, counted by
// keycore over every key of the tenant that is not deleted (the keys GET
// /keys lists). GET /inventory/stats/keys lists the keys behind any count
// with the same predicate, so a drill-down is exactly as long as its bar.

type KeyStatCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type KeyStatPoint struct {
	Start time.Time `json:"start"`
	Count int       `json:"count"`
}

type KeyStats struct {
	From          time.Time      `json:"from"`
	To            time.Time      `json:"to"`
	BucketSeconds int64          `json:"bucket_seconds"`
	Total         int            `json:"total"`
	Created       int            `json:"created"` // created in [from, to]
	ByState       []KeyStatCount `json:"by_state"`
	ByAlgorithm   []KeyStatCount `json:"by_algorithm"`
	Series        []KeyStatPoint `json:"series"` // keys created per bucket
}

// keyStatFilter selects the keys one count covers.
type keyStatFilter struct {
	State, Algorithm string
	From, To         time.Time
}

func (f keyStatFilter) match(k Key) bool {
	switch {
	case f.State != "" && normalizeLifecycleStatus(k.Status) != f.State,
		f.Algorithm != "" && k.Algorithm != f.Algorithm,
		!f.From.IsZero() && k.CreatedAt.Before(f.From),
		!f.To.IsZero() && k.CreatedAt.After(f.To):
		return false
	}
	return true
}

// liveKeys is every key of the tenant that is not deleted, newest first.
func (s *Service) liveKeys(ctx context.Context, tenantID string) ([]Key, error) {
	if err := s.reconcileLifecycle(ctx, tenantID); err != nil {
		return nil, err
	}
	keys, err := s.allKeys(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := keys[:0]
	for _, k := range keys {
		if normalizeLifecycleStatus(k.Status) != "deleted" {
			out = append(out, k)
		}
	}
	return out, nil
}

// KeyStats counts the tenant's keys. A zero from means since the first key.
func (s *Service) KeyStats(ctx context.Context, tenantID string, from, to time.Time) (KeyStats, error) {
	keys, err := s.liveKeys(ctx, tenantID)
	if err != nil {
		return KeyStats{}, err
	}
	if to.IsZero() {
		to = time.Now().UTC()
	}
	if from.IsZero() {
		from = to
		for _, k := range keys {
			if !k.CreatedAt.IsZero() && k.CreatedAt.Before(from) {
				from = k.CreatedAt
			}
		}
	}
	st := KeyStats{From: from.UTC(), To: to.UTC(), Total: len(keys), ByState: []KeyStatCount{}, ByAlgorithm: []KeyStatCount{}, Series: []KeyStatPoint{}}
	starts, w := timebucket.Buckets(st.From, st.To)
	st.BucketSeconds = int64(w / time.Second)
	for _, b := range starts {
		st.Series = append(st.Series, KeyStatPoint{Start: b})
	}
	states, algs := map[string]int{}, map[string]int{}
	window := keyStatFilter{From: st.From, To: st.To}
	for _, k := range keys {
		states[normalizeLifecycleStatus(k.Status)]++
		algs[k.Algorithm]++
		if window.match(k) {
			st.Created++
			if i := timebucket.Index(starts, w, k.CreatedAt.UTC()); i >= 0 {
				st.Series[i].Count++
			}
		}
	}
	st.ByState, st.ByAlgorithm = rankCounts(states), rankCounts(algs)
	return st, nil
}

// KeysMatching pages through the live keys a filter selects.
func (s *Service) KeysMatching(ctx context.Context, tenantID string, f keyStatFilter, offset, limit int) ([]Key, bool, error) {
	keys, err := s.liveKeys(ctx, tenantID)
	if err != nil {
		return nil, false, err
	}
	var out []Key
	seen := 0
	for _, k := range keys {
		if !f.match(k) {
			continue
		}
		if seen >= offset && len(out) < limit {
			out = append(out, k)
		}
		seen++
	}
	return out, seen > offset+len(out), nil
}

func rankCounts(m map[string]int) []KeyStatCount {
	out := make([]KeyStatCount, 0, len(m))
	for k, n := range m {
		out = append(out, KeyStatCount{Key: k, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// statWindow reads from and to; a malformed one is refused.
func statWindow(c *route.Call) (time.Time, time.Time, bool) {
	q := c.R.URL.Query()
	parse := func(name string) (time.Time, bool) {
		v := strings.TrimSpace(q.Get(name))
		if v == "" {
			return time.Time{}, true
		}
		t, err := time.Parse(time.RFC3339Nano, v)
		return t, err == nil
	}
	from, okFrom := parse("from")
	to, okTo := parse("to")
	if !okFrom || !okTo {
		c.Refuse(http.StatusBadRequest, "bad_window", "from and to must be RFC 3339 times")
		return time.Time{}, time.Time{}, false
	}
	return from, to, true
}

func (h *Handler) keyStats(c *route.Call) {
	from, to, ok := statWindow(c)
	if !ok {
		return
	}
	st, err := h.svc.KeyStats(c.R.Context(), c.Tenant, from, to)
	if err != nil {
		c.Error(http.StatusInternalServerError, "stats_failed", "key statistics failed")
		return
	}
	c.Detail("total", st.Total)
	c.JSON(http.StatusOK, map[string]any{"stats": st})
}

func (h *Handler) keyStatsKeys(c *route.Call) {
	from, to, ok := statWindow(c)
	if !ok {
		return
	}
	q := c.R.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	f := keyStatFilter{State: strings.TrimSpace(q.Get("state")), Algorithm: strings.TrimSpace(q.Get("algorithm")), From: from, To: to}
	keys, more, err := h.svc.KeysMatching(c.R.Context(), c.Tenant, f, offset, limit)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_failed", "failed to list keys")
		return
	}
	c.Detail("count", len(keys))
	c.JSON(http.StatusOK, map[string]any{"items": renderKeys(keys), "has_more": more})
}
