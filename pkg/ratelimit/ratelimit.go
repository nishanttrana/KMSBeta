package ratelimit

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Config controls per-tenant rate limiting behavior.
type Config struct {
	RequestsPerSecond float64       // Token refill rate per tenant
	BurstSize         int           // Max burst per tenant
	CleanupInterval   time.Duration // How often to purge idle buckets
}

type bucket struct {
	tokens   float64
	lastFill time.Time
	mu       sync.Mutex
}

// Limiter implements per-tenant token-bucket rate limiting.
type Limiter struct {
	mu      sync.RWMutex
	tenants map[string]*bucket
	cfg     Config
	done    chan struct{}
}

// New creates a rate limiter. Pass zero Config values for defaults.
func New(cfg Config) *Limiter {
	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = 100
	}
	if cfg.BurstSize <= 0 {
		cfg.BurstSize = int(cfg.RequestsPerSecond * 2)
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}
	l := &Limiter{
		tenants: make(map[string]*bucket),
		cfg:     cfg,
		done:    make(chan struct{}),
	}
	go l.cleanupLoop()
	return l
}

// Allow checks whether the tenant has capacity for one request.
func (l *Limiter) Allow(tenantID string) bool {
	if tenantID == "" {
		return true
	}
	b := l.getBucket(tenantID)
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * l.cfg.RequestsPerSecond
	if b.tokens > float64(l.cfg.BurstSize) {
		b.tokens = float64(l.cfg.BurstSize)
	}
	b.lastFill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *Limiter) getBucket(tenantID string) *bucket {
	l.mu.RLock()
	b, ok := l.tenants[tenantID]
	l.mu.RUnlock()
	if ok {
		return b
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok = l.tenants[tenantID]; ok {
		return b
	}
	b = &bucket{
		tokens:   float64(l.cfg.BurstSize),
		lastFill: time.Now(),
	}
	l.tenants[tenantID] = b
	return b
}

func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(l.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-l.cfg.CleanupInterval * 2)
			l.mu.Lock()
			for id, b := range l.tenants {
				b.mu.Lock()
				if b.lastFill.Before(cutoff) {
					delete(l.tenants, id)
				}
				b.mu.Unlock()
			}
			l.mu.Unlock()
		case <-l.done:
			return
		}
	}
}

// Middleware wraps an http.Handler with per-tenant rate limiting.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			tenantID = r.URL.Query().Get("tenant_id")
		}
		if tenantID != "" && !l.Allow(tenantID) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]string{
					"code":    "RATE_LIMITED",
					"message": "too many requests for this tenant",
				},
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
