package keycache

import (
	"sync"
	"time"

	"vecta-kms/pkg/crypto"
)

// Entry holds cached key material in locked memory.
type Entry struct {
	KeyID      string
	Version    int
	Material   []byte // raw key bytes (Mlock'd)
	Algorithm  string
	ExportedAt time.Time
	ExpiresAt  time.Time
}

// Cache provides a thread-safe, TTL-based local key material cache
// with secure memory management (Mlock/Zeroize).
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*Entry
	ttl     time.Duration
	enabled bool
	stopCh  chan struct{}
}

// New creates a key cache. If enabled is false, Get always misses and Put is a no-op.
func New(enabled bool, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Cache{
		entries: make(map[string]*Entry),
		ttl:     ttl,
		enabled: enabled,
		stopCh:  make(chan struct{}),
	}
}

// Get returns a cached entry if it exists and is not expired.
func (c *Cache) Get(keyID string) (*Entry, bool) {
	if !c.enabled {
		return nil, false
	}
	c.mu.RLock()
	e, ok := c.entries[keyID]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(e.ExpiresAt) {
		c.Evict(keyID)
		return nil, false
	}
	return e, true
}

// Put stores key material in the cache with Mlock protection.
func (c *Cache) Put(keyID string, version int, algorithm string, material []byte) {
	if !c.enabled || len(material) == 0 {
		return
	}

	// Copy material into a dedicated slice so we control its lifecycle
	mat := make([]byte, len(material))
	copy(mat, material)
	_ = crypto.Mlock(mat)

	e := &Entry{
		KeyID:      keyID,
		Version:    version,
		Material:   mat,
		Algorithm:  algorithm,
		ExportedAt: time.Now(),
		ExpiresAt:  time.Now().Add(c.ttl),
	}

	c.mu.Lock()
	// Evict old entry if present
	if old, ok := c.entries[keyID]; ok {
		crypto.Zeroize(old.Material)
		_ = crypto.Munlock(old.Material)
	}
	c.entries[keyID] = e
	c.mu.Unlock()
}

// Evict removes a key from the cache, zeroizing its material.
func (c *Cache) Evict(keyID string) {
	c.mu.Lock()
	if e, ok := c.entries[keyID]; ok {
		crypto.Zeroize(e.Material)
		_ = crypto.Munlock(e.Material)
		delete(c.entries, keyID)
	}
	c.mu.Unlock()
}

// StartEvictionLoop runs a background goroutine that removes expired entries.
func (c *Cache) StartEvictionLoop(interval time.Duration) {
	if !c.enabled {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.evictExpired()
			case <-c.stopCh:
				return
			}
		}
	}()
}

func (c *Cache) evictExpired() {
	now := time.Now()
	c.mu.Lock()
	for id, e := range c.entries {
		if now.After(e.ExpiresAt) {
			crypto.Zeroize(e.Material)
			_ = crypto.Munlock(e.Material)
			delete(c.entries, id)
		}
	}
	c.mu.Unlock()
}

// Close zeroizes all cached entries and stops the eviction loop.
func (c *Cache) Close() {
	close(c.stopCh)
	c.mu.Lock()
	for id, e := range c.entries {
		crypto.Zeroize(e.Material)
		_ = crypto.Munlock(e.Material)
		delete(c.entries, id)
	}
	c.mu.Unlock()
}

// Len returns the number of currently cached entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Enabled returns whether the cache is active.
func (c *Cache) Enabled() bool {
	return c.enabled
}
