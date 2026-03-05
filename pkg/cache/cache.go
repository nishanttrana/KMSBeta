package cache

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache provides a generic key-value cache with TTL.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// --- Memory backend ---

type memItem struct {
	value     []byte
	expiresAt time.Time
}

type memoryCache struct {
	mu   sync.RWMutex
	data map[string]memItem
	ttl  time.Duration
	done chan struct{}
}

// NewMemory creates an in-process cache with background eviction.
func NewMemory(defaultTTL time.Duration) Cache {
	c := &memoryCache{
		data: make(map[string]memItem),
		ttl:  defaultTTL,
		done: make(chan struct{}),
	}
	go c.evictLoop()
	return c
}

func (m *memoryCache) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	it, ok := m.data[key]
	if !ok || time.Now().UTC().After(it.expiresAt) {
		return nil, false, nil
	}
	cp := make([]byte, len(it.value))
	copy(cp, it.value)
	return cp, true, nil
}

func (m *memoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = m.ttl
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	m.mu.Lock()
	m.data[key] = memItem{value: cp, expiresAt: time.Now().UTC().Add(ttl)}
	m.mu.Unlock()
	return nil
}

func (m *memoryCache) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	delete(m.data, key)
	m.mu.Unlock()
	return nil
}

func (m *memoryCache) evictLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now().UTC()
			m.mu.Lock()
			for k, v := range m.data {
				if now.After(v.expiresAt) {
					delete(m.data, k)
				}
			}
			m.mu.Unlock()
		case <-m.done:
			return
		}
	}
}

// --- Redis backend ---

type redisCache struct {
	client *redis.Client
}

// NewRedis creates a Redis-backed cache.
func NewRedis(client *redis.Client) Cache {
	return &redisCache{client: client}
}

func (r *redisCache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	val, err := r.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return val, true, nil
}

func (r *redisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}

func (r *redisCache) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

// --- Typed helpers ---

// GetTyped retrieves and JSON-unmarshals a cached value.
func GetTyped[T any](ctx context.Context, c Cache, key string) (T, bool, error) {
	var zero T
	raw, ok, err := c.Get(ctx, key)
	if err != nil || !ok {
		return zero, false, err
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return zero, false, err
	}
	return v, true, nil
}

// SetTyped JSON-marshals and caches a value.
func SetTyped[T any](ctx context.Context, c Cache, key string, val T, ttl time.Duration) error {
	raw, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return c.Set(ctx, key, raw, ttl)
}
