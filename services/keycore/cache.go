package main

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type KeyCache interface {
	Get(ctx context.Context, tenantID string, keyID string) (Key, bool, error)
	Set(ctx context.Context, key Key) error
	Delete(ctx context.Context, tenantID string, keyID string) error
}

type memoryCache struct {
	mu   sync.RWMutex
	data map[string]cacheItem
	ttl  time.Duration
}

type cacheItem struct {
	Key       Key
	ExpiresAt time.Time
}

func newMemoryCache(ttl time.Duration) *memoryCache {
	return &memoryCache{
		data: make(map[string]cacheItem),
		ttl:  ttl,
	}
}

func (m *memoryCache) Get(_ context.Context, tenantID string, keyID string) (Key, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	it, ok := m.data[cacheKey(tenantID, keyID)]
	if !ok || time.Now().UTC().After(it.ExpiresAt) {
		return Key{}, false, nil
	}
	return it.Key, true, nil
}

func (m *memoryCache) Set(_ context.Context, key Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[cacheKey(key.TenantID, key.ID)] = cacheItem{
		Key:       key,
		ExpiresAt: time.Now().UTC().Add(m.ttl),
	}
	return nil
}

func (m *memoryCache) Delete(_ context.Context, tenantID string, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, cacheKey(tenantID, keyID))
	return nil
}

type redisKeyCache struct {
	client *redis.Client
	ttl    time.Duration
}

func newRedisKeyCache(client *redis.Client, ttl time.Duration) *redisKeyCache {
	return &redisKeyCache{client: client, ttl: ttl}
}

func (r *redisKeyCache) Get(ctx context.Context, tenantID string, keyID string) (Key, bool, error) {
	val, err := r.client.Get(ctx, cacheKey(tenantID, keyID)).Result()
	if err == redis.Nil {
		return Key{}, false, nil
	}
	if err != nil {
		return Key{}, false, err
	}
	var k Key
	if err := json.Unmarshal([]byte(val), &k); err != nil {
		return Key{}, false, err
	}
	return k, true, nil
}

func (r *redisKeyCache) Set(ctx context.Context, key Key) error {
	raw, err := json.Marshal(key)
	if err != nil {
		return err
	}
	return r.client.Set(ctx, cacheKey(key.TenantID, key.ID), raw, r.ttl).Err()
}

func (r *redisKeyCache) Delete(ctx context.Context, tenantID string, keyID string) error {
	return r.client.Del(ctx, cacheKey(tenantID, keyID)).Err()
}

func cacheKey(tenantID string, keyID string) string {
	return "keycore:" + tenantID + ":" + keyID
}
