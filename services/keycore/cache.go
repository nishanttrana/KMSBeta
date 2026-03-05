package main

import (
	"context"
	"time"

	pkgcache "vecta-kms/pkg/cache"
)

// KeyCache is a typed cache for Key metadata lookups.
type KeyCache interface {
	Get(ctx context.Context, tenantID string, keyID string) (Key, bool, error)
	Set(ctx context.Context, key Key) error
	Delete(ctx context.Context, tenantID string, keyID string) error
}

type keyCacheAdapter struct {
	backend pkgcache.Cache
	ttl     time.Duration
}

// NewKeyCache wraps a generic pkg/cache.Cache with typed Key operations.
func NewKeyCache(backend pkgcache.Cache, ttl time.Duration) KeyCache {
	return &keyCacheAdapter{backend: backend, ttl: ttl}
}

func (a *keyCacheAdapter) Get(ctx context.Context, tenantID string, keyID string) (Key, bool, error) {
	return pkgcache.GetTyped[Key](ctx, a.backend, cacheKey(tenantID, keyID))
}

func (a *keyCacheAdapter) Set(ctx context.Context, key Key) error {
	return pkgcache.SetTyped(ctx, a.backend, cacheKey(key.TenantID, key.ID), key, a.ttl)
}

func (a *keyCacheAdapter) Delete(ctx context.Context, tenantID string, keyID string) error {
	return a.backend.Delete(ctx, cacheKey(tenantID, keyID))
}

func cacheKey(tenantID string, keyID string) string {
	return "keycore:" + tenantID + ":" + keyID
}
