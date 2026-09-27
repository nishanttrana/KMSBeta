package main

import (
	"context"
	"errors"
	"sync"
)

type ImportInput struct {
	TenantID    string
	KeyID       string
	Account     CloudAccount
	Region      string
	Credentials map[string]interface{}
	KeyMeta     map[string]interface{}
	Export      map[string]interface{}
	Metadata    map[string]interface{}
}

type RotateInput struct {
	TenantID    string
	Binding     CloudKeyBinding
	Account     CloudAccount
	Credentials map[string]interface{}
	KeyMeta     map[string]interface{}
	Export      map[string]interface{}
	Reason      string
}

type SyncInput struct {
	TenantID    string
	Binding     CloudKeyBinding
	Account     CloudAccount
	Credentials map[string]interface{}
}

type InventoryInput struct {
	TenantID    string
	Account     CloudAccount
	Region      string
	Credentials map[string]interface{}
}

type ImportResult struct {
	CloudKeyID  string
	CloudKeyRef string
	State       string
	Metadata    map[string]interface{}
}

type CloudProvider interface {
	Name() string
	ImportKey(ctx context.Context, in ImportInput) (ImportResult, error)
	RotateKey(ctx context.Context, in RotateInput) (ImportResult, error)
	SyncBinding(ctx context.Context, in SyncInput) (ImportResult, error)
	Inventory(ctx context.Context, in InventoryInput) ([]InventoryItem, error)
	DefaultRegion() string
}

type ProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]CloudProvider
}

func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: map[string]CloudProvider{},
	}
}

func (r *ProviderRegistry) Register(p CloudProvider) {
	if p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[normalizeProvider(p.Name())] = p
}

func (r *ProviderRegistry) Get(name string) (CloudProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[normalizeProvider(name)]
	if !ok {
		return nil, errors.New("unsupported provider")
	}
	return p, nil
}

func (r *ProviderRegistry) MustGet(name string) CloudProvider {
	p, _ := r.Get(name)
	return p
}

func defaultProviderRegistry() *ProviderRegistry {
	return newRealProviderRegistry()
}
