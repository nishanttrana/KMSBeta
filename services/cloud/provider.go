package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
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

func newMockProviderRegistry() *ProviderRegistry {
	r := NewProviderRegistry()
	r.Register(newMockProvider(ProviderAWS))
	r.Register(newMockProvider(ProviderAzure))
	r.Register(newMockProvider(ProviderGCP))
	r.Register(newMockProvider(ProviderOCI))
	r.Register(newMockProvider(ProviderSalesforce))
	return r
}

type mockProvider struct {
	name string
}

func newMockProvider(name string) *mockProvider {
	return &mockProvider{name: normalizeProvider(name)}
}

func (m *mockProvider) Name() string { return m.name }

func (m *mockProvider) DefaultRegion() string {
	switch m.name {
	case ProviderAWS:
		return "us-east-1"
	case ProviderAzure:
		return "eastus"
	case ProviderGCP:
		return "us-central1"
	case ProviderOCI:
		return "us-ashburn-1"
	case ProviderSalesforce:
		return "global"
	default:
		return "global"
	}
}

func (m *mockProvider) ImportKey(_ context.Context, in ImportInput) (ImportResult, error) {
	if strings.TrimSpace(in.KeyID) == "" {
		return ImportResult{}, errors.New("key_id is required")
	}
	digest := providerDigest(m.name, in.TenantID, in.Account.ID, in.KeyID, in.Region, "import")
	cloudKeyID := fmt.Sprintf("%s-key-%s", m.name, digest[:16])
	ref := m.buildRef(in.Account, in.Region, cloudKeyID)
	meta := cloneMap(in.Metadata)
	meta["provider"] = m.name
	meta["action"] = "import"
	meta["cloud_key_id"] = cloudKeyID
	meta["generated_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	return ImportResult{
		CloudKeyID:  cloudKeyID,
		CloudKeyRef: ref,
		State:       "enabled",
		Metadata:    meta,
	}, nil
}

func (m *mockProvider) RotateKey(_ context.Context, in RotateInput) (ImportResult, error) {
	if strings.TrimSpace(in.Binding.CloudKeyID) == "" {
		return ImportResult{}, errors.New("cloud key id is required")
	}
	meta := map[string]interface{}{
		"provider":     m.name,
		"action":       "rotate",
		"reason":       defaultString(in.Reason, "manual"),
		"cloud_key_id": in.Binding.CloudKeyID,
		"rotated_at":   time.Now().UTC().Format(time.RFC3339Nano),
		"key_id":       in.Binding.KeyID,
	}
	return ImportResult{
		CloudKeyID:  in.Binding.CloudKeyID,
		CloudKeyRef: in.Binding.CloudKeyRef,
		State:       "enabled",
		Metadata:    meta,
	}, nil
}

func (m *mockProvider) SyncBinding(_ context.Context, in SyncInput) (ImportResult, error) {
	if strings.TrimSpace(in.Binding.CloudKeyID) == "" {
		return ImportResult{}, errors.New("cloud key id is required")
	}
	meta := map[string]interface{}{
		"provider":     m.name,
		"action":       "sync",
		"synced_at":    time.Now().UTC().Format(time.RFC3339Nano),
		"cloud_key_id": in.Binding.CloudKeyID,
	}
	return ImportResult{
		CloudKeyID:  in.Binding.CloudKeyID,
		CloudKeyRef: in.Binding.CloudKeyRef,
		State:       "enabled",
		Metadata:    meta,
	}, nil
}

func (m *mockProvider) Inventory(_ context.Context, in InventoryInput) ([]InventoryItem, error) {
	account := in.Account
	region := strings.TrimSpace(in.Region)
	if region == "" {
		region = defaultString(account.DefaultRegion, m.DefaultRegion())
	}
	digest := providerDigest(m.name, account.TenantID, account.ID, region, "inventory")
	item := InventoryItem{
		CloudKeyID:     fmt.Sprintf("%s-discovered-%s", m.name, digest[:12]),
		CloudKeyRef:    m.buildRef(account, region, fmt.Sprintf("%s-discovered-%s", m.name, digest[:12])),
		Provider:       m.name,
		AccountID:      account.ID,
		Region:         region,
		State:          "enabled",
		Algorithm:      "AES-256",
		ManagedByVecta: false,
	}
	return []InventoryItem{item}, nil
}

func (m *mockProvider) buildRef(account CloudAccount, region string, cloudKeyID string) string {
	switch m.name {
	case ProviderAWS:
		return fmt.Sprintf("arn:aws:kms:%s:%s:key/%s", region, account.ID, cloudKeyID)
	case ProviderAzure:
		return fmt.Sprintf("https://%s.vault.azure.net/keys/%s", account.Name, cloudKeyID)
	case ProviderGCP:
		return fmt.Sprintf("projects/%s/locations/%s/keyRings/vecta/cryptoKeys/%s", account.ID, region, cloudKeyID)
	case ProviderOCI:
		return fmt.Sprintf("ocid1.key.oc1.%s.%s", strings.ReplaceAll(region, "-", ""), cloudKeyID)
	case ProviderSalesforce:
		return fmt.Sprintf("salesforce://tenant-secrets/%s", cloudKeyID)
	default:
		return cloudKeyID
	}
}

func providerDigest(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])
}

func cloneMap(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return map[string]interface{}{}
	}
	raw, _ := json.Marshal(in)
	out := map[string]interface{}{}
	_ = json.Unmarshal(raw, &out)
	return out
}
