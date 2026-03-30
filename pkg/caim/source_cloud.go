package caim

import (
	"context"
	"fmt"
	"time"
)

// CloudKMSInventory provides a key inventory from a cloud KMS provider.
type CloudKMSInventory interface {
	// Provider returns the cloud provider name (aws, azure, gcp, oci, alibaba).
	Provider() string
	// ListCloudKeys returns all keys managed in the cloud KMS account.
	ListCloudKeys(ctx context.Context, accountID string) ([]CloudKeyInfo, error)
}

// CloudKeyInfo represents a key in a cloud KMS.
type CloudKeyInfo struct {
	KeyID     string
	KeyName   string
	Algorithm string
	KeySize   int
	State     string // enabled, disabled, pending_deletion, etc.
	CreatedAt time.Time
	Region    string
	AccountID string
}

// CloudAccount represents a registered BYOK cloud account.
type CloudAccount struct {
	Provider  string `json:"provider"`
	AccountID string `json:"account_id"`
	TenantID  string `json:"tenant_id"`
}

// CloudSource discovers crypto assets from registered cloud KMS accounts.
type CloudSource struct {
	providers map[string]CloudKMSInventory
	accounts  []CloudAccount
}

// NewCloudSource creates a cloud discovery source with registered providers and accounts.
func NewCloudSource(accounts []CloudAccount) *CloudSource {
	return &CloudSource{
		providers: make(map[string]CloudKMSInventory),
		accounts:  accounts,
	}
}

// RegisterProvider adds a cloud KMS inventory provider.
func (s *CloudSource) RegisterProvider(provider CloudKMSInventory) {
	s.providers[provider.Provider()] = provider
}

// Name returns the source identifier.
func (s *CloudSource) Name() string {
	return "cloud_kms"
}

// Discover aggregates key inventories from all registered BYOK cloud accounts.
func (s *CloudSource) Discover(ctx context.Context, tenantID string) ([]CryptoAsset, error) {
	var assets []CryptoAsset

	for _, account := range s.accounts {
		if account.TenantID != tenantID {
			continue
		}

		provider, ok := s.providers[account.Provider]
		if !ok {
			continue
		}

		keys, err := provider.ListCloudKeys(ctx, account.AccountID)
		if err != nil {
			// Log error but continue with other accounts
			assets = append(assets, CryptoAsset{
				TenantID:        tenantID,
				AssetType:       AssetTypeKey,
				Name:            fmt.Sprintf("error_%s_%s", account.Provider, account.AccountID),
				Location:        Location{Cloud: account.Provider, Service: "kms"},
				DiscoverySource: "cloud_kms",
				LastSeen:        time.Now(),
				ComplianceStatus: ComplianceUnknown,
				Metadata: map[string]string{
					"error":      err.Error(),
					"account_id": account.AccountID,
				},
			})
			continue
		}

		for _, k := range keys {
			asset := CryptoAsset{
				TenantID:        tenantID,
				AssetType:       AssetTypeKey,
				Name:            k.KeyName,
				Location:        Location{Cloud: account.Provider, Service: "kms", Host: k.Region},
				Algorithm:       k.Algorithm,
				KeySize:         k.KeySize,
				CreatedAt:       k.CreatedAt,
				DiscoverySource: "cloud_kms",
				LastSeen:        time.Now(),
				Metadata: map[string]string{
					"cloud_key_id": k.KeyID,
					"account_id":   k.AccountID,
					"region":       k.Region,
					"state":        k.State,
					"provider":     account.Provider,
				},
			}
			assets = append(assets, asset)
		}
	}

	return assets, nil
}
