package caim

import (
	"context"
	"fmt"
	"time"
)

// KeyCoreClient provides access to Vecta KMS internal key data.
type KeyCoreClient interface {
	// ListKeys returns all keys with their metadata.
	ListKeys(ctx context.Context, tenantID string) ([]KeyInfo, error)
}

// CertServiceClient provides access to the certificate management service.
type CertServiceClient interface {
	// ListCertificates returns all managed certificates.
	ListCertificates(ctx context.Context, tenantID string) ([]CertInfo, error)
}

// TLSConfigClient provides access to TLS configuration across services.
type TLSConfigClient interface {
	// ListTLSConfigs returns TLS configurations for all services.
	ListTLSConfigs(ctx context.Context, tenantID string) ([]TLSConfigInfo, error)
}

// HSMInventoryClient provides access to HSM slot/key inventory.
type HSMInventoryClient interface {
	// ListHSMKeys returns all keys stored in HSMs.
	ListHSMKeys(ctx context.Context, tenantID string) ([]HSMKeyInfo, error)
}

// KeyInfo represents a key from KeyCore.
type KeyInfo struct {
	ID        string
	Name      string
	Algorithm string
	KeySize   int
	Status    string
	CreatedAt time.Time
	RotatedAt time.Time
	Owner     string
}

// CertInfo represents a certificate from the cert service.
type CertInfo struct {
	ID        string
	Subject   string
	Issuer    string
	Algorithm string
	KeySize   int
	NotBefore time.Time
	NotAfter  time.Time
	Serial    string
	Owner     string
}

// TLSConfigInfo represents a TLS configuration on a service.
type TLSConfigInfo struct {
	ServiceName string
	Host        string
	Port        int
	TLSVersion  string
	CipherSuite string
	CertSubject string
}

// HSMKeyInfo represents a key in an HSM.
type HSMKeyInfo struct {
	SlotID    uint
	Label     string
	Algorithm string
	KeySize   int
	TokenSerial string
}

// InternalSource discovers crypto assets from Vecta KMS internal systems.
type InternalSource struct {
	keyCore  KeyCoreClient
	certs    CertServiceClient
	tls      TLSConfigClient
	hsm      HSMInventoryClient
}

// NewInternalSource creates a new internal discovery source.
func NewInternalSource(keyCore KeyCoreClient, certs CertServiceClient, tls TLSConfigClient, hsm HSMInventoryClient) *InternalSource {
	return &InternalSource{
		keyCore: keyCore,
		certs:   certs,
		tls:     tls,
		hsm:     hsm,
	}
}

// Name returns the source identifier.
func (s *InternalSource) Name() string {
	return "vecta_internal"
}

// Discover scans all internal Vecta KMS systems for cryptographic assets.
func (s *InternalSource) Discover(ctx context.Context, tenantID string) ([]CryptoAsset, error) {
	var assets []CryptoAsset

	// Discover keys from KeyCore
	if s.keyCore != nil {
		keys, err := s.keyCore.ListKeys(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("caim/internal: list keys: %w", err)
		}
		for _, k := range keys {
			assets = append(assets, CryptoAsset{
				TenantID:        tenantID,
				AssetType:       AssetTypeKey,
				Name:            k.Name,
				Location:        Location{Service: "vecta-keycore", Host: "internal"},
				Algorithm:       k.Algorithm,
				KeySize:         k.KeySize,
				CreatedAt:       k.CreatedAt,
				Owner:           k.Owner,
				DiscoverySource: "vecta_internal",
				LastSeen:        time.Now(),
				Metadata: map[string]string{
					"key_id": k.ID,
					"status": k.Status,
				},
			})
		}
	}

	// Discover certificates
	if s.certs != nil {
		certs, err := s.certs.ListCertificates(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("caim/internal: list certs: %w", err)
		}
		for _, c := range certs {
			assets = append(assets, CryptoAsset{
				TenantID:        tenantID,
				AssetType:       AssetTypeCert,
				Name:            c.Subject,
				Location:        Location{Service: "vecta-certs", Host: "internal"},
				Algorithm:       c.Algorithm,
				KeySize:         c.KeySize,
				CreatedAt:       c.NotBefore,
				ExpiresAt:       c.NotAfter,
				Owner:           c.Owner,
				DiscoverySource: "vecta_internal",
				LastSeen:        time.Now(),
				Metadata: map[string]string{
					"cert_id": c.ID,
					"issuer":  c.Issuer,
					"serial":  c.Serial,
				},
			})
		}
	}

	// Discover TLS configurations
	if s.tls != nil {
		configs, err := s.tls.ListTLSConfigs(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("caim/internal: list tls configs: %w", err)
		}
		for _, cfg := range configs {
			assets = append(assets, CryptoAsset{
				TenantID:        tenantID,
				AssetType:       AssetTypeProtocol,
				Name:            cfg.TLSVersion,
				Location:        Location{Service: cfg.ServiceName, Host: cfg.Host},
				Algorithm:       cfg.CipherSuite,
				DiscoverySource: "vecta_internal",
				LastSeen:        time.Now(),
				Metadata: map[string]string{
					"port":         fmt.Sprintf("%d", cfg.Port),
					"cert_subject": cfg.CertSubject,
				},
			})
		}
	}

	// Discover HSM keys
	if s.hsm != nil {
		hsmKeys, err := s.hsm.ListHSMKeys(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("caim/internal: list hsm keys: %w", err)
		}
		for _, hk := range hsmKeys {
			assets = append(assets, CryptoAsset{
				TenantID:        tenantID,
				AssetType:       AssetTypeKey,
				Name:            hk.Label,
				Location:        Location{Service: "hsm", Host: fmt.Sprintf("slot-%d", hk.SlotID)},
				Algorithm:       hk.Algorithm,
				KeySize:         hk.KeySize,
				DiscoverySource: "vecta_internal",
				LastSeen:        time.Now(),
				Metadata: map[string]string{
					"token_serial": hk.TokenSerial,
					"slot_id":      fmt.Sprintf("%d", hk.SlotID),
				},
			})
		}
	}

	return assets, nil
}
