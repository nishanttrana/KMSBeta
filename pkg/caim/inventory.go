package caim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"
)

// AssetType enumerates the types of cryptographic assets.
const (
	AssetTypeKey       = "key"
	AssetTypeCert      = "cert"
	AssetTypeAlgorithm = "algorithm"
	AssetTypeLibrary   = "library"
	AssetTypeProtocol  = "protocol"
)

// ComplianceStatus values.
const (
	ComplianceCompliant    = "compliant"
	ComplianceNonCompliant = "non_compliant"
	ComplianceUnknown      = "unknown"
	ComplianceWarning      = "warning"
)

// CryptoAsset represents a single cryptographic asset discovered in the environment.
type CryptoAsset struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	AssetType        string    `json:"asset_type"` // key, cert, algorithm, library, protocol
	Name             string    `json:"name"`
	Location         Location  `json:"location"`
	Algorithm        string    `json:"algorithm"`
	KeySize          int       `json:"key_size"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
	Owner            string    `json:"owner"`
	ComplianceStatus string    `json:"compliance_status"`
	RiskScore        float64   `json:"risk_score"` // 0.0 - 10.0
	DiscoverySource  string    `json:"discovery_source"`
	LastSeen         time.Time `json:"last_seen"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// Location identifies where a crypto asset resides.
type Location struct {
	Service string `json:"service"`
	Host    string `json:"host"`
	Cloud   string `json:"cloud,omitempty"`
	Path    string `json:"path,omitempty"`
}

// DiscoverySource is implemented by any component that can discover crypto assets.
type DiscoverySource interface {
	// Name returns the source identifier.
	Name() string
	// Discover scans for cryptographic assets belonging to the given tenant.
	Discover(ctx context.Context, tenantID string) ([]CryptoAsset, error)
}

// DiscoveryReport summarizes the results of a discovery run.
type DiscoveryReport struct {
	TenantID     string         `json:"tenant_id"`
	RunID        string         `json:"run_id"`
	StartedAt    time.Time      `json:"started_at"`
	CompletedAt  time.Time      `json:"completed_at"`
	TotalFound   int            `json:"total_found"`
	NewAssets    int            `json:"new_assets"`
	Updated      int            `json:"updated"`
	Removed      int            `json:"removed"`
	ByType       map[string]int `json:"by_type"`
	ByAlgorithm  map[string]int `json:"by_algorithm"`
	ByCompliance map[string]int `json:"by_compliance"`
	Errors       []string       `json:"errors,omitempty"`
}

// Inventory manages the discovery and tracking of cryptographic assets.
type Inventory struct {
	sources []DiscoverySource
	store   *SQLStore
	logf    func(string, ...interface{})
}

// NewInventory creates a new crypto asset inventory manager.
func NewInventory(store *SQLStore, logf func(string, ...interface{})) *Inventory {
	if logf == nil {
		logf = log.Printf
	}
	return &Inventory{
		store: store,
		logf:  logf,
	}
}

// RegisterSource adds a discovery source.
func (inv *Inventory) RegisterSource(src DiscoverySource) {
	inv.sources = append(inv.sources, src)
}

// RunDiscovery executes all registered discovery sources, deduplicates results, and stores them.
func (inv *Inventory) RunDiscovery(ctx context.Context, tenantID string) (*DiscoveryReport, error) {
	report := &DiscoveryReport{
		TenantID:     tenantID,
		RunID:        generateID(),
		StartedAt:    time.Now(),
		ByType:       make(map[string]int),
		ByAlgorithm:  make(map[string]int),
		ByCompliance: make(map[string]int),
	}

	// Collect assets from all sources
	var allAssets []CryptoAsset
	for _, src := range inv.sources {
		inv.logf("[caim] running discovery source: %s", src.Name())
		assets, err := src.Discover(ctx, tenantID)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", src.Name(), err))
			inv.logf("[caim] discovery source %s failed: %v", src.Name(), err)
			continue
		}
		inv.logf("[caim] source %s found %d assets", src.Name(), len(assets))
		allAssets = append(allAssets, assets...)
	}

	// Deduplicate by (tenant_id, asset_type, name, location)
	deduped := deduplicateAssets(allAssets)
	report.TotalFound = len(deduped)

	// Classify compliance and compute risk for each asset
	for i := range deduped {
		classifyCompliance(&deduped[i])
		computeRiskScore(&deduped[i])
	}

	// Get existing assets to determine new vs updated vs removed
	existing, err := inv.store.ListAssets(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("caim: list existing assets: %w", err)
	}
	existingMap := make(map[string]*CryptoAsset, len(existing))
	for i := range existing {
		key := assetDedupeKey(&existing[i])
		existingMap[key] = &existing[i]
	}

	// Upsert discovered assets
	now := time.Now()
	seenKeys := make(map[string]bool)
	for i := range deduped {
		asset := &deduped[i]
		asset.TenantID = tenantID
		asset.LastSeen = now

		key := assetDedupeKey(asset)
		seenKeys[key] = true

		if ex, found := existingMap[key]; found {
			asset.ID = ex.ID
			if err := inv.store.UpdateAsset(ctx, asset); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("update %s: %v", asset.Name, err))
				continue
			}
			report.Updated++
		} else {
			if asset.ID == "" {
				asset.ID = generateID()
			}
			if err := inv.store.CreateAsset(ctx, asset); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("create %s: %v", asset.Name, err))
				continue
			}
			report.NewAssets++
		}

		// Aggregate stats
		report.ByType[asset.AssetType]++
		report.ByAlgorithm[asset.Algorithm]++
		report.ByCompliance[asset.ComplianceStatus]++
	}

	// Mark assets not seen in this run as removed
	for key, ex := range existingMap {
		if !seenKeys[key] {
			if err := inv.store.MarkAssetRemoved(ctx, ex.ID); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("remove %s: %v", ex.Name, err))
				continue
			}
			report.Removed++
		}
	}

	report.CompletedAt = time.Now()
	return report, nil
}

// deduplicateAssets merges duplicate entries, preferring the most recent LastSeen.
func deduplicateAssets(assets []CryptoAsset) []CryptoAsset {
	seen := make(map[string]int) // key -> index in result
	var result []CryptoAsset

	for _, a := range assets {
		key := assetDedupeKey(&a)
		if idx, exists := seen[key]; exists {
			// Keep the one with the later LastSeen
			if a.LastSeen.After(result[idx].LastSeen) {
				result[idx] = a
			}
		} else {
			seen[key] = len(result)
			result = append(result, a)
		}
	}
	return result
}

func assetDedupeKey(a *CryptoAsset) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s", a.TenantID, a.AssetType, a.Name, a.Location.Host, a.Location.Service)
}

// classifyCompliance evaluates the compliance status of an asset.
func classifyCompliance(a *CryptoAsset) {
	// Weak algorithms
	weakAlgos := map[string]bool{
		"DES": true, "3DES": true, "RC4": true, "MD5": true, "SHA1": true,
		"RSA-1024": true, "DSA-1024": true,
	}
	algoUpper := strings.ToUpper(a.Algorithm)
	if weakAlgos[algoUpper] {
		a.ComplianceStatus = ComplianceNonCompliant
		return
	}

	// Insufficient key sizes
	if a.AssetType == AssetTypeKey {
		switch {
		case strings.Contains(algoUpper, "RSA") && a.KeySize < 2048:
			a.ComplianceStatus = ComplianceNonCompliant
			return
		case strings.Contains(algoUpper, "EC") && a.KeySize < 256:
			a.ComplianceStatus = ComplianceNonCompliant
			return
		case strings.Contains(algoUpper, "AES") && a.KeySize < 128:
			a.ComplianceStatus = ComplianceNonCompliant
			return
		}
	}

	// Expired certificates
	if a.AssetType == AssetTypeCert && !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(time.Now()) {
		a.ComplianceStatus = ComplianceNonCompliant
		return
	}

	// Certificates expiring within 30 days
	if a.AssetType == AssetTypeCert && !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(time.Now().Add(30*24*time.Hour)) {
		a.ComplianceStatus = ComplianceWarning
		return
	}

	// Deprecated TLS versions
	if a.AssetType == AssetTypeProtocol {
		deprecated := map[string]bool{"TLS 1.0": true, "TLS 1.1": true, "SSL 3.0": true, "SSL 2.0": true}
		if deprecated[a.Name] {
			a.ComplianceStatus = ComplianceNonCompliant
			return
		}
	}

	a.ComplianceStatus = ComplianceCompliant
}

// computeRiskScore assigns a 0-10 risk score based on asset properties.
func computeRiskScore(a *CryptoAsset) {
	score := 0.0

	// Weak algorithm penalty
	weakAlgos := map[string]float64{
		"DES": 9.0, "3DES": 6.0, "RC4": 8.0, "MD5": 7.0, "SHA1": 5.0,
	}
	if penalty, found := weakAlgos[strings.ToUpper(a.Algorithm)]; found {
		score += penalty
	}

	// Small key size penalty
	if a.AssetType == AssetTypeKey && a.KeySize > 0 {
		if strings.Contains(strings.ToUpper(a.Algorithm), "RSA") {
			switch {
			case a.KeySize < 2048:
				score += 8.0
			case a.KeySize < 3072:
				score += 3.0
			case a.KeySize < 4096:
				score += 1.0
			}
		}
	}

	// Expiry penalty for certificates
	if a.AssetType == AssetTypeCert && !a.ExpiresAt.IsZero() {
		daysUntilExpiry := time.Until(a.ExpiresAt).Hours() / 24
		switch {
		case daysUntilExpiry < 0:
			score += 10.0 // already expired
		case daysUntilExpiry < 7:
			score += 8.0
		case daysUntilExpiry < 30:
			score += 5.0
		case daysUntilExpiry < 90:
			score += 2.0
		}
	}

	// Cap at 10.0
	if score > 10.0 {
		score = 10.0
	}
	a.RiskScore = score
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
