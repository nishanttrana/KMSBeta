package caim

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// CAIMReport is a comprehensive crypto asset inventory report.
type CAIMReport struct {
	TenantID           string                   `json:"tenant_id"`
	GeneratedAt        time.Time                `json:"generated_at"`
	TotalAssets        int                      `json:"total_assets"`
	AssetsByType       map[string]int           `json:"assets_by_type"`
	AlgorithmDist      []AlgorithmEntry         `json:"algorithm_distribution"`
	ExpiringCerts      []ExpiringCert           `json:"expiring_certificates"`
	WeakAlgorithms     []WeakAlgorithmEntry     `json:"weak_algorithms"`
	CompliancePosture  CompliancePosture        `json:"compliance_posture"`
	RiskHeatmap        []RiskHeatmapEntry       `json:"risk_heatmap"`
	TopRiskAssets      []CryptoAsset            `json:"top_risk_assets"`
}

// AlgorithmEntry represents usage count for a specific algorithm (for pie chart).
type AlgorithmEntry struct {
	Algorithm string  `json:"algorithm"`
	Count     int     `json:"count"`
	Percent   float64 `json:"percent"`
}

// ExpiringCert contains details about a certificate approaching expiration.
type ExpiringCert struct {
	AssetID    string    `json:"asset_id"`
	Name       string    `json:"name"`
	ExpiresAt  time.Time `json:"expires_at"`
	DaysLeft   int       `json:"days_left"`
	Location   Location  `json:"location"`
	RiskScore  float64   `json:"risk_score"`
}

// WeakAlgorithmEntry describes an asset using a deprecated or weak algorithm.
type WeakAlgorithmEntry struct {
	AssetID   string   `json:"asset_id"`
	Name      string   `json:"name"`
	Algorithm string   `json:"algorithm"`
	KeySize   int      `json:"key_size"`
	Location  Location `json:"location"`
	Reason    string   `json:"reason"`
}

// CompliancePosture summarizes the overall compliance state.
type CompliancePosture struct {
	TotalAssets    int     `json:"total_assets"`
	Compliant      int     `json:"compliant"`
	NonCompliant   int     `json:"non_compliant"`
	Warning        int     `json:"warning"`
	Unknown        int     `json:"unknown"`
	ComplianceRate float64 `json:"compliance_rate"` // 0.0 - 100.0
}

// RiskHeatmapEntry maps (asset_type, location) to aggregate risk.
type RiskHeatmapEntry struct {
	AssetType    string  `json:"asset_type"`
	LocationKey  string  `json:"location_key"`
	AssetCount   int     `json:"asset_count"`
	AvgRiskScore float64 `json:"avg_risk_score"`
	MaxRiskScore float64 `json:"max_risk_score"`
}

// GenerateCAIMReport produces a full crypto asset inventory report for a tenant.
func GenerateCAIMReport(ctx context.Context, store *SQLStore, tenantID string) (*CAIMReport, error) {
	assets, err := store.ListAssets(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("caim/report: list assets: %w", err)
	}

	report := &CAIMReport{
		TenantID:      tenantID,
		GeneratedAt:   time.Now(),
		TotalAssets:   len(assets),
		AssetsByType:  make(map[string]int),
	}

	algoCounts := make(map[string]int)
	complianceCounts := map[string]int{
		ComplianceCompliant:    0,
		ComplianceNonCompliant: 0,
		ComplianceWarning:      0,
		ComplianceUnknown:      0,
	}
	// Heatmap aggregation: key = "asset_type|location"
	heatmapAgg := make(map[string]*RiskHeatmapEntry)

	now := time.Now()

	for i := range assets {
		a := &assets[i]
		report.AssetsByType[a.AssetType]++
		algoCounts[a.Algorithm]++
		complianceCounts[a.ComplianceStatus]++

		// Expiring certificates (within 90 days)
		if a.AssetType == AssetTypeCert && !a.ExpiresAt.IsZero() {
			daysLeft := int(a.ExpiresAt.Sub(now).Hours() / 24)
			if daysLeft <= 90 {
				report.ExpiringCerts = append(report.ExpiringCerts, ExpiringCert{
					AssetID:   a.ID,
					Name:      a.Name,
					ExpiresAt: a.ExpiresAt,
					DaysLeft:  daysLeft,
					Location:  a.Location,
					RiskScore: a.RiskScore,
				})
			}
		}

		// Weak algorithms
		if reason := weakAlgorithmReason(a); reason != "" {
			report.WeakAlgorithms = append(report.WeakAlgorithms, WeakAlgorithmEntry{
				AssetID:   a.ID,
				Name:      a.Name,
				Algorithm: a.Algorithm,
				KeySize:   a.KeySize,
				Location:  a.Location,
				Reason:    reason,
			})
		}

		// Heatmap aggregation
		locKey := fmt.Sprintf("%s/%s", a.Location.Service, a.Location.Host)
		hmKey := fmt.Sprintf("%s|%s", a.AssetType, locKey)
		if entry, ok := heatmapAgg[hmKey]; ok {
			entry.AssetCount++
			entry.AvgRiskScore += a.RiskScore
			if a.RiskScore > entry.MaxRiskScore {
				entry.MaxRiskScore = a.RiskScore
			}
		} else {
			heatmapAgg[hmKey] = &RiskHeatmapEntry{
				AssetType:    a.AssetType,
				LocationKey:  locKey,
				AssetCount:   1,
				AvgRiskScore: a.RiskScore,
				MaxRiskScore: a.RiskScore,
			}
		}
	}

	// Build algorithm distribution
	for algo, count := range algoCounts {
		pct := 0.0
		if report.TotalAssets > 0 {
			pct = float64(count) / float64(report.TotalAssets) * 100.0
		}
		report.AlgorithmDist = append(report.AlgorithmDist, AlgorithmEntry{
			Algorithm: algo,
			Count:     count,
			Percent:   pct,
		})
	}
	sort.Slice(report.AlgorithmDist, func(i, j int) bool {
		return report.AlgorithmDist[i].Count > report.AlgorithmDist[j].Count
	})

	// Sort expiring certs by days left
	sort.Slice(report.ExpiringCerts, func(i, j int) bool {
		return report.ExpiringCerts[i].DaysLeft < report.ExpiringCerts[j].DaysLeft
	})

	// Compliance posture
	report.CompliancePosture = CompliancePosture{
		TotalAssets:  report.TotalAssets,
		Compliant:    complianceCounts[ComplianceCompliant],
		NonCompliant: complianceCounts[ComplianceNonCompliant],
		Warning:      complianceCounts[ComplianceWarning],
		Unknown:      complianceCounts[ComplianceUnknown],
	}
	if report.TotalAssets > 0 {
		report.CompliancePosture.ComplianceRate = float64(complianceCounts[ComplianceCompliant]) / float64(report.TotalAssets) * 100.0
	}

	// Finalize heatmap
	for _, entry := range heatmapAgg {
		if entry.AssetCount > 0 {
			entry.AvgRiskScore /= float64(entry.AssetCount)
		}
		report.RiskHeatmap = append(report.RiskHeatmap, *entry)
	}
	sort.Slice(report.RiskHeatmap, func(i, j int) bool {
		return report.RiskHeatmap[i].MaxRiskScore > report.RiskHeatmap[j].MaxRiskScore
	})

	// Top 10 riskiest assets
	sort.Slice(assets, func(i, j int) bool {
		return assets[i].RiskScore > assets[j].RiskScore
	})
	limit := 10
	if len(assets) < limit {
		limit = len(assets)
	}
	report.TopRiskAssets = assets[:limit]

	return report, nil
}

// weakAlgorithmReason returns why an algorithm is considered weak, or empty if acceptable.
func weakAlgorithmReason(a *CryptoAsset) string {
	weak := map[string]string{
		"DES":      "DES is obsolete and trivially breakable",
		"3DES":     "3DES has a 64-bit block size vulnerable to Sweet32 attacks",
		"RC4":      "RC4 has known biases and is prohibited by RFC 7465",
		"MD5":      "MD5 is vulnerable to collision attacks",
		"SHA1":     "SHA-1 is deprecated due to practical collision attacks",
		"RSA-1024": "RSA-1024 provides insufficient security margin",
		"DSA-1024": "DSA-1024 provides insufficient security margin",
	}

	if reason, found := weak[a.Algorithm]; found {
		return reason
	}

	// Check key size for RSA
	if a.AssetType == AssetTypeKey && a.Algorithm == "RSA" && a.KeySize < 2048 {
		return fmt.Sprintf("RSA key size %d is below minimum 2048 bits", a.KeySize)
	}

	return ""
}
