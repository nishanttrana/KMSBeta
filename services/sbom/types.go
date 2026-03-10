package main

import (
	"context"
	"time"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type KeyCoreClient interface {
	ListKeys(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
}

type CertsClient interface {
	ListCertificates(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
}

type DiscoveryClient interface {
	ListCryptoAssets(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
}

type SchedulerConfig struct {
	SBOMMode string
	CBOMMode string
	Tenants  []string
}

type BOMComponent struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Type      string            `json:"type"`
	PURL      string            `json:"purl"`
	Supplier  string            `json:"supplier"`
	Licenses  []string          `json:"licenses"`
	Hashes    map[string]string `json:"hashes"`
	Metadata  map[string]string `json:"metadata"`
	Ecosystem string            `json:"ecosystem"`
}

type SBOMDocument struct {
	Format      string         `json:"format"`
	SpecVersion string         `json:"spec_version"`
	GeneratedAt time.Time      `json:"generated_at"`
	Appliance   string         `json:"appliance"`
	Components  []BOMComponent `json:"components"`
}

type SBOMSnapshot struct {
	ID         string                 `json:"id"`
	SourceHash string                 `json:"source_hash"`
	CreatedAt  time.Time              `json:"created_at"`
	Document   SBOMDocument           `json:"document"`
	Summary    map[string]interface{} `json:"summary"`
}

type VulnerabilityMatch struct {
	ID               string `json:"id"`
	Source           string `json:"source"`
	Severity         string `json:"severity"`
	Component        string `json:"component"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"`
	Summary          string `json:"summary"`
	Reference        string `json:"reference"`
}

type ManualAdvisory struct {
	ID                string    `json:"id"`
	Component         string    `json:"component"`
	Ecosystem         string    `json:"ecosystem"`
	IntroducedVersion string    `json:"introduced_version"`
	FixedVersion      string    `json:"fixed_version"`
	Severity          string    `json:"severity"`
	Summary           string    `json:"summary"`
	Reference         string    `json:"reference"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type CryptoAsset struct {
	ID           string                 `json:"id"`
	TenantID     string                 `json:"tenant_id"`
	Source       string                 `json:"source"`
	AssetType    string                 `json:"asset_type"`
	Name         string                 `json:"name"`
	Algorithm    string                 `json:"algorithm"`
	StrengthBits int                    `json:"strength_bits"`
	Status       string                 `json:"status"`
	PQCReady     bool                   `json:"pqc_ready"`
	Deprecated   bool                   `json:"deprecated"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type CBOMDocument struct {
	Format                string            `json:"format"`
	SpecVersion           string            `json:"spec_version"`
	TenantID              string            `json:"tenant_id"`
	GeneratedAt           time.Time         `json:"generated_at"`
	Assets                []CryptoAsset     `json:"assets"`
	AlgorithmDistribution map[string]int    `json:"algorithm_distribution"`
	StrengthHistogram     map[string]int    `json:"strength_histogram"`
	DeprecatedCount       int               `json:"deprecated_count"`
	PQCReadyCount         int               `json:"pqc_ready_count"`
	TotalAssetCount       int               `json:"total_asset_count"`
	PQCReadinessPercent   float64           `json:"pqc_readiness_percent"`
	SourceCount           map[string]int    `json:"source_count"`
	Metadata              map[string]string `json:"metadata"`
}

type CBOMSnapshot struct {
	ID         string                 `json:"id"`
	TenantID   string                 `json:"tenant_id"`
	SourceHash string                 `json:"source_hash"`
	CreatedAt  time.Time              `json:"created_at"`
	Document   CBOMDocument           `json:"document"`
	Summary    map[string]interface{} `json:"summary"`
}

type BOMDiff struct {
	FromID   string                   `json:"from_id"`
	ToID     string                   `json:"to_id"`
	Added    []map[string]interface{} `json:"added"`
	Removed  []map[string]interface{} `json:"removed"`
	Changed  []map[string]interface{} `json:"changed"`
	Metrics  map[string]interface{}   `json:"metrics"`
	Compared time.Time                `json:"compared_at"`
}

type ExportArtifact struct {
	Format      string `json:"format"`
	ContentType string `json:"content_type"`
	Encoding    string `json:"encoding"`
	Content     string `json:"content"`
}
