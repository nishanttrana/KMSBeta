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

type Store interface {
	CreateScan(ctx context.Context, scan DiscoveryScan) error
	UpdateScan(ctx context.Context, scan DiscoveryScan) error
	GetScan(ctx context.Context, tenantID string, id string) (DiscoveryScan, error)
	ListScans(ctx context.Context, tenantID string, limit int, offset int) ([]DiscoveryScan, error)

	UpsertAsset(ctx context.Context, asset CryptoAsset) error
	GetAsset(ctx context.Context, tenantID string, id string) (CryptoAsset, error)
	ListAssets(ctx context.Context, tenantID string, limit int, offset int, source string, assetType string, classification string) ([]CryptoAsset, error)
	CountAssets(ctx context.Context, tenantID string) (int, error)

	// Lineage / source traceability
	InsertLineageEvent(ctx context.Context, e LineageEvent) (LineageEvent, error)
	GetLineageByKey(ctx context.Context, tenantID, keyID string, limit int) ([]LineageEvent, error)
	GetLineageGraph(ctx context.Context, tenantID string, since time.Time, limit int) ([]LineageEvent, error)
}

type DiscoveryScan struct {
	ID          string                 `json:"id"`
	TenantID    string                 `json:"tenant_id"`
	ScanType    string                 `json:"scan_type"`
	Status      string                 `json:"status"`
	Trigger     string                 `json:"trigger"`
	Stats       map[string]interface{} `json:"stats"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt time.Time              `json:"completed_at,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

type CryptoAsset struct {
	ID             string                 `json:"id"`
	TenantID       string                 `json:"tenant_id"`
	ScanID         string                 `json:"scan_id"`
	AssetType      string                 `json:"asset_type"`
	Name           string                 `json:"name"`
	Location       string                 `json:"location"`
	Source         string                 `json:"source"`
	Algorithm      string                 `json:"algorithm"`
	StrengthBits   int                    `json:"strength_bits"`
	Status         string                 `json:"status"`
	Classification string                 `json:"classification"`
	PQCReady       bool                   `json:"pqc_ready"`
	QSLScore       float64                `json:"qsl_score"`
	Metadata       map[string]interface{} `json:"metadata"`
	FirstSeen      time.Time              `json:"first_seen"`
	LastSeen       time.Time              `json:"last_seen"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

type DiscoverySummary struct {
	TenantID              string         `json:"tenant_id"`
	TotalAssets           int            `json:"total_assets"`
	SourceDistribution    map[string]int `json:"source_distribution"`
	AlgorithmDistribution map[string]int `json:"algorithm_distribution"`
	ClassificationCounts  map[string]int `json:"classification_counts"`
	PQCReadyCount         int            `json:"pqc_ready_count"`
	PQCReadinessPercent   float64        `json:"pqc_readiness_percent"`
	AverageQSL            float64        `json:"average_qsl"`
	PostureScore          int            `json:"posture_score"`
}

type ScanRequest struct {
	TenantID  string   `json:"tenant_id"`
	ScanTypes []string `json:"scan_types"`
	Trigger   string   `json:"trigger"`
}

type ClassifyRequest struct {
	TenantID       string `json:"tenant_id"`
	Classification string `json:"classification"`
	Status         string `json:"status"`
	Notes          string `json:"notes"`
}
