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
	RotateKey(ctx context.Context, tenantID string, keyID string, reason string) error
}

type DiscoveryClient interface {
	ListCryptoAssets(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
}

type Store interface {
	CreateReadinessScan(ctx context.Context, item ReadinessScan) error
	GetReadinessScan(ctx context.Context, tenantID string, id string) (ReadinessScan, error)
	GetLatestReadinessScan(ctx context.Context, tenantID string) (ReadinessScan, error)
	ListReadinessScans(ctx context.Context, tenantID string, limit int, offset int) ([]ReadinessScan, error)

	CreateMigrationPlan(ctx context.Context, item MigrationPlan) error
	UpdateMigrationPlan(ctx context.Context, item MigrationPlan) error
	GetMigrationPlan(ctx context.Context, tenantID string, id string) (MigrationPlan, error)
	ListMigrationPlans(ctx context.Context, tenantID string, limit int, offset int) ([]MigrationPlan, error)

	CreateMigrationRun(ctx context.Context, item MigrationRun) error
	UpdateMigrationRun(ctx context.Context, item MigrationRun) error
	ListMigrationRuns(ctx context.Context, tenantID string, planID string) ([]MigrationRun, error)
}

type AssetRisk struct {
	AssetID         string  `json:"asset_id"`
	AssetType       string  `json:"asset_type"`
	Name            string  `json:"name"`
	Source          string  `json:"source"`
	Algorithm       string  `json:"algorithm"`
	Classification  string  `json:"classification"`
	QSLScore        float64 `json:"qsl_score"`
	MigrationTarget string  `json:"migration_target"`
	Priority        int     `json:"priority"`
	Reason          string  `json:"reason"`
}

type ReadinessScan struct {
	ID               string                 `json:"id"`
	TenantID         string                 `json:"tenant_id"`
	Status           string                 `json:"status"`
	TotalAssets      int                    `json:"total_assets"`
	PQCReadyAssets   int                    `json:"pqc_ready_assets"`
	HybridAssets     int                    `json:"hybrid_assets"`
	ClassicalAssets  int                    `json:"classical_assets"`
	AverageQSL       float64                `json:"average_qsl"`
	ReadinessScore   int                    `json:"readiness_score"`
	AlgorithmSummary map[string]int         `json:"algorithm_summary"`
	TimelineStatus   map[string]interface{} `json:"timeline_status"`
	RiskItems        []AssetRisk            `json:"risk_items"`
	Metadata         map[string]interface{} `json:"metadata"`
	CreatedAt        time.Time              `json:"created_at"`
	CompletedAt      time.Time              `json:"completed_at"`
}

type MigrationStep struct {
	ID           string                 `json:"id"`
	AssetID      string                 `json:"asset_id"`
	AssetType    string                 `json:"asset_type"`
	Name         string                 `json:"name"`
	CurrentAlg   string                 `json:"current_algorithm"`
	TargetAlg    string                 `json:"target_algorithm"`
	Phase        string                 `json:"phase"`
	Priority     int                    `json:"priority"`
	Status       string                 `json:"status"`
	Reason       string                 `json:"reason"`
	Metadata     map[string]interface{} `json:"metadata"`
	ExecutedAt   time.Time              `json:"executed_at,omitempty"`
	RolledBackAt time.Time              `json:"rolled_back_at,omitempty"`
}

type MigrationPlan struct {
	ID               string                 `json:"id"`
	TenantID         string                 `json:"tenant_id"`
	Name             string                 `json:"name"`
	Status           string                 `json:"status"`
	TargetProfile    string                 `json:"target_profile"`
	TimelineStandard string                 `json:"timeline_standard"`
	Deadline         time.Time              `json:"deadline"`
	Summary          map[string]interface{} `json:"summary"`
	Steps            []MigrationStep        `json:"steps"`
	CreatedBy        string                 `json:"created_by"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
	ExecutedAt       time.Time              `json:"executed_at,omitempty"`
}

type MigrationRun struct {
	ID          string                 `json:"id"`
	TenantID    string                 `json:"tenant_id"`
	PlanID      string                 `json:"plan_id"`
	Status      string                 `json:"status"`
	DryRun      bool                   `json:"dry_run"`
	Summary     map[string]interface{} `json:"summary"`
	CreatedAt   time.Time              `json:"created_at"`
	CompletedAt time.Time              `json:"completed_at"`
}

type TimelineMilestone struct {
	ID          string    `json:"id"`
	Standard    string    `json:"standard"`
	Title       string    `json:"title"`
	DueDate     time.Time `json:"due_date"`
	Status      string    `json:"status"`
	DaysLeft    int       `json:"days_left"`
	Description string    `json:"description"`
}

type ScanRequest struct {
	TenantID string `json:"tenant_id"`
	Trigger  string `json:"trigger"`
}

type PlanRequest struct {
	TenantID         string `json:"tenant_id"`
	Name             string `json:"name"`
	TargetProfile    string `json:"target_profile"`
	TimelineStandard string `json:"timeline_standard"`
	Deadline         string `json:"deadline"`
	CreatedBy        string `json:"created_by"`
}

type ExecuteRequest struct {
	TenantID string `json:"tenant_id"`
	DryRun   bool   `json:"dry_run"`
	Actor    string `json:"actor"`
}

type RollbackRequest struct {
	TenantID string `json:"tenant_id"`
	Actor    string `json:"actor"`
}
