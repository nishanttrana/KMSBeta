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
	ListInterfacePorts(ctx context.Context, tenantID string) ([]map[string]interface{}, error)
	RotateKey(ctx context.Context, tenantID string, keyID string, reason string) error
}

type DiscoveryClient interface {
	ListCryptoAssets(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
}

type CertsClient interface {
	ListCertificates(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
}

type Store interface {
	CreateReadinessScan(ctx context.Context, item ReadinessScan) error
	GetReadinessScan(ctx context.Context, tenantID string, id string) (ReadinessScan, error)
	GetLatestReadinessScan(ctx context.Context, tenantID string) (ReadinessScan, error)
	ListReadinessScans(ctx context.Context, tenantID string, limit int, offset int) ([]ReadinessScan, error)

	GetPolicy(ctx context.Context, tenantID string) (PQCPolicy, error)
	UpsertPolicy(ctx context.Context, item PQCPolicy) (PQCPolicy, error)

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

type PQCPolicy struct {
	TenantID               string    `json:"tenant_id"`
	ProfileID              string    `json:"profile_id"`
	DefaultKEM             string    `json:"default_kem"`
	DefaultSignature       string    `json:"default_signature"`
	InterfaceDefaultMode   string    `json:"interface_default_mode"`
	CertificateDefaultMode string    `json:"certificate_default_mode"`
	HQCBackupEnabled       bool      `json:"hqc_backup_enabled"`
	FlagClassicalUsage     bool      `json:"flag_classical_usage"`
	FlagClassicalCerts     bool      `json:"flag_classical_certificates"`
	FlagNonMigratedIfaces  bool      `json:"flag_non_migrated_interfaces"`
	RequirePQCForNewKeys   bool      `json:"require_pqc_for_new_keys"`
	UpdatedBy              string    `json:"updated_by,omitempty"`
	UpdatedAt              time.Time `json:"updated_at,omitempty"`
}

type InventoryBreakdown struct {
	Total      int            `json:"total"`
	Classical  int            `json:"classical"`
	Hybrid     int            `json:"hybrid"`
	PQCOnly    int            `json:"pqc_only"`
	Algorithms map[string]int `json:"algorithms,omitempty"`
}

type ClassicalUsageItem struct {
	AssetType string  `json:"asset_type"`
	AssetID   string  `json:"asset_id"`
	Name      string  `json:"name"`
	Algorithm string  `json:"algorithm"`
	Location  string  `json:"location"`
	QSLScore  float64 `json:"qsl_score"`
	Reason    string  `json:"reason"`
}

type InterfacePQCItem struct {
	InterfaceName    string `json:"interface_name"`
	Description      string `json:"description"`
	BindAddress      string `json:"bind_address"`
	Port             int    `json:"port"`
	Protocol         string `json:"protocol"`
	PQCMode          string `json:"pqc_mode"`
	EffectivePQCMode string `json:"effective_pqc_mode"`
	Enabled          bool   `json:"enabled"`
	Status           string `json:"status"`
	CertSource       string `json:"certificate_source"`
	CAID             string `json:"ca_id,omitempty"`
	CertificateID    string `json:"certificate_id,omitempty"`
}

type CertificatePQCItem struct {
	CertID         string `json:"cert_id"`
	SubjectCN      string `json:"subject_cn"`
	Algorithm      string `json:"algorithm"`
	CertClass      string `json:"cert_class"`
	Status         string `json:"status"`
	NotAfter       string `json:"not_after,omitempty"`
	MigrationState string `json:"migration_state"`
}

type PQCInventory struct {
	TenantID                string               `json:"tenant_id"`
	GeneratedAt             time.Time            `json:"generated_at"`
	Policy                  PQCPolicy            `json:"policy"`
	ReadinessScore          int                  `json:"readiness_score"`
	QuantumReadinessPercent float64              `json:"quantum_readiness_percent"`
	Keys                    InventoryBreakdown   `json:"keys"`
	Certificates            InventoryBreakdown   `json:"certificates"`
	Interfaces              InventoryBreakdown   `json:"interfaces"`
	ClassicalUsage          []ClassicalUsageItem `json:"classical_usage"`
	NonMigratedInterfaces   []InterfacePQCItem   `json:"non_migrated_interfaces"`
	NonMigratedCertificates []CertificatePQCItem `json:"non_migrated_certificates"`
	Recommendations         []string             `json:"recommendations"`
}

type PQCMigrationReport struct {
	TenantID        string              `json:"tenant_id"`
	GeneratedAt     time.Time           `json:"generated_at"`
	Policy          PQCPolicy           `json:"policy"`
	Inventory       PQCInventory        `json:"inventory"`
	LatestReadiness ReadinessScan       `json:"latest_readiness"`
	Timeline        []TimelineMilestone `json:"timeline"`
	TopRisks        []AssetRisk         `json:"top_risks"`
	NextActions     []string            `json:"next_actions"`
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
