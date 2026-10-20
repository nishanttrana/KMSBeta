package main

import (
	"context"
	"encoding/json"
	"time"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type KeyCoreClient interface {
	ListKeys(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
}

type CertsClient interface {
	AllCertificates(ctx context.Context, tenantID string) ([]map[string]interface{}, error)
}

type Store interface {
	CreateScan(ctx context.Context, scan DiscoveryScan) error
	UpdateScan(ctx context.Context, scan DiscoveryScan) error
	GetScan(ctx context.Context, tenantID string, id string) (DiscoveryScan, error)
	ListScans(ctx context.Context, tenantID string, limit int, offset int) ([]DiscoveryScan, error)

	UpsertAsset(ctx context.Context, asset CryptoAsset) error
	GetAsset(ctx context.Context, tenantID string, id string) (CryptoAsset, error)
	DeleteAsset(ctx context.Context, tenantID string, id string) error
	EachAsset(ctx context.Context, tenantID string, fn func(CryptoAsset) error) error

	CreateRepository(ctx context.Context, repo Repository) error
	ListRepositories(ctx context.Context, tenantID string) ([]Repository, error)
	DeleteRepository(ctx context.Context, tenantID string, id string) error

	CreateBucket(ctx context.Context, bucket Bucket) error
	ListBuckets(ctx context.Context, tenantID string) ([]Bucket, error)
	DeleteBucket(ctx context.Context, tenantID string, id string) error
	SaveBucketProgress(ctx context.Context, bucket Bucket) error
	BucketObjects(ctx context.Context, tenantID string, bucketID string) (map[string]BucketObject, error)
	PutBucketObjects(ctx context.Context, objects []BucketObject, at time.Time) error
	PruneBucketObjects(ctx context.Context, tenantID string, bucketID string, before time.Time) error
	TouchAssets(ctx context.Context, tenantID string, ids []string, scanID string, at time.Time) (int, error)

	GetSchedule(ctx context.Context, tenantID string) (Schedule, error)
	PutSchedule(ctx context.Context, sch Schedule) error
	DueSchedules(ctx context.Context, now time.Time) ([]Schedule, error)

	CreateTarget(ctx context.Context, target ScanTarget) error
	ListTargets(ctx context.Context, tenantID string) ([]ScanTarget, error)
	DeleteTarget(ctx context.Context, tenantID string, id string) error
}

// ScanTarget is an endpoint a tenant added for the network scan. Host is a
// DNS name, an IP address or a CIDR range; Protocol is "tls" or "ssh".
type ScanTarget struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// Repository is a git repository a tenant added for the "git" scan source.
// URL is https://host/path with no credential; ConnectionID names the
// sealed git connection for a private one.
type Repository struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	URL          string    `json:"url"`
	Ref          string    `json:"ref"`
	Provider     string    `json:"provider"`
	ConnectionID string    `json:"connection_id"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

// Bucket is an object storage bucket (provider "s3": S3 or a service that
// speaks its API) or Azure Blob container (provider "azure") a tenant added
// for the "storage" scan source. Endpoint is https://host with no
// credential; ConnectionID names the sealed s3 or azure_blob connection for
// a private one.
type Bucket struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	Provider     string `json:"provider"`
	Endpoint     string `json:"endpoint"`
	Name         string `json:"bucket"`
	Prefix       string `json:"prefix"`
	Region       string `json:"region"`
	ConnectionID string `json:"connection_id"`
	// Deep: also read the first kilobyte of every object whose name says
	// nothing, and scan those that hold key material (7.37.0-beta).
	Deep      bool      `json:"deep"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`

	// Scan progress (7.38.0-beta). A pass is one reading of the whole
	// listing; a bucket larger than a run's budget takes several scans.
	// Cursor is where the pass in progress continues ("" between passes).
	Cursor            string    `json:"-"`
	PassStartedAt     time.Time `json:"-"`
	PassObjects       int       `json:"pass_objects"` // listed so far in the pass in progress
	LastPassStartedAt time.Time `json:"-"`
	LastPassAt        time.Time `json:"last_pass_at,omitempty"` // when the last complete pass ended
	LastPassObjects   int       `json:"last_pass_objects"`
	ScannedAt         time.Time `json:"scanned_at,omitempty"`
	// PassInProgress: a pass has started and not reached the end of the
	// listing; the next scan continues it.
	PassInProgress bool `json:"pass_in_progress"`
}

// MarshalJSON leaves out the times that have not happened yet (a zero
// time.Time is not "empty" to encoding/json and would read as year 1).
func (b Bucket) MarshalJSON() ([]byte, error) {
	type plain Bucket
	opt := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		return &t
	}
	return json.Marshal(struct {
		plain
		LastPassAt *time.Time `json:"last_pass_at,omitempty"`
		ScannedAt  *time.Time `json:"scanned_at,omitempty"`
	}{plain(b), opt(b.LastPassAt), opt(b.ScannedAt)})
}

// BucketObject records an object the scan read: its ETag when read, and the
// assets found in it. An object listed again with the same ETag is not read
// again; its assets are marked seen.
type BucketObject struct {
	TenantID string
	BucketID string
	Key      string
	ETag     string
	Size     int64
	AssetIDs []string
	Rules    int // the parser's rule set when read (scanRules)
	// Consts are the constants the object defines for other objects to
	// read; Needs the constant names it reads and does not define; and
	// NeedsHash what those stood for when it was read (usage_unit.go).
	Consts    map[string][]string
	Needs     []string
	NeedsHash string
}

// Schedule runs a tenant's scan every IntervalHours on the authority of the
// user who saved it.
type Schedule struct {
	TenantID      string    `json:"tenant_id"`
	Enabled       bool      `json:"enabled"`
	IntervalHours int       `json:"interval_hours"`
	Sources       []string  `json:"sources"`
	AuthorizedBy  string    `json:"authorized_by"`
	NextRunAt     time.Time `json:"next_run_at"`
	LastRunAt     time.Time `json:"last_run_at"`
	LastScanID    string    `json:"last_scan_id"`
	PausedReason  string    `json:"paused_reason"`
	UpdatedAt     time.Time `json:"updated_at"`
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
	// The breakdowns the dashboard charts (7.18.0-beta). Each count equals
	// the total GET /discovery/assets returns for the same filter.
	AlgorithmClasses     map[string]map[string]int `json:"algorithm_classes"`
	SourceClassification map[string]map[string]int `json:"source_classification"`
	// Expiring30: assets whose not_after has passed or falls within 30 days.
	Expiring30 int `json:"expiring_30d"`
}

// AssetFilter selects assets. The summary counts with the same predicate
// the list filters with, so a count and its list always agree.
type AssetFilter struct {
	Source, AssetType, Query string
	Classes                  []string // any of these classes
	Algorithm                *string  // exact match; "" is the assets with no algorithm
	PQCReady                 bool
	ExpiringDays             int  // not_after passed or within this many days
	NotSeen                  bool // not observed by its source's last scan
}

// SourceStatus says whether a scan source has anything to read, and how its
// last scan went (GET /discovery/sources).
type SourceStatus struct {
	ID         string                 `json:"id"`
	Configured bool                   `json:"configured"`
	Detail     map[string]interface{} `json:"detail"`
	Error      string                 `json:"error,omitempty"`
	LastScan   *SourceLastScan        `json:"last_scan,omitempty"`
}

type SourceLastScan struct {
	ScanID string `json:"scan_id"`
	// An asset of this source last seen before StartedAt wasn't observed by
	// the last scan.
	StartedAt time.Time `json:"started_at"`
	At        time.Time `json:"at"`
	Assets    int       `json:"assets"`
	Error     string    `json:"error,omitempty"`
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
