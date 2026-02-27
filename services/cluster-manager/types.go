package main

import (
	"context"
	"time"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Store interface {
	ListProfiles(ctx context.Context, tenantID string) ([]ClusterProfile, error)
	GetProfile(ctx context.Context, tenantID string, profileID string) (ClusterProfile, error)
	UpsertProfile(ctx context.Context, item ClusterProfile) error
	SetDefaultProfile(ctx context.Context, tenantID string, profileID string) error
	DeleteProfile(ctx context.Context, tenantID string, profileID string) error

	ListNodes(ctx context.Context, tenantID string) ([]ClusterNode, error)
	GetNode(ctx context.Context, tenantID string, nodeID string) (ClusterNode, error)
	UpsertNode(ctx context.Context, item ClusterNode) error

	CreateJoinToken(ctx context.Context, token ClusterJoinToken) error
	GetJoinToken(ctx context.Context, tenantID string, tokenID string) (ClusterJoinToken, error)
	MarkJoinTokenConsumed(ctx context.Context, tenantID string, tokenID string, consumedAt time.Time) error
	PurgeExpiredJoinTokens(ctx context.Context, now time.Time) error

	CreateSyncEvent(ctx context.Context, event ClusterSyncEvent) (ClusterSyncEvent, error)
	ListSyncEvents(ctx context.Context, tenantID string, profileID string, afterID int64, limit int, components []string) ([]ClusterSyncEvent, error)
	UpsertSyncCheckpoint(ctx context.Context, checkpoint ClusterSyncCheckpoint) error
	GetSyncCheckpoint(ctx context.Context, tenantID string, nodeID string, profileID string) (ClusterSyncCheckpoint, error)
	ConsumeSyncNonce(ctx context.Context, tenantID string, sourceNodeID string, nonce string, expiresAt time.Time) (bool, error)
	AppendClusterLog(ctx context.Context, entry ClusterLogEntry) error
	ListClusterLogs(ctx context.Context, tenantID string, nodeID string, eventType string, limit int) ([]ClusterLogEntry, error)
}

type ClusterProfile struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Components  []string  `json:"components"`
	IsDefault   bool      `json:"is_default"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ClusterNode struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	Name              string    `json:"name"`
	Role              string    `json:"role"`
	Endpoint          string    `json:"endpoint"`
	Status            string    `json:"status"`
	CPUPercent        float64   `json:"cpu_percent"`
	RAMGB             float64   `json:"ram_gb"`
	EnabledComponents []string  `json:"enabled_components"`
	ProfileID         string    `json:"profile_id"`
	JoinState         string    `json:"join_state"`
	CertFingerprint   string    `json:"cert_fingerprint"`
	LastHeartbeatAt   time.Time `json:"last_heartbeat_at"`
	LastSyncAt        time.Time `json:"last_sync_at"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type ClusterJoinToken struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	TargetNodeID  string    `json:"target_node_id"`
	TargetNode    string    `json:"target_node_name"`
	Endpoint      string    `json:"endpoint"`
	ProfileID     string    `json:"profile_id"`
	SecretHash    string    `json:"-"`
	Nonce         string    `json:"nonce"`
	RequestedBy   string    `json:"requested_by"`
	ExpiresAt     time.Time `json:"expires_at"`
	ConsumedAt    time.Time `json:"consumed_at"`
	CreatedAt     time.Time `json:"created_at"`
	IssuedSecret  string    `json:"issued_secret,omitempty"`
	ProfileName   string    `json:"profile_name,omitempty"`
	ProfileScopes []string  `json:"profile_components,omitempty"`
}

type ClusterSyncEvent struct {
	ID           int64                  `json:"id"`
	TenantID     string                 `json:"tenant_id"`
	ProfileID    string                 `json:"profile_id"`
	Component    string                 `json:"component"`
	EntityType   string                 `json:"entity_type"`
	EntityID     string                 `json:"entity_id"`
	Operation    string                 `json:"operation"`
	Payload      map[string]interface{} `json:"payload"`
	SourceNodeID string                 `json:"source_node_id"`
	CreatedAt    time.Time              `json:"created_at"`
}

type ClusterSyncCheckpoint struct {
	TenantID    string    `json:"tenant_id"`
	NodeID      string    `json:"node_id"`
	ProfileID   string    `json:"profile_id"`
	LastEventID int64     `json:"last_event_id"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ClusterLogEntry struct {
	ID        int64                  `json:"id"`
	TenantID  string                 `json:"tenant_id"`
	NodeID    string                 `json:"node_id"`
	Level     string                 `json:"level"`
	EventType string                 `json:"event_type"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details"`
	CreatedAt time.Time              `json:"created_at"`
}

type ClusterOverview struct {
	Nodes    []ClusterNode    `json:"nodes"`
	Profiles []ClusterProfile `json:"profiles"`
	Summary  struct {
		LeaderNodeID  string `json:"leader_node_id"`
		TotalNodes    int    `json:"total_nodes"`
		OnlineNodes   int    `json:"online_nodes"`
		DegradedNodes int    `json:"degraded_nodes"`
		DownNodes     int    `json:"down_nodes"`
	} `json:"summary"`
	SelectiveComponentSync struct {
		Enabled bool   `json:"enabled"`
		Note    string `json:"note"`
	} `json:"selective_component_sync"`
}

type UpsertProfileInput struct {
	TenantID    string   `json:"tenant_id"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Components  []string `json:"components"`
	IsDefault   bool     `json:"is_default"`
}

type CreateJoinTokenInput struct {
	TenantID       string `json:"tenant_id"`
	TargetNodeID   string `json:"target_node_id"`
	TargetNodeName string `json:"target_node_name"`
	Endpoint       string `json:"endpoint"`
	ProfileID      string `json:"profile_id"`
	RequestedBy    string `json:"requested_by"`
	ExpiresMinutes int    `json:"expires_minutes"`
}

type CompleteJoinInput struct {
	TenantID        string   `json:"tenant_id"`
	TokenID         string   `json:"token_id"`
	JoinSecret      string   `json:"join_secret"`
	NodeID          string   `json:"node_id"`
	NodeName        string   `json:"node_name"`
	Endpoint        string   `json:"endpoint"`
	CertFingerprint string   `json:"cert_fingerprint"`
	Components      []string `json:"components"`
	CPUPercent      float64  `json:"cpu_percent"`
	RAMGB           float64  `json:"ram_gb"`
}

type HeartbeatInput struct {
	TenantID    string   `json:"tenant_id"`
	NodeID      string   `json:"node_id"`
	Status      string   `json:"status"`
	CPUPercent  float64  `json:"cpu_percent"`
	RAMGB       float64  `json:"ram_gb"`
	Components  []string `json:"components"`
	LastSyncAt  string   `json:"last_sync_at"`
	ProfileID   string   `json:"profile_id"`
	JoinState   string   `json:"join_state"`
	NodeRole    string   `json:"role"`
	NodeName    string   `json:"name"`
	NodeAddress string   `json:"endpoint"`
}

type PublishSyncEventInput struct {
	TenantID     string                 `json:"tenant_id"`
	ProfileID    string                 `json:"profile_id"`
	Component    string                 `json:"component"`
	EntityType   string                 `json:"entity_type"`
	EntityID     string                 `json:"entity_id"`
	Operation    string                 `json:"operation"`
	Payload      map[string]interface{} `json:"payload"`
	SourceNodeID string                 `json:"source_node_id"`
}

type SyncAckInput struct {
	TenantID    string `json:"tenant_id"`
	NodeID      string `json:"node_id"`
	ProfileID   string `json:"profile_id"`
	LastEventID int64  `json:"last_event_id"`
}
