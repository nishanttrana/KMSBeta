package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	pkgclustersync "vecta-kms/pkg/clustersync"
)

const defaultProfileName = "base-platform"
const minActiveCPUPercent = 0.1
const defaultDegradedHeartbeatSec = 45
const defaultDownHeartbeatSec = 90

var requiredCoreComponents = []string{"auth", "keycore", "policy", "governance"}

type clusterProfilePreset struct {
	ID          string
	Name        string
	Description string
	Components  []string
}

var builtinClusterProfilePresets = []clusterProfilePreset{
	{
		ID:          "cluster-profile-base",
		Name:        defaultProfileName,
		Description: "Base KMS platform state sync for auth, tenant policy, governance, REST client security, and SCIM provisioning state.",
		Components:  []string{},
	},
	{
		ID:          "cluster-profile-standard",
		Name:        "standard-platform",
		Description: "Base platform plus secrets, certificates with coordinated renewal intelligence, Autokey, artifact signing, key-access governance, BYOK, EKM, and data protection replication.",
		Components:  []string{"secrets", "certs", "autokey", "signing", "keyaccess", "byok", "ekm", "dataprotect"},
	},
	{
		ID:          "cluster-profile-security",
		Name:        "security-suite",
		Description: "Standard platform plus compliance, posture, discovery, workload identity, confidential compute, Autokey, artifact signing, key-access governance, SBOM, and reporting replication.",
		Components:  []string{"secrets", "certs", "autokey", "signing", "keyaccess", "byok", "ekm", "dataprotect", "compliance", "posture", "discovery", "workload", "confidential", "sbom", "reporting"},
	},
	{
		ID:          "cluster-profile-full",
		Name:        "full-platform",
		Description: "Full platform replication including AI, Autokey, artifact signing, key-access governance, workload identity, confidential compute, KMIP, payment, PQC, QKD, QRNG, MPC, and HYOK services.",
		Components:  []string{"secrets", "certs", "autokey", "signing", "keyaccess", "byok", "ekm", "dataprotect", "compliance", "posture", "discovery", "workload", "confidential", "sbom", "reporting", "payment", "hyok", "kmip", "pqc", "qkd", "qrng", "mpc", "ai"},
	},
}

type Service struct {
	store                  Store
	events                 EventPublisher
	now                    func() time.Time
	bootstrapNodeID        string
	bootstrapNodeName      string
	bootstrapNodeRole      string
	bootstrapNodeAddress   string
	bootstrapProfileID     string
	consulAddress          string
	heartbeatDegradedAfter time.Duration
	heartbeatDownAfter     time.Duration
	syncRequireMTLS        bool
	syncSharedSecret       []byte
	syncReplayWindowSec    int64
	localHSMPartition      string
	localMEKInHSM          bool
	localMEKLogicalID      string
	hsmReplicationShared   bool
}

func NewService(store Store, events EventPublisher) *Service {
	replayWindowSec := parseEnvInt64("CLUSTER_SYNC_ANTI_REPLAY_SEC", 120)
	if replayWindowSec < 30 {
		replayWindowSec = 30
	}
	degradedAfterSec := parseEnvInt64("CLUSTER_HEARTBEAT_DEGRADED_AFTER_SEC", defaultDegradedHeartbeatSec)
	downAfterSec := parseEnvInt64("CLUSTER_HEARTBEAT_DOWN_AFTER_SEC", defaultDownHeartbeatSec)
	if degradedAfterSec < 10 {
		degradedAfterSec = defaultDegradedHeartbeatSec
	}
	if downAfterSec <= degradedAfterSec {
		downAfterSec = degradedAfterSec + 30
	}
	return &Service{
		store:                  store,
		events:                 events,
		now:                    func() time.Time { return time.Now().UTC() },
		bootstrapNodeID:        defaultIfEmpty(os.Getenv("CLUSTER_NODE_ID"), "vecta-kms-01"),
		bootstrapNodeName:      defaultIfEmpty(os.Getenv("CLUSTER_NODE_NAME"), "vecta-kms-01"),
		bootstrapNodeRole:      normalizeRole(defaultIfEmpty(os.Getenv("CLUSTER_NODE_ROLE"), "leader")),
		bootstrapNodeAddress:   defaultIfEmpty(os.Getenv("CLUSTER_NODE_ENDPOINT"), "10.0.1.100"),
		bootstrapProfileID:     defaultIfEmpty(os.Getenv("CLUSTER_BOOTSTRAP_PROFILE_ID"), "cluster-profile-base"),
		consulAddress:          defaultIfEmpty(os.Getenv("CONSUL_HTTP_ADDR"), "consul:8500"),
		heartbeatDegradedAfter: time.Duration(degradedAfterSec) * time.Second,
		heartbeatDownAfter:     time.Duration(downAfterSec) * time.Second,
		syncRequireMTLS:        parseEnvBool("CLUSTER_SYNC_REQUIRE_MTLS", false),
		syncSharedSecret:       []byte(strings.TrimSpace(os.Getenv("CLUSTER_SYNC_SHARED_SECRET"))),
		syncReplayWindowSec:    replayWindowSec,
		localHSMPartition: defaultIfEmpty(
			os.Getenv("CLUSTER_HSM_PARTITION_LABEL"),
			defaultIfEmpty(os.Getenv("HSM_PARTITION_LABEL"), strings.TrimSpace(os.Getenv("THALES_PARTITION"))),
		),
		localMEKInHSM:        parseEnvBool("CLUSTER_MEK_IN_HSM", parseEnvBool("KEYCORE_MEK_IN_HSM", false)),
		localMEKLogicalID:    strings.TrimSpace(defaultIfEmpty(os.Getenv("CLUSTER_MEK_LOGICAL_ID"), os.Getenv("KEYCORE_MEK_LOGICAL_ID"))),
		hsmReplicationShared: parseEnvBool("CLUSTER_HSM_KEY_REPLICATION_ENABLED", false),
	}
}

func (s *Service) GetOverview(ctx context.Context, tenantID string) (ClusterOverview, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ClusterOverview{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	if err := s.ensureBootstrap(ctx, tenantID); err != nil {
		return ClusterOverview{}, err
	}
	profiles, err := s.store.ListProfiles(ctx, tenantID)
	if err != nil {
		return ClusterOverview{}, err
	}
	nodes, err := s.store.ListNodes(ctx, tenantID)
	if err != nil {
		return ClusterOverview{}, err
	}
	for i := range nodes {
		nodes[i].Status = s.effectiveNodeStatus(nodes[i])
		nodes[i].Role = normalizeRole(nodes[i].Role)
		nodes[i].EnabledComponents = normalizeDisplayComponents(nodes[i].EnabledComponents)
		if strings.TrimSpace(nodes[i].ID) == strings.TrimSpace(s.bootstrapNodeID) {
			if s.enrichLocalNodeRuntime(ctx, &nodes[i]) {
				_ = s.store.UpsertNode(ctx, nodes[i])
			}
			nodes[i].Status = s.effectiveNodeStatus(nodes[i])
		}
	}
	out := ClusterOverview{Nodes: nodes, Profiles: profiles}
	out.SelectiveComponentSync.Enabled = true
	out.SelectiveComponentSync.Note = "Nodes sync only the state for their enabled components. Auth replication includes REST client sender-constraint profiles, per-client security counters, SCIM tenant settings, SCIM-managed users and groups, and role-mapped memberships; certs replication includes ACME Renewal Information windows, ACME STAR subscriptions and delegated subscriber metadata, and coordinated renewal hotspot state; Autokey replication includes tenant templates, service defaults, request catalogs, and managed handles; artifact-signing replication includes signing profiles, trust constraints, and transparency-linked signature records; key-access replication includes tenant justification rules, approval policy bindings, and decision history, while short-lived anti-replay nonce caches stay node-local."
	for _, node := range nodes {
		if node.Role == "leader" && out.Summary.LeaderNodeID == "" {
			out.Summary.LeaderNodeID = node.ID
		}
		switch node.Status {
		case "online":
			out.Summary.OnlineNodes++
		case "degraded":
			out.Summary.DegradedNodes++
		case "down":
			out.Summary.DownNodes++
		}
	}
	out.Summary.TotalNodes = len(nodes)
	return out, nil
}

func (s *Service) ListMembers(ctx context.Context, tenantID string) ([]ClusterNode, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	if err := s.ensureBootstrap(ctx, tenantID); err != nil {
		return nil, err
	}
	nodes, err := s.store.ListNodes(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]ClusterNode, 0, len(nodes))
	for _, node := range nodes {
		if strings.ToLower(strings.TrimSpace(node.JoinState)) == "revoked" {
			continue
		}
		node.Role = normalizeRole(node.Role)
		node.Status = s.effectiveNodeStatus(node)
		node.EnabledComponents = normalizeDisplayComponents(node.EnabledComponents)
		out = append(out, node)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Role == out[j].Role {
			return out[i].Name < out[j].Name
		}
		return out[i].Role == "leader"
	})
	return out, nil
}

func (s *Service) ListProfiles(ctx context.Context, tenantID string) ([]ClusterProfile, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	if err := s.ensureBootstrap(ctx, tenantID); err != nil {
		return nil, err
	}
	return s.store.ListProfiles(ctx, tenantID)
}

func (s *Service) UpsertProfile(ctx context.Context, in UpsertProfileInput) (ClusterProfile, error) {
	in.TenantID = strings.TrimSpace(in.TenantID)
	if in.TenantID == "" {
		return ClusterProfile{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	if err := s.ensureBootstrap(ctx, in.TenantID); err != nil {
		return ClusterProfile{}, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return ClusterProfile{}, newServiceError(400, "bad_request", "profile name is required")
	}
	components := ensureProfileComponents(in.Components)
	if len(components) == 0 {
		return ClusterProfile{}, newServiceError(400, "bad_request", "at least one component is required")
	}
	profileID := strings.TrimSpace(in.ID)
	if profileID == "" {
		profileID = newID("profile")
	}
	item := ClusterProfile{
		ID:          profileID,
		TenantID:    in.TenantID,
		Name:        name,
		Description: strings.TrimSpace(in.Description),
		Components:  components,
		IsDefault:   in.IsDefault,
	}
	if err := s.store.UpsertProfile(ctx, item); err != nil {
		return ClusterProfile{}, err
	}
	if in.IsDefault {
		if err := s.store.SetDefaultProfile(ctx, in.TenantID, profileID); err != nil {
			return ClusterProfile{}, err
		}
	}
	out, err := s.store.GetProfile(ctx, in.TenantID, profileID)
	if err != nil {
		return ClusterProfile{}, err
	}
	_ = s.publishAudit(ctx, "audit.cluster.profile_upserted", in.TenantID, map[string]interface{}{
		"profile_id": profileID,
		"components": components,
	})
	return out, nil
}

func (s *Service) DeleteProfile(ctx context.Context, tenantID string, profileID string) error {
	tenantID = strings.TrimSpace(tenantID)
	profileID = strings.TrimSpace(profileID)
	if tenantID == "" || profileID == "" {
		return newServiceError(400, "bad_request", "tenant_id and profile_id are required")
	}
	profile, err := s.store.GetProfile(ctx, tenantID, profileID)
	if err != nil {
		return err
	}
	if profile.IsDefault {
		return newServiceError(409, "profile_locked", "default profile cannot be deleted")
	}
	if err := s.store.DeleteProfile(ctx, tenantID, profileID); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.cluster.profile_deleted", tenantID, map[string]interface{}{"profile_id": profileID})
	return nil
}

func (s *Service) CreateJoinToken(ctx context.Context, in CreateJoinTokenInput) (ClusterJoinToken, error) {
	in.TenantID = strings.TrimSpace(in.TenantID)
	if in.TenantID == "" {
		return ClusterJoinToken{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	if err := s.ensureBootstrap(ctx, in.TenantID); err != nil {
		return ClusterJoinToken{}, err
	}
	in.TargetNodeID = strings.TrimSpace(in.TargetNodeID)
	if in.TargetNodeID == "" {
		return ClusterJoinToken{}, newServiceError(400, "bad_request", "target_node_id is required")
	}
	profileID := strings.TrimSpace(in.ProfileID)
	if profileID == "" {
		profiles, err := s.store.ListProfiles(ctx, in.TenantID)
		if err != nil {
			return ClusterJoinToken{}, err
		}
		for _, profile := range profiles {
			if profile.IsDefault {
				profileID = profile.ID
				break
			}
		}
		if profileID == "" && len(profiles) > 0 {
			profileID = profiles[0].ID
		}
	}
	if profileID == "" {
		return ClusterJoinToken{}, newServiceError(409, "missing_profile", "cluster profile is required")
	}
	profile, err := s.store.GetProfile(ctx, in.TenantID, profileID)
	if err != nil {
		return ClusterJoinToken{}, err
	}
	expiresMin := in.ExpiresMinutes
	if expiresMin <= 0 || expiresMin > 240 {
		expiresMin = 30
	}
	issuedSecret := randomHex(24)
	token := ClusterJoinToken{
		ID:            newID("join"),
		TenantID:      in.TenantID,
		TargetNodeID:  in.TargetNodeID,
		TargetNode:    defaultIfEmpty(in.TargetNodeName, in.TargetNodeID),
		Endpoint:      strings.TrimSpace(in.Endpoint),
		ProfileID:     profile.ID,
		SecretHash:    sha256Hex(issuedSecret),
		Nonce:         randomHex(12),
		RequestedBy:   defaultIfEmpty(in.RequestedBy, "system"),
		ExpiresAt:     s.now().Add(time.Duration(expiresMin) * time.Minute),
		CreatedAt:     s.now(),
		IssuedSecret:  issuedSecret,
		ProfileName:   profile.Name,
		ProfileScopes: profile.Components,
	}
	if err := s.store.CreateJoinToken(ctx, token); err != nil {
		return ClusterJoinToken{}, err
	}
	_ = s.store.PurgeExpiredJoinTokens(ctx, s.now())
	_ = s.publishAudit(ctx, "audit.cluster.join_requested", in.TenantID, map[string]interface{}{
		"token_id":   token.ID,
		"node_id":    token.TargetNodeID,
		"profile_id": profile.ID,
	})
	return token, nil
}

func (s *Service) CompleteJoin(ctx context.Context, in CompleteJoinInput) (ClusterNode, error) {
	in.TenantID = strings.TrimSpace(in.TenantID)
	if in.TenantID == "" {
		return ClusterNode{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	if strings.TrimSpace(in.TokenID) == "" || strings.TrimSpace(in.JoinSecret) == "" {
		return ClusterNode{}, newServiceError(400, "bad_request", "token_id and join_secret are required")
	}
	token, err := s.store.GetJoinToken(ctx, in.TenantID, in.TokenID)
	if err != nil {
		return ClusterNode{}, err
	}
	if !token.ConsumedAt.IsZero() {
		return ClusterNode{}, newServiceError(409, "token_consumed", "join token already consumed")
	}
	if s.now().After(token.ExpiresAt) {
		return ClusterNode{}, newServiceError(410, "token_expired", "join token expired")
	}
	if sha256Hex(strings.TrimSpace(in.JoinSecret)) != strings.TrimSpace(token.SecretHash) {
		return ClusterNode{}, newServiceError(401, "invalid_secret", "join secret verification failed")
	}
	nodeID := strings.TrimSpace(in.NodeID)
	if nodeID == "" {
		nodeID = token.TargetNodeID
	}
	if token.TargetNodeID != "" && nodeID != token.TargetNodeID {
		return ClusterNode{}, newServiceError(400, "bad_request", "node_id does not match join request")
	}
	profile, err := s.store.GetProfile(ctx, in.TenantID, token.ProfileID)
	if err != nil {
		return ClusterNode{}, err
	}
	components := disallowAuditComponent(normalizeComponents(in.Components))
	if len(components) == 0 {
		components = profile.Components
	}
	node := ClusterNode{
		ID:                nodeID,
		TenantID:          in.TenantID,
		Name:              defaultIfEmpty(in.NodeName, token.TargetNode),
		Role:              "follower",
		Endpoint:          defaultIfEmpty(in.Endpoint, token.Endpoint),
		Status:            "online",
		CPUPercent:        in.CPUPercent,
		RAMGB:             in.RAMGB,
		EnabledComponents: components,
		ProfileID:         profile.ID,
		JoinState:         "active",
		CertFingerprint:   strings.TrimSpace(in.CertFingerprint),
		LastHeartbeatAt:   s.now(),
	}
	if err := s.store.UpsertNode(ctx, node); err != nil {
		return ClusterNode{}, err
	}
	if err := s.store.MarkJoinTokenConsumed(ctx, in.TenantID, token.ID, s.now()); err != nil {
		return ClusterNode{}, err
	}
	out, err := s.store.GetNode(ctx, in.TenantID, node.ID)
	if err != nil {
		return ClusterNode{}, err
	}
	_ = s.publishAudit(ctx, "audit.cluster.node_joined", in.TenantID, map[string]interface{}{
		"node_id":    out.ID,
		"profile_id": out.ProfileID,
	})
	return out, nil
}

func (s *Service) UpdateHeartbeat(ctx context.Context, nodeID string, in HeartbeatInput) (ClusterNode, error) {
	in.TenantID = strings.TrimSpace(in.TenantID)
	if in.TenantID == "" {
		return ClusterNode{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		nodeID = strings.TrimSpace(in.NodeID)
	}
	if nodeID == "" {
		return ClusterNode{}, newServiceError(400, "bad_request", "node_id is required")
	}
	node, err := s.store.GetNode(ctx, in.TenantID, nodeID)
	if err != nil {
		if !errorsIsNotFound(err) {
			return ClusterNode{}, err
		}
		profiles, listErr := s.store.ListProfiles(ctx, in.TenantID)
		if listErr != nil {
			return ClusterNode{}, listErr
		}
		if len(profiles) == 0 {
			return ClusterNode{}, newServiceError(409, "missing_profile", "no cluster profile configured")
		}
		selectedProfileID := strings.TrimSpace(in.ProfileID)
		if selectedProfileID == "" {
			selectedProfileID = profiles[0].ID
		}
		node = ClusterNode{
			ID:        nodeID,
			TenantID:  in.TenantID,
			Name:      defaultIfEmpty(in.NodeName, nodeID),
			Role:      normalizeRole(defaultIfEmpty(in.NodeRole, "follower")),
			Endpoint:  defaultIfEmpty(in.NodeAddress, "unknown"),
			ProfileID: selectedProfileID,
			JoinState: defaultIfEmpty(in.JoinState, "active"),
		}
	}
	node.Status = normalizeNodeStatus(defaultIfEmpty(in.Status, node.Status))
	prevCPU := round1(clampFloat(node.CPUPercent, 0, 100))
	incomingCPU := round1(clampFloat(in.CPUPercent, 0, 100))
	// Preserve last known non-zero CPU for active nodes when heartbeat rounds down to 0.
	if incomingCPU <= 0 && (node.Status == "online" || node.Status == "degraded") && prevCPU > 0 {
		incomingCPU = prevCPU
	}
	node.CPUPercent = incomingCPU
	node.RAMGB = round1(clampFloat(in.RAMGB, 0, 65536))
	if parsed := parseTimeString(in.LastSyncAt); !parsed.IsZero() {
		node.LastSyncAt = parsed
	}
	if normalized := disallowAuditComponent(normalizeComponents(in.Components)); len(normalized) > 0 {
		node.EnabledComponents = normalized
	}
	if strings.TrimSpace(in.ProfileID) != "" {
		node.ProfileID = strings.TrimSpace(in.ProfileID)
	}
	if strings.TrimSpace(in.NodeName) != "" {
		node.Name = strings.TrimSpace(in.NodeName)
	}
	if strings.TrimSpace(in.NodeAddress) != "" {
		node.Endpoint = strings.TrimSpace(in.NodeAddress)
	}
	if strings.TrimSpace(in.JoinState) != "" {
		node.JoinState = strings.TrimSpace(in.JoinState)
	}
	if strings.TrimSpace(in.NodeRole) != "" {
		node.Role = normalizeRole(in.NodeRole)
	}
	node.CPUPercent = enforceActiveCPUFloor(node.CPUPercent, node.Status, node.JoinState, node.EnabledComponents)
	node.LastHeartbeatAt = s.now()
	if err := s.store.UpsertNode(ctx, node); err != nil {
		return ClusterNode{}, err
	}
	return s.store.GetNode(ctx, in.TenantID, node.ID)
}

func (s *Service) UpsertNode(ctx context.Context, in UpsertNodeInput) (ClusterNode, error) {
	in.TenantID = strings.TrimSpace(in.TenantID)
	if in.TenantID == "" {
		return ClusterNode{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	if err := s.ensureBootstrap(ctx, in.TenantID); err != nil {
		return ClusterNode{}, err
	}
	nodeID := strings.TrimSpace(in.NodeID)
	if nodeID == "" {
		return ClusterNode{}, newServiceError(400, "bad_request", "node_id is required")
	}
	profileID := strings.TrimSpace(in.ProfileID)
	if profileID == "" {
		profiles, err := s.store.ListProfiles(ctx, in.TenantID)
		if err != nil {
			return ClusterNode{}, err
		}
		for _, profile := range profiles {
			if profile.IsDefault {
				profileID = profile.ID
				break
			}
		}
		if profileID == "" && len(profiles) > 0 {
			profileID = profiles[0].ID
		}
	}
	if profileID == "" {
		return ClusterNode{}, newServiceError(409, "missing_profile", "cluster profile is required")
	}
	profile, err := s.store.GetProfile(ctx, in.TenantID, profileID)
	if err != nil {
		return ClusterNode{}, err
	}
	normalizedComponents := disallowAuditComponent(normalizeComponents(in.Components))
	if len(normalizedComponents) == 0 {
		normalizedComponents = profile.Components
	}
	for _, component := range normalizedComponents {
		if !componentAllowedForProfile(component, profile.Components) {
			return ClusterNode{}, newServiceError(409, "component_not_allowed", "node components must be part of the selected profile")
		}
	}
	node, err := s.store.GetNode(ctx, in.TenantID, nodeID)
	nodeExists := err == nil
	if err != nil && !errorsIsNotFound(err) {
		return ClusterNode{}, err
	}
	if !nodeExists {
		node = ClusterNode{
			ID:       nodeID,
			TenantID: in.TenantID,
		}
	}
	node.Name = defaultIfEmpty(in.NodeName, defaultIfEmpty(node.Name, nodeID))
	node.Role = normalizeRole(defaultIfEmpty(in.Role, defaultIfEmpty(node.Role, "follower")))
	node.Endpoint = defaultIfEmpty(in.Endpoint, defaultIfEmpty(node.Endpoint, "unknown"))
	node.Status = normalizeNodeStatus(defaultIfEmpty(in.Status, defaultIfEmpty(node.Status, "unknown")))
	node.CPUPercent = round1(clampFloat(in.CPUPercent, 0, 100))
	node.RAMGB = round1(clampFloat(in.RAMGB, 0, 65536))
	node.EnabledComponents = normalizeDisplayComponents(normalizedComponents)
	node.ProfileID = profile.ID
	node.JoinState = defaultIfEmpty(in.JoinState, defaultIfEmpty(node.JoinState, "active"))
	node.CertFingerprint = defaultIfEmpty(in.CertFingerprint, node.CertFingerprint)
	node.CPUPercent = enforceActiveCPUFloor(node.CPUPercent, node.Status, node.JoinState, node.EnabledComponents)
	node.LastHeartbeatAt = s.now()
	if err := s.store.UpsertNode(ctx, node); err != nil {
		return ClusterNode{}, err
	}
	if node.Role == "leader" {
		if err := s.demoteOtherLeaders(ctx, in.TenantID, node.ID); err != nil {
			return ClusterNode{}, err
		}
	}
	out, err := s.store.GetNode(ctx, in.TenantID, node.ID)
	if err != nil {
		return ClusterNode{}, err
	}
	if !nodeExists || in.SeedSync {
		_, _ = s.seedNodeSyncEvents(ctx, out, profile, defaultIfEmpty(strings.TrimSpace(in.RequestedBy), s.bootstrapNodeID))
	}
	s.appendClusterLog(ctx, ClusterLogEntry{
		TenantID:  in.TenantID,
		NodeID:    out.ID,
		Level:     "info",
		EventType: "node_upserted",
		Message:   "cluster node registration updated",
		Details: map[string]interface{}{
			"profile_id": out.ProfileID,
			"role":       out.Role,
			"components": out.EnabledComponents,
			"seed_sync":  !nodeExists || in.SeedSync,
		},
	})
	_ = s.publishAudit(ctx, "audit.cluster.node_upserted", in.TenantID, map[string]interface{}{
		"node_id":    out.ID,
		"profile_id": out.ProfileID,
		"role":       out.Role,
		"components": out.EnabledComponents,
	})
	return out, nil
}

func (s *Service) UpdateNodeRole(ctx context.Context, nodeID string, in UpdateNodeRoleInput) (ClusterNode, error) {
	in.TenantID = strings.TrimSpace(in.TenantID)
	if in.TenantID == "" {
		return ClusterNode{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return ClusterNode{}, newServiceError(400, "bad_request", "node_id is required")
	}
	targetRole := normalizeRole(in.Role)
	node, err := s.store.GetNode(ctx, in.TenantID, nodeID)
	if err != nil {
		return ClusterNode{}, err
	}
	if node.Role == targetRole {
		return node, nil
	}
	node.Role = targetRole
	node.UpdatedAt = s.now()
	if err := s.store.UpsertNode(ctx, node); err != nil {
		return ClusterNode{}, err
	}
	if targetRole == "leader" {
		if err := s.demoteOtherLeaders(ctx, in.TenantID, nodeID); err != nil {
			return ClusterNode{}, err
		}
	}
	out, err := s.store.GetNode(ctx, in.TenantID, nodeID)
	if err != nil {
		return ClusterNode{}, err
	}
	s.appendClusterLog(ctx, ClusterLogEntry{
		TenantID:  in.TenantID,
		NodeID:    out.ID,
		Level:     "info",
		EventType: "node_role_updated",
		Message:   "cluster node role updated",
		Details: map[string]interface{}{
			"role":       out.Role,
			"updated_by": defaultIfEmpty(strings.TrimSpace(in.RequestedBy), "system"),
		},
	})
	_ = s.publishAudit(ctx, "audit.cluster.node_role_updated", in.TenantID, map[string]interface{}{
		"node_id":    out.ID,
		"role":       out.Role,
		"updated_by": defaultIfEmpty(strings.TrimSpace(in.RequestedBy), "system"),
	})
	return out, nil
}

func (s *Service) RemoveNode(ctx context.Context, nodeID string, in RemoveNodeInput) (RemoveNodeResult, error) {
	in.TenantID = strings.TrimSpace(in.TenantID)
	if in.TenantID == "" {
		return RemoveNodeResult{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return RemoveNodeResult{}, newServiceError(400, "bad_request", "node_id is required")
	}
	if err := s.ensureBootstrap(ctx, in.TenantID); err != nil {
		return RemoveNodeResult{}, err
	}
	node, err := s.store.GetNode(ctx, in.TenantID, nodeID)
	if err != nil {
		return RemoveNodeResult{}, err
	}
	if strings.EqualFold(strings.TrimSpace(node.ID), strings.TrimSpace(s.bootstrapNodeID)) {
		return RemoveNodeResult{}, newServiceError(409, "node_locked", "local bootstrap node cannot be removed from itself")
	}
	profile, err := s.store.GetProfile(ctx, in.TenantID, node.ProfileID)
	if err != nil {
		return RemoveNodeResult{}, err
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		reason = "removed_from_cluster"
	}
	purgeSyncedData := true
	purgeEventIDs, seedErr := s.emitNodeDecommissionEvents(ctx, node, profile, reason, purgeSyncedData)
	if seedErr != nil {
		return RemoveNodeResult{}, seedErr
	}
	promotedLeaderNode := ""
	if normalizeRole(node.Role) == "leader" {
		candidateID, promoteErr := s.promoteReplacementLeader(ctx, in.TenantID, node.ID)
		if promoteErr != nil {
			return RemoveNodeResult{}, promoteErr
		}
		promotedLeaderNode = candidateID
	}
	if err := s.store.DeleteNode(ctx, in.TenantID, node.ID); err != nil {
		return RemoveNodeResult{}, err
	}
	result := RemoveNodeResult{
		NodeID:             node.ID,
		TenantID:           in.TenantID,
		Standalone:         true,
		PurgeSyncedData:    purgeSyncedData,
		PurgeEventIDs:      purgeEventIDs,
		PreviousRole:       normalizeRole(node.Role),
		PromotedLeaderNode: promotedLeaderNode,
	}
	s.appendClusterLog(ctx, ClusterLogEntry{
		TenantID:  in.TenantID,
		NodeID:    node.ID,
		Level:     "warn",
		EventType: "node_removed",
		Message:   "cluster node removed and decommissioned",
		Details: map[string]interface{}{
			"purge_synced_data":  purgeSyncedData,
			"purge_event_ids":    purgeEventIDs,
			"promoted_leader_id": promotedLeaderNode,
			"requested_by":       defaultIfEmpty(strings.TrimSpace(in.RequestedBy), "system"),
			"reason":             reason,
		},
	})
	_ = s.publishAudit(ctx, "audit.cluster.node_removed", in.TenantID, map[string]interface{}{
		"node_id":            node.ID,
		"purge_synced_data":  purgeSyncedData,
		"purge_event_ids":    purgeEventIDs,
		"promoted_leader_id": promotedLeaderNode,
		"requested_by":       defaultIfEmpty(strings.TrimSpace(in.RequestedBy), "system"),
		"reason":             reason,
	})
	return result, nil
}

func (s *Service) PublishSyncEvent(ctx context.Context, in PublishSyncEventInput) (ClusterSyncEvent, error) {
	in.TenantID = strings.TrimSpace(in.TenantID)
	if in.TenantID == "" {
		return ClusterSyncEvent{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	if strings.TrimSpace(in.ProfileID) == "" {
		return ClusterSyncEvent{}, newServiceError(400, "bad_request", "profile_id is required")
	}
	profile, err := s.store.GetProfile(ctx, in.TenantID, in.ProfileID)
	if err != nil {
		return ClusterSyncEvent{}, err
	}
	component := normalizeComponentName(in.Component)
	if component == "" {
		return ClusterSyncEvent{}, newServiceError(400, "bad_request", "component is required")
	}
	if component == "audit" {
		return ClusterSyncEvent{}, newServiceError(409, "component_blocked", "audit component sync is disabled; audit logs remain local per node")
	}
	if !componentAllowedForProfile(component, profile.Components) {
		return ClusterSyncEvent{}, newServiceError(409, "component_not_allowed", "component not allowed for selected sync profile")
	}
	entityType := strings.TrimSpace(in.EntityType)
	entityID := strings.TrimSpace(in.EntityID)
	operation := strings.TrimSpace(in.Operation)
	if entityType == "" || entityID == "" || operation == "" {
		return ClusterSyncEvent{}, newServiceError(400, "bad_request", "entity_type, entity_id and operation are required")
	}
	payload, removedSensitive := sanitizeSyncPayload(in.Payload)
	if len(removedSensitive) > 0 {
		s.appendClusterLog(ctx, ClusterLogEntry{
			TenantID:  in.TenantID,
			NodeID:    strings.TrimSpace(in.SourceNodeID),
			Level:     "warn",
			EventType: "sync_payload_rejected",
			Message:   "sync payload included prohibited sensitive fields",
			Details: map[string]interface{}{
				"component": component,
				"entity":    entityType,
				"removed":   removedSensitive,
			},
		})
		return ClusterSyncEvent{}, newServiceError(400, "sensitive_payload_blocked", "sync payload contains prohibited sensitive key material fields")
	}
	if component == "keycore" {
		policyAdjusted, policyMeta := s.applyKeycoreHSMSyncPolicy(payload)
		payload = policyAdjusted
		if len(policyMeta) > 0 {
			s.appendClusterLog(ctx, ClusterLogEntry{
				TenantID:  in.TenantID,
				NodeID:    strings.TrimSpace(in.SourceNodeID),
				Level:     "info",
				EventType: "hsm_sync_policy_applied",
				Message:   "keycore HSM sync portability policy evaluated",
				Details:   policyMeta,
			})
		}
	}
	event := ClusterSyncEvent{
		TenantID:     in.TenantID,
		ProfileID:    profile.ID,
		Component:    component,
		EntityType:   entityType,
		EntityID:     entityID,
		Operation:    operation,
		Payload:      payload,
		SourceNodeID: defaultIfEmpty(in.SourceNodeID, s.bootstrapNodeID),
	}
	created, err := s.store.CreateSyncEvent(ctx, event)
	if err != nil {
		return ClusterSyncEvent{}, err
	}
	s.appendClusterLog(ctx, ClusterLogEntry{
		TenantID:  in.TenantID,
		NodeID:    created.SourceNodeID,
		Level:     "info",
		EventType: "sync_event_published",
		Message:   "cluster sync event accepted",
		Details: map[string]interface{}{
			"event_id":   created.ID,
			"profile_id": created.ProfileID,
			"component":  created.Component,
			"entity":     created.EntityType,
			"operation":  created.Operation,
		},
	})
	_ = s.publishAudit(ctx, "audit.cluster.sync_event", in.TenantID, map[string]interface{}{
		"event_id":   created.ID,
		"profile_id": profile.ID,
		"component":  component,
		"operation":  operation,
	})
	targetNodeIDs := s.resolvePushTargets(ctx, created.TenantID, created.ProfileID, created.SourceNodeID, created.Component)
	if s.events != nil {
		pushRaw, _ := json.Marshal(map[string]interface{}{
			"tenant_id":       created.TenantID,
			"profile_id":      created.ProfileID,
			"event_id":        created.ID,
			"component":       created.Component,
			"entity":          created.EntityType,
			"operation":       created.Operation,
			"node_id":         created.SourceNodeID,
			"target_node_ids": targetNodeIDs,
			"created_at":      created.CreatedAt.Format(time.RFC3339Nano),
		})
		_ = s.events.Publish(ctx, "cluster.sync.push", pushRaw)
		for _, nodeID := range targetNodeIDs {
			_ = s.events.Publish(ctx, "cluster.sync.push."+natsSubjectToken(nodeID), pushRaw)
		}
		s.appendClusterLog(ctx, ClusterLogEntry{
			TenantID:  created.TenantID,
			NodeID:    created.SourceNodeID,
			Level:     "info",
			EventType: "sync_push_dispatched",
			Message:   "cluster sync push dispatched to eligible followers",
			Details: map[string]interface{}{
				"event_id":       created.ID,
				"target_nodes":   targetNodeIDs,
				"target_count":   len(targetNodeIDs),
				"component":      created.Component,
				"profile_id":     created.ProfileID,
				"source_node_id": created.SourceNodeID,
			},
		})
	}
	return created, nil
}

func (s *Service) ListSyncEvents(ctx context.Context, tenantID string, profileID string, afterID int64, limit int, nodeID string) ([]ClusterSyncEvent, error) {
	tenantID = strings.TrimSpace(tenantID)
	profileID = strings.TrimSpace(profileID)
	if tenantID == "" || profileID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id and profile_id are required")
	}
	var components []string
	nodeID = strings.TrimSpace(nodeID)
	if nodeID != "" {
		node, err := s.store.GetNode(ctx, tenantID, nodeID)
		if err == nil {
			components = node.EnabledComponents
			if node.ProfileID != "" {
				profileID = node.ProfileID
			}
		}
	}
	items, err := s.store.ListSyncEvents(ctx, tenantID, profileID, afterID, limit, components)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *Service) AckSync(ctx context.Context, in SyncAckInput) (ClusterSyncCheckpoint, error) {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.NodeID = strings.TrimSpace(in.NodeID)
	in.ProfileID = strings.TrimSpace(in.ProfileID)
	if in.TenantID == "" || in.NodeID == "" || in.ProfileID == "" {
		return ClusterSyncCheckpoint{}, newServiceError(400, "bad_request", "tenant_id, node_id and profile_id are required")
	}
	checkpoint := ClusterSyncCheckpoint{
		TenantID:    in.TenantID,
		NodeID:      in.NodeID,
		ProfileID:   in.ProfileID,
		LastEventID: in.LastEventID,
	}
	if err := s.store.UpsertSyncCheckpoint(ctx, checkpoint); err != nil {
		return ClusterSyncCheckpoint{}, err
	}
	s.appendClusterLog(ctx, ClusterLogEntry{
		TenantID:  in.TenantID,
		NodeID:    in.NodeID,
		Level:     "info",
		EventType: "sync_acknowledged",
		Message:   "sync checkpoint updated",
		Details: map[string]interface{}{
			"profile_id":    in.ProfileID,
			"last_event_id": in.LastEventID,
		},
	})
	return s.store.GetSyncCheckpoint(ctx, in.TenantID, in.NodeID, in.ProfileID)
}

func (s *Service) GetSyncCheckpoint(ctx context.Context, tenantID string, nodeID string, profileID string) (ClusterSyncCheckpoint, error) {
	tenantID = strings.TrimSpace(tenantID)
	nodeID = strings.TrimSpace(nodeID)
	profileID = strings.TrimSpace(profileID)
	if tenantID == "" || nodeID == "" || profileID == "" {
		return ClusterSyncCheckpoint{}, newServiceError(400, "bad_request", "tenant_id, node_id and profile_id are required")
	}
	checkpoint, err := s.store.GetSyncCheckpoint(ctx, tenantID, nodeID, profileID)
	if err != nil {
		if errorsIsNotFound(err) {
			return ClusterSyncCheckpoint{TenantID: tenantID, NodeID: nodeID, ProfileID: profileID, LastEventID: 0}, nil
		}
		return ClusterSyncCheckpoint{}, err
	}
	return checkpoint, nil
}

func (s *Service) ListClusterLogs(ctx context.Context, tenantID string, nodeID string, eventType string, limit int) ([]ClusterLogEntry, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	return s.store.ListClusterLogs(ctx, tenantID, nodeID, eventType, limit)
}

func (s *Service) ValidateSignedSyncRequest(ctx context.Context, method string, path string, tenantID string, sourceNodeID string, timestamp string, nonce string, signature string, body []byte, transportMTLS bool) error {
	if s.syncRequireMTLS && !transportMTLS {
		s.appendClusterLog(ctx, ClusterLogEntry{
			TenantID:  strings.TrimSpace(tenantID),
			NodeID:    strings.TrimSpace(sourceNodeID),
			Level:     "warn",
			EventType: "sync_auth_rejected",
			Message:   "mTLS transport is required for cluster sync",
		})
		return newServiceError(401, "sync_transport_insecure", "mTLS transport is required for cluster sync")
	}
	if len(s.syncSharedSecret) == 0 {
		return nil
	}
	tenantID = strings.TrimSpace(tenantID)
	sourceNodeID = strings.TrimSpace(sourceNodeID)
	timestamp = strings.TrimSpace(timestamp)
	nonce = strings.TrimSpace(nonce)
	signature = strings.TrimSpace(signature)
	if tenantID == "" || timestamp == "" || nonce == "" || signature == "" {
		s.appendClusterLog(ctx, ClusterLogEntry{
			TenantID:  tenantID,
			NodeID:    sourceNodeID,
			Level:     "warn",
			EventType: "sync_auth_rejected",
			Message:   "missing sync signature headers",
		})
		return newServiceError(401, "sync_auth_missing", "signed sync request headers are required")
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		s.appendClusterLog(ctx, ClusterLogEntry{
			TenantID:  tenantID,
			NodeID:    sourceNodeID,
			Level:     "warn",
			EventType: "sync_auth_rejected",
			Message:   "invalid sync timestamp",
			Details:   map[string]interface{}{"timestamp": timestamp},
		})
		return newServiceError(401, "sync_auth_invalid", "invalid sync timestamp")
	}
	nowUnix := s.now().UTC().Unix()
	if abs64(nowUnix-ts) > s.syncReplayWindowSec {
		s.appendClusterLog(ctx, ClusterLogEntry{
			TenantID:  tenantID,
			NodeID:    sourceNodeID,
			Level:     "warn",
			EventType: "sync_auth_rejected",
			Message:   "sync signature timestamp outside replay window",
			Details: map[string]interface{}{
				"timestamp":         timestamp,
				"replay_window_sec": s.syncReplayWindowSec,
			},
		})
		return newServiceError(401, "sync_auth_expired", "sync signature expired")
	}
	if !pkgclustersync.VerifySignature(s.syncSharedSecret, signature, method, path, tenantID, sourceNodeID, timestamp, nonce, body) {
		s.appendClusterLog(ctx, ClusterLogEntry{
			TenantID:  tenantID,
			NodeID:    sourceNodeID,
			Level:     "warn",
			EventType: "sync_auth_rejected",
			Message:   "sync signature verification failed",
		})
		return newServiceError(401, "sync_auth_invalid", "sync signature verification failed")
	}
	inserted, err := s.store.ConsumeSyncNonce(ctx, tenantID, sourceNodeID, nonce, s.now().Add(time.Duration(s.syncReplayWindowSec)*time.Second))
	if err != nil {
		return err
	}
	if !inserted {
		s.appendClusterLog(ctx, ClusterLogEntry{
			TenantID:  tenantID,
			NodeID:    sourceNodeID,
			Level:     "warn",
			EventType: "sync_auth_rejected",
			Message:   "replay detected for sync request nonce",
			Details:   map[string]interface{}{"nonce": nonce},
		})
		return newServiceError(409, "sync_replay_detected", "sync request replay detected")
	}
	return nil
}

func (s *Service) ensureBootstrap(ctx context.Context, tenantID string) error {
	profiles, err := s.store.ListProfiles(ctx, tenantID)
	if err != nil {
		return err
	}
	bootstrapProfileID := strings.TrimSpace(s.bootstrapProfileID)
	if bootstrapProfileID == "" {
		bootstrapProfileID = "cluster-profile-base"
	}
	preferredDefaultProfileID := bootstrapProfileID
	if _, ok := builtinClusterProfileByID(tenantID, preferredDefaultProfileID, true); !ok {
		preferredDefaultProfileID = "cluster-profile-base"
	}
	defaultProfileID := ""
	if len(profiles) == 0 {
		for _, preset := range builtinClusterProfiles(tenantID, preferredDefaultProfileID) {
			if err := s.store.UpsertProfile(ctx, preset); err != nil {
				return err
			}
		}
		if err := s.store.SetDefaultProfile(ctx, tenantID, preferredDefaultProfileID); err != nil {
			return err
		}
		profiles, err = s.store.ListProfiles(ctx, tenantID)
		if err != nil {
			return err
		}
	}
	for _, profile := range profiles {
		if profile.IsDefault {
			defaultProfileID = profile.ID
			break
		}
	}
	if _, ok := builtinClusterProfileByID(tenantID, bootstrapProfileID, defaultProfileID == bootstrapProfileID); ok {
		found := false
		for _, profile := range profiles {
			if strings.TrimSpace(profile.ID) == bootstrapProfileID {
				found = true
				break
			}
		}
		if !found {
			preset, _ := builtinClusterProfileByID(tenantID, bootstrapProfileID, false)
			if err := s.store.UpsertProfile(ctx, preset); err != nil {
				return err
			}
			profiles = append(profiles, preset)
		}
	}
	if defaultProfileID == "" {
		defaultProfileID = preferredDefaultProfileID
		found := false
		for _, profile := range profiles {
			if strings.TrimSpace(profile.ID) == defaultProfileID {
				found = true
				break
			}
		}
		if !found && len(profiles) > 0 {
			defaultProfileID = profiles[0].ID
		}
		_ = s.store.SetDefaultProfile(ctx, tenantID, defaultProfileID)
	}
	nodeID := strings.TrimSpace(s.bootstrapNodeID)
	if nodeID == "" {
		return nil
	}
	if _, err := s.store.GetNode(ctx, tenantID, nodeID); err == nil {
		return nil
	} else if !errorsIsNotFound(err) {
		return err
	}
	discoveredComponents, _ := s.discoverLocalComponents()
	bootstrapNode := ClusterNode{
		ID:                nodeID,
		TenantID:          tenantID,
		Name:              defaultIfEmpty(s.bootstrapNodeName, nodeID),
		Role:              normalizeRole(s.bootstrapNodeRole),
		Endpoint:          defaultIfEmpty(s.bootstrapNodeAddress, "127.0.0.1"),
		Status:            "online",
		CPUPercent:        0,
		RAMGB:             0,
		EnabledComponents: normalizeDisplayComponents(discoveredComponents),
		ProfileID:         defaultProfileID,
		JoinState:         "active",
		LastHeartbeatAt:   s.now(),
	}
	return s.store.UpsertNode(ctx, bootstrapNode)
}

func (s *Service) appendClusterLog(ctx context.Context, entry ClusterLogEntry) {
	if s == nil || s.store == nil {
		return
	}
	if strings.TrimSpace(entry.TenantID) == "" {
		return
	}
	_ = s.store.AppendClusterLog(ctx, entry)
}

func sanitizeSyncPayload(in map[string]interface{}) (map[string]interface{}, []string) {
	if len(in) == 0 {
		return map[string]interface{}{}, nil
	}
	out := make(map[string]interface{}, len(in))
	removed := make([]string, 0)
	for key, value := range in {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if isSensitiveSyncField(normalized) {
			removed = append(removed, key)
			continue
		}
		out[key] = value
	}
	sort.Strings(removed)
	return out, removed
}

func (s *Service) enrichLocalNodeRuntime(ctx context.Context, node *ClusterNode) bool {
	if node == nil {
		return false
	}
	changed := false

	runtimeComponents, componentsOK := s.discoverLocalComponents()
	if componentsOK {
		normalized := normalizeDisplayComponents(runtimeComponents)
		if !equalStringSlices(node.EnabledComponents, normalized) {
			node.EnabledComponents = normalized
			changed = true
		}
	}

	cpuPercent, ramGB, metricsOK := sampleLocalRuntimeMetrics(ctx)
	if metricsOK {
		cpuPercent = enforceActiveCPUFloor(cpuPercent, node.Status, node.JoinState, node.EnabledComponents)
		if math.Abs(node.CPUPercent-cpuPercent) >= 0.1 {
			node.CPUPercent = cpuPercent
			changed = true
		}
		if math.Abs(node.RAMGB-ramGB) >= 0.1 {
			node.RAMGB = ramGB
			changed = true
		}
	}

	if normalizeNodeStatus(node.Status) != "online" {
		node.Status = "online"
		changed = true
	}
	if strings.TrimSpace(node.JoinState) == "" {
		node.JoinState = "active"
		changed = true
	}
	if node.LastHeartbeatAt.IsZero() || s.now().Sub(node.LastHeartbeatAt) >= 30*time.Second {
		node.LastHeartbeatAt = s.now()
		changed = true
	}
	return changed
}

func (s *Service) discoverLocalComponents() ([]string, bool) {
	consulAddr := strings.TrimSpace(s.consulAddress)
	if consulAddr == "" {
		return []string{}, false
	}
	cfg := api.DefaultConfig()
	cfg.Address = consulAddr
	cfg.HttpClient = &http.Client{Timeout: 800 * time.Millisecond}
	client, err := api.NewClient(cfg)
	if err != nil {
		return []string{}, false
	}

	// Prefer catalog-by-node discovery so each node exposes only services running on itself.
	components := make([]string, 0, 16)
	foundNodeRecord := false
	for _, nodeName := range localConsulNodeCandidates(s.bootstrapNodeName, s.bootstrapNodeID) {
		nodeComponents, found := discoverComponentsForConsulNode(client, nodeName)
		if !found {
			continue
		}
		foundNodeRecord = true
		components = append(components, nodeComponents...)
	}

	if foundNodeRecord {
		return normalizeDisplayComponents(components), true
	}

	// Fallback to local Consul agent services when catalog node lookup is unavailable.
	if services, err := client.Agent().Services(); err == nil && len(services) > 0 {
		for _, svc := range services {
			if svc == nil {
				continue
			}
			if mapped := componentFromServiceName(svc.Service); mapped != "" {
				components = append(components, mapped)
			}
		}
		normalized := normalizeDisplayComponents(components)
		if len(normalized) > 0 {
			return normalized, true
		}
	}

	// Last fallback: passing checks filtered to local node identifiers.
	checks, _, err := client.Health().State("passing", nil)
	if err != nil {
		return []string{}, false
	}
	identifiers := localNodeIdentifiers(s.bootstrapNodeName, s.bootstrapNodeID, s.bootstrapNodeAddress)
	for _, check := range checks {
		if !checkMatchesLocalNode(check, identifiers) {
			continue
		}
		name := strings.TrimSpace(check.ServiceName)
		if name == "" {
			continue
		}
		if mapped := componentFromServiceName(name); mapped != "" {
			components = append(components, mapped)
			continue
		}
		if strings.HasPrefix(strings.ToLower(name), "kms-") {
			components = append(components, strings.TrimPrefix(strings.ToLower(name), "kms-"))
		}
	}
	return normalizeDisplayComponents(components), true
}

func discoverComponentsForConsulNode(client *api.Client, nodeName string) ([]string, bool) {
	nodeName = strings.TrimSpace(nodeName)
	if client == nil || nodeName == "" {
		return nil, false
	}
	nodeInfo, _, err := client.Catalog().Node(nodeName, nil)
	if err != nil {
		return nil, false
	}
	if nodeInfo == nil {
		return nil, false
	}
	services := nodeInfo.Services
	if len(services) == 0 {
		return []string{}, true
	}

	passingByID := map[string]struct{}{}
	passingByName := map[string]struct{}{}
	checks, _, err := client.Health().Node(nodeName, nil)
	if err != nil {
		return nil, false
	}
	for _, check := range checks {
		if check == nil || !strings.EqualFold(strings.TrimSpace(check.Status), api.HealthPassing) {
			continue
		}
		if sid := strings.TrimSpace(check.ServiceID); sid != "" {
			passingByID[sid] = struct{}{}
		}
		if sname := strings.ToLower(strings.TrimSpace(check.ServiceName)); sname != "" {
			passingByName[sname] = struct{}{}
		}
	}

	components := make([]string, 0, len(services))
	for _, svc := range services {
		if svc == nil {
			continue
		}
		serviceName := strings.TrimSpace(svc.Service)
		if serviceName == "" {
			continue
		}
		if len(passingByID) > 0 || len(passingByName) > 0 {
			_, okByID := passingByID[strings.TrimSpace(svc.ID)]
			_, okByName := passingByName[strings.ToLower(serviceName)]
			if !okByID && !okByName {
				continue
			}
		}
		if mapped := componentFromServiceName(serviceName); mapped != "" {
			components = append(components, mapped)
		}
	}
	return normalizeDisplayComponents(components), true
}

func localConsulNodeCandidates(bootstrapNodeName string, bootstrapNodeID string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 4)
	add := func(v string) {
		name := strings.TrimSpace(v)
		if name == "" {
			return
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, name)
	}
	add(bootstrapNodeName)
	add(bootstrapNodeID)
	if host, err := os.Hostname(); err == nil {
		add(host)
	}
	return out
}

func localNodeIdentifiers(bootstrapNodeName string, bootstrapNodeID string, bootstrapNodeAddr string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 8)
	add := func(v string) {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	add(bootstrapNodeName)
	add(bootstrapNodeID)
	addr := strings.TrimSpace(bootstrapNodeAddr)
	if addr != "" {
		add(strings.Split(addr, ":")[0])
	}
	if host, err := os.Hostname(); err == nil {
		add(host)
	}
	return out
}

func checkMatchesLocalNode(check *api.HealthCheck, identifiers []string) bool {
	if check == nil {
		return false
	}
	if len(identifiers) == 0 {
		return true
	}
	candidates := []string{
		strings.ToLower(strings.TrimSpace(check.Node)),
		strings.ToLower(strings.TrimSpace(check.ServiceID)),
		strings.ToLower(strings.TrimSpace(check.CheckID)),
		strings.ToLower(strings.TrimSpace(check.Name)),
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		for _, id := range identifiers {
			if id != "" && strings.Contains(candidate, id) {
				return true
			}
		}
	}
	return false
}

func sampleLocalRuntimeMetrics(ctx context.Context) (float64, float64, bool) {
	metricsCtx, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
	defer cancel()

	var cpuPercent float64
	var ramGB float64
	available := false

	if values, err := cpu.PercentWithContext(metricsCtx, 100*time.Millisecond, false); err == nil && len(values) > 0 {
		cpuPercent = clampFloat(values[0], 0, 100)
		available = true
	}
	if cpuPercent <= 0 {
		if avg, err := load.AvgWithContext(metricsCtx); err == nil {
			cores := float64(runtime.NumCPU())
			if cores <= 0 {
				cores = 1
			}
			cpuPercent = clampFloat((avg.Load1/cores)*100, 0, 100)
			available = true
		}
	}
	if cpuPercent > 0 && cpuPercent < 1 {
		cpuPercent = 1
	}
	if vm, err := mem.VirtualMemoryWithContext(metricsCtx); err == nil {
		ramGB = float64(vm.Used) / (1024.0 * 1024.0 * 1024.0)
		available = true
	}

	return round1(cpuPercent), round1(ramGB), available
}

func parseLocalComponentHints() []string {
	rawInputs := []string{
		os.Getenv("CLUSTER_LOCAL_COMPONENTS"),
		os.Getenv("VECTA_ENABLED_COMPONENTS"),
		os.Getenv("COMPOSE_PROFILES"),
	}
	items := make([]string, 0, 16)
	for _, raw := range rawInputs {
		for _, token := range splitComponentTokens(raw) {
			if mapped := componentFromHint(token); mapped != "" {
				items = append(items, mapped)
			}
		}
	}
	return normalizeDisplayComponents(items)
}

func splitComponentTokens(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	replacer := strings.NewReplacer(";", ",", "|", ",", " ", ",", "\n", ",", "\t", ",")
	normalized := replacer.Replace(raw)
	parts := strings.Split(normalized, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func componentFromHint(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "auth", "keycore", "policy", "governance", "audit", "payment", "workload", "confidential", "dataprotect", "byok", "hyok", "ekm", "kmip", "certs", "secrets", "qkd", "mpc", "cluster", "compliance", "reporting", "sbom", "pqc", "discovery", "ai", "keyaccess", "signing":
		return v
	case "key_access", "key_access_justifications", "key-access", "kaj":
		return "keyaccess"
	case "artifact_signing", "artifact-signing", "supply_chain_signing", "supply-chain-signing":
		return "signing"
	case "workload_identity", "spiffe", "spiffe_federation":
		return "workload"
	case "cloud", "cloud_control", "cloud-key-control":
		return "byok"
	case "payments":
		return "payment"
	case "data_protection", "data-protection", "field_encryption", "field-encryption":
		return "dataprotect"
	case "certificates", "pki":
		return "certs"
	case "vault":
		return "secrets"
	case "clustering":
		return "cluster"
	}
	if mapped := componentFromServiceName(v); mapped != "" {
		return mapped
	}
	if strings.HasPrefix(v, "kms-") {
		return strings.TrimPrefix(v, "kms-")
	}
	return strings.ReplaceAll(v, "_", "-")
}

func componentFromServiceName(serviceName string) string {
	switch strings.ToLower(strings.TrimSpace(serviceName)) {
	case "kms-auth":
		return "auth"
	case "kms-keycore":
		return "keycore"
	case "kms-policy":
		return "policy"
	case "kms-governance":
		return "governance"
	case "kms-audit":
		return "audit"
	case "kms-payment":
		return "payment"
	case "kms-workload-identity":
		return "workload"
	case "kms-key-access":
		return "keyaccess"
	case "kms-confidential":
		return "confidential"
	case "kms-dataprotect":
		return "dataprotect"
	case "kms-cloud":
		return "byok"
	case "kms-hyok", "kms-hyok-proxy":
		return "hyok"
	case "kms-ekm":
		return "ekm"
	case "kms-kmip":
		return "kmip"
	case "kms-certs":
		return "certs"
	case "kms-secrets":
		return "secrets"
	case "kms-qkd":
		return "qkd"
	case "kms-mpc":
		return "mpc"
	case "kms-cluster-manager":
		return "cluster"
	case "kms-compliance":
		return "compliance"
	case "kms-reporting":
		return "reporting"
	case "kms-sbom":
		return "sbom"
	case "kms-pqc":
		return "pqc"
	case "kms-discovery":
		return "discovery"
	case "kms-ai":
		return "ai"
	case "kms-software-vault":
		return "software-vault"
	case "kms-posture":
		return "posture"
	case "kms-qrng":
		return "qrng"
	default:
		return ""
	}
}

func normalizeDisplayComponents(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		raw := strings.ToLower(strings.TrimSpace(item))
		if raw == "" {
			continue
		}
		if known := normalizeComponentName(raw); known != "" {
			raw = known
		} else {
			raw = strings.ReplaceAll(raw, "_", "-")
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	sort.Strings(out)
	return out
}

func equalStringSlices(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func clampFloat(v float64, min float64, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

func (s *Service) effectiveNodeStatus(node ClusterNode) string {
	status := normalizeNodeStatus(node.Status)
	if strings.EqualFold(strings.TrimSpace(node.JoinState), "revoked") {
		return "down"
	}
	if node.LastHeartbeatAt.IsZero() {
		return status
	}
	now := time.Now().UTC()
	if s != nil && s.now != nil {
		now = s.now()
	}
	age := now.Sub(node.LastHeartbeatAt)
	if age < 0 {
		age = 0
	}
	downAfter := defaultDownHeartbeatSec * time.Second
	degradedAfter := defaultDegradedHeartbeatSec * time.Second
	if s != nil {
		if s.heartbeatDownAfter > 0 {
			downAfter = s.heartbeatDownAfter
		}
		if s.heartbeatDegradedAfter > 0 {
			degradedAfter = s.heartbeatDegradedAfter
		}
	}
	if age >= downAfter {
		return "down"
	}
	if age >= degradedAfter {
		if status == "online" || status == "unknown" {
			return "degraded"
		}
	}
	return status
}

func enforceActiveCPUFloor(cpu float64, status string, joinState string, components []string) float64 {
	cpu = round1(clampFloat(cpu, 0, 100))
	if cpu >= minActiveCPUPercent {
		return cpu
	}
	status = normalizeNodeStatus(status)
	if status == "down" {
		return 0
	}
	if strings.EqualFold(strings.TrimSpace(joinState), "revoked") {
		return 0
	}
	if len(normalizeDisplayComponents(components)) == 0 {
		return cpu
	}
	return minActiveCPUPercent
}

func isSensitiveSyncField(key string) bool {
	if key == "" {
		return false
	}
	switch key {
	case "material", "material_b64", "materialiv", "material_iv", "encrypted_material",
		"wrapped_dek", "wrapped_material", "wrapped_key", "plaintext", "plain",
		"private_key", "secret", "secret_key", "raw_key", "key_bytes", "join_secret",
		"import_password", "passphrase", "dek", "mek", "kek_raw":
		return true
	default:
		return strings.Contains(key, "private") && strings.Contains(key, "key")
	}
}

func (s *Service) applyKeycoreHSMSyncPolicy(payload map[string]interface{}) (map[string]interface{}, map[string]interface{}) {
	out := cloneMap(payload)
	meta := map[string]interface{}{}

	hsmNonExportable := mapBool(out, "hsm_non_exportable", !mapBool(out, "key_export_allowed", true))
	sourcePartition := mapString(out, "source_hsm_partition_label", "hsm_partition_label")
	sourceMEKInHSM := mapBool(out, "source_mek_in_hsm", false)
	sourceMEKLogicalID := mapString(out, "source_mek_logical_id")

	if hsmNonExportable {
		out["sync_mode"] = "metadata_only"
		out["key_material_sync"] = "metadata_only"
		out["crypto_failover_ready"] = false
		meta["hsm_non_exportable"] = true
		if sourcePartition != "" && s.localHSMPartition != "" && !strings.EqualFold(sourcePartition, s.localHSMPartition) && !s.hsmReplicationShared {
			out["control_plane_only"] = true
			out["hsm_sync_reason"] = "partition_mismatch_without_hsm_replication"
			meta["control_plane_only"] = true
			meta["source_hsm_partition_label"] = sourcePartition
			meta["local_hsm_partition_label"] = s.localHSMPartition
		} else {
			out["control_plane_only"] = false
		}
	}

	if sourceMEKInHSM {
		meta["source_mek_in_hsm"] = true
		out["mek_sync_mode"] = "hsm_wrapped"
		if sourceMEKLogicalID != "" && s.localMEKLogicalID != "" && !strings.EqualFold(sourceMEKLogicalID, s.localMEKLogicalID) {
			out["requires_rewrap"] = true
			out["mek_compatible"] = false
			out["crypto_failover_ready"] = false
			meta["mek_compatible"] = false
			meta["source_mek_logical_id"] = sourceMEKLogicalID
			meta["local_mek_logical_id"] = s.localMEKLogicalID
		} else {
			out["mek_compatible"] = true
		}
	}

	if mapBool(out, "control_plane_only", false) {
		out["replication_expectation"] = "control-plane-only"
	} else if mapBool(out, "mek_compatible", false) || !sourceMEKInHSM {
		out["replication_expectation"] = "metadata-and-policy-realtime"
	}

	return out, meta
}

func cloneMap(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		return map[string]interface{}{}
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mapString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		raw, ok := m[key]
		if !ok || raw == nil {
			continue
		}
		switch v := raw.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		default:
			out := strings.TrimSpace(fmt.Sprint(v))
			if out != "" && out != "<nil>" {
				return out
			}
		}
	}
	return ""
}

func mapBool(m map[string]interface{}, key string, def bool) bool {
	raw, ok := m[key]
	if !ok || raw == nil {
		return def
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		return parseBoolString(v, def)
	default:
		return parseBoolString(fmt.Sprint(v), def)
	}
}

func parseBoolString(v string, def bool) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return def
	}
	switch v {
	case "true", "1", "yes", "y", "on":
		return true
	case "false", "0", "no", "n", "off":
		return false
	default:
		return def
	}
}

func ensureProfileComponents(in []string) []string {
	merged := make([]string, 0, len(in)+len(requiredCoreComponents))
	merged = append(merged, in...)
	merged = append(merged, requiredCoreComponents...)
	return disallowAuditComponent(normalizeComponents(merged))
}

func (s *Service) demoteOtherLeaders(ctx context.Context, tenantID string, selectedNodeID string) error {
	nodes, err := s.store.ListNodes(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		if strings.TrimSpace(node.ID) == "" {
			continue
		}
		if strings.TrimSpace(node.ID) == strings.TrimSpace(selectedNodeID) {
			continue
		}
		if normalizeRole(node.Role) != "leader" {
			continue
		}
		node.Role = "follower"
		if err := s.store.UpsertNode(ctx, node); err != nil {
			return err
		}
		s.appendClusterLog(ctx, ClusterLogEntry{
			TenantID:  tenantID,
			NodeID:    node.ID,
			Level:     "info",
			EventType: "leader_demoted",
			Message:   "existing leader demoted because another node was promoted",
			Details: map[string]interface{}{
				"promoted_node_id": selectedNodeID,
			},
		})
	}
	return nil
}

func builtinClusterProfiles(tenantID string, defaultProfileID string) []ClusterProfile {
	out := make([]ClusterProfile, 0, len(builtinClusterProfilePresets))
	for _, preset := range builtinClusterProfilePresets {
		out = append(out, ClusterProfile{
			ID:          preset.ID,
			TenantID:    tenantID,
			Name:        preset.Name,
			Description: preset.Description,
			Components:  ensureProfileComponents(preset.Components),
			IsDefault:   strings.TrimSpace(preset.ID) == strings.TrimSpace(defaultProfileID),
		})
	}
	return out
}

func builtinClusterProfileByID(tenantID string, profileID string, isDefault bool) (ClusterProfile, bool) {
	profileID = strings.TrimSpace(profileID)
	for _, preset := range builtinClusterProfilePresets {
		if strings.TrimSpace(preset.ID) != profileID {
			continue
		}
		return ClusterProfile{
			ID:          preset.ID,
			TenantID:    tenantID,
			Name:        preset.Name,
			Description: preset.Description,
			Components:  ensureProfileComponents(preset.Components),
			IsDefault:   isDefault,
		}, true
	}
	return ClusterProfile{}, false
}

func (s *Service) seedNodeSyncEvents(ctx context.Context, node ClusterNode, profile ClusterProfile, sourceNodeID string) ([]int64, error) {
	sourceNodeID = strings.TrimSpace(sourceNodeID)
	if sourceNodeID == "" {
		sourceNodeID = s.bootstrapNodeID
	}
	components := normalizeComponents(node.EnabledComponents)
	if len(components) == 0 {
		components = normalizeComponents(profile.Components)
	}
	events := make([]int64, 0, len(components))
	for _, component := range components {
		if component == "audit" {
			continue
		}
		if !componentAllowedForProfile(component, profile.Components) {
			continue
		}
		created, err := s.PublishSyncEvent(ctx, PublishSyncEventInput{
			TenantID:     node.TenantID,
			ProfileID:    profile.ID,
			Component:    component,
			EntityType:   "cluster_node",
			EntityID:     node.ID,
			Operation:    "seed_sync",
			SourceNodeID: sourceNodeID,
			Payload: map[string]interface{}{
				"target_node_id": node.ID,
				"reason":         "node_added",
				"profile_id":     profile.ID,
			},
		})
		if err != nil {
			return events, err
		}
		events = append(events, created.ID)
	}
	return events, nil
}

func (s *Service) emitNodeDecommissionEvents(ctx context.Context, node ClusterNode, profile ClusterProfile, reason string, purgeSyncedData bool) ([]int64, error) {
	components := normalizeComponents(node.EnabledComponents)
	if len(components) == 0 {
		components = normalizeComponents(profile.Components)
	}
	eventIDs := make([]int64, 0, len(components))
	for _, component := range components {
		if component == "audit" {
			continue
		}
		if !componentAllowedForProfile(component, profile.Components) {
			continue
		}
		created, err := s.PublishSyncEvent(ctx, PublishSyncEventInput{
			TenantID:     node.TenantID,
			ProfileID:    profile.ID,
			Component:    component,
			EntityType:   "cluster_node",
			EntityID:     node.ID,
			Operation:    "decommission",
			SourceNodeID: s.bootstrapNodeID,
			Payload: map[string]interface{}{
				"target_node_id":      node.ID,
				"decommissioned":      true,
				"set_standalone":      true,
				"purge_synced_state":  purgeSyncedData,
				"remove_from_cluster": true,
				"reason":              reason,
			},
		})
		if err != nil {
			return eventIDs, err
		}
		eventIDs = append(eventIDs, created.ID)
	}
	return eventIDs, nil
}

func (s *Service) promoteReplacementLeader(ctx context.Context, tenantID string, removingNodeID string) (string, error) {
	nodes, err := s.store.ListNodes(ctx, tenantID)
	if err != nil {
		return "", err
	}
	candidates := make([]ClusterNode, 0, len(nodes))
	for _, node := range nodes {
		if strings.TrimSpace(node.ID) == "" || strings.TrimSpace(node.ID) == strings.TrimSpace(removingNodeID) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(node.JoinState), "revoked") {
			continue
		}
		candidates = append(candidates, node)
	}
	if len(candidates) == 0 {
		return "", nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		return strings.ToLower(strings.TrimSpace(candidates[i].Name)) < strings.ToLower(strings.TrimSpace(candidates[j].Name))
	})
	candidate := candidates[0]
	candidate.Role = "leader"
	if err := s.store.UpsertNode(ctx, candidate); err != nil {
		return "", err
	}
	if err := s.demoteOtherLeaders(ctx, tenantID, candidate.ID); err != nil {
		return "", err
	}
	return candidate.ID, nil
}

func (s *Service) resolvePushTargets(ctx context.Context, tenantID string, profileID string, sourceNodeID string, component string) []string {
	nodes, err := s.store.ListNodes(ctx, tenantID)
	if err != nil {
		return []string{}
	}
	out := make([]string, 0, len(nodes))
	sourceNodeID = strings.TrimSpace(sourceNodeID)
	profileID = strings.TrimSpace(profileID)
	for _, node := range nodes {
		nodeID := strings.TrimSpace(node.ID)
		if nodeID == "" {
			continue
		}
		if sourceNodeID != "" && nodeID == sourceNodeID {
			continue
		}
		joinState := strings.ToLower(strings.TrimSpace(node.JoinState))
		if joinState != "" && joinState != "active" {
			continue
		}
		if normalizeNodeStatus(node.Status) == "down" {
			continue
		}
		if profileID != "" && strings.TrimSpace(node.ProfileID) != "" && strings.TrimSpace(node.ProfileID) != profileID {
			continue
		}
		if !componentAllowedForProfile(component, node.EnabledComponents) {
			continue
		}
		out = append(out, nodeID)
	}
	sort.Strings(out)
	return out
}

func natsSubjectToken(in string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return "unknown"
	}
	var b strings.Builder
	b.Grow(len(in))
	for _, r := range in {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('_')
	}
	out := strings.Trim(strings.TrimSpace(b.String()), ".")
	if out == "" {
		return "unknown"
	}
	return out
}

func disallowAuditComponent(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	for _, item := range in {
		if normalizeComponentName(item) == "audit" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func parseEnvInt64(key string, def int64) int64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func parseEnvBool(key string, def bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return def
	}
	return parseBoolString(raw, def)
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func componentAllowedForProfile(component string, profileComponents []string) bool {
	component = normalizeComponentName(component)
	if component == "audit" {
		return false
	}
	for _, item := range profileComponents {
		if normalizeComponentName(item) == component {
			return true
		}
	}
	return false
}

func errorsIsNotFound(err error) bool {
	return errors.Is(err, errNotFound)
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "cluster-manager",
		"action":    subject,
		"timestamp": s.now().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}
