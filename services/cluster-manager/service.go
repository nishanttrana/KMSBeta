package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	pkgclustersync "vecta-kms/pkg/clustersync"
)

const defaultProfileName = "base-platform"

var requiredCoreComponents = []string{"auth", "keycore", "policy", "governance"}

type Service struct {
	store                Store
	events               EventPublisher
	now                  func() time.Time
	bootstrapNodeID      string
	bootstrapNodeName    string
	bootstrapNodeRole    string
	bootstrapNodeAddress string
	bootstrapProfileID   string
	syncRequireMTLS      bool
	syncSharedSecret     []byte
	syncReplayWindowSec  int64
	localHSMPartition    string
	localMEKInHSM        bool
	localMEKLogicalID    string
	hsmReplicationShared bool
}

func NewService(store Store, events EventPublisher) *Service {
	replayWindowSec := parseEnvInt64("CLUSTER_SYNC_ANTI_REPLAY_SEC", 120)
	if replayWindowSec < 30 {
		replayWindowSec = 30
	}
	return &Service{
		store:                store,
		events:               events,
		now:                  func() time.Time { return time.Now().UTC() },
		bootstrapNodeID:      defaultIfEmpty(os.Getenv("CLUSTER_NODE_ID"), "vecta-kms-01"),
		bootstrapNodeName:    defaultIfEmpty(os.Getenv("CLUSTER_NODE_NAME"), "vecta-kms-01"),
		bootstrapNodeRole:    normalizeRole(defaultIfEmpty(os.Getenv("CLUSTER_NODE_ROLE"), "leader")),
		bootstrapNodeAddress: defaultIfEmpty(os.Getenv("CLUSTER_NODE_ENDPOINT"), "10.0.1.100"),
		bootstrapProfileID:   defaultIfEmpty(os.Getenv("CLUSTER_BOOTSTRAP_PROFILE_ID"), "cluster-profile-base"),
		syncRequireMTLS:      parseEnvBool("CLUSTER_SYNC_REQUIRE_MTLS", false),
		syncSharedSecret:     []byte(strings.TrimSpace(os.Getenv("CLUSTER_SYNC_SHARED_SECRET"))),
		syncReplayWindowSec:  replayWindowSec,
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
		nodes[i].Status = normalizeNodeStatus(nodes[i].Status)
		nodes[i].Role = normalizeRole(nodes[i].Role)
		nodes[i].EnabledComponents = normalizeComponents(nodes[i].EnabledComponents)
	}
	out := ClusterOverview{Nodes: nodes, Profiles: profiles}
	out.SelectiveComponentSync.Enabled = true
	out.SelectiveComponentSync.Note = "Nodes sync only the state for their enabled components."
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
		node.Status = normalizeNodeStatus(node.Status)
		node.EnabledComponents = normalizeComponents(node.EnabledComponents)
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
	node.CPUPercent = in.CPUPercent
	node.RAMGB = in.RAMGB
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
	node.LastHeartbeatAt = s.now()
	if err := s.store.UpsertNode(ctx, node); err != nil {
		return ClusterNode{}, err
	}
	return s.store.GetNode(ctx, in.TenantID, node.ID)
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
	if len(profiles) == 0 {
		defaultProfile := ClusterProfile{
			ID:          s.bootstrapProfileID,
			TenantID:    tenantID,
			Name:        defaultProfileName,
			Description: "Base KMS platform state sync for auth/keycore/policy/governance.",
			Components:  append([]string{}, requiredCoreComponents...),
			IsDefault:   true,
		}
		if err := s.store.UpsertProfile(ctx, defaultProfile); err != nil {
			return err
		}
		if err := s.store.SetDefaultProfile(ctx, tenantID, defaultProfile.ID); err != nil {
			return err
		}
		profiles = []ClusterProfile{defaultProfile}
	}
	defaultProfileID := ""
	for _, profile := range profiles {
		if profile.IsDefault {
			defaultProfileID = profile.ID
			break
		}
	}
	if defaultProfileID == "" {
		defaultProfileID = profiles[0].ID
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
	bootstrapNode := ClusterNode{
		ID:                nodeID,
		TenantID:          tenantID,
		Name:              defaultIfEmpty(s.bootstrapNodeName, nodeID),
		Role:              normalizeRole(s.bootstrapNodeRole),
		Endpoint:          defaultIfEmpty(s.bootstrapNodeAddress, "127.0.0.1"),
		Status:            "online",
		CPUPercent:        0,
		RAMGB:             0,
		EnabledComponents: append([]string{}, requiredCoreComponents...),
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
