package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Service struct {
	store   Store
	keycore KeyCoreClient
	events  EventPublisher
}

func NewService(store Store, keycore KeyCoreClient, events EventPublisher) *Service {
	return &Service{
		store:   store,
		keycore: keycore,
		events:  events,
	}
}

func (s *Service) RegisterAgent(ctx context.Context, req RegisterAgentRequest, tlsClientCN string) (Agent, *TDEKeyRecord, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.AgentID = strings.TrimSpace(req.AgentID)
	req.Name = strings.TrimSpace(req.Name)
	req.Role = normalizeRole(req.Role)
	req.DBEngine = normalizeDBEngine(req.DBEngine)
	req.Host = strings.TrimSpace(req.Host)
	req.Version = strings.TrimSpace(req.Version)
	req.MetadataJSON = validJSONOr(req.MetadataJSON, "{}")
	if req.TenantID == "" {
		return Agent{}, nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if req.AgentID == "" {
		req.AgentID = newID("agent")
	}
	if req.Name == "" {
		req.Name = req.AgentID
	}
	if req.Role == "" {
		req.Role = "ekm-agent"
	}
	if req.DBEngine == "" {
		req.DBEngine = DefaultDBEngine
	}

	existing, err := s.store.GetAgent(ctx, req.TenantID, req.AgentID)
	isNewAgent := false
	switch {
	case err == nil:
	case errors.Is(err, errNotFound):
		isNewAgent = true
	default:
		return Agent{}, nil, err
	}

	configVersion := 1
	configAck := 0
	assignedKeyID := ""
	assignedKeyVersion := ""
	if !isNewAgent {
		configVersion = defaultInt(existing.ConfigVersion, 1)
		configAck = existing.ConfigVersionAck
		assignedKeyID = existing.AssignedKeyID
		assignedKeyVersion = existing.AssignedKeyVersion
	}

	now := time.Now().UTC()
	agent := Agent{
		ID:                   req.AgentID,
		TenantID:             req.TenantID,
		Name:                 req.Name,
		Role:                 req.Role,
		DBEngine:             req.DBEngine,
		Host:                 req.Host,
		Version:              req.Version,
		Status:               AgentStatusConnected,
		TDEState:             normalizeTDEState(existing.TDEState),
		HeartbeatIntervalSec: defaultInt(req.HeartbeatIntervalSec, DefaultHeartbeatSec),
		LastHeartbeatAt:      now,
		AssignedKeyID:        assignedKeyID,
		AssignedKeyVersion:   assignedKeyVersion,
		ConfigVersion:        configVersion,
		ConfigVersionAck:     configAck,
		MetadataJSON:         req.MetadataJSON,
		TLSClientCN:          strings.TrimSpace(tlsClientCN),
	}
	if agent.TDEState == "" {
		agent.TDEState = "unknown"
	}

	var provisioned *TDEKeyRecord
	autoProvision := shouldAuto(req.AutoProvisionTDE, isSQLServerEngine(req.DBEngine))
	if isNewAgent && autoProvision && isSQLServerEngine(req.DBEngine) {
		key, err := s.createTDEKey(ctx, CreateTDEKeyRequest{
			TenantID:        req.TenantID,
			Name:            "tde-agent-" + req.AgentID,
			Algorithm:       DefaultTDEAlgorithm,
			CreatedBy:       "ekm-auto-agent",
			AgentID:         req.AgentID,
			AutoProvisioned: true,
		})
		if err != nil {
			return Agent{}, nil, err
		}
		provisioned = &key
		agent.AssignedKeyID = key.ID
		agent.AssignedKeyVersion = key.CurrentVersion
	}

	if err := s.store.UpsertAgent(ctx, agent); err != nil {
		return Agent{}, nil, err
	}
	out, err := s.store.GetAgent(ctx, req.TenantID, req.AgentID)
	if err != nil {
		return Agent{}, nil, err
	}

	_ = s.publishAudit(ctx, "audit.ekm.agent_registered", req.TenantID, map[string]interface{}{
		"agent_id":        out.ID,
		"role":            out.Role,
		"db_engine":       out.DBEngine,
		"auto_provision":  provisioned != nil,
		"assigned_key_id": out.AssignedKeyID,
		"host":            out.Host,
	})
	return out, provisioned, nil
}

func (s *Service) ListAgents(ctx context.Context, tenantID string) ([]Agent, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	items, err := s.store.ListAgents(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Agent, 0, len(items))
	for _, item := range items {
		refreshed, err := s.refreshAgentConnectivity(ctx, item)
		if err != nil {
			return nil, err
		}
		out = append(out, refreshed)
	}
	return out, nil
}

func (s *Service) GetAgentStatus(ctx context.Context, tenantID string, agentID string) (AgentStatus, error) {
	tenantID = strings.TrimSpace(tenantID)
	agentID = strings.TrimSpace(agentID)
	if tenantID == "" || agentID == "" {
		return AgentStatus{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and agent id are required")
	}
	agent, err := s.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return AgentStatus{}, err
	}
	agent, err = s.refreshAgentConnectivity(ctx, agent)
	if err != nil {
		return AgentStatus{}, err
	}
	dbs, err := s.store.ListDatabases(ctx, tenantID, agentID)
	if err != nil {
		return AgentStatus{}, err
	}
	tdeEnabled := 0
	for _, db := range dbs {
		if db.TDEEnabled {
			tdeEnabled++
		}
	}
	age := int64(0)
	if !agent.LastHeartbeatAt.IsZero() {
		age = int64(time.Since(agent.LastHeartbeatAt.UTC()).Seconds())
		if age < 0 {
			age = 0
		}
	}
	return AgentStatus{
		Agent:               agent,
		ManagedDatabases:    len(dbs),
		TDEEnabledDatabases: tdeEnabled,
		LastHeartbeatAgeSec: age,
	}, nil
}

func (s *Service) AgentHeartbeat(ctx context.Context, agentID string, req AgentHeartbeatRequest, tlsClientCN string) (Agent, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	agentID = strings.TrimSpace(agentID)
	if req.TenantID == "" || agentID == "" {
		return Agent{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and agent id are required")
	}
	status := normalizeAgentStatus(req.Status)
	if status == "" {
		status = AgentStatusConnected
	}
	tdeState := normalizeTDEState(req.TDEState)
	now := time.Now().UTC()
	if err := s.store.UpdateAgentHeartbeat(
		ctx,
		req.TenantID,
		agentID,
		status,
		tdeState,
		strings.TrimSpace(req.ActiveKeyID),
		strings.TrimSpace(req.ActiveKeyVersion),
		req.ConfigVersionAck,
		validJSONOr(req.MetadataJSON, "{}"),
		now,
	); err != nil {
		return Agent{}, err
	}
	agent, err := s.store.GetAgent(ctx, req.TenantID, agentID)
	if err != nil {
		return Agent{}, err
	}
	if strings.TrimSpace(tlsClientCN) != "" {
		agent.TLSClientCN = strings.TrimSpace(tlsClientCN)
		_ = s.store.UpsertAgent(ctx, agent)
	}
	_ = s.publishAudit(ctx, "audit.ekm.agent_heartbeat", req.TenantID, map[string]interface{}{
		"agent_id":           agentID,
		"status":             status,
		"tde_state":          tdeState,
		"active_key_id":      req.ActiveKeyID,
		"active_key_version": req.ActiveKeyVersion,
		"config_version_ack": req.ConfigVersionAck,
	})
	return agent, nil
}

func (s *Service) RegisterDatabase(ctx context.Context, req RegisterDatabaseRequest) (DatabaseInstance, *TDEKeyRecord, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.DatabaseID = strings.TrimSpace(req.DatabaseID)
	req.AgentID = strings.TrimSpace(req.AgentID)
	req.Name = strings.TrimSpace(req.Name)
	req.Engine = normalizeDBEngine(req.Engine)
	req.Host = strings.TrimSpace(req.Host)
	req.DatabaseName = strings.TrimSpace(req.DatabaseName)
	req.TDEState = normalizeTDEState(req.TDEState)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.MetadataJSON = validJSONOr(req.MetadataJSON, "{}")
	if req.TenantID == "" || req.AgentID == "" {
		return DatabaseInstance{}, nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and agent_id are required")
	}
	if req.DatabaseID == "" {
		req.DatabaseID = newID("db")
	}
	if req.Name == "" {
		req.Name = req.DatabaseID
	}
	if req.Engine == "" {
		req.Engine = DefaultDBEngine
	}
	if req.Port <= 0 {
		if isSQLServerEngine(req.Engine) {
			req.Port = 1433
		}
	}
	if req.TDEState == "unknown" {
		if req.TDEEnabled {
			req.TDEState = "enabled"
		} else {
			req.TDEState = "disabled"
		}
	}
	agent, err := s.store.GetAgent(ctx, req.TenantID, req.AgentID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return DatabaseInstance{}, nil, newServiceError(http.StatusNotFound, "agent_not_found", "agent is not registered")
		}
		return DatabaseInstance{}, nil, err
	}

	var provisioned *TDEKeyRecord
	autoProvision := shouldAuto(req.AutoProvisionKey, isSQLServerEngine(req.Engine))
	if req.KeyID == "" && autoProvision && isSQLServerEngine(req.Engine) {
		key, err := s.createTDEKey(ctx, CreateTDEKeyRequest{
			TenantID:        req.TenantID,
			Name:            "tde-db-" + req.DatabaseID,
			Algorithm:       DefaultTDEAlgorithm,
			CreatedBy:       "ekm-auto-database",
			AgentID:         req.AgentID,
			DatabaseID:      req.DatabaseID,
			AutoProvisioned: true,
		})
		if err != nil {
			return DatabaseInstance{}, nil, err
		}
		req.KeyID = key.ID
		provisioned = &key
	}
	if req.KeyID != "" {
		if _, err := s.store.GetTDEKey(ctx, req.TenantID, req.KeyID); err != nil {
			if errors.Is(err, errNotFound) {
				return DatabaseInstance{}, nil, newServiceError(http.StatusNotFound, "key_not_found", "tde key not found")
			}
			return DatabaseInstance{}, nil, err
		}
	}

	dbi := DatabaseInstance{
		ID:              req.DatabaseID,
		TenantID:        req.TenantID,
		AgentID:         req.AgentID,
		Name:            req.Name,
		Engine:          req.Engine,
		Host:            req.Host,
		Port:            req.Port,
		DatabaseName:    req.DatabaseName,
		TDEEnabled:      req.TDEEnabled,
		TDEState:        req.TDEState,
		KeyID:           req.KeyID,
		AutoProvisioned: provisioned != nil,
		MetadataJSON:    req.MetadataJSON,
		LastSeenAt:      time.Now().UTC(),
	}
	if err := s.store.UpsertDatabase(ctx, dbi); err != nil {
		return DatabaseInstance{}, nil, err
	}
	if req.KeyID != "" && (agent.AssignedKeyID != req.KeyID || strings.TrimSpace(agent.AssignedKeyVersion) == "") {
		_ = s.store.BumpAgentConfigVersion(ctx, req.TenantID, req.AgentID, req.KeyID, "")
		_ = s.publishAudit(ctx, "audit.ekm.agent_config_updated", req.TenantID, map[string]interface{}{
			"agent_id":    req.AgentID,
			"database_id": req.DatabaseID,
			"key_id":      req.KeyID,
			"reason":      "database_registration",
		})
	}
	out, err := s.store.GetDatabase(ctx, req.TenantID, req.DatabaseID)
	if err != nil {
		return DatabaseInstance{}, nil, err
	}
	return out, provisioned, nil
}

func (s *Service) ListDatabases(ctx context.Context, tenantID string, agentID string) ([]DatabaseInstance, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	return s.store.ListDatabases(ctx, tenantID, strings.TrimSpace(agentID))
}

func (s *Service) GetDatabase(ctx context.Context, tenantID string, databaseID string) (DatabaseInstance, error) {
	tenantID = strings.TrimSpace(tenantID)
	databaseID = strings.TrimSpace(databaseID)
	if tenantID == "" || databaseID == "" {
		return DatabaseInstance{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and database id are required")
	}
	return s.store.GetDatabase(ctx, tenantID, databaseID)
}

func (s *Service) CreateTDEKey(ctx context.Context, req CreateTDEKeyRequest) (TDEKeyRecord, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return TDEKeyRecord{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	return s.createTDEKey(ctx, req)
}

func (s *Service) createTDEKey(ctx context.Context, req CreateTDEKeyRequest) (TDEKeyRecord, error) {
	if s.keycore == nil {
		return TDEKeyRecord{}, newServiceError(http.StatusFailedDependency, "keycore_unavailable", "keycore client is not configured")
	}
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Name = strings.TrimSpace(req.Name)
	req.Algorithm = strings.TrimSpace(req.Algorithm)
	req.CreatedBy = strings.TrimSpace(req.CreatedBy)
	req.AgentID = strings.TrimSpace(req.AgentID)
	req.DatabaseID = strings.TrimSpace(req.DatabaseID)
	req.MetadataJSON = validJSONOr(req.MetadataJSON, "{}")
	if req.Name == "" {
		req.Name = "ekm-tde-" + newID("key")
	}
	if req.Algorithm == "" {
		req.Algorithm = DefaultTDEAlgorithm
	}
	if req.CreatedBy == "" {
		req.CreatedBy = "ekm"
	}

	keyID, err := s.keycore.CreateAsymmetricKey(ctx, req.TenantID, req.Name, req.Algorithm, map[string]string{
		"service": "ekm",
		"use":     "tde",
	})
	if err != nil {
		return TDEKeyRecord{}, newServiceError(http.StatusBadGateway, "keycore_create_failed", err.Error())
	}
	meta, err := s.keycore.GetKey(ctx, req.TenantID, keyID)
	if err != nil {
		return TDEKeyRecord{}, newServiceError(http.StatusBadGateway, "keycore_get_failed", err.Error())
	}
	version := "v1"
	if v := extractInt(meta["current_version"]); v > 0 {
		version = "v" + strconvItoa(v)
	}
	publicKey := strings.TrimSpace(firstString(meta["public_key_pem"], meta["public_key"]))
	format := "opaque"
	if strings.Contains(publicKey, "BEGIN") {
		format = "pem"
	}
	if publicKey == "" {
		publicKey = buildPublicKeyFallback(req.TenantID, keyID)
	}

	key := TDEKeyRecord{
		ID:              keyID,
		TenantID:        req.TenantID,
		KeyCoreKeyID:    keyID,
		Name:            req.Name,
		Algorithm:       defaultString(firstString(meta["algorithm"]), req.Algorithm),
		Status:          "active",
		CurrentVersion:  version,
		PublicKey:       publicKey,
		PublicKeyFormat: format,
		CreatedBy:       req.CreatedBy,
		AutoProvisioned: req.AutoProvisioned,
		MetadataJSON:    req.MetadataJSON,
	}
	if err := s.store.CreateTDEKey(ctx, key); err != nil {
		return TDEKeyRecord{}, err
	}
	out, err := s.store.GetTDEKey(ctx, req.TenantID, keyID)
	if err != nil {
		return TDEKeyRecord{}, err
	}
	_ = s.publishAudit(ctx, "audit.ekm.tde_key_provisioned", req.TenantID, map[string]interface{}{
		"key_id":           out.ID,
		"keycore_key_id":   out.KeyCoreKeyID,
		"algorithm":        out.Algorithm,
		"created_by":       out.CreatedBy,
		"auto_provisioned": out.AutoProvisioned,
		"agent_id":         req.AgentID,
		"database_id":      req.DatabaseID,
	})
	if req.AgentID != "" {
		if err := s.store.BumpAgentConfigVersion(ctx, req.TenantID, req.AgentID, out.ID, out.CurrentVersion); err == nil {
			_ = s.publishAudit(ctx, "audit.ekm.agent_config_updated", req.TenantID, map[string]interface{}{
				"agent_id":    req.AgentID,
				"key_id":      out.ID,
				"key_version": out.CurrentVersion,
				"reason":      "key_provisioned",
			})
		}
	}
	return out, nil
}

func (s *Service) WrapDEK(ctx context.Context, keyID string, req WrapDEKRequest) (WrapDEKResponse, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	keyID = strings.TrimSpace(keyID)
	if req.TenantID == "" || keyID == "" {
		return WrapDEKResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key id are required")
	}
	if s.keycore == nil {
		return WrapDEKResponse{}, newServiceError(http.StatusFailedDependency, "keycore_unavailable", "keycore client is not configured")
	}
	plainRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PlaintextB64))
	if err != nil || len(plainRaw) == 0 {
		return WrapDEKResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "plaintext must be non-empty base64")
	}
	// Security: plaintext DEK is decoded for validation and zeroized immediately after request dispatch.
	defer pkgcrypto.Zeroize(plainRaw)

	key, err := s.store.GetTDEKey(ctx, req.TenantID, keyID)
	if err != nil {
		return WrapDEKResponse{}, err
	}
	out, err := s.keycore.Wrap(ctx, req.TenantID, key.KeyCoreKeyID, req.PlaintextB64, req.IVB64, req.ReferenceID)
	if err != nil {
		_ = s.store.RecordKeyAccess(ctx, KeyAccessLog{
			ID:           newID("kacc"),
			TenantID:     req.TenantID,
			KeyID:        keyID,
			AgentID:      strings.TrimSpace(req.AgentID),
			DatabaseID:   strings.TrimSpace(req.DatabaseID),
			Operation:    "wrap",
			Status:       "failed",
			ErrorMessage: err.Error(),
			CreatedAt:    time.Now().UTC(),
		})
		return WrapDEKResponse{}, newServiceError(http.StatusBadGateway, "keycore_wrap_failed", err.Error())
	}
	_ = s.store.TouchTDEKeyAccess(ctx, req.TenantID, keyID, time.Now().UTC())
	_ = s.store.RecordKeyAccess(ctx, KeyAccessLog{
		ID:         newID("kacc"),
		TenantID:   req.TenantID,
		KeyID:      keyID,
		AgentID:    strings.TrimSpace(req.AgentID),
		DatabaseID: strings.TrimSpace(req.DatabaseID),
		Operation:  "wrap",
		Status:     "success",
		CreatedAt:  time.Now().UTC(),
	})
	_ = s.publishAudit(ctx, "audit.ekm.tde_key_accessed", req.TenantID, map[string]interface{}{
		"key_id":      keyID,
		"operation":   "wrap",
		"agent_id":    req.AgentID,
		"database_id": req.DatabaseID,
	})
	return WrapDEKResponse{
		KeyID:         strings.TrimSpace(firstString(out["key_id"], keyID)),
		Version:       extractInt(out["version"]),
		CiphertextB64: strings.TrimSpace(firstString(out["ciphertext"])),
		IVB64:         strings.TrimSpace(firstString(out["iv"])),
	}, nil
}

func (s *Service) UnwrapDEK(ctx context.Context, keyID string, req UnwrapDEKRequest) (UnwrapDEKResponse, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	keyID = strings.TrimSpace(keyID)
	if req.TenantID == "" || keyID == "" {
		return UnwrapDEKResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key id are required")
	}
	if s.keycore == nil {
		return UnwrapDEKResponse{}, newServiceError(http.StatusFailedDependency, "keycore_unavailable", "keycore client is not configured")
	}
	cipherRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.CiphertextB64))
	if err != nil || len(cipherRaw) == 0 {
		return UnwrapDEKResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "ciphertext must be non-empty base64")
	}
	// Security: ciphertext buffer is short-lived and explicitly zeroized after call.
	defer pkgcrypto.Zeroize(cipherRaw)

	key, err := s.store.GetTDEKey(ctx, req.TenantID, keyID)
	if err != nil {
		return UnwrapDEKResponse{}, err
	}
	out, err := s.keycore.Unwrap(ctx, req.TenantID, key.KeyCoreKeyID, req.CiphertextB64, req.IVB64)
	if err != nil {
		_ = s.store.RecordKeyAccess(ctx, KeyAccessLog{
			ID:           newID("kacc"),
			TenantID:     req.TenantID,
			KeyID:        keyID,
			AgentID:      strings.TrimSpace(req.AgentID),
			DatabaseID:   strings.TrimSpace(req.DatabaseID),
			Operation:    "unwrap",
			Status:       "failed",
			ErrorMessage: err.Error(),
			CreatedAt:    time.Now().UTC(),
		})
		return UnwrapDEKResponse{}, newServiceError(http.StatusBadGateway, "keycore_unwrap_failed", err.Error())
	}
	plaintextB64 := strings.TrimSpace(firstString(out["plaintext"]))
	if plainRaw, err := base64.StdEncoding.DecodeString(plaintextB64); err == nil {
		defer pkgcrypto.Zeroize(plainRaw)
	}
	_ = s.store.TouchTDEKeyAccess(ctx, req.TenantID, keyID, time.Now().UTC())
	_ = s.store.RecordKeyAccess(ctx, KeyAccessLog{
		ID:         newID("kacc"),
		TenantID:   req.TenantID,
		KeyID:      keyID,
		AgentID:    strings.TrimSpace(req.AgentID),
		DatabaseID: strings.TrimSpace(req.DatabaseID),
		Operation:  "unwrap",
		Status:     "success",
		CreatedAt:  time.Now().UTC(),
	})
	_ = s.publishAudit(ctx, "audit.ekm.tde_key_accessed", req.TenantID, map[string]interface{}{
		"key_id":      keyID,
		"operation":   "unwrap",
		"agent_id":    req.AgentID,
		"database_id": req.DatabaseID,
	})
	return UnwrapDEKResponse{
		KeyID:        strings.TrimSpace(firstString(out["key_id"], keyID)),
		Version:      extractInt(out["version"]),
		PlaintextB64: plaintextB64,
	}, nil
}

func (s *Service) RotateTDEKey(ctx context.Context, keyID string, req RotateTDEKeyRequest) (RotateTDEKeyResponse, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	keyID = strings.TrimSpace(keyID)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.TenantID == "" || keyID == "" {
		return RotateTDEKeyResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key id are required")
	}
	if s.keycore == nil {
		return RotateTDEKeyResponse{}, newServiceError(http.StatusFailedDependency, "keycore_unavailable", "keycore client is not configured")
	}
	key, err := s.store.GetTDEKey(ctx, req.TenantID, keyID)
	if err != nil {
		return RotateTDEKeyResponse{}, err
	}
	if req.Reason == "" {
		req.Reason = "scheduled"
	}
	out, err := s.keycore.RotateKey(ctx, req.TenantID, key.KeyCoreKeyID, req.Reason)
	if err != nil {
		return RotateTDEKeyResponse{}, newServiceError(http.StatusBadGateway, "keycore_rotate_failed", err.Error())
	}
	versionID := strings.TrimSpace(firstString(out["version_id"]))
	if versionID == "" {
		v := extractInt(out["version"])
		if v <= 0 {
			v = extractInt(out["current_version"])
		}
		if v <= 0 {
			v = parseVersionID(key.CurrentVersion) + 1
		}
		if v <= 0 {
			v = 2
		}
		versionID = "v" + strconvItoa(v)
	}
	if err := s.store.UpdateTDEKeyRotation(ctx, req.TenantID, keyID, versionID, time.Now().UTC()); err != nil {
		return RotateTDEKeyResponse{}, err
	}
	dbs, err := s.store.ListDatabasesByKey(ctx, req.TenantID, keyID)
	if err != nil {
		return RotateTDEKeyResponse{}, err
	}
	seen := map[string]struct{}{}
	affected := make([]string, 0)
	for _, db := range dbs {
		aid := strings.TrimSpace(db.AgentID)
		if aid == "" {
			continue
		}
		if _, ok := seen[aid]; ok {
			continue
		}
		seen[aid] = struct{}{}
		if err := s.store.BumpAgentConfigVersion(ctx, req.TenantID, aid, keyID, versionID); err == nil {
			affected = append(affected, aid)
			_ = s.publishAudit(ctx, "audit.ekm.agent_config_updated", req.TenantID, map[string]interface{}{
				"agent_id":    aid,
				"key_id":      keyID,
				"key_version": versionID,
				"reason":      "key_rotated",
			})
		}
	}
	_ = s.publishAudit(ctx, "audit.ekm.tde_key_rotated", req.TenantID, map[string]interface{}{
		"key_id":             keyID,
		"version_id":         versionID,
		"reason":             req.Reason,
		"affected_agent_ids": affected,
	})
	return RotateTDEKeyResponse{
		KeyID:            keyID,
		VersionID:        versionID,
		AffectedAgentIDs: affected,
	}, nil
}

func (s *Service) GetTDEPublicKey(ctx context.Context, tenantID string, keyID string) (PublicKeyResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	keyID = strings.TrimSpace(keyID)
	if tenantID == "" || keyID == "" {
		return PublicKeyResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key id are required")
	}
	key, err := s.store.GetTDEKey(ctx, tenantID, keyID)
	if err != nil {
		return PublicKeyResponse{}, err
	}

	publicKey := strings.TrimSpace(key.PublicKey)
	format := strings.TrimSpace(key.PublicKeyFormat)
	algorithm := strings.TrimSpace(key.Algorithm)
	version := strings.TrimSpace(key.CurrentVersion)
	if publicKey == "" {
		if s.keycore != nil {
			meta, err := s.keycore.GetKey(ctx, tenantID, key.KeyCoreKeyID)
			if err == nil {
				publicKey = strings.TrimSpace(firstString(meta["public_key_pem"], meta["public_key"]))
				algorithm = defaultString(firstString(meta["algorithm"]), algorithm)
				if v := extractInt(meta["current_version"]); v > 0 {
					version = "v" + strconvItoa(v)
				}
			}
		}
		if publicKey == "" {
			publicKey = buildPublicKeyFallback(tenantID, keyID)
		}
		if strings.Contains(publicKey, "BEGIN") {
			format = "pem"
		}
		if format == "" {
			format = "opaque"
		}
		_ = s.store.UpdateTDEKeyMetadata(ctx, tenantID, keyID, publicKey, format, "")
	}
	if version == "" {
		version = "v1"
	}
	if format == "" {
		format = "opaque"
	}
	_ = s.store.TouchTDEKeyAccess(ctx, tenantID, keyID, time.Now().UTC())
	_ = s.store.RecordKeyAccess(ctx, KeyAccessLog{
		ID:        newID("kacc"),
		TenantID:  tenantID,
		KeyID:     keyID,
		Operation: "public",
		Status:    "success",
		CreatedAt: time.Now().UTC(),
	})
	_ = s.publishAudit(ctx, "audit.ekm.tde_key_accessed", tenantID, map[string]interface{}{
		"key_id":    keyID,
		"operation": "public",
	})
	return PublicKeyResponse{
		KeyID:      keyID,
		Algorithm:  defaultString(algorithm, key.Algorithm),
		PublicKey:  publicKey,
		Format:     format,
		KeyVersion: version,
	}, nil
}

func (s *Service) GetAgentHealth(ctx context.Context, tenantID string, agentID string) (AgentHealthStatus, error) {
	tenantID = strings.TrimSpace(tenantID)
	agentID = strings.TrimSpace(agentID)
	if tenantID == "" || agentID == "" {
		return AgentHealthStatus{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and agent id are required")
	}
	agent, err := s.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return AgentHealthStatus{}, err
	}
	agent, err = s.refreshAgentConnectivity(ctx, agent)
	if err != nil {
		return AgentHealthStatus{}, err
	}
	ageSec := int64(0)
	if !agent.LastHeartbeatAt.IsZero() {
		ageSec = int64(time.Since(agent.LastHeartbeatAt.UTC()).Seconds())
		if ageSec < 0 {
			ageSec = 0
		}
	}
	meta := parseJSONMap(agent.MetadataJSON)
	metrics := AgentOSMetrics{
		Hostname:        defaultString(mapStringAny(meta, "hostname", "host_name", "os_hostname"), agent.Host),
		OSName:          mapStringAny(meta, "os_name", "os", "platform"),
		OSVersion:       mapStringAny(meta, "os_version", "platform_version", "version"),
		Kernel:          mapStringAny(meta, "kernel", "kernel_version"),
		Arch:            mapStringAny(meta, "arch", "architecture"),
		CPUUsagePct:     mapFloatAny(meta, "cpu_usage_pct", "cpu_pct", "cpu_percent"),
		MemoryUsagePct:  mapFloatAny(meta, "memory_usage_pct", "memory_pct", "mem_pct"),
		DiskUsagePct:    mapFloatAny(meta, "disk_usage_pct", "disk_pct"),
		Load1:           mapFloatAny(meta, "load_1", "load1"),
		UptimeSec:       mapInt64Any(meta, "uptime_sec", "uptime_seconds"),
		AgentRuntimeSec: mapInt64Any(meta, "agent_runtime_sec"),
	}
	warnings := make([]string, 0)
	health := "healthy"
	if normalizeAgentStatus(agent.Status) == AgentStatusDisconnected {
		health = "down"
		warnings = append(warnings, "heartbeat timed out")
	}
	if metrics.CPUUsagePct >= 90 {
		health = "degraded"
		warnings = append(warnings, fmt.Sprintf("cpu high (%.1f%%)", metrics.CPUUsagePct))
	}
	if metrics.MemoryUsagePct >= 90 {
		health = "degraded"
		warnings = append(warnings, fmt.Sprintf("memory high (%.1f%%)", metrics.MemoryUsagePct))
	}
	if metrics.DiskUsagePct >= 90 {
		health = "degraded"
		warnings = append(warnings, fmt.Sprintf("disk high (%.1f%%)", metrics.DiskUsagePct))
	}
	if normalizeAgentStatus(agent.Status) == AgentStatusDegraded {
		health = "degraded"
	}
	if normalizeAgentStatus(agent.Status) == AgentStatusDisconnected {
		health = "down"
	}
	if len(warnings) == 0 {
		warnings = []string{"all health checks within threshold"}
	}
	return AgentHealthStatus{
		Agent:               agent,
		Health:              health,
		LastHeartbeatAgeSec: ageSec,
		Metrics:             metrics,
		Warnings:            warnings,
	}, nil
}

func (s *Service) ListAgentLogs(ctx context.Context, tenantID string, agentID string, limit int) ([]KeyAccessLog, error) {
	tenantID = strings.TrimSpace(tenantID)
	agentID = strings.TrimSpace(agentID)
	if tenantID == "" || agentID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and agent id are required")
	}
	if _, err := s.store.GetAgent(ctx, tenantID, agentID); err != nil {
		return nil, err
	}
	return s.store.ListKeyAccessByAgent(ctx, tenantID, agentID, limit)
}

func (s *Service) RotateAgentAssignedKey(ctx context.Context, tenantID string, agentID string, reason string) (RotateTDEKeyResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	agentID = strings.TrimSpace(agentID)
	if tenantID == "" || agentID == "" {
		return RotateTDEKeyResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and agent id are required")
	}
	agent, err := s.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return RotateTDEKeyResponse{}, err
	}
	keyID := strings.TrimSpace(agent.AssignedKeyID)
	if keyID == "" {
		dbs, err := s.store.ListDatabases(ctx, tenantID, agentID)
		if err != nil {
			return RotateTDEKeyResponse{}, err
		}
		for _, db := range dbs {
			if strings.TrimSpace(db.KeyID) != "" {
				keyID = strings.TrimSpace(db.KeyID)
				break
			}
		}
	}
	if keyID == "" {
		return RotateTDEKeyResponse{}, newServiceError(http.StatusBadRequest, "no_assigned_key", "agent has no assigned TDE key to rotate")
	}
	out, err := s.RotateTDEKey(ctx, keyID, RotateTDEKeyRequest{
		TenantID: tenantID,
		Reason:   defaultString(reason, "agent-initiated"),
	})
	if err != nil {
		return RotateTDEKeyResponse{}, err
	}
	_ = s.store.BumpAgentConfigVersion(ctx, tenantID, agentID, keyID, out.VersionID)
	return out, nil
}

func (s *Service) DeleteAgent(ctx context.Context, tenantID string, agentID string, reason string) (DeleteAgentResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	agentID = strings.TrimSpace(agentID)
	reason = strings.TrimSpace(reason)
	if tenantID == "" || agentID == "" {
		return DeleteAgentResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and agent id are required")
	}
	if reason == "" {
		reason = "manual-delete"
	}

	agent, err := s.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return DeleteAgentResponse{}, newServiceError(http.StatusNotFound, "agent_not_found", "agent is not registered")
		}
		return DeleteAgentResponse{}, err
	}

	dbs, err := s.store.ListDatabases(ctx, tenantID, agentID)
	if err != nil {
		return DeleteAgentResponse{}, err
	}

	keySeen := map[string]struct{}{}
	keyIDs := make([]string, 0, len(dbs)+1)
	addKey := func(v string) {
		id := strings.TrimSpace(v)
		if id == "" {
			return
		}
		if _, ok := keySeen[id]; ok {
			return
		}
		keySeen[id] = struct{}{}
		keyIDs = append(keyIDs, id)
	}
	addKey(agent.AssignedKeyID)
	for _, dbi := range dbs {
		addKey(dbi.KeyID)
	}

	if len(keyIDs) > 0 && s.keycore == nil {
		return DeleteAgentResponse{}, newServiceError(http.StatusFailedDependency, "keycore_unavailable", "cannot delete agent keys because keycore client is not configured")
	}

	deletedKeyIDs := make([]string, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		keyRec, getErr := s.store.GetTDEKey(ctx, tenantID, keyID)
		if getErr != nil {
			if errors.Is(getErr, errNotFound) {
				continue
			}
			return DeleteAgentResponse{}, getErr
		}
		keyName := strings.TrimSpace(keyRec.Name)
		if keyName == "" {
			keyName = keyID
		}
		keyCoreID := strings.TrimSpace(keyRec.KeyCoreKeyID)
		if keyCoreID == "" {
			keyCoreID = keyID
		}
		if err := s.keycore.DestroyKeyImmediately(
			ctx,
			tenantID,
			keyCoreID,
			keyName,
			"ekm agent delete: "+agentID+" reason="+reason,
		); err != nil {
			msg := strings.ToLower(strings.TrimSpace(err.Error()))
			if !strings.Contains(msg, "not found") && !strings.Contains(msg, "already deleted") {
				return DeleteAgentResponse{}, newServiceError(http.StatusBadGateway, "key_destroy_failed", err.Error())
			}
		}
		deletedKeyIDs = append(deletedKeyIDs, keyID)
		_ = s.publishAudit(ctx, "audit.ekm.tde_key_deleted", tenantID, map[string]interface{}{
			"agent_id":       agentID,
			"key_id":         keyID,
			"keycore_key_id": keyCoreID,
			"reason":         reason,
		})
	}

	for _, dbi := range dbs {
		_ = s.publishAudit(ctx, "audit.ekm.database_deleted", tenantID, map[string]interface{}{
			"agent_id":    agentID,
			"database_id": dbi.ID,
			"name":        dbi.Name,
			"engine":      dbi.Engine,
			"key_id":      dbi.KeyID,
			"reason":      reason,
		})
	}

	deletedDB, deletedKeys, deletedLogs, err := s.store.PurgeAgent(ctx, tenantID, agentID, keyIDs)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return DeleteAgentResponse{}, newServiceError(http.StatusNotFound, "agent_not_found", "agent is not registered")
		}
		return DeleteAgentResponse{}, err
	}

	resp := DeleteAgentResponse{
		AgentID:         agentID,
		DeletedDatabase: deletedDB,
		DeletedKeys:     deletedKeys,
		DeletedLogs:     deletedLogs,
		DeletedKeyIDs:   deletedKeyIDs,
	}
	_ = s.publishAudit(ctx, "audit.ekm.agent_deleted", tenantID, map[string]interface{}{
		"agent_id":           agentID,
		"agent_name":         agent.Name,
		"reason":             reason,
		"deleted_databases":  deletedDB,
		"deleted_keys":       deletedKeys,
		"deleted_logs":       deletedLogs,
		"deleted_key_ids":    deletedKeyIDs,
		"deleted_db_records": len(dbs),
	})
	return resp, nil
}

func (s *Service) BuildAgentDeployPackage(ctx context.Context, tenantID string, agentID string, targetOS string) (DeployPackage, error) {
	tenantID = strings.TrimSpace(tenantID)
	agentID = strings.TrimSpace(agentID)
	targetOS = normalizeTargetOS(targetOS)
	if tenantID == "" || agentID == "" || targetOS == "" {
		return DeployPackage{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, agent id, and target os are required")
	}
	agent, err := s.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return DeployPackage{}, err
	}
	rotation := int(mapInt64Any(parseJSONMap(agent.MetadataJSON), "rotation_cycle_days"))
	if rotation <= 0 {
		rotation = 90
	}
	pkcs11ModuleHint := "/usr/lib/softhsm/libsofthsm2.so"
	if targetOS == "windows" {
		pkcs11ModuleHint = "C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll"
	}
	engine := normalizeDBEngine(agent.DBEngine)
	if engine == "" {
		engine = DefaultDBEngine
	}

	envFile := strings.TrimSpace(fmt.Sprintf(`TENANT_ID=%s
AGENT_ID=%s
AGENT_NAME=%s
DB_ENGINE=%s
AGENT_HOST=%s
HEARTBEAT_INTERVAL_SEC=%d
ROTATION_CYCLE_DAYS=%d
PKCS11_MODULE_PATH=%s
PKCS11_SLOT_ID=0
PKCS11_PIN_ENV=PKCS11_PIN
EKM_API_BASE_URL=https://kms.example.com/svc/ekm
EKM_REGISTER_PATH=/ekm/agents/register
EKM_HEARTBEAT_PATH=/ekm/agents/%s/heartbeat
EKM_ROTATE_PATH=/ekm/agents/%s/rotate
`, tenantID, agent.ID, agent.Name, engine, defaultString(agent.Host, "127.0.0.1"), defaultInt(agent.HeartbeatIntervalSec, DefaultHeartbeatSec), rotation, pkcs11ModuleHint, agent.ID, agent.ID))

	pkcs11Cfg := `provider = "pkcs11"
module_path = "${PKCS11_MODULE_PATH}"
slot_id = "${PKCS11_SLOT_ID}"
pin_env = "${PKCS11_PIN_ENV}"
key_usage = "tde"
`
	linuxHeartbeat := `#!/usr/bin/env bash
set -euo pipefail
source /etc/vecta-ekm/agent.env
CPU=$(awk -v FS=" " '/^cpu /{u=$2+$4;s=$5} END {if ((u+s)>0) printf("%.2f", (u/(u+s))*100); else print "0"}' /proc/stat || echo "0")
MEM=$(free | awk '/Mem:/ {if ($2>0) printf("%.2f", ($3/$2)*100); else print "0"}' || echo "0")
DISK=$(df -P / | awk 'NR==2 {gsub("%","",$5); print $5}' || echo "0")
UP=$(cut -d. -f1 /proc/uptime || echo "0")
HOST=$(hostname | tr -dc 'a-zA-Z0-9._-')
OS=$(uname -s | tr -dc 'a-zA-Z0-9._-')
META=$(printf '{"hostname":"%s","os_name":"%s","cpu_usage_pct":%s,"memory_usage_pct":%s,"disk_usage_pct":%s,"uptime_sec":%s}' "$HOST" "$OS" "$CPU" "$MEM" "$DISK" "$UP")
BODY=$(printf '{"tenant_id":"%s","status":"connected","tde_state":"enabled","active_key_id":"%s","active_key_version":"%s","metadata_json":"%s"}' "$TENANT_ID" "${ACTIVE_KEY_ID:-}" "${ACTIVE_KEY_VERSION:-}" "$(printf '%s' "$META" | sed 's/"/\\"/g')")
curl -fsS -X POST "$EKM_API_BASE_URL$EKM_HEARTBEAT_PATH" -H "Content-Type: application/json" -d "$BODY" >/dev/null
`
	windowsHeartbeat := `$ErrorActionPreference = "Stop"
$envFile = "C:\vecta-ekm\agent.env"
$lines = Get-Content -Path $envFile
$cfg = @{}
foreach ($line in $lines) {
  if ($line -match "^[A-Za-z_][A-Za-z0-9_]*=") {
    $idx = $line.IndexOf("=")
    $k = $line.Substring(0, $idx)
    $v = $line.Substring($idx + 1)
    $cfg[$k] = $v
  }
}
$cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue
$mem = (Get-Counter '\Memory\% Committed Bytes In Use').CounterSamples[0].CookedValue
$disk = (Get-Counter '\LogicalDisk(_Total)\% Free Space').CounterSamples[0].CookedValue
$diskUsed = [Math]::Max(0, (100 - $disk))
$uptime = [int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds
$meta = @{
  hostname = $env:COMPUTERNAME
  os_name = "windows"
  cpu_usage_pct = [Math]::Round($cpu,2)
  memory_usage_pct = [Math]::Round($mem,2)
  disk_usage_pct = [Math]::Round($diskUsed,2)
  uptime_sec = $uptime
} | ConvertTo-Json -Compress
$body = @{
  tenant_id = $cfg["TENANT_ID"]
  status = "connected"
  tde_state = "enabled"
  active_key_id = $cfg["ACTIVE_KEY_ID"]
  active_key_version = $cfg["ACTIVE_KEY_VERSION"]
  metadata_json = $meta
} | ConvertTo-Json -Compress
Invoke-RestMethod -Method Post -Uri ($cfg["EKM_API_BASE_URL"] + $cfg["EKM_HEARTBEAT_PATH"]) -ContentType "application/json" -Body $body | Out-Null
`
	linuxInstall := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
mkdir -p /etc/vecta-ekm
cat > /etc/vecta-ekm/agent.env <<'EOF'
%s
EOF
cat > /etc/vecta-ekm/pkcs11.conf <<'EOF'
%s
EOF
cat > /etc/vecta-ekm/heartbeat.sh <<'EOF'
%s
EOF
chmod 750 /etc/vecta-ekm/heartbeat.sh
echo "Install vecta-ekm-agent binary and systemd service next."
echo "Then run: systemctl daemon-reload && systemctl enable --now vecta-ekm-agent"
echo "Schedule health heartbeat every 30s (systemd timer or cron) using /etc/vecta-ekm/heartbeat.sh"
`, envFile, pkcs11Cfg, linuxHeartbeat)
	windowsInstall := fmt.Sprintf(`$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path "C:\vecta-ekm" | Out-Null
@"
%s
"@ | Set-Content -Path "C:\vecta-ekm\agent.env" -Encoding UTF8
@"
%s
"@ | Set-Content -Path "C:\vecta-ekm\pkcs11.conf" -Encoding UTF8
@"
%s
"@ | Set-Content -Path "C:\vecta-ekm\heartbeat.ps1" -Encoding UTF8
Write-Host "Install vecta-ekm-agent.exe and create Windows service (NSSM/sc.exe)."
Write-Host "Schedule heartbeat.ps1 in Windows Task Scheduler every 30 seconds."
`, strings.ReplaceAll(envFile, "\n", "\r\n"), strings.ReplaceAll(pkcs11Cfg, "\n", "\r\n"), strings.ReplaceAll(windowsHeartbeat, "\n", "\r\n"))

	files := []DeployPackageFile{
		{Path: "agent.env", Content: envFile, Mode: "0600"},
		{Path: "pkcs11.conf", Content: pkcs11Cfg, Mode: "0600"},
		{Path: "heartbeat.sh", Content: linuxHeartbeat, Mode: "0750"},
		{Path: "heartbeat.ps1", Content: windowsHeartbeat, Mode: "0644"},
	}
	if targetOS == "linux" {
		files = append(files, DeployPackageFile{Path: "install.sh", Content: linuxInstall, Mode: "0750"})
	} else {
		files = append(files, DeployPackageFile{Path: "install.ps1", Content: windowsInstall, Mode: "0644"})
	}

	pkg := DeployPackage{
		AgentID:             agent.ID,
		Name:                agent.Name,
		DBEngine:            engine,
		TargetOS:            targetOS,
		CreatedAt:           time.Now().UTC(),
		PKCS11Provider:      "PKCS#11",
		HeartbeatPath:       "/ekm/agents/" + agent.ID + "/heartbeat",
		RegisterPath:        "/ekm/agents/register",
		RotatePath:          "/ekm/agents/" + agent.ID + "/rotate",
		SupportedDatabases:  []string{"mssql", "oracle"},
		RecommendedProfiles: []string{"mssql-tde-pkcs11", "oracle-tde-pkcs11"},
		Files:               files,
	}
	_ = s.publishAudit(ctx, "audit.ekm.deploy_package_generated", tenantID, map[string]interface{}{
		"agent_id":  agent.ID,
		"target_os": targetOS,
		"db_engine": engine,
	})
	return pkg, nil
}

func (s *Service) refreshAgentConnectivity(ctx context.Context, agent Agent) (Agent, error) {
	if agent.LastHeartbeatAt.IsZero() {
		return agent, nil
	}
	timeout := heartbeatTimeout(agent)
	if time.Since(agent.LastHeartbeatAt.UTC()) > timeout && normalizeAgentStatus(agent.Status) != AgentStatusDisconnected {
		if err := s.store.MarkAgentDisconnected(ctx, agent.TenantID, agent.ID, time.Now().UTC()); err != nil {
			return Agent{}, err
		}
		agent.Status = AgentStatusDisconnected
		_ = s.publishAudit(ctx, "audit.ekm.agent_disconnected", agent.TenantID, map[string]interface{}{
			"agent_id":           agent.ID,
			"last_heartbeat_at":  agent.LastHeartbeatAt.UTC().Format(time.RFC3339Nano),
			"disconnect_timeout": int(timeout.Seconds()),
		})
	}
	return agent, nil
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "ekm",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}

func strconvItoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := false
	if v < 0 {
		neg = true
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
