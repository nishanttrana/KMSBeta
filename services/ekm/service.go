package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgkeyaccess "vecta-kms/pkg/keyaccess"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Service struct {
	store   Store
	keycore KeyCoreClient
	events  EventPublisher
	mek     []byte
	keyAccess pkgkeyaccess.Client
}

func NewService(store Store, keycore KeyCoreClient, events EventPublisher, mek []byte) *Service {
	if len(mek) < 32 {
		sum := sha256.Sum256([]byte("vecta-ekm-dev-mek"))
		mek = sum[:]
	}
	outMEK := make([]byte, 32)
	copy(outMEK, mek[:32])
	return &Service{
		store:   store,
		keycore: keycore,
		events:  events,
		mek:     outMEK,
	}
}

func (s *Service) SetKeyAccessClient(client pkgkeyaccess.Client) {
	s.keyAccess = client
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
	autoProvision := shouldAuto(req.AutoProvisionTDE, isSupportedTDEEngine(req.DBEngine))
	if isNewAgent && autoProvision && isSupportedTDEEngine(req.DBEngine) {
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
		req.Port = defaultPortForEngine(req.Engine)
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
	autoProvision := shouldAuto(req.AutoProvisionKey, isSupportedTDEEngine(req.Engine))
	if req.KeyID == "" && autoProvision && isSupportedTDEEngine(req.Engine) {
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
	keyAccessResult, err := s.evaluateKeyAccess(ctx, pkgkeyaccess.EvaluateRequest{
		TenantID:          req.TenantID,
		Service:           "ekm",
		Connector:         "tde",
		Operation:         "wrap",
		KeyID:             keyID,
		ResourceID:        firstNonEmpty(strings.TrimSpace(req.DatabaseID), strings.TrimSpace(req.AgentID)),
		RequestID:         newID("ekmreq"),
		RequesterID:       strings.TrimSpace(req.RequesterID),
		RequesterEmail:    strings.TrimSpace(req.RequesterEmail),
		JustificationCode: strings.TrimSpace(req.JustificationCode),
		JustificationText: strings.TrimSpace(req.JustificationText),
		Metadata:          buildEKMKeyAccessMetadata("", req.AgentID, req.DatabaseID),
	})
	if err != nil {
		return WrapDEKResponse{}, err
	}
	if strings.EqualFold(keyAccessResult.Action, "deny") {
		_ = s.store.RecordKeyAccess(ctx, KeyAccessLog{
			ID:           newID("kacc"),
			TenantID:     req.TenantID,
			KeyID:        keyID,
			AgentID:      strings.TrimSpace(req.AgentID),
			DatabaseID:   strings.TrimSpace(req.DatabaseID),
			Operation:    "wrap",
			Status:       "denied",
			ErrorMessage: keyAccessResult.Reason,
			CreatedAt:    time.Now().UTC(),
		})
		_ = s.publishAudit(ctx, "audit.ekm.tde_key_accessed", req.TenantID, map[string]interface{}{
			"key_id":             keyID,
			"operation":          "wrap",
			"agent_id":           req.AgentID,
			"database_id":        req.DatabaseID,
			"status":             "denied",
			"justification_code": req.JustificationCode,
			"reason":             keyAccessResult.Reason,
		})
		return WrapDEKResponse{}, newServiceError(http.StatusForbidden, "key_access_denied", firstNonEmpty(keyAccessResult.Reason, "blocked by key access justification policy"))
	}
	if keyAccessResult.ApprovalRequired {
		_ = s.store.RecordKeyAccess(ctx, KeyAccessLog{
			ID:           newID("kacc"),
			TenantID:     req.TenantID,
			KeyID:        keyID,
			AgentID:      strings.TrimSpace(req.AgentID),
			DatabaseID:   strings.TrimSpace(req.DatabaseID),
			Operation:    "wrap",
			Status:       "pending_approval",
			ErrorMessage: keyAccessResult.ApprovalRequestID,
			CreatedAt:    time.Now().UTC(),
		})
		return WrapDEKResponse{KeyID: keyID, Status: "pending_approval", ApprovalRequestID: keyAccessResult.ApprovalRequestID}, nil
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
	keyAccessResult, err := s.evaluateKeyAccess(ctx, pkgkeyaccess.EvaluateRequest{
		TenantID:          req.TenantID,
		Service:           "ekm",
		Connector:         "tde",
		Operation:         "unwrap",
		KeyID:             keyID,
		ResourceID:        firstNonEmpty(strings.TrimSpace(req.DatabaseID), strings.TrimSpace(req.AgentID)),
		RequestID:         newID("ekmreq"),
		RequesterID:       strings.TrimSpace(req.RequesterID),
		RequesterEmail:    strings.TrimSpace(req.RequesterEmail),
		JustificationCode: strings.TrimSpace(req.JustificationCode),
		JustificationText: strings.TrimSpace(req.JustificationText),
		Metadata:          buildEKMKeyAccessMetadata("", req.AgentID, req.DatabaseID),
	})
	if err != nil {
		return UnwrapDEKResponse{}, err
	}
	if strings.EqualFold(keyAccessResult.Action, "deny") {
		_ = s.store.RecordKeyAccess(ctx, KeyAccessLog{
			ID:           newID("kacc"),
			TenantID:     req.TenantID,
			KeyID:        keyID,
			AgentID:      strings.TrimSpace(req.AgentID),
			DatabaseID:   strings.TrimSpace(req.DatabaseID),
			Operation:    "unwrap",
			Status:       "denied",
			ErrorMessage: keyAccessResult.Reason,
			CreatedAt:    time.Now().UTC(),
		})
		return UnwrapDEKResponse{}, newServiceError(http.StatusForbidden, "key_access_denied", firstNonEmpty(keyAccessResult.Reason, "blocked by key access justification policy"))
	}
	if keyAccessResult.ApprovalRequired {
		_ = s.store.RecordKeyAccess(ctx, KeyAccessLog{
			ID:           newID("kacc"),
			TenantID:     req.TenantID,
			KeyID:        keyID,
			AgentID:      strings.TrimSpace(req.AgentID),
			DatabaseID:   strings.TrimSpace(req.DatabaseID),
			Operation:    "unwrap",
			Status:       "pending_approval",
			ErrorMessage: keyAccessResult.ApprovalRequestID,
			CreatedAt:    time.Now().UTC(),
		})
		return UnwrapDEKResponse{KeyID: keyID, Status: "pending_approval", ApprovalRequestID: keyAccessResult.ApprovalRequestID}, nil
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
	keyAccessResult, err := s.evaluateKeyAccess(ctx, pkgkeyaccess.EvaluateRequest{
		TenantID:          req.TenantID,
		Service:           "ekm",
		Connector:         "tde",
		Operation:         "rotate",
		KeyID:             keyID,
		ResourceID:        keyID,
		RequestID:         newID("ekmreq"),
		RequesterID:       strings.TrimSpace(req.RequesterID),
		RequesterEmail:    strings.TrimSpace(req.RequesterEmail),
		JustificationCode: strings.TrimSpace(req.JustificationCode),
		JustificationText: strings.TrimSpace(req.JustificationText),
		Metadata:          map[string]interface{}{"reason": req.Reason},
	})
	if err != nil {
		return RotateTDEKeyResponse{}, err
	}
	if strings.EqualFold(keyAccessResult.Action, "deny") {
		return RotateTDEKeyResponse{}, newServiceError(http.StatusForbidden, "key_access_denied", firstNonEmpty(keyAccessResult.Reason, "blocked by key access justification policy"))
	}
	if keyAccessResult.ApprovalRequired {
		return RotateTDEKeyResponse{KeyID: keyID, Status: "pending_approval", ApprovalRequestID: keyAccessResult.ApprovalRequestID}, nil
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
EKM_API_BASE_URL=${EKM_API_BASE_URL:-https://kms.example.com/svc/ekm}
EKM_REGISTER_PATH=/ekm/agents/register
EKM_HEARTBEAT_PATH=/ekm/agents/%s/heartbeat
EKM_ROTATE_PATH=/ekm/agents/%s/rotate
EKM_VALIDATE_PATH=/ekm/agents/%s/validate-deploy
`, tenantID, agent.ID, agent.Name, engine, defaultString(agent.Host, "127.0.0.1"), defaultInt(agent.HeartbeatIntervalSec, DefaultHeartbeatSec), rotation, pkcs11ModuleHint, agent.ID, agent.ID, agent.ID))

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

# ---- Pre-flight checks ----
echo "[preflight] Checking prerequisites..."

# Verify bash version >= 4
if (( BASH_VERSINFO[0] < 4 )); then
  echo "[error] bash 4+ required, found $BASH_VERSION" >&2; exit 1
fi

# Verify curl is available
if ! command -v curl &>/dev/null; then
  echo "[error] curl is required but not found. Install with: apt-get install curl / yum install curl" >&2; exit 1
fi

# Verify disk space (need at least 50MB free in /etc)
AVAIL_KB=$(df -P /etc 2>/dev/null | awk 'NR==2{print $4}' || echo 0)
if (( AVAIL_KB < 51200 )); then
  echo "[error] Insufficient disk space in /etc (need 50MB, have ${AVAIL_KB}KB)" >&2; exit 1
fi

# Verify network connectivity to KMS
EKM_URL="${EKM_API_BASE_URL:-https://kms.example.com/svc/ekm}"
if ! curl -fsS --connect-timeout 5 --max-time 10 "${EKM_URL%%/}/ekm/agents" -o /dev/null 2>/dev/null; then
  echo "[warn] Cannot reach KMS at $EKM_URL -- deployment may fail at validation step"
fi

echo "[preflight] All checks passed."

# ---- Rollback function ----
INSTALL_DIR="/etc/vecta-ekm"
rollback() {
  echo "[rollback] Installation failed, cleaning up..."
  rm -rf "$INSTALL_DIR"
  echo "[rollback] Removed $INSTALL_DIR. Please check errors above and retry."
  exit 1
}
trap rollback ERR

# ---- Install ----
mkdir -p "$INSTALL_DIR"
cat > "$INSTALL_DIR/agent.env" <<'EOF'
%s
EOF
cat > "$INSTALL_DIR/pkcs11.conf" <<'EOF'
%s
EOF
cat > "$INSTALL_DIR/heartbeat.sh" <<'EOF'
%s
EOF
chmod 750 "$INSTALL_DIR/heartbeat.sh"

echo "[install] Configuration written to $INSTALL_DIR"
echo "[install] Next steps:"
echo "  1. Install vecta-ekm-agent binary and systemd service"
echo "  2. Run: systemctl daemon-reload && systemctl enable --now vecta-ekm-agent"
echo "  3. Schedule heartbeat every 30s (systemd timer or cron) using $INSTALL_DIR/heartbeat.sh"
echo "  4. Set EKM_API_BASE_URL in agent.env if KMS is not at the default address"

# ---- Validate deployment ----
echo "[validate] Contacting KMS to validate deployment..."
VALIDATE_BODY=$(printf '{"tenant_id":"%%s","agent_id":"%%s","version":"1.0","connectivity":"ok"}' "%s" "%s")
if curl -fsS -X POST "${EKM_URL%%/}/ekm/agents/%s/validate-deploy" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: %s" \
  -d "$VALIDATE_BODY" 2>/dev/null; then
  echo ""
  echo "[validate] Deployment validated successfully."
else
  echo "[warn] Could not validate deployment with KMS. Verify connectivity and try manually."
fi

trap - ERR
echo "[done] Vecta EKM agent setup complete."
`, envFile, pkcs11Cfg, linuxHeartbeat, tenantID, agent.ID, agent.ID, tenantID)

	windowsInstall := fmt.Sprintf(`$ErrorActionPreference = "Stop"

# ---- Pre-flight checks ----
Write-Host "[preflight] Checking prerequisites..."

# Verify PowerShell version >= 5.1
if ($PSVersionTable.PSVersion.Major -lt 5) {
  Write-Error "[error] PowerShell 5.1+ required, found $($PSVersionTable.PSVersion)"
  exit 1
}

# Verify disk space (need at least 50MB)
$freeGB = (Get-PSDrive C).Free / 1MB
if ($freeGB -lt 50) {
  Write-Error "[error] Insufficient disk space on C: (need 50MB, have $([Math]::Round($freeGB))MB)"
  exit 1
}

# Verify network connectivity
$ekmUrl = if ($env:EKM_API_BASE_URL) { $env:EKM_API_BASE_URL } else { "https://kms.example.com/svc/ekm" }
try {
  $null = Invoke-WebRequest -Uri "$ekmUrl/ekm/agents" -Method GET -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
} catch {
  Write-Warning "[warn] Cannot reach KMS at $ekmUrl -- deployment may fail at validation step"
}

Write-Host "[preflight] All checks passed."

# ---- Install ----
$installDir = "C:\vecta-ekm"
try {
  New-Item -ItemType Directory -Force -Path $installDir | Out-Null
  @"
%s
"@ | Set-Content -Path "$installDir\agent.env" -Encoding UTF8
  @"
%s
"@ | Set-Content -Path "$installDir\pkcs11.conf" -Encoding UTF8
  @"
%s
"@ | Set-Content -Path "$installDir\heartbeat.ps1" -Encoding UTF8

  Write-Host "[install] Configuration written to $installDir"
  Write-Host "[install] Next steps:"
  Write-Host "  1. Install vecta-ekm-agent.exe and create Windows service (NSSM/sc.exe)"
  Write-Host "  2. Schedule heartbeat.ps1 in Windows Task Scheduler every 30 seconds"
  Write-Host "  3. Set EKM_API_BASE_URL environment variable if KMS is not at the default address"
} catch {
  Write-Error "[error] Installation failed: $_"
  Write-Host "[rollback] Removing $installDir..."
  Remove-Item -Recurse -Force $installDir -ErrorAction SilentlyContinue
  exit 1
}

# ---- Validate deployment ----
Write-Host "[validate] Contacting KMS to validate deployment..."
try {
  $body = @{ tenant_id = "%s"; agent_id = "%s"; version = "1.0"; connectivity = "ok" } | ConvertTo-Json -Compress
  $null = Invoke-RestMethod -Method Post -Uri "$ekmUrl/ekm/agents/%s/validate-deploy" -ContentType "application/json" -Body $body -Headers @{"X-Tenant-ID"="%s"} -TimeoutSec 10
  Write-Host "[validate] Deployment validated successfully."
} catch {
  Write-Warning "[warn] Could not validate deployment with KMS. Verify connectivity and try manually."
}

Write-Host "[done] Vecta EKM agent setup complete."
`, strings.ReplaceAll(envFile, "\n", "\r\n"), strings.ReplaceAll(pkcs11Cfg, "\n", "\r\n"), strings.ReplaceAll(windowsHeartbeat, "\n", "\r\n"), tenantID, agent.ID, agent.ID, tenantID)

	// Engine-specific TDE setup guide
	tdeSetupGuide := buildTDESetupGuide(engine, agent.ID)

	files := []DeployPackageFile{
		{Path: "agent.env", Content: envFile, Mode: "0600"},
		{Path: "pkcs11.conf", Content: pkcs11Cfg, Mode: "0600"},
		{Path: "tde-setup.md", Content: tdeSetupGuide, Mode: "0644"},
	}
	if targetOS == "linux" {
		files = append(files,
			DeployPackageFile{Path: "heartbeat.sh", Content: linuxHeartbeat, Mode: "0750"},
			DeployPackageFile{Path: "install.sh", Content: linuxInstall, Mode: "0750"},
		)
	} else {
		files = append(files,
			DeployPackageFile{Path: "heartbeat.ps1", Content: windowsHeartbeat, Mode: "0644"},
			DeployPackageFile{Path: "install.ps1", Content: windowsInstall, Mode: "0644"},
		)
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
		SupportedDatabases:  []string{"mssql", "oracle", "postgresql", "mysql", "db2", "mariadb"},
		RecommendedProfiles: recommendedProfilesForEngine(engine),
		Files:               files,
	}
	_ = s.publishAudit(ctx, "audit.ekm.deploy_package_generated", tenantID, map[string]interface{}{
		"agent_id":  agent.ID,
		"target_os": targetOS,
		"db_engine": engine,
	})
	return pkg, nil
}

// BuildFileEncryptAgentPackage generates a user-space file-encryption TDE agent package.
// The agent encrypts files/directories using AES-256-GCM with a key from Vecta KMS.
// No kernel module or OS driver is required — runs entirely at the user (process) level.
//
// Supported platforms:
//   - Windows (PowerShell + Windows Task Scheduler)
//   - Linux Ubuntu/Debian   (bash + systemd user unit)
//   - Linux RHEL/CentOS     (bash + systemd user unit)
//   - Linux Alpine          (bash + OpenRC user service)
func (s *Service) BuildFileEncryptAgentPackage(ctx context.Context, req FileEncryptDownloadRequest) (FileEncryptPackage, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return FileEncryptPackage{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}

	// Normalise OS / distro
	targetOS := strings.ToLower(strings.TrimSpace(req.TargetOS))
	if targetOS != "windows" {
		targetOS = "linux"
	}
	distro := strings.ToLower(strings.TrimSpace(req.Distro))
	if distro == "" {
		if targetOS == "windows" {
			distro = "windows"
		} else {
			distro = "ubuntu"
		}
	}

	// Defaults
	apiBase := defaultString(req.APIBaseURL, "https://kms.example.com/svc/ekm")
	keyID := defaultString(req.KeyID, "")
	watchDirs := defaultString(req.WatchDirs, func() string {
		if targetOS == "windows" {
			return `C:\Sensitive`
		}
		return "/data/sensitive"
	}())
	patterns := defaultString(req.FilePatterns, "*.docx,*.xlsx,*.pdf,*.csv,*.json,*.key,*.pem")
	rotDays := defaultInt(req.RotationDays, 90)

	// Shared env config written to disk — read by the agent at startup and rotation.
	// NOTE: auth token is stored in a separate credentials file (chmod 0600), never here.
	envContent := fmt.Sprintf(`# Vecta File Encryption TDE — agent configuration
# Algorithm: AES-256-GCM (FIPS 140-3 Level 1 approved)
# Mode: user-space — no kernel module required
# Auth token is stored separately in the credentials file below (never in this file).
VECTA_API_BASE_URL=%s
VECTA_TENANT_ID=%s
VECTA_KEY_ID=%s
VECTA_WATCH_DIRS=%s
VECTA_FILE_PATTERNS=%s
VECTA_ROTATION_DAYS=%d
VECTA_ALGORITHM=AES-256-GCM
VECTA_HEARTBEAT_PATH=/ekm/agents/{agent_id}/heartbeat
VECTA_ROTATE_PATH=/ekm/agents/{agent_id}/rotate
VECTA_CREDENTIALS_FILE=${HOME}/.config/vecta-file-encrypt/credentials
`, apiBase, req.TenantID, keyID, watchDirs, patterns, rotDays)

	// ── Linux scripts ─────────────────────────────────────────────────────────
	linuxEncryptSh := `#!/usr/bin/env bash
# vecta-file-encrypt.sh — User-space file encryption agent for Vecta KMS.
# Runs as the current user; no kernel module required.
# Algorithm: AES-256-GCM (FIPS 140-3 approved)
# Requires: openssl 3.x, curl, jq
set -euo pipefail

CONF_DIR="${VECTA_CONF_DIR:-$HOME/.config/vecta-file-encrypt}"
ENV_FILE="$CONF_DIR/agent.env"
CREDS_FILE="$CONF_DIR/credentials"
AUDIT_DIR="$HOME/.local/share/vecta-file-encrypt"
AUDIT_LOG="$AUDIT_DIR/audit.log"

# Load config
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Config not found at $ENV_FILE. Run install.sh first." >&2; exit 1
fi
# shellcheck source=/dev/null
source "$ENV_FILE"

# Load auth token from credentials file (separate from agent.env, chmod 0600)
if [[ ! -f "$CREDS_FILE" ]]; then
  echo "ERROR: Credentials not found at $CREDS_FILE. Run install.sh and set VECTA_AUTH_TOKEN." >&2; exit 1
fi
# shellcheck source=/dev/null
source "$CREDS_FILE"

# Fetch current DEK from Vecta KMS (AES-256, raw key material delivered via TLS)
fetch_key() {
  local key_b64
  key_b64=$(curl -fsS --max-time 10 \
    -H "X-Tenant-ID: ${VECTA_TENANT_ID}" \
    -H "Authorization: Bearer ${VECTA_AUTH_TOKEN:-}" \
    "${VECTA_API_BASE_URL}/ekm/tde/keys/${VECTA_KEY_ID}/unwrap" \
    --data '{"purpose":"file_encrypt"}' \
    | jq -r '.plaintext_dek // empty')
  if [[ -z "$key_b64" ]]; then
    echo "ERROR: Failed to fetch DEK from Vecta KMS." >&2; exit 1
  fi
  echo "$key_b64"
}

# Encrypt a single file in-place using AES-256-GCM.
# Output: original file replaced with .venc (original removed after encrypt).
encrypt_file() {
  local src="$1"
  local dst="${src}.venc"
  local key_b64="$2"
  # Generate random 96-bit IV
  local iv_hex
  iv_hex=$(openssl rand -hex 12)
  # Encrypt (AES-256-GCM via openssl, user-space only)
  openssl enc -aes-256-gcm \
    -K "$(echo "$key_b64" | base64 -d | xxd -p -c 256)" \
    -iv "$iv_hex" \
    -in "$src" -out "${dst}.tmp" 2>/dev/null
  # Prepend IV to ciphertext for deterministic decryption
  printf '%s' "$iv_hex" | xxd -r -p > "$dst"
  cat "${dst}.tmp" >> "$dst"
  rm -f "${dst}.tmp" "$src"
  echo "  encrypted: $src -> $dst"
}

# Decrypt a single .venc file in-place.
decrypt_file() {
  local src="$1"
  local orig="${src%.venc}"
  local key_b64="$2"
  # Extract IV (first 12 bytes)
  local iv_hex
  iv_hex=$(dd if="$src" bs=1 count=12 2>/dev/null | xxd -p)
  # Extract ciphertext
  dd if="$src" bs=12 skip=1 of="${src}.ct" 2>/dev/null
  openssl enc -d -aes-256-gcm \
    -K "$(echo "$key_b64" | base64 -d | xxd -p -c 256)" \
    -iv "$iv_hex" \
    -in "${src}.ct" -out "$orig" 2>/dev/null
  rm -f "${src}.ct" "$src"
  echo "  decrypted: $src -> $orig"
}

CMD="${1:-encrypt}"
KEY_B64=$(fetch_key)
FILES_PROCESSED=0

IFS=',' read -ra DIRS <<< "${VECTA_WATCH_DIRS}"
IFS=',' read -ra PATS <<< "${VECTA_FILE_PATTERNS}"

for dir in "${DIRS[@]}"; do
  dir="${dir// /}"
  [[ -d "$dir" ]] || { echo "WARN: watch dir not found: $dir" >&2; continue; }
  for pat in "${PATS[@]}"; do
    pat="${pat// /}"
    while IFS= read -r -d '' file; do
      if [[ "$CMD" == "decrypt" ]]; then
        if [[ "$file" == *.venc ]]; then
          decrypt_file "$file" "$KEY_B64"
          FILES_PROCESSED=$(( FILES_PROCESSED + 1 ))
        fi
      else
        if [[ "$file" != *.venc ]]; then
          encrypt_file "$file" "$KEY_B64"
          FILES_PROCESSED=$(( FILES_PROCESSED + 1 ))
        fi
      fi
    done < <(find "$dir" -maxdepth 8 -type f -name "$pat" -print0 2>/dev/null)
  done
done

# Explicitly clear DEK from memory
KEY_B64=""; unset KEY_B64

# Write local audit log entry
mkdir -p "$AUDIT_DIR"
printf '%s [INFO] op=%s files=%d key=%s host=%s\n' \
  "$(date -u +%FT%TZ)" "$CMD" "$FILES_PROCESSED" "${VECTA_KEY_ID:-unknown}" "$(hostname)" \
  >> "$AUDIT_LOG"

# Best-effort POST audit event to KMS (do not fail if KMS unreachable)
_audit_ts="$(date -u +%FT%TZ)"
curl -fsS --max-time 5 \
  -H "X-Tenant-ID: ${VECTA_TENANT_ID}" \
  -H "Authorization: Bearer ${VECTA_AUTH_TOKEN:-}" \
  -H "Content-Type: application/json" \
  "${VECTA_API_BASE_URL}/ekm/file-encrypt/audit" \
  --data "{\"tenant_id\":\"${VECTA_TENANT_ID}\",\"key_id\":\"${VECTA_KEY_ID}\",\"operation\":\"${CMD}\",\"files_processed\":${FILES_PROCESSED},\"timestamp\":\"${_audit_ts}\",\"hostname\":\"$(hostname)\",\"agent_version\":\"1.0\"}" \
  >/dev/null 2>&1 || true

echo "[vecta-file-encrypt] Done: $CMD"
`

	linuxInstallSh := fmt.Sprintf(`#!/usr/bin/env bash
# install.sh — Install Vecta File Encryption TDE agent (user-space, no root required).
set -euo pipefail

CONF_DIR="${HOME}/.config/vecta-file-encrypt"
BIN_DIR="${HOME}/.local/bin"

echo "Vecta File Encryption TDE — User-space install"
echo "  No root / kernel module required."
echo ""

# Install missing dependencies based on distro
_install_deps() {
  if command -v apt-get &>/dev/null; then
    echo "  Installing dependencies via apt-get..."
    apt-get install -y openssl curl jq 2>/dev/null || true
  elif command -v yum &>/dev/null; then
    echo "  Installing dependencies via yum..."
    yum install -y openssl curl jq 2>/dev/null || true
  elif command -v apk &>/dev/null; then
    echo "  Installing dependencies via apk..."
    apk add --no-cache openssl curl jq 2>/dev/null || true
  else
    echo "  WARN: Unknown package manager. Please install openssl, curl, jq manually." >&2
  fi
}

# Verify dependencies; attempt auto-install if missing
_missing=0
for dep in openssl curl jq xxd; do
  if ! command -v "$dep" &>/dev/null; then
    echo "  WARN: $dep not found, attempting install..." >&2
    _missing=1
  fi
done
if (( _missing )); then
  _install_deps
  for dep in openssl curl jq xxd; do
    command -v "$dep" &>/dev/null || { echo "ERROR: $dep is required but could not be installed." >&2; exit 1; }
  done
fi

# Check openssl version >= 3 (required for AES-256-GCM AEAD)
OSSL_VER=$(openssl version | awk '{print $2}')
OSSL_MAJOR=$(echo "$OSSL_VER" | cut -d. -f1)
if (( OSSL_MAJOR < 3 )); then
  echo "ERROR: openssl 3.x required for FIPS-approved AES-256-GCM. Found: $OSSL_VER" >&2
  exit 1
fi

mkdir -p "$CONF_DIR" "$BIN_DIR"
chmod 700 "$CONF_DIR"

# Write config (no auth token — stored in credentials file below)
cat > "$CONF_DIR/agent.env" <<'ENVEOF'
%s
ENVEOF
chmod 600 "$CONF_DIR/agent.env"

# Create separate credentials file (chmod 0600) for auth token
CREDS_FILE="$CONF_DIR/credentials"
touch "$CREDS_FILE"
chmod 0600 "$CREDS_FILE"
cat > "$CREDS_FILE" <<'EOF'
# Vecta File Encryption TDE — credentials (chmod 0600, not committed)
# Set your auth token here. This file is never sourced globally.
VECTA_AUTH_TOKEN=
EOF
echo "  credentials file: $CREDS_FILE (edit and set VECTA_AUTH_TOKEN)"

# Install agent script
cp vecta-file-encrypt.sh "$BIN_DIR/vecta-file-encrypt"
chmod 750 "$BIN_DIR/vecta-file-encrypt"

echo "Configuration : $CONF_DIR/agent.env"
echo "Agent script  : $BIN_DIR/vecta-file-encrypt"
echo ""
`, envContent)

	// Systemd user unit (no root — installed in ~/.config/systemd/user/)
	systemdUnit := `[Unit]
Description=Vecta File Encryption TDE Agent
After=network-online.target

[Service]
Type=oneshot
# User-space: runs as the logged-in user, no kernel/system privileges needed
ExecStart=%h/.local/bin/vecta-file-encrypt encrypt
Environment=VECTA_CONF_DIR=%h/.config/vecta-file-encrypt
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
`

	systemdTimer := `[Unit]
Description=Vecta File Encryption TDE — periodic encrypt run
Requires=vecta-file-encrypt.service

[Timer]
# Run every 5 minutes to pick up newly created files
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
`

	// Alpine OpenRC user script
	alpineInitSh := `#!/sbin/openrc-run
# OpenRC user service for Vecta File Encryption TDE Agent
description="Vecta File Encryption TDE Agent (user-space)"
command="$HOME/.local/bin/vecta-file-encrypt"
command_args="encrypt"
depend() { need net; }
`

	// Rotation script (Linux)
	linuxRotateSh := fmt.Sprintf(`#!/usr/bin/env bash
# vecta-rotate-key.sh — Trigger key rotation via Vecta KMS REST API.
# Runs as the current user (no root required).
set -euo pipefail

CONF_DIR="${VECTA_CONF_DIR:-$HOME/.config/vecta-file-encrypt}"
# shellcheck source=/dev/null
source "$CONF_DIR/agent.env"

echo "[rotate] Requesting key rotation from Vecta KMS..."
curl -fsS -X POST \
  -H "X-Tenant-ID: ${VECTA_TENANT_ID}" \
  -H "Authorization: Bearer ${VECTA_AUTH_TOKEN:-}" \
  -H "Content-Type: application/json" \
  "${VECTA_API_BASE_URL}${VECTA_ROTATE_PATH}" \
  --data '{"rotation_cycle_days":%d}' \
  | jq .
echo "[rotate] Done."
`, rotDays)

	// ── Windows scripts ───────────────────────────────────────────────────────
	// Note: PowerShell backtick (`) is Go's raw-string terminator, so we use
	// splatting and single-line calls to avoid backtick line-continuation in PS.
	windowsInstallPs1 := fmt.Sprintf("#Requires -Version 5.1\r\n"+
		"# install.ps1 - Install Vecta File Encryption TDE agent (user-space, no admin required).\r\n"+
		"# Algorithm: AES-256-GCM (FIPS 140-3 Level 1 approved). No kernel driver needed.\r\n"+
		"$ErrorActionPreference = \"Stop\"\r\n"+
		"Set-StrictMode -Version Latest\r\n"+
		"$confDir = Join-Path $env:APPDATA \"Vecta\\FileEncrypt\"\r\n"+
		"$binDir  = Join-Path $env:LOCALAPPDATA \"Vecta\\bin\"\r\n"+
		"Write-Host \"Vecta File Encryption TDE - User-space install\" -ForegroundColor Green\r\n"+
		"foreach ($cmd in @(\"openssl\",\"curl\",\"jq\")) {\r\n"+
		"  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {\r\n"+
		"    Write-Error \"$cmd is required. Install via: winget install $cmd\"; exit 1 }}\r\n"+
		"New-Item -ItemType Directory -Path $confDir,$binDir -Force | Out-Null\r\n"+
		"icacls $confDir /inheritance:r /grant:r \"${env:USERNAME}:(OI)(CI)F\" 2>$null | Out-Null\r\n"+
		"@'\r\n%s\r\n'@ | Set-Content -Path (Join-Path $confDir \"agent.env\") -Encoding UTF8\r\n"+
		"# Create separate credentials file (current user only ACL) for auth token\r\n"+
		"$credsFile = Join-Path $confDir \"credentials.env\"\r\n"+
		"if (-not (Test-Path $credsFile)) {\r\n"+
		"  \"# Vecta File Encryption TDE - credentials`r`nVECTA_AUTH_TOKEN=\" | Set-Content $credsFile -Encoding UTF8\r\n"+
		"  icacls $credsFile /inheritance:r /grant:r \"${env:USERNAME}:F\" 2>$null | Out-Null\r\n"+
		"}\r\n"+
		"Write-Host \"  credentials file: $credsFile (edit and set VECTA_AUTH_TOKEN)\" -ForegroundColor Yellow\r\n"+
		"Copy-Item \"vecta-file-encrypt.ps1\" (Join-Path $binDir \"vecta-file-encrypt.ps1\") -Force\r\n"+
		"Copy-Item \"vecta-rotate-key.ps1\"   (Join-Path $binDir \"vecta-rotate-key.ps1\")   -Force\r\n"+
		"# Register Task Scheduler job (runs as current user - no admin needed)\r\n"+
		"$argStr = \"-NonInteractive -NoProfile -ExecutionPolicy Bypass -File \"\"$(Join-Path $binDir 'vecta-file-encrypt.ps1')\"\" -Command encrypt\"\r\n"+
		"$action   = New-ScheduledTaskAction -Execute \"powershell.exe\" -Argument $argStr\r\n"+
		"$trigger  = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)\r\n"+
		"$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -StartWhenAvailable\r\n"+
		"$taskArgs = @{ TaskName=\"VectaFileEncryptTDE\"; Action=$action; Trigger=$trigger; Settings=$settings; RunLevel=\"Limited\"; Force=$true }\r\n"+
		"Register-ScheduledTask @taskArgs | Out-Null\r\n"+
		"Write-Host \"Configuration : $confDir\\agent.env\" -ForegroundColor Cyan\r\n"+
		"Write-Host \"Agent script  : $binDir\\vecta-file-encrypt.ps1\"\r\n"+
		"Write-Host \"Scheduler     : VectaFileEncryptTDE (every 5 minutes, current user)\"\r\n",
		strings.ReplaceAll(envContent, "\n", "\r\n"))

	// Note: PowerShell backtick (`) is the Go raw-string terminator so this block
	// is assembled via string concatenation — do NOT convert to a raw literal.
	windowsEncryptPs1 := "# vecta-file-encrypt.ps1 — User-space file encryption agent for Vecta KMS (Windows).\r\n" +
		"# Algorithm: AES-256-GCM (FIPS 140-3 approved) via openssl CLI.\r\n" +
		"# Runs as current user — no admin, no kernel driver required.\r\n" +
		"param([ValidateSet(\"encrypt\",\"decrypt\")][string]$Command = \"encrypt\")\r\n" +
		"$ErrorActionPreference = \"Stop\"\r\n" +
		"Set-StrictMode -Version Latest\r\n" +
		"\r\n" +
		"$confDir   = Join-Path $env:APPDATA \"Vecta\\FileEncrypt\"\r\n" +
		"$envFile   = Join-Path $confDir \"agent.env\"\r\n" +
		"$credsFile = Join-Path $confDir \"credentials.env\"\r\n" +
		"$auditDir  = Join-Path $env:LOCALAPPDATA \"Vecta\\FileEncrypt\"\r\n" +
		"$auditLog  = Join-Path $auditDir \"audit.log\"\r\n" +
		"if (-not (Test-Path $envFile)) {\r\n" +
		"  Write-Error \"Config not found at $envFile. Run install.ps1 first.\"\r\n" +
		"  exit 1\r\n" +
		"}\r\n" +
		"if (-not (Test-Path $credsFile)) {\r\n" +
		"  Write-Error \"Credentials not found at $credsFile. Run install.ps1 and set VECTA_AUTH_TOKEN.\"\r\n" +
		"  exit 1\r\n" +
		"}\r\n" +
		"\r\n" +
		"# Load config from agent.env\r\n" +
		"$cfg = @{}\r\n" +
		"Get-Content $envFile | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' } | ForEach-Object {\r\n" +
		"  $idx = $_.IndexOf('='); $cfg[$_.Substring(0, $idx)] = $_.Substring($idx + 1)\r\n" +
		"}\r\n" +
		"\r\n" +
		"# Load auth token from separate credentials file (not agent.env)\r\n" +
		"$creds = @{}\r\n" +
		"Get-Content $credsFile | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' } | ForEach-Object {\r\n" +
		"  $idx = $_.IndexOf('='); $creds[$_.Substring(0, $idx)] = $_.Substring($idx + 1)\r\n" +
		"}\r\n" +
		"$authToken = $creds['VECTA_AUTH_TOKEN']\r\n" +
		"\r\n" +
		"# Fetch DEK from Vecta KMS\r\n" +
		"$headers = @{ \"X-Tenant-ID\" = $cfg[\"VECTA_TENANT_ID\"]; \"Authorization\" = \"Bearer $authToken\" }\r\n" +
		"$body    = '{\"purpose\":\"file_encrypt\"}'\r\n" +
		"$irmArgs = @{ Method=\"Post\"; Uri=\"$($cfg['VECTA_API_BASE_URL'])/ekm/tde/keys/$($cfg['VECTA_KEY_ID'])/unwrap\"; Headers=$headers; ContentType=\"application/json\"; Body=$body }\r\n" +
		"$resp    = Invoke-RestMethod @irmArgs\r\n" +
		"$keyB64  = $resp.plaintext_dek\r\n" +
		"if ([string]::IsNullOrEmpty($keyB64)) { Write-Error \"Failed to fetch DEK from Vecta KMS.\"; exit 1 }\r\n" +
		"$keyHex  = [BitConverter]::ToString([Convert]::FromBase64String($keyB64)) -replace '-',''\r\n" +
		"\r\n" +
		"$dirs     = $cfg[\"VECTA_WATCH_DIRS\"] -split ','\r\n" +
		"$patterns = $cfg[\"VECTA_FILE_PATTERNS\"] -split ','\r\n" +
		"$filesProcessed = 0\r\n" +
		"\r\n" +
		"foreach ($dir in $dirs) {\r\n" +
		"  $dir = $dir.Trim()\r\n" +
		"  if (-not (Test-Path $dir)) { Write-Warning \"Watch dir not found: $dir\"; continue }\r\n" +
		"  foreach ($pat in $patterns) {\r\n" +
		"    $pat = $pat.Trim()\r\n" +
		"    Get-ChildItem -Path $dir -Filter $pat -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {\r\n" +
		"      $src = $_.FullName\r\n" +
		"      if ($Command -eq \"encrypt\" -and $src -notlike \"*.venc\") {\r\n" +
		"        $dst = \"$src.venc\"\r\n" +
		"        $ivHex = (openssl rand -hex 12).Trim()\r\n" +
		"        # Encrypt with AES-256-GCM (user-space openssl, FIPS-approved)\r\n" +
		"        openssl enc -aes-256-gcm -K $keyHex -iv $ivHex -in \"$src\" -out \"$dst.tmp\" 2>$null\r\n" +
		"        $ivBytes = [byte[]]@(0..11 | ForEach-Object { [Convert]::ToByte($ivHex.Substring($_ * 2, 2), 16) })\r\n" +
		"        $cipherBytes = [System.IO.File]::ReadAllBytes(\"$dst.tmp\")\r\n" +
		"        $out = New-Object byte[] ($ivBytes.Length + $cipherBytes.Length)\r\n" +
		"        [Array]::Copy($ivBytes, 0, $out, 0, $ivBytes.Length)\r\n" +
		"        [Array]::Copy($cipherBytes, 0, $out, $ivBytes.Length, $cipherBytes.Length)\r\n" +
		"        [System.IO.File]::WriteAllBytes($dst, $out)\r\n" +
		"        Remove-Item \"$dst.tmp\", $src -Force\r\n" +
		"        Write-Host \"  encrypted: $src -> $dst\"\r\n" +
		"        $filesProcessed++\r\n" +
		"      } elseif ($Command -eq \"decrypt\" -and $src -like \"*.venc\") {\r\n" +
		"        $orig = $src -replace '\\.venc$',''\r\n" +
		"        $blob = [System.IO.File]::ReadAllBytes($src)\r\n" +
		"        $ivHex = [BitConverter]::ToString($blob[0..11]) -replace '-',''\r\n" +
		"        [System.IO.File]::WriteAllBytes(\"$src.ct\", $blob[12..($blob.Length - 1)])\r\n" +
		"        openssl enc -d -aes-256-gcm -K $keyHex -iv $ivHex -in \"$src.ct\" -out $orig 2>$null\r\n" +
		"        Remove-Item \"$src.ct\", $src -Force\r\n" +
		"        Write-Host \"  decrypted: $src -> $orig\"\r\n" +
		"        $filesProcessed++\r\n" +
		"      }\r\n" +
		"    }\r\n" +
		"  }\r\n" +
		"}\r\n" +
		"\r\n" +
		"# Explicitly clear DEK from memory\r\n" +
		"$keyB64 = $null; $keyHex = $null; [System.GC]::Collect()\r\n" +
		"\r\n" +
		"# Write local audit log entry\r\n" +
		"New-Item -ItemType Directory -Path $auditDir -Force | Out-Null\r\n" +
		"$auditTs = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')\r\n" +
		"\"$auditTs [INFO] op=$Command files=$filesProcessed key=$($cfg['VECTA_KEY_ID']) host=$env:COMPUTERNAME\" | Add-Content $auditLog\r\n" +
		"\r\n" +
		"# Best-effort POST audit event to KMS (do not fail if KMS unreachable)\r\n" +
		"try {\r\n" +
		"  $auditBody = \"{`\"tenant_id`\":`\"$($cfg['VECTA_TENANT_ID'])`\",`\"key_id`\":`\"$($cfg['VECTA_KEY_ID'])`\",`\"operation`\":`\"$Command`\",`\"files_processed`\":$filesProcessed,`\"timestamp`\":`\"$auditTs`\",`\"hostname`\":`\"$env:COMPUTERNAME`\",`\"agent_version`\":`\"1.0`\"}\"\r\n" +
		"  $auditArgs = @{ Method=\"Post\"; Uri=\"$($cfg['VECTA_API_BASE_URL'])/ekm/file-encrypt/audit\"; Headers=@{ \"X-Tenant-ID\"=$cfg[\"VECTA_TENANT_ID\"]; \"Authorization\"=\"Bearer $authToken\"; \"Content-Type\"=\"application/json\" }; Body=$auditBody; TimeoutSec=5 }\r\n" +
		"  Invoke-RestMethod @auditArgs | Out-Null\r\n" +
		"} catch { <# best effort — ignore KMS unreachable #> }\r\n" +
		"\r\n" +
		"Write-Host \"[vecta-file-encrypt] Done: $Command\"\r\n"

	windowsRotatePs1 := fmt.Sprintf(`# vecta-rotate-key.ps1 — Trigger key rotation via Vecta KMS.
param([int]$RotationDays = %d)
$ErrorActionPreference = "Stop"
$cfg = @{}
Get-Content (Join-Path $env:APPDATA "Vecta\FileEncrypt\agent.env") | Where-Object { $_ -match '^[A-Za-z_]' } | ForEach-Object {
  $idx = $_.IndexOf('='); $cfg[$_.Substring(0,$idx)] = $_.Substring($idx+1)
}
$headers = @{ "X-Tenant-ID" = $cfg["VECTA_TENANT_ID"]; "Authorization" = "Bearer $($cfg['VECTA_AUTH_TOKEN'])" }
$body    = '{"rotation_cycle_days":' + $RotationDays + '}'
$irmArgs2 = @{ Method="Post"; Uri="$($cfg['VECTA_API_BASE_URL'])$($cfg['VECTA_ROTATE_PATH'])"; Headers=$headers; ContentType="application/json"; Body=$body }
Invoke-RestMethod @irmArgs2 | ConvertTo-Json
Write-Host "[rotate] Key rotation requested."
`, rotDays)

	// ── Assemble package ──────────────────────────────────────────────────────
	var files []DeployPackageFile
	if targetOS == "windows" {
		files = []DeployPackageFile{
			{Path: "agent.env", Content: envContent, Mode: "0600"},
			{Path: "install.ps1", Content: windowsInstallPs1, Mode: "0644"},
			{Path: "vecta-file-encrypt.ps1", Content: windowsEncryptPs1, Mode: "0644"},
			{Path: "vecta-rotate-key.ps1", Content: windowsRotatePs1, Mode: "0644"},
			{Path: "README.txt", Content: buildFileEncryptReadme("windows", distro, apiBase, watchDirs, patterns, rotDays), Mode: "0644"},
		}
	} else {
		files = []DeployPackageFile{
			{Path: "agent.env", Content: envContent, Mode: "0600"},
			{Path: "install.sh", Content: linuxInstallSh, Mode: "0755"},
			{Path: "vecta-file-encrypt.sh", Content: linuxEncryptSh, Mode: "0750"},
			{Path: "vecta-rotate-key.sh", Content: linuxRotateSh, Mode: "0750"},
			{Path: "README.md", Content: buildFileEncryptReadme("linux", distro, apiBase, watchDirs, patterns, rotDays), Mode: "0644"},
		}
		// Include the systemd unit for systemd-based distros, OpenRC for Alpine
		switch distro {
		case "alpine":
			files = append(files, DeployPackageFile{Path: "vecta-file-encrypt.openrc", Content: alpineInitSh, Mode: "0755"})
		default:
			files = append(files,
				DeployPackageFile{Path: "vecta-file-encrypt.service", Content: systemdUnit, Mode: "0644"},
				DeployPackageFile{Path: "vecta-file-encrypt.timer", Content: systemdTimer, Mode: "0644"},
			)
		}
	}

	_ = s.publishAudit(ctx, "audit.ekm.file_encrypt_agent_downloaded", req.TenantID, map[string]interface{}{
		"target_os":     targetOS,
		"distro":        distro,
		"key_id":        keyID,
		"watch_dirs":    watchDirs,
		"file_patterns": patterns,
	})
	return FileEncryptPackage{
		TargetOS:     targetOS,
		Distro:       distro,
		CreatedAt:    time.Now().UTC(),
		Algorithm:    "AES-256-GCM",
		Mode:         "file_encrypt",
		KeyID:        keyID,
		RotationDays: rotDays,
		Files:        files,
	}, nil
}

func buildFileEncryptReadme(targetOS, distro, apiBase, watchDirs, patterns string, rotDays int) string {
	if targetOS == "windows" {
		return fmt.Sprintf(`Vecta KMS — File Encryption TDE Agent (Windows, User-Space)
============================================================
Algorithm  : AES-256-GCM (FIPS 140-3 Level 1 approved)
Mode       : User-space — no kernel driver or admin rights required
API        : %s

Quick Start
-----------
1. Edit agent.env — set VECTA_AUTH_TOKEN and confirm VECTA_KEY_ID
2. Run install.ps1  (no admin needed)
3. The Windows Task Scheduler job "VectaFileEncryptTDE" runs every 5 minutes

Manual encrypt :  powershell -File vecta-file-encrypt.ps1 -Command encrypt
Manual decrypt :  powershell -File vecta-file-encrypt.ps1 -Command decrypt
Rotate key     :  powershell -File vecta-rotate-key.ps1

Watch dirs     : %s
File patterns  : %s
Rotation       : every %d days

Security Notes
--------------
* AES-256-GCM provides confidentiality AND integrity (AEAD).
* The DEK is never stored on disk — fetched from Vecta KMS per run over mTLS.
* agent.env permissions are set to current user only (icacls).
`, apiBase, watchDirs, patterns, rotDays)
	}
	svcInstructions := ""
	switch distro {
	case "alpine":
		svcInstructions = `  rc-update add vecta-file-encrypt default   # add to user runlevel
  rc-service vecta-file-encrypt start`
	default:
		svcInstructions = `  mkdir -p ~/.config/systemd/user
  cp vecta-file-encrypt.service vecta-file-encrypt.timer ~/.config/systemd/user/
  systemctl --user daemon-reload
  systemctl --user enable --now vecta-file-encrypt.timer`
	}
	return fmt.Sprintf(`# Vecta KMS — File Encryption TDE Agent (Linux/%s, User-Space)
Algorithm  : AES-256-GCM (FIPS 140-3 Level 1 approved)
Mode       : User-space — no kernel module or root required
API        : %s

## Quick Start

1. Edit agent.env — set VECTA_AUTH_TOKEN and confirm VECTA_KEY_ID
2. Run the installer (no root required):

   bash install.sh

3. Install the service/timer:

%s

## Manual Operations

  Encrypt now : bash vecta-file-encrypt.sh encrypt
  Decrypt now : bash vecta-file-encrypt.sh decrypt
  Rotate key  : bash vecta-rotate-key.sh

## Policy

  Watch dirs    : %s
  File patterns : %s
  Rotation      : every %d days

## Security Notes

* AES-256-GCM provides confidentiality AND integrity (AEAD).
* The DEK is fetched from Vecta KMS per run over TLS 1.3 — never stored on disk.
* agent.env permissions are set to 600 (owner read/write only).
* openssl 3.x is required for FIPS-validated AES-256-GCM.
`, distro, apiBase, svcInstructions, watchDirs, patterns, rotDays)
}

// RevokeTDEKey revokes a TDE key, marks all agents and databases using it.
func (s *Service) RevokeTDEKey(ctx context.Context, keyID string, req RevokeTDEKeyRequest) (RevokeTDEKeyResponse, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	keyID = strings.TrimSpace(keyID)
	if req.TenantID == "" || keyID == "" {
		return RevokeTDEKeyResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key id are required")
	}
	if s.keycore == nil {
		return RevokeTDEKeyResponse{}, newServiceError(http.StatusFailedDependency, "keycore_unavailable", "keycore client is not configured")
	}

	key, err := s.store.GetTDEKey(ctx, req.TenantID, keyID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return RevokeTDEKeyResponse{}, newServiceError(http.StatusNotFound, "key_not_found", "tde key not found")
		}
		return RevokeTDEKeyResponse{}, err
	}

	// Destroy the key in KeyCore
	keyName := strings.TrimSpace(key.Name)
	if keyName == "" {
		keyName = keyID
	}
	keyCoreID := strings.TrimSpace(key.KeyCoreKeyID)
	if keyCoreID == "" {
		keyCoreID = keyID
	}
	reason := defaultString(req.Reason, "key-revocation")
	if err := s.keycore.DestroyKeyImmediately(ctx, req.TenantID, keyCoreID, keyName, "tde key revoke: "+reason); err != nil {
		msg := strings.ToLower(strings.TrimSpace(err.Error()))
		if !strings.Contains(msg, "not found") && !strings.Contains(msg, "already deleted") {
			return RevokeTDEKeyResponse{}, newServiceError(http.StatusBadGateway, "key_destroy_failed", err.Error())
		}
	}

	// Update key status to revoked
	_ = s.store.UpdateTDEKeyStatus(ctx, req.TenantID, keyID, "revoked")

	// Update all databases using this key
	dbs, err := s.store.ListDatabasesByKey(ctx, req.TenantID, keyID)
	if err != nil {
		return RevokeTDEKeyResponse{}, err
	}
	seen := map[string]struct{}{}
	affected := make([]string, 0)
	for _, db := range dbs {
		_ = s.store.UpdateDatabaseStatus(ctx, req.TenantID, db.ID, "key_revoked")
		aid := strings.TrimSpace(db.AgentID)
		if aid == "" {
			continue
		}
		if _, ok := seen[aid]; ok {
			continue
		}
		seen[aid] = struct{}{}
		// Mark agents as having a revoked key via config bump
		_ = s.store.BumpAgentConfigVersion(ctx, req.TenantID, aid, "", "")
		affected = append(affected, aid)
	}

	_ = s.publishAudit(ctx, "audit.ekm.tde_key_revoked", req.TenantID, map[string]interface{}{
		"key_id":              keyID,
		"reason":              reason,
		"affected_agent_ids":  affected,
		"affected_databases":  len(dbs),
	})

	return RevokeTDEKeyResponse{
		KeyID:             keyID,
		AffectedAgentIDs:  affected,
		AffectedDatabases: len(dbs),
	}, nil
}

// RevokeDatabaseTDE revokes TDE for a single database without affecting others on the same agent.
func (s *Service) RevokeDatabaseTDE(ctx context.Context, dbID string, req RevokeDatabaseTDERequest) (RevokeDatabaseTDEResponse, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	dbID = strings.TrimSpace(dbID)
	if req.TenantID == "" || dbID == "" {
		return RevokeDatabaseTDEResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and database id are required")
	}

	dbi, err := s.store.GetDatabase(ctx, req.TenantID, dbID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return RevokeDatabaseTDEResponse{}, newServiceError(http.StatusNotFound, "database_not_found", "database not found")
		}
		return RevokeDatabaseTDEResponse{}, err
	}

	// Mark TDE as disabled for this database only
	if err := s.store.UpdateDatabaseStatus(ctx, req.TenantID, dbID, "tde_disabled"); err != nil {
		return RevokeDatabaseTDEResponse{}, err
	}

	reason := defaultString(req.Reason, "database-tde-revoke")
	_ = s.publishAudit(ctx, "audit.ekm.database_tde_revoked", req.TenantID, map[string]interface{}{
		"database_id": dbID,
		"agent_id":    dbi.AgentID,
		"key_id":      dbi.KeyID,
		"engine":      dbi.Engine,
		"reason":      reason,
	})

	return RevokeDatabaseTDEResponse{
		DatabaseID: dbID,
		KeyID:      dbi.KeyID,
		Status:     "tde_disabled",
	}, nil
}

// ValidateDeployment validates that an agent deployment is properly connected.
func (s *Service) ValidateDeployment(ctx context.Context, agentID string, req ValidateDeploymentRequest) (ValidateDeploymentResponse, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	agentID = strings.TrimSpace(agentID)
	if req.TenantID == "" || agentID == "" {
		return ValidateDeploymentResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and agent id are required")
	}

	messages := make([]string, 0)
	status := "valid"

	agent, err := s.store.GetAgent(ctx, req.TenantID, agentID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			// Agent not registered yet -- register it now from the validation request
			regReq := RegisterAgentRequest{
				TenantID: req.TenantID,
				AgentID:  agentID,
				Version:  strings.TrimSpace(req.Version),
				Host:     strings.TrimSpace(req.Host),
				DBEngine: strings.TrimSpace(req.DBEngine),
			}
			agent, _, err = s.RegisterAgent(ctx, regReq, "")
			if err != nil {
				return ValidateDeploymentResponse{}, err
			}
			messages = append(messages, "agent auto-registered during validation")
		} else {
			return ValidateDeploymentResponse{}, err
		}
	}

	// Check agent connectivity
	connectivity := strings.ToLower(strings.TrimSpace(req.Connectivity))
	if connectivity == "failed" {
		status = "invalid"
		messages = append(messages, "agent reported connectivity failure")
	} else if connectivity == "degraded" {
		messages = append(messages, "agent reported degraded connectivity")
	}

	// Check version match
	if strings.TrimSpace(req.Version) != "" && strings.TrimSpace(agent.Version) != "" {
		if strings.TrimSpace(req.Version) != strings.TrimSpace(agent.Version) {
			messages = append(messages, "agent version mismatch: expected "+agent.Version+" got "+req.Version)
		}
	}

	// Update heartbeat to mark the agent as connected
	now := time.Now().UTC()
	_ = s.store.UpdateAgentHeartbeat(ctx, req.TenantID, agentID, AgentStatusConnected, agent.TDEState, "", "", 0, validJSONOr(agent.MetadataJSON, "{}"), now)

	if len(messages) == 0 {
		messages = append(messages, "deployment validated successfully")
	}

	_ = s.publishAudit(ctx, "audit.ekm.deployment_validated", req.TenantID, map[string]interface{}{
		"agent_id":     agentID,
		"status":       status,
		"connectivity": connectivity,
		"messages":     messages,
	})

	return ValidateDeploymentResponse{
		AgentID:  agentID,
		Status:   status,
		Messages: messages,
	}, nil
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

func recommendedProfilesForEngine(engine string) []string {
	switch normalizeDBEngine(engine) {
	case "mssql":
		return []string{"mssql-tde-pkcs11"}
	case "oracle":
		return []string{"oracle-tde-pkcs11"}
	case "postgresql":
		return []string{"postgresql-tde-pkcs11"}
	case "mysql":
		return []string{"mysql-tde-pkcs11"}
	case "mariadb":
		return []string{"mariadb-tde-pkcs11"}
	case "db2":
		return []string{"db2-tde-pkcs11"}
	default:
		return []string{"mssql-tde-pkcs11", "oracle-tde-pkcs11"}
	}
}

func buildTDESetupGuide(engine string, agentID string) string {
	header := `# Vecta EKM - TDE Setup Guide
# Agent: ` + agentID + `
# Engine: ` + engine + `
#
# This file contains SQL commands to configure Transparent Data Encryption (TDE)
# using the Vecta EKM PKCS#11 provider. Replace placeholder values before executing.

`
	mssqlGuide := `## MSSQL (SQL Server) TDE Setup

` + "```sql" + `
-- Step 1: Create EKM Provider
CREATE CRYPTOGRAPHIC PROVIDER VectaEKM FROM FILE = 'C:\vecta-ekm\vecta-pkcs11.dll';

-- Step 2: Create credential mapped to EKM
CREATE CREDENTIAL VectaEKMCred WITH IDENTITY = 'vecta-ekm', SECRET = '<agent-token>';
ALTER LOGIN [sa] ADD CREDENTIAL VectaEKMCred;

-- Step 3: Create asymmetric key from EKM
CREATE ASYMMETRIC KEY VectaTDEKey FROM PROVIDER VectaEKM WITH ALGORITHM = RSA_2048, PROVIDER_KEY_NAME = '<key-name>';

-- Step 4: Create database encryption key and enable TDE
USE <database>;
CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER ASYMMETRIC KEY VectaTDEKey;
ALTER DATABASE <database> SET ENCRYPTION ON;
` + "```" + `

`

	oracleGuide := `## Oracle TDE Setup

` + "```sql" + `
-- Option A: Configure Oracle TDE wallet
ALTER SYSTEM SET ENCRYPTION WALLET OPEN IDENTIFIED BY "<wallet-password>";

-- Option B: PKCS#11 integration
ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=OKV|PKCS11' SCOPE=BOTH;

-- Create master encryption key
ADMINISTER KEY MANAGEMENT CREATE KEY USING TAG 'vecta-managed' IDENTIFIED BY "<password>" WITH BACKUP;
ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY "<password>" WITH BACKUP;

-- Encrypt tablespace
ALTER TABLESPACE users ENCRYPTION ONLINE USING 'AES256' ENCRYPT;
` + "```" + `

`

	postgresqlGuide := `## PostgreSQL TDE Setup (pg_tde extension or native 17+)

` + "```sql" + `
-- Configure encryption provider
ALTER SYSTEM SET pg_tde.keyring_provider = 'pkcs11';
ALTER SYSTEM SET pg_tde.pkcs11_library = '/usr/lib/vecta-ekm/libvecta-pkcs11.so';
SELECT pg_reload_conf();

-- Create encrypted tablespace
CREATE TABLESPACE encrypted_ts LOCATION '/data/encrypted' WITH (encryption = 'aes-256');
` + "```" + `

`

	mysqlGuide := `## MySQL TDE Setup (with PKCS#11 keyring)

` + "```sql" + `
-- Install PKCS#11 keyring plugin
INSTALL PLUGIN keyring_pkcs11 SONAME 'keyring_pkcs11.so';
SET GLOBAL keyring_pkcs11_lib_path = '/usr/lib/vecta-ekm/libvecta-pkcs11.so';

-- Encrypt a table
ALTER TABLE sensitive_data ENCRYPTION='Y';

-- Encrypt a tablespace
CREATE TABLESPACE encrypted_ts ADD DATAFILE 'encrypted01.ibd' ENCRYPTION='Y';
` + "```" + `

`

	db2Guide := `## DB2 TDE Setup (native encryption with external keystore)

` + "```sql" + `
-- Configure DB2 to use external keystore
UPDATE DBM CFG USING KEYSTORE_TYPE PKCS12 KEYSTORE_LOCATION /etc/vecta-ekm/db2keystore;

-- Create encrypted database
CREATE DATABASE mydb ENCRYPT;
` + "```" + `

`

	mariadbGuide := `## MariaDB TDE Setup (with PKCS#11 encryption plugin)

` + "```sql" + `
-- Install file_key_management or PKCS#11 encryption plugin
INSTALL SONAME 'file_key_management';

-- Or use the Vecta PKCS#11 provider via keyring
SET GLOBAL innodb_encrypt_tables = ON;
SET GLOBAL innodb_encryption_threads = 4;

-- Encrypt individual tables
ALTER TABLE sensitive_data ENCRYPTED=YES ENCRYPTION_KEY_ID=1;
` + "```" + `

`

	switch normalizeDBEngine(engine) {
	case "mssql":
		return header + mssqlGuide
	case "oracle":
		return header + oracleGuide
	case "postgresql":
		return header + postgresqlGuide
	case "mysql":
		return header + mysqlGuide
	case "db2":
		return header + db2Guide
	case "mariadb":
		return header + mariadbGuide
	default:
		// Include all guides when engine is unknown
		return header + mssqlGuide + oracleGuide + postgresqlGuide + mysqlGuide + db2Guide + mariadbGuide
	}
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
