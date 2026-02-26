package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Service struct {
	store            Store
	keycore          KeyCoreClient
	policy           PolicyClient
	governance       GovernanceClient
	events           EventPublisher
	policyFailClosed bool
}

func NewService(store Store, keycore KeyCoreClient, policy PolicyClient, governance GovernanceClient, events EventPublisher, policyFailClosed bool) *Service {
	return &Service{
		store:            store,
		keycore:          keycore,
		policy:           policy,
		governance:       governance,
		events:           events,
		policyFailClosed: policyFailClosed,
	}
}

func (s *Service) ConfigureEndpoint(ctx context.Context, cfg EndpointConfig) (EndpointConfig, error) {
	cfg.TenantID = strings.TrimSpace(cfg.TenantID)
	cfg.Protocol = normalizeProtocol(cfg.Protocol)
	cfg.AuthMode = normalizeAuthMode(cfg.AuthMode)
	cfg.MetadataJSON = validJSONOr(cfg.MetadataJSON, "{}")
	if cfg.TenantID == "" || cfg.Protocol == "" {
		return EndpointConfig{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and protocol are required")
	}
	if cfg.AuthMode == "" {
		return EndpointConfig{}, newServiceError(http.StatusBadRequest, "bad_request", "invalid auth_mode")
	}
	if err := s.store.UpsertEndpoint(ctx, cfg); err != nil {
		return EndpointConfig{}, err
	}
	out, err := s.store.GetEndpoint(ctx, cfg.TenantID, cfg.Protocol)
	if err != nil {
		return EndpointConfig{}, err
	}
	_ = s.publishAudit(ctx, "audit.hyok.endpoint_configured", cfg.TenantID, map[string]interface{}{
		"protocol":            out.Protocol,
		"enabled":             out.Enabled,
		"auth_mode":           out.AuthMode,
		"governance_required": out.GovernanceRequired,
	})
	return out, nil
}

func (s *Service) ListEndpoints(ctx context.Context, tenantID string) ([]EndpointConfig, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	current, err := s.store.ListEndpoints(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	index := map[string]EndpointConfig{}
	for _, item := range current {
		index[item.Protocol] = item
	}
	protocols := []string{ProtocolDKE, ProtocolSalesforce, ProtocolGoogleEKM, ProtocolGeneric}
	out := make([]EndpointConfig, 0, len(protocols))
	for _, p := range protocols {
		if item, ok := index[p]; ok {
			out = append(out, item)
			continue
		}
		out = append(out, defaultEndpointConfig(tenantID, p))
	}
	return out, nil
}

func (s *Service) DeleteEndpoint(ctx context.Context, tenantID string, protocol string) error {
	tenantID = strings.TrimSpace(tenantID)
	protocol = normalizeProtocol(protocol)
	if tenantID == "" || protocol == "" {
		return newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and protocol are required")
	}
	if err := s.store.DeleteEndpoint(ctx, tenantID, protocol); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.hyok.endpoint_removed", tenantID, map[string]interface{}{
		"protocol": protocol,
	})
	return nil
}

func (s *Service) ListRequests(ctx context.Context, tenantID string, protocol string, limit int, offset int) ([]ProxyRequestLog, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if protocol != "" {
		protocol = normalizeProtocol(protocol)
		if protocol == "" {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", "invalid protocol")
		}
	}
	return s.store.ListRequestLogs(ctx, tenantID, protocol, limit, offset)
}

func (s *Service) Health(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	endpoints, err := s.ListEndpoints(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	enabled := 0
	for _, item := range endpoints {
		if item.Enabled {
			enabled++
		}
	}
	out := map[string]interface{}{
		"status":             "ok",
		"tenant_id":          tenantID,
		"endpoint_count":     len(endpoints),
		"enabled_endpoints":  enabled,
		"policy_fail_closed": s.policyFailClosed,
		"checked_at":         time.Now().UTC().Format(time.RFC3339Nano),
	}
	_ = s.publishAudit(ctx, "audit.hyok.health_check", tenantID, out)
	return out, nil
}

func (s *Service) ProcessCrypto(ctx context.Context, tenantID string, protocol string, operation string, keyID string, endpointPath string, identity AuthIdentity, req ProxyCryptoRequest) (ProxyCryptoResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	protocol = normalizeProtocol(protocol)
	operation = normalizeOperation(operation)
	keyID = strings.TrimSpace(keyID)
	if err := validateProtocolOperation(protocol, operation); err != nil {
		return ProxyCryptoResponse{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	if tenantID == "" || keyID == "" {
		return ProxyCryptoResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key id are required")
	}
	if req.TenantID != "" && strings.TrimSpace(req.TenantID) != tenantID {
		return ProxyCryptoResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant mismatch")
	}

	cfg, err := s.endpointForProtocol(ctx, tenantID, protocol)
	if err != nil {
		return ProxyCryptoResponse{}, err
	}
	if !cfg.Enabled {
		return ProxyCryptoResponse{}, newServiceError(http.StatusForbidden, "endpoint_disabled", "protocol endpoint is disabled")
	}
	if err := checkAuthMode(cfg.AuthMode, identity.Mode); err != nil {
		return ProxyCryptoResponse{}, newServiceError(http.StatusUnauthorized, "unauthorized", err.Error())
	}

	logEntry := ProxyRequestLog{
		ID:             newID("hreq"),
		TenantID:       tenantID,
		Protocol:       protocol,
		Operation:      operation,
		KeyID:          keyID,
		Endpoint:       strings.TrimSpace(endpointPath),
		AuthMode:       identity.Mode,
		AuthSubject:    firstNonEmpty(identity.Subject, identity.ClientCN, identity.UserID),
		RequesterID:    firstNonEmpty(req.RequesterID, identity.UserID, identity.Subject),
		RequesterEmail: strings.TrimSpace(req.RequesterEmail),
		Status:         "started",
		RequestJSON:    mustJSON(req),
		ResponseJSON:   "{}",
	}
	if err := s.store.CreateRequestLog(ctx, logEntry); err != nil {
		return ProxyCryptoResponse{}, err
	}

	policyDecision, policyReason, err := s.evaluatePolicy(ctx, tenantID, protocol, operation, keyID, cfg.PolicyID)
	if err != nil {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", err.Error(), "", policyDecision)
		return ProxyCryptoResponse{}, err
	}
	if policyDecision == "DENY" {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "denied", "{}", policyReason, "", policyDecision)
		_ = s.publishAudit(ctx, "audit.hyok.request_denied", tenantID, map[string]interface{}{
			"request_id": logEntry.ID,
			"protocol":   protocol,
			"operation":  operation,
			"key_id":     keyID,
			"reason":     policyReason,
		})
		return ProxyCryptoResponse{}, newServiceError(http.StatusForbidden, "policy_denied", firstNonEmpty(policyReason, "blocked by policy"))
	}

	if cfg.GovernanceRequired {
		if s.governance == nil {
			err := newServiceError(http.StatusFailedDependency, "governance_unavailable", "governance client is not configured")
			_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", err.Error(), "", policyDecision)
			return ProxyCryptoResponse{}, err
		}
		approvalID, err := s.governance.CreateKeyApproval(ctx, GovernanceApprovalRequest{
			TenantID:        tenantID,
			KeyID:           keyID,
			Operation:       operation,
			PayloadHash:     hashJSONPayload(req),
			RequesterID:     logEntry.RequesterID,
			RequesterEmail:  logEntry.RequesterEmail,
			RequesterIP:     identity.RemoteIP,
			CallbackService: "kms-hyok-proxy",
			CallbackAction:  "release_pending_operation",
			CallbackPayload: map[string]interface{}{"request_id": logEntry.ID},
		})
		if err != nil {
			_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", err.Error(), "", policyDecision)
			return ProxyCryptoResponse{}, newServiceError(http.StatusFailedDependency, "governance_failed", err.Error())
		}
		resp := ProxyCryptoResponse{
			Status:            "pending_approval",
			KeyID:             keyID,
			Protocol:          protocol,
			Operation:         operation,
			ApprovalRequestID: approvalID,
		}
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "pending_approval", mustJSON(resp), "", approvalID, policyDecision)
		_ = s.publishAudit(ctx, protocolEventSubject(protocol, operation), tenantID, map[string]interface{}{
			"request_id":          logEntry.ID,
			"protocol":            protocol,
			"operation":           operation,
			"key_id":              keyID,
			"approval_request_id": approvalID,
			"status":              "pending_approval",
		})
		return resp, nil
	}

	raw, callErr := s.keycoreDispatch(ctx, tenantID, keyID, operation, req)
	if callErr != nil {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", callErr.Error(), "", policyDecision)
		return ProxyCryptoResponse{}, newServiceError(http.StatusBadGateway, "keycore_failed", callErr.Error())
	}
	resp := ProxyCryptoResponse{
		Status:        "ok",
		KeyID:         strings.TrimSpace(firstString(raw["key_id"], keyID)),
		Protocol:      protocol,
		Operation:     operation,
		Version:       extractInt(raw["version"]),
		CiphertextB64: strings.TrimSpace(firstString(raw["ciphertext"])),
		PlaintextB64:  strings.TrimSpace(firstString(raw["plaintext"])),
		IVB64:         strings.TrimSpace(firstString(raw["iv"])),
	}
	_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "success", mustJSON(resp), "", "", policyDecision)
	_ = s.publishAudit(ctx, protocolEventSubject(protocol, operation), tenantID, map[string]interface{}{
		"request_id":      logEntry.ID,
		"protocol":        protocol,
		"operation":       operation,
		"key_id":          keyID,
		"policy_decision": policyDecision,
		"status":          "success",
	})
	return resp, nil
}

func (s *Service) GetDKEPublicKey(ctx context.Context, tenantID string, keyID string, endpointPath string, identity AuthIdentity) (DKEPublicKeyResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	keyID = strings.TrimSpace(keyID)
	if tenantID == "" || keyID == "" {
		return DKEPublicKeyResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key id are required")
	}
	cfg, err := s.endpointForProtocol(ctx, tenantID, ProtocolDKE)
	if err != nil {
		return DKEPublicKeyResponse{}, err
	}
	if !cfg.Enabled {
		return DKEPublicKeyResponse{}, newServiceError(http.StatusForbidden, "endpoint_disabled", "protocol endpoint is disabled")
	}
	if err := checkAuthMode(cfg.AuthMode, identity.Mode); err != nil {
		return DKEPublicKeyResponse{}, newServiceError(http.StatusUnauthorized, "unauthorized", err.Error())
	}

	logEntry := ProxyRequestLog{
		ID:           newID("hreq"),
		TenantID:     tenantID,
		Protocol:     ProtocolDKE,
		Operation:    "publickey",
		KeyID:        keyID,
		Endpoint:     strings.TrimSpace(endpointPath),
		AuthMode:     identity.Mode,
		AuthSubject:  firstNonEmpty(identity.Subject, identity.ClientCN, identity.UserID),
		Status:       "started",
		RequestJSON:  "{}",
		ResponseJSON: "{}",
	}
	if err := s.store.CreateRequestLog(ctx, logEntry); err != nil {
		return DKEPublicKeyResponse{}, err
	}

	policyDecision, policyReason, err := s.evaluatePolicy(ctx, tenantID, ProtocolDKE, "publickey", keyID, cfg.PolicyID)
	if err != nil {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", err.Error(), "", policyDecision)
		return DKEPublicKeyResponse{}, err
	}
	if policyDecision == "DENY" {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "denied", "{}", policyReason, "", policyDecision)
		_ = s.publishAudit(ctx, "audit.hyok.request_denied", tenantID, map[string]interface{}{
			"request_id": logEntry.ID,
			"protocol":   ProtocolDKE,
			"operation":  "publickey",
			"key_id":     keyID,
			"reason":     policyReason,
		})
		return DKEPublicKeyResponse{}, newServiceError(http.StatusForbidden, "policy_denied", firstNonEmpty(policyReason, "blocked by policy"))
	}

	keyMeta, err := s.keycore.GetKey(ctx, tenantID, keyID)
	if err != nil {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", err.Error(), "", policyDecision)
		return DKEPublicKeyResponse{}, newServiceError(http.StatusBadGateway, "keycore_failed", err.Error())
	}
	algorithm := strings.TrimSpace(firstString(keyMeta["algorithm"], "unknown"))
	publicKey := strings.TrimSpace(firstString(keyMeta["public_key_pem"], keyMeta["public_key"]))
	format := "opaque"
	if strings.Contains(publicKey, "BEGIN") {
		format = "pem"
	}
	if publicKey == "" {
		publicKey = "DKE-PUBLIC-" + hashJSONPayload(map[string]string{"tenant_id": tenantID, "key_id": keyID})[:32]
		format = "opaque"
	}
	out := DKEPublicKeyResponse{
		KeyID:      keyID,
		Algorithm:  algorithm,
		PublicKey:  publicKey,
		Format:     format,
		KeyVersion: extractInt(keyMeta["current_version"]),
	}
	_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "success", mustJSON(out), "", "", policyDecision)
	_ = s.publishAudit(ctx, "audit.hyok.dke_request", tenantID, map[string]interface{}{
		"request_id":      logEntry.ID,
		"operation":       "publickey",
		"key_id":          keyID,
		"policy_decision": policyDecision,
		"status":          "success",
	})
	return out, nil
}

func (s *Service) GetMicrosoftDKEKey(ctx context.Context, tenantID string, keyID string, endpointPath string, host string, identity AuthIdentity) (MicrosoftDKEKeyResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	keyID = strings.TrimSpace(keyID)
	if tenantID == "" || keyID == "" {
		return MicrosoftDKEKeyResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key id are required")
	}
	cfg, err := s.endpointForProtocol(ctx, tenantID, ProtocolDKE)
	if err != nil {
		return MicrosoftDKEKeyResponse{}, err
	}
	if !cfg.Enabled {
		return MicrosoftDKEKeyResponse{}, newServiceError(http.StatusForbidden, "endpoint_disabled", "protocol endpoint is disabled")
	}
	if err := checkAuthMode(cfg.AuthMode, identity.Mode); err != nil {
		return MicrosoftDKEKeyResponse{}, newServiceError(http.StatusUnauthorized, "unauthorized", err.Error())
	}
	meta, err := parseDKEEndpointMetadata(cfg.MetadataJSON)
	if err != nil {
		return MicrosoftDKEKeyResponse{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	if err := validateDKEIdentity(meta, tenantID, normalizeHost(host), identity); err != nil {
		return MicrosoftDKEKeyResponse{}, err
	}

	logEntry := ProxyRequestLog{
		ID:           newID("hreq"),
		TenantID:     tenantID,
		Protocol:     ProtocolDKE,
		Operation:    "publickey",
		KeyID:        keyID,
		Endpoint:     strings.TrimSpace(endpointPath),
		AuthMode:     identity.Mode,
		AuthSubject:  firstNonEmpty(identity.Subject, identity.ClientCN, identity.UserID),
		Status:       "started",
		RequestJSON:  "{}",
		ResponseJSON: "{}",
	}
	if err := s.store.CreateRequestLog(ctx, logEntry); err != nil {
		return MicrosoftDKEKeyResponse{}, err
	}

	policyDecision, policyReason, err := s.evaluatePolicy(ctx, tenantID, ProtocolDKE, "publickey", keyID, cfg.PolicyID)
	if err != nil {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", err.Error(), "", policyDecision)
		return MicrosoftDKEKeyResponse{}, err
	}
	if policyDecision == "DENY" {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "denied", "{}", policyReason, "", policyDecision)
		_ = s.publishAudit(ctx, "audit.hyok.request_denied", tenantID, map[string]interface{}{
			"request_id": logEntry.ID,
			"protocol":   ProtocolDKE,
			"operation":  "publickey",
			"key_id":     keyID,
			"reason":     policyReason,
		})
		return MicrosoftDKEKeyResponse{}, newServiceError(http.StatusForbidden, "policy_denied", firstNonEmpty(policyReason, "blocked by policy"))
	}

	keyMeta, err := s.keycore.GetKey(ctx, tenantID, keyID)
	if err != nil {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", err.Error(), "", policyDecision)
		return MicrosoftDKEKeyResponse{}, newServiceError(http.StatusBadGateway, "keycore_failed", err.Error())
	}
	publicKeyPEM := strings.TrimSpace(firstString(keyMeta["public_key_pem"], keyMeta["public_key"]))
	if publicKeyPEM == "" {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", "public key is unavailable for key", "", policyDecision)
		return MicrosoftDKEKeyResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "public key is unavailable for this key")
	}
	rsaPub, err := parseRSAPublicKey(publicKeyPEM)
	if err != nil {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", err.Error(), "", policyDecision)
		return MicrosoftDKEKeyResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "key is not RSA-compatible for DKE")
	}
	alg := inferDKEAlg(keyMeta, meta)
	out := MicrosoftDKEKeyResponse{
		KTY:    "RSA",
		KeyOps: []string{"decrypt"},
		N:      base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes()),
		E:      base64.RawURLEncoding.EncodeToString(bigEndianExponentBytes(rsaPub.E)),
		Alg:    alg,
		KID:    keyID,
		Use:    "enc",
	}
	_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "success", mustJSON(out), "", "", policyDecision)
	_ = s.publishAudit(ctx, "audit.hyok.dke_request", tenantID, map[string]interface{}{
		"request_id":      logEntry.ID,
		"operation":       "publickey",
		"key_id":          keyID,
		"policy_decision": policyDecision,
		"status":          "success",
		"adapter":         "microsoft",
	})
	return out, nil
}

func (s *Service) ProcessMicrosoftDKEDecrypt(ctx context.Context, tenantID string, keyID string, endpointPath string, host string, identity AuthIdentity, req MicrosoftDKEDecryptRequest) (MicrosoftDKEDecryptResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	keyID = strings.TrimSpace(keyID)
	if tenantID == "" || keyID == "" {
		return MicrosoftDKEDecryptResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key id are required")
	}
	ciphertextB64URL := strings.TrimSpace(req.Value)
	if ciphertextB64URL == "" {
		return MicrosoftDKEDecryptResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "value is required")
	}
	cfg, err := s.endpointForProtocol(ctx, tenantID, ProtocolDKE)
	if err != nil {
		return MicrosoftDKEDecryptResponse{}, err
	}
	if !cfg.Enabled {
		return MicrosoftDKEDecryptResponse{}, newServiceError(http.StatusForbidden, "endpoint_disabled", "protocol endpoint is disabled")
	}
	if err := checkAuthMode(cfg.AuthMode, identity.Mode); err != nil {
		return MicrosoftDKEDecryptResponse{}, newServiceError(http.StatusUnauthorized, "unauthorized", err.Error())
	}
	meta, err := parseDKEEndpointMetadata(cfg.MetadataJSON)
	if err != nil {
		return MicrosoftDKEDecryptResponse{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	if err := validateDKEIdentity(meta, tenantID, normalizeHost(host), identity); err != nil {
		return MicrosoftDKEDecryptResponse{}, err
	}
	if err := validateDKEAlg(strings.TrimSpace(req.Alg), meta); err != nil {
		return MicrosoftDKEDecryptResponse{}, err
	}
	if kid := strings.TrimSpace(req.KID); kid != "" && !strings.EqualFold(kid, keyID) {
		return MicrosoftDKEDecryptResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "kid does not match key id")
	}

	ciphertextRaw, err := base64.RawURLEncoding.DecodeString(ciphertextB64URL)
	if err != nil {
		return MicrosoftDKEDecryptResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "value must be base64url")
	}
	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertextRaw)

	cryptoResp, err := s.ProcessCrypto(ctx, tenantID, ProtocolDKE, "decrypt", keyID, endpointPath, identity, ProxyCryptoRequest{
		CiphertextB64: ciphertextB64,
	})
	if err != nil {
		return MicrosoftDKEDecryptResponse{}, err
	}
	plaintextB64 := strings.TrimSpace(cryptoResp.PlaintextB64)
	if plaintextB64 == "" {
		return MicrosoftDKEDecryptResponse{}, newServiceError(http.StatusBadGateway, "keycore_failed", "decrypt response missing plaintext")
	}
	plainRaw, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		if rawURL, errURL := base64.RawURLEncoding.DecodeString(plaintextB64); errURL == nil {
			return MicrosoftDKEDecryptResponse{Value: base64.RawURLEncoding.EncodeToString(rawURL)}, nil
		}
		return MicrosoftDKEDecryptResponse{}, newServiceError(http.StatusBadGateway, "keycore_failed", "invalid decrypt plaintext encoding")
	}
	return MicrosoftDKEDecryptResponse{Value: base64.RawURLEncoding.EncodeToString(plainRaw)}, nil
}

func (s *Service) endpointForProtocol(ctx context.Context, tenantID string, protocol string) (EndpointConfig, error) {
	cfg, err := s.store.GetEndpoint(ctx, tenantID, protocol)
	if errors.Is(err, errNotFound) {
		return defaultEndpointConfig(tenantID, protocol), nil
	}
	if err != nil {
		return EndpointConfig{}, err
	}
	cfg.AuthMode = normalizeAuthMode(cfg.AuthMode)
	if cfg.AuthMode == "" {
		cfg.AuthMode = AuthModeMTLSOrJWT
	}
	return cfg, nil
}

func (s *Service) evaluatePolicy(ctx context.Context, tenantID string, protocol string, operation string, keyID string, policyID string) (string, string, error) {
	if s.policy == nil {
		return "ALLOW", "", nil
	}
	resp, err := s.policy.Evaluate(ctx, PolicyEvaluateRequest{
		TenantID:  tenantID,
		Operation: composePolicyOperation(protocol, operation),
		KeyID:     keyID,
		PolicyID:  strings.TrimSpace(policyID),
	})
	if err != nil {
		if s.policyFailClosed {
			return "ERROR", "", newServiceError(http.StatusFailedDependency, "policy_unavailable", err.Error())
		}
		return "ALLOW", "policy_unavailable_fail_open", nil
	}
	decision := strings.ToUpper(strings.TrimSpace(resp.Decision))
	if decision == "" {
		decision = "ALLOW"
	}
	return decision, strings.TrimSpace(resp.Reason), nil
}

func (s *Service) keycoreDispatch(ctx context.Context, tenantID string, keyID string, operation string, req ProxyCryptoRequest) (map[string]interface{}, error) {
	switch operation {
	case "encrypt":
		if strings.TrimSpace(req.PlaintextB64) == "" {
			return nil, errors.New("plaintext is required")
		}
		return s.keycore.Encrypt(ctx, tenantID, keyID, req.PlaintextB64, req.IVB64, req.ReferenceID)
	case "decrypt":
		if strings.TrimSpace(req.CiphertextB64) == "" {
			return nil, errors.New("ciphertext is required")
		}
		return s.keycore.Decrypt(ctx, tenantID, keyID, req.CiphertextB64, req.IVB64)
	case "wrap":
		if strings.TrimSpace(req.PlaintextB64) == "" {
			return nil, errors.New("plaintext is required")
		}
		return s.keycore.Wrap(ctx, tenantID, keyID, req.PlaintextB64, req.IVB64, req.ReferenceID)
	case "unwrap":
		if strings.TrimSpace(req.CiphertextB64) == "" {
			return nil, errors.New("ciphertext is required")
		}
		return s.keycore.Unwrap(ctx, tenantID, keyID, req.CiphertextB64, req.IVB64)
	default:
		return nil, errors.New("unsupported operation")
	}
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "hyok",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}

func protocolEventSubject(protocol string, operation string) string {
	switch normalizeProtocol(protocol) {
	case ProtocolDKE:
		return "audit.hyok.dke_request"
	case ProtocolSalesforce:
		return "audit.hyok.salesforce_request"
	case ProtocolGoogleEKM:
		return "audit.hyok.google_ekm_request"
	case ProtocolGeneric:
		switch normalizeOperation(operation) {
		case "decrypt", "unwrap":
			return "audit.hyok.unwrap_request"
		default:
			return "audit.hyok.wrap_request"
		}
	default:
		return "audit.hyok.wrap_request"
	}
}

func composePolicyOperation(protocol string, operation string) string {
	return "hyok." + normalizeProtocol(protocol) + "." + normalizeOperation(operation)
}

func checkAuthMode(required string, actual string) error {
	required = normalizeAuthMode(required)
	actual = strings.TrimSpace(strings.ToLower(actual))
	switch required {
	case AuthModeMTLSOrJWT:
		if actual == "mtls" || actual == "jwt" {
			return nil
		}
		return errors.New("mTLS or JWT authentication is required")
	case AuthModeMTLS:
		if actual == "mtls" {
			return nil
		}
		return errors.New("mTLS authentication is required")
	case AuthModeJWT:
		if actual == "jwt" {
			return nil
		}
		return errors.New("JWT authentication is required")
	default:
		return errors.New("invalid auth_mode")
	}
}

func mustJSON(v interface{}) string {
	raw, _ := json.Marshal(v)
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

func firstString(values ...interface{}) string {
	for _, v := range values {
		switch x := v.(type) {
		case string:
			if strings.TrimSpace(x) != "" {
				return strings.TrimSpace(x)
			}
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func parseDKEEndpointMetadata(raw string) (DKEEndpointMetadata, error) {
	meta := DKEEndpointMetadata{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return meta, nil
	}
	var body map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		return DKEEndpointMetadata{}, errors.New("metadata_json must be valid JSON")
	}
	meta.AuthorizedTenants = nonEmptyStrings(
		extractStringSlice(body["authorized_tenants"]),
		extractStringSlice(body["authorized_tenant_ids"]),
		extractStringSlice(body["authorizedTenants"]),
	)
	meta.ValidIssuers = nonEmptyStrings(
		extractStringSlice(body["valid_issuers"]),
		extractStringSlice(body["validIssuers"]),
	)
	meta.JWTAudiences = nonEmptyStrings(
		extractStringSlice(body["jwt_audiences"]),
		extractStringSlice(body["jwt_audience"]),
		extractStringSlice(body["audience"]),
	)
	meta.KeyURIHostname = strings.TrimSpace(firstString(body["key_uri_hostname"], body["keyURIHostname"]))
	meta.AllowedAlgorithms = nonEmptyStrings(
		extractStringSlice(body["allowed_algorithms"]),
		extractStringSlice(body["allowed_algs"]),
		extractStringSlice(body["algorithms"]),
	)
	return meta, nil
}

func validateDKEIdentity(meta DKEEndpointMetadata, tenantID string, host string, identity AuthIdentity) error {
	if len(meta.AuthorizedTenants) > 0 && !containsFold(meta.AuthorizedTenants, tenantID) {
		return newServiceError(http.StatusForbidden, "policy_denied", "tenant is not authorized for this DKE endpoint")
	}
	if len(meta.ValidIssuers) > 0 {
		issuer := strings.TrimSpace(identity.JWTIssuer)
		if issuer == "" || !containsFold(meta.ValidIssuers, issuer) {
			return newServiceError(http.StatusUnauthorized, "unauthorized", "token issuer is not allowed")
		}
	}
	if len(meta.JWTAudiences) > 0 {
		if len(identity.JWTAudiences) == 0 {
			return newServiceError(http.StatusUnauthorized, "unauthorized", "token audience is required")
		}
		ok := false
		for _, aud := range identity.JWTAudiences {
			if containsFold(meta.JWTAudiences, aud) {
				ok = true
				break
			}
		}
		if !ok {
			return newServiceError(http.StatusUnauthorized, "unauthorized", "token audience is not allowed")
		}
	}
	if strings.TrimSpace(meta.KeyURIHostname) != "" && !strings.EqualFold(strings.TrimSpace(meta.KeyURIHostname), strings.TrimSpace(host)) {
		return newServiceError(http.StatusUnauthorized, "unauthorized", "host does not match configured key URI hostname")
	}
	return nil
}

func validateDKEAlg(alg string, meta DKEEndpointMetadata) error {
	alg = strings.TrimSpace(alg)
	if alg == "" {
		return nil
	}
	if len(meta.AllowedAlgorithms) > 0 && !containsFold(meta.AllowedAlgorithms, alg) {
		return newServiceError(http.StatusBadRequest, "bad_request", "algorithm is not allowed")
	}
	if !strings.HasPrefix(strings.ToUpper(alg), "RSA-OAEP") {
		return newServiceError(http.StatusBadRequest, "bad_request", "unsupported algorithm")
	}
	return nil
}

func inferDKEAlg(keyMeta map[string]interface{}, meta DKEEndpointMetadata) string {
	if len(meta.AllowedAlgorithms) > 0 {
		return strings.TrimSpace(meta.AllowedAlgorithms[0])
	}
	alg := strings.ToUpper(strings.TrimSpace(firstString(keyMeta["algorithm"])))
	switch {
	case strings.Contains(alg, "SHA512"):
		return "RSA-OAEP-512"
	case strings.Contains(alg, "SHA384"):
		return "RSA-OAEP-384"
	case strings.Contains(alg, "RSA"):
		return "RSA-OAEP-256"
	default:
		return "RSA-OAEP-256"
	}
}

func parseRSAPublicKey(publicKey string) (*rsa.PublicKey, error) {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return nil, errors.New("empty public key")
	}
	if block, _ := pem.Decode([]byte(publicKey)); block != nil {
		if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if rsaPub, ok := parsed.(*rsa.PublicKey); ok {
				return rsaPub, nil
			}
		}
		if rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
			return rsaPub, nil
		}
	}
	if der, err := base64.StdEncoding.DecodeString(publicKey); err == nil {
		if parsed, err := x509.ParsePKIXPublicKey(der); err == nil {
			if rsaPub, ok := parsed.(*rsa.PublicKey); ok {
				return rsaPub, nil
			}
		}
	}
	return nil, errors.New("unable to parse RSA public key")
}

func bigEndianExponentBytes(e int) []byte {
	if e <= 0 {
		return []byte{0x01, 0x00, 0x01}
	}
	out := []byte{}
	for e > 0 {
		out = append([]byte{byte(e & 0xff)}, out...)
		e >>= 8
	}
	return out
}

func extractStringSlice(v interface{}) []string {
	switch x := v.(type) {
	case string:
		x = strings.TrimSpace(x)
		if x == "" {
			return nil
		}
		if strings.Contains(x, ",") {
			parts := strings.Split(x, ",")
			out := make([]string, 0, len(parts))
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					out = append(out, p)
				}
			}
			return out
		}
		return []string{x}
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	case []string:
		return x
	default:
		return nil
	}
}

func nonEmptyStrings(values ...[]string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, set := range values {
		for _, item := range set {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			key := strings.ToLower(item)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}

func containsFold(values []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, item := range values {
		if strings.EqualFold(strings.TrimSpace(item), target) {
			return true
		}
	}
	return false
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return host
	}
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			return strings.TrimSpace(strings.ToLower(h))
		}
	}
	return host
}
