package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgkeyaccess "vecta-kms/pkg/keyaccess"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Service struct {
	store      Store
	keycore    KeyCoreClient
	policy     PolicyClient
	governance GovernanceClient
	events     EventPublisher
	keyAccess  pkgkeyaccess.Gate
}

func NewService(store Store, keycore KeyCoreClient, policy PolicyClient, governance GovernanceClient, events EventPublisher) *Service {
	return &Service{
		store:      store,
		keycore:    keycore,
		policy:     policy,
		governance: governance,
		events:     events,
	}
}

// SetKeyAccess wires the key access gate. Until it is set the zero gate
// refuses every key operation (fail closed).
func (s *Service) SetKeyAccess(g pkgkeyaccess.Gate) {
	s.keyAccess = g
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
	if cfg.AuthMode == AuthModeMTLS {
		// Envoy's edge listener does not verify client certificates, so no
		// request could ever prove an mTLS identity; refuse rather than store a
		// mode that looks enforced.
		return EndpointConfig{}, newServiceError(http.StatusBadRequest, "auth_mode_unavailable", "mTLS client authentication is not available: the edge does not verify client certificates; use jwt")
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
	protocols := []string{ProtocolDKE, ProtocolSalesforce, ProtocolGoogleEKM, ProtocolGeneric, ProtocolServiceNow, ProtocolAlibaba}
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
	configuredEndpoints, err := s.store.ListEndpoints(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	configuredByProtocol := map[string]EndpointConfig{}
	for _, item := range configuredEndpoints {
		configuredByProtocol[normalizeProtocol(item.Protocol)] = item
	}
	endpoints, err := s.ListEndpoints(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	enabled := 0
	connected := 0
	degraded := 0
	notConfigured := 0
	protocolStatuses := map[string]map[string]interface{}{}
	for _, item := range endpoints {
		if item.Enabled {
			enabled++
		}
		protocol := normalizeProtocol(item.Protocol)
		if protocol == "" {
			continue
		}

		cfg, configured := configuredByProtocol[protocol]
		status := "not_configured"
		reason := "endpoint config not saved yet"
		if configured {
			if !cfg.Enabled {
				status = "disabled"
				reason = "endpoint is disabled"
			} else {
				status, reason = s.endpointRuntimeStatus(ctx, tenantID, protocol)
			}
		}

		switch status {
		case "connected":
			connected++
		case "degraded", "auth_failed", "unreachable":
			degraded++
		case "not_configured":
			notConfigured++
		}
		protocolStatuses[protocol] = map[string]interface{}{
			"status":     status,
			"reason":     reason,
			"configured": configured,
			"enabled":    item.Enabled,
		}
	}

	overallStatus := "ok"
	switch {
	case degraded > 0:
		overallStatus = "degraded"
	case notConfigured == len(endpoints):
		overallStatus = "not_configured"
	case connected == 0 && enabled > 0:
		overallStatus = "configured"
	}

	out := map[string]interface{}{
		"status":                   overallStatus,
		"tenant_id":                tenantID,
		"endpoint_count":           len(endpoints),
		"enabled_endpoints":        enabled,
		"configured_endpoints":     len(configuredByProtocol),
		"connected_endpoints":      connected,
		"degraded_endpoints":       degraded,
		"not_configured_endpoints": notConfigured,
		"policy_fail_closed":       true,
		"protocol_statuses":        protocolStatuses,
		"checked_at":               time.Now().UTC().Format(time.RFC3339Nano),
	}
	_ = s.publishAudit(ctx, "audit.hyok.health_check", tenantID, out)
	return out, nil
}

func (s *Service) endpointRuntimeStatus(ctx context.Context, tenantID string, protocol string) (string, string) {
	logs, err := s.store.ListRequestLogs(ctx, tenantID, protocol, 25, 0)
	if err != nil {
		return "degraded", "unable to inspect request history"
	}
	if len(logs) == 0 {
		return "configured", "awaiting first successful request"
	}

	latest := logs[0]
	for _, item := range logs {
		state := strings.ToLower(strings.TrimSpace(item.Status))
		if state != "success" && state != "ok" {
			continue
		}
		when := item.CompletedAt
		if when.IsZero() {
			when = item.CreatedAt
		}
		if when.IsZero() {
			return "connected", "request flow verified"
		}
		return "connected", "last success " + when.UTC().Format(time.RFC3339)
	}

	latestState := strings.ToLower(strings.TrimSpace(latest.Status))
	if latestState == "pending_approval" {
		return "configured", "pending governance approval"
	}
	reason := strings.TrimSpace(latest.ErrorMessage)
	if reason == "" {
		reason = "latest request status: " + firstNonEmpty(latestState, "unknown")
	}
	reasonLower := strings.ToLower(reason)
	if strings.Contains(reasonLower, "unauthorized") || strings.Contains(reasonLower, "auth") || strings.Contains(reasonLower, "token") || strings.Contains(reasonLower, "forbidden") {
		return "auth_failed", reason
	}
	return "degraded", reason
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
		ID:                newID("hreq"),
		TenantID:          tenantID,
		Protocol:          protocol,
		Operation:         operation,
		KeyID:             keyID,
		Endpoint:          strings.TrimSpace(endpointPath),
		AuthMode:          identity.Mode,
		AuthSubject:       firstNonEmpty(identity.Subject, identity.ClientCN, identity.UserID),
		RequesterID:       firstNonEmpty(req.RequesterID, identity.UserID, identity.Subject),
		RequesterEmail:    strings.TrimSpace(req.RequesterEmail),
		Status:            "started",
		RequestJSON:       mustJSON(req),
		ResponseJSON:      "{}",
		GovernanceReq:     cfg.GovernanceRequired,
		ApprovalRequestID: strings.TrimSpace(req.ApprovalRequestID),
	}
	if err := s.store.CreateRequestLog(ctx, logEntry); err != nil {
		return ProxyCryptoResponse{}, err
	}
	// A retry carrying an approval ID is released only by that approval:
	// approved, for this key and operation (and payload, for a HYOK
	// approval), and not used before.
	approvedBy := ""
	if id := logEntry.ApprovalRequestID; id != "" {
		if err := s.redeemApproval(ctx, tenantID, id, logEntry.ID, keyID, operation, req); err != nil {
			_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "denied", "{}", err.Error(), id, "")
			_ = s.publishAudit(ctx, "audit.hyok.approval_refused", tenantID, map[string]interface{}{
				"request_id": logEntry.ID, "approval_request_id": id, "protocol": protocol, "operation": operation,
				"key_id": keyID, "reason": err.Error(), "result": "refused", "severity": "warning",
			})
			return ProxyCryptoResponse{}, newServiceError(http.StatusForbidden, "approval_invalid", err.Error())
		}
		approvedBy = id
	}

	policyDecision, policyReason, err := s.evaluatePolicy(ctx, tenantID, protocol, operation, keyID, cfg.PolicyID)
	if err != nil {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", err.Error(), "", policyDecision)
		_ = s.publishAudit(ctx, "audit.hyok.request_denied", tenantID, map[string]interface{}{
			"request_id": logEntry.ID, "operation": operation, "key_id": keyID,
			"reason": "policy_unavailable", "result": "refused", "severity": "warning",
		})
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

	keyAccessResult := pkgkeyaccess.EvaluateResponse{Action: "allow"}
	// A redeemed approval was already released by governance. Otherwise the
	// gate decides; a deployed key access service that gives no decision
	// refuses the request, whatever the policy service says.
	if approvedBy == "" {
		keyAccessResult, err = s.keyAccess.Evaluate(ctx, pkgkeyaccess.EvaluateRequest{
			TenantID:          tenantID,
			Service:           "hyok",
			Connector:         protocol,
			Operation:         operation,
			KeyID:             keyID,
			ResourceID:        strings.TrimSpace(endpointPath),
			RequestID:         logEntry.ID,
			RequesterID:       logEntry.RequesterID,
			RequesterEmail:    logEntry.RequesterEmail,
			RequesterIP:       identity.RemoteIP,
			JustificationCode: strings.TrimSpace(req.JustificationCode),
			JustificationText: strings.TrimSpace(req.JustificationText),
			Metadata: map[string]interface{}{
				"endpoint":     strings.TrimSpace(endpointPath),
				"auth_mode":    identity.Mode,
				"auth_subject": logEntry.AuthSubject,
				"reference_id": strings.TrimSpace(req.ReferenceID),
			},
		})
		if err != nil {
			_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", pkgkeyaccess.ReasonUnavailable, "", policyDecision)
			_ = s.publishAudit(ctx, "audit.hyok.request_denied", tenantID, map[string]interface{}{
				"request_id": logEntry.ID, "protocol": protocol, "operation": operation, "key_id": keyID,
				"reason": pkgkeyaccess.ReasonUnavailable, "error": err.Error(), "result": "refused", "severity": "warning",
			})
			return ProxyCryptoResponse{}, newServiceError(http.StatusFailedDependency, pkgkeyaccess.ReasonUnavailable, pkgkeyaccess.ErrUnavailable.Error())
		}
	}
	if strings.EqualFold(keyAccessResult.Action, "deny") {
		reason := firstNonEmpty(keyAccessResult.Reason, "blocked by key access justification policy")
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "denied", "{}", reason, "", policyDecision)
		_ = s.publishAudit(ctx, "audit.hyok.request_denied", tenantID, map[string]interface{}{
			"request_id":          logEntry.ID,
			"protocol":            protocol,
			"operation":           operation,
			"key_id":              keyID,
			"reason":              reason,
			"justification_code":  req.JustificationCode,
			"key_access_decision": keyAccessResult.Action,
		})
		return ProxyCryptoResponse{}, newServiceError(http.StatusForbidden, "key_access_denied", reason)
	}
	if keyAccessResult.ApprovalRequired {
		resp := ProxyCryptoResponse{
			Status:            "pending_approval",
			KeyID:             keyID,
			Protocol:          protocol,
			Operation:         operation,
			ApprovalRequestID: keyAccessResult.ApprovalRequestID,
		}
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "pending_approval", mustJSON(resp), "", keyAccessResult.ApprovalRequestID, policyDecision)
		_ = s.publishAudit(ctx, protocolEventSubject(protocol, operation), tenantID, map[string]interface{}{
			"request_id":          logEntry.ID,
			"protocol":            protocol,
			"operation":           operation,
			"key_id":              keyID,
			"approval_request_id": keyAccessResult.ApprovalRequestID,
			"status":              "pending_approval",
			"justification_code":  req.JustificationCode,
		})
		return resp, nil
	}

	if cfg.GovernanceRequired && approvedBy == "" {
		if s.governance == nil {
			err := newServiceError(http.StatusFailedDependency, "governance_unavailable", "governance client is not configured")
			_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", err.Error(), "", policyDecision)
			return ProxyCryptoResponse{}, err
		}
		approvalID, err := s.governance.CreateKeyApproval(ctx, GovernanceApprovalRequest{
			TenantID:       tenantID,
			KeyID:          keyID,
			Operation:      operation,
			PayloadHash:    approvalPayloadHash(req),
			RequesterID:    logEntry.RequesterID,
			RequesterEmail: logEntry.RequesterEmail,
			RequesterIP:    identity.RemoteIP,
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
	_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "success", mustJSON(resp), "", approvedBy, policyDecision)
	_ = s.publishAudit(ctx, protocolEventSubject(protocol, operation), tenantID, map[string]interface{}{
		"request_id":          logEntry.ID,
		"protocol":            protocol,
		"operation":           operation,
		"key_id":              keyID,
		"policy_decision":     policyDecision,
		"justification_code":  req.JustificationCode,
		"key_access_reason":   keyAccessResult.Reason,
		"approval_request_id": approvedBy,
		"status":              "success",
	})
	return resp, nil
}

// approvalPayloadHash is the hash a HYOK approval binds to: the request
// without the approval ID it is later retried with.
func approvalPayloadHash(req ProxyCryptoRequest) string {
	req.ApprovalRequestID = ""
	return hashJSONPayload(req)
}

// redeemApproval checks that a governance approval releases this operation.
func (s *Service) redeemApproval(ctx context.Context, tenantID, approvalID, logID, keyID, operation string, req ProxyCryptoRequest) error {
	if s.governance == nil {
		return errors.New("governance is not configured")
	}
	st, err := s.governance.GetApprovalStatus(ctx, tenantID, approvalID)
	if err != nil {
		return fmt.Errorf("approval could not be checked: %w", err)
	}
	if !strings.EqualFold(st.Status, "approved") {
		return fmt.Errorf("approval is %s, not approved", firstNonEmpty(st.Status, "unknown"))
	}
	if st.TargetID != keyID {
		return errors.New("approval is for a different key")
	}
	switch st.Action {
	case "key." + operation:
		if st.PayloadHash != approvalPayloadHash(req) {
			return errors.New("approval is for a different request payload")
		}
	case "external_key_access":
		if !strings.EqualFold(st.Operation, operation) {
			return errors.New("approval is for a different operation")
		}
	default:
		return errors.New("approval is for a different action")
	}
	used, err := s.store.ApprovalRedeemed(ctx, tenantID, approvalID, logID)
	if err != nil {
		return err
	}
	if used {
		return errors.New("approval was already used")
	}
	return nil
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
		_ = s.publishAudit(ctx, "audit.hyok.request_denied", tenantID, map[string]interface{}{
			"request_id": logEntry.ID, "operation": "publickey", "key_id": keyID,
			"reason": "policy_unavailable", "result": "refused", "severity": "warning",
		})
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
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "error", "", "public key not available for key "+keyID, "", policyDecision)
		return DKEPublicKeyResponse{}, fmt.Errorf("public key not available for key %s: ensure the key exists in KeyCore and has an RSA public component", keyID)
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

// dkeKeyCacheTTL is how long Office may cache a DKE public key.
const dkeKeyCacheTTL = 24 * time.Hour

// GetMicrosoftDKEKey serves a DKE key's public part. keyURL is the public URL
// the call came in on; the kid is keyURL/<current version>, and Office posts
// decrypt requests to kid/decrypt.
func (s *Service) GetMicrosoftDKEKey(ctx context.Context, tenantID string, keyID string, endpointPath string, host string, keyURL string, identity AuthIdentity) (MicrosoftDKEKeyResponse, error) {
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
	if identity.Mode != authModeAnonymous {
		if err := checkAuthMode(cfg.AuthMode, identity.Mode); err != nil {
			return MicrosoftDKEKeyResponse{}, newServiceError(http.StatusUnauthorized, "unauthorized", err.Error())
		}
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
	rsaPub, err := pkgcrypto.ParseRSAPublicKeyAny(publicKeyPEM)
	if err != nil {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", err.Error(), "", policyDecision)
		return MicrosoftDKEKeyResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "key is not RSA-compatible for DKE")
	}
	jwkN, _, err := pkgcrypto.RSAPublicKeyJWK(rsaPub)
	if err != nil {
		_ = s.store.CompleteRequestLog(ctx, tenantID, logEntry.ID, "failed", "{}", err.Error(), "", policyDecision)
		return MicrosoftDKEKeyResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "key is not RSA-compatible for DKE")
	}
	version := extractInt(keyMeta["current_version"])
	if version <= 0 {
		version = 1
	}
	out := MicrosoftDKEKeyResponse{
		Key: MicrosoftDKEPublicKey{
			KTY: "RSA",
			N:   jwkN,
			E:   rsaPub.E,
			Alg: inferDKEAlg(keyMeta, meta),
			KID: strings.TrimRight(keyURL, "/") + "/" + strconv.Itoa(version),
		},
		Cache: MicrosoftDKEKeyCache{Exp: time.Now().UTC().Add(dkeKeyCacheTTL).Format(time.RFC3339)},
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

// ProcessMicrosoftDKEDecrypt decrypts a DKE-wrapped content key posted to
// kid/decrypt. Only the key's current version can be decrypted: keycore
// decrypts with the current version, so an older kid is refused rather than
// tried against the wrong key.
func (s *Service) ProcessMicrosoftDKEDecrypt(ctx context.Context, tenantID string, keyID string, version string, endpointPath string, host string, identity AuthIdentity, req MicrosoftDKEDecryptRequest) (MicrosoftDKEDecryptResponse, error) {
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
	keyMeta, err := s.keycore.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return MicrosoftDKEDecryptResponse{}, newServiceError(http.StatusBadGateway, "keycore_failed", err.Error())
	}
	if current := extractInt(keyMeta["current_version"]); current > 0 && strings.TrimSpace(version) != strconv.Itoa(current) {
		return MicrosoftDKEDecryptResponse{}, newServiceError(http.StatusConflict, "key_version_not_current", "only the key's current version can decrypt; this kid names another version")
	}

	// Office sends standard base64; base64url is accepted too.
	ciphertextRaw, err := base64.StdEncoding.DecodeString(ciphertextB64URL)
	if err != nil {
		if ciphertextRaw, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(ciphertextB64URL, "=")); err != nil {
			return MicrosoftDKEDecryptResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "value must be base64")
		}
	}
	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertextRaw)

	cryptoResp, err := s.ProcessCrypto(ctx, tenantID, ProtocolDKE, "decrypt", keyID, endpointPath, identity, ProxyCryptoRequest{
		CiphertextB64:  ciphertextB64,
		RequesterEmail: dkeRequesterEmail(identity),
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
		return MicrosoftDKEDecryptResponse{}, newServiceError(http.StatusBadGateway, "keycore_failed", "invalid decrypt plaintext encoding")
	}
	return MicrosoftDKEDecryptResponse{Value: base64.StdEncoding.EncodeToString(plainRaw)}, nil
}

// dkeRequesterEmail is the verified Entra user's email, for key access rules.
func dkeRequesterEmail(identity AuthIdentity) string {
	if identity.EntraTenantID != "" && strings.Contains(identity.UserID, "@") {
		return identity.UserID
	}
	return ""
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
		cfg.AuthMode = AuthModeJWT
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
		// Never fail open: an unreachable policy service refuses (6.20.0-beta).
		return "ERROR", "", newServiceError(http.StatusFailedDependency, "policy_unavailable", err.Error())
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
	case ProtocolServiceNow:
		return "audit.hyok.servicenow_request"
	case ProtocolAlibaba:
		return "audit.hyok.alibaba_request"
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
	case AuthModeMTLS:
		// Stored before mTLS was refused: no request can satisfy it.
		return errors.New("this endpoint requires mTLS, which the edge cannot verify; reconfigure it to jwt")
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
	meta.AuthorizedEmails = nonEmptyStrings(extractStringSlice(body["authorized_emails"]))
	meta.AuthorizedRoles = nonEmptyStrings(extractStringSlice(body["authorized_roles"]))
	meta.KeyURIHostname = strings.TrimSpace(firstString(body["key_uri_hostname"], body["keyURIHostname"]))
	meta.AllowedAlgorithms = nonEmptyStrings(
		extractStringSlice(body["allowed_algorithms"]),
		extractStringSlice(body["allowed_algs"]),
		extractStringSlice(body["algorithms"]),
	)
	return meta, nil
}

func validateDKEIdentity(meta DKEEndpointMetadata, tenantID string, host string, identity AuthIdentity) error {
	if identity.Mode == authModeAnonymous {
		// Office fetches the public key without a token; only on the host
		// this endpoint names, and never for decrypt (checkAuthMode).
		if meta.KeyURIHostname == "" || !strings.EqualFold(strings.TrimSpace(meta.KeyURIHostname), strings.TrimSpace(host)) {
			return newServiceError(http.StatusUnauthorized, "unauthorized", "a Bearer token is required")
		}
		return nil
	}
	// For an Entra caller the authorized tenants are Entra tenant IDs; for a
	// Vecta token they are the Vecta tenant.
	callerTenant := firstNonEmpty(identity.EntraTenantID, tenantID)
	if len(meta.AuthorizedTenants) > 0 && !containsFold(meta.AuthorizedTenants, callerTenant) {
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
