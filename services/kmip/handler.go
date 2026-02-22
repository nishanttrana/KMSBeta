package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Handler struct {
	store             Store
	keycore           KeyCoreClient
	certs             CertsClient
	events            EventPublisher
	requireRegistered bool
}

type kmipStoredAttributes struct {
	Name                string                        `json:"name,omitempty"`
	ObjectType          kmip.ObjectType               `json:"object_type,omitempty"`
	CryptographicAlg    kmip.CryptographicAlgorithm   `json:"cryptographic_algorithm,omitempty"`
	CryptographicLength int32                         `json:"cryptographic_length,omitempty"`
	CryptographicUsage  kmip.CryptographicUsageMask   `json:"cryptographic_usage_mask,omitempty"`
	KeyRoleType         kmip.KeyRoleType              `json:"key_role_type,omitempty"`
	OperationPolicyName string                        `json:"operation_policy_name,omitempty"`
	State               kmip.State                    `json:"state,omitempty"`
	ExportAllowed       bool                          `json:"export_allowed,omitempty"`
	OpsLimit            int64                         `json:"ops_limit,omitempty"`
	OpsLimitWindow      string                        `json:"ops_limit_window,omitempty"`
	IVMode              string                        `json:"iv_mode,omitempty"`
	ApprovalRequired    bool                          `json:"approval_required,omitempty"`
	ApprovalPolicyID    string                        `json:"approval_policy_id,omitempty"`
	CryptoParams        *kmip.CryptographicParameters `json:"crypto_params,omitempty"`
}

type kmipConnectionContext struct {
	Principal Principal
	SessionID string
}

type kmipConnContextKey struct{}

func NewHandler(store Store, keycore KeyCoreClient, certs CertsClient, events EventPublisher, requireRegistered bool) *Handler {
	return &Handler{
		store:             store,
		keycore:           keycore,
		certs:             certs,
		events:            events,
		requireRegistered: requireRegistered,
	}
}

func (h *Handler) NewBatchExecutor() *kmipserver.BatchExecutor {
	exec := kmipserver.NewBatchExecutor()
	exec.SetSupportedProtocolVersions(parseSupportedProtocolVersions()...)
	exec.BatchItemUse(h.auditMiddleware, h.authorizationMiddleware)

	exec.Route(kmip.OperationCreate, kmipserver.HandleFunc(h.handleCreate))
	exec.Route(kmip.OperationRegister, kmipserver.HandleFunc(h.handleRegister))
	exec.Route(kmip.OperationGet, kmipserver.HandleFunc(h.handleGet))
	exec.Route(kmip.OperationGetAttributes, kmipserver.HandleFunc(h.handleGetAttributes))
	exec.Route(kmip.OperationLocate, kmipserver.HandleFunc(h.handleLocate))
	exec.Route(kmip.OperationActivate, kmipserver.HandleFunc(h.handleActivate))
	exec.Route(kmip.OperationRevoke, kmipserver.HandleFunc(h.handleRevoke))
	exec.Route(kmip.OperationDestroy, kmipserver.HandleFunc(h.handleDestroy))
	exec.Route(kmip.OperationReKey, kmipserver.HandleFunc(h.handleReKey))
	exec.Route(kmip.OperationEncrypt, kmipserver.HandleFunc(h.handleEncrypt))
	exec.Route(kmip.OperationDecrypt, kmipserver.HandleFunc(h.handleDecrypt))
	exec.Route(kmip.OperationSign, kmipserver.HandleFunc(h.handleSign))
	exec.Route(kmip.OperationSignatureVerify, kmipserver.HandleFunc(h.handleSignatureVerify))
	exec.Route(kmip.OperationQuery, kmipserver.HandleFunc(h.handleQuery))
	exec.Route(kmip.OperationDiscoverVersions, kmipserver.HandleFunc(h.handleDiscoverVersions))

	return exec
}

func (h *Handler) ConnectHook(ctx context.Context) (context.Context, error) {
	peerCerts := kmipserver.PeerCertificates(ctx)
	if len(peerCerts) == 0 {
		return nil, kmipserver.ErrPermissionDenied
	}
	leafCert := peerCerts[0]
	fingerprint := clientFingerprintSHA256(leafCert)

	var (
		principal Principal
		clientID  string
	)
	client, err := h.store.GetClientByFingerprint(ctx, fingerprint)
	if err == nil {
		if strings.ToLower(strings.TrimSpace(client.Status)) != "active" {
			return nil, kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "kmip client is not active")
		}
		role := strings.TrimSpace(client.Role)
		if !isRoleAllowed(role) {
			return nil, kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "kmip client role is not allowed")
		}
		principal = Principal{
			TenantID: client.TenantID,
			Role:     role,
			CN:       strings.TrimSpace(leafCert.Subject.CommonName),
		}
		clientID = client.ID
	} else {
		if h.requireRegistered || !errors.Is(err, errNotFound) {
			return nil, kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "unregistered kmip client certificate")
		}
		principal, err = principalFromCert(leafCert)
		if err != nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "%v", err)
		}
	}

	sess := Session{
		ID:          newID("kmips"),
		TenantID:    principal.TenantID,
		ClientCN:    defaultString(clientID, principal.CN),
		Role:        principal.Role,
		RemoteAddr:  kmipserver.RemoteAddr(ctx),
		ConnectedAt: time.Now().UTC(),
	}
	sess.TLSSubject = leafCert.Subject.String()
	sess.TLSIssuer = leafCert.Issuer.String()
	if err := h.store.CreateSession(ctx, sess); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "session create failed: %v", err)
	}
	_ = h.publishAudit(ctx, "audit.kmip.client_connected", principal.TenantID, map[string]any{
		"session_id":         sess.ID,
		"client_cn":          principal.CN,
		"client_id":          clientID,
		"fingerprint_sha256": fingerprint,
		"role":               principal.Role,
		"remote":             sess.RemoteAddr,
	})
	return context.WithValue(ctx, kmipConnContextKey{}, kmipConnectionContext{
		Principal: principal,
		SessionID: sess.ID,
	}), nil
}

func (h *Handler) TerminateHook(ctx context.Context) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return
	}
	_ = h.store.CloseSession(context.Background(), connCtx.SessionID)
	_ = h.publishAudit(context.Background(), "audit.kmip.client_disconnected", connCtx.Principal.TenantID, map[string]any{
		"session_id": connCtx.SessionID,
		"client_cn":  connCtx.Principal.CN,
	})
}

func (h *Handler) authorizationMiddleware(next kmipserver.BatchItemNext, ctx context.Context, bi *kmip.RequestBatchItem) (*kmip.ResponseBatchItem, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	if !isRoleAllowed(connCtx.Principal.Role) {
		return nil, kmipserver.ErrPermissionDenied
	}
	if !roleCanOperate(connCtx.Principal.Role, bi.Operation) {
		return nil, kmipserver.ErrPermissionDenied
	}
	return next(ctx, bi)
}

func (h *Handler) auditMiddleware(next kmipserver.BatchItemNext, ctx context.Context, bi *kmip.RequestBatchItem) (*kmip.ResponseBatchItem, error) {
	start := time.Now()
	resp, err := next(ctx, bi)

	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return resp, err
	}
	status := "success"
	reason := "OK"
	if err != nil {
		status = "failure"
		reason = err.Error()
	}
	if resp != nil && resp.ResultStatus == kmip.ResultStatusOperationFailed {
		status = "failure"
		if strings.TrimSpace(resp.ResultMessage) != "" {
			reason = strings.TrimSpace(resp.ResultMessage)
		}
	}

	requestBytes := 0
	if bi.RequestPayload != nil {
		requestBytes = safeTTLVLen(bi.RequestPayload)
	}
	responseBytes := 0
	if resp != nil && resp.ResponsePayload != nil {
		responseBytes = safeTTLVLen(resp.ResponsePayload)
	}
	objectID := extractUniqueIdentifierFromPayload(bi.RequestPayload)
	if objectID == "" && resp != nil {
		objectID = extractUniqueIdentifierFromPayload(resp.ResponsePayload)
	}
	if objectID == "" {
		objectID = kmipserver.IdPlaceholder(ctx)
	}
	reqID := batchRequestID(bi)

	_ = h.store.RecordOperation(ctx, OperationRecord{
		ID:            newID("kmipo"),
		TenantID:      connCtx.Principal.TenantID,
		SessionID:     connCtx.SessionID,
		RequestID:     reqID,
		Operation:     ttlv.EnumStr(bi.Operation),
		ObjectID:      objectID,
		Status:        status,
		ErrorMessage:  reason,
		RequestBytes:  requestBytes,
		ResponseBytes: responseBytes,
		CreatedAt:     time.Now().UTC(),
	})
	_ = h.publishAudit(ctx, "audit.kmip."+strings.ToLower(ttlv.EnumStr(bi.Operation)), connCtx.Principal.TenantID, map[string]any{
		"session_id":  connCtx.SessionID,
		"request_id":  reqID,
		"operation":   ttlv.EnumStr(bi.Operation),
		"object_id":   objectID,
		"status":      status,
		"reason":      reason,
		"client_cn":   connCtx.Principal.CN,
		"client_role": connCtx.Principal.Role,
		"latency_ms":  time.Since(start).Milliseconds(),
	})
	return resp, err
}

func (h *Handler) handleCreate(ctx context.Context, req *payloads.CreateRequestPayload) (*payloads.CreateResponsePayload, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	if req == nil {
		return nil, kmipserver.ErrMissingData
	}
	attrs := parseTemplate(req.TemplateAttribute)
	if attrs.ObjectType == 0 {
		attrs.ObjectType = req.ObjectType
	}
	if attrs.Name == "" {
		attrs.Name = "kmip-key-" + newID("n")
	}
	if attrs.State == 0 {
		attrs.State = kmip.StateActive
	}
	if attrs.IVMode == "" {
		attrs.IVMode = "internal"
	}
	keyType := keyTypeFromObjectType(req.ObjectType)
	if keyType == "" {
		return nil, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "unsupported object type: %s", ttlv.EnumStr(req.ObjectType))
	}
	keycoreAlg := keycoreAlgorithmFromKMIP(attrs.CryptographicAlg, attrs.CryptographicLength, attrs.CryptoParams, req.ObjectType)
	if keycoreAlg == "" {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "unable to resolve algorithm")
	}
	purpose := purposeFromUsageMask(attrs.CryptographicUsage, keycoreAlg)
	approvalPolicy := strings.TrimSpace(attrs.OperationPolicyName)
	approvalRequired := approvalPolicy != ""
	keyID, err := h.keycore.CreateKey(ctx, connCtx.Principal.TenantID, CreateRequest{
		Name:             attrs.Name,
		Algorithm:        keycoreAlg,
		KeyType:          keyType,
		Purpose:          purpose,
		IVMode:           attrs.IVMode,
		OpsLimit:         attrs.OpsLimit,
		OpsWindow:        defaultString(attrs.OpsLimitWindow, "total"),
		ApprovalRequired: approvalRequired,
		ApprovalPolicyID: approvalPolicy,
	})
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	if st := keycoreStatusFromKMIPState(attrs.State); st != "" && st != "active" {
		if err := h.keycore.SetKeyStatus(ctx, connCtx.Principal.TenantID, keyID, st); err != nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
		}
	}
	objID := newID("obj")
	if err := h.store.UpsertObject(ctx, ObjectMapping{
		TenantID:       connCtx.Principal.TenantID,
		ObjectID:       objID,
		KeyID:          keyID,
		ObjectType:     objectTypeToStore(req.ObjectType),
		Name:           attrs.Name,
		State:          keycoreStatusFromKMIPState(attrs.State),
		Algorithm:      keycoreAlg,
		AttributesJSON: marshalStoredAttributes(attrs),
	}); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, objID)
	return &payloads.CreateResponsePayload{
		ObjectType:       req.ObjectType,
		UniqueIdentifier: objID,
	}, nil
}

func (h *Handler) handleRegister(ctx context.Context, req *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	if req == nil {
		return nil, kmipserver.ErrMissingData
	}
	rawMaterial, detectedAlg, err := extractRegisterMaterial(req.Object, req.ObjectType)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "%v", err)
	}
	attrs := parseTemplate(req.TemplateAttribute)
	if attrs.ObjectType == 0 {
		attrs.ObjectType = req.ObjectType
	}
	if attrs.Name == "" {
		attrs.Name = "kmip-registered-" + newID("n")
	}
	if attrs.State == 0 {
		attrs.State = kmip.StateActive
	}
	if attrs.IVMode == "" {
		attrs.IVMode = "internal"
	}
	keycoreAlg := keycoreAlgorithmFromKMIP(attrs.CryptographicAlg, attrs.CryptographicLength, attrs.CryptoParams, req.ObjectType)
	if keycoreAlg == "" {
		keycoreAlg = detectedAlg
	}
	if keycoreAlg == "" {
		keycoreAlg = "Auto-detect from format"
	}
	purpose := purposeFromUsageMask(attrs.CryptographicUsage, keycoreAlg)
	keyType := keyTypeFromObjectType(req.ObjectType)
	if keyType == "" {
		return nil, kmipserver.Errorf(kmip.ResultReasonFeatureNotSupported, "unsupported object type: %s", ttlv.EnumStr(req.ObjectType))
	}
	keyID, err := h.keycore.ImportKey(ctx, connCtx.Principal.TenantID, RegisterRequest{
		Name:        attrs.Name,
		Algorithm:   keycoreAlg,
		KeyType:     keyType,
		Purpose:     purpose,
		MaterialB64: base64.StdEncoding.EncodeToString(rawMaterial),
	})
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	if st := keycoreStatusFromKMIPState(attrs.State); st != "" && st != "active" {
		if err := h.keycore.SetKeyStatus(ctx, connCtx.Principal.TenantID, keyID, st); err != nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
		}
	}
	objID := newID("obj")
	if err := h.store.UpsertObject(ctx, ObjectMapping{
		TenantID:       connCtx.Principal.TenantID,
		ObjectID:       objID,
		KeyID:          keyID,
		ObjectType:     objectTypeToStore(req.ObjectType),
		Name:           attrs.Name,
		State:          keycoreStatusFromKMIPState(attrs.State),
		Algorithm:      keycoreAlg,
		AttributesJSON: marshalStoredAttributes(attrs),
	}); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, objID)
	return &payloads.RegisterResponsePayload{
		UniqueIdentifier: objID,
	}, nil
}

func (h *Handler) handleGet(ctx context.Context, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	objectID, err := kmipserver.GetIdOrPlaceholder(ctx, strings.TrimSpace(req.UniqueIdentifier))
	if err != nil {
		return nil, kmipserver.ErrMissingData
	}
	obj, err := h.store.GetObject(ctx, connCtx.Principal.TenantID, objectID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, kmipserver.ErrItemNotFound
		}
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	meta := parseStoredAttributes(obj.AttributesJSON)
	if err := h.enforceObjectPolicy(connCtx.Principal, ttlv.EnumStr(kmip.OperationGet), meta); err != nil {
		return nil, err
	}
	objType := objectTypeFromStore(obj.ObjectType)
	managedObj, err := buildKMIPObject(objType, meta)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.GetResponsePayload{
		ObjectType:       objType,
		UniqueIdentifier: objectID,
		Object:           managedObj,
	}, nil
}

func (h *Handler) handleGetAttributes(ctx context.Context, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	objectID, err := kmipserver.GetIdOrPlaceholder(ctx, strings.TrimSpace(req.UniqueIdentifier))
	if err != nil {
		return nil, kmipserver.ErrMissingData
	}
	obj, err := h.store.GetObject(ctx, connCtx.Principal.TenantID, objectID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, kmipserver.ErrItemNotFound
		}
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	meta := parseStoredAttributes(obj.AttributesJSON)
	attrs := buildAttributeList(objectID, obj, meta)
	if len(req.AttributeName) > 0 {
		filtered := make([]kmip.Attribute, 0, len(req.AttributeName))
		for _, name := range req.AttributeName {
			for _, attr := range attrs {
				if attr.AttributeName == name {
					filtered = append(filtered, attr)
				}
			}
		}
		attrs = filtered
	}
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.GetAttributesResponsePayload{
		UniqueIdentifier: objectID,
		Attribute:        attrs,
	}, nil
}

func (h *Handler) handleLocate(ctx context.Context, req *payloads.LocateRequestPayload) (*payloads.LocateResponsePayload, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	query := LocateRequest{
		Limit: int(req.MaximumItems),
	}
	for _, attr := range req.Attribute {
		switch attr.AttributeName {
		case kmip.AttributeNameName:
			switch v := attr.AttributeValue.(type) {
			case kmip.Name:
				query.Name = strings.TrimSpace(v.NameValue)
			case string:
				query.Name = strings.TrimSpace(v)
			}
		case kmip.AttributeNameObjectType:
			if v, ok := attr.AttributeValue.(kmip.ObjectType); ok {
				query.ObjectType = objectTypeToStore(v)
			}
		case kmip.AttributeNameCryptographicAlgorithm:
			if v, ok := attr.AttributeValue.(kmip.CryptographicAlgorithm); ok {
				query.Algorithm = keycoreAlgorithmFromKMIP(v, 0, nil, 0)
			}
		case kmip.AttributeNameState:
			if v, ok := attr.AttributeValue.(kmip.State); ok {
				query.State = keycoreStatusFromKMIPState(v)
			}
		}
	}
	if query.Limit <= 0 {
		query.Limit = 100
	}
	items, err := h.store.LocateObjects(ctx, connCtx.Principal.TenantID, query)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	ids := make([]string, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.ObjectID)
	}
	if len(ids) == 1 {
		kmipserver.SetIdPlaceholder(ctx, ids[0])
	} else {
		kmipserver.ClearIdPlaceholder(ctx)
	}
	located := int32(len(ids))
	return &payloads.LocateResponsePayload{
		LocatedItems:     &located,
		UniqueIdentifier: ids,
	}, nil
}

func (h *Handler) handleActivate(ctx context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
	return h.changeState(ctx, req.UniqueIdentifier, kmip.StateActive, "kmip activate")
}

func (h *Handler) handleRevoke(ctx context.Context, req *payloads.RevokeRequestPayload) (*payloads.RevokeResponsePayload, error) {
	state := kmip.StateDeactivated
	if req != nil {
		code := req.RevocationReason.RevocationReasonCode
		if code == kmip.RevocationReasonCodeKeyCompromise || code == kmip.RevocationReasonCodeCACompromise {
			state = kmip.StateCompromised
		}
	}
	out, err := h.changeState(ctx, req.UniqueIdentifier, state, "kmip revoke")
	if err != nil {
		return nil, err
	}
	return &payloads.RevokeResponsePayload{UniqueIdentifier: out.UniqueIdentifier}, nil
}

func (h *Handler) handleDestroy(ctx context.Context, req *payloads.DestroyRequestPayload) (*payloads.DestroyResponsePayload, error) {
	out, err := h.changeState(ctx, req.UniqueIdentifier, kmip.StateDestroyed, "kmip destroy")
	if err != nil {
		return nil, err
	}
	return &payloads.DestroyResponsePayload{UniqueIdentifier: out.UniqueIdentifier}, nil
}

func (h *Handler) handleReKey(ctx context.Context, req *payloads.RekeyRequestPayload) (*payloads.RekeyResponsePayload, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	objectID, err := kmipserver.GetIdOrPlaceholder(ctx, strings.TrimSpace(req.UniqueIdentifier))
	if err != nil {
		return nil, kmipserver.ErrMissingData
	}
	obj, err := h.store.GetObject(ctx, connCtx.Principal.TenantID, objectID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, kmipserver.ErrItemNotFound
		}
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	meta := parseStoredAttributes(obj.AttributesJSON)
	if err := h.enforceObjectPolicy(connCtx.Principal, "rekey", meta); err != nil {
		return nil, err
	}
	if _, err := h.keycore.RotateKey(ctx, connCtx.Principal.TenantID, obj.KeyID, "kmip rekey"); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	obj.State = "active"
	meta.State = kmip.StateActive
	obj.AttributesJSON = marshalStoredAttributes(meta)
	_ = h.store.UpsertObject(ctx, obj)
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.RekeyResponsePayload{
		UniqueIdentifier: objectID,
	}, nil
}

func (h *Handler) handleEncrypt(ctx context.Context, req *payloads.EncryptRequestPayload) (*payloads.EncryptResponsePayload, error) {
	connCtx, obj, meta, objectID, err := h.resolveOperationalObject(ctx, req.UniqueIdentifier, kmip.OperationEncrypt)
	if err != nil {
		return nil, err
	}
	if err := enforceUsage(meta.CryptographicUsage, kmip.OperationEncrypt); err != nil {
		return nil, err
	}
	if err := validateKeyRole(meta.KeyRoleType, req.CryptographicParameters); err != nil {
		return nil, err
	}
	plainB64 := base64.StdEncoding.EncodeToString(req.Data)
	ivB64 := ""
	if len(req.IVCounterNonce) > 0 {
		ivB64 = base64.StdEncoding.EncodeToString(req.IVCounterNonce)
	}
	raw, err := h.keycore.Encrypt(ctx, connCtx.Principal.TenantID, obj.KeyID, plainB64, ivB64, "")
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	ciphertext, err := decodeBase64MapField(raw, "ciphertext")
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	iv, _ := decodeBase64MapField(raw, "iv")
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.EncryptResponsePayload{
		UniqueIdentifier: objectID,
		Data:             ciphertext,
		IVCounterNonce:   iv,
	}, nil
}

func (h *Handler) handleDecrypt(ctx context.Context, req *payloads.DecryptRequestPayload) (*payloads.DecryptResponsePayload, error) {
	connCtx, obj, meta, objectID, err := h.resolveOperationalObject(ctx, req.UniqueIdentifier, kmip.OperationDecrypt)
	if err != nil {
		return nil, err
	}
	if err := enforceUsage(meta.CryptographicUsage, kmip.OperationDecrypt); err != nil {
		return nil, err
	}
	if err := validateKeyRole(meta.KeyRoleType, req.CryptographicParameters); err != nil {
		return nil, err
	}
	cipherB64 := base64.StdEncoding.EncodeToString(req.Data)
	ivB64 := ""
	if len(req.IVCounterNonce) > 0 {
		ivB64 = base64.StdEncoding.EncodeToString(req.IVCounterNonce)
	}
	raw, err := h.keycore.Decrypt(ctx, connCtx.Principal.TenantID, obj.KeyID, cipherB64, ivB64)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	plain, err := decodeBase64MapField(raw, "plaintext")
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.DecryptResponsePayload{
		UniqueIdentifier: objectID,
		Data:             plain,
	}, nil
}

func (h *Handler) handleSign(ctx context.Context, req *payloads.SignRequestPayload) (*payloads.SignResponsePayload, error) {
	connCtx, obj, meta, objectID, err := h.resolveOperationalObject(ctx, req.UniqueIdentifier, kmip.OperationSign)
	if err != nil {
		return nil, err
	}
	if err := enforceUsage(meta.CryptographicUsage, kmip.OperationSign); err != nil {
		return nil, err
	}
	if err := validateKeyRole(meta.KeyRoleType, req.CryptographicParameters); err != nil {
		return nil, err
	}
	data := req.Data
	if len(data) == 0 {
		data = req.DigestedData
	}
	if len(data) == 0 {
		return nil, kmipserver.ErrMissingData
	}
	algorithmHint := signingAlgorithmHint(req.CryptographicParameters)
	raw, err := h.keycore.Sign(ctx, connCtx.Principal.TenantID, obj.KeyID, base64.StdEncoding.EncodeToString(data), algorithmHint)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	signature, err := decodeBase64MapField(raw, "signature")
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.SignResponsePayload{
		UniqueIdentifier: objectID,
		SignatureData:    signature,
	}, nil
}

func (h *Handler) handleSignatureVerify(ctx context.Context, req *payloads.SignatureVerifyRequestPayload) (*payloads.SignatureVerifyResponsePayload, error) {
	connCtx, obj, meta, objectID, err := h.resolveOperationalObject(ctx, req.UniqueIdentifier, kmip.OperationSignatureVerify)
	if err != nil {
		return nil, err
	}
	if err := enforceUsage(meta.CryptographicUsage, kmip.OperationSignatureVerify); err != nil {
		return nil, err
	}
	if err := validateKeyRole(meta.KeyRoleType, req.CryptographicParameters); err != nil {
		return nil, err
	}
	data := req.Data
	if len(data) == 0 {
		data = req.DigestedData
	}
	if len(data) == 0 || len(req.SignatureData) == 0 {
		return nil, kmipserver.ErrMissingData
	}
	algorithmHint := signingAlgorithmHint(req.CryptographicParameters)
	raw, err := h.keycore.Verify(
		ctx,
		connCtx.Principal.TenantID,
		obj.KeyID,
		base64.StdEncoding.EncodeToString(data),
		base64.StdEncoding.EncodeToString(req.SignatureData),
		algorithmHint,
	)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	verified := false
	if v, ok := raw["verified"].(bool); ok {
		verified = v
	}
	indicator := kmip.ValidityIndicatorInvalid
	if verified {
		indicator = kmip.ValidityIndicatorValid
	}
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.SignatureVerifyResponsePayload{
		UniqueIdentifier:  objectID,
		ValidityIndicator: indicator,
	}, nil
}

func (h *Handler) handleQuery(ctx context.Context, req *payloads.QueryRequestPayload) (*payloads.QueryResponsePayload, error) {
	var functions []kmip.QueryFunction
	if req != nil {
		functions = req.QueryFunction
	}
	if len(functions) == 0 {
		functions = []kmip.QueryFunction{
			kmip.QueryFunctionOperations,
			kmip.QueryFunctionObjects,
			kmip.QueryFunctionServerInformation,
			kmip.QueryFunctionProfiles,
			kmip.QueryFunctionCapabilities,
			kmip.QueryFunctionApplicationNamespaces,
			kmip.QueryFunctionClientRegistrationMethods,
		}
	}
	has := func(target kmip.QueryFunction) bool {
		for _, f := range functions {
			if f == target {
				return true
			}
		}
		return false
	}

	resp := &payloads.QueryResponsePayload{}
	if has(kmip.QueryFunctionOperations) {
		resp.Operations = append(resp.Operations, supportedKMIPOperations()...)
	}
	if has(kmip.QueryFunctionObjects) {
		resp.ObjectType = append(resp.ObjectType, supportedKMIPObjectTypes()...)
	}
	if has(kmip.QueryFunctionServerInformation) {
		resp.VendorIdentification = "Vecta KMS"
	}
	if has(kmip.QueryFunctionApplicationNamespaces) {
		resp.ApplicationNamespace = []string{"vecta.kms.kmip"}
	}
	if has(kmip.QueryFunctionProfiles) {
		resp.ProfileInformation = []kmip.ProfileInformation{
			{ProfileName: kmip.ProfileNameBasicCryptographicServerKMIPV1_4},
			{ProfileName: kmip.ProfileNameBaselineServerBasicKMIPV1_4},
		}
	}
	if has(kmip.QueryFunctionCapabilities) {
		trueVal := true
		falseVal := false
		resp.CapabilityInformation = []kmip.CapabilityInformation{{
			StreamingCapability:     &falseVal,
			AsynchronousCapability:  &falseVal,
			AttestationCapability:   &falseVal,
			BatchUndoCapability:     &falseVal,
			BatchContinueCapability: &trueVal,
		}}
	}
	if has(kmip.QueryFunctionClientRegistrationMethods) {
		resp.ClientRegistrationMethod = []kmip.ClientRegistrationMethod{
			kmip.ClientRegistrationMethodServerPreGenerated,
		}
	}
	return resp, nil
}

func (h *Handler) handleDiscoverVersions(_ context.Context, req *payloads.DiscoverVersionsRequestPayload) (*payloads.DiscoverVersionsResponsePayload, error) {
	supported := parseSupportedProtocolVersions()
	if req == nil || len(req.ProtocolVersion) == 0 {
		return &payloads.DiscoverVersionsResponsePayload{
			ProtocolVersion: supported,
		}, nil
	}

	clientSet := make(map[string]struct{}, len(req.ProtocolVersion))
	for _, v := range req.ProtocolVersion {
		clientSet[fmt.Sprintf("%d.%d", v.ProtocolVersionMajor, v.ProtocolVersionMinor)] = struct{}{}
	}

	intersection := make([]kmip.ProtocolVersion, 0, len(supported))
	for _, v := range supported {
		key := fmt.Sprintf("%d.%d", v.ProtocolVersionMajor, v.ProtocolVersionMinor)
		if _, ok := clientSet[key]; ok {
			intersection = append(intersection, v)
		}
	}
	return &payloads.DiscoverVersionsResponsePayload{
		ProtocolVersion: intersection,
	}, nil
}

func (h *Handler) resolveOperationalObject(ctx context.Context, uniqueID string, operation kmip.Operation) (kmipConnectionContext, ObjectMapping, kmipStoredAttributes, string, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return kmipConnectionContext{}, ObjectMapping{}, kmipStoredAttributes{}, "", kmipserver.ErrPermissionDenied
	}
	objectID, err := kmipserver.GetIdOrPlaceholder(ctx, strings.TrimSpace(uniqueID))
	if err != nil {
		return kmipConnectionContext{}, ObjectMapping{}, kmipStoredAttributes{}, "", kmipserver.ErrMissingData
	}
	obj, err := h.store.GetObject(ctx, connCtx.Principal.TenantID, objectID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return kmipConnectionContext{}, ObjectMapping{}, kmipStoredAttributes{}, "", kmipserver.ErrItemNotFound
		}
		return kmipConnectionContext{}, ObjectMapping{}, kmipStoredAttributes{}, "", kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	meta := parseStoredAttributes(obj.AttributesJSON)
	if err := h.enforceObjectPolicy(connCtx.Principal, strings.ToLower(ttlv.EnumStr(operation)), meta); err != nil {
		return kmipConnectionContext{}, ObjectMapping{}, kmipStoredAttributes{}, "", err
	}
	return connCtx, obj, meta, objectID, nil
}

func (h *Handler) changeState(ctx context.Context, uniqueID string, target kmip.State, reason string) (*payloads.ActivateResponsePayload, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	objectID, err := kmipserver.GetIdOrPlaceholder(ctx, strings.TrimSpace(uniqueID))
	if err != nil {
		return nil, kmipserver.ErrMissingData
	}
	obj, err := h.store.GetObject(ctx, connCtx.Principal.TenantID, objectID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, kmipserver.ErrItemNotFound
		}
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	meta := parseStoredAttributes(obj.AttributesJSON)
	if err := h.enforceObjectPolicy(connCtx.Principal, "state_change", meta); err != nil {
		return nil, err
	}
	targetStatus := keycoreStatusFromKMIPState(target)
	if targetStatus == "" {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "unsupported state transition")
	}
	if err := h.keycore.SetKeyStatus(ctx, connCtx.Principal.TenantID, obj.KeyID, targetStatus); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	obj.State = targetStatus
	meta.State = target
	obj.AttributesJSON = marshalStoredAttributes(meta)
	_ = h.store.UpsertObject(ctx, obj)
	_ = h.publishAudit(ctx, "audit.kmip.state_change", connCtx.Principal.TenantID, map[string]any{
		"object_id": objectID,
		"key_id":    obj.KeyID,
		"state":     ttlv.EnumStr(target),
		"reason":    reason,
	})
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.ActivateResponsePayload{UniqueIdentifier: objectID}, nil
}

func (h *Handler) enforceObjectPolicy(principal Principal, operation string, meta kmipStoredAttributes) error {
	policy := strings.TrimSpace(meta.OperationPolicyName)
	if policy == "" {
		return nil
	}
	role := strings.ToLower(strings.TrimSpace(principal.Role))
	if strings.Contains(strings.ToLower(policy), "admin") && role != "kmip-admin" {
		return kmipserver.ErrPermissionDenied
	}
	if strings.Contains(strings.ToLower(policy), "readonly") && role == "kmip-client" {
		return kmipserver.ErrPermissionDenied
	}
	if operation == "state_change" && role == "kmip-client" {
		return kmipserver.ErrPermissionDenied
	}
	return nil
}

func getConnectionContext(ctx context.Context) (kmipConnectionContext, bool) {
	v, ok := ctx.Value(kmipConnContextKey{}).(kmipConnectionContext)
	if !ok {
		return kmipConnectionContext{}, false
	}
	return v, true
}

func supportedKMIPOperations() []kmip.Operation {
	return []kmip.Operation{
		kmip.OperationCreate,
		kmip.OperationRegister,
		kmip.OperationGet,
		kmip.OperationGetAttributes,
		kmip.OperationLocate,
		kmip.OperationActivate,
		kmip.OperationRevoke,
		kmip.OperationDestroy,
		kmip.OperationReKey,
		kmip.OperationEncrypt,
		kmip.OperationDecrypt,
		kmip.OperationSign,
		kmip.OperationSignatureVerify,
		kmip.OperationQuery,
		kmip.OperationDiscoverVersions,
	}
}

func supportedKMIPObjectTypes() []kmip.ObjectType {
	return []kmip.ObjectType{
		kmip.ObjectTypeSymmetricKey,
		kmip.ObjectTypePublicKey,
		kmip.ObjectTypePrivateKey,
		kmip.ObjectTypeSecretData,
	}
}

func parseSupportedProtocolVersions() []kmip.ProtocolVersion {
	spec := strings.TrimSpace(os.Getenv("KMIP_SUPPORTED_VERSIONS"))
	if spec == "" {
		spec = "3.2,3.1,3.0,2.2,2.1,2.0,1.4,1.3,1.2,1.1,1.0"
	}
	parts := strings.Split(spec, ",")
	out := make([]kmip.ProtocolVersion, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		split := strings.SplitN(p, ".", 2)
		if len(split) != 2 {
			continue
		}
		major, errMaj := strconv.Atoi(strings.TrimSpace(split[0]))
		minor, errMin := strconv.Atoi(strings.TrimSpace(split[1]))
		if errMaj != nil || errMin != nil || major < 1 || minor < 0 {
			continue
		}
		key := fmt.Sprintf("%d.%d", major, minor)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, kmip.ProtocolVersion{
			ProtocolVersionMajor: int32(major),
			ProtocolVersionMinor: int32(minor),
		})
	}
	if len(out) == 0 {
		out = []kmip.ProtocolVersion{
			{ProtocolVersionMajor: 3, ProtocolVersionMinor: 0},
			kmip.V2_2,
			kmip.V2_1,
			kmip.V1_4,
			kmip.V1_3,
			kmip.V1_2,
			kmip.V1_1,
			kmip.V1_0,
		}
	}
	// Enforce KMIP 3.x minimum support for interoperability requirements.
	hasV3 := false
	for _, v := range out {
		if v.ProtocolVersionMajor >= 3 {
			hasV3 = true
			break
		}
	}
	if !hasV3 {
		out = append(out,
			kmip.ProtocolVersion{ProtocolVersionMajor: 3, ProtocolVersionMinor: 2},
			kmip.ProtocolVersion{ProtocolVersionMajor: 3, ProtocolVersionMinor: 1},
			kmip.ProtocolVersion{ProtocolVersionMajor: 3, ProtocolVersionMinor: 0},
		)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProtocolVersionMajor == out[j].ProtocolVersionMajor {
			return out[i].ProtocolVersionMinor > out[j].ProtocolVersionMinor
		}
		return out[i].ProtocolVersionMajor > out[j].ProtocolVersionMajor
	})
	uniq := make([]kmip.ProtocolVersion, 0, len(out))
	seenOut := map[string]struct{}{}
	for _, v := range out {
		key := fmt.Sprintf("%d.%d", v.ProtocolVersionMajor, v.ProtocolVersionMinor)
		if _, ok := seenOut[key]; ok {
			continue
		}
		seenOut[key] = struct{}{}
		uniq = append(uniq, v)
	}
	out = uniq
	return out
}

func buildKMIPObject(objType kmip.ObjectType, meta kmipStoredAttributes) (kmip.Object, error) {
	switch objType {
	case kmip.ObjectTypeSymmetricKey:
		return &kmip.SymmetricKey{
			KeyBlock: kmip.KeyBlock{
				KeyFormatType:          kmip.KeyFormatTypeRaw,
				CryptographicAlgorithm: meta.CryptographicAlg,
				CryptographicLength:    meta.CryptographicLength,
			},
		}, nil
	case kmip.ObjectTypePublicKey:
		return &kmip.PublicKey{
			KeyBlock: kmip.KeyBlock{
				KeyFormatType:          kmip.KeyFormatTypeX_509,
				CryptographicAlgorithm: meta.CryptographicAlg,
				CryptographicLength:    meta.CryptographicLength,
			},
		}, nil
	case kmip.ObjectTypePrivateKey:
		return &kmip.PrivateKey{
			KeyBlock: kmip.KeyBlock{
				KeyFormatType:          kmip.KeyFormatTypePKCS_8,
				CryptographicAlgorithm: meta.CryptographicAlg,
				CryptographicLength:    meta.CryptographicLength,
			},
		}, nil
	case kmip.ObjectTypeSecretData:
		return &kmip.SecretData{
			SecretDataType: kmip.SecretDataTypeSeed,
			KeyBlock: kmip.KeyBlock{
				KeyFormatType: kmip.KeyFormatTypeOpaque,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported object type")
	}
}

func buildAttributeList(objectID string, obj ObjectMapping, meta kmipStoredAttributes) []kmip.Attribute {
	attrs := []kmip.Attribute{
		{
			AttributeName:  kmip.AttributeNameUniqueIdentifier,
			AttributeValue: objectID,
		},
		{
			AttributeName: kmip.AttributeNameName,
			AttributeValue: kmip.Name{
				NameValue: obj.Name,
				NameType:  kmip.NameTypeUninterpretedTextString,
			},
		},
		{
			AttributeName:  kmip.AttributeNameObjectType,
			AttributeValue: objectTypeFromStore(obj.ObjectType),
		},
		{
			AttributeName:  kmip.AttributeNameState,
			AttributeValue: stateFromStore(obj.State, meta.State),
		},
	}
	if meta.CryptographicAlg != 0 {
		attrs = append(attrs, kmip.Attribute{
			AttributeName:  kmip.AttributeNameCryptographicAlgorithm,
			AttributeValue: meta.CryptographicAlg,
		})
	}
	if meta.CryptographicLength > 0 {
		attrs = append(attrs, kmip.Attribute{
			AttributeName:  kmip.AttributeNameCryptographicLength,
			AttributeValue: meta.CryptographicLength,
		})
	}
	if meta.CryptographicUsage != 0 {
		attrs = append(attrs, kmip.Attribute{
			AttributeName:  kmip.AttributeNameCryptographicUsageMask,
			AttributeValue: meta.CryptographicUsage,
		})
	}
	if meta.KeyRoleType != 0 {
		attrs = append(attrs, kmip.Attribute{
			AttributeName: kmip.AttributeNameCryptographicParameters,
			AttributeValue: kmip.CryptographicParameters{
				KeyRoleType: meta.KeyRoleType,
			},
		})
	}
	if strings.TrimSpace(meta.OperationPolicyName) != "" {
		attrs = append(attrs, kmip.Attribute{
			AttributeName:  kmip.AttributeNameOperationPolicyName,
			AttributeValue: strings.TrimSpace(meta.OperationPolicyName),
		})
	}
	return attrs
}

func objectTypeFromStore(v string) kmip.ObjectType {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "symmetrickey", "symmetric", "secret":
		return kmip.ObjectTypeSymmetricKey
	case "publickey", "public":
		return kmip.ObjectTypePublicKey
	case "privatekey", "private":
		return kmip.ObjectTypePrivateKey
	case "secretdata":
		return kmip.ObjectTypeSecretData
	default:
		return kmip.ObjectTypeSymmetricKey
	}
}

func objectTypeToStore(v kmip.ObjectType) string {
	switch v {
	case kmip.ObjectTypeSymmetricKey:
		return "SymmetricKey"
	case kmip.ObjectTypePublicKey:
		return "PublicKey"
	case kmip.ObjectTypePrivateKey:
		return "PrivateKey"
	case kmip.ObjectTypeSecretData:
		return "SecretData"
	default:
		return "SymmetricKey"
	}
}

func keyTypeFromObjectType(v kmip.ObjectType) string {
	switch v {
	case kmip.ObjectTypeSymmetricKey, kmip.ObjectTypeSecretData:
		return "symmetric"
	case kmip.ObjectTypePublicKey:
		return "public"
	case kmip.ObjectTypePrivateKey:
		return "private"
	default:
		return ""
	}
}

func parseTemplate(t kmip.TemplateAttribute) kmipStoredAttributes {
	out := kmipStoredAttributes{
		OpsLimitWindow: "total",
		IVMode:         "internal",
	}
	if len(t.Name) > 0 {
		out.Name = strings.TrimSpace(t.Name[0].NameValue)
	}
	for _, attr := range t.Attribute {
		switch attr.AttributeName {
		case kmip.AttributeNameName:
			switch v := attr.AttributeValue.(type) {
			case kmip.Name:
				if out.Name == "" {
					out.Name = strings.TrimSpace(v.NameValue)
				}
			case string:
				if out.Name == "" {
					out.Name = strings.TrimSpace(v)
				}
			}
		case kmip.AttributeNameObjectType:
			if v, ok := attr.AttributeValue.(kmip.ObjectType); ok {
				out.ObjectType = v
			}
		case kmip.AttributeNameCryptographicAlgorithm:
			if v, ok := attr.AttributeValue.(kmip.CryptographicAlgorithm); ok {
				out.CryptographicAlg = v
			}
		case kmip.AttributeNameCryptographicLength:
			if v, ok := attr.AttributeValue.(int32); ok {
				out.CryptographicLength = v
			}
		case kmip.AttributeNameCryptographicUsageMask:
			if v, ok := attr.AttributeValue.(kmip.CryptographicUsageMask); ok {
				out.CryptographicUsage = v
			}
		case kmip.AttributeNameCryptographicParameters:
			if v, ok := attr.AttributeValue.(kmip.CryptographicParameters); ok {
				out.KeyRoleType = v.KeyRoleType
				params := v
				out.CryptoParams = &params
				if v.BlockCipherMode != 0 {
					out.IVMode = "internal"
				}
			}
		case kmip.AttributeNameOperationPolicyName:
			if v, ok := attr.AttributeValue.(string); ok {
				out.OperationPolicyName = strings.TrimSpace(v)
				out.ApprovalPolicyID = strings.TrimSpace(v)
				out.ApprovalRequired = strings.TrimSpace(v) != ""
			}
		case kmip.AttributeNameState:
			if v, ok := attr.AttributeValue.(kmip.State); ok {
				out.State = v
			}
		case kmip.AttributeNameUsageLimits:
			if v, ok := attr.AttributeValue.(kmip.UsageLimits); ok {
				out.OpsLimit = v.UsageLimitsTotal
				switch v.UsageLimitsUnit {
				case kmip.UsageLimitsUnitByte:
					out.OpsLimitWindow = "bytes"
				case kmip.UsageLimitsUnitObject:
					out.OpsLimitWindow = "objects"
				default:
					out.OpsLimitWindow = "total"
				}
			}
		case kmip.AttributeNameExtractable:
			if v, ok := attr.AttributeValue.(bool); ok {
				out.ExportAllowed = v
			}
		}
	}
	return out
}

func marshalStoredAttributes(v kmipStoredAttributes) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func parseStoredAttributes(raw string) kmipStoredAttributes {
	out := kmipStoredAttributes{}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func purposeFromUsageMask(mask kmip.CryptographicUsageMask, algorithm string) string {
	if mask == 0 {
		a := strings.ToUpper(strings.TrimSpace(algorithm))
		switch {
		case strings.Contains(a, "HMAC"):
			return "mac"
		case strings.Contains(a, "RSA"), strings.Contains(a, "ECDSA"), strings.Contains(a, "ED25519"):
			return "sign-verify"
		case strings.Contains(a, "ML-KEM"):
			return "wrap-unwrap"
		default:
			return "encrypt-decrypt"
		}
	}
	if mask&(kmip.CryptographicUsageSign|kmip.CryptographicUsageVerify|kmip.CryptographicUsageContentCommitment) != 0 {
		return "sign-verify"
	}
	if mask&(kmip.CryptographicUsageMACGenerate|kmip.CryptographicUsageMACVerify) != 0 {
		return "mac"
	}
	if mask&(kmip.CryptographicUsageWrapKey|kmip.CryptographicUsageUnwrapKey) != 0 {
		return "wrap-unwrap"
	}
	if mask&kmip.CryptographicUsageDeriveKey != 0 {
		return "derive"
	}
	if mask&(kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt) != 0 {
		return "encrypt-decrypt"
	}
	return "encrypt-decrypt"
}

func keycoreAlgorithmFromKMIP(
	alg kmip.CryptographicAlgorithm,
	length int32,
	params *kmip.CryptographicParameters,
	objectType kmip.ObjectType,
) string {
	mode := "GCM"
	if params != nil {
		switch params.BlockCipherMode {
		case kmip.BlockCipherModeCBC:
			mode = "CBC"
		case kmip.BlockCipherModeCTR:
			mode = "CTR"
		case kmip.BlockCipherModeECB:
			mode = "ECB"
		case kmip.BlockCipherModeGCM:
			mode = "GCM"
		case kmip.BlockCipherModeCCM:
			mode = "CCM"
		}
	}
	switch alg {
	case kmip.CryptographicAlgorithmAES:
		bits := normalizeBits(length, 256)
		return fmt.Sprintf("AES-%d-%s", bits, mode)
	case kmip.CryptographicAlgorithmDES:
		return "DES-CBC"
	case kmip.CryptographicAlgorithm3DES:
		return "3DES-CBC"
	case kmip.CryptographicAlgorithmRSA:
		bits := normalizeBits(length, 3072)
		if bits == 8192 {
			return "RSA-8192"
		}
		if bits >= 4096 {
			return "RSA-4096"
		}
		if bits >= 3072 {
			return "RSA-3072"
		}
		return "RSA-2048"
	case kmip.CryptographicAlgorithmECDSA, kmip.CryptographicAlgorithmEC:
		bits := normalizeBits(length, 256)
		if bits >= 521 {
			return "ECDSA-P521"
		}
		if bits >= 384 {
			return "ECDSA-P384"
		}
		return "ECDSA-P256"
	case kmip.CryptographicAlgorithmECDH:
		bits := normalizeBits(length, 256)
		if bits >= 384 {
			return "ECDH-P384"
		}
		return "ECDH-P256"
	case kmip.CryptographicAlgorithmHMACSHA256:
		return "HMAC-SHA256"
	case kmip.CryptographicAlgorithmHMACSHA384:
		return "HMAC-SHA384"
	case kmip.CryptographicAlgorithmHMACSHA512:
		return "HMAC-SHA512"
	case kmip.CryptographicAlgorithmChaCha20, kmip.CryptographicAlgorithmChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	default:
		if objectType == kmip.ObjectTypePrivateKey || objectType == kmip.ObjectTypePublicKey {
			return "RSA-3072"
		}
		return "AES-256-GCM"
	}
}

func normalizeBits(v int32, fallback int32) int32 {
	if v <= 0 {
		return fallback
	}
	return v
}

func keycoreStatusFromKMIPState(v kmip.State) string {
	switch v {
	case kmip.StatePreActive:
		return "pre-active"
	case kmip.StateActive:
		return "active"
	case kmip.StateDeactivated:
		return "deactivated"
	case kmip.StateCompromised:
		return "disabled"
	case kmip.StateDestroyed, kmip.StateDestroyedCompromised:
		return "destroyed"
	default:
		return "active"
	}
}

func stateFromStore(storeState string, metaState kmip.State) kmip.State {
	if metaState != 0 {
		return metaState
	}
	switch strings.ToLower(strings.TrimSpace(storeState)) {
	case "pre-active":
		return kmip.StatePreActive
	case "active":
		return kmip.StateActive
	case "deactivated":
		return kmip.StateDeactivated
	case "disabled":
		return kmip.StateCompromised
	case "destroyed", "deleted", "destroy-pending":
		return kmip.StateDestroyed
	default:
		return kmip.StateActive
	}
}

func enforceUsage(mask kmip.CryptographicUsageMask, op kmip.Operation) error {
	if mask == 0 {
		return nil
	}
	var required kmip.CryptographicUsageMask
	switch op {
	case kmip.OperationEncrypt:
		required = kmip.CryptographicUsageEncrypt
	case kmip.OperationDecrypt:
		required = kmip.CryptographicUsageDecrypt
	case kmip.OperationSign:
		required = kmip.CryptographicUsageSign | kmip.CryptographicUsageMACGenerate
	case kmip.OperationSignatureVerify:
		required = kmip.CryptographicUsageVerify | kmip.CryptographicUsageMACVerify
	default:
		return nil
	}
	if mask&required == 0 {
		return kmipserver.ErrPermissionDenied
	}
	return nil
}

func validateKeyRole(expected kmip.KeyRoleType, params *kmip.CryptographicParameters) error {
	if expected == 0 || params == nil || params.KeyRoleType == 0 {
		return nil
	}
	if expected != params.KeyRoleType {
		return kmipserver.Errorf(
			kmip.ResultReasonInvalidField,
			"key role mismatch: expected=%s got=%s",
			ttlv.EnumStr(expected),
			ttlv.EnumStr(params.KeyRoleType),
		)
	}
	return nil
}

func decodeBase64MapField(v map[string]interface{}, field string) ([]byte, error) {
	s, _ := v[field].(string)
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64", field)
	}
	return out, nil
}

func signingAlgorithmHint(params *kmip.CryptographicParameters) string {
	if params == nil {
		return ""
	}
	if params.DigitalSignatureAlgorithm != 0 {
		return strings.TrimSpace(ttlv.EnumStr(params.DigitalSignatureAlgorithm))
	}
	if params.HashingAlgorithm != 0 {
		return strings.TrimSpace(ttlv.EnumStr(params.HashingAlgorithm))
	}
	return ""
}

func extractRegisterMaterial(obj kmip.Object, objectType kmip.ObjectType) ([]byte, string, error) {
	switch v := obj.(type) {
	case *kmip.SymmetricKey:
		raw, err := v.KeyMaterial()
		if err != nil {
			return nil, "", err
		}
		alg := keycoreAlgorithmFromKMIP(v.KeyBlock.CryptographicAlgorithm, v.KeyBlock.CryptographicLength, nil, objectType)
		return raw, alg, nil
	case *kmip.PublicKey:
		if raw, err := v.KeyBlock.GetBytes(); err == nil && len(raw) > 0 {
			alg := keycoreAlgorithmFromKMIP(v.KeyBlock.CryptographicAlgorithm, v.KeyBlock.CryptographicLength, nil, objectType)
			return raw, alg, nil
		}
		key, err := v.CryptoPublicKey()
		if err != nil {
			return nil, "", err
		}
		raw, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, "", err
		}
		alg := keycoreAlgorithmFromKMIP(v.KeyBlock.CryptographicAlgorithm, v.KeyBlock.CryptographicLength, nil, objectType)
		return raw, alg, nil
	case *kmip.PrivateKey:
		if raw, err := v.KeyBlock.GetBytes(); err == nil && len(raw) > 0 {
			alg := keycoreAlgorithmFromKMIP(v.KeyBlock.CryptographicAlgorithm, v.KeyBlock.CryptographicLength, nil, objectType)
			return raw, alg, nil
		}
		key, err := v.CryptoPrivateKey()
		if err != nil {
			return nil, "", err
		}
		raw, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, "", err
		}
		alg := keycoreAlgorithmFromKMIP(v.KeyBlock.CryptographicAlgorithm, v.KeyBlock.CryptographicLength, nil, objectType)
		return raw, alg, nil
	case *kmip.SecretData:
		raw, err := v.Data()
		if err != nil {
			return nil, "", err
		}
		return raw, "AES-256-GCM", nil
	default:
		return nil, "", errors.New("unsupported register object")
	}
}

func batchRequestID(bi *kmip.RequestBatchItem) string {
	if bi == nil {
		return newID("req")
	}
	if len(bi.UniqueBatchItemID) > 0 {
		return hex.EncodeToString(bi.UniqueBatchItemID)
	}
	return newID("req")
}

func extractUniqueIdentifierFromPayload(payload kmip.OperationPayload) string {
	switch p := payload.(type) {
	case *payloads.CreateResponsePayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.RegisterResponsePayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.GetRequestPayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.GetResponsePayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.GetAttributesRequestPayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.GetAttributesResponsePayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.ActivateRequestPayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.ActivateResponsePayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.RevokeRequestPayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.RevokeResponsePayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.DestroyRequestPayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.DestroyResponsePayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.RekeyRequestPayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.RekeyResponsePayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.EncryptRequestPayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.EncryptResponsePayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.DecryptRequestPayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.DecryptResponsePayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.SignRequestPayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.SignResponsePayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.SignatureVerifyRequestPayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	case *payloads.SignatureVerifyResponsePayload:
		return strings.TrimSpace(p.UniqueIdentifier)
	default:
		return ""
	}
}

func roleCanOperate(role string, op kmip.Operation) bool {
	r := strings.ToLower(strings.TrimSpace(role))
	switch r {
	case "kmip-admin":
		return true
	case "kmip-service":
		return true
	case "kmip-client":
		switch op {
		case kmip.OperationDestroy, kmip.OperationRevoke, kmip.OperationReKey:
			return false
		default:
			return true
		}
	default:
		return false
	}
}

func principalFromTLSState(state tls.ConnectionState) (Principal, error) {
	if len(state.PeerCertificates) == 0 {
		return Principal{}, errors.New("client certificate required")
	}
	cert := state.PeerCertificates[0]
	return principalFromCert(cert)
}

func principalFromCert(cert *x509.Certificate) (Principal, error) {
	if cert == nil {
		return Principal{}, errors.New("certificate is nil")
	}
	cn := strings.TrimSpace(cert.Subject.CommonName)
	if cn == "" {
		return Principal{}, errors.New("client cert CN is required")
	}
	parts := strings.SplitN(cn, ":", 2)
	if len(parts) != 2 {
		return Principal{}, errors.New("client cert CN must be tenant:role")
	}
	tenantID := strings.TrimSpace(parts[0])
	role := strings.TrimSpace(parts[1])
	if tenantID == "" || role == "" {
		return Principal{}, errors.New("invalid tenant:role in CN")
	}
	if !isRoleAllowed(role) {
		return Principal{}, errors.New("role not allowed for kmip")
	}
	return Principal{
		TenantID: tenantID,
		Role:     role,
		CN:       cn,
	}, nil
}

func isRoleAllowed(role string) bool {
	r := strings.ToLower(strings.TrimSpace(role))
	return r == "kmip-client" || r == "kmip-admin" || r == "kmip-service"
}

func (h *Handler) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if h.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "kmip",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return h.events.Publish(ctx, subject, raw)
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func clientFingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func safeTTLVLen(v interface{}) (n int) {
	defer func() {
		if recover() != nil {
			n = 0
		}
	}()
	if v == nil {
		return 0
	}
	return len(ttlv.MarshalTTLV(v))
}
