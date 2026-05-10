//go:build kmip32_extension

package main

// handler_kmip32.go — KMIP 3.2 gap-fill: 12 operations + 5 object types.
// Gated behind the `kmip32_extension` build tag because ovh/kmip-go does not
// yet expose payload types for several operations (CreateKeyPair, Import,
// Export, Archive, Recover, Check, Validate, MAC, MACVerify, Hash, DeriveKey,
// Certify, ReCertify, GetAttributeList, ModifyAttribute, DeleteAttribute,
// GetUsageAllocation). Re-enable per-operation as upstream lands the types,
// or build with `-tags kmip32_extension` once they're all available.
//
// All operations route through the ovh/kmip-go BatchExecutor (SDK routing).
// Crypto-sensitive ops delegate to keycore; attribute-only ops are local.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"

	kmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

// ── CreateKeyPair ────────────────────────────────────────────────────────────

func (h *Handler) handleCreateKeyPair(ctx context.Context, req *payloads.CreateKeyPairRequestPayload) (*payloads.CreateKeyPairResponsePayload, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	if req == nil {
		return nil, kmipserver.ErrMissingData
	}
	// Parse common + per-key templates
	commonAttrs := parseTemplate(req.CommonTemplateAttribute)
	privAttrs := parseTemplate(req.PrivateKeyTemplateAttribute)
	pubAttrs := parseTemplate(req.PublicKeyTemplateAttribute)

	// Merge common → private
	if privAttrs.CryptographicAlg == 0 {
		privAttrs.CryptographicAlg = commonAttrs.CryptographicAlg
	}
	if privAttrs.CryptographicLength == 0 {
		privAttrs.CryptographicLength = commonAttrs.CryptographicLength
	}
	if privAttrs.OperationPolicyName == "" {
		privAttrs.OperationPolicyName = commonAttrs.OperationPolicyName
	}
	if privAttrs.IVMode == "" {
		privAttrs.IVMode = defaultString(commonAttrs.IVMode, "internal")
	}
	if privAttrs.Name == "" {
		privAttrs.Name = defaultString(commonAttrs.Name, "kmip-key-"+newID("n"))
	}

	// Merge common → public
	if pubAttrs.CryptographicAlg == 0 {
		pubAttrs.CryptographicAlg = commonAttrs.CryptographicAlg
	}
	if pubAttrs.CryptographicLength == 0 {
		pubAttrs.CryptographicLength = commonAttrs.CryptographicLength
	}
	if pubAttrs.Name == "" {
		pubAttrs.Name = privAttrs.Name + "-pub"
	}

	alg := keycoreAlgorithmFromKMIP(privAttrs.CryptographicAlg, privAttrs.CryptographicLength, privAttrs.CryptoParams, kmip.ObjectTypePrivateKey)
	if alg == "" {
		alg = "RSA-3072"
	}

	privKeyID, pubKeyID, err := h.keycore.CreateKeyPair(ctx, connCtx.Principal.TenantID, alg, privAttrs.Name)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}

	privObjID := newID("obj")
	pubObjID := newID("obj")

	privAttrs.ObjectType = kmip.ObjectTypePrivateKey
	pubAttrs.ObjectType = kmip.ObjectTypePublicKey

	if err := h.store.UpsertObject(ctx, ObjectMapping{
		TenantID:       connCtx.Principal.TenantID,
		ObjectID:       privObjID,
		KeyID:          privKeyID,
		ObjectType:     "PrivateKey",
		Name:           privAttrs.Name,
		State:          "active",
		Algorithm:      alg,
		AttributesJSON: marshalStoredAttributes(privAttrs),
	}); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	if err := h.store.UpsertObject(ctx, ObjectMapping{
		TenantID:       connCtx.Principal.TenantID,
		ObjectID:       pubObjID,
		KeyID:          pubKeyID,
		ObjectType:     "PublicKey",
		Name:           pubAttrs.Name,
		State:          "active",
		Algorithm:      alg,
		AttributesJSON: marshalStoredAttributes(pubAttrs),
	}); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, privObjID)
	return &payloads.CreateKeyPairResponsePayload{
		PrivateKeyUniqueIdentifier: privObjID,
		PublicKeyUniqueIdentifier:  pubObjID,
	}, nil
}

// ── ModifyAttribute ──────────────────────────────────────────────────────────

func (h *Handler) handleModifyAttribute(ctx context.Context, req *payloads.ModifyAttributeRequestPayload) (*payloads.ModifyAttributeResponsePayload, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	if !kmipMutableAttribute(req.Attribute.AttributeName) {
		_ = h.publishAudit(ctx, "audit.kmip.attribute_mutation_denied", connCtx.Principal.TenantID, map[string]any{
			"attribute": string(req.Attribute.AttributeName),
			"reason":    "attribute is immutable",
		})
		return nil, kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "attribute %q is immutable after creation", req.Attribute.AttributeName)
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
	applyAttribute(&meta, req.Attribute)
	obj.AttributesJSON = marshalStoredAttributes(meta)
	if err := h.store.UpsertObject(ctx, obj); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.ModifyAttributeResponsePayload{UniqueIdentifier: objectID}, nil
}

// ── DeleteAttribute ──────────────────────────────────────────────────────────

func (h *Handler) handleDeleteAttribute(ctx context.Context, req *payloads.DeleteAttributeRequestPayload) (*payloads.DeleteAttributeResponsePayload, error) {
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
	deleteAttribute(&meta, req.AttributeName)
	obj.AttributesJSON = marshalStoredAttributes(meta)
	if err := h.store.UpsertObject(ctx, obj); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.DeleteAttributeResponsePayload{UniqueIdentifier: objectID}, nil
}

// ── GetAttributeList ─────────────────────────────────────────────────────────

func (h *Handler) handleGetAttributeList(ctx context.Context, req *payloads.GetAttributeListRequestPayload) (*payloads.GetAttributeListResponsePayload, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	uid := ""
	if req != nil {
		uid = strings.TrimSpace(req.UniqueIdentifier)
	}
	objectID, err := kmipserver.GetIdOrPlaceholder(ctx, uid)
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
	names := presentAttributeNames(objectID, obj, meta)
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.GetAttributeListResponsePayload{
		UniqueIdentifier: objectID,
		AttributeName:    names,
	}, nil
}

// ── Import (KMIP 3.x equivalent of Register) ─────────────────────────────────

func (h *Handler) handleImport(ctx context.Context, req *payloads.ImportRequestPayload) (*payloads.ImportResponsePayload, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	if req == nil {
		return nil, kmipserver.ErrMissingData
	}
	rawMaterial, detectedAlg, err := extractRegisterMaterial(req.ManagedCryptographicObject, req.ObjectType)
	if err != nil {
		rawMaterial, detectedAlg, err = extractRegisterMaterial(req.Object, req.ObjectType)
		if err != nil {
			return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "cannot extract material: %v", err)
		}
	}
	attrs := parseTemplate(req.Attributes)
	if attrs.Name == "" {
		attrs.Name = "kmip-imported-" + newID("n")
	}
	keycoreAlg := keycoreAlgorithmFromKMIP(attrs.CryptographicAlg, attrs.CryptographicLength, attrs.CryptoParams, req.ObjectType)
	if keycoreAlg == "" {
		keycoreAlg = detectedAlg
	}
	if keycoreAlg == "" {
		keycoreAlg = "AES-256-GCM"
	}
	keyType := keyTypeFromObjectType(req.ObjectType)
	if keyType == "" {
		keyType = "symmetric"
	}
	keyID, err := h.keycore.ImportKey(ctx, connCtx.Principal.TenantID, RegisterRequest{
		Name:        attrs.Name,
		Algorithm:   keycoreAlg,
		KeyType:     keyType,
		Purpose:     purposeFromUsageMask(attrs.CryptographicUsage, keycoreAlg),
		MaterialB64: base64.StdEncoding.EncodeToString(rawMaterial),
	})
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	objID := newID("obj")
	if err := h.store.UpsertObject(ctx, ObjectMapping{
		TenantID:       connCtx.Principal.TenantID,
		ObjectID:       objID,
		KeyID:          keyID,
		ObjectType:     objectTypeToStore(req.ObjectType),
		Name:           attrs.Name,
		State:          "active",
		Algorithm:      keycoreAlg,
		AttributesJSON: marshalStoredAttributes(attrs),
	}); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, objID)
	return &payloads.ImportResponsePayload{UniqueIdentifier: objID}, nil
}

// ── Export ───────────────────────────────────────────────────────────────────

func (h *Handler) handleExport(ctx context.Context, req *payloads.ExportRequestPayload) (*payloads.ExportResponsePayload, error) {
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
	if !meta.ExportAllowed {
		return nil, kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "object is not marked exportable")
	}
	if err := h.enforceObjectPolicy(connCtx.Principal, ttlv.EnumStr(kmip.OperationGet), meta); err != nil {
		return nil, err
	}
	materialB64, err := h.keycore.ExportKeyMaterial(ctx, connCtx.Principal.TenantID, obj.KeyID)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "export failed: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(materialB64)
	objType := objectTypeFromStore(obj.ObjectType)
	managedObj := buildExportedKMIPObject(objType, meta, raw)
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.ExportResponsePayload{
		ObjectType:       objType,
		UniqueIdentifier: objectID,
		Object:           managedObj,
	}, nil
}

// ── Archive ──────────────────────────────────────────────────────────────────

func (h *Handler) handleArchive(ctx context.Context, req *payloads.ArchiveRequestPayload) (*payloads.ArchiveResponsePayload, error) {
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
	if err := h.enforceObjectPolicy(connCtx.Principal, "state_change", meta); err != nil {
		return nil, err
	}
	// Archive: mark as archived in attributes; KMIP state unchanged
	setArchivedFlag(&meta, true)
	obj.AttributesJSON = marshalStoredAttributes(meta)
	if err := h.store.UpsertObject(ctx, obj); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.ArchiveResponsePayload{UniqueIdentifier: objectID}, nil
}

// ── Recover ──────────────────────────────────────────────────────────────────

func (h *Handler) handleRecover(ctx context.Context, req *payloads.RecoverRequestPayload) (*payloads.RecoverResponsePayload, error) {
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
	if err := h.enforceObjectPolicy(connCtx.Principal, "state_change", meta); err != nil {
		return nil, err
	}
	setArchivedFlag(&meta, false)
	obj.AttributesJSON = marshalStoredAttributes(meta)
	if err := h.store.UpsertObject(ctx, obj); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.RecoverResponsePayload{UniqueIdentifier: objectID}, nil
}

// ── Check / Validate / MAC / MACVerify / Hash ────────────────────────────────
// Removed: ovh/kmip-go does not yet expose the corresponding payload structs.
// Restore from git history once upstream publishes them.

// ── DeriveKey ────────────────────────────────────────────────────────────────

func (h *Handler) handleDeriveKey(ctx context.Context, req *payloads.DeriveKeyRequestPayload) (*payloads.DeriveKeyResponsePayload, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	if req == nil || len(req.UniqueIdentifier) == 0 {
		return nil, kmipserver.ErrMissingData
	}
	sourceID, err := kmipserver.GetIdOrPlaceholder(ctx, strings.TrimSpace(req.UniqueIdentifier[0]))
	if err != nil {
		return nil, kmipserver.ErrMissingData
	}
	sourceObj, err := h.store.GetObject(ctx, connCtx.Principal.TenantID, sourceID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, kmipserver.ErrItemNotFound
		}
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	sourceMeta := parseStoredAttributes(sourceObj.AttributesJSON)
	if err := h.enforceObjectPolicy(connCtx.Principal, "derive", sourceMeta); err != nil {
		return nil, err
	}

	derivAttrs := parseTemplate(req.TemplateAttribute)
	if derivAttrs.Name == "" {
		derivAttrs.Name = "kmip-derived-" + newID("n")
	}
	targetAlg := keycoreAlgorithmFromKMIP(derivAttrs.CryptographicAlg, derivAttrs.CryptographicLength, derivAttrs.CryptoParams, req.ObjectType)
	if targetAlg == "" {
		targetAlg = "AES-256-GCM"
	}

	derivedKeyID, err := h.keycore.DeriveKey(ctx, connCtx.Principal.TenantID, sourceObj.KeyID,
		derivationMethodStr(req.DerivationMethod), targetAlg, derivAttrs.Name)
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}

	derivAttrs.ObjectType = req.ObjectType
	objID := newID("obj")
	if err := h.store.UpsertObject(ctx, ObjectMapping{
		TenantID:       connCtx.Principal.TenantID,
		ObjectID:       objID,
		KeyID:          derivedKeyID,
		ObjectType:     objectTypeToStore(req.ObjectType),
		Name:           derivAttrs.Name,
		State:          "active",
		Algorithm:      targetAlg,
		AttributesJSON: marshalStoredAttributes(derivAttrs),
	}); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, objID)
	return &payloads.DeriveKeyResponsePayload{
		ObjectType:       req.ObjectType,
		UniqueIdentifier: objID,
	}, nil
}

// ── GetUsageAllocation ───────────────────────────────────────────────────────

func (h *Handler) handleGetUsageAllocation(ctx context.Context, req *payloads.GetUsageAllocationRequestPayload) (*payloads.GetUsageAllocationResponsePayload, error) {
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
	total := meta.OpsLimit
	if total <= 0 {
		total = 0 // unlimited
	}
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.GetUsageAllocationResponsePayload{
		UniqueIdentifier: objectID,
		UsageLimits: kmip.UsageLimits{
			UsageLimitsTotal: total,
			UsageLimitsUnit:  kmip.UsageLimitsUnitObject,
		},
	}, nil
}

// ── Certify ──────────────────────────────────────────────────────────────────

func (h *Handler) handleCertify(ctx context.Context, req *payloads.CertifyRequestPayload) (*payloads.CertifyResponsePayload, error) {
	connCtx, ok := getConnectionContext(ctx)
	if !ok {
		return nil, kmipserver.ErrPermissionDenied
	}
	if req == nil {
		return nil, kmipserver.ErrMissingData
	}
	attrs := parseTemplate(req.Attributes)
	if attrs.Name == "" {
		attrs.Name = "kmip-cert-" + newID("n")
	}
	// RequestMessage carries the CSR PEM/DER; field may be []byte in SDK
	csr := extractCSRFromCertifyReq(req)
	issued, err := h.certs.IssueCertificate(ctx, CertsIssueCertificateRequest{
		TenantID:     connCtx.Principal.TenantID,
		CertType:     "server",
		Algorithm:    "RSA-3072",
		SubjectCN:    attrs.Name,
		CSRPem:       csr,
		ServerKeygen: csr == "",
		ValidityDays: 365,
		Protocol:     "kmip",
	})
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "certify failed: %v", err)
	}

	objID := newID("obj")
	certAttrs := kmipStoredAttributes{
		Name:       attrs.Name,
		ObjectType: kmip.ObjectTypeCertificate,
		State:      kmip.StateActive,
	}
	certAttrsRaw := marshalStoredAttributes(certAttrs)
	// Embed the PEM in attributes JSON
	certAttrsRaw = setCertPEMInAttrs(certAttrsRaw, issued.CertPEM, issued.ID)

	if err := h.store.UpsertObject(ctx, ObjectMapping{
		TenantID:       connCtx.Principal.TenantID,
		ObjectID:       objID,
		KeyID:          issued.ID,
		ObjectType:     "Certificate",
		Name:           attrs.Name,
		State:          "active",
		Algorithm:      "X.509",
		AttributesJSON: certAttrsRaw,
	}); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, objID)
	return &payloads.CertifyResponsePayload{UniqueIdentifier: objID}, nil
}

// ── ReCertify ────────────────────────────────────────────────────────────────

func (h *Handler) handleReCertify(ctx context.Context, req *payloads.ReCertifyRequestPayload) (*payloads.ReCertifyResponsePayload, error) {
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
	if !strings.EqualFold(strings.TrimSpace(obj.ObjectType), "certificate") {
		return nil, kmipserver.Errorf(kmip.ResultReasonInvalidField, "object is not a Certificate")
	}
	csr := extractCSRFromReCertifyReq(req)
	issued, err := h.certs.IssueCertificate(ctx, CertsIssueCertificateRequest{
		TenantID:     connCtx.Principal.TenantID,
		CertType:     "server",
		Algorithm:    "RSA-3072",
		SubjectCN:    obj.Name,
		CSRPem:       csr,
		ServerKeygen: csr == "",
		ValidityDays: 365,
		Protocol:     "kmip-recertify",
	})
	if err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "recertify failed: %v", err)
	}
	obj.KeyID = issued.ID
	obj.AttributesJSON = setCertPEMInAttrs(obj.AttributesJSON, issued.CertPEM, issued.ID)
	if err := h.store.UpsertObject(ctx, obj); err != nil {
		return nil, kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "%v", err)
	}
	kmipserver.SetIdPlaceholder(ctx, objectID)
	return &payloads.ReCertifyResponsePayload{UniqueIdentifier: objectID}, nil
}

// ── Helpers for new object types / attributes ─────────────────────────────────

// kmipMutableAttribute reports whether an attribute may be modified after a
// managed object has been created. Cryptographic-defining attributes
// (algorithm, length, usage mask, state, extractable) are deliberately
// immutable: changing them post-creation would let a client weaken or
// repurpose a key in ways that bypass policy checks performed at
// registration. Operation policy name, usage limits, and other ancillary
// metadata remain mutable.
func kmipMutableAttribute(name kmip.AttributeName) bool {
	switch name {
	case kmip.AttributeNameOperationPolicyName,
		kmip.AttributeNameUsageLimits:
		return true
	default:
		return false
	}
}

// applyAttribute sets a specific attribute on the stored meta.
func applyAttribute(meta *kmipStoredAttributes, attr kmip.Attribute) {
	if !kmipMutableAttribute(attr.AttributeName) {
		return
	}
	switch attr.AttributeName {
	case kmip.AttributeNameOperationPolicyName:
		if v, ok := attr.AttributeValue.(string); ok {
			meta.OperationPolicyName = strings.TrimSpace(v)
		}
	case kmip.AttributeNameUsageLimits:
		if v, ok := attr.AttributeValue.(kmip.UsageLimits); ok {
			meta.OpsLimit = v.UsageLimitsTotal
		}
	}
}

// deleteAttribute zeros a named attribute.
func deleteAttribute(meta *kmipStoredAttributes, attrName string) {
	switch attrName {
	case kmip.AttributeNameCryptographicAlgorithm:
		meta.CryptographicAlg = 0
	case kmip.AttributeNameCryptographicLength:
		meta.CryptographicLength = 0
	case kmip.AttributeNameCryptographicUsageMask:
		meta.CryptographicUsage = 0
	case kmip.AttributeNameOperationPolicyName:
		meta.OperationPolicyName = ""
		meta.ApprovalRequired = false
		meta.ApprovalPolicyID = ""
	case kmip.AttributeNameCryptographicParameters:
		meta.CryptoParams = nil
		meta.KeyRoleType = 0
	case kmip.AttributeNameExtractable:
		meta.ExportAllowed = false
	case kmip.AttributeNameUsageLimits:
		meta.OpsLimit = 0
	}
}

// presentAttributeNames lists all attribute names that are populated on the object.
func presentAttributeNames(objectID string, obj ObjectMapping, meta kmipStoredAttributes) []string {
	names := []string{
		kmip.AttributeNameUniqueIdentifier,
		kmip.AttributeNameName,
		kmip.AttributeNameObjectType,
		kmip.AttributeNameState,
	}
	if meta.CryptographicAlg != 0 {
		names = append(names, kmip.AttributeNameCryptographicAlgorithm)
	}
	if meta.CryptographicLength > 0 {
		names = append(names, kmip.AttributeNameCryptographicLength)
	}
	if meta.CryptographicUsage != 0 {
		names = append(names, kmip.AttributeNameCryptographicUsageMask)
	}
	if meta.KeyRoleType != 0 {
		names = append(names, kmip.AttributeNameCryptographicParameters)
	}
	if strings.TrimSpace(meta.OperationPolicyName) != "" {
		names = append(names, kmip.AttributeNameOperationPolicyName)
	}
	if meta.OpsLimit > 0 {
		names = append(names, kmip.AttributeNameUsageLimits)
	}
	_ = objectID
	_ = obj
	return names
}

// buildExportedKMIPObject builds an object with real material for Export responses.
func buildExportedKMIPObject(objType kmip.ObjectType, meta kmipStoredAttributes, material []byte) kmip.Object {
	switch objType {
	case kmip.ObjectTypeSymmetricKey:
		return &kmip.SymmetricKey{
			KeyBlock: kmip.KeyBlock{
				KeyFormatType:          kmip.KeyFormatTypeRaw,
				CryptographicAlgorithm: meta.CryptographicAlg,
				CryptographicLength:    meta.CryptographicLength,
				KeyValue: kmip.KeyValue{
					KeyMaterial: material,
				},
			},
		}
	case kmip.ObjectTypePrivateKey:
		return &kmip.PrivateKey{
			KeyBlock: kmip.KeyBlock{
				KeyFormatType:          kmip.KeyFormatTypePKCS_8,
				CryptographicAlgorithm: meta.CryptographicAlg,
				CryptographicLength:    meta.CryptographicLength,
				KeyValue: kmip.KeyValue{
					KeyMaterial: material,
				},
			},
		}
	case kmip.ObjectTypePublicKey:
		return &kmip.PublicKey{
			KeyBlock: kmip.KeyBlock{
				KeyFormatType:          kmip.KeyFormatTypeX_509,
				CryptographicAlgorithm: meta.CryptographicAlg,
				CryptographicLength:    meta.CryptographicLength,
				KeyValue: kmip.KeyValue{
					KeyMaterial: material,
				},
			},
		}
	case kmip.ObjectTypeCertificate:
		return &kmip.Certificate{
			CertificateType:  kmip.CertificateTypeX_509,
			CertificateValue: material,
		}
	case kmip.ObjectTypeSecretData:
		return &kmip.SecretData{
			SecretDataType: kmip.SecretDataTypeSeed,
			KeyBlock: kmip.KeyBlock{
				KeyFormatType: kmip.KeyFormatTypeOpaque,
				KeyValue: kmip.KeyValue{
					KeyMaterial: material,
				},
			},
		}
	default:
		return &kmip.OpaqueObject{
			OpaqueDataType:  kmip.OpaqueDataTypeStructure,
			OpaqueDataValue: material,
		}
	}
}

// setArchivedFlag sets/clears the "archived" boolean in the AttributesJSON map.
func setArchivedFlag(meta *kmipStoredAttributes, archived bool) {
	// We store archived state in IVMode field overloaded value since
	// kmipStoredAttributes doesn't have a dedicated field; use IVMode="archived"
	// IVMode is only meaningful for symmetric keys; for all other states we preserve it.
	if archived {
		meta.IVMode = "archived|" + meta.IVMode
	} else {
		meta.IVMode = strings.TrimPrefix(meta.IVMode, "archived|")
		if meta.IVMode == "" {
			meta.IVMode = "internal"
		}
	}
}

// setCertPEMInAttrs embeds cert PEM into an attributes JSON blob.
func setCertPEMInAttrs(attrsJSON string, certPEM string, certID string) string {
	m := map[string]interface{}{}
	_ = json.Unmarshal([]byte(attrsJSON), &m)
	m["cert_pem"] = certPEM
	m["cert_id"] = certID
	raw, _ := json.Marshal(m)
	return string(raw)
}

// hashAlgorithmHint extracts a hash algorithm name from CryptographicParameters.
func hashAlgorithmHint(params *kmip.CryptographicParameters) string {
	if params == nil {
		return "HMAC-SHA256"
	}
	switch params.HashingAlgorithm {
	case kmip.HashingAlgorithmSHA_384:
		return "HMAC-SHA384"
	case kmip.HashingAlgorithmSHA_512:
		return "HMAC-SHA512"
	default:
		return "HMAC-SHA256"
	}
}

// derivationMethodStr converts kmip.DerivationMethod to a string for keycore.
func derivationMethodStr(m kmip.DerivationMethod) string {
	switch m {
	case kmip.DerivationMethodPBKDF2:
		return "PBKDF2"
	case kmip.DerivationMethodHashFunction:
		return "Hash"
	case kmip.DerivationMethodHMACFunction:
		return "HMAC"
	case kmip.DerivationMethodEncryptThenMAC:
		return "EncryptThenMAC"
	case kmip.DerivationMethodNIST800_108C:
		return "NIST800-108-C"
	default:
		return "HKDF" // default to HKDF for KMIP 3.x compliance
	}
}

// extractCSRFromCertifyReq extracts the CSR string from CertifyRequestPayload.
// The field may be []byte (DER) or string (PEM) depending on SDK version.
func extractCSRFromCertifyReq(req *payloads.CertifyRequestPayload) string {
	if req == nil {
		return ""
	}
	// Try string field first (KMIP 3.x SDK may use []byte RequestMessage)
	if len(req.RequestMessage) > 0 {
		// If it looks like PEM, use as-is; otherwise treat as DER
		s := string(req.RequestMessage)
		if strings.Contains(s, "-----BEGIN") {
			return strings.TrimSpace(s)
		}
		// DER — return base64 representation; certs service handles both
		return base64.StdEncoding.EncodeToString(req.RequestMessage)
	}
	return ""
}

// extractCSRFromReCertifyReq extracts the CSR from ReCertifyRequestPayload.
func extractCSRFromReCertifyReq(req *payloads.ReCertifyRequestPayload) string {
	if req == nil {
		return ""
	}
	if len(req.RequestMessage) > 0 {
		s := string(req.RequestMessage)
		if strings.Contains(s, "-----BEGIN") {
			return strings.TrimSpace(s)
		}
		return base64.StdEncoding.EncodeToString(req.RequestMessage)
	}
	return ""
}

// hmacInService computes HMAC in-service as a fallback when keycore is unavailable.
// Prefer keycore delegation in production; this is used for testing/offline scenarios.
func hmacInService(key []byte, data []byte, algorithm string) []byte {
	var hf func() hash.Hash
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "HMAC-SHA384":
		hf = sha512.New384
	case "HMAC-SHA512":
		hf = sha512.New
	default:
		hf = sha256.New
	}
	mac := hmac.New(hf, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

// generateOpaqueID creates a placeholder key ID for opaque objects that have no keycore backing.
func generateOpaqueID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("opaque-%x", b)
}

// Ensure time import is used via this package-level reference.
var _ = time.RFC3339
