package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	tr31lib "github.com/moov-io/tr31/pkg/tr31"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/metering"
	pkgpayment "vecta-kms/pkg/payment"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

var supportedTR31KeyUsages = []string{
	"B0", "D0", "K0", "K1", "M3", "P0", "V0", "V1",
}

var supportedPaymentTypes = map[string]struct{}{
	"ZMK":  {},
	"TMK":  {},
	"TPK":  {},
	"BMK":  {},
	"BDK":  {},
	"IPEK": {},
	"ZPK":  {},
	"ZAK":  {},
	"ZEK":  {},
}

type Service struct {
	store   Store
	keycore KeyCoreClient
	events  EventPublisher
	meter   *metering.Meter
}

var supportedPaymentTR31Versions = []string{"B", "C", "D"}
var supportedPINBlockFormats = []string{"ISO-0", "ISO-1", "ISO-3"}

const defaultPaymentDecimalizationTable = "0123456789012345"

func NewService(store Store, keycore KeyCoreClient, events EventPublisher, meter *metering.Meter) *Service {
	if meter == nil {
		meter = metering.NewMeter(0, 0)
	}
	return &Service{
		store:   store,
		keycore: keycore,
		events:  events,
		meter:   meter,
	}
}

func defaultPaymentPolicy(tenantID string) PaymentPolicy {
	return PaymentPolicy{
		TenantID:                  strings.TrimSpace(tenantID),
		AllowedTR31Versions:       append([]string{}, supportedPaymentTR31Versions...),
		RequireKBPKForTR31:        false,
		AllowInlineKeyMaterial:    true,
		MaxISO20022PayloadBytes:   262144,
		RequireISO20022LAUContext: false,
		StrictPCIDSS40:            false,
		RequireKeyIDForOperations: false,
		AllowTCPInterface:         true,
		RequireJWTOnTCP:           true,
		MaxTCPPayloadBytes:        262144,
		AllowedTCPOperations:      append([]string{}, supportedPaymentCryptoOperations...),
		AllowedPINBlockFormats:    append([]string{}, supportedPINBlockFormats...),
		DisableISO0PINBlock:       false,
		DecimalizationTable:       defaultPaymentDecimalizationTable,
		BlockWildcardPAN:          true,
	}
}

func isValidDecimalizationTable(raw string) bool {
	value := strings.TrimSpace(raw)
	if len(value) != 16 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func normalizeDecimalizationTable(raw string) string {
	value := strings.TrimSpace(raw)
	if !isValidDecimalizationTable(value) {
		return defaultPaymentDecimalizationTable
	}
	return value
}

func normalizePaymentPolicy(in PaymentPolicy) PaymentPolicy {
	in.TenantID = strings.TrimSpace(in.TenantID)
	allowed := uniqueStrings(in.AllowedTR31Versions)
	outAllowed := make([]string, 0, len(allowed))
	for _, item := range allowed {
		v := normalizeTR31Version(item)
		if containsString(supportedPaymentTR31Versions, v) {
			outAllowed = append(outAllowed, v)
		}
	}
	if len(outAllowed) == 0 {
		outAllowed = append([]string{}, supportedPaymentTR31Versions...)
	}
	in.AllowedTR31Versions = outAllowed
	if in.MaxISO20022PayloadBytes <= 0 {
		in.MaxISO20022PayloadBytes = 262144
	}
	if in.MaxISO20022PayloadBytes > 4194304 {
		in.MaxISO20022PayloadBytes = 4194304
	}
	pinFormats := uniqueStrings(in.AllowedPINBlockFormats)
	outPIN := make([]string, 0, len(pinFormats))
	for _, item := range pinFormats {
		v := normalizePINFormat(item)
		if containsString(supportedPINBlockFormats, v) {
			outPIN = append(outPIN, v)
		}
	}
	if len(outPIN) == 0 {
		outPIN = append([]string{}, supportedPINBlockFormats...)
	}
	if in.DisableISO0PINBlock {
		filtered := make([]string, 0, len(outPIN))
		for _, v := range outPIN {
			if strings.EqualFold(v, "ISO-0") {
				continue
			}
			filtered = append(filtered, v)
		}
		if len(filtered) == 0 {
			filtered = []string{"ISO-1", "ISO-3"}
		}
		outPIN = filtered
	}
	in.AllowedPINBlockFormats = outPIN
	in.DecimalizationTable = normalizeDecimalizationTable(in.DecimalizationTable)
	tcpOps := uniqueStrings(in.AllowedTCPOperations)
	outOps := make([]string, 0, len(tcpOps))
	for _, item := range tcpOps {
		v := strings.ToLower(strings.TrimSpace(item))
		if containsString(supportedPaymentCryptoOperations, v) {
			outOps = append(outOps, v)
		}
	}
	if len(outOps) == 0 {
		outOps = append([]string{}, supportedPaymentCryptoOperations...)
	}
	in.AllowedTCPOperations = outOps
	if in.MaxTCPPayloadBytes <= 0 {
		in.MaxTCPPayloadBytes = 262144
	}
	if in.MaxTCPPayloadBytes < 4096 {
		in.MaxTCPPayloadBytes = 4096
	}
	if in.MaxTCPPayloadBytes > 1048576 {
		in.MaxTCPPayloadBytes = 1048576
	}
	in.UpdatedBy = strings.TrimSpace(in.UpdatedBy)
	return in
}

func (s *Service) GetPaymentPolicy(ctx context.Context, tenantID string) (PaymentPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return PaymentPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetPaymentPolicy(ctx, tenantID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return defaultPaymentPolicy(tenantID), nil
		}
		return PaymentPolicy{}, err
	}
	return normalizePaymentPolicy(item), nil
}

func (s *Service) UpdatePaymentPolicy(ctx context.Context, in PaymentPolicy) (PaymentPolicy, error) {
	if raw := strings.TrimSpace(in.DecimalizationTable); raw != "" && !isValidDecimalizationTable(raw) {
		return PaymentPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "decimalization_table must be exactly 16 digits (0-9)")
	}
	in = normalizePaymentPolicy(in)
	if in.TenantID == "" {
		return PaymentPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	item, err := s.store.UpsertPaymentPolicy(ctx, in)
	if err != nil {
		return PaymentPolicy{}, err
	}
	item = normalizePaymentPolicy(item)
	_ = s.publishAudit(ctx, "audit.payment.policy_updated", item.TenantID, map[string]interface{}{
		"allowed_tr31_versions":         item.AllowedTR31Versions,
		"require_kbpk_for_tr31":         item.RequireKBPKForTR31,
		"allow_inline_key_material":     item.AllowInlineKeyMaterial,
		"max_iso20022_payload_bytes":    item.MaxISO20022PayloadBytes,
		"require_iso20022_lau_context":  item.RequireISO20022LAUContext,
		"strict_pci_dss_4_0":            item.StrictPCIDSS40,
		"require_key_id_for_operations": item.RequireKeyIDForOperations,
		"allow_tcp_interface":           item.AllowTCPInterface,
		"require_jwt_on_tcp":            item.RequireJWTOnTCP,
		"max_tcp_payload_bytes":         item.MaxTCPPayloadBytes,
		"allowed_tcp_operations":        item.AllowedTCPOperations,
		"allowed_pin_block_formats":     item.AllowedPINBlockFormats,
		"disable_iso0_pin_block":        item.DisableISO0PINBlock,
		"decimalization_table":          item.DecimalizationTable,
		"block_wildcard_pan":            item.BlockWildcardPAN,
	})
	return item, nil
}

func (s *Service) mustPaymentPolicy(ctx context.Context, tenantID string) (PaymentPolicy, error) {
	item, err := s.GetPaymentPolicy(ctx, tenantID)
	if err != nil {
		return PaymentPolicy{}, err
	}
	return item, nil
}

func paymentTR31VersionAllowed(policy PaymentPolicy, version string) bool {
	ver := normalizeTR31Version(version)
	if ver == "" {
		return false
	}
	for _, allowed := range policy.AllowedTR31Versions {
		if normalizeTR31Version(allowed) == ver {
			return true
		}
	}
	return false
}

func (s *Service) RegisterPaymentKey(ctx context.Context, req RegisterPaymentKeyRequest) (PaymentKey, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	if req.TenantID == "" || req.KeyID == "" {
		return PaymentKey{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key_id are required")
	}
	paymentType := strings.ToUpper(strings.TrimSpace(req.PaymentType))
	if _, ok := supportedPaymentTypes[paymentType]; !ok {
		return PaymentKey{}, newServiceError(http.StatusBadRequest, "bad_request", "unsupported payment_type")
	}
	usage := normalizeTR31UsageCode(req.UsageCode)
	if usage == "" {
		return PaymentKey{}, newServiceError(http.StatusBadRequest, "bad_request", "invalid usage_code")
	}
	mode := normalizeModeOfUse(req.ModeOfUse)
	if mode == "" {
		return PaymentKey{}, newServiceError(http.StatusBadRequest, "bad_request", "invalid mode_of_use")
	}
	exportability := normalizeExportability(req.Exportability)
	if exportability == "" {
		return PaymentKey{}, newServiceError(http.StatusBadRequest, "bad_request", "invalid exportability")
	}

	var kcvHex string
	if s.keycore != nil {
		if out, err := s.keycore.GetKey(ctx, req.TenantID, req.KeyID); err == nil {
			kcvHex = strings.ToUpper(strings.TrimSpace(firstString(out["kcv"], out["kcv_hex"])))
		}
	}
	item := PaymentKey{
		ID:               newID("pkey"),
		TenantID:         req.TenantID,
		KeyID:            req.KeyID,
		PaymentType:      paymentType,
		UsageCode:        usage,
		ModeOfUse:        mode,
		KeyVersionNum:    defaultTR31KeyVersion(req.KeyVersionNum),
		Exportability:    exportability,
		TR31Header:       strings.TrimSpace(req.TR31Header),
		KCV:              parseKCVHex(kcvHex),
		KCVHex:           kcvHex,
		ISO20022PartyID:  strings.TrimSpace(req.ISO20022PartyID),
		ISO20022MsgTypes: mustJSON(req.ISO20022MsgTypes),
	}
	if strings.TrimSpace(item.TR31Header) == "" {
		item.TR31Header = item.KeyVersionNum + item.UsageCode + "AES"
	}
	if err := s.store.CreatePaymentKey(ctx, item); err != nil {
		return PaymentKey{}, err
	}
	_ = s.publishAudit(ctx, "audit.payment.key_registered", item.TenantID, map[string]interface{}{
		"payment_key_id": item.ID,
		"key_id":         item.KeyID,
		"payment_type":   item.PaymentType,
		"usage_code":     item.UsageCode,
	})
	return s.store.GetPaymentKey(ctx, item.TenantID, item.ID)
}

func (s *Service) ListPaymentKeys(ctx context.Context, tenantID string) ([]PaymentKey, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	return s.store.ListPaymentKeys(ctx, tenantID)
}

func (s *Service) GetPaymentKey(ctx context.Context, tenantID string, id string) (PaymentKey, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return PaymentKey{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and id are required")
	}
	return s.store.GetPaymentKey(ctx, tenantID, id)
}

func (s *Service) UpdatePaymentKey(ctx context.Context, id string, req UpdatePaymentKeyRequest) (PaymentKey, error) {
	id = strings.TrimSpace(id)
	req.TenantID = strings.TrimSpace(req.TenantID)
	if id == "" || req.TenantID == "" {
		return PaymentKey{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and id are required")
	}
	current, err := s.store.GetPaymentKey(ctx, req.TenantID, id)
	if err != nil {
		return PaymentKey{}, err
	}

	if strings.TrimSpace(req.PaymentType) != "" {
		req.PaymentType = strings.ToUpper(strings.TrimSpace(req.PaymentType))
		if _, ok := supportedPaymentTypes[req.PaymentType]; !ok {
			return PaymentKey{}, newServiceError(http.StatusBadRequest, "bad_request", "unsupported payment_type")
		}
	} else {
		req.PaymentType = current.PaymentType
	}
	if strings.TrimSpace(req.UsageCode) == "" {
		req.UsageCode = current.UsageCode
	}
	req.UsageCode = normalizeTR31UsageCode(req.UsageCode)
	if req.UsageCode == "" {
		return PaymentKey{}, newServiceError(http.StatusBadRequest, "bad_request", "invalid usage_code")
	}
	if strings.TrimSpace(req.ModeOfUse) == "" {
		req.ModeOfUse = current.ModeOfUse
	}
	req.ModeOfUse = normalizeModeOfUse(req.ModeOfUse)
	if req.ModeOfUse == "" {
		return PaymentKey{}, newServiceError(http.StatusBadRequest, "bad_request", "invalid mode_of_use")
	}
	if strings.TrimSpace(req.Exportability) == "" {
		req.Exportability = current.Exportability
	}
	req.Exportability = normalizeExportability(req.Exportability)
	if req.Exportability == "" {
		return PaymentKey{}, newServiceError(http.StatusBadRequest, "bad_request", "invalid exportability")
	}

	msgTypes := req.ISO20022MsgTypes
	if len(msgTypes) == 0 {
		msgTypes = parseStringListJSON(current.ISO20022MsgTypes)
	}
	updated := PaymentKey{
		ID:               id,
		TenantID:         req.TenantID,
		KeyID:            current.KeyID,
		PaymentType:      req.PaymentType,
		UsageCode:        req.UsageCode,
		ModeOfUse:        req.ModeOfUse,
		KeyVersionNum:    defaultTR31KeyVersion(firstString(req.KeyVersionNum, current.KeyVersionNum)),
		Exportability:    req.Exportability,
		TR31Header:       firstString(req.TR31Header, current.TR31Header),
		ISO20022PartyID:  firstString(req.ISO20022PartyID, current.ISO20022PartyID),
		ISO20022MsgTypes: mustJSON(msgTypes),
		KCV:              current.KCV,
	}
	if err := s.store.UpdatePaymentKey(ctx, updated); err != nil {
		return PaymentKey{}, err
	}
	_ = s.publishAudit(ctx, "audit.payment.key_updated", req.TenantID, map[string]interface{}{
		"payment_key_id": id,
		"key_id":         current.KeyID,
	})
	return s.store.GetPaymentKey(ctx, req.TenantID, id)
}

func (s *Service) RotatePaymentKey(ctx context.Context, id string, req RotatePaymentKeyRequest) (RotatePaymentKeyResponse, error) {
	id = strings.TrimSpace(id)
	req.TenantID = strings.TrimSpace(req.TenantID)
	if id == "" || req.TenantID == "" {
		return RotatePaymentKeyResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and id are required")
	}
	key, err := s.store.GetPaymentKey(ctx, req.TenantID, id)
	if err != nil {
		return RotatePaymentKeyResponse{}, err
	}
	if s.keycore == nil {
		return RotatePaymentKeyResponse{}, newServiceError(http.StatusFailedDependency, "keycore_unavailable", "keycore client is not configured")
	}
	rot, err := s.keycore.RotateKey(ctx, req.TenantID, key.KeyID, req.Reason)
	if err != nil {
		return RotatePaymentKeyResponse{}, newServiceError(http.StatusBadGateway, "keycore_rotate_failed", err.Error())
	}
	verID := firstString(rot["version_id"], rot["version"], rot["id"])
	nextVersion := incrementTR31KeyVersion(key.KeyVersionNum)
	if err := s.store.UpdatePaymentKeyVersion(ctx, req.TenantID, id, nextVersion); err != nil {
		return RotatePaymentKeyResponse{}, err
	}
	_ = s.publishAudit(ctx, "audit.payment.key_rotated", req.TenantID, map[string]interface{}{
		"payment_key_id": id,
		"key_id":         key.KeyID,
		"reason":         defaultString(req.Reason, "manual"),
		"version_id":     verID,
	})
	return RotatePaymentKeyResponse{
		PaymentKeyID: id,
		KeyID:        key.KeyID,
		VersionID:    verID,
	}, nil
}

func (s *Service) CreateTR31(ctx context.Context, req CreateTR31Request) (CreateTR31Response, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	if req.TenantID == "" || req.KeyID == "" {
		return CreateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key_id are required")
	}
	policy, err := s.enforceOperationPolicy(ctx, req.TenantID, "tr31.create")
	if err != nil {
		return CreateTR31Response{}, err
	}
	ctx = withPaymentPolicy(ctx, policy)
	if !policy.AllowInlineKeyMaterial && strings.TrimSpace(req.MaterialB64) != "" {
		return CreateTR31Response{}, newServiceError(http.StatusForbidden, "policy_violation", "inline key material is blocked by payment policy")
	}
	if policy.RequireKBPKForTR31 && firstString(req.KBPKKeyID, req.KBPKKeyB64, req.KEKKeyID, req.KEKKeyB64) == "" {
		return CreateTR31Response{}, newServiceError(http.StatusForbidden, "policy_violation", "kbpk/kek is required by payment policy for TR-31")
	}
	version := normalizeTR31Version(req.TR31Version)
	if strings.TrimSpace(req.TR31Version) == "" {
		version = "D"
	}
	if version == "" {
		return CreateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", "unsupported tr31_version")
	}
	if !paymentTR31VersionAllowed(policy, version) {
		return CreateTR31Response{}, newServiceError(http.StatusForbidden, "policy_violation", "tr31_version is blocked by payment policy")
	}
	raw, err := s.resolveKeyMaterial(ctx, req.TenantID, req.KeyID, req.MaterialB64)
	if err != nil {
		return CreateTR31Response{}, err
	}
	defer pkgcrypto.Zeroize(raw)
	kbpk, kbpkRef, err := s.resolveKBPKMaterial(ctx, req.TenantID, req.KBPKKeyID, req.KBPKKeyB64, req.KEKKeyID, req.KEKKeyB64, "kbpk_key_b64", "kbpk_key_id")
	if err != nil {
		return CreateTR31Response{}, err
	}
	defer pkgcrypto.Zeroize(kbpk)
	if err := s.consumeMeter(); err != nil {
		return CreateTR31Response{}, err
	}
	usage := normalizeTR31UsageCode(req.UsageCode)
	if usage == "" {
		usage = "D0"
	}
	algorithm := strings.ToUpper(defaultString(req.Algorithm, "AES"))
	algorithmCode := tr31AlgorithmCode(algorithm, len(raw))
	modeOfUse := normalizeModeOfUse(req.ModeOfUse)
	if modeOfUse == "" {
		modeOfUse = "B"
	}
	exportability := normalizeExportability(req.Exportability)
	if exportability == "" {
		exportability = "E"
	}
	versionNum := defaultTR31KeyVersion(req.KeyVersionNum)
	header, err := tr31lib.NewHeader(version, usage, algorithmCode, modeOfUse, versionNum, exportability)
	if err != nil {
		return CreateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	kb, err := tr31lib.NewKeyBlock(kbpk, header)
	if err != nil {
		return CreateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	maskedLen := len(raw)
	block, err := kb.Wrap(raw, &maskedLen)
	if err != nil {
		return CreateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	kcv, err := computePaymentKCV(raw, tr31AlgorithmNameFromCode(algorithmCode))
	if err != nil {
		return CreateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	sourceFormat := tr31FormatForVersion(version)
	_ = s.publishAudit(ctx, "audit.payment.tr31_created", req.TenantID, map[string]interface{}{
		"key_id":       req.KeyID,
		"tr31_version": version,
		"usage_code":   usage,
		"source":       sourceFormat,
		"kbpk_key_id":  kbpkRef,
	})
	return CreateTR31Response{
		Version:      version,
		Algorithm:    tr31AlgorithmNameFromCode(algorithmCode),
		UsageCode:    usage,
		TR31Header:   header.String(),
		KeyBlock:     block,
		KCV:          kcv,
		SourceFormat: sourceFormat,
	}, nil
}

func (s *Service) ParseTR31(ctx context.Context, req ParseTR31Request) (ParseTR31Response, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyBlock = strings.TrimSpace(req.KeyBlock)
	if req.TenantID == "" || req.KeyBlock == "" {
		return ParseTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key_block are required")
	}
	policy, err := s.enforceOperationPolicy(ctx, req.TenantID, "tr31.parse")
	if err != nil {
		return ParseTR31Response{}, err
	}
	ctx = withPaymentPolicy(ctx, policy)
	if policy.RequireKBPKForTR31 && firstString(req.KBPKKeyID, req.KBPKKeyB64, req.KEKKeyID, req.KEKKeyB64) == "" {
		return ParseTR31Response{}, newServiceError(http.StatusForbidden, "policy_violation", "kbpk/kek is required by payment policy for TR-31")
	}
	kbpk, kbpkRef, err := s.resolveKBPKMaterial(ctx, req.TenantID, req.KBPKKeyID, req.KBPKKeyB64, req.KEKKeyID, req.KEKKeyB64, "kbpk_key_b64", "kbpk_key_id")
	if err != nil {
		return ParseTR31Response{Valid: false}, err
	}
	defer pkgcrypto.Zeroize(kbpk)
	header, key, err := unwrapTR31Block(req.KeyBlock, kbpk)
	if err != nil {
		return ParseTR31Response{Valid: false}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	defer pkgcrypto.Zeroize(key)
	if err := s.consumeMeter(); err != nil {
		return ParseTR31Response{}, err
	}
	version := normalizeTR31Version(header.VersionID)
	if !paymentTR31VersionAllowed(policy, version) {
		return ParseTR31Response{}, newServiceError(http.StatusForbidden, "policy_violation", "tr31_version is blocked by payment policy")
	}
	algorithm := tr31AlgorithmNameFromCode(header.Algorithm)
	usage := normalizeTR31UsageCode(header.KeyUsage)
	if usage == "" {
		usage = strings.ToUpper(strings.TrimSpace(header.KeyUsage))
	}
	kcv, err := computePaymentKCV(key, algorithm)
	if err != nil {
		return ParseTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	out := ParseTR31Response{
		Version:   version,
		Algorithm: algorithm,
		UsageCode: usage,
		KCV:       kcv,
		Valid:     true,
	}
	if req.ImportToKMS {
		if s.keycore == nil {
			return ParseTR31Response{}, newServiceError(http.StatusFailedDependency, "keycore_unavailable", "keycore client is not configured")
		}
		keyID, err := s.keycore.ImportKey(
			ctx,
			req.TenantID,
			defaultString(req.ImportName, "payment-tr31-import"),
			defaultString(algorithm, "AES-256"),
			"symmetric",
			defaultString(req.ImportPurpose, "encrypt"),
			base64.StdEncoding.EncodeToString(key),
		)
		if err != nil {
			return ParseTR31Response{}, newServiceError(http.StatusBadGateway, "keycore_import_failed", err.Error())
		}
		out.ImportedKeyID = keyID
	}
	_ = s.publishAudit(ctx, "audit.payment.tr31_parsed", req.TenantID, map[string]interface{}{
		"version":       version,
		"algorithm":     algorithm,
		"usage_code":    usage,
		"import_to_kms": req.ImportToKMS,
		"kbpk_key_id":   kbpkRef,
	})
	return out, nil
}

func (s *Service) TranslateTR31(ctx context.Context, req TranslateTR31Request) (TranslateTR31Response, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return TranslateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	policy, err := s.enforceOperationPolicy(ctx, req.TenantID, "tr31.translate")
	if err != nil {
		return TranslateTR31Response{}, err
	}
	ctx = withPaymentPolicy(ctx, policy)
	sourceFmt := normalizeTR31Format(req.SourceFormat)
	targetFmt := normalizeTR31Format(req.TargetFormat)
	if sourceFmt == "" || targetFmt == "" {
		return TranslateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", "source_format and target_format are required")
	}
	if !isTR31TranslationAllowed(sourceFmt, targetFmt) {
		return TranslateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", "translation path is not allowed")
	}

	sourceKeyID := strings.TrimSpace(req.SourceKeyID)
	sourceKBPKKeyID := firstString(req.SourceKBPKKeyID, req.KEKKeyID)
	sourceKBPKKeyB64 := firstString(req.SourceKBPKKeyB64, req.KEKKeyB64)
	targetKBPKKeyID := firstString(req.TargetKBPKKeyID, req.KEKKeyID)
	targetKBPKKeyB64 := firstString(req.TargetKBPKKeyB64, req.KEKKeyB64)
	if policy.RequireKBPKForTR31 {
		sourceNeedsKBPK := sourceFmt == TR31FormatB || sourceFmt == TR31FormatC || sourceFmt == TR31FormatD
		targetNeedsKBPK := targetFmt == TR31FormatB || targetFmt == TR31FormatC || targetFmt == TR31FormatD
		if sourceNeedsKBPK && firstString(sourceKBPKKeyID, sourceKBPKKeyB64) == "" {
			return TranslateTR31Response{}, newServiceError(http.StatusForbidden, "policy_violation", "source kbpk/kek is required by payment policy for TR-31 translation")
		}
		if targetNeedsKBPK && firstString(targetKBPKKeyID, targetKBPKKeyB64) == "" {
			return TranslateTR31Response{}, newServiceError(http.StatusForbidden, "policy_violation", "target kbpk/kek is required by payment policy for TR-31 translation")
		}
	}

	keyMaterial, sourceKCV, err := s.resolveSourceMaterial(ctx, req.TenantID, sourceKeyID, sourceFmt, req.SourceBlock, sourceKBPKKeyID, sourceKBPKKeyB64)
	if err != nil {
		_ = s.store.CreateTR31Translation(ctx, TR31Translation{
			ID:           newID("tr31tx"),
			TenantID:     req.TenantID,
			SourceKeyID:  sourceKeyID,
			SourceFormat: sourceFmt,
			TargetFormat: targetFmt,
			KEKKeyID:     firstString(targetKBPKKeyID, sourceKBPKKeyID),
			ResultBlock:  "",
			Status:       "failed",
		})
		return TranslateTR31Response{}, err
	}
	defer pkgcrypto.Zeroize(keyMaterial)
	if err := s.consumeMeter(); err != nil {
		return TranslateTR31Response{}, err
	}
	if sourceKCV == "" {
		sourceKCV, err = computePaymentKCV(keyMaterial, req.Algorithm)
		if err != nil {
			return TranslateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
	}

	versionForTarget := normalizeTR31Version(req.TR31Version)
	switch targetFmt {
	case TR31FormatB:
		versionForTarget = "B"
	case TR31FormatC:
		versionForTarget = "C"
	case TR31FormatD:
		versionForTarget = "D"
	}
	if targetFmt == TR31FormatB || targetFmt == TR31FormatC || targetFmt == TR31FormatD {
		if !paymentTR31VersionAllowed(policy, versionForTarget) {
			return TranslateTR31Response{}, newServiceError(http.StatusForbidden, "policy_violation", "target tr31_version is blocked by payment policy")
		}
	}

	algorithm := strings.ToUpper(defaultString(req.Algorithm, "AES"))
	usage := normalizeTR31UsageCode(req.UsageCode)
	if usage == "" {
		usage = "D0"
	}
	modeOfUse := normalizeModeOfUse(req.ModeOfUse)
	if modeOfUse == "" {
		modeOfUse = "B"
	}
	exportability := normalizeExportability(req.Exportability)
	if exportability == "" {
		exportability = "E"
	}
	versionNum := defaultTR31KeyVersion(req.KeyVersionNum)

	tr31KEKRef := ""
	var result string
	switch targetFmt {
	case TR31FormatVariant:
		result = "VARIANT|" + base64.StdEncoding.EncodeToString(keyMaterial) + "|" + sourceKCV
	case TR31FormatAESKWP:
		result = "AESKWP|" + base64.StdEncoding.EncodeToString(keyMaterial) + "|" + sourceKCV
	default:
		targetKBPK, targetKBPKRef, err := s.resolveKBPKMaterial(ctx, req.TenantID, targetKBPKKeyID, targetKBPKKeyB64, req.KEKKeyID, req.KEKKeyB64, "target_kbpk_key_b64", "target_kbpk_key_id")
		if err != nil {
			return TranslateTR31Response{}, err
		}
		defer pkgcrypto.Zeroize(targetKBPK)
		algorithmCode := tr31AlgorithmCode(algorithm, len(keyMaterial))
		header, err := tr31lib.NewHeader(versionForTarget, usage, algorithmCode, modeOfUse, versionNum, exportability)
		if err != nil {
			return TranslateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		kb, err := tr31lib.NewKeyBlock(targetKBPK, header)
		if err != nil {
			return TranslateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		maskedLen := len(keyMaterial)
		block, err := kb.Wrap(keyMaterial, &maskedLen)
		if err != nil {
			return TranslateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		result = block
		tr31KEKRef = targetKBPKRef
	}

	kekRef := strings.TrimSpace(req.KEKKeyID)
	if tr31KEKRef != "" {
		kekRef = tr31KEKRef
	} else if targetKBPKKeyID != "" {
		kekRef = targetKBPKKeyID
	} else if sourceKBPKKeyID != "" {
		kekRef = sourceKBPKKeyID
	}

	tx := TR31Translation{
		ID:           newID("tr31tx"),
		TenantID:     req.TenantID,
		SourceKeyID:  sourceKeyID,
		SourceFormat: sourceFmt,
		TargetFormat: targetFmt,
		KEKKeyID:     kekRef,
		ResultBlock:  result,
		Status:       "success",
	}
	if err := s.store.CreateTR31Translation(ctx, tx); err != nil {
		return TranslateTR31Response{}, err
	}
	_ = s.publishAudit(ctx, "audit.payment.tr31_translated", req.TenantID, map[string]interface{}{
		"id":            tx.ID,
		"source_format": sourceFmt,
		"target_format": targetFmt,
		"source_key_id": sourceKeyID,
	})
	return TranslateTR31Response{
		ID:           tx.ID,
		SourceFormat: sourceFmt,
		TargetFormat: targetFmt,
		ResultBlock:  result,
		Status:       tx.Status,
	}, nil
}

func (s *Service) ValidateTR31(ctx context.Context, req ValidateTR31Request) (ValidateTR31Response, error) {
	req.KeyBlock = strings.TrimSpace(req.KeyBlock)
	if strings.TrimSpace(req.TenantID) == "" || req.KeyBlock == "" {
		return ValidateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key_block are required")
	}
	tenantID := strings.TrimSpace(req.TenantID)
	policy, err := s.enforceOperationPolicy(ctx, tenantID, "tr31.validate")
	if err != nil {
		return ValidateTR31Response{}, err
	}
	ctx = withPaymentPolicy(ctx, policy)
	if policy.RequireKBPKForTR31 && firstString(req.KBPKKeyID, req.KBPKKeyB64, req.KEKKeyID, req.KEKKeyB64) == "" {
		return ValidateTR31Response{}, newServiceError(http.StatusForbidden, "policy_violation", "kbpk/kek is required by payment policy for TR-31")
	}
	kbpk, _, err := s.resolveKBPKMaterial(ctx, tenantID, req.KBPKKeyID, req.KBPKKeyB64, req.KEKKeyID, req.KEKKeyB64, "kbpk_key_b64", "kbpk_key_id")
	if err != nil {
		return ValidateTR31Response{}, err
	}
	defer pkgcrypto.Zeroize(kbpk)
	header, key, err := unwrapTR31Block(req.KeyBlock, kbpk)
	if err != nil {
		return ValidateTR31Response{
			Valid:  false,
			Reason: err.Error(),
		}, nil
	}
	defer pkgcrypto.Zeroize(key)
	version := normalizeTR31Version(header.VersionID)
	if !paymentTR31VersionAllowed(policy, version) {
		return ValidateTR31Response{}, newServiceError(http.StatusForbidden, "policy_violation", "tr31_version is blocked by payment policy")
	}
	algorithm := tr31AlgorithmNameFromCode(header.Algorithm)
	usage := normalizeTR31UsageCode(header.KeyUsage)
	if usage == "" {
		usage = strings.ToUpper(strings.TrimSpace(header.KeyUsage))
	}
	kcv, err := computePaymentKCV(key, algorithm)
	if err != nil {
		return ValidateTR31Response{}, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	return ValidateTR31Response{
		Valid:     true,
		Version:   version,
		Algorithm: algorithm,
		UsageCode: usage,
		KCV:       kcv,
		Reason:    "",
	}, nil
}

func (s *Service) SupportedTR31KeyUsages() []string {
	out := make([]string, len(supportedTR31KeyUsages))
	copy(out, supportedTR31KeyUsages)
	return out
}

func (s *Service) TranslatePIN(ctx context.Context, req TranslatePINRequest) (string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	policy, err := s.enforceOperationPolicy(ctx, req.TenantID, "pin.translate")
	if err != nil {
		return "", err
	}
	ctx = withPaymentPolicy(ctx, policy)
	source := normalizePINFormat(req.SourceFormat)
	target := normalizePINFormat(req.TargetFormat)
	block := strings.ToUpper(strings.TrimSpace(req.PINBlock))
	if source == "" || target == "" {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "source_format and target_format are required")
	}
	if !isPINFormatAllowed(policy, source) || !isPINFormatAllowed(policy, target) {
		return "", newServiceError(http.StatusForbidden, "policy_violation", "pin block format is blocked by payment policy")
	}
	if err := validatePANPolicy(policy, req.PAN); err != nil {
		return "", err
	}
	if len(block) != 16 || !isHex(block) {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "pin_block must be 16 hex chars")
	}
	if source == target {
		return block, nil
	}
	if source == "ISO-4" || target == "ISO-4" {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "ISO-4 translation is not supported in this build")
	}
	sourceZPK := firstString(req.SourceZPKKeyID, req.ZPKKeyID)
	targetZPK := firstString(req.TargetZPKKeyID, req.ZPKKeyID, sourceZPK)
	sourceZPKB64 := firstString(req.SourceZPKKeyB64, req.ZPKKeyB64)
	targetZPKB64 := firstString(req.TargetZPKKeyB64, req.ZPKKeyB64, sourceZPKB64)
	if (sourceZPK == "" && sourceZPKB64 == "") || (targetZPK == "" && targetZPKB64 == "") {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "provide source/target ZPK via key_id or key_b64")
	}
	sourceKeyRaw, err := s.resolveOperationKeyMaterial(ctx, req.TenantID, sourceZPK, sourceZPKB64, "source_zpk_key_b64", "source_zpk_key_id")
	if err != nil {
		return "", err
	}
	defer pkgcrypto.Zeroize(sourceKeyRaw)
	targetKeyRaw, err := s.resolveOperationKeyMaterial(ctx, req.TenantID, targetZPK, targetZPKB64, "target_zpk_key_b64", "target_zpk_key_id")
	if err != nil {
		return "", err
	}
	defer pkgcrypto.Zeroize(targetKeyRaw)
	sourceKey, err := normalizeTDESKey(sourceKeyRaw)
	if err != nil {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "invalid source zpk key length")
	}
	defer pkgcrypto.Zeroize(sourceKey)
	targetKey, err := normalizeTDESKey(targetKeyRaw)
	if err != nil {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "invalid target zpk key length")
	}
	defer pkgcrypto.Zeroize(targetKey)
	if err := s.consumeMeter(); err != nil {
		return "", err
	}
	blockRaw, err := hex.DecodeString(block)
	if err != nil {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "pin_block must be valid hex")
	}
	clear, err := tdesECBDecrypt(sourceKey, blockRaw)
	if err != nil {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "failed to decrypt source pin block")
	}
	defer pkgcrypto.Zeroize(clear)
	pin, err := decodePINFromClearBlock(source, clear, req.PAN)
	if err != nil {
		return "", newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	targetClear, err := buildPINClearBlock(target, pin, req.PAN)
	if err != nil {
		return "", newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	defer pkgcrypto.Zeroize(targetClear)
	targetBlock, err := tdesECBEncrypt(targetKey, targetClear)
	if err != nil {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "failed to encrypt target pin block")
	}
	block = strings.ToUpper(hex.EncodeToString(targetBlock))
	_ = s.store.CreatePINOperationLog(ctx, PINOperationLog{
		ID:           newID("pinlog"),
		TenantID:     req.TenantID,
		Operation:    "translate",
		SourceFormat: source,
		TargetFormat: target,
		ZPKKeyID:     sourceZPK + "->" + targetZPK,
		Result:       "success",
	})
	_ = s.publishAudit(ctx, "audit.payment.pin_translated", req.TenantID, map[string]interface{}{
		"source_format": source,
		"target_format": target,
		"source_zpk":    sourceZPK,
		"target_zpk":    targetZPK,
	})
	return block, nil
}

func (s *Service) GeneratePVV(ctx context.Context, req PVVGenerateRequest) (string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	policy, err := s.enforceOperationPolicy(ctx, req.TenantID, "pin.pvv.generate")
	if err != nil {
		return "", err
	}
	ctx = withPaymentPolicy(ctx, policy)
	if err := validatePANPolicy(policy, req.PAN); err != nil {
		return "", err
	}
	key, err := s.resolveOperationKeyMaterial(ctx, req.TenantID, req.PVKKeyID, req.PVKKeyB64, "pvk_key_b64", "pvk_key_id")
	if err != nil {
		return "", err
	}
	defer pkgcrypto.Zeroize(key)
	if err := s.consumeMeter(); err != nil {
		return "", err
	}
	pvv, err := generatePVV(key, req.PIN, req.PAN, req.PVKI, policy.DecimalizationTable)
	if err != nil {
		return "", newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	_ = s.store.CreatePINOperationLog(ctx, PINOperationLog{
		ID:           newID("pinlog"),
		TenantID:     req.TenantID,
		Operation:    "generate_pvv",
		SourceFormat: normalizePINFormat(req.SourceFmt),
		TargetFormat: "",
		ZPKKeyID:     strings.TrimSpace(req.ZPKKeyID),
		Result:       "success",
	})
	_ = s.publishAudit(ctx, "audit.payment.pvv_generated", req.TenantID, map[string]interface{}{
		"source_format": normalizePINFormat(req.SourceFmt),
		"zpk_key_id":    strings.TrimSpace(req.ZPKKeyID),
	})
	return pvv, nil
}

func (s *Service) VerifyPVV(ctx context.Context, req PVVVerifyRequest) (bool, error) {
	policy, err := s.enforceOperationPolicy(ctx, strings.TrimSpace(req.TenantID), "pin.pvv.verify")
	if err != nil {
		return false, err
	}
	ctx = withPaymentPolicy(ctx, policy)
	pvv, err := s.GeneratePVV(ctx, PVVGenerateRequest{
		TenantID:  req.TenantID,
		PVKKeyID:  req.PVKKeyID,
		PVKKeyB64: req.PVKKeyB64,
		PIN:       req.PIN,
		PAN:       req.PAN,
		PVKI:      req.PVKI,
		ZPKKeyID:  req.ZPKKeyID,
	})
	if err != nil {
		return false, err
	}
	ok := subtle.ConstantTimeCompare([]byte(pvv), []byte(strings.TrimSpace(req.PVV))) == 1
	_ = s.store.CreatePINOperationLog(ctx, PINOperationLog{
		ID:           newID("pinlog"),
		TenantID:     strings.TrimSpace(req.TenantID),
		Operation:    "verify_pvv",
		SourceFormat: "",
		TargetFormat: "",
		ZPKKeyID:     strings.TrimSpace(req.ZPKKeyID),
		Result:       boolStatus(ok),
	})
	_ = s.publishAudit(ctx, "audit.payment.pvv_verified", strings.TrimSpace(req.TenantID), map[string]interface{}{
		"verified":   ok,
		"zpk_key_id": strings.TrimSpace(req.ZPKKeyID),
	})
	return ok, nil
}

func (s *Service) GenerateOffset(ctx context.Context, req OffsetGenerateRequest) (string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	policy, err := s.enforceOperationPolicy(ctx, req.TenantID, "pin.offset.generate")
	if err != nil {
		return "", err
	}
	ctx = withPaymentPolicy(ctx, policy)
	offset, err := generatePINOffset(req.PIN, req.ReferencePIN)
	if err != nil {
		return "", newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	_ = s.store.CreatePINOperationLog(ctx, PINOperationLog{
		ID:           newID("pinlog"),
		TenantID:     req.TenantID,
		Operation:    "generate_offset",
		SourceFormat: "",
		TargetFormat: "",
		ZPKKeyID:     strings.TrimSpace(req.ZPKKeyID),
		Result:       "success",
	})
	_ = s.publishAudit(ctx, "audit.payment.pin_offset_generated", req.TenantID, map[string]interface{}{
		"zpk_key_id": strings.TrimSpace(req.ZPKKeyID),
	})
	return offset, nil
}

func (s *Service) VerifyOffset(ctx context.Context, req OffsetVerifyRequest) (bool, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return false, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	policy, err := s.enforceOperationPolicy(ctx, req.TenantID, "pin.offset.verify")
	if err != nil {
		return false, err
	}
	ctx = withPaymentPolicy(ctx, policy)
	ok := verifyPINOffset(req.PIN, req.ReferencePIN, req.Offset)
	_ = s.store.CreatePINOperationLog(ctx, PINOperationLog{
		ID:           newID("pinlog"),
		TenantID:     req.TenantID,
		Operation:    "verify_offset",
		SourceFormat: "",
		TargetFormat: "",
		ZPKKeyID:     strings.TrimSpace(req.ZPKKeyID),
		Result:       boolStatus(ok),
	})
	_ = s.publishAudit(ctx, "audit.payment.pin_offset_verified", req.TenantID, map[string]interface{}{
		"verified":   ok,
		"zpk_key_id": strings.TrimSpace(req.ZPKKeyID),
	})
	return ok, nil
}

func (s *Service) ComputeCVV(ctx context.Context, req CVVComputeRequest) (string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	policy, err := s.enforceOperationPolicy(ctx, req.TenantID, "pin.cvv.compute")
	if err != nil {
		return "", err
	}
	ctx = withPaymentPolicy(ctx, policy)
	if err := validatePANPolicy(policy, req.PAN); err != nil {
		return "", err
	}
	cvk, err := s.resolveOperationKeyMaterial(ctx, req.TenantID, req.CVKKeyID, req.CVKKeyB64, "cvk_key_b64", "cvk_key_id")
	if err != nil {
		return "", err
	}
	defer pkgcrypto.Zeroize(cvk)
	if err := s.consumeMeter(); err != nil {
		return "", err
	}
	cvv, err := computeCVVWithTDES(cvk, strings.TrimSpace(req.PAN), strings.TrimSpace(req.ExpiryYYMM), strings.TrimSpace(req.ServiceCode))
	if err != nil {
		return "", newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	_ = s.store.CreatePINOperationLog(ctx, PINOperationLog{
		ID:           newID("pinlog"),
		TenantID:     req.TenantID,
		Operation:    "compute_cvv",
		SourceFormat: "",
		TargetFormat: "",
		ZPKKeyID:     "",
		Result:       "success",
	})
	_ = s.publishAudit(ctx, "audit.payment.cvv_computed", req.TenantID, map[string]interface{}{
		"service_code": strings.TrimSpace(req.ServiceCode),
	})
	return cvv, nil
}

func (s *Service) VerifyCVV(ctx context.Context, req CVVVerifyRequest) (bool, error) {
	policy, err := s.enforceOperationPolicy(ctx, strings.TrimSpace(req.TenantID), "pin.cvv.verify")
	if err != nil {
		return false, err
	}
	ctx = withPaymentPolicy(ctx, policy)
	cvv, err := s.ComputeCVV(ctx, CVVComputeRequest{
		TenantID:    req.TenantID,
		CVKKeyID:    req.CVKKeyID,
		CVKKeyB64:   req.CVKKeyB64,
		PAN:         req.PAN,
		ExpiryYYMM:  req.ExpiryYYMM,
		ServiceCode: req.ServiceCode,
	})
	if err != nil {
		return false, err
	}
	ok := subtle.ConstantTimeCompare([]byte(cvv), []byte(strings.TrimSpace(req.CVV))) == 1
	_ = s.publishAudit(ctx, "audit.payment.cvv_verified", strings.TrimSpace(req.TenantID), map[string]interface{}{
		"verified": ok,
	})
	return ok, nil
}

func (s *Service) ComputeMAC(ctx context.Context, req MACRequest) (string, error) {
	op := "mac.retail"
	switch normalizeMACType(req.Type) {
	case "iso9797":
		op = "mac.iso9797"
	case "cmac":
		op = "mac.cmac"
	}
	policy, err := s.enforceOperationPolicy(ctx, strings.TrimSpace(req.TenantID), op)
	if err != nil {
		return "", err
	}
	ctx = withPaymentPolicy(ctx, policy)
	key, err := s.resolveOperationKeyMaterial(ctx, strings.TrimSpace(req.TenantID), req.KeyID, req.KeyB64, "key_b64", "key_id")
	if err != nil {
		return "", err
	}
	defer pkgcrypto.Zeroize(key)
	data, err := decodeB64(req.DataB64, "data_b64")
	if err != nil {
		return "", err
	}
	defer pkgcrypto.Zeroize(data)
	switch normalizeMACType(req.Type) {
	case "retail":
		if len(key) < 16 {
			return "", newServiceError(http.StatusBadRequest, "bad_request", "retail MAC key must be at least 16 bytes")
		}
		mac, err := pkgpayment.RetailMACANSI919(key[:16], data)
		if err != nil {
			return "", newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		return base64.StdEncoding.EncodeToString(mac), nil
	case "iso9797":
		switch req.Algorithm {
		case 0, 1:
			mac, err := iso9797Alg1MAC(key, data)
			if err != nil {
				return "", newServiceError(http.StatusBadRequest, "bad_request", err.Error())
			}
			return base64.StdEncoding.EncodeToString(mac), nil
		case 3:
			if len(key) < 16 {
				return "", newServiceError(http.StatusBadRequest, "bad_request", "iso9797 alg3 key must be at least 16 bytes")
			}
			mac, err := pkgpayment.RetailMACANSI919(key[:16], data)
			if err != nil {
				return "", newServiceError(http.StatusBadRequest, "bad_request", err.Error())
			}
			return base64.StdEncoding.EncodeToString(mac), nil
		default:
			return "", newServiceError(http.StatusBadRequest, "bad_request", "unsupported iso9797 algorithm (use 1 or 3)")
		}
	case "cmac":
		mac, err := aesCMAC(key, data)
		if err != nil {
			return "", newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		return base64.StdEncoding.EncodeToString(mac), nil
	default:
		return "", newServiceError(http.StatusBadRequest, "bad_request", "unsupported mac type")
	}
}

func (s *Service) VerifyMAC(ctx context.Context, req VerifyMACRequest) (bool, error) {
	policy, err := s.enforceOperationPolicy(ctx, strings.TrimSpace(req.TenantID), "mac.verify")
	if err != nil {
		return false, err
	}
	ctx = withPaymentPolicy(ctx, policy)
	expectedB64, err := s.ComputeMAC(ctx, MACRequest{
		TenantID:  req.TenantID,
		KeyID:     req.KeyID,
		KeyB64:    req.KeyB64,
		DataB64:   req.DataB64,
		Algorithm: req.Algorithm,
		Type:      req.Type,
	})
	if err != nil {
		return false, err
	}
	expected, err := base64.StdEncoding.DecodeString(expectedB64)
	if err != nil {
		return false, err
	}
	got, err := decodeB64(req.MACB64, "mac_b64")
	if err != nil {
		return false, err
	}
	defer pkgcrypto.Zeroize(got)
	ok := subtle.ConstantTimeCompare(expected, got) == 1
	return ok, nil
}

func (s *Service) ISO20022Sign(ctx context.Context, req ISO20022SignRequest) (map[string]string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	xml := normalizeISOXML(req.XML)
	if req.TenantID == "" || req.KeyID == "" || xml == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, key_id and xml are required")
	}
	policy, err := s.enforceOperationPolicy(ctx, req.TenantID, "iso20022.sign")
	if err != nil {
		return nil, err
	}
	ctx = withPaymentPolicy(ctx, policy)
	if policy.MaxISO20022PayloadBytes > 0 && len([]byte(xml)) > policy.MaxISO20022PayloadBytes {
		return nil, newServiceError(http.StatusRequestEntityTooLarge, "payload_too_large", "xml exceeds payment policy max_iso20022_payload_bytes")
	}
	if s.keycore == nil {
		return nil, newServiceError(http.StatusFailedDependency, "keycore_unavailable", "keycore client is not configured")
	}
	if err := s.consumeMeter(); err != nil {
		return nil, err
	}
	dataB64 := base64.StdEncoding.EncodeToString([]byte(xml))
	out, err := s.keycore.Sign(ctx, req.TenantID, req.KeyID, dataB64)
	if err != nil {
		return nil, newServiceError(http.StatusBadGateway, "keycore_sign_failed", err.Error())
	}
	sig := firstString(out["signature"], out["signature_b64"])
	if sig == "" {
		return nil, newServiceError(http.StatusBadGateway, "keycore_sign_failed", "signature missing in keycore response")
	}
	signedXML := xml + "\n<SignatureValue>" + sig + "</SignatureValue>"
	_ = s.publishAudit(ctx, "audit.payment.iso20022_signed", req.TenantID, map[string]interface{}{
		"key_id": req.KeyID,
	})
	return map[string]string{
		"signature_b64": sig,
		"signed_xml":    signedXML,
	}, nil
}

func (s *Service) ISO20022Verify(ctx context.Context, req ISO20022VerifyRequest) (bool, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	xml := normalizeISOXML(req.XML)
	sig := strings.TrimSpace(req.SignatureB64)
	if req.TenantID == "" || req.KeyID == "" || xml == "" || sig == "" {
		return false, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, key_id, xml and signature_b64 are required")
	}
	policy, err := s.enforceOperationPolicy(ctx, req.TenantID, "iso20022.verify")
	if err != nil {
		return false, err
	}
	ctx = withPaymentPolicy(ctx, policy)
	if policy.MaxISO20022PayloadBytes > 0 && len([]byte(xml)) > policy.MaxISO20022PayloadBytes {
		return false, newServiceError(http.StatusRequestEntityTooLarge, "payload_too_large", "xml exceeds payment policy max_iso20022_payload_bytes")
	}
	if s.keycore == nil {
		return false, newServiceError(http.StatusFailedDependency, "keycore_unavailable", "keycore client is not configured")
	}
	dataB64 := base64.StdEncoding.EncodeToString([]byte(xml))
	out, err := s.keycore.Verify(ctx, req.TenantID, req.KeyID, dataB64, sig)
	if err != nil {
		return false, newServiceError(http.StatusBadGateway, "keycore_verify_failed", err.Error())
	}
	return boolValue(out["verified"]), nil
}

func (s *Service) ISO20022Encrypt(ctx context.Context, req ISO20022EncryptRequest) (map[string]string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	xml := normalizeISOXML(req.XML)
	if req.TenantID == "" || req.KeyID == "" || xml == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, key_id and xml are required")
	}
	policy, err := s.enforceOperationPolicy(ctx, req.TenantID, "iso20022.encrypt")
	if err != nil {
		return nil, err
	}
	ctx = withPaymentPolicy(ctx, policy)
	if policy.MaxISO20022PayloadBytes > 0 && len([]byte(xml)) > policy.MaxISO20022PayloadBytes {
		return nil, newServiceError(http.StatusRequestEntityTooLarge, "payload_too_large", "xml exceeds payment policy max_iso20022_payload_bytes")
	}
	if s.keycore == nil {
		return nil, newServiceError(http.StatusFailedDependency, "keycore_unavailable", "keycore client is not configured")
	}
	if err := s.consumeMeter(); err != nil {
		return nil, err
	}
	out, err := s.keycore.Encrypt(ctx, req.TenantID, req.KeyID, base64.StdEncoding.EncodeToString([]byte(xml)), strings.TrimSpace(req.IVB64), strings.TrimSpace(req.ReferenceID))
	if err != nil {
		return nil, newServiceError(http.StatusBadGateway, "keycore_encrypt_failed", err.Error())
	}
	ciphertext := firstString(out["ciphertext"], out["ciphertext_b64"])
	iv := firstString(out["iv"])
	if ciphertext == "" {
		return nil, newServiceError(http.StatusBadGateway, "keycore_encrypt_failed", "ciphertext missing in keycore response")
	}
	_ = s.publishAudit(ctx, "audit.payment.iso20022_encrypted", req.TenantID, map[string]interface{}{
		"key_id": req.KeyID,
	})
	return map[string]string{
		"ciphertext": ciphertext,
		"iv":         iv,
	}, nil
}

func (s *Service) ISO20022Decrypt(ctx context.Context, req ISO20022DecryptRequest) (string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	if req.TenantID == "" || req.KeyID == "" || strings.TrimSpace(req.CiphertextB64) == "" {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, key_id and ciphertext are required")
	}
	policy, err := s.enforceOperationPolicy(ctx, req.TenantID, "iso20022.decrypt")
	if err != nil {
		return "", err
	}
	ctx = withPaymentPolicy(ctx, policy)
	if s.keycore == nil {
		return "", newServiceError(http.StatusFailedDependency, "keycore_unavailable", "keycore client is not configured")
	}
	out, err := s.keycore.Decrypt(ctx, req.TenantID, req.KeyID, strings.TrimSpace(req.CiphertextB64), strings.TrimSpace(req.IVB64))
	if err != nil {
		return "", newServiceError(http.StatusBadGateway, "keycore_decrypt_failed", err.Error())
	}
	plainB64 := firstString(out["plaintext"], out["plaintext_b64"])
	if plainB64 == "" {
		return "", newServiceError(http.StatusBadGateway, "keycore_decrypt_failed", "plaintext missing in keycore response")
	}
	raw, err := base64.StdEncoding.DecodeString(plainB64)
	if err != nil {
		return "", newServiceError(http.StatusBadGateway, "keycore_decrypt_failed", "invalid base64 plaintext from keycore")
	}
	defer pkgcrypto.Zeroize(raw)
	return string(raw), nil
}

func (s *Service) GenerateLAU(ctx context.Context, req LAUGenerateRequest) (string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" || strings.TrimSpace(req.Message) == "" {
		return "", newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and message are required")
	}
	policy, err := s.enforceOperationPolicy(ctx, req.TenantID, "iso20022.lau.generate")
	if err != nil {
		return "", err
	}
	ctx = withPaymentPolicy(ctx, policy)
	if policy.RequireISO20022LAUContext && strings.TrimSpace(req.Context) == "" {
		return "", newServiceError(http.StatusForbidden, "policy_violation", "context is required by payment policy for LAU")
	}
	if policy.MaxISO20022PayloadBytes > 0 && len([]byte(req.Message)) > policy.MaxISO20022PayloadBytes {
		return "", newServiceError(http.StatusRequestEntityTooLarge, "payload_too_large", "message exceeds payment policy max_iso20022_payload_bytes")
	}
	key, err := s.resolveOperationKeyMaterial(ctx, req.TenantID, req.KeyID, req.LAUKeyB64, "lau_key_b64", "key_id")
	if err != nil {
		return "", err
	}
	defer pkgcrypto.Zeroize(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(strings.TrimSpace(req.Context)))
	_, _ = mac.Write([]byte{0x1F})
	_, _ = mac.Write([]byte(req.Message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Service) VerifyLAU(ctx context.Context, req LAUVerifyRequest) (bool, error) {
	policy, err := s.enforceOperationPolicy(ctx, strings.TrimSpace(req.TenantID), "iso20022.lau.verify")
	if err != nil {
		return false, err
	}
	ctx = withPaymentPolicy(ctx, policy)
	if policy.RequireISO20022LAUContext && strings.TrimSpace(req.Context) == "" {
		return false, newServiceError(http.StatusForbidden, "policy_violation", "context is required by payment policy for LAU")
	}
	got, err := s.GenerateLAU(ctx, LAUGenerateRequest{
		TenantID:  req.TenantID,
		KeyID:     req.KeyID,
		LAUKeyB64: req.LAUKeyB64,
		Message:   req.Message,
		Context:   req.Context,
	})
	if err != nil {
		return false, err
	}
	expected, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.LAUB64))
	if err != nil {
		return false, newServiceError(http.StatusBadRequest, "bad_request", "lau_b64 must be base64")
	}
	defer pkgcrypto.Zeroize(expected)
	gotRaw, _ := base64.StdEncoding.DecodeString(got)
	ok := subtle.ConstantTimeCompare(gotRaw, expected) == 1
	return ok, nil
}

func (s *Service) resolveKeyMaterial(ctx context.Context, tenantID string, keyID string, materialB64 string) ([]byte, error) {
	if strings.TrimSpace(materialB64) != "" {
		raw, err := decodeB64(materialB64, "material_b64")
		if err != nil {
			return nil, err
		}
		return raw, nil
	}
	if s.keycore == nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "material_b64 is required when keycore export is unavailable")
	}
	out, err := s.keycore.ExportKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, newServiceError(http.StatusBadGateway, "keycore_export_failed", err.Error())
	}
	matB64 := firstString(out["material"], out["material_b64"], out["plaintext"], out["key"])
	if strings.TrimSpace(matB64) == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "material_b64 is required; keycore export did not provide raw material")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(matB64))
	if err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "material_b64 must be base64")
	}
	return raw, nil
}

func (s *Service) resolveOperationKeyMaterial(ctx context.Context, tenantID string, keyID string, materialB64 string, materialField string, keyField string) ([]byte, error) {
	tenantID = strings.TrimSpace(tenantID)
	keyID = strings.TrimSpace(keyID)
	materialB64 = strings.TrimSpace(materialB64)
	policy, err := s.policyFromContextOrStore(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if err := enforceInlineKeyMaterialPolicy(policy, keyID, materialB64, materialField, keyField); err != nil {
		return nil, err
	}
	if materialB64 != "" {
		return decodeB64(materialB64, materialField)
	}
	if keyID == "" {
		if materialField == "" {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", "key material is required")
		}
		if keyField == "" {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", materialField+" is required")
		}
		return nil, newServiceError(http.StatusBadRequest, "bad_request", materialField+" or "+keyField+" is required")
	}
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	return s.resolveKeyMaterial(ctx, tenantID, keyID, "")
}

func (s *Service) resolveKBPKMaterial(ctx context.Context, tenantID string, kbpkKeyID string, kbpkKeyB64 string, kekKeyID string, kekKeyB64 string, materialField string, keyField string) ([]byte, string, error) {
	selectedID := strings.TrimSpace(firstString(kbpkKeyID, kekKeyID))
	selectedB64 := strings.TrimSpace(firstString(kbpkKeyB64, kekKeyB64))
	raw, err := s.resolveOperationKeyMaterial(ctx, tenantID, selectedID, selectedB64, materialField, keyField)
	if err != nil {
		return nil, "", err
	}
	return raw, selectedID, nil
}

func tr31AlgorithmCode(algorithm string, keyLen int) string {
	algo := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(algo, "AES"):
		return tr31lib.ENC_ALGORITHM_AES
	case strings.Contains(algo, "TDES"), strings.Contains(algo, "3DES"), strings.Contains(algo, "TRIPLE"):
		return tr31lib.ENC_ALGORITHM_TRIPLE_DES
	case algo == "DES" || strings.Contains(algo, "SINGLE"):
		return tr31lib.ENC_ALGORITHM_DES
	}
	switch keyLen {
	case 8:
		return tr31lib.ENC_ALGORITHM_DES
	case 16, 24:
		return tr31lib.ENC_ALGORITHM_TRIPLE_DES
	case 32:
		return tr31lib.ENC_ALGORITHM_AES
	default:
		return tr31lib.ENC_ALGORITHM_AES
	}
}

func tr31AlgorithmNameFromCode(code string) string {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case tr31lib.ENC_ALGORITHM_DES:
		return "DES"
	case tr31lib.ENC_ALGORITHM_TRIPLE_DES:
		return "TDES"
	case tr31lib.ENC_ALGORITHM_AES:
		return "AES"
	default:
		return strings.ToUpper(strings.TrimSpace(code))
	}
}

func tr31FormatForVersion(version string) string {
	switch normalizeTR31Version(version) {
	case "B":
		return TR31FormatB
	case "C":
		return TR31FormatC
	case "D":
		return TR31FormatD
	default:
		return TR31FormatVariant
	}
}

func unwrapTR31Block(keyBlock string, kbpk []byte) (*tr31lib.Header, []byte, error) {
	kb, err := tr31lib.NewKeyBlock(kbpk, nil)
	if err != nil {
		return nil, nil, err
	}
	key, err := kb.Unwrap(strings.TrimSpace(keyBlock))
	if err != nil {
		return nil, nil, err
	}
	header := kb.GetHeader()
	if header == nil {
		pkgcrypto.Zeroize(key)
		return nil, nil, errors.New("missing tr31 header")
	}
	return header, key, nil
}

func (s *Service) resolveSourceMaterial(ctx context.Context, tenantID string, keyID string, sourceFormat string, sourceBlock string, sourceKBPKKeyID string, sourceKBPKKeyB64 string) ([]byte, string, error) {
	sourceBlock = strings.TrimSpace(sourceBlock)
	if sourceBlock != "" {
		switch sourceFormat {
		case TR31FormatB, TR31FormatC, TR31FormatD:
			kbpk, _, err := s.resolveKBPKMaterial(ctx, tenantID, sourceKBPKKeyID, sourceKBPKKeyB64, "", "", "source_kbpk_key_b64", "source_kbpk_key_id")
			if err != nil {
				return nil, "", err
			}
			defer pkgcrypto.Zeroize(kbpk)
			header, key, err := unwrapTR31Block(sourceBlock, kbpk)
			if err != nil {
				return nil, "", err
			}
			algorithm := tr31AlgorithmNameFromCode(header.Algorithm)
			kcv, err := computePaymentKCV(key, algorithm)
			if err != nil {
				pkgcrypto.Zeroize(key)
				return nil, "", newServiceError(http.StatusBadRequest, "bad_request", err.Error())
			}
			return key, kcv, nil
		case TR31FormatVariant:
			return parseWrapperBlock(sourceBlock, "VARIANT")
		case TR31FormatAESKWP:
			return parseWrapperBlock(sourceBlock, "AESKWP")
		default:
			return nil, "", newServiceError(http.StatusBadRequest, "bad_request", "unsupported source format")
		}
	}
	if strings.TrimSpace(keyID) == "" {
		return nil, "", newServiceError(http.StatusBadRequest, "bad_request", "source_block or source_key_id is required")
	}
	raw, err := s.resolveKeyMaterial(ctx, tenantID, keyID, "")
	if err != nil {
		return nil, "", err
	}
	kcv, err := computePaymentKCV(raw, "")
	if err != nil {
		return nil, "", newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	return raw, kcv, nil
}

func parseWrapperBlock(raw string, expectedPrefix string) ([]byte, string, error) {
	parts := strings.Split(raw, "|")
	if len(parts) == 1 {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, "", newServiceError(http.StatusBadRequest, "bad_request", "invalid key block payload")
		}
		kcv, err := computePaymentKCV(key, "")
		if err != nil {
			return nil, "", newServiceError(http.StatusBadRequest, "bad_request", err.Error())
		}
		return key, kcv, nil
	}
	if len(parts) != 3 {
		return nil, "", newServiceError(http.StatusBadRequest, "bad_request", "invalid key block payload")
	}
	if !strings.EqualFold(strings.TrimSpace(parts[0]), expectedPrefix) {
		return nil, "", newServiceError(http.StatusBadRequest, "bad_request", "invalid wrapper block prefix")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, "", newServiceError(http.StatusBadRequest, "bad_request", "invalid wrapped key payload")
	}
	kcv := strings.ToUpper(strings.TrimSpace(parts[2]))
	return key, kcv, nil
}

func parseTR31Wire(raw string) (string, string, string, []byte, string, error) {
	parts := strings.Split(strings.TrimSpace(raw), "|")
	if len(parts) != 5 {
		return "", "", "", nil, "", errors.New("invalid TR-31 payload")
	}
	version := normalizeTR31Version(parts[0])
	if version == "" {
		return "", "", "", nil, "", errors.New("unsupported TR-31 version")
	}
	algorithm := strings.ToUpper(strings.TrimSpace(parts[1]))
	usage := normalizeTR31UsageCode(parts[2])
	if usage == "" {
		return "", "", "", nil, "", errors.New("invalid usage code")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[3]))
	if err != nil {
		return "", "", "", nil, "", errors.New("invalid TR-31 key payload")
	}
	kcv := strings.ToUpper(strings.TrimSpace(parts[4]))
	if !isHex(kcv) || len(kcv) < 6 {
		pkgcrypto.Zeroize(key)
		return "", "", "", nil, "", errors.New("invalid TR-31 kcv")
	}
	return version, algorithm, usage, key, kcv, nil
}

func isTR31TranslationAllowed(source string, target string) bool {
	if source == target {
		return true
	}
	switch source {
	case TR31FormatVariant:
		return target == TR31FormatB || target == TR31FormatC || target == TR31FormatD || target == TR31FormatAESKWP
	case TR31FormatB:
		return target == TR31FormatVariant || target == TR31FormatC || target == TR31FormatD || target == TR31FormatAESKWP
	case TR31FormatC:
		return target == TR31FormatVariant || target == TR31FormatB || target == TR31FormatD || target == TR31FormatAESKWP
	case TR31FormatD:
		return target == TR31FormatAESKWP
	case TR31FormatAESKWP:
		return target == TR31FormatD
	default:
		return false
	}
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "payment",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}

func (s *Service) consumeMeter() error {
	if s.meter == nil {
		return nil
	}
	if !s.meter.IncrementOps() {
		return newServiceError(http.StatusTooManyRequests, "rate_limited", "operation limit reached")
	}
	return nil
}

func normalizeTR31UsageCode(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if len(v) != 2 {
		return ""
	}
	if !isHexAlphaNum(v) {
		return ""
	}
	return v
}

func normalizeMACType(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "retail", "ansi-x9.19", "x9.19", "ansi919", "ansi_919":
		return "retail"
	case "iso9797", "iso-9797":
		return "iso9797"
	case "cmac", "aes-cmac":
		return "cmac"
	default:
		return ""
	}
}

func isHex(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func isHexAlphaNum(value string) bool {
	for _, c := range value {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		default:
			return false
		}
	}
	return true
}

func parseStringListJSON(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func pinFormatNibble(format string) string {
	switch format {
	case "ISO-0":
		return "0"
	case "ISO-1":
		return "1"
	case "ISO-3":
		return "3"
	case "ISO-4":
		return "4"
	default:
		return "0"
	}
}

func defaultTR31KeyVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) != 2 {
		return "00"
	}
	if _, err := strconv.Atoi(v); err != nil {
		return "00"
	}
	return v
}

func incrementTR31KeyVersion(v string) string {
	n, err := strconv.Atoi(defaultTR31KeyVersion(v))
	if err != nil {
		return "00"
	}
	n = (n + 1) % 100
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func boolStatus(ok bool) string {
	if ok {
		return "success"
	}
	return "failed"
}
