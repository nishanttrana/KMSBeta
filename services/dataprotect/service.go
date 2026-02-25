package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

type Service struct {
	store   Store
	keycore KeyCoreClient
	events  EventPublisher
	now     func() time.Time
}

var supportedDataProtectAlgorithms = []string{"AES-GCM", "AES-SIV", "CHACHA20-POLY1305"}

func defaultDataAlgorithmProfilePolicy() map[string][]string {
	return map[string][]string{
		"field_level": []string{"AES-GCM", "AES-SIV", "CHACHA20-POLY1305"},
		"envelope":    []string{"AES-GCM", "AES-SIV", "CHACHA20-POLY1305"},
		"searchable":  []string{"AES-SIV"},
	}
}

func defaultTokenizationModePolicy() map[string][]string {
	return map[string][]string{
		"credit_card": []string{"vault", "vaultless"},
		"ssn":         []string{"vault", "vaultless"},
		"iban":        []string{"vault", "vaultless"},
		"email":       []string{"vault", "vaultless"},
		"phone":       []string{"vault", "vaultless"},
		"custom":      []string{"vault", "vaultless"},
		"bitlocker":   []string{"vault"},
	}
}

func defaultTokenFormatPolicy() map[string][]string {
	return map[string][]string{
		"credit_card": []string{"format_preserving", "deterministic", "irreversible", "random"},
		"ssn":         []string{"format_preserving", "deterministic", "irreversible", "random"},
		"iban":        []string{"format_preserving", "deterministic", "irreversible", "random"},
		"email":       []string{"format_preserving", "deterministic", "irreversible", "random"},
		"phone":       []string{"format_preserving", "deterministic", "irreversible", "random"},
		"custom":      []string{"format_preserving", "deterministic", "irreversible", "random"},
		"bitlocker":   []string{"deterministic", "irreversible", "random"},
	}
}

func defaultMaskingRolePolicy() map[string]string {
	return map[string]string{
		"admin":   "none",
		"auditor": "hash",
		"analyst": "partial_last4",
		"support": "partial_last4",
	}
}

func NewService(store Store, keycore KeyCoreClient, events EventPublisher) *Service {
	return &Service{
		store:   store,
		keycore: keycore,
		events:  events,
		now:     func() time.Time { return time.Now().UTC() },
	}
}

func defaultDataProtectionPolicy(tenantID string) DataProtectionPolicy {
	return DataProtectionPolicy{
		TenantID:                       strings.TrimSpace(tenantID),
		AllowedDataAlgorithms:          append([]string{}, supportedDataProtectAlgorithms...),
		AlgorithmProfilePolicy:         defaultDataAlgorithmProfilePolicy(),
		RequireAADForAEAD:              false,
		RequiredAADClaims:              []string{},
		EnforceAADTenantBinding:        false,
		AllowedAADEvironments:          []string{},
		MaxFieldsPerOperation:          64,
		MaxDocumentBytes:               262144,
		MaxAppCryptoRequestBytes:       1048576,
		MaxAppCryptoBatchSize:          256,
		RequireSymmetricKeys:           true,
		RequireFIPSKeys:                false,
		MinKeySizeBits:                 0,
		AllowedEncryptFieldPaths:       []string{},
		AllowedDecryptFieldPaths:       []string{},
		DeniedDecryptFieldPaths:        []string{},
		BlockWildcardFieldPaths:        true,
		AllowDeterministicEncryption:   true,
		AllowSearchableEncryption:      true,
		AllowRangeSearch:               false,
		EnvelopeKEKAllowlist:           []string{},
		MaxWrappedDEKAgeMinutes:        0,
		RequireRewrapOnDEKAgeExceeded:  true,
		AllowVaultlessTokenization:     true,
		TokenizationModePolicy:         defaultTokenizationModePolicy(),
		TokenFormatPolicy:              defaultTokenFormatPolicy(),
		RequireTokenTTL:                false,
		MaxTokenTTLHours:               0,
		AllowTokenRenewal:              true,
		MaxTokenRenewals:               3,
		AllowOneTimeTokens:             true,
		DetokenizeAllowedPurposes:      []string{},
		DetokenizeAllowedWorkflows:     []string{},
		RequireDetokenizeJustification: false,
		AllowBulkTokenize:              true,
		AllowBulkDetokenize:            true,
		AllowRedactionDetectOnly:       true,
		AllowedRedactionDetectors:      []string{"EMAIL", "PHONE", "SSN", "PAN", "IBAN", "NAME", "CUSTOM"},
		AllowedRedactionActions:        []string{"replace_placeholder", "remove", "hash"},
		AllowCustomRegexTokens:         true,
		MaxCustomRegexLength:           512,
		MaxCustomRegexGroups:           16,
		MaxTokenBatch:                  10000,
		MaxDetokenizeBatch:             10000,
		RequireTokenContextTags:        false,
		RequiredTokenContextKeys:       []string{},
		MaskingRolePolicy:              defaultMaskingRolePolicy(),
		TokenMetadataRetentionDays:     365,
		RedactionEventRetentionDays:    365,
		RequireRegisteredWrapper:       true,
		LocalCryptoAllowed:             false,
		CacheEnabled:                   false,
		CacheTTLSeconds:                300,
		LeaseMaxOps:                    1000,
		MaxCachedKeys:                  16,
		AllowedLocalAlgorithms:         []string{"AES-GCM", "AES-SIV", "CHACHA20-POLY1305"},
		AllowedKeyClassesForLocal:      []string{"symmetric"},
		ForceRemoteOps:                 []string{},
		RequireMTLS:                    false,
		RequireSignedNonce:             true,
		AntiReplayWindowSeconds:        300,
		AttestedWrapperOnly:            false,
		RevokeOnPolicyChange:           true,
		RekeyOnPolicyChange:            false,
	}
}

func normalizeDataProtectionPolicy(in DataProtectionPolicy) DataProtectionPolicy {
	in.TenantID = strings.TrimSpace(in.TenantID)
	allowed := uniqueStrings(in.AllowedDataAlgorithms)
	outAllowed := make([]string, 0, len(allowed))
	for _, item := range allowed {
		algo := strings.ToUpper(strings.TrimSpace(item))
		if containsString(supportedDataProtectAlgorithms, algo) {
			outAllowed = append(outAllowed, algo)
		}
	}
	if len(outAllowed) == 0 {
		outAllowed = append([]string{}, supportedDataProtectAlgorithms...)
	}
	sort.Strings(outAllowed)
	in.AllowedDataAlgorithms = outAllowed
	in.AlgorithmProfilePolicy = normalizeDataAlgorithmProfilesPolicy(in.AlgorithmProfilePolicy)
	in.RequiredAADClaims = normalizeLowerKeys(uniqueStrings(in.RequiredAADClaims))
	in.AllowedAADEvironments = normalizeLowerKeys(uniqueStrings(in.AllowedAADEvironments))
	if in.MaxAppCryptoRequestBytes <= 0 {
		in.MaxAppCryptoRequestBytes = 1048576
	}
	if in.MaxAppCryptoRequestBytes > 67108864 {
		in.MaxAppCryptoRequestBytes = 67108864
	}
	if in.MaxAppCryptoBatchSize <= 0 {
		in.MaxAppCryptoBatchSize = 256
	}
	if in.MaxAppCryptoBatchSize > 4096 {
		in.MaxAppCryptoBatchSize = 4096
	}
	if in.MinKeySizeBits < 0 {
		in.MinKeySizeBits = 0
	}
	if in.MinKeySizeBits > 16384 {
		in.MinKeySizeBits = 16384
	}
	in.AllowedEncryptFieldPaths = normalizeFieldPathList(in.AllowedEncryptFieldPaths)
	in.AllowedDecryptFieldPaths = normalizeFieldPathList(in.AllowedDecryptFieldPaths)
	in.DeniedDecryptFieldPaths = normalizeFieldPathList(in.DeniedDecryptFieldPaths)
	in.EnvelopeKEKAllowlist = uniqueStrings(in.EnvelopeKEKAllowlist)
	if in.MaxWrappedDEKAgeMinutes < 0 {
		in.MaxWrappedDEKAgeMinutes = 0
	}
	if in.MaxWrappedDEKAgeMinutes > 525600 {
		in.MaxWrappedDEKAgeMinutes = 525600
	}
	if in.MaxFieldsPerOperation <= 0 {
		in.MaxFieldsPerOperation = 64
	}
	if in.MaxFieldsPerOperation > 2048 {
		in.MaxFieldsPerOperation = 2048
	}
	if in.MaxDocumentBytes <= 0 {
		in.MaxDocumentBytes = 262144
	}
	if in.MaxDocumentBytes > 16777216 {
		in.MaxDocumentBytes = 16777216
	}
	if in.MaxTokenTTLHours < 0 {
		in.MaxTokenTTLHours = 0
	}
	if in.MaxTokenTTLHours > 87600 {
		in.MaxTokenTTLHours = 87600
	}
	if in.MaxTokenRenewals < 0 {
		in.MaxTokenRenewals = 0
	}
	if in.MaxTokenRenewals > 100 {
		in.MaxTokenRenewals = 100
	}
	if in.MaxCustomRegexLength <= 0 {
		in.MaxCustomRegexLength = 512
	}
	if in.MaxCustomRegexLength > 4096 {
		in.MaxCustomRegexLength = 4096
	}
	if in.MaxCustomRegexGroups <= 0 {
		in.MaxCustomRegexGroups = 16
	}
	if in.MaxCustomRegexGroups > 128 {
		in.MaxCustomRegexGroups = 128
	}
	if in.MaxTokenBatch <= 0 {
		in.MaxTokenBatch = 10000
	}
	if in.MaxTokenBatch > 100000 {
		in.MaxTokenBatch = 100000
	}
	if in.MaxDetokenizeBatch <= 0 {
		in.MaxDetokenizeBatch = 10000
	}
	if in.MaxDetokenizeBatch > 100000 {
		in.MaxDetokenizeBatch = 100000
	}
	if in.TokenMetadataRetentionDays <= 0 {
		in.TokenMetadataRetentionDays = 365
	}
	if in.TokenMetadataRetentionDays > 36500 {
		in.TokenMetadataRetentionDays = 36500
	}
	if in.RedactionEventRetentionDays <= 0 {
		in.RedactionEventRetentionDays = 365
	}
	if in.RedactionEventRetentionDays > 36500 {
		in.RedactionEventRetentionDays = 36500
	}
	if in.CacheTTLSeconds <= 0 {
		in.CacheTTLSeconds = 300
	}
	if in.CacheTTLSeconds > 86400 {
		in.CacheTTLSeconds = 86400
	}
	if in.LeaseMaxOps <= 0 {
		in.LeaseMaxOps = 1000
	}
	if in.LeaseMaxOps > 1000000 {
		in.LeaseMaxOps = 1000000
	}
	if in.MaxCachedKeys <= 0 {
		in.MaxCachedKeys = 16
	}
	if in.MaxCachedKeys > 10000 {
		in.MaxCachedKeys = 10000
	}
	if in.AntiReplayWindowSeconds <= 0 {
		in.AntiReplayWindowSeconds = 300
	}
	if in.AntiReplayWindowSeconds > 86400 {
		in.AntiReplayWindowSeconds = 86400
	}
	in.AllowedLocalAlgorithms = uniqueUpper(uniqueStrings(in.AllowedLocalAlgorithms))
	if len(in.AllowedLocalAlgorithms) == 0 {
		in.AllowedLocalAlgorithms = []string{"AES-GCM", "AES-SIV", "CHACHA20-POLY1305"}
	}
	in.AllowedKeyClassesForLocal = normalizeLowerKeys(uniqueStrings(in.AllowedKeyClassesForLocal))
	if len(in.AllowedKeyClassesForLocal) == 0 {
		in.AllowedKeyClassesForLocal = []string{"symmetric"}
	}
	in.ForceRemoteOps = normalizeLowerKeys(uniqueStrings(in.ForceRemoteOps))
	in.DetokenizeAllowedPurposes = uniqueStrings(in.DetokenizeAllowedPurposes)
	in.DetokenizeAllowedWorkflows = uniqueStrings(in.DetokenizeAllowedWorkflows)
	in.RequiredTokenContextKeys = uniqueStrings(in.RequiredTokenContextKeys)
	in.AllowedRedactionDetectors = uniqueUpper(uniqueStrings(in.AllowedRedactionDetectors))
	if len(in.AllowedRedactionDetectors) == 0 {
		in.AllowedRedactionDetectors = []string{"EMAIL", "PHONE", "SSN", "PAN", "IBAN", "NAME", "CUSTOM"}
	}
	actions := uniqueStrings(in.AllowedRedactionActions)
	outActions := make([]string, 0, len(actions))
	for _, action := range actions {
		normalized := normalizeRedactAction(action)
		if !containsString(outActions, normalized) {
			outActions = append(outActions, normalized)
		}
	}
	if len(outActions) == 0 {
		outActions = []string{"replace_placeholder", "remove", "hash"}
	}
	in.AllowedRedactionActions = outActions
	in.TokenizationModePolicy = normalizeTokenModesPolicy(in.TokenizationModePolicy)
	in.TokenFormatPolicy = normalizeTokenFormatsPolicy(in.TokenFormatPolicy)
	in.MaskingRolePolicy = normalizeMaskingRolePolicy(in.MaskingRolePolicy)
	in.UpdatedBy = strings.TrimSpace(in.UpdatedBy)
	return in
}

func (s *Service) GetDataProtectionPolicy(ctx context.Context, tenantID string) (DataProtectionPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return DataProtectionPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetDataProtectionPolicy(ctx, tenantID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return defaultDataProtectionPolicy(tenantID), nil
		}
		return DataProtectionPolicy{}, err
	}
	return normalizeDataProtectionPolicy(item), nil
}

func (s *Service) UpdateDataProtectionPolicy(ctx context.Context, in DataProtectionPolicy) (DataProtectionPolicy, error) {
	in = normalizeDataProtectionPolicy(in)
	if in.TenantID == "" {
		return DataProtectionPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	item, err := s.store.UpsertDataProtectionPolicy(ctx, in)
	if err != nil {
		return DataProtectionPolicy{}, err
	}
	item = normalizeDataProtectionPolicy(item)
	_ = s.publishAudit(ctx, "audit.dataprotect.policy_updated", item.TenantID, map[string]interface{}{
		"allowed_data_algorithms":            item.AllowedDataAlgorithms,
		"algorithm_profile_policy":           item.AlgorithmProfilePolicy,
		"require_aad_for_aead":               item.RequireAADForAEAD,
		"required_aad_claims":                item.RequiredAADClaims,
		"enforce_aad_tenant_binding":         item.EnforceAADTenantBinding,
		"allowed_aad_environments":           item.AllowedAADEvironments,
		"max_fields_per_operation":           item.MaxFieldsPerOperation,
		"max_document_bytes":                 item.MaxDocumentBytes,
		"max_app_crypto_request_bytes":       item.MaxAppCryptoRequestBytes,
		"max_app_crypto_batch_size":          item.MaxAppCryptoBatchSize,
		"require_symmetric_keys":             item.RequireSymmetricKeys,
		"require_fips_keys":                  item.RequireFIPSKeys,
		"min_key_size_bits":                  item.MinKeySizeBits,
		"allowed_encrypt_field_paths":        item.AllowedEncryptFieldPaths,
		"allowed_decrypt_field_paths":        item.AllowedDecryptFieldPaths,
		"denied_decrypt_field_paths":         item.DeniedDecryptFieldPaths,
		"block_wildcard_field_paths":         item.BlockWildcardFieldPaths,
		"allow_deterministic_encryption":     item.AllowDeterministicEncryption,
		"allow_searchable_encryption":        item.AllowSearchableEncryption,
		"allow_range_search":                 item.AllowRangeSearch,
		"envelope_kek_allowlist":             item.EnvelopeKEKAllowlist,
		"max_wrapped_dek_age_minutes":        item.MaxWrappedDEKAgeMinutes,
		"require_rewrap_on_dek_age_exceeded": item.RequireRewrapOnDEKAgeExceeded,
		"allow_vaultless_tokenization":       item.AllowVaultlessTokenization,
		"tokenization_mode_policy":           item.TokenizationModePolicy,
		"token_format_policy":                item.TokenFormatPolicy,
		"require_token_ttl":                  item.RequireTokenTTL,
		"max_token_ttl_hours":                item.MaxTokenTTLHours,
		"allow_token_renewal":                item.AllowTokenRenewal,
		"max_token_renewals":                 item.MaxTokenRenewals,
		"allow_one_time_tokens":              item.AllowOneTimeTokens,
		"detokenize_allowed_purposes":        item.DetokenizeAllowedPurposes,
		"detokenize_allowed_workflows":       item.DetokenizeAllowedWorkflows,
		"require_detokenize_justification":   item.RequireDetokenizeJustification,
		"allow_bulk_tokenize":                item.AllowBulkTokenize,
		"allow_bulk_detokenize":              item.AllowBulkDetokenize,
		"allow_redaction_detect_only":        item.AllowRedactionDetectOnly,
		"allowed_redaction_detectors":        item.AllowedRedactionDetectors,
		"allowed_redaction_actions":          item.AllowedRedactionActions,
		"allow_custom_regex_tokens":          item.AllowCustomRegexTokens,
		"max_custom_regex_length":            item.MaxCustomRegexLength,
		"max_custom_regex_groups":            item.MaxCustomRegexGroups,
		"max_token_batch":                    item.MaxTokenBatch,
		"max_detokenize_batch":               item.MaxDetokenizeBatch,
		"require_token_context_tags":         item.RequireTokenContextTags,
		"required_token_context_keys":        item.RequiredTokenContextKeys,
		"masking_role_policy":                item.MaskingRolePolicy,
		"token_metadata_retention_days":      item.TokenMetadataRetentionDays,
		"redaction_event_retention_days":     item.RedactionEventRetentionDays,
		"require_registered_wrapper":         item.RequireRegisteredWrapper,
		"local_crypto_allowed":               item.LocalCryptoAllowed,
		"cache_enabled":                      item.CacheEnabled,
		"cache_ttl_sec":                      item.CacheTTLSeconds,
		"lease_max_ops":                      item.LeaseMaxOps,
		"max_cached_keys":                    item.MaxCachedKeys,
		"allowed_local_algorithms":           item.AllowedLocalAlgorithms,
		"allowed_key_classes_for_local":      item.AllowedKeyClassesForLocal,
		"force_remote_ops":                   item.ForceRemoteOps,
		"require_mtls":                       item.RequireMTLS,
		"require_signed_nonce":               item.RequireSignedNonce,
		"anti_replay_window_sec":             item.AntiReplayWindowSeconds,
		"attested_wrapper_only":              item.AttestedWrapperOnly,
		"revoke_on_policy_change":            item.RevokeOnPolicyChange,
		"rekey_on_policy_change":             item.RekeyOnPolicyChange,
	})
	return item, nil
}

func (s *Service) mustDataProtectionPolicy(ctx context.Context, tenantID string) (DataProtectionPolicy, error) {
	item, err := s.GetDataProtectionPolicy(ctx, tenantID)
	if err != nil {
		return DataProtectionPolicy{}, err
	}
	return item, nil
}

func (s *Service) ListFieldEncryptionWrappers(ctx context.Context, tenantID string, limit int, offset int) ([]FieldEncryptionWrapper, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	items, err := s.store.ListFieldEncryptionWrappers(ctx, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *Service) ListFieldEncryptionLeases(ctx context.Context, tenantID string, wrapperID string, limit int, offset int) ([]FieldEncryptionLease, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	items, err := s.store.ListFieldEncryptionLeases(ctx, tenantID, strings.TrimSpace(wrapperID), limit, offset)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *Service) InitFieldEncryptionWrapperRegistration(ctx context.Context, req FieldEncryptionRegisterInitRequest) (map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.WrapperID = strings.TrimSpace(req.WrapperID)
	req.AppID = strings.TrimSpace(req.AppID)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	req.SigningPublicKeyB64 = strings.TrimSpace(req.SigningPublicKeyB64)
	req.EncryptionPublicKey = strings.TrimSpace(req.EncryptionPublicKey)
	req.Transport = strings.TrimSpace(req.Transport)
	if req.Transport == "" {
		req.Transport = "mtls+jwt"
	}
	if req.TenantID == "" || req.WrapperID == "" || req.AppID == "" || req.SigningPublicKeyB64 == "" || req.EncryptionPublicKey == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, wrapper_id, app_id, signing_public_key_b64 and encryption_public_key_b64 are required")
	}
	signPub, err := b64d(req.SigningPublicKeyB64)
	if err != nil || len(signPub) != ed25519.PublicKeySize {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "signing_public_key_b64 must be base64 encoded ed25519 public key")
	}
	encPubRaw, err := b64d(req.EncryptionPublicKey)
	if err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "encryption_public_key_b64 must be base64")
	}
	if _, err := ecdh.X25519().NewPublicKey(encPubRaw); err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "encryption_public_key_b64 must be valid X25519 public key")
	}
	challenge := randBytes(32)
	defer zeroizeAll(challenge)
	item := FieldEncryptionWrapperChallenge{
		TenantID:            req.TenantID,
		ChallengeID:         newID("wrpchal"),
		WrapperID:           req.WrapperID,
		AppID:               req.AppID,
		ChallengeB64:        b64(challenge),
		Nonce:               newID("nonce"),
		SigningPublicKeyB64: req.SigningPublicKeyB64,
		EncryptionPublicKey: req.EncryptionPublicKey,
		Metadata:            req.Metadata,
		ExpiresAt:           s.now().Add(10 * time.Minute),
		Used:                false,
	}
	if err := s.store.CreateFieldEncryptionWrapperChallenge(ctx, item); err != nil {
		return nil, err
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.field_encryption.register_init", req.TenantID, map[string]interface{}{
		"wrapper_id": item.WrapperID,
		"app_id":     item.AppID,
		"challenge":  item.ChallengeID,
		"transport":  req.Transport,
		"expires_at": item.ExpiresAt.Format(time.RFC3339),
	})
	return map[string]interface{}{
		"challenge_id":  item.ChallengeID,
		"challenge_b64": item.ChallengeB64,
		"nonce":         item.Nonce,
		"expires_at":    item.ExpiresAt.Format(time.RFC3339),
	}, nil
}

func (s *Service) CompleteFieldEncryptionWrapperRegistration(ctx context.Context, req FieldEncryptionRegisterCompleteRequest) (FieldEncryptionWrapper, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.ChallengeID = strings.TrimSpace(req.ChallengeID)
	req.WrapperID = strings.TrimSpace(req.WrapperID)
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)
	req.ApprovedBy = strings.TrimSpace(req.ApprovedBy)
	if req.TenantID == "" || req.ChallengeID == "" || req.WrapperID == "" || req.SignatureB64 == "" {
		return FieldEncryptionWrapper{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, challenge_id, wrapper_id and signature_b64 are required")
	}
	if !req.GovernanceApproved {
		return FieldEncryptionWrapper{}, newServiceError(http.StatusForbidden, "governance_required", "wrapper registration requires governance approval")
	}
	challenge, err := s.store.GetFieldEncryptionWrapperChallenge(ctx, req.TenantID, req.ChallengeID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return FieldEncryptionWrapper{}, newServiceError(http.StatusNotFound, "not_found", "registration challenge was not found")
		}
		return FieldEncryptionWrapper{}, err
	}
	if challenge.Used {
		return FieldEncryptionWrapper{}, newServiceError(http.StatusConflict, "invalid_state", "registration challenge is already used")
	}
	if s.now().After(challenge.ExpiresAt) {
		return FieldEncryptionWrapper{}, newServiceError(http.StatusConflict, "expired", "registration challenge has expired")
	}
	if challenge.WrapperID != req.WrapperID {
		return FieldEncryptionWrapper{}, newServiceError(http.StatusBadRequest, "bad_request", "wrapper_id does not match challenge")
	}
	pubRaw, err := b64d(challenge.SigningPublicKeyB64)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return FieldEncryptionWrapper{}, newServiceError(http.StatusBadRequest, "bad_request", "challenge signing key is invalid")
	}
	signature, err := b64d(req.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return FieldEncryptionWrapper{}, newServiceError(http.StatusBadRequest, "bad_request", "signature_b64 must be valid ed25519 signature")
	}
	challengeBytes, err := b64d(challenge.ChallengeB64)
	if err != nil || len(challengeBytes) == 0 {
		return FieldEncryptionWrapper{}, newServiceError(http.StatusBadRequest, "bad_request", "challenge payload is invalid")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), challengeBytes, signature) {
		return FieldEncryptionWrapper{}, newServiceError(http.StatusForbidden, "access_denied", "challenge signature verification failed")
	}
	approvedBy := defaultString(req.ApprovedBy, "governance")
	policy, err := s.mustDataProtectionPolicy(ctx, req.TenantID)
	if err != nil {
		return FieldEncryptionWrapper{}, err
	}
	certFingerprint := strings.TrimSpace(req.CertFingerprint)
	if policy.RequireMTLS && certFingerprint == "" {
		return FieldEncryptionWrapper{}, newServiceError(http.StatusForbidden, "policy_denied", "mTLS is required by policy; cert_fingerprint is mandatory")
	}
	item := FieldEncryptionWrapper{
		TenantID:            req.TenantID,
		WrapperID:           challenge.WrapperID,
		AppID:               challenge.AppID,
		DisplayName:         defaultString(challenge.WrapperID, challenge.WrapperID),
		SigningPublicKeyB64: challenge.SigningPublicKeyB64,
		EncryptionPublicKey: challenge.EncryptionPublicKey,
		Transport:           "mtls+jwt",
		Status:              "active",
		CertFingerprint:     certFingerprint,
		Metadata:            mergeStringMaps(challenge.Metadata, req.Metadata),
		ApprovedBy:          approvedBy,
		ApprovedAt:          s.now(),
	}
	if existing, getErr := s.store.GetFieldEncryptionWrapper(ctx, req.TenantID, req.WrapperID); getErr == nil {
		if strings.TrimSpace(existing.TenantID) != strings.TrimSpace(item.TenantID) ||
			strings.TrimSpace(existing.AppID) != strings.TrimSpace(item.AppID) ||
			strings.TrimSpace(existing.SigningPublicKeyB64) != strings.TrimSpace(item.SigningPublicKeyB64) ||
			strings.TrimSpace(existing.EncryptionPublicKey) != strings.TrimSpace(item.EncryptionPublicKey) {
			return FieldEncryptionWrapper{}, newServiceError(http.StatusConflict, "immutable_binding_violation", "wrapper binding (tenant/app/keys) is immutable")
		}
		if strings.TrimSpace(existing.CertFingerprint) != "" &&
			!strings.EqualFold(strings.TrimSpace(existing.CertFingerprint), strings.TrimSpace(item.CertFingerprint)) {
			return FieldEncryptionWrapper{}, newServiceError(http.StatusConflict, "immutable_binding_violation", "wrapper certificate fingerprint is immutable")
		}
	} else if !errors.Is(getErr, errNotFound) {
		return FieldEncryptionWrapper{}, getErr
	}
	wrapper, err := s.store.UpsertFieldEncryptionWrapper(ctx, item)
	if err != nil {
		return FieldEncryptionWrapper{}, err
	}
	if err := s.store.MarkFieldEncryptionWrapperChallengeUsed(ctx, req.TenantID, req.ChallengeID); err != nil {
		return FieldEncryptionWrapper{}, err
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.field_encryption.register_complete", req.TenantID, map[string]interface{}{
		"wrapper_id":       wrapper.WrapperID,
		"app_id":           wrapper.AppID,
		"challenge_id":     req.ChallengeID,
		"governance":       true,
		"cert_fingerprint": wrapper.CertFingerprint,
	})
	return wrapper, nil
}

func (s *Service) IssueFieldEncryptionLease(ctx context.Context, req FieldEncryptionLeaseRequest) (FieldEncryptionLease, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.WrapperID = strings.TrimSpace(req.WrapperID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.Operation = strings.ToLower(strings.TrimSpace(req.Operation))
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)
	if req.TenantID == "" || req.WrapperID == "" || req.KeyID == "" {
		return FieldEncryptionLease{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, wrapper_id and key_id are required")
	}
	if req.Operation == "" {
		req.Operation = "encrypt"
	}
	policy, err := s.mustDataProtectionPolicy(ctx, req.TenantID)
	if err != nil {
		return FieldEncryptionLease{}, err
	}
	if !policy.LocalCryptoAllowed {
		return FieldEncryptionLease{}, newServiceError(http.StatusForbidden, "policy_denied", "local crypto is disabled by policy")
	}
	if !policy.CacheEnabled {
		return FieldEncryptionLease{}, newServiceError(http.StatusForbidden, "policy_denied", "cache_enabled=false requires remote KMS crypto path")
	}
	if containsString(policy.ForceRemoteOps, req.Operation) {
		return FieldEncryptionLease{}, newServiceError(http.StatusForbidden, "policy_denied", "operation is forced to remote path by policy")
	}
	wrapper, err := s.store.GetFieldEncryptionWrapper(ctx, req.TenantID, req.WrapperID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return FieldEncryptionLease{}, newServiceError(http.StatusNotFound, "not_found", "wrapper registration is not found")
		}
		return FieldEncryptionLease{}, err
	}
	if policy.RequireRegisteredWrapper && strings.ToLower(strings.TrimSpace(wrapper.Status)) != "active" {
		return FieldEncryptionLease{}, newServiceError(http.StatusForbidden, "policy_denied", "wrapper is not active")
	}
	if err := s.enforceWrapperTransportPolicy(policy, wrapper); err != nil {
		return FieldEncryptionLease{}, err
	}
	if policy.MaxCachedKeys > 0 {
		activeLeases, err := s.store.ListFieldEncryptionLeases(ctx, req.TenantID, req.WrapperID, policy.MaxCachedKeys+1, 0)
		if err != nil {
			return FieldEncryptionLease{}, err
		}
		activeCount := 0
		now := s.now()
		for _, item := range activeLeases {
			if item.Revoked {
				continue
			}
			if now.After(item.ExpiresAt) {
				continue
			}
			activeCount++
		}
		if activeCount >= policy.MaxCachedKeys {
			return FieldEncryptionLease{}, newServiceError(http.StatusForbidden, "policy_denied", "max_cached_keys limit reached for wrapper")
		}
	}
	if policy.RequireSignedNonce {
		if err := s.verifyWrapperSignedNonce(wrapper, "lease", req.KeyID, req.Operation, req.Nonce, req.Timestamp, req.SignatureB64, policy.AntiReplayWindowSeconds); err != nil {
			return FieldEncryptionLease{}, err
		}
	}
	keyMeta := map[string]interface{}{}
	if s.keycore != nil {
		keyMeta, err = s.keycore.GetKey(ctx, req.TenantID, req.KeyID)
		if err != nil {
			return FieldEncryptionLease{}, err
		}
	}
	if err := s.enforceLocalWrapperKeyPolicies(policy, keyMeta, req.Operation); err != nil {
		return FieldEncryptionLease{}, err
	}
	workingKey, err := s.resolveWorkingKeyForDataPolicy(ctx, req.TenantID, req.KeyID, "field-local-lease", policy)
	if err != nil {
		return FieldEncryptionLease{}, err
	}
	defer zeroizeAll(workingKey)
	leasePayload, err := s.wrapLeaseKeyForWrapper(req.TenantID, req.WrapperID, req.KeyID, req.Operation, wrapper.EncryptionPublicKey, workingKey)
	if err != nil {
		return FieldEncryptionLease{}, err
	}
	maxOps := policy.LeaseMaxOps
	if req.RequestedMaxOps > 0 && req.RequestedMaxOps < maxOps {
		maxOps = req.RequestedMaxOps
	}
	if maxOps <= 0 {
		maxOps = 1
	}
	ttlSeconds := policy.CacheTTLSeconds
	if req.RequestedTTLSecond > 0 && req.RequestedTTLSecond < ttlSeconds {
		ttlSeconds = req.RequestedTTLSecond
	}
	if ttlSeconds <= 0 {
		ttlSeconds = 300
	}
	now := s.now()
	expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)
	policyHash := hashHex(mustJSON(policy, "{}"))
	leasePayload["policy_hash"] = policyHash
	leasePayload["exp"] = expiresAt.Format(time.RFC3339)
	leasePayload["max_ops"] = maxOps
	leasePayload["revocation_counter"] = 0
	signingKey := keyFromHash([]byte(req.TenantID+"|"+req.WrapperID), "field-lease-signature")
	leasePayload["kms_sig"] = b64(hmacSHA256(signingKey, mustJSON(leasePayload, "{}")))
	zeroizeAll(signingKey)
	lease := FieldEncryptionLease{
		TenantID:          req.TenantID,
		LeaseID:           newID("lease"),
		WrapperID:         req.WrapperID,
		KeyID:             req.KeyID,
		Operation:         req.Operation,
		LeasePackage:      leasePayload,
		PolicyHash:        policyHash,
		RevocationCounter: 0,
		MaxOps:            maxOps,
		UsedOps:           0,
		ExpiresAt:         expiresAt,
		Revoked:           false,
		IssuedAt:          now,
		UpdatedAt:         now,
	}
	if err := s.store.CreateFieldEncryptionLease(ctx, lease); err != nil {
		return FieldEncryptionLease{}, err
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.field_encryption.lease_issued", req.TenantID, map[string]interface{}{
		"lease_id":    lease.LeaseID,
		"wrapper_id":  lease.WrapperID,
		"key_id":      lease.KeyID,
		"operation":   lease.Operation,
		"expires_at":  lease.ExpiresAt.Format(time.RFC3339),
		"max_ops":     lease.MaxOps,
		"policy_hash": lease.PolicyHash,
	})
	return lease, nil
}

func (s *Service) SubmitFieldEncryptionUsageReceipt(ctx context.Context, req FieldEncryptionReceiptRequest) (FieldEncryptionUsageReceipt, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.LeaseID = strings.TrimSpace(req.LeaseID)
	req.WrapperID = strings.TrimSpace(req.WrapperID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.Operation = strings.ToLower(strings.TrimSpace(req.Operation))
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)
	req.ClientStatus = strings.TrimSpace(req.ClientStatus)
	if req.TenantID == "" || req.LeaseID == "" || req.WrapperID == "" || req.KeyID == "" || req.Operation == "" || req.Nonce == "" || req.SignatureB64 == "" {
		return FieldEncryptionUsageReceipt{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, lease_id, wrapper_id, key_id, operation, nonce and signature_b64 are required")
	}
	if req.OpCount <= 0 {
		req.OpCount = 1
	}
	if req.OpCount > 1000 {
		return FieldEncryptionUsageReceipt{}, newServiceError(http.StatusBadRequest, "bad_request", "op_count exceeds max allowed value")
	}
	policy, err := s.mustDataProtectionPolicy(ctx, req.TenantID)
	if err != nil {
		return FieldEncryptionUsageReceipt{}, err
	}
	wrapper, err := s.store.GetFieldEncryptionWrapper(ctx, req.TenantID, req.WrapperID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return FieldEncryptionUsageReceipt{}, newServiceError(http.StatusNotFound, "not_found", "wrapper registration is not found")
		}
		return FieldEncryptionUsageReceipt{}, err
	}
	if policy.RequireRegisteredWrapper && strings.ToLower(strings.TrimSpace(wrapper.Status)) != "active" {
		return FieldEncryptionUsageReceipt{}, newServiceError(http.StatusForbidden, "policy_denied", "wrapper is not active")
	}
	if err := s.enforceWrapperTransportPolicy(policy, wrapper); err != nil {
		return FieldEncryptionUsageReceipt{}, err
	}
	if _, err := s.store.GetFieldEncryptionUsageReceiptByNonce(ctx, req.TenantID, req.WrapperID, req.Nonce); err == nil {
		return FieldEncryptionUsageReceipt{}, newServiceError(http.StatusConflict, "replay_detected", "receipt nonce has already been used")
	} else if !errors.Is(err, errNotFound) {
		return FieldEncryptionUsageReceipt{}, err
	}
	if policy.RequireSignedNonce {
		if err := s.verifyWrapperSignedNonce(wrapper, "receipt", req.LeaseID+"|"+req.KeyID, req.Operation+"|"+strconvI(req.OpCount), req.Nonce, req.Timestamp, req.SignatureB64, policy.AntiReplayWindowSeconds); err != nil {
			_ = s.store.RevokeFieldEncryptionLease(ctx, req.TenantID, req.LeaseID, "receipt_signature_verification_failed")
			_ = s.publishAudit(ctx, "audit.dataprotect.field_encryption.lease_revoked", req.TenantID, map[string]interface{}{
				"lease_id": req.LeaseID,
				"reason":   "receipt_signature_verification_failed",
			})
			return FieldEncryptionUsageReceipt{}, err
		}
	}
	lease, err := s.store.GetFieldEncryptionLease(ctx, req.TenantID, req.LeaseID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return FieldEncryptionUsageReceipt{}, newServiceError(http.StatusNotFound, "not_found", "lease not found")
		}
		return FieldEncryptionUsageReceipt{}, err
	}
	if lease.Revoked {
		return FieldEncryptionUsageReceipt{}, newServiceError(http.StatusForbidden, "access_denied", "lease is revoked")
	}
	if s.now().After(lease.ExpiresAt) {
		return FieldEncryptionUsageReceipt{}, newServiceError(http.StatusForbidden, "lease_expired", "lease has expired")
	}
	if lease.WrapperID != req.WrapperID || lease.KeyID != req.KeyID {
		return FieldEncryptionUsageReceipt{}, newServiceError(http.StatusBadRequest, "bad_request", "receipt does not match lease binding")
	}
	if lease.Operation != req.Operation {
		return FieldEncryptionUsageReceipt{}, newServiceError(http.StatusBadRequest, "bad_request", "receipt operation does not match lease operation")
	}
	currentPolicyHash := hashHex(mustJSON(policy, "{}"))
	if strings.TrimSpace(lease.PolicyHash) != "" && lease.PolicyHash != currentPolicyHash {
		if policy.RevokeOnPolicyChange {
			_ = s.store.RevokeFieldEncryptionLease(ctx, req.TenantID, req.LeaseID, "policy_changed")
			_ = s.publishAudit(ctx, "audit.dataprotect.field_encryption.lease_revoked", req.TenantID, map[string]interface{}{
				"lease_id": req.LeaseID,
				"reason":   "policy_changed",
			})
			return FieldEncryptionUsageReceipt{}, newServiceError(http.StatusForbidden, "policy_changed", "lease revoked due to policy change")
		}
		if policy.RekeyOnPolicyChange {
			return FieldEncryptionUsageReceipt{}, newServiceError(http.StatusForbidden, "rekey_required", "policy changed, re-lease key required")
		}
	}
	updatedLease, err := s.store.ConsumeFieldEncryptionLeaseOps(ctx, req.TenantID, req.LeaseID, req.OpCount)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return FieldEncryptionUsageReceipt{}, newServiceError(http.StatusTooManyRequests, "ops_limit_reached", "lease operation limit reached")
		}
		return FieldEncryptionUsageReceipt{}, err
	}
	for i := 0; i < req.OpCount; i++ {
		if err := s.enforceKeycoreMetering(ctx, req.TenantID, req.KeyID, req.Operation); err != nil {
			return FieldEncryptionUsageReceipt{}, err
		}
	}
	ts := parseTimeString(req.Timestamp)
	payloadHash := hashHex(req.TenantID, req.LeaseID, req.WrapperID, req.KeyID, req.Operation, strconvI(req.OpCount), req.Nonce, req.Timestamp, req.ClientStatus)
	receipt := FieldEncryptionUsageReceipt{
		TenantID:     req.TenantID,
		ReceiptID:    newID("rcpt"),
		LeaseID:      req.LeaseID,
		WrapperID:    req.WrapperID,
		KeyID:        req.KeyID,
		Operation:    req.Operation,
		OpCount:      req.OpCount,
		Nonce:        req.Nonce,
		Timestamp:    ts,
		SignatureB64: req.SignatureB64,
		PayloadHash:  payloadHash,
		Accepted:     true,
		CreatedAt:    s.now(),
	}
	if err := s.store.CreateFieldEncryptionUsageReceipt(ctx, receipt); err != nil {
		return FieldEncryptionUsageReceipt{}, err
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.field_encryption.receipt_accepted", req.TenantID, map[string]interface{}{
		"receipt_id":    receipt.ReceiptID,
		"lease_id":      receipt.LeaseID,
		"wrapper_id":    receipt.WrapperID,
		"key_id":        receipt.KeyID,
		"operation":     receipt.Operation,
		"op_count":      receipt.OpCount,
		"lease_used":    updatedLease.UsedOps,
		"lease_max_ops": updatedLease.MaxOps,
	})
	return receipt, nil
}

func (s *Service) RevokeFieldEncryptionLease(ctx context.Context, tenantID string, leaseID string, reason string) error {
	tenantID = strings.TrimSpace(tenantID)
	leaseID = strings.TrimSpace(leaseID)
	reason = strings.TrimSpace(reason)
	if tenantID == "" || leaseID == "" {
		return newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and lease_id are required")
	}
	if reason == "" {
		reason = "operator_request"
	}
	if err := s.store.RevokeFieldEncryptionLease(ctx, tenantID, leaseID, reason); err != nil {
		if errors.Is(err, errNotFound) {
			return newServiceError(http.StatusNotFound, "not_found", "lease was not found")
		}
		return err
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.field_encryption.lease_revoked", tenantID, map[string]interface{}{
		"lease_id": leaseID,
		"reason":   reason,
	})
	return nil
}

func (s *Service) enforceLocalWrapperKeyPolicies(policy DataProtectionPolicy, keyMeta map[string]interface{}, operation string) error {
	keyType := strings.ToLower(strings.TrimSpace(firstString(keyMeta["key_type"])))
	if keyType == "" {
		keyType = inferDataProtectionKeyTypeFromAlgorithm(firstString(keyMeta["algorithm"]))
	}
	if len(policy.AllowedKeyClassesForLocal) > 0 && keyType != "" && !containsString(policy.AllowedKeyClassesForLocal, keyType) {
		return newServiceError(http.StatusForbidden, "policy_denied", "key class is blocked for local crypto export")
	}
	localAlg := s.classifyLocalAlgorithm(firstString(keyMeta["algorithm"]))
	if len(policy.AllowedLocalAlgorithms) > 0 && localAlg != "" && !containsString(policy.AllowedLocalAlgorithms, localAlg) {
		return newServiceError(http.StatusForbidden, "policy_denied", "key algorithm is blocked for local crypto")
	}
	if containsString(policy.ForceRemoteOps, operation) {
		return newServiceError(http.StatusForbidden, "policy_denied", "operation is forced to remote path by policy")
	}
	return nil
}

func (s *Service) classifyLocalAlgorithm(keyAlgorithm string) string {
	a := strings.ToUpper(strings.TrimSpace(keyAlgorithm))
	switch {
	case strings.Contains(a, "CHACHA20"):
		return "CHACHA20-POLY1305"
	case strings.Contains(a, "SIV"):
		return "AES-SIV"
	case strings.Contains(a, "AES"):
		return "AES-GCM"
	default:
		return "AES-GCM"
	}
}

func (s *Service) enforceWrapperTransportPolicy(policy DataProtectionPolicy, wrapper FieldEncryptionWrapper) error {
	transport := strings.ToLower(strings.TrimSpace(wrapper.Transport))
	fingerprint := strings.TrimSpace(wrapper.CertFingerprint)
	if policy.RequireMTLS {
		if !strings.Contains(transport, "mtls") {
			return newServiceError(http.StatusForbidden, "policy_denied", "wrapper transport must include mTLS")
		}
		if fingerprint == "" {
			return newServiceError(http.StatusForbidden, "policy_denied", "wrapper cert fingerprint is required when mTLS is enforced")
		}
	}
	if policy.AttestedWrapperOnly {
		attested := false
		if strings.EqualFold(strings.TrimSpace(wrapper.Metadata["attested"]), "true") ||
			strings.EqualFold(strings.TrimSpace(wrapper.Metadata["attestation"]), "verified") ||
			strings.EqualFold(strings.TrimSpace(wrapper.Metadata["attestation_status"]), "verified") {
			attested = true
		}
		if !attested && fingerprint == "" {
			return newServiceError(http.StatusForbidden, "policy_denied", "attested wrapper is required by policy")
		}
	}
	return nil
}

func (s *Service) wrapLeaseKeyForWrapper(tenantID string, wrapperID string, keyID string, operation string, wrapperPubKeyB64 string, rawKey []byte) (map[string]interface{}, error) {
	pubRaw, err := b64d(wrapperPubKeyB64)
	if err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "wrapper encryption key must be valid base64")
	}
	curve := ecdh.X25519()
	wrapperPub, err := curve.NewPublicKey(pubRaw)
	if err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "wrapper encryption key must be valid X25519 key")
	}
	ephemeralKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := ephemeralKey.ECDH(wrapperPub)
	if err != nil {
		return nil, err
	}
	defer zeroizeAll(shared)
	kek := keyFromHash(shared, "field-wrapper-lease")
	defer zeroizeAll(kek)
	aad := []byte(tenantID + "|" + wrapperID + "|" + keyID + "|" + strings.ToLower(strings.TrimSpace(operation)))
	iv, ciphertext, err := encryptWithAlgorithm(kek, "AES-GCM", rawKey, aad, false)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"alg":               "X25519+AES-256-GCM",
		"ephemeral_pub_b64": b64(ephemeralKey.PublicKey().Bytes()),
		"ciphertext_b64":    b64(ciphertext),
		"iv_b64":            b64(iv),
		"key_id":            keyID,
		"operation":         strings.ToLower(strings.TrimSpace(operation)),
	}, nil
}

func (s *Service) verifyWrapperSignedNonce(wrapper FieldEncryptionWrapper, mode string, left string, right string, nonce string, ts string, signatureB64 string, replayWindowSec int) error {
	nonce = strings.TrimSpace(nonce)
	ts = strings.TrimSpace(ts)
	signatureB64 = strings.TrimSpace(signatureB64)
	if nonce == "" || ts == "" || signatureB64 == "" {
		return newServiceError(http.StatusBadRequest, "bad_request", "nonce, timestamp and signature are required")
	}
	if replayWindowSec <= 0 {
		replayWindowSec = 300
	}
	parsedTs := parseTimeString(ts)
	if parsedTs.IsZero() {
		return newServiceError(http.StatusBadRequest, "bad_request", "timestamp must be RFC3339")
	}
	delta := s.now().Sub(parsedTs)
	if delta < 0 {
		delta = -delta
	}
	if delta > time.Duration(replayWindowSec)*time.Second {
		return newServiceError(http.StatusForbidden, "access_denied", "signed nonce is outside anti-replay window")
	}
	pubRaw, err := b64d(wrapper.SigningPublicKeyB64)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return newServiceError(http.StatusBadRequest, "bad_request", "wrapper signing key is invalid")
	}
	signature, err := b64d(signatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return newServiceError(http.StatusBadRequest, "bad_request", "signature must be a valid ed25519 signature")
	}
	payload := strings.Join([]string{
		mode,
		strings.TrimSpace(wrapper.TenantID),
		strings.TrimSpace(wrapper.WrapperID),
		strings.TrimSpace(left),
		strings.TrimSpace(right),
		nonce,
		ts,
	}, "|")
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), []byte(payload), signature) {
		return newServiceError(http.StatusForbidden, "access_denied", "wrapper signature verification failed")
	}
	return nil
}

func mergeStringMaps(base map[string]string, override map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(v)
	}
	for k, v := range override {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(v)
	}
	return out
}

func normalizeLowerKeys(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		s := strings.ToLower(strings.TrimSpace(item))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func normalizeFieldPath(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "$.") || p == "$" {
		return p
	}
	if strings.HasPrefix(p, "$") {
		return "$." + strings.TrimPrefix(p, "$")
	}
	return "$." + p
}

func normalizeFieldPathList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		p := normalizeFieldPath(item)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func normalizeDataAlgorithmProfilesPolicy(in map[string][]string) map[string][]string {
	defaults := defaultDataAlgorithmProfilePolicy()
	out := map[string][]string{}
	for _, useCase := range []string{"field_level", "envelope", "searchable"} {
		candidate := defaults[useCase]
		if supplied, ok := in[useCase]; ok {
			candidate = supplied
		} else {
			for alias, values := range in {
				switch useCase {
				case "field_level":
					if strings.EqualFold(alias, "field-level") || strings.EqualFold(alias, "fle") {
						candidate = values
					}
				case "searchable":
					if strings.EqualFold(alias, "search") {
						candidate = values
					}
				}
			}
		}
		valid := make([]string, 0, len(candidate))
		for _, item := range candidate {
			alg := strings.ToUpper(strings.TrimSpace(item))
			if containsString(supportedDataProtectAlgorithms, alg) && !containsString(valid, alg) {
				valid = append(valid, alg)
			}
		}
		if len(valid) == 0 {
			valid = append(valid, defaults[useCase]...)
		}
		out[useCase] = valid
	}
	return out
}

func useCaseAlgorithms(policy DataProtectionPolicy, useCase string) []string {
	p := normalizeDataProtectionPolicy(policy)
	k := strings.ToLower(strings.TrimSpace(useCase))
	switch k {
	case "field-level", "fle":
		k = "field_level"
	case "search":
		k = "searchable"
	}
	values := p.AlgorithmProfilePolicy[k]
	if len(values) == 0 {
		return append([]string{}, defaultDataAlgorithmProfilePolicy()[k]...)
	}
	return append([]string{}, values...)
}

func matchesPathPolicy(pattern string, path string) bool {
	p := normalizeFieldPath(pattern)
	t := normalizeFieldPath(path)
	if p == "" || t == "" {
		return false
	}
	if p == "*" || p == "$.*" {
		return true
	}
	if strings.Contains(p, "*") {
		prefix := strings.SplitN(p, "*", 2)[0]
		return strings.HasPrefix(t, prefix)
	}
	return strings.EqualFold(p, t)
}

func hasPathWildcard(path string) bool {
	p := strings.TrimSpace(path)
	return strings.Contains(p, "*") || strings.Contains(p, "[") || strings.Contains(p, "]")
}

func parseAADClaims(aad string) map[string]string {
	out := map[string]string{}
	raw := strings.TrimSpace(aad)
	if raw == "" {
		return out
	}
	if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") {
		js := map[string]interface{}{}
		if err := json.Unmarshal([]byte(raw), &js); err == nil {
			for k, v := range js {
				key := strings.ToLower(strings.TrimSpace(k))
				if key == "" {
					continue
				}
				out[key] = strings.TrimSpace(firstString(v))
			}
			return out
		}
	}
	separators := strings.NewReplacer("\n", ",", ";", ",", "&", ",")
	parts := strings.Split(separators.Replace(raw), ",")
	for _, part := range parts {
		token := strings.TrimSpace(part)
		if token == "" {
			continue
		}
		kv := strings.SplitN(token, "=", 2)
		if len(kv) != 2 {
			kv = strings.SplitN(token, ":", 2)
		}
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		if key == "" || val == "" {
			continue
		}
		out[key] = val
	}
	return out
}

func extractKeyBitsFromAlgorithm(algorithm string) int {
	re := regexp.MustCompile(`\d{2,5}`)
	matches := re.FindAllString(strings.ToUpper(strings.TrimSpace(algorithm)), -1)
	for _, m := range matches {
		v := extractInt(m)
		if v >= 64 && v <= 16384 {
			return v
		}
	}
	return 0
}

func isFIPSApprovedDataAlgorithm(algorithm string) bool {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	return strings.HasPrefix(a, "AES")
}

func isTruthy(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "1" || s == "true" || s == "yes" || s == "on"
	default:
		return false
	}
}

func (s *Service) enforceAppCryptoPayloadPolicy(policy DataProtectionPolicy, request interface{}, batchCount int) error {
	if policy.MaxAppCryptoBatchSize > 0 && batchCount > policy.MaxAppCryptoBatchSize {
		return newServiceError(http.StatusBadRequest, "bad_request", "batch size exceeds configured app crypto policy limit")
	}
	if policy.MaxAppCryptoRequestBytes > 0 {
		if raw, err := json.Marshal(request); err == nil && len(raw) > policy.MaxAppCryptoRequestBytes {
			return newServiceError(http.StatusBadRequest, "bad_request", "request size exceeds configured app crypto policy limit")
		}
	}
	return nil
}

func (s *Service) enforceAADContractPolicy(policy DataProtectionPolicy, tenantID string, aad string) error {
	if !policy.RequireAADForAEAD && len(policy.RequiredAADClaims) == 0 && !policy.EnforceAADTenantBinding && len(policy.AllowedAADEvironments) == 0 {
		return nil
	}
	if strings.TrimSpace(aad) == "" {
		return newServiceError(http.StatusBadRequest, "bad_request", "aad is required by data encryption policy")
	}
	claims := parseAADClaims(aad)
	for _, reqClaim := range policy.RequiredAADClaims {
		if strings.TrimSpace(claims[strings.ToLower(strings.TrimSpace(reqClaim))]) == "" {
			return newServiceError(http.StatusForbidden, "policy_denied", "aad claim "+reqClaim+" is required by policy")
		}
	}
	if policy.EnforceAADTenantBinding {
		aadTenant := strings.TrimSpace(firstString(claims["tenant_id"], claims["tenant"]))
		if aadTenant == "" || !strings.EqualFold(aadTenant, strings.TrimSpace(tenantID)) {
			return newServiceError(http.StatusForbidden, "policy_denied", "aad tenant binding check failed")
		}
	}
	if len(policy.AllowedAADEvironments) > 0 {
		env := strings.ToLower(strings.TrimSpace(firstString(claims["env"], claims["environment"])))
		if env == "" || !containsString(policy.AllowedAADEvironments, env) {
			return newServiceError(http.StatusForbidden, "policy_denied", "aad environment is blocked by policy")
		}
	}
	return nil
}

func (s *Service) enforceFieldScopePolicy(policy DataProtectionPolicy, path string, decrypt bool) error {
	p := normalizeFieldPath(path)
	if p == "" {
		return newServiceError(http.StatusBadRequest, "bad_request", "field path is required")
	}
	if policy.BlockWildcardFieldPaths && hasPathWildcard(p) {
		return newServiceError(http.StatusForbidden, "policy_denied", "wildcard field paths are blocked by policy")
	}
	if decrypt {
		for _, denied := range policy.DeniedDecryptFieldPaths {
			if matchesPathPolicy(denied, p) {
				return newServiceError(http.StatusForbidden, "policy_denied", "field path is blocked for decrypt by policy")
			}
		}
		if len(policy.AllowedDecryptFieldPaths) > 0 {
			allowed := false
			for _, allowedPath := range policy.AllowedDecryptFieldPaths {
				if matchesPathPolicy(allowedPath, p) {
					allowed = true
					break
				}
			}
			if !allowed {
				return newServiceError(http.StatusForbidden, "policy_denied", "field path is not allowed for decrypt by policy")
			}
		}
		return nil
	}
	if len(policy.AllowedEncryptFieldPaths) > 0 {
		allowed := false
		for _, allowedPath := range policy.AllowedEncryptFieldPaths {
			if matchesPathPolicy(allowedPath, p) {
				allowed = true
				break
			}
		}
		if !allowed {
			return newServiceError(http.StatusForbidden, "policy_denied", "field path is not allowed for encrypt by policy")
		}
	}
	return nil
}

func (s *Service) enforceUseCaseAlgorithmPolicy(policy DataProtectionPolicy, useCase string, algorithm string) error {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	if !containsString(policy.AllowedDataAlgorithms, alg) {
		return newServiceError(http.StatusForbidden, "policy_denied", "algorithm is disabled by data protection policy")
	}
	if !containsString(useCaseAlgorithms(policy, useCase), alg) {
		return newServiceError(http.StatusForbidden, "policy_denied", "algorithm is blocked by data encryption profile policy")
	}
	if policy.RequireFIPSKeys && !isFIPSApprovedDataAlgorithm(alg) {
		return newServiceError(http.StatusForbidden, "policy_denied", "algorithm is not FIPS-approved under current policy")
	}
	return nil
}

func (s *Service) enforceSearchablePolicy(policy DataProtectionPolicy, queryType string) error {
	if !policy.AllowSearchableEncryption {
		return newServiceError(http.StatusForbidden, "policy_denied", "searchable encryption is disabled by policy")
	}
	if !policy.AllowDeterministicEncryption {
		return newServiceError(http.StatusForbidden, "policy_denied", "deterministic encryption is disabled by policy")
	}
	q := strings.ToLower(strings.TrimSpace(defaultString(queryType, "equality")))
	switch q {
	case "", "equality":
		return nil
	case "range":
		if !policy.AllowRangeSearch {
			return newServiceError(http.StatusForbidden, "policy_denied", "range search is blocked by policy")
		}
		return nil
	default:
		return newServiceError(http.StatusBadRequest, "bad_request", "query_type must be equality or range")
	}
}

func (s *Service) enforceEnvelopePolicyEncrypt(policy DataProtectionPolicy, keyID string) error {
	if len(policy.EnvelopeKEKAllowlist) > 0 && !containsString(policy.EnvelopeKEKAllowlist, strings.TrimSpace(keyID)) {
		return newServiceError(http.StatusForbidden, "policy_denied", "selected KEK is blocked by envelope policy")
	}
	return nil
}

func (s *Service) enforceEnvelopePolicyDecrypt(policy DataProtectionPolicy, keyID string, dekCreatedAt string) error {
	if len(policy.EnvelopeKEKAllowlist) > 0 && !containsString(policy.EnvelopeKEKAllowlist, strings.TrimSpace(keyID)) {
		return newServiceError(http.StatusForbidden, "policy_denied", "selected KEK is blocked by envelope policy")
	}
	if policy.MaxWrappedDEKAgeMinutes <= 0 {
		return nil
	}
	ts := strings.TrimSpace(dekCreatedAt)
	if ts == "" {
		return newServiceError(http.StatusBadRequest, "bad_request", "dek_created_at is required by envelope policy")
	}
	createdAt, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return newServiceError(http.StatusBadRequest, "bad_request", "dek_created_at must be RFC3339")
	}
	ageLimit := time.Duration(policy.MaxWrappedDEKAgeMinutes) * time.Minute
	if s.now().Sub(createdAt.UTC()) <= ageLimit {
		return nil
	}
	if policy.RequireRewrapOnDEKAgeExceeded {
		return newServiceError(http.StatusConflict, "rewrap_required", "wrapped DEK age exceeded policy threshold; re-wrap is required")
	}
	return newServiceError(http.StatusForbidden, "policy_denied", "wrapped DEK age exceeded policy threshold")
}

func (s *Service) CreateTokenVault(ctx context.Context, tenantID string, in TokenVault) (TokenVault, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return TokenVault{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Mode = "vault"
	in.TokenType = strings.ToLower(strings.TrimSpace(in.TokenType))
	in.Format = normalizeTokenFormat(in.Format)
	in.KeyID = strings.TrimSpace(in.KeyID)
	in.CustomRegex = strings.TrimSpace(in.CustomRegex)
	if in.Name == "" || in.TokenType == "" || in.KeyID == "" {
		return TokenVault{}, newServiceError(http.StatusBadRequest, "bad_request", "name, token_type and key_id are required")
	}
	if !isSupportedTokenType(in.TokenType) {
		return TokenVault{}, newServiceError(http.StatusBadRequest, "bad_request", "unsupported token_type")
	}
	if in.TokenType == "custom" && in.CustomRegex == "" {
		return TokenVault{}, newServiceError(http.StatusBadRequest, "bad_request", "custom_regex is required for custom token type")
	}
	policy, err := s.mustDataProtectionPolicy(ctx, tenantID)
	if err != nil {
		return TokenVault{}, err
	}
	if !policyAllowsTokenMode(policy, in.TokenType, "vault") {
		return TokenVault{}, newServiceError(http.StatusForbidden, "policy_denied", "vault mode is blocked for selected token type")
	}
	if !policyAllowsTokenFormat(policy, in.TokenType, in.Format) {
		return TokenVault{}, newServiceError(http.StatusForbidden, "policy_denied", "token format is blocked for selected token type")
	}
	if in.TokenType == "custom" {
		if !policy.AllowCustomRegexTokens {
			return TokenVault{}, newServiceError(http.StatusForbidden, "policy_denied", "custom regex tokenization is disabled by policy")
		}
		if err := validateCustomRegexPolicy(in.CustomRegex, policy); err != nil {
			return TokenVault{}, err
		}
	}
	if s.keycore != nil {
		item, err := s.keycore.GetKey(ctx, tenantID, in.KeyID)
		if err != nil {
			return TokenVault{}, newServiceError(http.StatusBadRequest, "bad_request", "key_id could not be resolved in keycore")
		}
		if err := validateDataProtectionKeyMetadata(item, "token vault encryption"); err != nil {
			return TokenVault{}, err
		}
	}
	in.ID = newID("vault")
	in.TenantID = tenantID
	if err := s.store.CreateTokenVault(ctx, in); err != nil {
		return TokenVault{}, err
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.token_vault_created", tenantID, map[string]interface{}{
		"vault_id":     in.ID,
		"token_type":   in.TokenType,
		"token_format": in.Format,
	})
	return s.store.GetTokenVault(ctx, tenantID, in.ID)
}

func (s *Service) ListTokenVaults(ctx context.Context, tenantID string, limit int, offset int) ([]TokenVault, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	return s.store.ListTokenVaults(ctx, tenantID, limit, offset)
}

func (s *Service) GetTokenVault(ctx context.Context, tenantID string, vaultID string) (map[string]interface{}, error) {
	tenantID = strings.TrimSpace(tenantID)
	vaultID = strings.TrimSpace(vaultID)
	if tenantID == "" || vaultID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and vault_id are required")
	}
	vault, err := s.store.GetTokenVault(ctx, tenantID, vaultID)
	if err != nil {
		return nil, err
	}
	count, err := s.store.CountTokensByVault(ctx, tenantID, vaultID)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"vault": vault,
		"stats": map[string]interface{}{
			"token_count": count,
		},
	}, nil
}

func (s *Service) DeleteTokenVault(ctx context.Context, tenantID string, vaultID string, governanceApproved bool) error {
	tenantID = strings.TrimSpace(tenantID)
	vaultID = strings.TrimSpace(vaultID)
	if tenantID == "" || vaultID == "" {
		return newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and vault_id are required")
	}
	if !governanceApproved {
		return newServiceError(http.StatusForbidden, "governance_required", "token vault deletion requires governance approval")
	}
	if err := s.store.DeleteTokenVault(ctx, tenantID, vaultID); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.token_vault_deleted", tenantID, map[string]interface{}{
		"vault_id": vaultID,
	})
	return nil
}

func (s *Service) Tokenize(ctx context.Context, req TokenizeRequest) ([]map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Mode = normalizeTokenMode(req.Mode)
	req.VaultID = strings.TrimSpace(req.VaultID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.TokenType = strings.ToLower(strings.TrimSpace(req.TokenType))
	req.Format = strings.ToLower(strings.TrimSpace(req.Format))
	req.CustomRegex = strings.TrimSpace(req.CustomRegex)
	if req.TenantID == "" || req.VaultID == "" {
		if req.Mode != "vaultless" {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and vault_id are required")
		}
	}
	if req.TenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if len(req.Values) == 0 {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "values cannot be empty")
	}
	policy, err := s.mustDataProtectionPolicy(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	if !policy.AllowBulkTokenize && len(req.Values) > 1 {
		return nil, newServiceError(http.StatusForbidden, "policy_denied", "bulk tokenization is disabled by policy")
	}
	if len(req.Values) > policy.MaxTokenBatch {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "batch size exceeds configured policy limit")
	}
	if policy.RequireTokenContextTags {
		if err := validateRequiredContextTags(req.MetadataTags, policy.RequiredTokenContextKeys); err != nil {
			return nil, err
		}
	}
	if req.OneTimeToken && !policy.AllowOneTimeTokens {
		return nil, newServiceError(http.StatusForbidden, "policy_denied", "one-time tokenization is disabled by policy")
	}

	vault := TokenVault{}
	if req.Mode == "vaultless" {
		if !policy.AllowVaultlessTokenization {
			return nil, newServiceError(http.StatusForbidden, "policy_denied", "vaultless tokenization is disabled by policy")
		}
		if req.KeyID == "" {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", "key_id is required for vaultless tokenization")
		}
		if req.TokenType == "" {
			req.TokenType = "custom"
		}
		if !isSupportedTokenType(req.TokenType) {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", "unsupported token_type")
		}
		if req.TokenType == "custom" && !policy.AllowCustomRegexTokens {
			return nil, newServiceError(http.StatusForbidden, "policy_denied", "custom regex tokenization is disabled by policy")
		}
		if req.TokenType == "custom" && req.CustomRegex != "" {
			if err := validateCustomRegexPolicy(req.CustomRegex, policy); err != nil {
				return nil, err
			}
		}
		if req.Format == "" {
			req.Format = "deterministic"
		} else {
			req.Format = normalizeTokenFormat(req.Format)
		}
		if req.Format == "random" {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", "vaultless mode does not support random format because detokenization is not possible")
		}
		if !policyAllowsTokenMode(policy, req.TokenType, "vaultless") {
			return nil, newServiceError(http.StatusForbidden, "policy_denied", "vaultless mode is blocked for selected token type")
		}
		if !policyAllowsTokenFormat(policy, req.TokenType, req.Format) {
			return nil, newServiceError(http.StatusForbidden, "policy_denied", "token format is blocked for selected token type")
		}
		vault = TokenVault{
			ID:          "vaultless",
			TenantID:    req.TenantID,
			Mode:        "vaultless",
			Name:        "vaultless",
			TokenType:   req.TokenType,
			Format:      req.Format,
			KeyID:       req.KeyID,
			CustomRegex: req.CustomRegex,
		}
	} else {
		var err error
		vault, err = s.store.GetTokenVault(ctx, req.TenantID, req.VaultID)
		if err != nil {
			return nil, err
		}
		vault.Mode = "vault"
		if !policyAllowsTokenMode(policy, vault.TokenType, "vault") {
			return nil, newServiceError(http.StatusForbidden, "policy_denied", "vault mode is blocked for selected token type")
		}
		if !policyAllowsTokenFormat(policy, vault.TokenType, vault.Format) {
			return nil, newServiceError(http.StatusForbidden, "policy_denied", "token format is blocked for selected token type")
		}
		if vault.TokenType == "custom" && !policy.AllowCustomRegexTokens {
			return nil, newServiceError(http.StatusForbidden, "policy_denied", "custom regex tokenization is disabled by policy")
		}
		if vault.TokenType == "custom" && strings.TrimSpace(vault.CustomRegex) != "" {
			if err := validateCustomRegexPolicy(vault.CustomRegex, policy); err != nil {
				return nil, err
			}
		}
		if policy.RequireTokenTTL && req.TTLHours <= 0 {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", "token ttl is required by policy")
		}
	}
	maxTTL := policy.MaxTokenTTLHours
	if policy.TokenMetadataRetentionDays > 0 {
		retentionTTL := policy.TokenMetadataRetentionDays * 24
		if maxTTL == 0 || retentionTTL < maxTTL {
			maxTTL = retentionTTL
		}
	}
	if maxTTL > 0 && req.TTLHours > maxTTL {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "token ttl exceeds configured policy limit")
	}
	if err := s.enforceKeycoreMetering(ctx, req.TenantID, vault.KeyID, "encrypt"); err != nil {
		return nil, err
	}

	key, err := s.resolveWorkingKey(ctx, req.TenantID, vault.KeyID, "tokenize")
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(key)

	results := make([]map[string]interface{}, 0, len(req.Values))
	created := 0
	for _, raw := range req.Values {
		value := strings.TrimSpace(raw)
		if value == "" {
			results = append(results, map[string]interface{}{
				"input": value,
				"error": "value cannot be empty",
			})
			continue
		}
		token, originalHash, metadata, err := buildTokenForVault(vault, key, value)
		if err != nil {
			results = append(results, map[string]interface{}{
				"input": value,
				"error": err.Error(),
			})
			continue
		}
		if req.Mode == "vaultless" {
			out := map[string]interface{}{
				"input":      value,
				"token":      token,
				"mode":       "vaultless",
				"token_type": vault.TokenType,
				"format":     vault.Format,
				"reused":     false,
			}
			if req.TTLHours > 0 {
				out["ttl_ignored"] = true
			}
			results = append(results, out)
			continue
		}
		if !req.OneTimeToken && (vault.Format == "deterministic" || vault.Format == "irreversible") {
			if existing, err := s.store.GetTokenByHash(ctx, req.TenantID, req.VaultID, originalHash); err == nil {
				results = append(results, map[string]interface{}{
					"input":    value,
					"token":    existing.Token,
					"vault_id": req.VaultID,
					"reused":   true,
				})
				continue
			} else if !errors.Is(err, errNotFound) {
				return nil, err
			}
		}
		rec := TokenRecord{
			ID:             newID("tok"),
			TenantID:       req.TenantID,
			VaultID:        req.VaultID,
			Token:          token,
			OriginalHash:   originalHash,
			FormatMetadata: metadata,
			MetadataTags:   req.MetadataTags,
		}
		if req.OneTimeToken {
			rec.UseLimit = 1
		}
		if req.TTLHours > 0 {
			rec.ExpiresAt = s.now().Add(time.Duration(req.TTLHours) * time.Hour)
		} else if policy.TokenMetadataRetentionDays > 0 {
			rec.ExpiresAt = s.now().Add(time.Duration(policy.TokenMetadataRetentionDays) * 24 * time.Hour)
		}
		if vault.Format != "irreversible" {
			enc, err := encryptTokenValue(key, value)
			if err != nil {
				return nil, err
			}
			rec.OriginalEnc = enc
		} else {
			rec.OriginalEnc = []byte("IRREVERSIBLE")
		}
		if err := s.store.CreateToken(ctx, rec); err != nil {
			return nil, err
		}
		created++
		out := map[string]interface{}{
			"input":    value,
			"token":    token,
			"vault_id": req.VaultID,
			"reused":   false,
		}
		if !rec.ExpiresAt.IsZero() {
			out["expires_at"] = rec.ExpiresAt
		}
		if rec.UseLimit > 0 {
			out["use_limit"] = rec.UseLimit
		}
		results = append(results, out)
	}
	if req.Mode == "vaultless" {
		_ = s.publishAudit(ctx, "audit.dataprotect.tokenized", req.TenantID, map[string]interface{}{
			"mode":       "vaultless",
			"count":      len(results),
			"token_type": vault.TokenType,
			"format":     vault.Format,
			"key_id":     vault.KeyID,
			"one_time":   req.OneTimeToken,
		})
		return results, nil
	}
	if created > 0 {
		_ = s.publishAudit(ctx, "audit.dataprotect.tokenized", req.TenantID, map[string]interface{}{
			"vault_id": req.VaultID,
			"count":    created,
			"one_time": req.OneTimeToken,
		})
	}
	return results, nil
}

func (s *Service) Detokenize(ctx context.Context, req DetokenizeRequest) ([]map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Purpose = strings.TrimSpace(req.Purpose)
	req.Workflow = strings.TrimSpace(req.Workflow)
	req.Justification = strings.TrimSpace(req.Justification)
	if req.TenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if len(req.Tokens) == 0 {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tokens cannot be empty")
	}
	policy, err := s.mustDataProtectionPolicy(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	if !policy.AllowBulkDetokenize && len(req.Tokens) > 1 {
		return nil, newServiceError(http.StatusForbidden, "policy_denied", "bulk detokenization is disabled by policy")
	}
	if len(req.Tokens) > policy.MaxDetokenizeBatch {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "detokenize batch size exceeds configured policy limit")
	}
	if policy.RequireTokenContextTags {
		if err := validateRequiredContextTags(req.MetadataTags, policy.RequiredTokenContextKeys); err != nil {
			return nil, err
		}
	}
	if len(policy.DetokenizeAllowedPurposes) > 0 && !containsString(policy.DetokenizeAllowedPurposes, req.Purpose) {
		return nil, newServiceError(http.StatusForbidden, "policy_denied", "detokenize purpose is blocked by policy")
	}
	if len(policy.DetokenizeAllowedWorkflows) > 0 && !containsString(policy.DetokenizeAllowedWorkflows, req.Workflow) {
		return nil, newServiceError(http.StatusForbidden, "policy_denied", "detokenize workflow is blocked by policy")
	}
	if policy.RequireDetokenizeJustification && req.Justification == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "detokenize justification is required by policy")
	}
	if req.RenewTTLHours > 0 && !policy.AllowTokenRenewal {
		return nil, newServiceError(http.StatusForbidden, "policy_denied", "token lease renewal is disabled by policy")
	}
	results := make([]map[string]interface{}, 0, len(req.Tokens))
	keyCache := map[string][]byte{}
	defer func() {
		for _, k := range keyCache {
			pkgcrypto.Zeroize(k)
		}
	}()

	okCount := 0
	for _, tok := range req.Tokens {
		token := strings.TrimSpace(tok)
		if token == "" {
			results = append(results, map[string]interface{}{"token": token, "error": "token is required"})
			continue
		}
		record, err := s.store.GetTokenByValue(ctx, req.TenantID, token)
		if err != nil {
			if errors.Is(err, errNotFound) {
				results = append(results, map[string]interface{}{"token": token, "error": "not found"})
				continue
			}
			return nil, err
		}
		if !record.ExpiresAt.IsZero() && s.now().After(record.ExpiresAt) {
			results = append(results, map[string]interface{}{"token": token, "error": "token expired"})
			continue
		}
		vault, err := s.store.GetTokenVault(ctx, req.TenantID, record.VaultID)
		if err != nil {
			return nil, err
		}
		if vault.Format == "irreversible" {
			results = append(results, map[string]interface{}{"token": token, "error": "token is irreversible and cannot be detokenized"})
			continue
		}
		if record.UseLimit > 0 {
			updated, err := s.store.ConsumeTokenUse(ctx, req.TenantID, record.ID)
			if err != nil {
				if errors.Is(err, errNotFound) {
					results = append(results, map[string]interface{}{"token": token, "error": "token usage limit reached"})
					continue
				}
				return nil, err
			}
			record = updated
		}
		key, ok := keyCache[vault.KeyID]
		if !ok {
			if err := s.enforceKeycoreMetering(ctx, req.TenantID, vault.KeyID, "decrypt"); err != nil {
				return nil, err
			}
			key, err = s.resolveWorkingKey(ctx, req.TenantID, vault.KeyID, "tokenize")
			if err != nil {
				return nil, err
			}
			keyCache[vault.KeyID] = key
		}
		value, err := decryptTokenValue(key, record.OriginalEnc)
		if err != nil {
			results = append(results, map[string]interface{}{"token": token, "error": "decryption failed"})
			continue
		}
		if req.RenewTTLHours > 0 {
			maxTTL := policy.MaxTokenTTLHours
			if policy.TokenMetadataRetentionDays > 0 {
				retentionTTL := policy.TokenMetadataRetentionDays * 24
				if maxTTL == 0 || retentionTTL < maxTTL {
					maxTTL = retentionTTL
				}
			}
			if maxTTL > 0 && req.RenewTTLHours > maxTTL {
				results = append(results, map[string]interface{}{"token": token, "error": "renew ttl exceeds configured policy limit"})
				continue
			}
			renewed, err := s.store.RenewTokenLease(ctx, req.TenantID, record.ID, s.now().Add(time.Duration(req.RenewTTLHours)*time.Hour), policy.MaxTokenRenewals)
			if err != nil {
				if errors.Is(err, errNotFound) {
					results = append(results, map[string]interface{}{"token": token, "error": "token renewal limit reached"})
					continue
				}
				return nil, err
			}
			record = renewed
		}
		okCount++
		results = append(results, map[string]interface{}{
			"token":       token,
			"value":       value,
			"vault_id":    record.VaultID,
			"created_at":  record.CreatedAt,
			"expires_at":  record.ExpiresAt,
			"use_count":   record.UseCount,
			"use_limit":   record.UseLimit,
			"renew_count": record.RenewCount,
		})
	}
	if okCount > 0 {
		_ = s.publishAudit(ctx, "audit.dataprotect.detokenized", req.TenantID, map[string]interface{}{
			"count":           okCount,
			"purpose":         req.Purpose,
			"workflow":        req.Workflow,
			"renew_ttl_hours": req.RenewTTLHours,
		})
	}
	return results, nil
}

func (s *Service) FPEEncrypt(ctx context.Context, req FPERequest) (map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.Plaintext = strings.TrimSpace(req.Plaintext)
	algo := strings.ToUpper(strings.TrimSpace(req.Algorithm))
	if req.TenantID == "" || req.KeyID == "" || req.Plaintext == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, key_id and plaintext are required")
	}
	if req.Radix == 0 {
		req.Radix = 10
	}
	if err := s.enforceKeycoreMetering(ctx, req.TenantID, req.KeyID, "encrypt"); err != nil {
		return nil, err
	}
	key, err := s.resolveWorkingKey(ctx, req.TenantID, req.KeyID, "fpe")
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(key)
	var cipherText string
	switch algo {
	case "", "FF1":
		cipherText, err = ff1Encrypt(key, req.Tweak, req.Plaintext, req.Radix)
	case "FF3", "FF3-1", "FF31":
		cipherText, err = ff3Encrypt(key, req.Tweak, req.Plaintext, req.Radix)
	default:
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "unsupported FPE algorithm")
	}
	if err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.fpe_encrypted", req.TenantID, map[string]interface{}{
		"key_id":    req.KeyID,
		"algorithm": defaultString(algo, "FF1"),
		"radix":     req.Radix,
	})
	return map[string]interface{}{"ciphertext": cipherText}, nil
}

func (s *Service) FPEDecrypt(ctx context.Context, req FPERequest) (map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.Ciphertext = strings.TrimSpace(req.Ciphertext)
	algo := strings.ToUpper(strings.TrimSpace(req.Algorithm))
	if req.TenantID == "" || req.KeyID == "" || req.Ciphertext == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, key_id and ciphertext are required")
	}
	if req.Radix == 0 {
		req.Radix = 10
	}
	if err := s.enforceKeycoreMetering(ctx, req.TenantID, req.KeyID, "decrypt"); err != nil {
		return nil, err
	}
	key, err := s.resolveWorkingKey(ctx, req.TenantID, req.KeyID, "fpe")
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(key)
	var plain string
	switch algo {
	case "", "FF1":
		plain, err = ff1Decrypt(key, req.Tweak, req.Ciphertext, req.Radix)
	case "FF3", "FF3-1", "FF31":
		plain, err = ff3Decrypt(key, req.Tweak, req.Ciphertext, req.Radix)
	default:
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "unsupported FPE algorithm")
	}
	if err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", err.Error())
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.fpe_decrypted", req.TenantID, map[string]interface{}{
		"key_id":    req.KeyID,
		"algorithm": defaultString(algo, "FF1"),
		"radix":     req.Radix,
	})
	return map[string]interface{}{"plaintext": plain}, nil
}

func (s *Service) CreateMaskingPolicy(ctx context.Context, tenantID string, in MaskingPolicy) (MaskingPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return MaskingPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	in.Name = strings.TrimSpace(in.Name)
	in.TargetType = strings.TrimSpace(in.TargetType)
	in.FieldPath = strings.TrimSpace(in.FieldPath)
	in.MaskPattern = normalizeMaskPattern(in.MaskPattern)
	in.KeyID = strings.TrimSpace(in.KeyID)
	in.RolesFull = uniqueStrings(in.RolesFull)
	in.RolesPartial = uniqueStrings(in.RolesPartial)
	in.RolesRedacted = uniqueStrings(in.RolesRedacted)
	if in.Name == "" || in.TargetType == "" || in.FieldPath == "" {
		return MaskingPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "name, target_type and field_path are required")
	}
	if in.KeyID != "" && s.keycore != nil {
		if _, err := s.keycore.GetKey(ctx, tenantID, in.KeyID); err != nil {
			return MaskingPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "masking key_id could not be resolved in keycore")
		}
	}
	in.ID = newID("mask")
	in.TenantID = tenantID
	if err := s.store.CreateMaskingPolicy(ctx, in); err != nil {
		return MaskingPolicy{}, err
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.masking_policy_created", tenantID, map[string]interface{}{
		"policy_id": in.ID,
	})
	return s.store.GetMaskingPolicy(ctx, tenantID, in.ID)
}

func (s *Service) UpdateMaskingPolicy(ctx context.Context, tenantID string, id string, in MaskingPolicy) error {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and id are required")
	}
	in.ID = id
	in.TenantID = tenantID
	in.MaskPattern = normalizeMaskPattern(in.MaskPattern)
	in.RolesFull = uniqueStrings(in.RolesFull)
	in.RolesPartial = uniqueStrings(in.RolesPartial)
	in.RolesRedacted = uniqueStrings(in.RolesRedacted)
	if err := s.store.UpdateMaskingPolicy(ctx, in); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.masking_policy_updated", tenantID, map[string]interface{}{
		"policy_id": id,
	})
	return nil
}

func (s *Service) DeleteMaskingPolicy(ctx context.Context, tenantID string, id string) error {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and id are required")
	}
	if err := s.store.DeleteMaskingPolicy(ctx, tenantID, id); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.masking_policy_deleted", tenantID, map[string]interface{}{
		"policy_id": id,
	})
	return nil
}

func (s *Service) ListMaskingPolicies(ctx context.Context, tenantID string) ([]MaskingPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	return s.store.ListMaskingPolicies(ctx, tenantID)
}

func (s *Service) ApplyMask(ctx context.Context, req MaskRequest) (map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.PolicyID = strings.TrimSpace(req.PolicyID)
	req.Role = strings.TrimSpace(req.Role)
	if req.TenantID == "" || req.PolicyID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and policy_id are required")
	}
	policyCfg, err := s.mustDataProtectionPolicy(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	policy, err := s.store.GetMaskingPolicy(ctx, req.TenantID, req.PolicyID)
	if err != nil {
		return nil, err
	}
	out := cloneMap(req.Data)
	raw, ok := getPathValue(out, policy.FieldPath)
	if !ok {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "policy field_path does not exist in payload")
	}
	if containsString(policy.RolesFull, req.Role) {
		return out, nil
	}
	pattern := policy.MaskPattern
	if rolePattern, ok := policyCfg.MaskingRolePolicy[strings.ToLower(req.Role)]; ok {
		rolePattern = strings.ToLower(strings.TrimSpace(rolePattern))
		if rolePattern == "none" {
			return out, nil
		}
		pattern = normalizeMaskPattern(rolePattern)
	}
	if containsString(policy.RolesRedacted, req.Role) {
		pattern = "full"
	}
	if containsString(policy.RolesPartial, req.Role) && pattern == "full" {
		pattern = "partial_last4"
	}
	seed := []byte{}
	if policy.Consistent {
		if policy.KeyID != "" {
			if err := s.enforceKeycoreMetering(ctx, req.TenantID, policy.KeyID, "encrypt"); err != nil {
				return nil, err
			}
			mk, err := s.resolveWorkingKey(ctx, req.TenantID, policy.KeyID, "masking")
			if err == nil {
				seed = hmacSHA256(mk, req.Role, policy.FieldPath, firstString(raw))
				pkgcrypto.Zeroize(mk)
			}
		}
		if len(seed) == 0 {
			tmp := keyFromHash([]byte(req.TenantID+"|"+policy.ID), "masking")
			seed = hmacSHA256(tmp, req.Role, policy.FieldPath, firstString(raw))
			pkgcrypto.Zeroize(tmp)
		}
	}
	masked := maskAny(raw, pattern, policy.Consistent, seed)
	_ = setPathValue(out, policy.FieldPath, masked)
	zeroizeAll(seed)
	if !req.Preview {
		_ = s.publishAudit(ctx, "audit.dataprotect.mask_applied", req.TenantID, map[string]interface{}{
			"policy_id": policy.ID,
			"role":      req.Role,
		})
	}
	return out, nil
}

func (s *Service) CreateRedactionPolicy(ctx context.Context, tenantID string, in RedactionPolicy) (RedactionPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return RedactionPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	policyCfg, err := s.mustDataProtectionPolicy(ctx, tenantID)
	if err != nil {
		return RedactionPolicy{}, err
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Scope = strings.TrimSpace(in.Scope)
	in.Action = normalizeRedactAction(in.Action)
	in.Placeholder = defaultString(in.Placeholder, "[REDACTED]")
	in.AppliesTo = uniqueStrings(in.AppliesTo)
	if in.Name == "" {
		return RedactionPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "name is required")
	}
	if len(in.Patterns) == 0 {
		in.Patterns = defaultRedactionPatterns()
	}
	if !containsString(policyCfg.AllowedRedactionActions, in.Action) {
		return RedactionPolicy{}, newServiceError(http.StatusForbidden, "policy_denied", "redaction action is blocked by policy")
	}
	for _, pattern := range in.Patterns {
		if !isAllowedRedactionDetector(pattern, policyCfg.AllowedRedactionDetectors) {
			return RedactionPolicy{}, newServiceError(http.StatusForbidden, "policy_denied", "redaction detector is blocked by policy")
		}
	}
	in.ID = newID("redact")
	in.TenantID = tenantID
	if err := s.store.CreateRedactionPolicy(ctx, in); err != nil {
		return RedactionPolicy{}, err
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.redaction_policy_created", tenantID, map[string]interface{}{
		"policy_id": in.ID,
	})
	return s.store.GetRedactionPolicy(ctx, tenantID, in.ID)
}

func (s *Service) ListRedactionPolicies(ctx context.Context, tenantID string) ([]RedactionPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	return s.store.ListRedactionPolicies(ctx, tenantID)
}

func (s *Service) Redact(ctx context.Context, req RedactRequest) (map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.PolicyID = strings.TrimSpace(req.PolicyID)
	req.ContentType = strings.ToLower(strings.TrimSpace(req.ContentType))
	req.EndpointName = strings.TrimSpace(req.EndpointName)
	if req.TenantID == "" || strings.TrimSpace(req.Content) == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and content are required")
	}
	policyCfg, err := s.mustDataProtectionPolicy(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	if req.DetectOnly && !policyCfg.AllowRedactionDetectOnly {
		return nil, newServiceError(http.StatusForbidden, "policy_denied", "redaction detect-only mode is disabled by policy")
	}
	policy := RedactionPolicy{
		Action:      "replace_placeholder",
		Placeholder: "[REDACTED]",
		Patterns:    defaultRedactionPatterns(),
		Scope:       "all",
		AppliesTo:   []string{"*"},
	}
	if req.PolicyID != "" {
		item, err := s.store.GetRedactionPolicy(ctx, req.TenantID, req.PolicyID)
		if err != nil {
			return nil, err
		}
		policy = item
	}
	if !containsString(policyCfg.AllowedRedactionActions, policy.Action) {
		return nil, newServiceError(http.StatusForbidden, "policy_denied", "redaction action is blocked by policy")
	}
	filteredPatterns := make([]RedactionPattern, 0, len(policy.Patterns))
	for _, pattern := range policy.Patterns {
		if isAllowedRedactionDetector(pattern, policyCfg.AllowedRedactionDetectors) {
			filteredPatterns = append(filteredPatterns, pattern)
		}
	}
	if len(filteredPatterns) == 0 {
		return nil, newServiceError(http.StatusForbidden, "policy_denied", "all redaction detectors are blocked by policy")
	}
	policy.Patterns = filteredPatterns
	if !matchesRedactionScope(policy, req.EndpointName) {
		return map[string]interface{}{
			"content": req.Content,
			"matches": []map[string]interface{}{},
		}, nil
	}
	matches := detectMatches(req.Content, policy.Patterns)
	if req.DetectOnly {
		return map[string]interface{}{
			"matches": matches,
		}, nil
	}
	redacted := applyRedaction(req.Content, matches, policy.Action, policy.Placeholder)
	_ = s.publishAudit(ctx, "audit.dataprotect.redacted", req.TenantID, map[string]interface{}{
		"policy_id":    defaultString(policy.ID, "default"),
		"match_count":  len(matches),
		"content_type": defaultString(req.ContentType, "text"),
	})
	return map[string]interface{}{
		"content": redacted,
		"matches": matches,
	}, nil
}

func (s *Service) EncryptFields(ctx context.Context, req AppFieldRequest) (map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.DocumentID = defaultString(strings.TrimSpace(req.DocumentID), newID("doc"))
	if req.TenantID == "" || req.KeyID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key_id are required")
	}
	if len(req.Fields) == 0 {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "fields are required")
	}
	algorithm := normalizeFieldAlgorithm(req.Algorithm, req.Searchable)
	policy, err := s.mustDataProtectionPolicy(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	if err := s.enforceAppCryptoPayloadPolicy(policy, req, len(req.Fields)); err != nil {
		return nil, err
	}
	if len(req.Fields) > policy.MaxFieldsPerOperation {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "field count exceeds configured policy limit")
	}
	if err := s.enforceUseCaseAlgorithmPolicy(policy, "field_level", algorithm); err != nil {
		return nil, err
	}
	if req.Searchable && !policy.AllowSearchableEncryption {
		return nil, newServiceError(http.StatusForbidden, "policy_denied", "searchable encryption is disabled by policy")
	}
	if strings.EqualFold(algorithm, "AES-SIV") && !policy.AllowDeterministicEncryption {
		return nil, newServiceError(http.StatusForbidden, "policy_denied", "deterministic encryption is disabled by policy")
	}
	if err := s.enforceAADContractPolicy(policy, req.TenantID, req.AAD); err != nil {
		return nil, err
	}
	if docRaw, jErr := json.Marshal(req.Document); jErr == nil && len(docRaw) > policy.MaxDocumentBytes {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "document size exceeds configured policy limit")
	}
	if err := s.enforceKeycoreMetering(ctx, req.TenantID, req.KeyID, "encrypt"); err != nil {
		return nil, err
	}
	key, err := s.resolveWorkingKeyForDataPolicy(ctx, req.TenantID, req.KeyID, "field-encrypt", policy)
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(key)

	doc := cloneMap(req.Document)
	done := make([]string, 0, len(req.Fields))
	for _, field := range uniqueStrings(req.Fields) {
		if err := s.enforceFieldScopePolicy(policy, field, false); err != nil {
			return nil, err
		}
		val, ok := getPathValue(doc, field)
		if !ok {
			continue
		}
		raw := encodeFieldValue(val)
		iv, ciphertext, err := encryptWithAlgorithm(key, algorithm, raw, []byte(req.AAD), req.Searchable || strings.EqualFold(algorithm, "AES-SIV"))
		pkgcrypto.Zeroize(raw)
		if err != nil {
			return nil, err
		}
		_ = setPathValue(doc, field, map[string]interface{}{
			"enc": "v1",
			"alg": algorithm,
			"ct":  b64(ciphertext),
			"iv":  b64(iv),
		})
		_ = s.store.CreateFLEMetadata(ctx, FLEMetadata{
			ID:         newID("fle"),
			TenantID:   req.TenantID,
			DocumentID: req.DocumentID,
			FieldPath:  field,
			KeyID:      req.KeyID,
			KeyVersion: 1,
			Algorithm:  algorithm,
			IV:         iv,
			Searchable: req.Searchable || strings.EqualFold(algorithm, "AES-SIV"),
		})
		done = append(done, field)
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.field_encrypted", req.TenantID, map[string]interface{}{
		"document_id": req.DocumentID,
		"fields":      done,
		"algorithm":   algorithm,
	})
	return map[string]interface{}{
		"document":         doc,
		"document_id":      req.DocumentID,
		"fields_encrypted": done,
	}, nil
}

func (s *Service) DecryptFields(ctx context.Context, req AppFieldRequest) (map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.DocumentID = strings.TrimSpace(req.DocumentID)
	if req.TenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if len(req.Fields) == 0 {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "fields are required")
	}
	policy, err := s.mustDataProtectionPolicy(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	if err := s.enforceAppCryptoPayloadPolicy(policy, req, len(req.Fields)); err != nil {
		return nil, err
	}
	if len(req.Fields) > policy.MaxFieldsPerOperation {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "field count exceeds configured policy limit")
	}
	if err := s.enforceAADContractPolicy(policy, req.TenantID, req.AAD); err != nil {
		return nil, err
	}
	doc := cloneMap(req.Document)
	metaByField := map[string]FLEMetadata{}
	if req.DocumentID != "" {
		if items, err := s.store.ListFLEMetadataByDocument(ctx, req.TenantID, req.DocumentID); err == nil {
			for _, item := range items {
				metaByField[item.FieldPath] = item
			}
		}
	}
	keyCache := map[string][]byte{}
	metered := map[string]struct{}{}
	defer func() {
		for _, k := range keyCache {
			pkgcrypto.Zeroize(k)
		}
	}()

	done := make([]string, 0, len(req.Fields))
	for _, field := range uniqueStrings(req.Fields) {
		if err := s.enforceFieldScopePolicy(policy, field, true); err != nil {
			return nil, err
		}
		v, ok := getPathValue(doc, field)
		if !ok {
			continue
		}
		block, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		alg := strings.ToUpper(strings.TrimSpace(firstString(block["alg"])))
		if alg == "" {
			alg = "AES-GCM"
		}
		if err := s.enforceUseCaseAlgorithmPolicy(policy, "field_level", alg); err != nil {
			return nil, err
		}
		if strings.EqualFold(alg, "AES-SIV") && !policy.AllowDeterministicEncryption {
			return nil, newServiceError(http.StatusForbidden, "policy_denied", "deterministic encryption is disabled by policy")
		}
		keyID := req.KeyID
		if keyID == "" {
			keyID = strings.TrimSpace(metaByField[field].KeyID)
		}
		if keyID == "" {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", "key_id is required for decryption")
		}
		key, ok := keyCache[keyID]
		if !ok {
			if _, seen := metered[keyID]; !seen {
				if err := s.enforceKeycoreMetering(ctx, req.TenantID, keyID, "decrypt"); err != nil {
					return nil, err
				}
				metered[keyID] = struct{}{}
			}
			var err error
			key, err = s.resolveWorkingKeyForDataPolicy(ctx, req.TenantID, keyID, "field-encrypt", policy)
			if err != nil {
				return nil, err
			}
			keyCache[keyID] = key
		}
		ct, err := b64d(firstString(block["ct"]))
		if err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", "invalid field ciphertext")
		}
		iv, err := b64d(firstString(block["iv"]))
		if err != nil {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", "invalid field iv")
		}
		pt, err := decryptWithAlgorithm(key, alg, iv, ct, []byte(req.AAD), strings.EqualFold(alg, "AES-SIV"))
		if err != nil {
			return nil, err
		}
		_ = setPathValue(doc, field, string(pt))
		pkgcrypto.Zeroize(pt)
		done = append(done, field)
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.field_decrypted", req.TenantID, map[string]interface{}{
		"document_id": defaultString(req.DocumentID, "unknown"),
		"fields":      done,
	})
	return map[string]interface{}{
		"document":         doc,
		"fields_decrypted": done,
	}, nil
}

func (s *Service) EnvelopeEncrypt(ctx context.Context, req EnvelopeRequest) (map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	if req.TenantID == "" || req.KeyID == "" || req.Plaintext == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, key_id and plaintext are required")
	}
	policy, err := s.mustDataProtectionPolicy(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	if err := s.enforceAppCryptoPayloadPolicy(policy, req, 1); err != nil {
		return nil, err
	}
	if err := s.enforceEnvelopePolicyEncrypt(policy, req.KeyID); err != nil {
		return nil, err
	}
	alg := normalizeFieldAlgorithm(req.Algorithm, false)
	if err := s.enforceUseCaseAlgorithmPolicy(policy, "envelope", alg); err != nil {
		return nil, err
	}
	if strings.EqualFold(alg, "AES-SIV") && !policy.AllowDeterministicEncryption {
		return nil, newServiceError(http.StatusForbidden, "policy_denied", "deterministic encryption is disabled by policy")
	}
	if err := s.enforceAADContractPolicy(policy, req.TenantID, req.AAD); err != nil {
		return nil, err
	}
	if err := s.enforceKeycoreMetering(ctx, req.TenantID, req.KeyID, "wrap"); err != nil {
		return nil, err
	}
	kek, err := s.resolveWorkingKeyForDataPolicy(ctx, req.TenantID, req.KeyID, "envelope-kek", policy)
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(kek)
	dek := randBytes(32)
	defer pkgcrypto.Zeroize(dek)

	iv, ciphertext, err := encryptWithAlgorithm(dek, alg, []byte(req.Plaintext), []byte(req.AAD), false)
	if err != nil {
		return nil, err
	}
	dekIV, wrappedDEK, err := encryptWithAlgorithm(kek, "AES-GCM", dek, nil, false)
	if err != nil {
		return nil, err
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.envelope_encrypted", req.TenantID, map[string]interface{}{
		"algorithm": alg,
		"key_id":    req.KeyID,
	})
	return map[string]interface{}{
		"ciphertext":     b64(ciphertext),
		"iv":             b64(iv),
		"wrapped_dek":    b64(wrappedDEK),
		"wrapped_dek_iv": b64(dekIV),
		"dek_created_at": s.now().Format(time.RFC3339),
		"algorithm":      alg,
	}, nil
}

func (s *Service) EnvelopeDecrypt(ctx context.Context, req EnvelopeRequest) (map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	if req.TenantID == "" || req.KeyID == "" || req.Ciphertext == "" || req.WrappedDEK == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, key_id, ciphertext and wrapped_dek are required")
	}
	policy, err := s.mustDataProtectionPolicy(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	if err := s.enforceAppCryptoPayloadPolicy(policy, req, 1); err != nil {
		return nil, err
	}
	alg := normalizeFieldAlgorithm(req.Algorithm, false)
	if err := s.enforceUseCaseAlgorithmPolicy(policy, "envelope", alg); err != nil {
		return nil, err
	}
	if strings.EqualFold(alg, "AES-SIV") && !policy.AllowDeterministicEncryption {
		return nil, newServiceError(http.StatusForbidden, "policy_denied", "deterministic encryption is disabled by policy")
	}
	if err := s.enforceAADContractPolicy(policy, req.TenantID, req.AAD); err != nil {
		return nil, err
	}
	if err := s.enforceEnvelopePolicyDecrypt(policy, req.KeyID, req.DEKCreatedAt); err != nil {
		return nil, err
	}
	if err := s.enforceKeycoreMetering(ctx, req.TenantID, req.KeyID, "unwrap"); err != nil {
		return nil, err
	}
	kek, err := s.resolveWorkingKeyForDataPolicy(ctx, req.TenantID, req.KeyID, "envelope-kek", policy)
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(kek)
	wrappedDEK, err := b64d(req.WrappedDEK)
	if err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "wrapped_dek must be base64")
	}
	wrappedIV, err := b64d(req.WrappedDEKIV)
	if err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "wrapped_dek_iv must be base64")
	}
	dek, err := decryptWithAlgorithm(kek, "AES-GCM", wrappedIV, wrappedDEK, nil, false)
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(dek)
	ct, err := b64d(req.Ciphertext)
	if err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "ciphertext must be base64")
	}
	iv, err := b64d(req.IV)
	if err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "iv must be base64")
	}
	pt, err := decryptWithAlgorithm(dek, alg, iv, ct, []byte(req.AAD), false)
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(pt)
	_ = s.publishAudit(ctx, "audit.dataprotect.envelope_decrypted", req.TenantID, map[string]interface{}{
		"algorithm": alg,
		"key_id":    req.KeyID,
	})
	return map[string]interface{}{
		"plaintext": string(pt),
	}, nil
}

func (s *Service) SearchableEncrypt(ctx context.Context, req SearchableRequest) (map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	if req.TenantID == "" || req.KeyID == "" || req.Plaintext == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, key_id and plaintext are required")
	}
	policy, err := s.mustDataProtectionPolicy(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	if err := s.enforceAppCryptoPayloadPolicy(policy, req, 1); err != nil {
		return nil, err
	}
	if err := s.enforceSearchablePolicy(policy, req.QueryType); err != nil {
		return nil, err
	}
	if err := s.enforceUseCaseAlgorithmPolicy(policy, "searchable", "AES-SIV"); err != nil {
		return nil, err
	}
	if err := s.enforceAADContractPolicy(policy, req.TenantID, req.AAD); err != nil {
		return nil, err
	}
	if err := s.enforceKeycoreMetering(ctx, req.TenantID, req.KeyID, "encrypt"); err != nil {
		return nil, err
	}
	key, err := s.resolveWorkingKeyForDataPolicy(ctx, req.TenantID, req.KeyID, "searchable", policy)
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(key)
	_, ct, err := encryptWithAlgorithm(key, "AES-SIV", []byte(req.Plaintext), []byte(req.AAD), true)
	if err != nil {
		return nil, err
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.searchable_encrypted", req.TenantID, map[string]interface{}{
		"key_id": req.KeyID,
	})
	return map[string]interface{}{"ciphertext": b64(ct)}, nil
}

func (s *Service) SearchableDecrypt(ctx context.Context, req SearchableRequest) (map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	if req.TenantID == "" || req.KeyID == "" || req.Ciphertext == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, key_id and ciphertext are required")
	}
	policy, err := s.mustDataProtectionPolicy(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	if err := s.enforceAppCryptoPayloadPolicy(policy, req, 1); err != nil {
		return nil, err
	}
	if err := s.enforceSearchablePolicy(policy, req.QueryType); err != nil {
		return nil, err
	}
	if err := s.enforceUseCaseAlgorithmPolicy(policy, "searchable", "AES-SIV"); err != nil {
		return nil, err
	}
	if err := s.enforceAADContractPolicy(policy, req.TenantID, req.AAD); err != nil {
		return nil, err
	}
	if err := s.enforceKeycoreMetering(ctx, req.TenantID, req.KeyID, "decrypt"); err != nil {
		return nil, err
	}
	key, err := s.resolveWorkingKeyForDataPolicy(ctx, req.TenantID, req.KeyID, "searchable", policy)
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(key)
	ct, err := b64d(req.Ciphertext)
	if err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "ciphertext must be base64")
	}
	pt, err := decryptWithAlgorithm(key, "AES-SIV", nil, ct, []byte(req.AAD), true)
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(pt)
	_ = s.publishAudit(ctx, "audit.dataprotect.searchable_decrypted", req.TenantID, map[string]interface{}{
		"key_id": req.KeyID,
	})
	return map[string]interface{}{"plaintext": string(pt)}, nil
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "dataprotect",
		"action":    subject,
		"timestamp": s.now().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}

func (s *Service) enforceKeycoreMetering(ctx context.Context, tenantID string, keyID string, operation string) error {
	tenantID = strings.TrimSpace(tenantID)
	keyID = strings.TrimSpace(keyID)
	if tenantID == "" || keyID == "" {
		return newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key_id are required")
	}
	if s.keycore == nil {
		return newServiceError(http.StatusServiceUnavailable, "keycore_unavailable", "keycore usage metering is required")
	}
	if err := s.keycore.MeterUsage(ctx, tenantID, keyID, operation); err != nil {
		var herr keycoreHTTPError
		if errors.As(err, &herr) {
			msg := strings.TrimSpace(herr.Message)
			if msg == "" {
				msg = "keycore usage metering failed"
			}
			switch herr.Status {
			case http.StatusTooManyRequests:
				return newServiceError(http.StatusTooManyRequests, "ops_limit_reached", msg)
			case http.StatusNotFound:
				return newServiceError(http.StatusNotFound, "not_found", msg)
			case http.StatusForbidden:
				return newServiceError(http.StatusForbidden, "access_denied", msg)
			case http.StatusConflict:
				return newServiceError(http.StatusConflict, "invalid_key_status", msg)
			case http.StatusBadRequest:
				code := strings.TrimSpace(herr.Code)
				if code == "" {
					code = "bad_request"
				}
				return newServiceError(http.StatusBadRequest, code, msg)
			default:
				return newServiceError(http.StatusBadGateway, "keycore_meter_failed", msg)
			}
		}
		msg := strings.TrimSpace(err.Error())
		if msg == "" {
			msg = "keycore usage metering failed"
		}
		return newServiceError(http.StatusBadGateway, "keycore_meter_failed", msg)
	}
	return nil
}

func (s *Service) resolveWorkingKey(ctx context.Context, tenantID string, keyID string, purpose string) ([]byte, error) {
	return s.resolveWorkingKeyInternal(ctx, tenantID, keyID, purpose, nil)
}

func (s *Service) resolveWorkingKeyForDataPolicy(ctx context.Context, tenantID string, keyID string, purpose string, policy DataProtectionPolicy) ([]byte, error) {
	return s.resolveWorkingKeyInternal(ctx, tenantID, keyID, purpose, &policy)
}

func (s *Service) resolveWorkingKeyInternal(ctx context.Context, tenantID string, keyID string, purpose string, policy *DataProtectionPolicy) ([]byte, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "key_id is required")
	}
	material := []byte{}
	if s.keycore != nil {
		item, err := s.keycore.GetKey(ctx, tenantID, keyID)
		if err != nil {
			return nil, err
		}
		if err := validateDataProtectionKeyMetadata(item, purpose); err != nil {
			return nil, err
		}
		if policy != nil {
			if err := enforceDataEncryptionKeyClassPolicy(*policy, item); err != nil {
				return nil, err
			}
		}
		if m := firstString(item["material_b64"]); m != "" {
			if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(m)); err == nil && len(raw) > 0 {
				material = raw
			}
		}
		if len(material) == 0 {
			seed := firstString(item["material"], item["wrapped_material"], item["kcv"], item["id"])
			if seed != "" {
				material = []byte(seed)
			}
		}
	}
	if len(material) == 0 {
		// No key bytes are persisted in this service; derive an ephemeral working key per request.
		material = []byte(tenantID + "|" + keyID + "|" + purpose)
	}
	out := keyFromHash(material, "dataprotect-"+purpose)
	pkgcrypto.Zeroize(material)
	return out, nil
}

func enforceDataEncryptionKeyClassPolicy(policy DataProtectionPolicy, item map[string]interface{}) error {
	keyType := strings.ToLower(strings.TrimSpace(firstString(item["key_type"])))
	if policy.RequireSymmetricKeys && keyType != "" && keyType != "symmetric" {
		return newServiceError(http.StatusForbidden, "policy_denied", "selected key type is blocked by key-class binding policy")
	}
	alg := strings.ToUpper(strings.TrimSpace(firstString(item["algorithm"])))
	if policy.RequireFIPSKeys {
		if flag, ok := item["fips_compliant"]; ok {
			if !isTruthy(flag) {
				return newServiceError(http.StatusForbidden, "policy_denied", "selected key is not FIPS-compliant")
			}
		} else if !isFIPSApprovedDataAlgorithm(alg) {
			return newServiceError(http.StatusForbidden, "policy_denied", "selected key algorithm is not FIPS-approved")
		}
	}
	if policy.MinKeySizeBits > 0 {
		bits := extractInt(item["key_strength"])
		if bits == 0 {
			bits = extractInt(item["size"])
		}
		if bits == 0 {
			bits = extractInt(item["key_size"])
		}
		if bits == 0 {
			bits = extractInt(item["bits"])
		}
		if bits == 0 {
			bits = extractKeyBitsFromAlgorithm(alg)
		}
		if bits == 0 || bits < policy.MinKeySizeBits {
			return newServiceError(http.StatusForbidden, "policy_denied", "selected key size/curve does not satisfy minimum key size policy")
		}
	}
	return nil
}

func buildTokenForVault(vault TokenVault, key []byte, value string) (string, string, map[string]interface{}, error) {
	hashB := hmacSHA256(key, "token-hash", value)
	defer zeroizeAll(hashB)
	hash := hex.EncodeToString(hashB)
	meta := map[string]interface{}{
		"input_length": len(value),
		"mode":         normalizeTokenMode(vault.Mode),
		"token_type":   vault.TokenType,
		"format":       vault.Format,
	}
	switch vault.Format {
	case "deterministic":
		raw := hmacSHA256(key, "token-deterministic", vault.ID, vault.Mode, vault.TokenType, vault.Format, value)
		defer zeroizeAll(raw)
		return "tokd_" + hex.EncodeToString(raw)[:24], hash, meta, nil
	case "irreversible":
		return "toki_" + hash[:24], hash, meta, nil
	case "format_preserving":
		return formatPreservingToken(vault, key, value), hash, meta, nil
	default:
		return "tokr_" + hex.EncodeToString(randBytes(12)), hash, meta, nil
	}
}

func formatPreservingToken(vault TokenVault, key []byte, value string) string {
	switch vault.TokenType {
	case "credit_card":
		return formatPANLike(value, key)
	case "email":
		return formatEmailLike(value, key)
	case "ssn", "phone", "iban", "custom":
		return formatCharsetLike(value, key, vault.TokenType)
	default:
		return formatCharsetLike(value, key, "generic")
	}
}

func formatPANLike(value string, key []byte) string {
	digits := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] >= '0' && value[i] <= '9' {
			digits = append(digits, value[i])
		}
	}
	if len(digits) < 13 {
		return formatCharsetLike(value, key, "pan-fallback")
	}
	stream := makeTokenStream(key, "pan", len(digits))
	for i := 0; i < len(digits)-1; i++ {
		digits[i] = byte('0' + int(stream[i]%10))
	}
	digits[len(digits)-1] = luhnCheckDigit(digits[:len(digits)-1])
	out := []byte(value)
	j := 0
	for i := 0; i < len(out) && j < len(digits); i++ {
		if out[i] >= '0' && out[i] <= '9' {
			out[i] = digits[j]
			j++
		}
	}
	zeroizeAll(stream)
	return string(out)
}

func formatEmailLike(value string, key []byte) string {
	parts := strings.Split(value, "@")
	if len(parts) != 2 {
		return formatCharsetLike(value, key, "email-fallback")
	}
	local := formatCharsetLike(parts[0], key, "email-local")
	return local + "@" + parts[1]
}

func formatCharsetLike(value string, key []byte, purpose string) string {
	if value == "" {
		return value
	}
	stream := makeTokenStream(key, "fmt-"+purpose, len(value)*2)
	defer zeroizeAll(stream)
	out := []rune(value)
	cursor := 0
	for i, r := range out {
		switch {
		case r >= '0' && r <= '9':
			out[i] = rune('0' + int(stream[cursor]%10))
			cursor++
		case r >= 'a' && r <= 'z':
			out[i] = rune('a' + int(stream[cursor]%26))
			cursor++
		case r >= 'A' && r <= 'Z':
			out[i] = rune('A' + int(stream[cursor]%26))
			cursor++
		default:
			// preserve separators and punctuation.
		}
	}
	return string(out)
}

func makeTokenStream(key []byte, purpose string, n int) []byte {
	if n <= 0 {
		return []byte{}
	}
	out := make([]byte, 0, n)
	counter := 0
	for len(out) < n {
		block := hmacSHA256(key, "stream", purpose, strconvI(counter))
		out = append(out, block...)
		zeroizeAll(block)
		counter++
	}
	return out[:n]
}

func luhnCheckDigit(input []byte) byte {
	sum := 0
	double := true
	for i := len(input) - 1; i >= 0; i-- {
		d := int(input[i] - '0')
		if double {
			d = d * 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	cd := (10 - (sum % 10)) % 10
	return byte('0' + cd)
}

func encryptTokenValue(key []byte, value string) ([]byte, error) {
	// Token vault original values are stored encrypted-at-rest and only decrypted during detokenization.
	iv, ct, err := encryptWithAlgorithm(key, "AES-GCM", []byte(value), nil, false)
	if err != nil {
		return nil, err
	}
	return []byte("v1." + b64(iv) + "." + b64(ct)), nil
}

func decryptTokenValue(key []byte, payload []byte) (string, error) {
	parts := strings.Split(strings.TrimSpace(string(payload)), ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return "", errors.New("invalid token payload")
	}
	iv, err := b64d(parts[1])
	if err != nil {
		return "", err
	}
	ct, err := b64d(parts[2])
	if err != nil {
		return "", err
	}
	pt, err := decryptWithAlgorithm(key, "AES-GCM", iv, ct, nil, false)
	if err != nil {
		return "", err
	}
	defer pkgcrypto.Zeroize(pt)
	return string(pt), nil
}

func maskAny(v interface{}, pattern string, consistent bool, seed []byte) interface{} {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return maskString(x, pattern, consistent, seed)
	case []byte:
		return maskString(string(x), pattern, consistent, seed)
	default:
		return maskString(firstString(v), pattern, consistent, seed)
	}
}

func defaultRedactionPatterns() []RedactionPattern {
	return []RedactionPattern{
		{Type: "regex", Pattern: regexEmail.String(), Label: "EMAIL"},
		{Type: "regex", Pattern: regexPhone.String(), Label: "PHONE"},
		{Type: "regex", Pattern: regexSSN.String(), Label: "SSN"},
		{Type: "regex", Pattern: regexPAN.String(), Label: "PAN"},
		{Type: "ner", Pattern: regexName.String(), Label: "PERSON"},
	}
}

func matchesRedactionScope(policy RedactionPolicy, endpoint string) bool {
	if len(policy.AppliesTo) == 0 {
		return true
	}
	if containsString(policy.AppliesTo, "*") {
		return true
	}
	if endpoint == "" {
		return true
	}
	return containsString(policy.AppliesTo, endpoint)
}

func detectMatches(content string, patterns []RedactionPattern) []map[string]interface{} {
	out := make([]map[string]interface{}, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(strings.TrimSpace(p.Pattern))
		if err != nil {
			continue
		}
		indices := re.FindAllStringIndex(content, -1)
		for _, idx := range indices {
			if len(idx) != 2 || idx[0] < 0 || idx[1] > len(content) || idx[0] >= idx[1] {
				continue
			}
			out = append(out, map[string]interface{}{
				"start": idx[0],
				"end":   idx[1],
				"label": defaultString(p.Label, strings.ToUpper(defaultString(p.Type, "REGEX"))),
				"match": content[idx[0]:idx[1]],
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		li := extractInt(out[i]["start"])
		lj := extractInt(out[j]["start"])
		if li == lj {
			return extractInt(out[i]["end"]) > extractInt(out[j]["end"])
		}
		return li < lj
	})
	return dedupOverlappingMatches(out)
}

func dedupOverlappingMatches(in []map[string]interface{}) []map[string]interface{} {
	if len(in) == 0 {
		return in
	}
	out := make([]map[string]interface{}, 0, len(in))
	lastEnd := -1
	for _, item := range in {
		start := extractInt(item["start"])
		end := extractInt(item["end"])
		if start < lastEnd {
			continue
		}
		out = append(out, item)
		lastEnd = end
	}
	return out
}

func applyRedaction(content string, matches []map[string]interface{}, action string, placeholder string) string {
	if len(matches) == 0 {
		return content
	}
	action = normalizeRedactAction(action)
	placeholder = defaultString(placeholder, "[REDACTED]")
	out := content
	for i := len(matches) - 1; i >= 0; i-- {
		start := extractInt(matches[i]["start"])
		end := extractInt(matches[i]["end"])
		if start < 0 || end > len(out) || start >= end {
			continue
		}
		match := out[start:end]
		repl := ""
		switch action {
		case "remove":
			repl = ""
		case "hash":
			repl = "hash_" + hashHex(match)[:16]
		default:
			repl = placeholder
		}
		out = out[:start] + repl + out[end:]
	}
	return out
}

func encodeFieldValue(v interface{}) []byte {
	switch x := v.(type) {
	case string:
		return []byte(x)
	case []byte:
		out := make([]byte, len(x))
		copy(out, x)
		return out
	default:
		raw, _ := json.Marshal(x)
		if len(raw) == 0 {
			return []byte(firstString(v))
		}
		return raw
	}
}

func isSupportedTokenType(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "credit_card", "ssn", "email", "phone", "iban", "bitlocker", "custom":
		return true
	default:
		return false
	}
}

func validateDataProtectionKeyMetadata(item map[string]interface{}, usage string) error {
	algorithm := strings.ToUpper(strings.TrimSpace(firstString(item["algorithm"])))
	keyType := strings.ToLower(strings.TrimSpace(firstString(item["key_type"])))
	purpose := strings.ToLower(strings.TrimSpace(firstString(item["purpose"])))
	status := strings.ToLower(strings.TrimSpace(firstString(item["status"])))

	if keyType == "" {
		keyType = inferDataProtectionKeyTypeFromAlgorithm(algorithm)
	}
	if keyType != "" && keyType != "symmetric" {
		return newServiceError(http.StatusBadRequest, "bad_request", "selected key must be symmetric for "+defaultString(usage, "data protection"))
	}
	if algorithm != "" {
		if isDataProtectionAsymmetricAlgorithm(algorithm) {
			return newServiceError(http.StatusBadRequest, "bad_request", "asymmetric and PQC key algorithms are not valid for "+defaultString(usage, "data protection"))
		}
		if !isDataProtectionCipherAlgorithm(algorithm) {
			return newServiceError(http.StatusBadRequest, "bad_request", "key algorithm "+algorithm+" is not supported for "+defaultString(usage, "data protection"))
		}
	}
	if purpose != "" && !purposeAllowsDataProtection(purpose) {
		return newServiceError(http.StatusBadRequest, "bad_request", "selected key purpose does not permit "+defaultString(usage, "data protection"))
	}
	if status != "" && status != "active" {
		return newServiceError(http.StatusBadRequest, "bad_request", "selected key must be active for "+defaultString(usage, "data protection"))
	}
	return nil
}

func inferDataProtectionKeyTypeFromAlgorithm(algorithm string) string {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	if a == "" {
		return ""
	}
	if isDataProtectionCipherAlgorithm(a) {
		return "symmetric"
	}
	if isDataProtectionAsymmetricAlgorithm(a) {
		return "asymmetric"
	}
	return ""
}

func isDataProtectionCipherAlgorithm(algorithm string) bool {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	if a == "" {
		return false
	}
	return strings.Contains(a, "AES") ||
		strings.Contains(a, "CHACHA20") ||
		strings.Contains(a, "3DES") ||
		strings.Contains(a, "TDES") ||
		strings.Contains(a, "DES") ||
		strings.Contains(a, "CAMELLIA")
}

func isDataProtectionAsymmetricAlgorithm(algorithm string) bool {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	if a == "" {
		return false
	}
	return strings.Contains(a, "RSA") ||
		strings.Contains(a, "ECDSA") ||
		strings.Contains(a, "ECDH") ||
		strings.Contains(a, "ED25519") ||
		strings.Contains(a, "ED448") ||
		strings.Contains(a, "BRAINPOOL") ||
		strings.Contains(a, "DSA") ||
		strings.Contains(a, "DH-") ||
		strings.Contains(a, "X25519") ||
		strings.Contains(a, "X448") ||
		strings.Contains(a, "ML-KEM") ||
		strings.Contains(a, "ML-DSA") ||
		strings.Contains(a, "SLH-DSA") ||
		strings.Contains(a, "XMSS") ||
		strings.Contains(a, "HSS")
}

func purposeAllowsDataProtection(purpose string) bool {
	p := strings.ToLower(strings.TrimSpace(purpose))
	if p == "" {
		return true
	}
	return strings.Contains(p, "encrypt") ||
		strings.Contains(p, "wrap") ||
		strings.Contains(p, "token") ||
		strings.Contains(p, "data") ||
		strings.Contains(p, "protect")
}

func uniqueUpper(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		s := strings.ToUpper(strings.TrimSpace(item))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func normalizeTokenModesPolicy(in map[string][]string) map[string][]string {
	defaults := defaultTokenizationModePolicy()
	if len(in) == 0 {
		return defaults
	}
	out := map[string][]string{}
	for tokenType, modes := range defaults {
		key := strings.ToLower(strings.TrimSpace(tokenType))
		candidate := modes
		if supplied, ok := in[key]; ok {
			candidate = supplied
		}
		valid := make([]string, 0, len(candidate))
		for _, mode := range candidate {
			n := normalizeTokenMode(mode)
			if !containsString(valid, n) {
				valid = append(valid, n)
			}
		}
		if len(valid) == 0 {
			valid = append(valid, modes...)
		}
		out[key] = valid
	}
	return out
}

func normalizeTokenFormatsPolicy(in map[string][]string) map[string][]string {
	defaults := defaultTokenFormatPolicy()
	if len(in) == 0 {
		return defaults
	}
	out := map[string][]string{}
	for tokenType, formats := range defaults {
		key := strings.ToLower(strings.TrimSpace(tokenType))
		candidate := formats
		if supplied, ok := in[key]; ok {
			candidate = supplied
		}
		valid := make([]string, 0, len(candidate))
		for _, format := range candidate {
			n := normalizeTokenFormat(format)
			if !containsString(valid, n) {
				valid = append(valid, n)
			}
		}
		if len(valid) == 0 {
			valid = append(valid, formats...)
		}
		out[key] = valid
	}
	return out
}

func normalizeMaskingRolePolicy(in map[string]string) map[string]string {
	base := defaultMaskingRolePolicy()
	if len(in) == 0 {
		return base
	}
	out := map[string]string{}
	for role, mode := range base {
		out[role] = mode
	}
	for role, mode := range in {
		key := strings.ToLower(strings.TrimSpace(role))
		if key == "" {
			continue
		}
		value := strings.ToLower(strings.TrimSpace(mode))
		if value == "none" {
			out[key] = value
			continue
		}
		out[key] = normalizeMaskPattern(value)
	}
	return out
}

func policyAllowsTokenMode(policy DataProtectionPolicy, tokenType string, mode string) bool {
	tokenType = strings.ToLower(strings.TrimSpace(tokenType))
	mode = normalizeTokenMode(mode)
	allowed, ok := policy.TokenizationModePolicy[tokenType]
	if !ok || len(allowed) == 0 {
		return mode == "vault"
	}
	return containsString(allowed, mode)
}

func policyAllowsTokenFormat(policy DataProtectionPolicy, tokenType string, format string) bool {
	tokenType = strings.ToLower(strings.TrimSpace(tokenType))
	format = normalizeTokenFormat(format)
	allowed, ok := policy.TokenFormatPolicy[tokenType]
	if !ok || len(allowed) == 0 {
		return true
	}
	return containsString(allowed, format)
}

func validateCustomRegexPolicy(pattern string, policy DataProtectionPolicy) error {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil
	}
	if len(pattern) > policy.MaxCustomRegexLength {
		return newServiceError(http.StatusBadRequest, "bad_request", "custom_regex exceeds policy length limit")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return newServiceError(http.StatusBadRequest, "bad_request", "invalid custom_regex")
	}
	if re.NumSubexp() > policy.MaxCustomRegexGroups {
		return newServiceError(http.StatusBadRequest, "bad_request", "custom_regex exceeds policy capture-group limit")
	}
	return nil
}

func validateRequiredContextTags(tags map[string]string, required []string) error {
	if len(required) == 0 {
		return nil
	}
	for _, key := range required {
		name := strings.TrimSpace(key)
		if name == "" {
			continue
		}
		value := strings.TrimSpace(tags[name])
		if value == "" {
			return newServiceError(http.StatusBadRequest, "bad_request", "required metadata tag "+name+" is missing")
		}
	}
	return nil
}

func isAllowedRedactionDetector(pattern RedactionPattern, allowed []string) bool {
	label := strings.ToUpper(strings.TrimSpace(pattern.Label))
	pType := strings.ToUpper(strings.TrimSpace(pattern.Type))
	switch {
	case strings.Contains(label, "EMAIL"):
		return containsString(allowed, "EMAIL")
	case strings.Contains(label, "PHONE"):
		return containsString(allowed, "PHONE")
	case strings.Contains(label, "SSN"):
		return containsString(allowed, "SSN")
	case strings.Contains(label, "PAN"), strings.Contains(label, "CARD"):
		return containsString(allowed, "PAN")
	case strings.Contains(label, "IBAN"):
		return containsString(allowed, "IBAN")
	case strings.Contains(label, "PERSON"), strings.Contains(label, "NAME"):
		return containsString(allowed, "NAME")
	default:
		return pType == "REGEX" && containsString(allowed, "CUSTOM")
	}
}
