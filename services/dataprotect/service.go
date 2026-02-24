package main

import (
	"context"
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

func NewService(store Store, keycore KeyCoreClient, events EventPublisher) *Service {
	return &Service{
		store:   store,
		keycore: keycore,
		events:  events,
		now:     func() time.Time { return time.Now().UTC() },
	}
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
	if in.TokenType == "custom" {
		if _, err := regexp.Compile(in.CustomRegex); err != nil {
			return TokenVault{}, newServiceError(http.StatusBadRequest, "bad_request", "invalid custom_regex")
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
	if len(req.Values) > 10000 {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "batch size limit is 10,000 values")
	}

	vault := TokenVault{}
	if req.Mode == "vaultless" {
		if req.KeyID == "" {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", "key_id is required for vaultless tokenization")
		}
		if req.TokenType == "" {
			req.TokenType = "custom"
		}
		if !isSupportedTokenType(req.TokenType) {
			return nil, newServiceError(http.StatusBadRequest, "bad_request", "unsupported token_type")
		}
		if req.TokenType == "custom" && req.CustomRegex != "" {
			if _, err := regexp.Compile(req.CustomRegex); err != nil {
				return nil, newServiceError(http.StatusBadRequest, "bad_request", "invalid custom_regex")
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
		if vault.Format == "deterministic" || vault.Format == "irreversible" {
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
		}
		if req.TTLHours > 0 {
			rec.ExpiresAt = s.now().Add(time.Duration(req.TTLHours) * time.Hour)
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
		results = append(results, out)
	}
	if req.Mode == "vaultless" {
		_ = s.publishAudit(ctx, "audit.dataprotect.tokenized", req.TenantID, map[string]interface{}{
			"mode":       "vaultless",
			"count":      len(results),
			"token_type": vault.TokenType,
			"format":     vault.Format,
			"key_id":     vault.KeyID,
		})
		return results, nil
	}
	if created > 0 {
		_ = s.publishAudit(ctx, "audit.dataprotect.tokenized", req.TenantID, map[string]interface{}{
			"vault_id": req.VaultID,
			"count":    created,
		})
	}
	return results, nil
}

func (s *Service) Detokenize(ctx context.Context, req DetokenizeRequest) ([]map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if len(req.Tokens) == 0 {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tokens cannot be empty")
	}
	if len(req.Tokens) > 10000 {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "batch size limit is 10,000 tokens")
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
		okCount++
		results = append(results, map[string]interface{}{
			"token":      token,
			"value":      value,
			"vault_id":   record.VaultID,
			"created_at": record.CreatedAt,
		})
	}
	if okCount > 0 {
		_ = s.publishAudit(ctx, "audit.dataprotect.detokenized", req.TenantID, map[string]interface{}{
			"count": okCount,
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
	if err := s.enforceKeycoreMetering(ctx, req.TenantID, req.KeyID, "encrypt"); err != nil {
		return nil, err
	}
	key, err := s.resolveWorkingKey(ctx, req.TenantID, req.KeyID, "field-encrypt")
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(key)

	doc := cloneMap(req.Document)
	done := make([]string, 0, len(req.Fields))
	for _, field := range uniqueStrings(req.Fields) {
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
			key, err = s.resolveWorkingKey(ctx, req.TenantID, keyID, "field-encrypt")
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
	if err := s.enforceKeycoreMetering(ctx, req.TenantID, req.KeyID, "wrap"); err != nil {
		return nil, err
	}
	kek, err := s.resolveWorkingKey(ctx, req.TenantID, req.KeyID, "envelope-kek")
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(kek)
	dek := randBytes(32)
	defer pkgcrypto.Zeroize(dek)

	alg := normalizeFieldAlgorithm(req.Algorithm, false)
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
		"algorithm":      alg,
	}, nil
}

func (s *Service) EnvelopeDecrypt(ctx context.Context, req EnvelopeRequest) (map[string]interface{}, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	if req.TenantID == "" || req.KeyID == "" || req.Ciphertext == "" || req.WrappedDEK == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, key_id, ciphertext and wrapped_dek are required")
	}
	if err := s.enforceKeycoreMetering(ctx, req.TenantID, req.KeyID, "unwrap"); err != nil {
		return nil, err
	}
	kek, err := s.resolveWorkingKey(ctx, req.TenantID, req.KeyID, "envelope-kek")
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
	alg := normalizeFieldAlgorithm(req.Algorithm, false)
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
	if err := s.enforceKeycoreMetering(ctx, req.TenantID, req.KeyID, "encrypt"); err != nil {
		return nil, err
	}
	key, err := s.resolveWorkingKey(ctx, req.TenantID, req.KeyID, "searchable")
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
	if err := s.enforceKeycoreMetering(ctx, req.TenantID, req.KeyID, "decrypt"); err != nil {
		return nil, err
	}
	key, err := s.resolveWorkingKey(ctx, req.TenantID, req.KeyID, "searchable")
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
	case "credit_card", "ssn", "email", "phone", "iban", "custom":
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
