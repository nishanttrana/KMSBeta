package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"vecta-kms/pkg/crypto"
)

// Service-bound key derivation: POST /keys/{id}/service-derive.
//
// Internal services that must hold a working key (dataprotect: tokenization,
// FPE, field protection) derive it here from the key's secret material, so a
// working key is never computed from identifiers. The HKDF context binds the
// caller's verified service client id, the tenant, the key, its version and
// the purpose:
//   - only that service can obtain its subkey (the client id comes from the
//     verified service JWT, never from the request body);
//   - nobody can reproduce it through POST /keys/{id}/derive, which refuses
//     the reserved info prefix;
//   - pinning the version keeps the subkey stable across key rotation.

const (
	serviceDeriveInfoPrefix = "vecta/service-derive/v1|"
	serviceDeriveSalt       = "vecta-service-derive"
	serviceDeriveKDF        = "HKDF-SHA256"
	serviceDeriveBytes      = 32
)

var (
	errServiceIdentityRequired = errors.New("service-derive is restricted to internal service identities")
	errReservedDeriveInfo      = errors.New("derive info uses the reserved service-derive prefix")
	serviceDerivePurposeRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

type ServiceDeriveRequest struct {
	TenantID string `json:"tenant_id"`
	Purpose  string `json:"purpose"`
	// Version pins the key version; 0 means the current version.
	Version int `json:"version"`
}

type ServiceDeriveResponse struct {
	KeyID      string `json:"key_id"`
	Version    int    `json:"version"`
	Purpose    string `json:"purpose"`
	KDF        string `json:"kdf"`
	DerivedB64 string `json:"derived_key"`
}

func serviceDeriveInfo(clientID, tenantID, keyID, purpose string, version int) []byte {
	return []byte(fmt.Sprintf("%s%s|%s|%s|%s|v%d", serviceDeriveInfoPrefix, clientID, tenantID, keyID, purpose, version))
}

func (s *Service) ServiceDerive(ctx context.Context, keyID string, req ServiceDeriveRequest) (ServiceDeriveResponse, error) {
	actor := accessActorFromContext(ctx)
	clientID := strings.TrimSpace(actor.ClientID)
	if !actorIsServicePrincipal(actor) || !strings.HasPrefix(clientID, "kms-") {
		return ServiceDeriveResponse{}, errServiceIdentityRequired
	}
	tenantID := strings.TrimSpace(req.TenantID)
	purpose := strings.ToLower(strings.TrimSpace(req.Purpose))
	if tenantID == "" || !serviceDerivePurposeRE.MatchString(purpose) {
		return ServiceDeriveResponse{}, errors.New("tenant_id and a purpose of [a-z0-9-] are required")
	}
	if req.Version < 0 {
		return ServiceDeriveResponse{}, errors.New("version must be >= 0")
	}
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return ServiceDeriveResponse{}, err
	}
	if !strings.EqualFold(strings.TrimSpace(key.KeyType), "symmetric") {
		return ServiceDeriveResponse{}, errors.New("service-derive requires a symmetric key")
	}
	// Deactivated keys still derive so data they protected stays readable.
	switch normalizeLifecycleStatus(key.Status) {
	case "active", "deactivated":
	default:
		return ServiceDeriveResponse{}, fmt.Errorf("key status %q does not permit derivation", key.Status)
	}
	if err := s.enforceFIPSKeyAlgorithm(ctx, tenantID, key.Algorithm, "key.service_derive"); err != nil {
		return ServiceDeriveResponse{}, err
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          tenantID,
		Operation:         "key.service_derive",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return ServiceDeriveResponse{}, err
	}
	ver, err := s.GetVersion(ctx, tenantID, keyID, req.Version)
	if err != nil {
		return ServiceDeriveResponse{}, err
	}
	raw, err := s.decryptMaterial(ver)
	if err != nil {
		return ServiceDeriveResponse{}, err
	}
	defer crypto.Zeroize(raw)
	derived, err := crypto.HKDFSHA256(raw, []byte(serviceDeriveSalt), serviceDeriveInfo(clientID, tenantID, keyID, purpose, ver.Version), serviceDeriveBytes)
	if err != nil {
		return ServiceDeriveResponse{}, err
	}
	defer crypto.Zeroize(derived)
	s.recordKeyUsage(ctx, tenantID, keyID, "service_derive")
	_ = s.publishAudit(ctx, "audit.key.service_derive", tenantID, map[string]any{
		"key_id":      keyID,
		"version":     ver.Version,
		"purpose":     purpose,
		"service":     clientID,
		"kdf":         serviceDeriveKDF,
		"algorithm":   key.Algorithm,
		"result":      "success",
		"severity":    "info",
		"description": "internal service derived a purpose-bound working key",
	})
	return ServiceDeriveResponse{
		KeyID:      keyID,
		Version:    ver.Version,
		Purpose:    purpose,
		KDF:        serviceDeriveKDF,
		DerivedB64: base64.StdEncoding.EncodeToString(derived),
	}, nil
}

// rejectReservedDeriveInfo stops POST /keys/{id}/derive from reproducing a
// service-bound subkey.
func rejectReservedDeriveInfo(info []byte) error {
	if strings.HasPrefix(string(info), serviceDeriveInfoPrefix) {
		return errReservedDeriveInfo
	}
	return nil
}
