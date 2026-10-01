package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/fips140"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/crypto/ssh"

	pkgcrypto "vecta-kms/pkg/crypto"
)

var (
	errExpired        = errors.New("secret lease has expired")
	errAlreadyCurrent = errors.New("that version is already the current one")
)

// Service holds the secrets domain logic. It emits no audit events itself:
// every call arrives through a pkg/route handler, and the kernel emits the
// one audit.secrets.<action> event for the request.
type Service struct {
	store Store
	mek   []byte
}

func NewService(store Store, mek []byte) *Service {
	return &Service{
		store: store,
		mek:   append([]byte{}, mek...),
	}
}

func (s *Service) CreateSecret(ctx context.Context, req CreateSecretRequest) (Secret, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Name = strings.TrimSpace(req.Name)
	req.SecretType = normalizeSecretType(req.SecretType)
	if req.CreatedBy == "" {
		req.CreatedBy = "system"
	}
	if req.TenantID == "" || req.Name == "" || req.SecretType == "" {
		return Secret{}, errors.New("tenant_id, name, secret_type are required")
	}
	if _, ok := supportedSecretTypes[req.SecretType]; !ok {
		return Secret{}, errors.New("unsupported secret_type")
	}
	if req.Value == "" {
		return Secret{}, errors.New("value is required")
	}
	if req.LeaseTTLSeconds < 0 {
		return Secret{}, errors.New("lease_ttl_seconds cannot be negative")
	}
	expiresAt := leaseExpiry(req.LeaseTTLSeconds)
	plain := []byte(req.Value)
	defer pkgcrypto.Zeroize(plain)

	enc, err := s.encryptValue(plain)
	if err != nil {
		return Secret{}, err
	}
	secret := Secret{
		ID:              newID("sec"),
		TenantID:        req.TenantID,
		Name:            req.Name,
		SecretType:      req.SecretType,
		Description:     req.Description,
		Labels:          defaultLabels(req.Labels),
		Metadata:        defaultMetadata(req.Metadata),
		Status:          SecretStatusActive,
		LeaseTTLSeconds: req.LeaseTTLSeconds,
		ExpiresAt:       expiresAt,
		CurrentVersion:  1,
		CreatedBy:       req.CreatedBy,
	}
	if err := s.store.CreateSecret(ctx, secret, enc); err != nil {
		return Secret{}, err
	}
	out, err := s.store.GetSecret(ctx, req.TenantID, secret.ID)
	if err != nil {
		return Secret{}, err
	}
	return out, nil
}

func (s *Service) ListSecrets(ctx context.Context, tenantID string, secretType string, limit int, offset int) ([]Secret, error) {
	return s.ListVisible(ctx, tenantID, secretType, SecretStatusActive, limit, offset, nil)
}

// ListVisible pages the secrets of one status that visible accepts (nil
// accepts all). limit and offset count visible secrets, so a caller's pages
// are full until the last one whatever the access rules hide.
func (s *Service) ListVisible(ctx context.Context, tenantID, secretType, status string, limit, offset int, visible func(Secret) bool) ([]Secret, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	secretType = normalizeSecretType(secretType)
	if visible == nil {
		return s.store.ListSecrets(ctx, tenantID, secretType, status, limit, offset)
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	const page = 500
	out := make([]Secret, 0)
	for from, skipped := 0, 0; len(out) < limit; from += page {
		items, err := s.store.ListSecrets(ctx, tenantID, secretType, status, page, from)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if !visible(item) {
				continue
			}
			if skipped < offset {
				skipped++
			} else if len(out) < limit {
				out = append(out, item)
			}
		}
		if len(items) < page {
			break
		}
	}
	return out, nil
}

func (s *Service) GetSecret(ctx context.Context, tenantID string, secretID string) (Secret, error) {
	tenantID = strings.TrimSpace(tenantID)
	secretID = strings.TrimSpace(secretID)
	if tenantID == "" || secretID == "" {
		return Secret{}, errors.New("tenant_id and secret_id are required")
	}
	secret, err := s.store.GetSecret(ctx, tenantID, secretID)
	if err != nil {
		return Secret{}, err
	}
	return secret, nil
}

func (s *Service) GetSecretByName(ctx context.Context, tenantID string, name string) (Secret, error) {
	tenantID = strings.TrimSpace(tenantID)
	name = strings.TrimSpace(name)
	if tenantID == "" || name == "" {
		return Secret{}, errors.New("tenant_id and name are required")
	}
	secret, err := s.store.GetSecretByName(ctx, tenantID, name)
	if err != nil {
		return Secret{}, err
	}
	return secret, nil
}

// GetSecretValue returns one version of the value, the current one when
// version is 0.
func (s *Service) GetSecretValue(ctx context.Context, tenantID string, secretID string, format string, version int) (SecretValueResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	secretID = strings.TrimSpace(secretID)
	format = strings.TrimSpace(strings.ToLower(format))
	if tenantID == "" || secretID == "" {
		return SecretValueResponse{}, errors.New("tenant_id and secret_id are required")
	}
	secret, enc, err := s.store.GetSecretWithValue(ctx, tenantID, secretID, version)
	if err != nil {
		return SecretValueResponse{}, err
	}
	if secret.Status != SecretStatusActive {
		return SecretValueResponse{}, errDeleted
	}
	if version <= 0 {
		version = secret.CurrentVersion
	}
	if secret.ExpiresAt != nil && time.Now().UTC().After(secret.ExpiresAt.UTC()) {
		return SecretValueResponse{}, errExpired
	}
	plain, err := s.decryptValue(enc)
	if err != nil {
		return SecretValueResponse{}, err
	}
	defer pkgcrypto.Zeroize(plain)

	converted, usedFormat, contentType, err := convertSecretFormat(secret, plain, format)
	if err != nil {
		return SecretValueResponse{}, err
	}
	return SecretValueResponse{
		Value:       string(converted),
		Version:     version,
		Format:      usedFormat,
		ContentType: contentType,
	}, nil
}

func (s *Service) UpdateSecret(ctx context.Context, tenantID string, secretID string, req UpdateSecretRequest) (Secret, error) {
	tenantID = strings.TrimSpace(tenantID)
	secretID = strings.TrimSpace(secretID)
	if req.UpdatedBy == "" {
		req.UpdatedBy = "system"
	}
	if tenantID == "" || secretID == "" {
		return Secret{}, errors.New("tenant_id and secret_id are required")
	}

	var (
		value     *EncryptedSecretValue
		expiresAt *time.Time
	)
	if req.LeaseTTLSeconds != nil {
		if *req.LeaseTTLSeconds < 0 {
			return Secret{}, errors.New("lease_ttl_seconds cannot be negative")
		}
		expiresAt = leaseExpiry(*req.LeaseTTLSeconds)
	}
	if req.Value != nil {
		raw := []byte(*req.Value)
		defer pkgcrypto.Zeroize(raw)
		enc, err := s.encryptValue(raw)
		if err != nil {
			return Secret{}, err
		}
		value = &enc
	}

	if value != nil {
		current, err := s.store.GetSecret(ctx, tenantID, secretID)
		if err != nil {
			return Secret{}, err
		}
		if req.maxVersions, _, err = s.VersionCapFor(ctx, tenantID, current.Path); err != nil {
			return Secret{}, err
		}
	}
	updated, err := s.store.UpdateSecret(ctx, tenantID, secretID, req, expiresAt, value)
	if err != nil {
		return Secret{}, err
	}
	return updated, nil
}

// DeleteSecret marks the secret deleted. Its versions are kept, unreadable,
// until RestoreSecret or DestroySecret.
func (s *Service) DeleteSecret(ctx context.Context, tenantID string, secretID string, actor string) error {
	return s.store.SoftDeleteSecret(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(secretID), actorOrSystem(actor))
}

func (s *Service) RestoreSecret(ctx context.Context, tenantID string, secretID string, actor string) error {
	return s.store.RestoreSecret(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(secretID), actorOrSystem(actor))
}

// DestroySecret removes the secret and every version, for good.
func (s *Service) DestroySecret(ctx context.Context, tenantID string, secretID string, actor string) error {
	return s.store.DestroySecret(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(secretID), actorOrSystem(actor))
}

func (s *Service) DestroyVersion(ctx context.Context, tenantID string, secretID string, version int, actor string) error {
	return s.store.DestroyVersion(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(secretID), version, actorOrSystem(actor))
}

// Rollback makes an earlier version's value the current one again, as a new
// version sealed under a new data key. Rolling back to the current version
// would change nothing and is refused.
func (s *Service) Rollback(ctx context.Context, tenantID string, secretID string, version int, expected *int, actor string) (Secret, error) {
	secret, enc, err := s.store.GetSecretWithValue(ctx, tenantID, secretID, version)
	if err != nil {
		return Secret{}, err
	}
	if version <= 0 || version == secret.CurrentVersion {
		return Secret{}, errAlreadyCurrent
	}
	plain, err := s.decryptValue(enc)
	if err != nil {
		return Secret{}, err
	}
	defer pkgcrypto.Zeroize(plain)
	sealed, err := s.encryptValue(plain)
	if err != nil {
		return Secret{}, err
	}
	maxVersions, _, err := s.VersionCapFor(ctx, tenantID, secret.Path)
	if err != nil {
		return Secret{}, err
	}
	return s.store.UpdateSecret(ctx, tenantID, secretID, UpdateSecretRequest{
		maxVersions:     maxVersions,
		UpdatedBy:       actorOrSystem(actor),
		ExpectedVersion: expected,
		changeAction:    "rolled_back",
		changeDetail:    fmt.Sprintf("Value of version %d restored as version %d", version, secret.CurrentVersion+1),
	}, nil, &sealed)
}

func actorOrSystem(actor string) string {
	if actor == "" {
		return "system"
	}
	return actor
}

func (s *Service) GenerateSSHKey(ctx context.Context, req GenerateSSHKeyRequest) (Secret, string, error) {
	kp, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgEd25519)
	if err != nil {
		return Secret{}, "", err
	}
	privPEM, err := pkgcrypto.MarshalPrivateKeyPEM(kp)
	if err != nil {
		return Secret{}, "", err
	}
	pubKey, err := ssh.NewPublicKey(kp.Public)
	if err != nil {
		return Secret{}, "", err
	}
	pubSSH := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))
	createReq := CreateSecretRequest{
		TenantID:        req.TenantID,
		Name:            req.Name,
		SecretType:      "ssh_private_key",
		Value:           string(privPEM),
		Description:     req.Description,
		Labels:          req.Labels,
		LeaseTTLSeconds: req.LeaseTTLSeconds,
		CreatedBy:       req.CreatedBy,
		Metadata: map[string]interface{}{
			"generated":  true,
			"algorithm":  "ed25519",
			"public_key": pubSSH,
		},
	}
	secret, err := s.CreateSecret(ctx, createReq)
	if err != nil {
		return Secret{}, "", err
	}
	return secret, pubSSH, nil
}

func (s *Service) GenerateKeyPair(ctx context.Context, req GenerateKeyPairRequest) (Secret, string, string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Name = strings.TrimSpace(req.Name)
	req.KeyType = strings.TrimSpace(strings.ToLower(req.KeyType))
	if req.CreatedBy == "" {
		req.CreatedBy = "system"
	}
	if req.TenantID == "" || req.Name == "" || req.KeyType == "" {
		return Secret{}, "", "", errors.New("tenant_id, name, key_type are required")
	}
	if req.LeaseTTLSeconds < 0 {
		return Secret{}, "", "", errors.New("lease_ttl_seconds cannot be negative")
	}

	var (
		secretType string
		privateVal string
		publicVal  string
		algorithm  string
		err        error
	)

	switch req.KeyType {
	case "ed25519":
		privateVal, publicVal, err = generateSSHKeyPair("ed25519")
		secretType = "ssh_private_key"
		algorithm = "ed25519"
	case "rsa-4096":
		privateVal, publicVal, err = generateSSHKeyPair("rsa-4096")
		secretType = "ssh_private_key"
		algorithm = "rsa-4096"
	case "ecdsa-p384":
		privateVal, publicVal, err = generateSSHKeyPair("ecdsa-p384")
		secretType = "ssh_private_key"
		algorithm = "ecdsa-p384"
	case "pgp-rsa-4096":
		privateVal, publicVal, err = generateOpenPGPKeyPair(req.Name)
		secretType = "pgp_private_key"
		algorithm = "pgp-rsa-4096"
	case "wireguard-curve25519":
		privateVal, publicVal, err = generateWireGuardKeyPair()
		secretType = "wireguard_private_key"
		algorithm = "curve25519"
	case "age-x25519":
		privateVal, publicVal, err = generateAgeX25519KeyPair()
		secretType = "age_key"
		algorithm = "x25519"
	default:
		return Secret{}, "", "", errors.New("unsupported key_type")
	}
	if err != nil {
		return Secret{}, "", "", err
	}

	createReq := CreateSecretRequest{
		TenantID:        req.TenantID,
		Name:            req.Name,
		SecretType:      secretType,
		Value:           privateVal,
		Description:     req.Description,
		Labels:          req.Labels,
		LeaseTTLSeconds: req.LeaseTTLSeconds,
		CreatedBy:       req.CreatedBy,
		Metadata: map[string]interface{}{
			"generated":  true,
			"algorithm":  algorithm,
			"key_type":   req.KeyType,
			"public_key": publicVal,
		},
	}
	secret, err := s.CreateSecret(ctx, createReq)
	if err != nil {
		return Secret{}, "", "", err
	}
	return secret, publicVal, req.KeyType, nil
}

func (s *Service) ListVersions(ctx context.Context, tenantID string, secretID string) ([]SecretVersionInfo, error) {
	tenantID = strings.TrimSpace(tenantID)
	secretID = strings.TrimSpace(secretID)
	if tenantID == "" || secretID == "" {
		return nil, errors.New("tenant_id and secret_id are required")
	}
	versions, err := s.store.ListVersions(ctx, tenantID, secretID)
	if err != nil {
		return nil, err
	}
	return versions, nil
}

func (s *Service) GetSecretAuditLog(ctx context.Context, tenantID string, secretID string, limit int) ([]SecretAuditEntry, error) {
	tenantID = strings.TrimSpace(tenantID)
	secretID = strings.TrimSpace(secretID)
	if tenantID == "" || secretID == "" {
		return nil, errors.New("tenant_id and secret_id are required")
	}
	entries, err := s.store.GetSecretAuditLog(ctx, tenantID, secretID, limit)
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *Service) RotateSecret(ctx context.Context, tenantID string, secretID string, newValue string, expected *int, updatedBy string) (Secret, error) {
	tenantID = strings.TrimSpace(tenantID)
	secretID = strings.TrimSpace(secretID)
	if tenantID == "" || secretID == "" || newValue == "" {
		return Secret{}, errors.New("tenant_id, secret_id and value are required")
	}
	if updatedBy == "" {
		updatedBy = "system"
	}
	updated, err := s.UpdateSecret(ctx, tenantID, secretID, UpdateSecretRequest{
		Value:           &newValue,
		UpdatedBy:       updatedBy,
		ExpectedVersion: expected,
	})
	if err != nil {
		return Secret{}, err
	}
	return updated, nil
}

// GetStats counts the active secrets visible accepts (nil accepts all) and
// their stored versions. A failed count is an error, never a zero.
func (s *Service) GetStats(ctx context.Context, tenantID string, visible func(Secret) bool) (VaultStats, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return VaultStats{}, errors.New("tenant_id is required")
	}
	versions, err := s.store.VersionCounts(ctx, tenantID)
	if err != nil {
		return VaultStats{}, err
	}
	stats := VaultStats{ByType: map[string]int{}}
	now := time.Now().UTC()
	for from := 0; ; from += 500 {
		items, err := s.store.ListSecrets(ctx, tenantID, "", SecretStatusActive, 500, from)
		if err != nil {
			return VaultStats{}, err
		}
		for _, item := range items {
			if visible != nil && !visible(item) {
				continue
			}
			stats.TotalSecrets++
			stats.TotalVersions += versions[item.ID]
			stats.ByType[item.SecretType]++
			switch {
			case item.ExpiresAt == nil:
			case !item.ExpiresAt.After(now):
				stats.Expired++
			case !item.ExpiresAt.After(now.Add(30 * 24 * time.Hour)):
				stats.ExpiringWithin++
			}
		}
		if len(items) < 500 {
			return stats, nil
		}
	}
}

// Settings.

func (s *Service) Settings(ctx context.Context, tenantID string) (VaultSettings, error) {
	return s.store.GetSettings(ctx, strings.TrimSpace(tenantID))
}

func (s *Service) PutSettings(ctx context.Context, v VaultSettings) (VaultSettings, error) {
	if v.MaxVersions < 0 || v.MaxVersions > maxVersionCap {
		return VaultSettings{}, fmt.Errorf("max_versions must be 0 (no cap) to %d", maxVersionCap)
	}
	if v.DeletedRetentionDays < 0 || v.DeletedRetentionDays > maxRetentionDays {
		return VaultSettings{}, fmt.Errorf("deleted_retention_days must be 0 (keep until destroyed) to %d", maxRetentionDays)
	}
	if err := s.store.PutSettings(ctx, v); err != nil {
		return VaultSettings{}, err
	}
	return s.store.GetSettings(ctx, v.TenantID)
}

// VersionCapFor is the version cap that applies to a path and where it
// comes from: the path of a cap, or "tenant".
func (s *Service) VersionCapFor(ctx context.Context, tenantID, path string) (int, string, error) {
	settings, err := s.store.GetSettings(ctx, tenantID)
	if err != nil {
		return 0, "", err
	}
	caps, err := s.store.ListVersionCaps(ctx, tenantID)
	if err != nil {
		return 0, "", err
	}
	maxVersions, from := capFor(caps, settings.MaxVersions, path)
	return maxVersions, from, nil
}

// ApplyVersionCaps prunes every secret of the tenant, deleted ones included,
// to the cap that applies to it now. It runs when a cap or the tenant's
// setting changes, so a lowered cap holds at once and not at each secret's
// next write. It returns how many secrets and versions it pruned.
func (s *Service) ApplyVersionCaps(ctx context.Context, tenantID, actor string) (int, int, error) {
	settings, err := s.store.GetSettings(ctx, tenantID)
	if err != nil {
		return 0, 0, err
	}
	caps, err := s.store.ListVersionCaps(ctx, tenantID)
	if err != nil {
		return 0, 0, err
	}
	secrets, versions := 0, 0
	for _, status := range []string{SecretStatusActive, SecretStatusDeleted} {
		for from := 0; ; from += 500 {
			items, err := s.store.ListSecrets(ctx, tenantID, "", status, 500, from)
			if err != nil {
				return secrets, versions, err
			}
			for _, item := range items {
				keep, _ := capFor(caps, settings.MaxVersions, item.Path)
				n, err := s.store.PruneVersions(ctx, tenantID, item.ID, keep, actorOrSystem(actor))
				if err != nil {
					return secrets, versions, err
				}
				if n > 0 {
					secrets, versions = secrets+1, versions+n
				}
			}
			if len(items) < 500 {
				break
			}
		}
	}
	return secrets, versions, nil
}

func (s *Service) VersionCaps(ctx context.Context, tenantID string) ([]VersionCap, error) {
	return s.store.ListVersionCaps(ctx, strings.TrimSpace(tenantID))
}

func (s *Service) PutVersionCap(ctx context.Context, c VersionCap) (VersionCap, error) {
	c.Path = strings.TrimSpace(c.Path)
	if err := validPath(c.Path); err != nil {
		return VersionCap{}, err
	}
	if c.MaxVersions < 0 || c.MaxVersions > maxVersionCap {
		return VersionCap{}, fmt.Errorf("max_versions must be 0 (keep every version) to %d", maxVersionCap)
	}
	existing, err := s.store.ListVersionCaps(ctx, c.TenantID)
	if err != nil {
		return VersionCap{}, err
	}
	if len(existing) >= maxRulesPerTenant {
		return VersionCap{}, fmt.Errorf("a tenant may have at most %d version caps", maxRulesPerTenant)
	}
	c.ID = newID("svc")
	if err := s.store.PutVersionCap(ctx, c); err != nil {
		return VersionCap{}, err
	}
	caps, err := s.store.ListVersionCaps(ctx, c.TenantID)
	for _, stored := range caps {
		if stored.Path == c.Path {
			return stored, err
		}
	}
	return VersionCap{}, err
}

func (s *Service) DeleteVersionCap(ctx context.Context, tenantID, capID string) (VersionCap, error) {
	return s.store.DeleteVersionCap(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(capID))
}

// Access rules.

func (s *Service) AccessRules(ctx context.Context, tenantID string) ([]AccessRule, error) {
	return s.store.ListAccessRules(ctx, strings.TrimSpace(tenantID))
}

func (s *Service) CreateAccessRule(ctx context.Context, rule AccessRule) (AccessRule, error) {
	rule, err := normalizeRule(rule)
	if err != nil {
		return AccessRule{}, err
	}
	existing, err := s.store.ListAccessRules(ctx, rule.TenantID)
	if err != nil {
		return AccessRule{}, err
	}
	if len(existing) >= maxRulesPerTenant {
		return AccessRule{}, fmt.Errorf("a tenant may have at most %d access rules", maxRulesPerTenant)
	}
	rule.ID = newID("sar")
	rule.CreatedAt = time.Now().UTC()
	if err := s.store.CreateAccessRule(ctx, rule); err != nil {
		return AccessRule{}, err
	}
	return rule, nil
}

func (s *Service) DeleteAccessRule(ctx context.Context, tenantID, ruleID string) (AccessRule, error) {
	return s.store.DeleteAccessRule(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(ruleID))
}

func generateSSHKeyPair(keyType string) (string, string, error) {
	var alg string
	switch keyType {
	case "ed25519":
		alg = pkgcrypto.AlgEd25519
	case "rsa-4096":
		alg = pkgcrypto.AlgRSA4096
	case "ecdsa-p384":
		alg = pkgcrypto.AlgECDSAP384
	default:
		return "", "", errors.New("unsupported ssh key type")
	}
	kp, err := pkgcrypto.GenerateKeyPair(alg)
	if err != nil {
		return "", "", err
	}
	privPEM, err := pkgcrypto.MarshalPrivateKeyPEM(kp)
	if err != nil {
		return "", "", err
	}
	pubKey, err := ssh.NewPublicKey(kp.Public)
	if err != nil {
		return "", "", err
	}
	pubSSH := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))
	return string(privPEM), pubSSH, nil
}

func generateOpenPGPKeyPair(name string) (string, string, error) {
	// OpenPGP v4 key fingerprints are SHA-1 by specification (RFC 4880), and
	// SHA-1 panics under FIPS strict mode, so refuse up front.
	if fips140.Enforced() {
		return "", "", errors.New("pgp-rsa-4096 is unavailable in FIPS strict mode: OpenPGP v4 fingerprints require SHA-1")
	}
	cfg := &packet.Config{
		RSABits:     4096,
		DefaultHash: crypto.SHA256,
		Time:        func() time.Time { return time.Now().UTC() },
	}
	emailSafe := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), " ", "-"))
	if emailSafe == "" {
		emailSafe = "vecta"
	}
	entity, err := openpgp.NewEntity(name, "vecta-kms", fmt.Sprintf("%s@local", emailSafe), cfg)
	if err != nil {
		return "", "", err
	}

	var pubBuf bytes.Buffer
	pubArmor, err := armor.Encode(&pubBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", "", err
	}
	if err := entity.Serialize(pubArmor); err != nil {
		return "", "", err
	}
	if err := pubArmor.Close(); err != nil {
		return "", "", err
	}

	var privBuf bytes.Buffer
	privArmor, err := armor.Encode(&privBuf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", "", err
	}
	if err := entity.SerializePrivate(privArmor, nil); err != nil {
		return "", "", err
	}
	if err := privArmor.Close(); err != nil {
		return "", "", err
	}
	return privBuf.String(), pubBuf.String(), nil
}

func generateWireGuardKeyPair() (string, string, error) {
	private, err := pkgcrypto.RandomBytes(32)
	if err != nil {
		return "", "", err
	}
	private[0] &= 248
	private[31] = (private[31] & 127) | 64

	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public), nil
}

func generateAgeX25519KeyPair() (string, string, error) {
	// age implements X25519 itself, outside the Go FIPS module, so the runtime
	// cannot enforce strict mode here; refuse explicitly.
	if fips140.Enforced() {
		return "", "", errors.New("age-x25519 is unavailable in FIPS strict mode: X25519 is not FIPS-approved")
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", err
	}
	return id.String(), id.Recipient().String(), nil
}

func (s *Service) encryptValue(plain []byte) (EncryptedSecretValue, error) {
	env, err := pkgcrypto.EncryptEnvelope(s.mek, plain)
	if err != nil {
		return EncryptedSecretValue{}, err
	}
	return EncryptedSecretValue{
		WrappedDEK:   env.WrappedDEK,
		WrappedDEKIV: env.WrappedDEKIV,
		Ciphertext:   env.Ciphertext,
		DataIV:       env.DataIV,
	}, nil
}

func (s *Service) decryptValue(enc EncryptedSecretValue) ([]byte, error) {
	return pkgcrypto.DecryptEnvelope(s.mek, &pkgcrypto.EnvelopeCiphertext{
		WrappedDEK:   enc.WrappedDEK,
		WrappedDEKIV: enc.WrappedDEKIV,
		Ciphertext:   enc.Ciphertext,
		DataIV:       enc.DataIV,
	})
}

func normalizeSecretType(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func defaultLabels(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	return in
}

func defaultMetadata(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return map[string]interface{}{}
	}
	return in
}

func leaseExpiry(ttlSeconds int64) *time.Time {
	if ttlSeconds <= 0 {
		return nil
	}
	ts := time.Now().UTC().Add(time.Duration(ttlSeconds) * time.Second)
	return &ts
}

func toRFC3339(ts *time.Time) string {
	if ts == nil {
		return ""
	}
	return ts.UTC().Format(time.RFC3339)
}

func newID(prefix string) string {
	b, err := pkgcrypto.RandomBytes(8)
	if err != nil {
		panic("secrets: system randomness unavailable: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(b)
}

func convertSecretFormat(secret Secret, plain []byte, format string) ([]byte, string, string, error) {
	if format == "" || format == "raw" {
		return plain, "raw", detectContentType(plain), nil
	}
	switch secret.SecretType {
	case "ssh_private_key":
		switch format {
		case "pem":
			return ensurePEMPrivate(plain)
		case "openssh":
			return privateToOpenSSHPublic(plain)
		default:
			return nil, "", "", errors.New("unsupported ssh format")
		}
	case "pgp_private_key", "pgp_public_key":
		if format != "armored" {
			return nil, "", "", errors.New("unsupported pgp format")
		}
		return toPGPArmor(secret.SecretType, plain)
	case "pkcs12":
		if format != "extract" {
			return nil, "", "", errors.New("unsupported pkcs12 format")
		}
		return extractPKCS12(plain)
	default:
		if format == "jwk" {
			if json.Valid(plain) {
				return plain, "jwk", "application/json", nil
			}
			return nil, "", "", errors.New("invalid jwk json")
		}
		return nil, "", "", errors.New("format conversion not supported for secret type")
	}
}

func ensurePEMPrivate(raw []byte) ([]byte, string, string, error) {
	if block, _ := pem.Decode(raw); block != nil {
		return raw, "pem", "application/x-pem-file", nil
	}
	return nil, "", "", errors.New("ssh private key is not in pem format")
}

func privateToOpenSSHPublic(raw []byte) ([]byte, string, string, error) {
	key, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, "", "", err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, "", "", err
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return []byte(pub), "openssh", "text/plain", nil
}

// toPGPArmor returns the key in RFC 4880 ASCII armor. A key stored already
// armored (as generated keys are) is returned unchanged; binary key packets
// are armored with the matching block type and CRC-24 checksum.
func toPGPArmor(secretType string, raw []byte) ([]byte, string, string, error) {
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("-----BEGIN PGP ")) {
		return raw, "armored", "application/pgp-keys", nil
	}
	blockType := openpgp.PrivateKeyType
	if secretType == "pgp_public_key" {
		blockType = openpgp.PublicKeyType
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, blockType, nil)
	if err != nil {
		return nil, "", "", err
	}
	if _, err := w.Write(raw); err != nil {
		return nil, "", "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", "", err
	}
	return buf.Bytes(), "armored", "application/pgp-keys", nil
}

func extractPKCS12(raw []byte) ([]byte, string, string, error) {
	blocks, err := pkcs12.ToPEM(raw, "")
	if err == nil && len(blocks) > 0 {
		var certs []string
		var keys []string
		for _, b := range blocks {
			if b == nil {
				continue
			}
			p := strings.TrimSpace(string(pem.EncodeToMemory(b)))
			if strings.Contains(b.Type, "PRIVATE KEY") {
				keys = append(keys, p)
			} else if strings.Contains(b.Type, "CERTIFICATE") {
				certs = append(certs, p)
			}
		}
		out, _ := json.Marshal(map[string]interface{}{
			"extracted": true,
			"keys":      keys,
			"certs":     certs,
		})
		return out, "extract", "application/json", nil
	}
	out, _ := json.Marshal(map[string]interface{}{
		"encoding":   "base64",
		"raw_base64": base64.StdEncoding.EncodeToString(raw),
		"length":     len(raw),
		"extracted":  false,
		"note":       "PKCS#12 decode failed; returning encoded bundle",
	})
	return out, "extract", "application/json", nil
}

func detectContentType(v []byte) string {
	if json.Valid(v) {
		return "application/json"
	}
	return "text/plain"
}
