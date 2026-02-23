package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/crypto/ssh"

	pkgcrypto "vecta-kms/pkg/crypto"
)

var errExpired = errors.New("secret lease has expired")

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Service struct {
	store  Store
	events EventPublisher
	mek    []byte
}

func NewService(store Store, events EventPublisher, mek []byte) *Service {
	return &Service{
		store:  store,
		events: events,
		mek:    append([]byte{}, mek...),
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
	_ = s.publishAudit(ctx, "audit.secrets.created", req.TenantID, map[string]interface{}{
		"secret_id":    out.ID,
		"secret_type":  out.SecretType,
		"expires_at":   toRFC3339(out.ExpiresAt),
		"current_ver":  out.CurrentVersion,
		"created_by":   out.CreatedBy,
		"value_stored": "envelope_encrypted",
	})
	return out, nil
}

func (s *Service) ListSecrets(ctx context.Context, tenantID string, secretType string, limit int, offset int) ([]Secret, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	secretType = normalizeSecretType(secretType)
	items, err := s.store.ListSecrets(ctx, tenantID, secretType, limit, offset)
	if err != nil {
		return nil, err
	}
	_ = s.publishAudit(ctx, "audit.secrets.listed", tenantID, map[string]interface{}{
		"count":       len(items),
		"secret_type": secretType,
	})
	return items, nil
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
	_ = s.publishAudit(ctx, "audit.secrets.read", tenantID, map[string]interface{}{
		"secret_id": secretID,
	})
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
	_ = s.publishAudit(ctx, "audit.secrets.read", tenantID, map[string]interface{}{
		"secret_name": name,
		"secret_id":   secret.ID,
	})
	return secret, nil
}

func (s *Service) GetSecretValue(ctx context.Context, tenantID string, secretID string, format string) (SecretValueResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	secretID = strings.TrimSpace(secretID)
	format = strings.TrimSpace(strings.ToLower(format))
	if tenantID == "" || secretID == "" {
		return SecretValueResponse{}, errors.New("tenant_id and secret_id are required")
	}
	secret, enc, err := s.store.GetSecretWithValue(ctx, tenantID, secretID)
	if err != nil {
		return SecretValueResponse{}, err
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
	_ = s.publishAudit(ctx, "audit.secrets.value_read", tenantID, map[string]interface{}{
		"secret_id": secretID,
		"format":    usedFormat,
	})
	return SecretValueResponse{
		Value:       string(converted),
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

	updated, err := s.store.UpdateSecret(ctx, tenantID, secretID, req, expiresAt, value)
	if err != nil {
		return Secret{}, err
	}
	_ = s.publishAudit(ctx, "audit.secrets.updated", tenantID, map[string]interface{}{
		"secret_id":       updated.ID,
		"rotated_value":   req.Value != nil,
		"lease_ttl_secs":  updated.LeaseTTLSeconds,
		"current_version": updated.CurrentVersion,
	})
	return updated, nil
}

func (s *Service) DeleteSecret(ctx context.Context, tenantID string, secretID string) error {
	tenantID = strings.TrimSpace(tenantID)
	secretID = strings.TrimSpace(secretID)
	if tenantID == "" || secretID == "" {
		return errors.New("tenant_id and secret_id are required")
	}
	if err := s.store.DeleteSecret(ctx, tenantID, secretID); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.secrets.deleted", tenantID, map[string]interface{}{
		"secret_id": secretID,
	})
	return nil
}

func (s *Service) GenerateSSHKey(ctx context.Context, req GenerateSSHKeyRequest) (Secret, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Secret{}, "", err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Secret{}, "", err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubKey, err := ssh.NewPublicKey(pub)
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
	_ = s.publishAudit(ctx, "audit.secrets.generated", req.TenantID, map[string]interface{}{
		"secret_id": secret.ID,
		"type":      "ssh_private_key",
	})
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
	_ = s.publishAudit(ctx, "audit.secrets.generated", req.TenantID, map[string]interface{}{
		"secret_id": secret.ID,
		"type":      secretType,
		"key_type":  req.KeyType,
	})
	return secret, publicVal, req.KeyType, nil
}

func generateSSHKeyPair(keyType string) (string, string, error) {
	var (
		privAny interface{}
		pubAny  interface{}
		err     error
	)
	switch keyType {
	case "ed25519":
		var pub ed25519.PublicKey
		var priv ed25519.PrivateKey
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", "", err
		}
		privAny = priv
		pubAny = pub
	case "rsa-4096":
		var priv *rsa.PrivateKey
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return "", "", err
		}
		privAny = priv
		pubAny = &priv.PublicKey
	case "ecdsa-p384":
		var priv *ecdsa.PrivateKey
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return "", "", err
		}
		privAny = priv
		pubAny = &priv.PublicKey
	default:
		return "", "", errors.New("unsupported ssh key type")
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(privAny)
	if err != nil {
		return "", "", err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubKey, err := ssh.NewPublicKey(pubAny)
	if err != nil {
		return "", "", err
	}
	pubSSH := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))
	return string(privPEM), pubSSH, nil
}

func generateOpenPGPKeyPair(name string) (string, string, error) {
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
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
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
	hash := sha256.Sum256(plain)
	return EncryptedSecretValue{
		WrappedDEK:   env.WrappedDEK,
		WrappedDEKIV: env.WrappedDEKIV,
		Ciphertext:   env.Ciphertext,
		DataIV:       env.DataIV,
		ValueHash:    hash[:],
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

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	payload, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "secrets",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, payload)
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
	b := make([]byte, 8)
	_, _ = rand.Read(b)
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
		case "ppk":
			return toPPK(plain)
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

func toPPK(raw []byte) ([]byte, string, string, error) {
	key, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, "", "", err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, "", "", err
	}
	pub := signer.PublicKey()
	pubLine := base64.StdEncoding.EncodeToString(pub.Marshal())
	privLine := base64.StdEncoding.EncodeToString(raw)
	mac := sha256.Sum256([]byte(pubLine + privLine))
	out := fmt.Sprintf("PuTTY-User-Key-File-2: %s\nEncryption: none\nComment: vecta\nPublic-Lines: 1\n%s\nPrivate-Lines: 1\n%s\nPrivate-MAC: %x\n", pub.Type(), pubLine, privLine, mac[:16])
	return []byte(out), "ppk", "application/x-putty-private-key", nil
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

func toPGPArmor(secretType string, raw []byte) ([]byte, string, string, error) {
	head := "PGP PRIVATE KEY BLOCK"
	if secretType == "pgp_public_key" {
		head = "PGP PUBLIC KEY BLOCK"
	}
	body := base64.StdEncoding.EncodeToString(raw)
	lines := make([]string, 0, len(body)/64+1)
	for len(body) > 64 {
		lines = append(lines, body[:64])
		body = body[64:]
	}
	if len(body) > 0 {
		lines = append(lines, body)
	}
	armored := "-----BEGIN " + head + "-----\n"
	armored += strings.Join(lines, "\n")
	armored += "\n-----END " + head + "-----\n"
	return []byte(armored), "armored", "application/pgp-keys", nil
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
