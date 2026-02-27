package main

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"math/bits"
	"sort"
	"strings"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/crypto/sha3"
	"vecta-kms/pkg/clustersync"
	"vecta-kms/pkg/crypto"
	"vecta-kms/pkg/metering"
	"vecta-kms/pkg/payment"
)

type Service struct {
	store    Store
	cache    KeyCache
	exists   *bloom.BloomFilter
	events   AuditPublisher
	cluster  clustersync.Publisher
	meter    *metering.Meter
	mek      []byte
	policy   PolicyEvaluator
	pf       bool
	fipsMode FIPSModeProvider
	approval *governanceApprovalClient
}

func NewService(store Store, cache KeyCache, events AuditPublisher, meter *metering.Meter, mek []byte, policy PolicyEvaluator, policyFailClosed bool) *Service {
	f := bloom.NewWithEstimates(10_000_000, 0.01)
	if policy == nil {
		policy = allowAllPolicyEvaluator{}
	}
	return &Service{
		store:    store,
		cache:    cache,
		exists:   f,
		events:   events,
		meter:    meter,
		mek:      mek,
		policy:   policy,
		pf:       policyFailClosed,
		fipsMode: staticFIPSModeProvider{enabled: false},
	}
}

func (s *Service) SetGovernanceApprovalClient(client *governanceApprovalClient) {
	if client == nil {
		return
	}
	s.approval = client
}

func (s *Service) SetClusterSyncPublisher(pub clustersync.Publisher) {
	if pub == nil {
		return
	}
	s.cluster = pub
}

type CreateKeyRequest struct {
	TenantID         string            `json:"tenant_id"`
	Name             string            `json:"name"`
	Algorithm        string            `json:"algorithm"`
	KeyType          string            `json:"key_type"`
	Purpose          string            `json:"purpose"`
	ActivationMode   string            `json:"activation_mode"`
	ActivationDate   *time.Time        `json:"activation_date"`
	Owner            string            `json:"owner"`
	Cloud            string            `json:"cloud"`
	Region           string            `json:"region"`
	Compliance       []string          `json:"compliance"`
	Tags             []string          `json:"tags"`
	Labels           map[string]string `json:"labels"`
	IVMode           string            `json:"iv_mode"`
	CreatedBy        string            `json:"created_by"`
	OpsLimit         int64             `json:"ops_limit"`
	OpsLimitWindow   string            `json:"ops_limit_window"`
	ExportAllowed    bool              `json:"export_allowed"`
	ApprovalRequired bool              `json:"approval_required"`
	ApprovalPolicyID string            `json:"approval_policy_id"`
}

type ImportKeyRequest struct {
	CreateKeyRequest
	MaterialB64    string `json:"material"`
	ExpectedKCV    string `json:"expected_kcv"`
	ImportMethod   string `json:"import_method"`
	ImportPassword string `json:"import_password"`
	WrappingKeyID  string `json:"wrapping_key_id"`
	MaterialIVB64  string `json:"material_iv"`
	Origin         string `json:"origin"`
}

type FormKeyComponent struct {
	MaterialB64        string `json:"material"`
	WrappedMaterialB64 string `json:"wrapped_material"`
	MaterialIVB64      string `json:"material_iv"`
	WrappingKeyID      string `json:"wrapping_key_id"`
}

type FormKeyRequest struct {
	CreateKeyRequest
	ComponentMode string             `json:"component_mode"`
	Components    []FormKeyComponent `json:"components"`
	Parity        string             `json:"parity"`
}

type WrappedExportResult struct {
	KeyID          string
	WrappedKeyB64  string
	MaterialIVB64  string
	KCV            string
	WrappingKeyID  string
	WrappingKeyKCV string
}

type PlaintextExportResult struct {
	KeyID               string
	KCV                 string
	PublicKeyPlaintext  string
	PublicKeyEncoding   string
	PublicComponentType string
}

type UpdateKeyRequest struct {
	Name       string            `json:"name"`
	Purpose    string            `json:"purpose"`
	Owner      string            `json:"owner"`
	Cloud      string            `json:"cloud"`
	Region     string            `json:"region"`
	Compliance []string          `json:"compliance"`
	Tags       []string          `json:"tags"`
	Labels     map[string]string `json:"labels"`
	IVMode     string            `json:"iv_mode"`
}

type EncryptRequest struct {
	TenantID     string `json:"tenant_id"`
	PlaintextB64 string `json:"plaintext"`
	IVB64        string `json:"iv"`
	IVMode       string `json:"iv_mode"`
	AADB64       string `json:"aad"`
	ReferenceID  string `json:"reference_id"`
	Operation    string `json:"-"`
}

type DecryptRequest struct {
	TenantID      string `json:"tenant_id"`
	CiphertextB64 string `json:"ciphertext"`
	IVB64         string `json:"iv"`
	AADB64        string `json:"aad"`
	ReferenceID   string `json:"reference_id"`
	Operation     string `json:"-"`
}

type SignRequest struct {
	TenantID  string `json:"tenant_id"`
	DataB64   string `json:"data"`
	Algorithm string `json:"algorithm"`
	Operation string `json:"-"`
}

type VerifyRequest struct {
	TenantID     string `json:"tenant_id"`
	DataB64      string `json:"data"`
	SignatureB64 string `json:"signature"`
	Algorithm    string `json:"algorithm"`
	Operation    string `json:"-"`
}

type CryptoResponse struct {
	KeyID        string `json:"key_id"`
	Version      int    `json:"version"`
	CipherB64    string `json:"ciphertext,omitempty"`
	IVB64        string `json:"iv,omitempty"`
	PlainB64     string `json:"plaintext,omitempty"`
	SignatureB64 string `json:"signature,omitempty"`
	Verified     bool   `json:"verified,omitempty"`
	KCV          string `json:"kcv,omitempty"`
}

type HashRequest struct {
	TenantID    string `json:"tenant_id"`
	Algorithm   string `json:"algorithm"`
	InputB64    string `json:"input"`
	ReferenceID string `json:"reference_id"`
}

type HashResponse struct {
	Algorithm string `json:"algorithm"`
	DigestB64 string `json:"digest"`
}

type RandomRequest struct {
	TenantID    string `json:"tenant_id"`
	Length      int    `json:"length"`
	Source      string `json:"source"`
	ReferenceID string `json:"reference_id"`
}

type RandomResponse struct {
	BytesB64 string `json:"bytes"`
	Length   int    `json:"length"`
	Source   string `json:"source"`
}

type DeriveRequest struct {
	TenantID    string `json:"tenant_id"`
	Algorithm   string `json:"algorithm"`
	LengthBits  int    `json:"length_bits"`
	InfoB64     string `json:"info"`
	SaltB64     string `json:"salt"`
	ReferenceID string `json:"reference_id"`
	Operation   string `json:"-"`
}

type DeriveResponse struct {
	KeyID      string `json:"key_id"`
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	LengthBits int    `json:"length_bits"`
	DerivedB64 string `json:"derived_key"`
}

type KEMEncapsulateRequest struct {
	TenantID    string `json:"tenant_id"`
	Algorithm   string `json:"algorithm"`
	AADB64      string `json:"aad"`
	ReferenceID string `json:"reference_id"`
	Operation   string `json:"-"`
}

type KEMDecapsulateRequest struct {
	TenantID        string `json:"tenant_id"`
	Algorithm       string `json:"algorithm"`
	EncapsulatedB64 string `json:"encapsulated_key"`
	IVB64           string `json:"iv"`
	AADB64          string `json:"aad"`
	ReferenceID     string `json:"reference_id"`
	Operation       string `json:"-"`
}

type KEMResponse struct {
	KeyID           string `json:"key_id"`
	Version         int    `json:"version"`
	Algorithm       string `json:"algorithm"`
	SharedSecretB64 string `json:"shared_secret"`
	EncapsulatedB64 string `json:"encapsulated_key,omitempty"`
	IVB64           string `json:"iv,omitempty"`
}

func normalizeTags(tags []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		t := strings.TrimSpace(tag)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func isHexColor(value string) bool {
	v := strings.TrimSpace(value)
	if len(v) != 7 || v[0] != '#' {
		return false
	}
	for i := 1; i < len(v); i += 1 {
		c := v[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

type approvalRequiredError struct {
	RequestID string
}

func (e approvalRequiredError) Error() string {
	return "approval required"
}

func normalizeActivationMode(mode string) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	switch m {
	case "", "immediate":
		return "immediate"
	case "pre-active", "preactive":
		return "pre-active"
	case "scheduled":
		return "scheduled"
	default:
		return ""
	}
}

func normalizeLifecycleStatus(status string) string {
	s := strings.ToLower(strings.TrimSpace(status))
	switch s {
	case "active":
		return "active"
	case "pre-active", "preactive":
		return "pre-active"
	case "disabled":
		return "disabled"
	case "deactivated", "retired":
		return "deactivated"
	case "destroy-pending", "delete-pending", "deletion-pending":
		return "destroy-pending"
	case "destroyed", "deleted":
		return "deleted"
	case "generation", "generated":
		return "pre-active"
	default:
		return s
	}
}

func isDeletedLike(status string) bool {
	norm := normalizeLifecycleStatus(status)
	return norm == "destroy-pending" || norm == "deleted"
}

func normalizeOldVersionAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "", "deactivate":
		return "deactivate"
	case "keep-active", "keep_active", "keepactive":
		return "keep-active"
	case "destroy", "delete":
		return "destroy"
	default:
		return ""
	}
}

func resolveActivation(mode string, at *time.Time) (string, *time.Time, error) {
	switch normalizeActivationMode(mode) {
	case "immediate":
		return "active", nil, nil
	case "pre-active":
		return "pre-active", nil, nil
	case "scheduled":
		if at == nil {
			return "", nil, errors.New("activation_date is required for scheduled activation")
		}
		when := at.UTC()
		if !when.After(time.Now().UTC()) {
			return "active", nil, nil
		}
		return "pre-active", &when, nil
	default:
		return "", nil, errors.New("activation mode must be immediate, pre-active, or scheduled")
	}
}

func normalizeComponentMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "clear-generated", "generated":
		return "clear-generated"
	case "clear-user", "clear":
		return "clear-user"
	case "encrypted-user", "encrypted":
		return "encrypted-user"
	default:
		return ""
	}
}

func normalizeParityMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "none":
		return "none"
	case "odd":
		return "odd"
	case "even":
		return "even"
	default:
		return ""
	}
}

func isDESFamilyAlgorithm(algorithm string) bool {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	return strings.Contains(a, "DES")
}

func materialLengthForAlgorithm(algorithm string) int {
	l := 32
	a := strings.ToUpper(algorithm)
	switch {
	case strings.Contains(a, "ML-KEM"):
		l = mlkem.SeedSize
	case strings.Contains(a, "AES-128"):
		l = 16
	case strings.Contains(a, "AES-192"):
		l = 24
	case strings.Contains(a, "AES"):
		l = 32
	case strings.Contains(a, "2DES"):
		l = 16
	case strings.Contains(a, "3DES") || strings.Contains(a, "TDES"):
		l = 24
	case strings.Contains(a, "DES"):
		l = 8
	case strings.Contains(a, "HMAC"):
		l = 32
	}
	return l
}

func hasByteParity(v byte, mode string) bool {
	ones := bits.OnesCount8(v)
	if mode == "even" {
		return ones%2 == 0
	}
	return ones%2 == 1
}

func validateParity(raw []byte, mode string) bool {
	for _, v := range raw {
		if !hasByteParity(v, mode) {
			return false
		}
	}
	return true
}

func applyParity(raw []byte, mode string) []byte {
	out := append([]byte{}, raw...)
	for i := range out {
		upper := out[i] & 0xFE
		ones := bits.OnesCount8(upper)
		switch mode {
		case "even":
			if ones%2 == 0 {
				out[i] = upper
			} else {
				out[i] = upper | 0x01
			}
		default: // odd
			if ones%2 == 0 {
				out[i] = upper | 0x01
			} else {
				out[i] = upper
			}
		}
	}
	return out
}

func xorComponents(components [][]byte, size int) []byte {
	out := make([]byte, size)
	for _, comp := range components {
		for i := 0; i < size; i++ {
			out[i] ^= comp[i]
		}
	}
	return out
}

func decodeFlexibleComponent(value string) ([]byte, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return nil, errors.New("component material is empty")
	}
	hexCandidate := strings.ReplaceAll(strings.ReplaceAll(raw, " ", ""), "-", "")
	if len(hexCandidate)%2 == 0 && len(hexCandidate) > 0 {
		isHex := true
		for i := 0; i < len(hexCandidate); i++ {
			c := hexCandidate[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				isHex = false
				break
			}
		}
		if isHex {
			return hex.DecodeString(hexCandidate)
		}
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("component material must be hex or base64")
	}
	return b, nil
}

func (s *Service) createKeyFromMaterial(
	ctx context.Context,
	req CreateKeyRequest,
	raw []byte,
	expectedKCV string,
	policyOperation string,
	auditSubject string,
) (Key, error) {
	if req.TenantID == "" || req.Name == "" || req.Algorithm == "" {
		return Key{}, errors.New("tenant_id, name, algorithm are required")
	}
	if err := s.enforceFIPSKeyAlgorithm(ctx, req.TenantID, req.Algorithm, policyOperation); err != nil {
		return Key{}, err
	}
	if req.KeyType == "" {
		req.KeyType = "symmetric"
	}
	if req.IVMode == "" {
		req.IVMode = "internal"
	}
	if req.CreatedBy == "" {
		req.CreatedBy = "system"
	}
	if policyOperation == "" {
		policyOperation = "key.create"
	}
	if auditSubject == "" {
		auditSubject = "audit.key.create"
	}
	req.Tags = normalizeTags(req.Tags)
	_ = s.store.EnsureDefaultTags(ctx, req.TenantID)
	initialStatus, activationAt, err := resolveActivation(req.ActivationMode, req.ActivationDate)
	if err != nil {
		return Key{}, err
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:  req.TenantID,
		Operation: policyOperation,
		Algorithm: req.Algorithm,
		Purpose:   req.Purpose,
		IVMode:    defaultIV(req.IVMode),
		OpsLimit:  req.OpsLimit,
		KeyStatus: initialStatus,
	}); err != nil {
		return Key{}, err
	}
	kcv, kcvMethod, err := computeKCVStrict(req.Algorithm, raw)
	if err != nil {
		return Key{}, err
	}
	if expectedKCV != "" && !strings.EqualFold(strings.TrimSpace(expectedKCV), hex.EncodeToString(kcv)) {
		return Key{}, errors.New("kcv mismatch")
	}
	env, err := crypto.EncryptEnvelope(s.mek, raw)
	if err != nil {
		return Key{}, err
	}
	keyID := newID("key")
	key := Key{
		ID:               keyID,
		TenantID:         req.TenantID,
		Name:             req.Name,
		Algorithm:        req.Algorithm,
		KeyType:          req.KeyType,
		Purpose:          req.Purpose,
		Status:           initialStatus,
		ActivationDate:   activationAt,
		CurrentVersion:   1,
		KCV:              kcv,
		KCVAlgorithm:     kcvMethod,
		IVMode:           defaultIV(req.IVMode),
		Owner:            req.Owner,
		Cloud:            req.Cloud,
		Region:           req.Region,
		Compliance:       req.Compliance,
		Tags:             req.Tags,
		Labels:           req.Labels,
		ExportAllowed:    req.ExportAllowed,
		OpsLimit:         req.OpsLimit,
		OpsLimitWindow:   req.OpsLimitWindow,
		ApprovalRequired: req.ApprovalRequired,
		ApprovalPolicyID: req.ApprovalPolicyID,
		CreatedBy:        req.CreatedBy,
	}
	ver := KeyVersion{
		ID:                newID("kv"),
		TenantID:          req.TenantID,
		KeyID:             keyID,
		Version:           1,
		EncryptedMaterial: env.Ciphertext,
		MaterialIV:        env.DataIV,
		WrappedDEK:        packWrappedDEK(env.WrappedDEKIV, env.WrappedDEK),
		KCV:               kcv,
		Status:            initialStatus,
	}
	if err := s.store.CreateKeyWithVersion(ctx, key, ver); err != nil {
		return Key{}, err
	}
	s.exists.AddString(existsToken(req.TenantID, keyID))
	_ = s.cache.Set(ctx, key)
	_ = s.publishAudit(ctx, auditSubject, req.TenantID, map[string]any{"key_id": keyID, "kcv": strings.ToUpper(hex.EncodeToString(kcv))})
	return key, nil
}

func derivePublicFromPrivateMaterial(algorithm string, privateRaw []byte) ([]byte, error) {
	if isMLKEMKeyAlgorithm(algorithm) {
		switch normalizeKEMAlgorithm(algorithm) {
		case "ml-kem-768":
			dk, err := mlkem.NewDecapsulationKey768(privateRaw)
			if err != nil {
				return nil, errors.New("invalid ML-KEM-768 private key material")
			}
			return dk.EncapsulationKey().Bytes(), nil
		case "ml-kem-1024":
			dk, err := mlkem.NewDecapsulationKey1024(privateRaw)
			if err != nil {
				return nil, errors.New("invalid ML-KEM-1024 private key material")
			}
			return dk.EncapsulationKey().Bytes(), nil
		default:
			return nil, errors.New("unsupported KEM algorithm")
		}
	}
	if key, err := x509.ParsePKCS8PrivateKey(privateRaw); err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return x509.MarshalPKIXPublicKey(&k.PublicKey)
		case *ecdsa.PrivateKey:
			return x509.MarshalPKIXPublicKey(&k.PublicKey)
		case ed25519.PrivateKey:
			pub := k.Public()
			return x509.MarshalPKIXPublicKey(pub)
		default:
			return nil, errors.New("unsupported private key type for public derivation")
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(privateRaw); err == nil {
		return x509.MarshalPKIXPublicKey(&key.PublicKey)
	}
	if key, err := x509.ParseECPrivateKey(privateRaw); err == nil {
		return x509.MarshalPKIXPublicKey(&key.PublicKey)
	}
	return nil, errors.New("could not derive public key from private material")
}

func (s *Service) resolvePublicMaterialFromPair(ctx context.Context, req CreateKeyRequest) ([]byte, error) {
	if !isPublicKeyType(req.KeyType) {
		return nil, errors.New("not a public-key create request")
	}
	pairID := strings.TrimSpace(req.Labels["pair_id"])
	if pairID == "" {
		return nil, errors.New("pair_id label is required for paired public-key creation")
	}
	const pageSize = 500
	offset := 0
	for {
		items, err := s.store.ListKeys(ctx, req.TenantID, pageSize, offset)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if strings.TrimSpace(item.Labels["pair_id"]) != pairID {
				continue
			}
			role := strings.ToLower(strings.TrimSpace(item.Labels["component_role"]))
			if role != "private" {
				continue
			}
			ver, err := s.GetVersion(ctx, req.TenantID, item.ID, 0)
			if err != nil {
				return nil, err
			}
			privateRaw, err := s.decryptMaterial(ver)
			if err != nil {
				return nil, err
			}
			defer crypto.Zeroize(privateRaw)
			return derivePublicFromPrivateMaterial(req.Algorithm, privateRaw)
		}
		if len(items) < pageSize {
			break
		}
		offset += len(items)
	}
	return nil, errors.New("matching private component not found for pair_id")
}

func (s *Service) CreateKey(ctx context.Context, req CreateKeyRequest) (Key, error) {
	var (
		raw []byte
		err error
	)
	if isPublicKeyType(req.KeyType) && req.Labels != nil && strings.TrimSpace(req.Labels["pair_id"]) != "" {
		raw, err = s.resolvePublicMaterialFromPair(ctx, req)
	} else {
		raw, err = generateMaterialForCreate(req.Algorithm, req.KeyType)
	}
	if err != nil {
		return Key{}, err
	}
	defer crypto.Zeroize(raw)
	return s.createKeyFromMaterial(ctx, req, raw, "", "key.create", "audit.key.create")
}

func (s *Service) ImportKey(ctx context.Context, req ImportKeyRequest) (Key, error) {
	parsed, err := s.resolveImportMaterial(ctx, req)
	if err != nil {
		return Key{}, err
	}
	if req.Labels == nil {
		req.Labels = map[string]string{}
	}
	req.Labels["import_method"] = parsed.Method
	if origin := strings.TrimSpace(req.Origin); origin != "" {
		req.Labels["origin"] = origin
	}
	if isAutoDetectAlgorithm(req.Algorithm) {
		req.Algorithm = parsed.Algorithm
	}
	if strings.TrimSpace(req.Algorithm) == "" {
		return Key{}, errors.New("algorithm is required for this import payload")
	}
	if strings.TrimSpace(req.KeyType) == "" {
		req.KeyType = parsed.KeyType
	}
	if strings.TrimSpace(req.KeyType) == "" {
		req.KeyType = inferKeyTypeFromAlgorithm(req.Algorithm)
	}
	if strings.TrimSpace(req.Purpose) == "" {
		req.Purpose = parsed.Purpose
	}
	if strings.TrimSpace(req.Purpose) == "" {
		req.Purpose = inferPurposeFromAlgorithm(req.Algorithm)
	}
	expectedKCV := strings.TrimSpace(req.ExpectedKCV)
	if expectedKCV == "" {
		expectedKCV = strings.TrimSpace(parsed.ExpectedKCV)
	}
	defer crypto.Zeroize(parsed.Raw)
	return s.createKeyFromMaterial(ctx, req.CreateKeyRequest, parsed.Raw, expectedKCV, "key.import", "audit.key.import")
}

type importMaterialResult struct {
	Raw         []byte
	Algorithm   string
	KeyType     string
	Purpose     string
	ExpectedKCV string
	Method      string
}

type wrappedImportEnvelope struct {
	WrappedMaterial string
	MaterialIV      string
	WrappingKeyID   string
}

func normalizeImportMethod(method string) string {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "", "raw", "raw-key", "raw-key-material", "base64", "raw-base64", "autodetect":
		return "raw"
	case "pem", "pkcs8", "pkcs-8", "pkcs#8", "pkcs#8 / pem", "pkcs8 / pem":
		return "pem"
	case "jwk", "json web key":
		return "jwk"
	case "tr31", "tr-31", "tr-31 key block", "tr31 key block":
		return "tr31"
	case "pkcs12", "pkcs-12", "pkcs#12", "pkcs#12 (.p12)", "p12":
		return "pkcs12"
	default:
		return ""
	}
}

func isAutoDetectAlgorithm(v string) bool {
	raw := strings.ToLower(strings.TrimSpace(v))
	return raw == "" || raw == "auto" || strings.Contains(raw, "auto-detect")
}

func inferSymmetricAlgorithmFromLen(size int) string {
	switch size {
	case 16:
		return "AES-128"
	case 24:
		return "AES-192"
	case 32:
		return "AES-256"
	case 8:
		return "DES"
	default:
		return ""
	}
}

func inferKeyTypeFromAlgorithm(algorithm string) string {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	if alg == "" {
		return "symmetric"
	}
	if strings.Contains(alg, "RSA") || strings.Contains(alg, "ECDSA") || strings.Contains(alg, "ECDH") ||
		strings.Contains(alg, "ED25519") || strings.Contains(alg, "ED448") || strings.Contains(alg, "X25519") ||
		strings.Contains(alg, "X448") || strings.Contains(alg, "ML-KEM") || strings.Contains(alg, "ML-DSA") || strings.Contains(alg, "SLH-DSA") {
		return "asymmetric"
	}
	return "symmetric"
}

func inferPurposeFromAlgorithm(algorithm string) string {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(alg, "HMAC"), strings.Contains(alg, "CMAC"), strings.Contains(alg, "GMAC"), strings.Contains(alg, "POLY1305"):
		return "mac"
	case strings.Contains(alg, "ECDH"), strings.Contains(alg, "X25519"), strings.Contains(alg, "X448"), strings.Contains(alg, "ML-KEM"):
		return "key-agreement"
	case strings.Contains(alg, "RSA") && strings.Contains(alg, "OAEP"):
		return "encrypt-decrypt"
	case strings.Contains(alg, "RSA"), strings.Contains(alg, "ECDSA"), strings.Contains(alg, "ED25519"), strings.Contains(alg, "ED448"), strings.Contains(alg, "DSA"):
		return "sign-verify"
	default:
		return "encrypt-decrypt"
	}
}

func parseWrappedImportEnvelope(raw string) (wrappedImportEnvelope, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
		return wrappedImportEnvelope{}, false
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return wrappedImportEnvelope{}, false
	}
	envelope := wrappedImportEnvelope{
		WrappedMaterial: mapString(payload, "wrapped_material", "wrapped_key", "material"),
		MaterialIV:      mapString(payload, "material_iv", "iv"),
		WrappingKeyID:   mapString(payload, "wrapping_key_id"),
	}
	if envelope.WrappedMaterial == "" && envelope.MaterialIV == "" && envelope.WrappingKeyID == "" {
		return wrappedImportEnvelope{}, false
	}
	return envelope, true
}

func mapString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			if s, ok := v.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func normalizeCurveAlgorithm(curveName string) string {
	name := strings.ToUpper(strings.TrimSpace(curveName))
	switch name {
	case "P-256", "SECP256R1", "PRIME256V1":
		return "ECDSA-P256"
	case "P-384", "SECP384R1":
		return "ECDSA-P384"
	case "P-521", "SECP521R1":
		return "ECDSA-P521"
	case "BRAINPOOLP256R1":
		return "ECDSA-Brainpool256"
	case "BRAINPOOLP384R1":
		return "ECDSA-Brainpool384"
	default:
		return ""
	}
}

func inferAlgorithmFromPublicKey(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil {
			return "RSA-2048"
		}
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil {
			return "ECDSA-P256"
		}
		if alg := normalizeCurveAlgorithm(k.Curve.Params().Name); alg != "" {
			return alg
		}
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return ""
	}
}

func inferAlgorithmFromPrivateKey(priv any) string {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		if k == nil || k.N == nil {
			return "RSA-2048"
		}
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PrivateKey:
		if k == nil || k.Curve == nil {
			return "ECDSA-P256"
		}
		if alg := normalizeCurveAlgorithm(k.Curve.Params().Name); alg != "" {
			return alg
		}
		return "ECDSA"
	case ed25519.PrivateKey:
		return "Ed25519"
	default:
		return ""
	}
}

func parseDERImportMaterial(der []byte) ([]byte, string, string, error) {
	raw := bytes.TrimSpace(der)
	if len(raw) == 0 {
		return nil, "", "", errors.New("empty DER payload")
	}
	if key, err := x509.ParsePKCS8PrivateKey(raw); err == nil {
		alg := inferAlgorithmFromPrivateKey(key)
		return append([]byte{}, raw...), alg, "asymmetric-private", nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(raw); err == nil {
		return append([]byte{}, raw...), fmt.Sprintf("RSA-%d", key.N.BitLen()), "asymmetric-private", nil
	}
	if key, err := x509.ParseECPrivateKey(raw); err == nil {
		if derKey, marshalErr := x509.MarshalECPrivateKey(key); marshalErr == nil {
			return derKey, inferAlgorithmFromPrivateKey(key), "asymmetric-private", nil
		}
		return append([]byte{}, raw...), inferAlgorithmFromPrivateKey(key), "asymmetric-private", nil
	}
	if pub, err := x509.ParsePKIXPublicKey(raw); err == nil {
		if derPub, marshalErr := x509.MarshalPKIXPublicKey(pub); marshalErr == nil {
			return derPub, inferAlgorithmFromPublicKey(pub), "asymmetric-public", nil
		}
		return append([]byte{}, raw...), inferAlgorithmFromPublicKey(pub), "asymmetric-public", nil
	}
	if pub, err := x509.ParsePKCS1PublicKey(raw); err == nil {
		derPub := x509.MarshalPKCS1PublicKey(pub)
		return derPub, fmt.Sprintf("RSA-%d", pub.N.BitLen()), "asymmetric-public", nil
	}
	if cert, err := x509.ParseCertificate(raw); err == nil {
		pubDER, marshalErr := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if marshalErr != nil {
			return nil, "", "", marshalErr
		}
		return pubDER, inferAlgorithmFromPublicKey(cert.PublicKey), "asymmetric-public", nil
	}
	return nil, "", "", errors.New("unsupported DER key/certificate payload")
}

func parsePEMImportMaterial(raw []byte, importPassword string) ([]byte, string, string, error) {
	payload := bytes.TrimSpace(raw)
	if len(payload) == 0 {
		return nil, "", "", errors.New("material is empty")
	}
	rest := payload
	seenPEM := false
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		seenPEM = true
		rest = next
		blockType := strings.ToUpper(strings.TrimSpace(block.Type))
		if x509.IsEncryptedPEMBlock(block) {
			if strings.TrimSpace(importPassword) == "" {
				return nil, "", "", errors.New("encrypted PEM requires import_password")
			}
			der, err := x509.DecryptPEMBlock(block, []byte(importPassword))
			if err != nil {
				return nil, "", "", errors.New("failed to decrypt PEM block")
			}
			return parseDERImportMaterial(der)
		}
		switch blockType {
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "PUBLIC KEY", "RSA PUBLIC KEY", "CERTIFICATE":
			if material, alg, keyType, err := parseDERImportMaterial(block.Bytes); err == nil {
				return material, alg, keyType, nil
			}
		case "ENCRYPTED PRIVATE KEY":
			return nil, "", "", errors.New("PKCS#8 encrypted private key is not supported; decrypt first or use PKCS#12")
		}
	}
	if seenPEM {
		return nil, "", "", errors.New("PEM payload does not contain a supported key block")
	}
	return parseDERImportMaterial(payload)
}

func decodeJWKBase64URL(value string) ([]byte, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return nil, errors.New("missing JWK field")
	}
	if b, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(raw); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(raw)
}

func algorithmFromJWKHint(alg string) string {
	up := strings.ToUpper(strings.TrimSpace(alg))
	switch {
	case strings.HasPrefix(up, "A128"):
		return "AES-128"
	case strings.HasPrefix(up, "A192"):
		return "AES-192"
	case strings.HasPrefix(up, "A256"):
		return "AES-256"
	case strings.HasPrefix(up, "HS256"):
		return "HMAC-SHA256"
	case strings.HasPrefix(up, "HS384"):
		return "HMAC-SHA384"
	case strings.HasPrefix(up, "HS512"):
		return "HMAC-SHA512"
	case strings.HasPrefix(up, "ES256"):
		return "ECDSA-P256"
	case strings.HasPrefix(up, "ES384"):
		return "ECDSA-P384"
	case strings.HasPrefix(up, "ES512"):
		return "ECDSA-P521"
	case strings.HasPrefix(up, "EDDSA"):
		return "Ed25519"
	case strings.HasPrefix(up, "RS"), strings.HasPrefix(up, "PS"):
		return "RSA-2048"
	default:
		return ""
	}
}

func parseJWKImportMaterial(raw string) ([]byte, string, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, "", "", errors.New("material is empty")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return nil, "", "", errors.New("invalid JWK JSON")
	}
	kty := strings.ToUpper(mapString(payload, "kty"))
	if kty == "" {
		return nil, "", "", errors.New("JWK missing kty")
	}
	algHint := algorithmFromJWKHint(mapString(payload, "alg"))
	switch kty {
	case "OCT":
		kRaw, err := decodeJWKBase64URL(mapString(payload, "k"))
		if err != nil {
			return nil, "", "", errors.New("JWK oct key is missing valid 'k'")
		}
		alg := algHint
		if alg == "" {
			alg = inferSymmetricAlgorithmFromLen(len(kRaw))
		}
		return kRaw, alg, "symmetric", nil
	case "RSA":
		bits := 0
		if nRaw, err := decodeJWKBase64URL(mapString(payload, "n")); err == nil {
			n := new(big.Int).SetBytes(nRaw)
			bits = n.BitLen()
		}
		alg := algHint
		if alg == "" {
			if bits > 0 {
				alg = fmt.Sprintf("RSA-%d", bits)
			} else {
				alg = "RSA-2048"
			}
		}
		keyType := "asymmetric-public"
		if mapString(payload, "d") != "" {
			keyType = "asymmetric-private"
		}
		return []byte(trimmed), alg, keyType, nil
	case "EC":
		alg := algHint
		if alg == "" {
			alg = normalizeCurveAlgorithm(mapString(payload, "crv"))
		}
		keyType := "asymmetric-public"
		if mapString(payload, "d") != "" {
			keyType = "asymmetric-private"
		}
		return []byte(trimmed), alg, keyType, nil
	case "OKP":
		crv := strings.ToUpper(mapString(payload, "crv"))
		alg := algHint
		if alg == "" {
			switch crv {
			case "ED25519":
				alg = "Ed25519"
			case "X25519":
				alg = "X25519"
			case "X448":
				alg = "X448"
			default:
				alg = crv
			}
		}
		keyType := "asymmetric-public"
		if mapString(payload, "d") != "" {
			keyType = "asymmetric-private"
		}
		return []byte(trimmed), alg, keyType, nil
	default:
		return nil, "", "", fmt.Errorf("unsupported JWK kty: %s", kty)
	}
}

func parseTR31ImportMaterial(raw string) ([]byte, string, string, string, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, "", "", "", "", errors.New("material is empty")
	}
	parsed := trimmed
	if strings.HasPrefix(trimmed, "{") {
		var payload map[string]any
		if err := json.Unmarshal([]byte(trimmed), &payload); err == nil {
			parsed = mapString(payload, "tr31", "tr31_block", "key_block", "material")
		}
	}
	parsed = strings.TrimSpace(parsed)
	if parsed == "" {
		return nil, "", "", "", "", errors.New("TR-31 payload is empty")
	}
	if !strings.Contains(parsed, "|") {
		if decoded, err := decodeFlexibleComponent(parsed); err == nil {
			parsed = strings.TrimSpace(string(decoded))
		}
	}
	block, err := payment.ParseTR31(parsed)
	if err != nil {
		return nil, "", "", "", "", errors.New("invalid TR-31 key block")
	}
	alg := strings.ToUpper(strings.TrimSpace(block.Algorithm))
	if alg == "" {
		alg = inferSymmetricAlgorithmFromLen(len(block.Key))
	}
	purpose := "encrypt-decrypt"
	usage := strings.ToUpper(strings.TrimSpace(block.Usage))
	switch {
	case strings.Contains(usage, "WRAP"), strings.Contains(usage, "KEK"), strings.Contains(usage, "K0"), strings.Contains(usage, "K1"):
		purpose = "wrap-unwrap"
	case strings.Contains(usage, "MAC"), strings.Contains(usage, "M0"), strings.Contains(usage, "M1"):
		purpose = "mac"
	case strings.Contains(usage, "SIGN"), strings.Contains(usage, "S0"), strings.Contains(usage, "S1"):
		purpose = "sign-verify"
	}
	return append([]byte{}, block.Key...), alg, "symmetric", purpose, strings.TrimSpace(block.KCV), nil
}

func parsePKCS12ImportMaterial(raw []byte, importPassword string) ([]byte, string, string, error) {
	payload := bytes.TrimSpace(raw)
	if len(payload) == 0 {
		return nil, "", "", errors.New("material is empty")
	}
	if bytes.HasPrefix(payload, []byte("-----BEGIN")) {
		return parsePEMImportMaterial(payload, importPassword)
	}
	if decoded, err := decodeFlexibleComponent(string(payload)); err == nil {
		payload = decoded
	}
	blocks, err := pkcs12.ToPEM(payload, strings.TrimSpace(importPassword))
	if err != nil {
		if strings.TrimSpace(importPassword) == "" {
			return nil, "", "", errors.New("failed to parse PKCS#12 payload (try import_password)")
		}
		return nil, "", "", errors.New("failed to parse PKCS#12 payload")
	}
	var pemBuf bytes.Buffer
	for _, block := range blocks {
		if block == nil {
			continue
		}
		if encodeErr := pem.Encode(&pemBuf, block); encodeErr != nil {
			return nil, "", "", encodeErr
		}
	}
	if pemBuf.Len() == 0 {
		return nil, "", "", errors.New("PKCS#12 payload does not contain key material")
	}
	return parsePEMImportMaterial(pemBuf.Bytes(), importPassword)
}

func parseRawImportMaterial(raw string) ([]byte, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, "", errors.New("material is required")
	}
	if strings.HasPrefix(trimmed, "{") {
		var payload map[string]any
		if err := json.Unmarshal([]byte(trimmed), &payload); err == nil {
			if wrapped := mapString(payload, "wrapped_material"); wrapped != "" {
				return nil, "", errors.New("wrapped material requires wrapping_key_id")
			}
			for _, key := range []string{"material", "raw_material", "key_material", "plaintext", "public_key_plaintext"} {
				if v := mapString(payload, key); v != "" {
					decoded, decodeErr := decodeFlexibleComponent(v)
					if decodeErr == nil {
						return decoded, inferSymmetricAlgorithmFromLen(len(decoded)), nil
					}
				}
			}
		}
	}
	decoded, err := decodeFlexibleComponent(trimmed)
	if err != nil {
		return nil, "", errors.New("material must be hex or base64")
	}
	return decoded, inferSymmetricAlgorithmFromLen(len(decoded)), nil
}

func parseImportMethodFromRaw(method string, raw string, password string) (importMaterialResult, error) {
	switch method {
	case "raw":
		material, alg, err := parseRawImportMaterial(raw)
		if err != nil {
			return importMaterialResult{}, err
		}
		return importMaterialResult{
			Raw:       material,
			Algorithm: alg,
			KeyType:   "symmetric",
			Method:    method,
		}, nil
	case "pem":
		material, alg, keyType, err := parsePEMImportMaterial([]byte(raw), password)
		if err != nil {
			return importMaterialResult{}, err
		}
		return importMaterialResult{
			Raw:       material,
			Algorithm: alg,
			KeyType:   keyType,
			Method:    method,
		}, nil
	case "jwk":
		material, alg, keyType, err := parseJWKImportMaterial(raw)
		if err != nil {
			return importMaterialResult{}, err
		}
		return importMaterialResult{
			Raw:       material,
			Algorithm: alg,
			KeyType:   keyType,
			Method:    method,
		}, nil
	case "tr31":
		material, alg, keyType, purpose, expectedKCV, err := parseTR31ImportMaterial(raw)
		if err != nil {
			return importMaterialResult{}, err
		}
		return importMaterialResult{
			Raw:         material,
			Algorithm:   alg,
			KeyType:     keyType,
			Purpose:     purpose,
			ExpectedKCV: expectedKCV,
			Method:      method,
		}, nil
	case "pkcs12":
		material, alg, keyType, err := parsePKCS12ImportMaterial([]byte(raw), password)
		if err != nil {
			return importMaterialResult{}, err
		}
		return importMaterialResult{
			Raw:       material,
			Algorithm: alg,
			KeyType:   keyType,
			Method:    method,
		}, nil
	default:
		return importMaterialResult{}, errors.New("unsupported import_method")
	}
}

func parseImportMethodFromDecoded(method string, raw []byte, password string) (importMaterialResult, error) {
	switch method {
	case "raw":
		return importMaterialResult{
			Raw:       append([]byte{}, raw...),
			Algorithm: inferSymmetricAlgorithmFromLen(len(raw)),
			KeyType:   "symmetric",
			Method:    method,
		}, nil
	case "pem":
		material, alg, keyType, err := parsePEMImportMaterial(raw, password)
		if err != nil {
			return importMaterialResult{}, err
		}
		return importMaterialResult{
			Raw:       material,
			Algorithm: alg,
			KeyType:   keyType,
			Method:    method,
		}, nil
	case "jwk":
		return parseImportMethodFromRaw(method, string(raw), password)
	case "tr31":
		return parseImportMethodFromRaw(method, string(raw), password)
	case "pkcs12":
		material, alg, keyType, err := parsePKCS12ImportMaterial(raw, password)
		if err != nil {
			return importMaterialResult{}, err
		}
		return importMaterialResult{
			Raw:       material,
			Algorithm: alg,
			KeyType:   keyType,
			Method:    method,
		}, nil
	default:
		return importMaterialResult{}, errors.New("unsupported import_method")
	}
}

func (s *Service) resolveImportMaterial(ctx context.Context, req ImportKeyRequest) (importMaterialResult, error) {
	method := normalizeImportMethod(req.ImportMethod)
	if method == "" {
		return importMaterialResult{}, errors.New("import_method must be raw, pem, jwk, tr31, or pkcs12")
	}
	payload := strings.TrimSpace(req.MaterialB64)
	if payload == "" {
		return importMaterialResult{}, errors.New("material is required")
	}
	envelope, hasEnvelope := parseWrappedImportEnvelope(payload)
	wrappingKeyID := strings.TrimSpace(req.WrappingKeyID)
	materialIV := strings.TrimSpace(req.MaterialIVB64)
	if wrappingKeyID == "" && hasEnvelope {
		wrappingKeyID = strings.TrimSpace(envelope.WrappingKeyID)
	}
	if wrappingKeyID != "" {
		wrappedPayload := payload
		if hasEnvelope && strings.TrimSpace(envelope.WrappedMaterial) != "" {
			wrappedPayload = envelope.WrappedMaterial
		}
		if materialIV == "" && hasEnvelope {
			materialIV = strings.TrimSpace(envelope.MaterialIV)
		}
		if materialIV == "" {
			return importMaterialResult{}, errors.New("material_iv is required when wrapping_key_id is set")
		}
		plain, err := s.decryptWithWrappingKey(ctx, req.TenantID, wrappingKeyID, wrappedPayload, materialIV)
		if err != nil {
			return importMaterialResult{}, err
		}
		return parseImportMethodFromDecoded(method, plain, req.ImportPassword)
	}
	if hasEnvelope && strings.TrimSpace(envelope.WrappedMaterial) != "" {
		return importMaterialResult{}, errors.New("wrapped material requires wrapping_key_id")
	}
	return parseImportMethodFromRaw(method, payload, req.ImportPassword)
}

func (s *Service) decryptWithWrappingKey(ctx context.Context, tenantID string, keyID string, wrappedB64 string, ivB64 string) ([]byte, error) {
	if tenantID == "" || keyID == "" {
		return nil, errors.New("tenant_id and wrapping_key_id are required")
	}
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, err
	}
	if isDeletedLike(key.Status) {
		return nil, errors.New("wrapping key is deleted")
	}
	if normalizeLifecycleStatus(key.Status) != "active" {
		return nil, errors.New("wrapping key must be active")
	}
	if !strings.Contains(strings.ToLower(strings.TrimSpace(key.Purpose)), "wrap") {
		return nil, errors.New("wrapping key purpose must allow wrap/unwrap")
	}
	ver, err := s.GetVersion(ctx, tenantID, keyID, 0)
	if err != nil {
		return nil, err
	}
	wrappingMaterial, err := s.decryptMaterial(ver)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "message authentication failed") {
			return nil, errors.New("cannot decrypt wrapping key material (MEK mismatch or corrupted key envelope)")
		}
		return nil, err
	}
	defer crypto.Zeroize(wrappingMaterial)

	wrapped, err := decodeFlexibleComponent(wrappedB64)
	if err != nil {
		return nil, errors.New("wrapped_material must be hex or base64")
	}
	iv, err := decodeFlexibleComponent(ivB64)
	if err != nil {
		return nil, errors.New("material_iv must be hex or base64")
	}
	plain, err := decryptAESGCM(wrappingMaterial, iv, wrapped, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt component with wrapping key")
	}
	return plain, nil
}

func (s *Service) FormKey(ctx context.Context, req FormKeyRequest) (Key, []string, error) {
	mode := normalizeComponentMode(req.ComponentMode)
	if mode == "" {
		return Key{}, nil, errors.New("component_mode must be clear-generated, clear-user, or encrypted-user")
	}
	if len(req.Components) < 2 {
		return Key{}, nil, errors.New("at least two components are required")
	}
	materialLen := materialLengthForAlgorithm(req.Algorithm)
	parity := normalizeParityMode(req.Parity)
	if parity == "" {
		return Key{}, nil, errors.New("parity must be none, odd, or even")
	}
	if !isDESFamilyAlgorithm(req.Algorithm) {
		parity = "none"
	}
	components := make([][]byte, 0, len(req.Components))
	generated := make([]string, 0)
	for idx, item := range req.Components {
		var part []byte
		switch mode {
		case "clear-generated":
			gen, err := generateMaterial(req.Algorithm)
			if err != nil {
				return Key{}, nil, err
			}
			if len(gen) != materialLen {
				return Key{}, nil, fmt.Errorf("generated component %d has invalid length", idx+1)
			}
			if parity != "none" {
				gen = applyParity(gen, parity)
			}
			part = gen
			generated = append(generated, base64.StdEncoding.EncodeToString(gen))
		case "clear-user":
			raw, err := decodeFlexibleComponent(item.MaterialB64)
			if err != nil {
				return Key{}, nil, fmt.Errorf("component %d material must be hex or base64", idx+1)
			}
			part = raw
		case "encrypted-user":
			raw, err := s.decryptWithWrappingKey(ctx, req.TenantID, strings.TrimSpace(item.WrappingKeyID), item.WrappedMaterialB64, item.MaterialIVB64)
			if err != nil {
				return Key{}, nil, fmt.Errorf("component %d unwrap failed: %w", idx+1, err)
			}
			part = raw
		default:
			return Key{}, nil, errors.New("invalid component_mode")
		}
		if len(part) != materialLen {
			return Key{}, nil, fmt.Errorf("component %d length must be %d bytes", idx+1, materialLen)
		}
		if parity != "none" && mode != "clear-generated" && !validateParity(part, parity) {
			return Key{}, nil, fmt.Errorf("component %d parity check failed (%s parity expected)", idx+1, parity)
		}
		components = append(components, append([]byte{}, part...))
	}
	combined := xorComponents(components, materialLen)
	defer crypto.Zeroize(combined)
	if parity != "none" {
		combined = applyParity(combined, parity)
	}
	if req.Labels == nil {
		req.Labels = map[string]string{}
	}
	req.Labels["formed_from_components"] = "true"
	req.Labels["component_mode"] = mode
	req.Labels["component_count"] = fmt.Sprintf("%d", len(req.Components))
	if parity != "none" {
		req.Labels["parity"] = parity
	}
	key, err := s.createKeyFromMaterial(ctx, req.CreateKeyRequest, combined, "", "key.form", "audit.key.form")
	return key, generated, err
}

func isPublicComponentKey(key Key) bool {
	keyType := strings.ToLower(strings.TrimSpace(key.KeyType))
	if strings.Contains(keyType, "public") {
		return true
	}
	role := strings.ToLower(strings.TrimSpace(key.Labels["component_role"]))
	if role == "public" {
		return true
	}
	return false
}

func (s *Service) ExportPublicComponentPlaintext(ctx context.Context, tenantID string, keyID string) (PlaintextExportResult, error) {
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return PlaintextExportResult{}, err
	}
	if isDeletedLike(key.Status) {
		return PlaintextExportResult{}, errors.New("cannot export a deleted key")
	}
	if err := s.enforceKeyAccess(ctx, key, "export"); err != nil {
		return PlaintextExportResult{}, err
	}
	if !isPublicComponentKey(key) {
		return PlaintextExportResult{}, errors.New("plaintext export is allowed only for public key components")
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          tenantID,
		Operation:         "key.export",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return PlaintextExportResult{}, err
	}
	ver, err := s.GetVersion(ctx, tenantID, keyID, 0)
	if err != nil {
		return PlaintextExportResult{}, err
	}
	var plain []byte
	encoding := "base64"
	if len(ver.PublicKey) > 0 {
		plain = append([]byte{}, ver.PublicKey...)
		encoding = "raw"
	} else {
		raw, decErr := s.decryptMaterial(ver)
		if decErr != nil {
			if strings.Contains(strings.ToLower(decErr.Error()), "message authentication failed") {
				return PlaintextExportResult{}, errors.New("cannot decrypt public key material (MEK mismatch or corrupted key envelope)")
			}
			return PlaintextExportResult{}, decErr
		}
		plain = raw
	}
	if len(plain) == 0 {
		return PlaintextExportResult{}, errors.New("public key material is empty")
	}
	if encoding == "raw" {
		encoding = "base64"
	}
	plainB64 := base64.StdEncoding.EncodeToString(plain)
	_ = s.publishAudit(ctx, "audit.key.export_public", tenantID, map[string]any{
		"key_id": key.ID,
	})
	return PlaintextExportResult{
		KeyID:               key.ID,
		KCV:                 strings.ToUpper(hex.EncodeToString(ver.KCV)),
		PublicKeyPlaintext:  plainB64,
		PublicKeyEncoding:   encoding,
		PublicComponentType: "public",
	}, nil
}

func (s *Service) ExportCurrentVersionWrapped(ctx context.Context, tenantID string, keyID string, wrappingKeyID string) (WrappedExportResult, error) {
	wrappingKeyID = strings.TrimSpace(wrappingKeyID)
	if wrappingKeyID == "" {
		return WrappedExportResult{}, errors.New("wrapping_key_id is required")
	}
	if keyID == wrappingKeyID {
		return WrappedExportResult{}, errors.New("wrapping_key_id cannot be the same as exported key")
	}
	key, ver, err := s.ExportCurrentVersion(ctx, tenantID, keyID)
	if err != nil {
		return WrappedExportResult{}, err
	}
	targetRaw, err := s.decryptMaterial(ver)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "message authentication failed") {
			return WrappedExportResult{}, errors.New("cannot decrypt export key material (MEK mismatch or corrupted key envelope)")
		}
		return WrappedExportResult{}, err
	}
	defer crypto.Zeroize(targetRaw)
	wrappingKey, err := s.GetKey(ctx, tenantID, wrappingKeyID)
	if err != nil {
		return WrappedExportResult{}, err
	}
	if isDeletedLike(wrappingKey.Status) {
		return WrappedExportResult{}, errors.New("wrapping key is deleted")
	}
	if normalizeLifecycleStatus(wrappingKey.Status) != "active" {
		return WrappedExportResult{}, errors.New("wrapping key must be active")
	}
	if !strings.Contains(strings.ToLower(strings.TrimSpace(wrappingKey.Purpose)), "wrap") {
		return WrappedExportResult{}, errors.New("wrapping key purpose must allow wrap/unwrap")
	}
	wrappingVer, err := s.GetVersion(ctx, tenantID, wrappingKeyID, 0)
	if err != nil {
		return WrappedExportResult{}, err
	}
	wrappingRaw, err := s.decryptMaterial(wrappingVer)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "message authentication failed") {
			return WrappedExportResult{}, errors.New("cannot decrypt wrapping key material (MEK mismatch or corrupted key envelope)")
		}
		return WrappedExportResult{}, err
	}
	defer crypto.Zeroize(wrappingRaw)

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return WrappedExportResult{}, err
	}
	wrapped, err := encryptAESGCM(wrappingRaw, iv, targetRaw, nil)
	if err != nil {
		return WrappedExportResult{}, err
	}
	_ = s.publishAudit(ctx, "audit.key.export", tenantID, map[string]any{
		"key_id":          key.ID,
		"wrapping_key_id": wrappingKeyID,
	})
	return WrappedExportResult{
		KeyID:          key.ID,
		WrappedKeyB64:  base64.StdEncoding.EncodeToString(wrapped),
		MaterialIVB64:  base64.StdEncoding.EncodeToString(iv),
		KCV:            strings.ToUpper(hex.EncodeToString(ver.KCV)),
		WrappingKeyID:  wrappingKeyID,
		WrappingKeyKCV: strings.ToUpper(hex.EncodeToString(wrappingKey.KCV)),
	}, nil
}

func (s *Service) RotateKey(ctx context.Context, tenantID string, keyID string, reason string, oldVersionAction string) (KeyVersion, error) {
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return KeyVersion{}, err
	}
	if isDeletedLike(key.Status) {
		return KeyVersion{}, errors.New("cannot rotate a deleted key")
	}
	if err := s.enforceKeyAccess(ctx, key, "all"); err != nil {
		return KeyVersion{}, err
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          tenantID,
		Operation:         "key.rotate",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return KeyVersion{}, err
	}
	raw, err := generateMaterialForCreate(key.Algorithm, key.KeyType)
	if err != nil {
		return KeyVersion{}, err
	}
	defer crypto.Zeroize(raw)
	newKCV, _, err := computeKCVStrict(key.Algorithm, raw)
	if err != nil {
		return KeyVersion{}, err
	}
	if crypto.ConstantTimeEqual(newKCV, key.KCV) {
		return KeyVersion{}, errors.New("rotation generated same KCV")
	}
	env, err := crypto.EncryptEnvelope(s.mek, raw)
	if err != nil {
		return KeyVersion{}, err
	}
	newVer := KeyVersion{
		ID:                newID("kv"),
		TenantID:          tenantID,
		KeyID:             keyID,
		EncryptedMaterial: env.Ciphertext,
		MaterialIV:        env.DataIV,
		WrappedDEK:        packWrappedDEK(env.WrappedDEKIV, env.WrappedDEK),
		KCV:               newKCV,
	}
	if reason == "" {
		reason = "manual"
	}
	action := normalizeOldVersionAction(oldVersionAction)
	if action == "" {
		return KeyVersion{}, errors.New("old_version_action must be deactivate, keep-active, or destroy")
	}
	if err := s.store.RotateVersion(ctx, tenantID, keyID, newVer, reason, action); err != nil {
		return KeyVersion{}, err
	}
	_ = s.cache.Delete(ctx, tenantID, keyID)
	_ = s.publishAudit(ctx, "audit.key.rotate", tenantID, map[string]any{"key_id": keyID, "reason": reason, "old_version_action": action})
	return newVer, nil
}

func (s *Service) reconcileLifecycle(ctx context.Context, tenantID string) error {
	now := time.Now().UTC()
	dueDestroyed, err := s.store.PurgeDueDestroyed(ctx, tenantID, now)
	if err != nil {
		return err
	}
	for _, keyID := range dueDestroyed {
		_ = s.cache.Delete(ctx, tenantID, keyID)
		_ = s.publishAudit(ctx, "audit.key.destroyed", tenantID, map[string]any{
			"key_id": keyID,
			"mode":   "scheduled",
		})
	}
	dueActivated, err := s.store.ActivateDueKeys(ctx, tenantID, now)
	if err != nil {
		return err
	}
	for _, keyID := range dueActivated {
		_ = s.cache.Delete(ctx, tenantID, keyID)
		_ = s.publishAudit(ctx, "audit.key.activated", tenantID, map[string]any{
			"key_id": keyID,
			"mode":   "scheduled",
		})
	}
	return nil
}

func (s *Service) ListKeys(ctx context.Context, tenantID string, limit int, offset int) ([]Key, error) {
	if err := s.reconcileLifecycle(ctx, tenantID); err != nil {
		return nil, err
	}
	keys, err := s.store.ListKeys(ctx, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	out := make([]Key, 0, len(keys))
	for _, k := range keys {
		if normalizeLifecycleStatus(k.Status) == "deleted" {
			_ = s.cache.Delete(ctx, tenantID, k.ID)
			continue
		}
		out = append(out, k)
		s.exists.AddString(existsToken(tenantID, k.ID))
		_ = s.cache.Set(ctx, k)
	}
	return out, nil
}

func (s *Service) GetKey(ctx context.Context, tenantID string, keyID string) (Key, error) {
	if err := s.reconcileLifecycle(ctx, tenantID); err != nil {
		return Key{}, err
	}
	token := existsToken(tenantID, keyID)
	if s.exists.TestString(token) {
		if k, ok, err := s.cache.Get(ctx, tenantID, keyID); err == nil && ok {
			if normalizeLifecycleStatus(k.Status) == "deleted" {
				_ = s.cache.Delete(ctx, tenantID, keyID)
				return Key{}, errStoreNotFound
			}
			return k, nil
		}
	}
	k, err := s.store.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return Key{}, err
	}
	if normalizeLifecycleStatus(k.Status) == "deleted" {
		_ = s.cache.Delete(ctx, tenantID, keyID)
		return Key{}, errStoreNotFound
	}
	s.exists.AddString(token)
	_ = s.cache.Set(ctx, k)
	return k, nil
}

func (s *Service) UpdateKey(ctx context.Context, tenantID string, keyID string, req UpdateKeyRequest) error {
	req.IVMode = defaultIV(req.IVMode)
	req.Tags = normalizeTags(req.Tags)
	if err := s.store.UpdateKeyMetadata(ctx, tenantID, keyID, req); err != nil {
		return err
	}
	_ = s.cache.Delete(ctx, tenantID, keyID)
	_ = s.publishAudit(ctx, "audit.key.update", tenantID, map[string]any{"key_id": keyID})
	return nil
}

func (s *Service) ConfigureKeyActivation(ctx context.Context, tenantID string, keyID string, mode string, activationAt *time.Time) (Key, error) {
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return Key{}, err
	}
	if isDeletedLike(key.Status) {
		return Key{}, errors.New("cannot change activation for deleted keys")
	}
	normMode := normalizeActivationMode(mode)
	if normMode == "" {
		return Key{}, errors.New("activation mode must be immediate, pre-active, or scheduled")
	}
	if key.Status != "pre-active" && normMode != "immediate" {
		return Key{}, errors.New("activation policy can be changed only while key is pre-active")
	}
	nextStatus, nextActivation, err := resolveActivation(mode, activationAt)
	if err != nil {
		return Key{}, err
	}
	op := "key.activate"
	if nextStatus == "pre-active" {
		op = "key.activate.schedule"
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          tenantID,
		Operation:         op,
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return Key{}, err
	}
	if err := s.store.SetKeyActivation(ctx, tenantID, keyID, nextStatus, nextActivation); err != nil {
		return Key{}, err
	}
	_ = s.cache.Delete(ctx, tenantID, keyID)
	auditPayload := map[string]any{
		"key_id": keyID,
		"mode":   normalizeActivationMode(mode),
		"status": nextStatus,
	}
	if nextActivation != nil {
		auditPayload["activation_date"] = nextActivation.UTC().Format(time.RFC3339)
	}
	_ = s.publishAudit(ctx, "audit.key.activation_updated", tenantID, auditPayload)
	return s.GetKey(ctx, tenantID, keyID)
}

func (s *Service) SetKeyStatus(ctx context.Context, tenantID string, keyID string, status string) error {
	nextStatus := normalizeLifecycleStatus(status)
	switch nextStatus {
	case "active", "pre-active", "disabled", "deactivated":
	default:
		return fmt.Errorf("invalid key status transition target: %s", status)
	}
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return err
	}
	currentStatus := normalizeLifecycleStatus(key.Status)
	if isDeletedLike(currentStatus) {
		return errors.New("cannot change status for deleted keys")
	}
	op := "key.status.update"
	switch nextStatus {
	case "active":
		op = "key.activate"
	case "pre-active":
		op = "key.activate.schedule"
	case "disabled":
		op = "key.disable"
	case "deactivated":
		op = "key.deactivate"
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          tenantID,
		Operation:         op,
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return err
	}
	if err := s.store.SetKeyStatus(ctx, tenantID, keyID, nextStatus); err != nil {
		return err
	}
	_ = s.cache.Delete(ctx, tenantID, keyID)
	_ = s.publishAudit(ctx, "audit.key."+nextStatus, tenantID, map[string]any{"key_id": keyID, "from": currentStatus, "to": nextStatus})
	return nil
}

func (s *Service) ScheduleKeyDestroy(ctx context.Context, tenantID string, keyID string, days int, justification string) (time.Time, error) {
	if days < 1 {
		return time.Time{}, errors.New("destroy_after_days must be at least 1")
	}
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return time.Time{}, err
	}
	if isDeletedLike(key.Status) {
		if normalizeLifecycleStatus(key.Status) == "destroy-pending" {
			return time.Time{}, errors.New("key is already pending deletion")
		}
		return time.Time{}, errors.New("key is already deleted")
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          tenantID,
		Operation:         "key.destroy",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return time.Time{}, err
	}
	destroyAt := time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)
	if err := s.store.ScheduleDestroy(ctx, tenantID, keyID, destroyAt); err != nil {
		return time.Time{}, err
	}
	_ = s.cache.Delete(ctx, tenantID, keyID)
	_ = s.publishAudit(ctx, "audit.key.destroy_scheduled", tenantID, map[string]any{
		"key_id":             keyID,
		"destroy_after_days": days,
		"destroy_at":         destroyAt.UTC().Format(time.RFC3339),
		"justification":      strings.TrimSpace(justification),
	})
	return destroyAt, nil
}

func (s *Service) DestroyKeyImmediately(ctx context.Context, tenantID string, keyID string, justification string) error {
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return err
	}
	if isDeletedLike(key.Status) {
		if normalizeLifecycleStatus(key.Status) == "destroy-pending" {
			return errors.New("key is already pending deletion")
		}
		return errors.New("key is already deleted")
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          tenantID,
		Operation:         "key.destroy",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return err
	}
	if err := s.store.MarkKeyDestroyed(ctx, tenantID, keyID, time.Now().UTC()); err != nil {
		return err
	}
	_ = s.cache.Delete(ctx, tenantID, keyID)
	_ = s.publishAudit(ctx, "audit.key.destroyed", tenantID, map[string]any{
		"key_id":        keyID,
		"mode":          "immediate",
		"justification": strings.TrimSpace(justification),
	})
	return nil
}

func (s *Service) SetUsageLimit(ctx context.Context, tenantID string, keyID string, limit int64, window string) error {
	if window == "" {
		window = "total"
	}
	if err := s.store.SetUsageLimit(ctx, tenantID, keyID, limit, window); err != nil {
		return err
	}
	_ = s.cache.Delete(ctx, tenantID, keyID)
	_ = s.publishAudit(ctx, "audit.key.usage_limit_updated", tenantID, map[string]any{"key_id": keyID, "ops_limit": limit, "window": window})
	return nil
}

func (s *Service) SetExportAllowed(ctx context.Context, tenantID string, keyID string, allowed bool) error {
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return err
	}
	if isDeletedLike(key.Status) {
		return errors.New("cannot change export policy for deleted keys")
	}
	if err := s.store.SetExportAllowed(ctx, tenantID, keyID, allowed); err != nil {
		return err
	}
	_ = s.cache.Delete(ctx, tenantID, keyID)
	_ = s.publishAudit(ctx, "audit.key.export_policy_updated", tenantID, map[string]any{
		"key_id":         keyID,
		"export_allowed": allowed,
	})
	return nil
}

func (s *Service) ExportCurrentVersion(ctx context.Context, tenantID string, keyID string) (Key, KeyVersion, error) {
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return Key{}, KeyVersion{}, err
	}
	if isDeletedLike(key.Status) {
		return Key{}, KeyVersion{}, errors.New("cannot export a deleted key")
	}
	if err := s.enforceKeyAccess(ctx, key, "export"); err != nil {
		return Key{}, KeyVersion{}, err
	}
	if !key.ExportAllowed {
		return Key{}, KeyVersion{}, errors.New("export is disabled by key policy")
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          tenantID,
		Operation:         "key.export",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return Key{}, KeyVersion{}, err
	}
	ver, err := s.GetVersion(ctx, tenantID, keyID, 0)
	if err != nil {
		return Key{}, KeyVersion{}, err
	}
	return key, ver, nil
}

func (s *Service) ListTagCatalog(ctx context.Context, tenantID string) ([]TagDefinition, error) {
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	if err := s.store.EnsureDefaultTags(ctx, tenantID); err != nil {
		return nil, err
	}
	return s.store.ListTagCatalog(ctx, tenantID)
}

func (s *Service) UpsertTag(ctx context.Context, tag TagDefinition) (TagDefinition, error) {
	tag.TenantID = strings.TrimSpace(tag.TenantID)
	tag.Name = strings.TrimSpace(tag.Name)
	tag.Color = strings.TrimSpace(tag.Color)
	if tag.TenantID == "" || tag.Name == "" {
		return TagDefinition{}, errors.New("tenant_id and name are required")
	}
	if !isHexColor(tag.Color) {
		return TagDefinition{}, errors.New("color must be a hex value like #14B8A6")
	}
	if err := s.store.EnsureDefaultTags(ctx, tag.TenantID); err != nil {
		return TagDefinition{}, err
	}
	existing, err := s.store.ListTagCatalog(ctx, tag.TenantID)
	if err != nil {
		return TagDefinition{}, err
	}
	normalizedColor := strings.ToLower(tag.Color)
	for _, item := range existing {
		if strings.EqualFold(strings.TrimSpace(item.Name), tag.Name) {
			continue
		}
		if strings.ToLower(strings.TrimSpace(item.Color)) == normalizedColor {
			return TagDefinition{}, fmt.Errorf("color already used by tag %q", item.Name)
		}
	}
	tag.IsSystem = false
	return s.store.UpsertTag(ctx, tag)
}

func (s *Service) DeleteTag(ctx context.Context, tenantID string, name string) error {
	tenantID = strings.TrimSpace(tenantID)
	name = strings.TrimSpace(name)
	if tenantID == "" || name == "" {
		return errors.New("tenant_id and name are required")
	}
	return s.store.DeleteTag(ctx, tenantID, name)
}

func (s *Service) ResetUsage(ctx context.Context, tenantID string, keyID string) error {
	if err := s.store.ResetUsage(ctx, tenantID, keyID); err != nil {
		return err
	}
	_ = s.cache.Delete(ctx, tenantID, keyID)
	_ = s.publishAudit(ctx, "audit.key.usage_reset", tenantID, map[string]any{"key_id": keyID})
	return nil
}

func (s *Service) SetApproval(ctx context.Context, tenantID string, keyID string, required bool, policyID string) error {
	if err := s.store.SetApproval(ctx, tenantID, keyID, required, policyID); err != nil {
		return err
	}
	_ = s.cache.Delete(ctx, tenantID, keyID)
	_ = s.publishAudit(ctx, "audit.key.approval_updated", tenantID, map[string]any{"key_id": keyID, "required": required, "policy_id": policyID})
	return nil
}

func (s *Service) GetUsage(ctx context.Context, tenantID string, keyID string) (Usage, error) {
	return s.store.GetUsage(ctx, tenantID, keyID)
}

func normalizeMeterOperation(op string) string {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "", "encrypt":
		return "encrypt"
	case "decrypt":
		return "decrypt"
	case "sign":
		return "sign"
	case "verify":
		return "verify"
	case "wrap":
		return "wrap"
	case "unwrap":
		return "unwrap"
	case "mac":
		return "mac"
	case "derive":
		return "derive"
	case "kem-encapsulate", "kem_encapsulate":
		return "kem-encapsulate"
	case "kem-decapsulate", "kem_decapsulate":
		return "kem-decapsulate"
	default:
		return strings.ToLower(strings.TrimSpace(op))
	}
}

func policyOperationForMeter(op string) string {
	switch op {
	case "encrypt":
		return "key.encrypt"
	case "decrypt":
		return "key.decrypt"
	case "sign":
		return "key.sign"
	case "verify":
		return "key.verify"
	case "wrap":
		return "key.wrap"
	case "unwrap":
		return "key.unwrap"
	case "mac":
		return "key.mac"
	case "derive":
		return "key.derive"
	case "kem-encapsulate":
		return "key.kem_encapsulate"
	case "kem-decapsulate":
		return "key.kem_decapsulate"
	default:
		return "key." + strings.ReplaceAll(op, "-", "_")
	}
}

func (s *Service) MeterUsage(ctx context.Context, tenantID string, keyID string, operation string) (Usage, error) {
	tenantID = strings.TrimSpace(tenantID)
	keyID = strings.TrimSpace(keyID)
	if tenantID == "" || keyID == "" {
		return Usage{}, errors.New("tenant_id and key_id are required")
	}
	op := normalizeMeterOperation(operation)
	if op == "" {
		return Usage{}, errors.New("operation is required")
	}
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return Usage{}, err
	}
	if isDeletedLike(key.Status) {
		return Usage{}, errStoreNotFound
	}
	if err := ensureKeySupportsOperation(key, op); err != nil {
		return Usage{}, err
	}
	if err := s.enforceKeyAccess(ctx, key, op); err != nil {
		return Usage{}, err
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          tenantID,
		Operation:         policyOperationForMeter(op),
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return Usage{}, err
	}
	if _, err := s.store.RunCryptoTx(ctx, tenantID, keyID, op, func(_ Key, _ KeyVersion) (CryptoTxResult, error) {
		return CryptoTxResult{}, nil
	}); err != nil {
		return Usage{}, err
	}
	_ = s.cache.Delete(ctx, tenantID, keyID)
	usage, err := s.store.GetUsage(ctx, tenantID, keyID)
	if err != nil {
		return Usage{}, err
	}
	_ = s.publishAudit(ctx, "audit.key.usage_metered", tenantID, map[string]any{
		"key_id":    keyID,
		"operation": op,
	})
	return usage, nil
}

func (s *Service) GetApproval(ctx context.Context, tenantID string, keyID string) (ApprovalConfig, error) {
	return s.store.GetApproval(ctx, tenantID, keyID)
}

func (s *Service) ListVersions(ctx context.Context, tenantID string, keyID string) ([]KeyVersion, error) {
	return s.store.ListVersions(ctx, tenantID, keyID)
}

func (s *Service) GetVersion(ctx context.Context, tenantID string, keyID string, version int) (KeyVersion, error) {
	if version == 0 {
		k, err := s.GetKey(ctx, tenantID, keyID)
		if err != nil {
			return KeyVersion{}, err
		}
		version = k.CurrentVersion
	}
	return s.store.GetVersion(ctx, tenantID, keyID, version)
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]any) error {
	var outErr error
	if s.events != nil {
		if err := publishAuditEvent(ctx, s.events, subject, tenantID, data); err != nil {
			outErr = err
		}
	}
	if req, ok := s.keycoreSyncRequest(ctx, subject, tenantID, data); ok && s.cluster != nil {
		if err := s.cluster.Publish(ctx, req); err != nil && outErr == nil {
			outErr = err
		}
	}
	return outErr
}

func approvalPayloadHash(operation string, payload map[string]string) string {
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(strings.ToLower(strings.TrimSpace(operation)))
	for _, key := range keys {
		b.WriteString("|")
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(payload[key])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func (s *Service) ensureApprovalAllowed(ctx context.Context, key Key, tenantID string, operation string, payload map[string]string) error {
	if !key.ApprovalRequired {
		return nil
	}
	payloadHash := approvalPayloadHash(operation, payload)
	if s.approval == nil {
		return errors.New("governance approval is required but governance client is not configured")
	}
	approved, requestID, err := s.approval.ensureApproval(ctx, governanceApprovalInput{
		TenantID:       tenantID,
		KeyID:          key.ID,
		Operation:      operation,
		PayloadHash:    payloadHash,
		RequesterID:    payload["requester_id"],
		RequesterEmail: payload["requester_email"],
		RequesterIP:    payload["requester_ip"],
		PolicyID:       key.ApprovalPolicyID,
	})
	if err != nil {
		return err
	}
	if approved {
		return nil
	}
	if strings.TrimSpace(requestID) == "" {
		return errors.New("governance approval request was not created")
	}
	return approvalRequiredError{RequestID: requestID}
}

func (s *Service) Encrypt(ctx context.Context, keyID string, req EncryptRequest) (CryptoResponse, error) {
	key, err := s.GetKey(ctx, req.TenantID, keyID)
	if err != nil {
		return CryptoResponse{}, err
	}
	operation := strings.TrimSpace(req.Operation)
	if operation == "" {
		operation = "encrypt"
	}
	if err := ensureKeySupportsOperation(key, operation); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.enforceKeyAccess(ctx, key, operation); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.enforceFIPSKeyAlgorithm(ctx, req.TenantID, key.Algorithm, "key.encrypt"); err != nil {
		return CryptoResponse{}, err
	}
	effectiveIVMode := defaultIV(key.IVMode)
	if strings.TrimSpace(req.IVMode) != "" {
		effectiveIVMode = defaultIV(req.IVMode)
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          req.TenantID,
		Operation:         "key.encrypt",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            effectiveIVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.ensureApprovalAllowed(ctx, key, req.TenantID, operation, map[string]string{
		"plaintext":    strings.TrimSpace(req.PlaintextB64),
		"iv":           strings.TrimSpace(req.IVB64),
		"iv_mode":      strings.TrimSpace(effectiveIVMode),
		"aad":          strings.TrimSpace(req.AADB64),
		"reference_id": strings.TrimSpace(req.ReferenceID),
	}); err != nil {
		return CryptoResponse{}, err
	}
	plain, err := base64.StdEncoding.DecodeString(req.PlaintextB64)
	if err != nil {
		return CryptoResponse{}, errors.New("plaintext must be base64")
	}
	defer crypto.Zeroize(plain)
	var aad []byte
	if strings.TrimSpace(req.AADB64) != "" {
		aad, err = base64.StdEncoding.DecodeString(req.AADB64)
		if err != nil {
			return CryptoResponse{}, errors.New("aad must be base64")
		}
	}

	result, err := s.store.RunCryptoTx(ctx, req.TenantID, keyID, operation, func(k Key, kv KeyVersion) (CryptoTxResult, error) {
		raw, err := s.decryptMaterial(kv)
		if err != nil {
			return CryptoTxResult{}, err
		}
		defer crypto.Zeroize(raw)
		ciphertext, iv, storeIV, err := encryptWithKeyAlgorithm(k.Algorithm, k.KeyType, raw, effectiveIVMode, req.IVB64, plain, aad)
		if err != nil {
			return CryptoTxResult{}, err
		}
		return CryptoTxResult{Payload: ciphertext, IV: iv, StoreIV: storeIV, ReferenceID: req.ReferenceID}, nil
	})
	if errors.Is(err, errOpsLimit) {
		return CryptoResponse{}, errOpsLimit
	}
	if err != nil {
		return CryptoResponse{}, err
	}
	if s.meter != nil {
		_ = s.meter.IncrementOps()
	}
	_ = s.publishAudit(ctx, "audit.key.encrypt", req.TenantID, map[string]any{"key_id": keyID})
	return CryptoResponse{
		KeyID:     keyID,
		Version:   result.KeyVersion,
		CipherB64: base64.StdEncoding.EncodeToString(result.Payload),
		IVB64:     base64.StdEncoding.EncodeToString(result.IV),
		KCV:       strings.ToUpper(hex.EncodeToString(key.KCV)),
	}, nil
}

func (s *Service) Decrypt(ctx context.Context, keyID string, req DecryptRequest) (CryptoResponse, error) {
	key, err := s.GetKey(ctx, req.TenantID, keyID)
	if err != nil {
		return CryptoResponse{}, err
	}
	operation := strings.TrimSpace(req.Operation)
	if operation == "" {
		operation = "decrypt"
	}
	if err := ensureKeySupportsOperation(key, operation); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.enforceKeyAccess(ctx, key, operation); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.enforceFIPSKeyAlgorithm(ctx, req.TenantID, key.Algorithm, "key.decrypt"); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          req.TenantID,
		Operation:         "key.decrypt",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.ensureApprovalAllowed(ctx, key, req.TenantID, operation, map[string]string{
		"ciphertext":   strings.TrimSpace(req.CiphertextB64),
		"iv":           strings.TrimSpace(req.IVB64),
		"aad":          strings.TrimSpace(req.AADB64),
		"reference_id": strings.TrimSpace(req.ReferenceID),
	}); err != nil {
		return CryptoResponse{}, err
	}
	cipherRaw, err := base64.StdEncoding.DecodeString(req.CiphertextB64)
	if err != nil {
		return CryptoResponse{}, errors.New("ciphertext must be base64")
	}
	iv, err := base64.StdEncoding.DecodeString(req.IVB64)
	if err != nil {
		return CryptoResponse{}, errors.New("iv must be base64")
	}
	var aad []byte
	if strings.TrimSpace(req.AADB64) != "" {
		aad, err = base64.StdEncoding.DecodeString(req.AADB64)
		if err != nil {
			return CryptoResponse{}, errors.New("aad must be base64")
		}
	}
	result, err := s.store.RunCryptoTx(ctx, req.TenantID, keyID, operation, func(_ Key, kv KeyVersion) (CryptoTxResult, error) {
		raw, err := s.decryptMaterial(kv)
		if err != nil {
			return CryptoTxResult{}, err
		}
		defer crypto.Zeroize(raw)
		plain, err := decryptWithKeyAlgorithm(key.Algorithm, key.KeyType, raw, iv, cipherRaw, aad)
		if err != nil {
			return CryptoTxResult{}, err
		}
		return CryptoTxResult{Payload: plain, IV: iv}, nil
	})
	if errors.Is(err, errOpsLimit) {
		return CryptoResponse{}, errOpsLimit
	}
	if err != nil {
		return CryptoResponse{}, err
	}
	if s.meter != nil {
		_ = s.meter.IncrementOps()
	}
	_ = s.publishAudit(ctx, "audit.key.decrypt", req.TenantID, map[string]any{"key_id": keyID})
	return CryptoResponse{
		KeyID:    keyID,
		Version:  result.KeyVersion,
		PlainB64: base64.StdEncoding.EncodeToString(result.Payload),
	}, nil
}

func (s *Service) Sign(ctx context.Context, keyID string, req SignRequest) (CryptoResponse, error) {
	key, err := s.GetKey(ctx, req.TenantID, keyID)
	if err != nil {
		return CryptoResponse{}, err
	}
	operation := strings.TrimSpace(req.Operation)
	if operation == "" {
		operation = "sign"
	}
	if err := ensureKeySupportsOperation(key, operation); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.enforceKeyAccess(ctx, key, operation); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.enforceFIPSKeyAlgorithm(ctx, req.TenantID, key.Algorithm, "key.sign"); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          req.TenantID,
		Operation:         "key.sign",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.ensureApprovalAllowed(ctx, key, req.TenantID, operation, map[string]string{
		"data":      strings.TrimSpace(req.DataB64),
		"algorithm": strings.TrimSpace(req.Algorithm),
	}); err != nil {
		return CryptoResponse{}, err
	}
	data, err := base64.StdEncoding.DecodeString(req.DataB64)
	if err != nil {
		return CryptoResponse{}, errors.New("data must be base64")
	}
	defer crypto.Zeroize(data)
	result, err := s.store.RunCryptoTx(ctx, req.TenantID, keyID, operation, func(k Key, kv KeyVersion) (CryptoTxResult, error) {
		raw, err := s.decryptMaterial(kv)
		if err != nil {
			return CryptoTxResult{}, err
		}
		defer crypto.Zeroize(raw)
		signature, err := signWithKeyAlgorithm(k.Algorithm, k.KeyType, raw, data, req.Algorithm)
		if err != nil {
			return CryptoTxResult{}, err
		}
		return CryptoTxResult{Payload: signature}, nil
	})
	if errors.Is(err, errOpsLimit) {
		return CryptoResponse{}, errOpsLimit
	}
	if err != nil {
		return CryptoResponse{}, err
	}
	if s.meter != nil {
		_ = s.meter.IncrementOps()
	}
	_ = s.publishAudit(ctx, "audit.key.sign", req.TenantID, map[string]any{"key_id": keyID})
	return CryptoResponse{
		KeyID:        keyID,
		Version:      result.KeyVersion,
		SignatureB64: base64.StdEncoding.EncodeToString(result.Payload),
	}, nil
}

func (s *Service) Verify(ctx context.Context, keyID string, req VerifyRequest) (CryptoResponse, error) {
	key, err := s.GetKey(ctx, req.TenantID, keyID)
	if err != nil {
		return CryptoResponse{}, err
	}
	operation := strings.TrimSpace(req.Operation)
	if operation == "" {
		operation = "verify"
	}
	if err := ensureKeySupportsOperation(key, operation); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.enforceKeyAccess(ctx, key, operation); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.enforceFIPSKeyAlgorithm(ctx, req.TenantID, key.Algorithm, "key.verify"); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          req.TenantID,
		Operation:         "key.verify",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return CryptoResponse{}, err
	}
	if err := s.ensureApprovalAllowed(ctx, key, req.TenantID, operation, map[string]string{
		"data":      strings.TrimSpace(req.DataB64),
		"signature": strings.TrimSpace(req.SignatureB64),
		"algorithm": strings.TrimSpace(req.Algorithm),
	}); err != nil {
		return CryptoResponse{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil {
		return CryptoResponse{}, errors.New("signature must be base64")
	}
	data, err := base64.StdEncoding.DecodeString(req.DataB64)
	if err != nil {
		return CryptoResponse{}, err
	}
	defer crypto.Zeroize(data)
	var (
		version  int
		verified bool
	)
	_, err = s.store.RunCryptoTx(ctx, req.TenantID, keyID, operation, func(k Key, kv KeyVersion) (CryptoTxResult, error) {
		raw, err := s.decryptMaterial(kv)
		if err != nil {
			return CryptoTxResult{}, err
		}
		defer crypto.Zeroize(raw)
		ok, err := verifyWithKeyAlgorithm(k.Algorithm, k.KeyType, raw, data, sig, req.Algorithm)
		if err != nil {
			return CryptoTxResult{}, err
		}
		verified = ok
		version = kv.Version
		return CryptoTxResult{}, nil
	})
	if errors.Is(err, errOpsLimit) {
		return CryptoResponse{}, errOpsLimit
	}
	if err != nil {
		return CryptoResponse{}, err
	}
	if s.meter != nil {
		_ = s.meter.IncrementOps()
	}
	_ = s.publishAudit(ctx, "audit.key.verify", req.TenantID, map[string]any{"key_id": keyID})
	return CryptoResponse{
		KeyID:    keyID,
		Version:  version,
		Verified: verified,
	}, nil
}

func normalizeHMACAlgorithm(algorithm string) string {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "", "hmac-sha256", "sha256", "hmac_sha256":
		return "hmac-sha256"
	case "hmac-sha384", "sha384", "hmac_sha384":
		return "hmac-sha384"
	case "hmac-sha512", "sha512", "hmac_sha512":
		return "hmac-sha512"
	default:
		return ""
	}
}

func hmacFactoryForAlgorithm(algorithm string) (func() hash.Hash, error) {
	switch normalizeHMACAlgorithm(algorithm) {
	case "hmac-sha256":
		return sha256.New, nil
	case "hmac-sha384":
		return sha512.New384, nil
	case "hmac-sha512":
		return sha512.New, nil
	default:
		return nil, errors.New("unsupported hmac algorithm")
	}
}

func normalizeDigestAlgorithm(algorithm string) string {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "", "sha-256", "sha256":
		return "sha-256"
	case "sha-384", "sha384":
		return "sha-384"
	case "sha-512", "sha512":
		return "sha-512"
	case "sha3-256", "sha3_256":
		return "sha3-256"
	case "sha3-384", "sha3_384":
		return "sha3-384"
	case "sha3-512", "sha3_512":
		return "sha3-512"
	case "blake2b-256", "blake2b256":
		return "blake2b-256"
	default:
		return ""
	}
}

func newDigestHasher(algorithm string) (hash.Hash, string, error) {
	switch normalizeDigestAlgorithm(algorithm) {
	case "sha-256":
		return sha256.New(), "sha-256", nil
	case "sha-384":
		return sha512.New384(), "sha-384", nil
	case "sha-512":
		return sha512.New(), "sha-512", nil
	case "sha3-256":
		return sha3.New256(), "sha3-256", nil
	case "sha3-384":
		return sha3.New384(), "sha3-384", nil
	case "sha3-512":
		return sha3.New512(), "sha3-512", nil
	case "blake2b-256":
		h, err := blake2b.New256(nil)
		if err != nil {
			return nil, "", err
		}
		return h, "blake2b-256", nil
	default:
		return nil, "", errors.New("unsupported hash algorithm")
	}
}

func normalizeHKDFAlgorithm(algorithm string) string {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "", "hkdf-sha256", "hkdf_sha256":
		return "hkdf-sha256"
	case "hkdf-sha384", "hkdf_sha384":
		return "hkdf-sha384"
	case "hkdf-sha512", "hkdf_sha512":
		return "hkdf-sha512"
	default:
		return ""
	}
}

func hkdfFactoryForAlgorithm(algorithm string) (func() hash.Hash, string, error) {
	switch normalizeHKDFAlgorithm(algorithm) {
	case "hkdf-sha256":
		return sha256.New, "hkdf-sha256", nil
	case "hkdf-sha384":
		return sha512.New384, "hkdf-sha384", nil
	case "hkdf-sha512":
		return sha512.New, "hkdf-sha512", nil
	default:
		return nil, "", errors.New("unsupported kdf algorithm")
	}
}

func normalizeRandomSource(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "kms-csprng", "csprng", "crypto/rand":
		return "kms-csprng"
	case "hsm-trng", "hsm":
		return "hsm-trng"
	case "qkd-seeded-csprng", "qkd":
		return "qkd-seeded-csprng"
	default:
		return ""
	}
}

func normalizeKEMAlgorithm(algorithm string) string {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "ml-kem-768", "mlkem-768", "ml_kem_768":
		return "ml-kem-768"
	case "ml-kem-1024", "mlkem-1024", "ml_kem_1024":
		return "ml-kem-1024"
	default:
		return ""
	}
}

func isPublicKeyType(keyType string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(keyType)), "public")
}

func isPrivateCapableKeyType(keyType string) bool {
	kt := strings.ToLower(strings.TrimSpace(keyType))
	if kt == "" {
		return true
	}
	if strings.Contains(kt, "private") || strings.Contains(kt, "asymmetric") {
		return true
	}
	return !isPublicKeyType(kt)
}

func isHMACKeyAlgorithm(algorithm string) bool {
	return strings.Contains(strings.ToUpper(strings.TrimSpace(algorithm)), "HMAC")
}

func isRSAKeyAlgorithm(algorithm string) bool {
	return strings.Contains(strings.ToUpper(strings.TrimSpace(algorithm)), "RSA")
}

func isECDSAKeyAlgorithm(algorithm string) bool {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	return strings.Contains(a, "ECDSA") || strings.Contains(a, "BRAINPOOL")
}

func isEd25519KeyAlgorithm(algorithm string) bool {
	return strings.Contains(strings.ToUpper(strings.TrimSpace(algorithm)), "ED25519")
}

func isMLKEMKeyAlgorithm(algorithm string) bool {
	return normalizeKEMAlgorithm(algorithm) != ""
}

func isSupportedSymmetricCipherAlgorithm(algorithm string) bool {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	if !strings.Contains(a, "AES") && !strings.Contains(a, "3DES") && !strings.Contains(a, "TDES") {
		return false
	}
	if strings.Contains(a, "AES") {
		if strings.Contains(a, "ECB") || strings.Contains(a, "CCM") || strings.Contains(a, "CFB") || strings.Contains(a, "OFB") || strings.Contains(a, "XTS") {
			return false
		}
		return true
	}
	if strings.Contains(a, "3DES") || strings.Contains(a, "TDES") {
		return strings.Contains(a, "CBC")
	}
	return false
}

func ensureKeySupportsOperation(key Key, op string) error {
	operation := strings.ToLower(strings.TrimSpace(op))
	algorithm := strings.ToUpper(strings.TrimSpace(key.Algorithm))
	switch operation {
	case "encrypt", "decrypt", "wrap", "unwrap":
		if isRSAKeyAlgorithm(algorithm) {
			if (operation == "decrypt" || operation == "unwrap") && !isPrivateCapableKeyType(key.KeyType) {
				return errors.New("decrypt requires a private or full RSA key component")
			}
			return nil
		}
		if !isSupportedSymmetricCipherAlgorithm(algorithm) {
			return fmt.Errorf("%s is not supported for algorithm %s", operation, key.Algorithm)
		}
		return nil
	case "sign":
		if isHMACKeyAlgorithm(algorithm) {
			return nil
		}
		if isRSAKeyAlgorithm(algorithm) || isECDSAKeyAlgorithm(algorithm) || isEd25519KeyAlgorithm(algorithm) {
			if isPublicKeyType(key.KeyType) {
				return errors.New("sign requires a private or full key component")
			}
			return nil
		}
		return fmt.Errorf("sign is not supported for algorithm %s", key.Algorithm)
	case "verify":
		if isHMACKeyAlgorithm(algorithm) || isRSAKeyAlgorithm(algorithm) || isECDSAKeyAlgorithm(algorithm) || isEd25519KeyAlgorithm(algorithm) {
			return nil
		}
		return fmt.Errorf("verify is not supported for algorithm %s", key.Algorithm)
	case "mac":
		if !isHMACKeyAlgorithm(algorithm) {
			return fmt.Errorf("mac is not supported for algorithm %s", key.Algorithm)
		}
		return nil
	case "derive":
		if isHMACKeyAlgorithm(algorithm) || isSupportedSymmetricCipherAlgorithm(algorithm) {
			return nil
		}
		return fmt.Errorf("derive is not supported for algorithm %s", key.Algorithm)
	case "kem-encapsulate":
		if !isMLKEMKeyAlgorithm(algorithm) {
			return fmt.Errorf("kem encapsulate is not supported for algorithm %s", key.Algorithm)
		}
		return nil
	case "kem-decapsulate":
		if !isMLKEMKeyAlgorithm(algorithm) {
			return fmt.Errorf("kem decapsulate is not supported for algorithm %s", key.Algorithm)
		}
		if !isPrivateCapableKeyType(key.KeyType) {
			return errors.New("kem decapsulate requires a private or full key component")
		}
		return nil
	default:
		return nil
	}
}

func (s *Service) Hash(ctx context.Context, req HashRequest) (HashResponse, error) {
	if err := s.enforceFIPSHashAlgorithm(ctx, req.TenantID, req.Algorithm); err != nil {
		return HashResponse{}, err
	}
	hasher, canonicalAlg, err := newDigestHasher(req.Algorithm)
	if err != nil {
		return HashResponse{}, err
	}
	input := []byte{}
	if strings.TrimSpace(req.InputB64) != "" {
		input, err = base64.StdEncoding.DecodeString(req.InputB64)
		if err != nil {
			return HashResponse{}, errors.New("input must be base64")
		}
	}
	_, _ = hasher.Write(input)
	digest := hasher.Sum(nil)
	_ = s.publishAudit(ctx, "audit.crypto.hash", req.TenantID, map[string]any{
		"algorithm":    canonicalAlg,
		"reference_id": req.ReferenceID,
		"size_bytes":   len(input),
	})
	return HashResponse{
		Algorithm: canonicalAlg,
		DigestB64: base64.StdEncoding.EncodeToString(digest),
	}, nil
}

func (s *Service) Random(ctx context.Context, req RandomRequest) (RandomResponse, error) {
	if err := s.enforceFIPSRandomSource(ctx, req.TenantID, req.Source); err != nil {
		return RandomResponse{}, err
	}
	source := normalizeRandomSource(req.Source)
	if source == "" {
		return RandomResponse{}, errors.New("source must be kms-csprng, hsm-trng, or qkd-seeded-csprng")
	}
	if req.Length <= 0 {
		req.Length = 32
	}
	if req.Length > 4096 {
		return RandomResponse{}, errors.New("length must be <= 4096 bytes")
	}
	raw := make([]byte, req.Length)
	if _, err := rand.Read(raw); err != nil {
		return RandomResponse{}, err
	}
	out := base64.StdEncoding.EncodeToString(raw)
	crypto.Zeroize(raw)
	_ = s.publishAudit(ctx, "audit.crypto.random", req.TenantID, map[string]any{
		"source":       source,
		"length":       req.Length,
		"reference_id": req.ReferenceID,
	})
	return RandomResponse{
		BytesB64: out,
		Length:   req.Length,
		Source:   source,
	}, nil
}

func (s *Service) Derive(ctx context.Context, keyID string, req DeriveRequest) (DeriveResponse, error) {
	key, err := s.GetKey(ctx, req.TenantID, keyID)
	if err != nil {
		return DeriveResponse{}, err
	}
	operation := strings.TrimSpace(req.Operation)
	if operation == "" {
		operation = "derive"
	}
	if err := ensureKeySupportsOperation(key, operation); err != nil {
		return DeriveResponse{}, err
	}
	if err := s.enforceKeyAccess(ctx, key, operation); err != nil {
		return DeriveResponse{}, err
	}
	if err := s.enforceFIPSKeyAlgorithm(ctx, req.TenantID, key.Algorithm, "key.derive"); err != nil {
		return DeriveResponse{}, err
	}
	hashFactory, canonicalAlg, err := hkdfFactoryForAlgorithm(req.Algorithm)
	if err != nil {
		return DeriveResponse{}, err
	}
	if req.LengthBits <= 0 {
		req.LengthBits = 256
	}
	if req.LengthBits > 4096 || req.LengthBits%8 != 0 {
		return DeriveResponse{}, errors.New("length_bits must be a multiple of 8 and <= 4096")
	}
	var info []byte
	if strings.TrimSpace(req.InfoB64) != "" {
		info, err = base64.StdEncoding.DecodeString(req.InfoB64)
		if err != nil {
			return DeriveResponse{}, errors.New("info must be base64")
		}
	}
	var salt []byte
	if strings.TrimSpace(req.SaltB64) != "" {
		salt, err = base64.StdEncoding.DecodeString(req.SaltB64)
		if err != nil {
			return DeriveResponse{}, errors.New("salt must be base64")
		}
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          req.TenantID,
		Operation:         "key.derive",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return DeriveResponse{}, err
	}
	if err := s.ensureApprovalAllowed(ctx, key, req.TenantID, operation, map[string]string{
		"algorithm":    strings.TrimSpace(canonicalAlg),
		"length_bits":  fmt.Sprintf("%d", req.LengthBits),
		"info":         strings.TrimSpace(req.InfoB64),
		"salt":         strings.TrimSpace(req.SaltB64),
		"reference_id": strings.TrimSpace(req.ReferenceID),
	}); err != nil {
		return DeriveResponse{}, err
	}
	result, err := s.store.RunCryptoTx(ctx, req.TenantID, keyID, operation, func(_ Key, kv KeyVersion) (CryptoTxResult, error) {
		raw, err := s.decryptMaterial(kv)
		if err != nil {
			return CryptoTxResult{}, err
		}
		defer crypto.Zeroize(raw)
		reader := hkdf.New(hashFactory, raw, salt, info)
		out := make([]byte, req.LengthBits/8)
		if _, err := io.ReadFull(reader, out); err != nil {
			return CryptoTxResult{}, err
		}
		return CryptoTxResult{Payload: out, ReferenceID: req.ReferenceID}, nil
	})
	if errors.Is(err, errOpsLimit) {
		return DeriveResponse{}, errOpsLimit
	}
	if err != nil {
		return DeriveResponse{}, err
	}
	derivedB64 := base64.StdEncoding.EncodeToString(result.Payload)
	crypto.Zeroize(result.Payload)
	_ = s.publishAudit(ctx, "audit.key.derive", req.TenantID, map[string]any{
		"key_id":       keyID,
		"algorithm":    canonicalAlg,
		"length_bits":  req.LengthBits,
		"reference_id": req.ReferenceID,
	})
	return DeriveResponse{
		KeyID:      keyID,
		Version:    result.KeyVersion,
		Algorithm:  canonicalAlg,
		LengthBits: req.LengthBits,
		DerivedB64: derivedB64,
	}, nil
}

func (s *Service) KEMEncapsulate(ctx context.Context, keyID string, req KEMEncapsulateRequest) (KEMResponse, error) {
	key, err := s.GetKey(ctx, req.TenantID, keyID)
	if err != nil {
		return KEMResponse{}, err
	}
	operation := strings.TrimSpace(req.Operation)
	if operation == "" {
		operation = "kem-encapsulate"
	}
	if err := ensureKeySupportsOperation(key, operation); err != nil {
		return KEMResponse{}, err
	}
	if err := s.enforceKeyAccess(ctx, key, operation); err != nil {
		return KEMResponse{}, err
	}
	if err := s.enforceFIPSKeyAlgorithm(ctx, req.TenantID, key.Algorithm, "key.kem_encapsulate"); err != nil {
		return KEMResponse{}, err
	}
	keyAlg := normalizeKEMAlgorithm(key.Algorithm)
	reqAlg := normalizeKEMAlgorithm(req.Algorithm)
	if keyAlg == "" {
		return KEMResponse{}, errors.New("key algorithm must be ml-kem-768 or ml-kem-1024")
	}
	if reqAlg != "" && reqAlg != keyAlg {
		return KEMResponse{}, errors.New("requested KEM algorithm does not match key algorithm")
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          req.TenantID,
		Operation:         "key.kem_encapsulate",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return KEMResponse{}, err
	}
	if err := s.ensureApprovalAllowed(ctx, key, req.TenantID, "kem-encapsulate", map[string]string{
		"algorithm":    strings.TrimSpace(keyAlg),
		"aad":          strings.TrimSpace(req.AADB64),
		"reference_id": strings.TrimSpace(req.ReferenceID),
	}); err != nil {
		return KEMResponse{}, err
	}
	result, err := s.store.RunCryptoTx(ctx, req.TenantID, keyID, operation, func(k Key, kv KeyVersion) (CryptoTxResult, error) {
		raw, err := s.decryptMaterial(kv)
		if err != nil {
			return CryptoTxResult{}, err
		}
		defer crypto.Zeroize(raw)
		shared, encapsulated, err := mlkemEncapsulate(k.Algorithm, k.KeyType, raw)
		if err != nil {
			return CryptoTxResult{}, err
		}
		return CryptoTxResult{Payload: shared, IV: encapsulated, ReferenceID: req.ReferenceID}, nil
	})
	if errors.Is(err, errOpsLimit) {
		return KEMResponse{}, errOpsLimit
	}
	if err != nil {
		return KEMResponse{}, err
	}
	sharedB64 := base64.StdEncoding.EncodeToString(result.Payload)
	encapsulatedB64 := base64.StdEncoding.EncodeToString(result.IV)
	crypto.Zeroize(result.Payload)
	crypto.Zeroize(result.IV)
	_ = s.publishAudit(ctx, "audit.key.kem_encapsulate", req.TenantID, map[string]any{
		"key_id":       keyID,
		"algorithm":    keyAlg,
		"reference_id": req.ReferenceID,
	})
	return KEMResponse{
		KeyID:           keyID,
		Version:         result.KeyVersion,
		Algorithm:       keyAlg,
		SharedSecretB64: sharedB64,
		EncapsulatedB64: encapsulatedB64,
	}, nil
}

func (s *Service) KEMDecapsulate(ctx context.Context, keyID string, req KEMDecapsulateRequest) (KEMResponse, error) {
	key, err := s.GetKey(ctx, req.TenantID, keyID)
	if err != nil {
		return KEMResponse{}, err
	}
	operation := strings.TrimSpace(req.Operation)
	if operation == "" {
		operation = "kem-decapsulate"
	}
	if err := ensureKeySupportsOperation(key, operation); err != nil {
		return KEMResponse{}, err
	}
	if err := s.enforceKeyAccess(ctx, key, operation); err != nil {
		return KEMResponse{}, err
	}
	if err := s.enforceFIPSKeyAlgorithm(ctx, req.TenantID, key.Algorithm, "key.kem_decapsulate"); err != nil {
		return KEMResponse{}, err
	}
	keyAlg := normalizeKEMAlgorithm(key.Algorithm)
	reqAlg := normalizeKEMAlgorithm(req.Algorithm)
	if keyAlg == "" {
		return KEMResponse{}, errors.New("key algorithm must be ml-kem-768 or ml-kem-1024")
	}
	if reqAlg != "" && reqAlg != keyAlg {
		return KEMResponse{}, errors.New("requested KEM algorithm does not match key algorithm")
	}
	encapsulated, err := base64.StdEncoding.DecodeString(req.EncapsulatedB64)
	if err != nil {
		return KEMResponse{}, errors.New("encapsulated_key must be base64")
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          req.TenantID,
		Operation:         "key.kem_decapsulate",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return KEMResponse{}, err
	}
	if err := s.ensureApprovalAllowed(ctx, key, req.TenantID, "kem-decapsulate", map[string]string{
		"algorithm":    strings.TrimSpace(keyAlg),
		"encapsulated": strings.TrimSpace(req.EncapsulatedB64),
		"reference_id": strings.TrimSpace(req.ReferenceID),
	}); err != nil {
		return KEMResponse{}, err
	}
	result, err := s.store.RunCryptoTx(ctx, req.TenantID, keyID, operation, func(k Key, kv KeyVersion) (CryptoTxResult, error) {
		raw, err := s.decryptMaterial(kv)
		if err != nil {
			return CryptoTxResult{}, err
		}
		defer crypto.Zeroize(raw)
		shared, err := mlkemDecapsulate(k.Algorithm, k.KeyType, raw, encapsulated)
		if err != nil {
			return CryptoTxResult{}, err
		}
		return CryptoTxResult{Payload: shared, ReferenceID: req.ReferenceID}, nil
	})
	if errors.Is(err, errOpsLimit) {
		return KEMResponse{}, errOpsLimit
	}
	if err != nil {
		return KEMResponse{}, err
	}
	sharedB64 := base64.StdEncoding.EncodeToString(result.Payload)
	crypto.Zeroize(result.Payload)
	_ = s.publishAudit(ctx, "audit.key.kem_decapsulate", req.TenantID, map[string]any{
		"key_id":       keyID,
		"algorithm":    keyAlg,
		"reference_id": req.ReferenceID,
	})
	return KEMResponse{
		KeyID:           keyID,
		Version:         result.KeyVersion,
		Algorithm:       keyAlg,
		SharedSecretB64: sharedB64,
	}, nil
}

func mlkemEncapsulate(algorithm string, keyType string, raw []byte) ([]byte, []byte, error) {
	alg := normalizeKEMAlgorithm(algorithm)
	if alg == "" {
		return nil, nil, errors.New("unsupported KEM algorithm")
	}
	switch alg {
	case "ml-kem-768":
		if isPublicKeyType(keyType) {
			ek, err := mlkem.NewEncapsulationKey768(raw)
			if err != nil {
				return nil, nil, errors.New("invalid ML-KEM-768 public key material")
			}
			shared, ciphertext := ek.Encapsulate()
			return shared, ciphertext, nil
		}
		if len(raw) != mlkem.SeedSize {
			return nil, nil, fmt.Errorf("ml-kem-768 private seed must be %d bytes", mlkem.SeedSize)
		}
		dk, err := mlkem.NewDecapsulationKey768(raw)
		if err != nil {
			return nil, nil, errors.New("invalid ML-KEM-768 private key seed")
		}
		shared, ciphertext := dk.EncapsulationKey().Encapsulate()
		return shared, ciphertext, nil
	case "ml-kem-1024":
		if isPublicKeyType(keyType) {
			ek, err := mlkem.NewEncapsulationKey1024(raw)
			if err != nil {
				return nil, nil, errors.New("invalid ML-KEM-1024 public key material")
			}
			shared, ciphertext := ek.Encapsulate()
			return shared, ciphertext, nil
		}
		if len(raw) != mlkem.SeedSize {
			return nil, nil, fmt.Errorf("ml-kem-1024 private seed must be %d bytes", mlkem.SeedSize)
		}
		dk, err := mlkem.NewDecapsulationKey1024(raw)
		if err != nil {
			return nil, nil, errors.New("invalid ML-KEM-1024 private key seed")
		}
		shared, ciphertext := dk.EncapsulationKey().Encapsulate()
		return shared, ciphertext, nil
	default:
		return nil, nil, errors.New("unsupported KEM algorithm")
	}
}

func mlkemDecapsulate(algorithm string, keyType string, raw []byte, ciphertext []byte) ([]byte, error) {
	if !isPrivateCapableKeyType(keyType) {
		return nil, errors.New("kem decapsulate requires a private or full key component")
	}
	alg := normalizeKEMAlgorithm(algorithm)
	if alg == "" {
		return nil, errors.New("unsupported KEM algorithm")
	}
	switch alg {
	case "ml-kem-768":
		if len(raw) != mlkem.SeedSize {
			return nil, fmt.Errorf("ml-kem-768 private seed must be %d bytes", mlkem.SeedSize)
		}
		if len(ciphertext) != mlkem.CiphertextSize768 {
			return nil, fmt.Errorf("ml-kem-768 ciphertext must be %d bytes", mlkem.CiphertextSize768)
		}
		dk, err := mlkem.NewDecapsulationKey768(raw)
		if err != nil {
			return nil, errors.New("invalid ML-KEM-768 private key seed")
		}
		return dk.Decapsulate(ciphertext)
	case "ml-kem-1024":
		if len(raw) != mlkem.SeedSize {
			return nil, fmt.Errorf("ml-kem-1024 private seed must be %d bytes", mlkem.SeedSize)
		}
		if len(ciphertext) != mlkem.CiphertextSize1024 {
			return nil, fmt.Errorf("ml-kem-1024 ciphertext must be %d bytes", mlkem.CiphertextSize1024)
		}
		dk, err := mlkem.NewDecapsulationKey1024(raw)
		if err != nil {
			return nil, errors.New("invalid ML-KEM-1024 private key seed")
		}
		return dk.Decapsulate(ciphertext)
	default:
		return nil, errors.New("unsupported KEM algorithm")
	}
}

func (s *Service) decryptMaterial(ver KeyVersion) ([]byte, error) {
	wiv, wrapped, err := unpackWrappedDEK(ver.WrappedDEK)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptEnvelope(s.mek, &crypto.EnvelopeCiphertext{
		WrappedDEK:   wrapped,
		WrappedDEKIV: wiv,
		Ciphertext:   ver.EncryptedMaterial,
		DataIV:       ver.MaterialIV,
	})
}

func selectIV(ivMode string, keyMaterial []byte, externalIVB64 string, payload []byte) ([]byte, bool, error) {
	return selectIVWithSize(ivMode, keyMaterial, externalIVB64, payload, 12)
}

func selectIVWithSize(ivMode string, keyMaterial []byte, externalIVB64 string, payload []byte, size int) ([]byte, bool, error) {
	if size <= 0 {
		return nil, false, errors.New("invalid iv size")
	}
	switch defaultIV(ivMode) {
	case "internal":
		iv := make([]byte, size)
		if _, err := rand.Read(iv); err != nil {
			return nil, false, err
		}
		return iv, true, nil
	case "external":
		iv, err := base64.StdEncoding.DecodeString(externalIVB64)
		if err != nil {
			return nil, false, errors.New("external iv must be base64")
		}
		if len(iv) != size {
			return nil, false, fmt.Errorf("external iv must be %d bytes", size)
		}
		return iv, false, nil
	case "deterministic":
		iv, err := crypto.GenerateIV(crypto.IVDeterministic, keyMaterial, nil, payload)
		if err != nil {
			return nil, false, err
		}
		if len(iv) < size {
			return nil, false, errors.New("deterministic iv length is too short")
		}
		return iv[:size], false, nil
	default:
		return nil, false, errors.New("invalid iv_mode")
	}
}

func symmetricCipherMode(algorithm string) string {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(a, "GCM"):
		return "gcm"
	case strings.Contains(a, "CBC"):
		return "cbc"
	case strings.Contains(a, "CTR"):
		return "ctr"
	case strings.Contains(a, "ECB"), strings.Contains(a, "CCM"), strings.Contains(a, "CFB"), strings.Contains(a, "OFB"), strings.Contains(a, "XTS"):
		return ""
	case strings.Contains(a, "AES"):
		return "gcm"
	default:
		return ""
	}
}

func normalizeAESKeyForAlgorithm(key []byte, algorithm string) ([]byte, error) {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	want := 32
	switch {
	case strings.Contains(a, "AES-128"):
		want = 16
	case strings.Contains(a, "AES-192"):
		want = 24
	case strings.Contains(a, "AES-256"):
		want = 32
	}
	if len(key) != want {
		return nil, fmt.Errorf("invalid AES key length: got=%d want=%d", len(key), want)
	}
	return append([]byte{}, key...), nil
}

func parseRSAPublicMaterial(raw []byte) (*rsa.PublicKey, error) {
	if pub, err := x509.ParsePKIXPublicKey(raw); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
	}
	if pub, err := x509.ParsePKCS1PublicKey(raw); err == nil {
		return pub, nil
	}
	if cert, err := x509.ParseCertificate(raw); err == nil {
		if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
	}
	return nil, errors.New("invalid RSA public key material")
}

func parseRSAPrivateMaterial(raw []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(raw); err == nil {
		if rsaPriv, ok := key.(*rsa.PrivateKey); ok {
			return rsaPriv, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(raw); err == nil {
		return key, nil
	}
	return nil, errors.New("invalid RSA private key material")
}

func parseECDSAPrivateMaterial(raw []byte) (*ecdsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(raw); err == nil {
		if ecdsaPriv, ok := key.(*ecdsa.PrivateKey); ok {
			return ecdsaPriv, nil
		}
	}
	if key, err := x509.ParseECPrivateKey(raw); err == nil {
		return key, nil
	}
	return nil, errors.New("invalid ECDSA private key material")
}

func parseECDSAPublicMaterial(raw []byte) (*ecdsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, errors.New("invalid ECDSA public key material")
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid ECDSA public key material")
	}
	return pub, nil
}

func parseEd25519PrivateMaterial(raw []byte) (ed25519.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, errors.New("invalid Ed25519 private key material")
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("invalid Ed25519 private key material")
	}
	return priv, nil
}

func parseEd25519PublicMaterial(raw []byte) (ed25519.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, errors.New("invalid Ed25519 public key material")
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("invalid Ed25519 public key material")
	}
	return pub, nil
}

func defaultSigningHashForECDSACurve(curve elliptic.Curve) stdcrypto.Hash {
	if curve == nil || curve.Params() == nil {
		return stdcrypto.SHA256
	}
	switch {
	case curve.Params().BitSize >= 521:
		return stdcrypto.SHA512
	case curve.Params().BitSize >= 384:
		return stdcrypto.SHA384
	default:
		return stdcrypto.SHA256
	}
}

func resolveSigningHash(algorithmHint string, fallback stdcrypto.Hash) stdcrypto.Hash {
	v := strings.ToUpper(strings.TrimSpace(algorithmHint))
	switch {
	case strings.Contains(v, "SHA-512") || strings.Contains(v, "SHA512"):
		return stdcrypto.SHA512
	case strings.Contains(v, "SHA-384") || strings.Contains(v, "SHA384"):
		return stdcrypto.SHA384
	case strings.Contains(v, "SHA-256") || strings.Contains(v, "SHA256"):
		return stdcrypto.SHA256
	default:
		if fallback == 0 {
			return stdcrypto.SHA256
		}
		return fallback
	}
}

func digestForSigning(data []byte, hashAlg stdcrypto.Hash) ([]byte, error) {
	switch hashAlg {
	case stdcrypto.SHA256:
		sum := sha256.Sum256(data)
		return sum[:], nil
	case stdcrypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:], nil
	case stdcrypto.SHA512:
		sum := sha512.Sum512(data)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm for signing: %v", hashAlg)
	}
}

func signWithKeyAlgorithm(keyAlgorithm string, keyType string, keyMaterial []byte, data []byte, algorithmHint string) ([]byte, error) {
	alg := strings.ToUpper(strings.TrimSpace(keyAlgorithm))
	switch {
	case isHMACKeyAlgorithm(alg):
		hmacAlg := normalizeHMACAlgorithm(algorithmHint)
		if hmacAlg == "" {
			hmacAlg = normalizeHMACAlgorithm(keyAlgorithm)
		}
		if hmacAlg == "" {
			return nil, errors.New("algorithm must be hmac-sha256, hmac-sha384, or hmac-sha512")
		}
		macFactory, err := hmacFactoryForAlgorithm(hmacAlg)
		if err != nil {
			return nil, err
		}
		mac := hmac.New(macFactory, keyMaterial)
		_, _ = mac.Write(data)
		return mac.Sum(nil), nil
	case isRSAKeyAlgorithm(alg):
		if isPublicKeyType(keyType) {
			return nil, errors.New("rsa sign requires private key material")
		}
		priv, err := parseRSAPrivateMaterial(keyMaterial)
		if err != nil {
			return nil, err
		}
		hashAlg := resolveSigningHash(algorithmHint, stdcrypto.SHA256)
		digest, err := digestForSigning(data, hashAlg)
		if err != nil {
			return nil, err
		}
		return rsa.SignPSS(rand.Reader, priv, hashAlg, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case isECDSAKeyAlgorithm(alg):
		if isPublicKeyType(keyType) {
			return nil, errors.New("ecdsa sign requires private key material")
		}
		priv, err := parseECDSAPrivateMaterial(keyMaterial)
		if err != nil {
			return nil, err
		}
		hashAlg := resolveSigningHash(algorithmHint, defaultSigningHashForECDSACurve(priv.Curve))
		digest, err := digestForSigning(data, hashAlg)
		if err != nil {
			return nil, err
		}
		return ecdsa.SignASN1(rand.Reader, priv, digest)
	case isEd25519KeyAlgorithm(alg):
		if isPublicKeyType(keyType) {
			return nil, errors.New("ed25519 sign requires private key material")
		}
		priv, err := parseEd25519PrivateMaterial(keyMaterial)
		if err != nil {
			return nil, err
		}
		return ed25519.Sign(priv, data), nil
	default:
		return nil, fmt.Errorf("sign is not supported for algorithm %s", keyAlgorithm)
	}
}

func verifyWithKeyAlgorithm(keyAlgorithm string, keyType string, keyMaterial []byte, data []byte, signature []byte, algorithmHint string) (bool, error) {
	alg := strings.ToUpper(strings.TrimSpace(keyAlgorithm))
	switch {
	case isHMACKeyAlgorithm(alg):
		hmacAlg := normalizeHMACAlgorithm(algorithmHint)
		if hmacAlg == "" {
			hmacAlg = normalizeHMACAlgorithm(keyAlgorithm)
		}
		if hmacAlg == "" {
			return false, errors.New("algorithm must be hmac-sha256, hmac-sha384, or hmac-sha512")
		}
		macFactory, err := hmacFactoryForAlgorithm(hmacAlg)
		if err != nil {
			return false, err
		}
		mac := hmac.New(macFactory, keyMaterial)
		_, _ = mac.Write(data)
		expected := mac.Sum(nil)
		return crypto.ConstantTimeEqual(signature, expected), nil
	case isRSAKeyAlgorithm(alg):
		var pub *rsa.PublicKey
		if isPublicKeyType(keyType) {
			parsed, err := parseRSAPublicMaterial(keyMaterial)
			if err != nil {
				return false, err
			}
			pub = parsed
		} else {
			priv, err := parseRSAPrivateMaterial(keyMaterial)
			if err != nil {
				return false, err
			}
			pub = &priv.PublicKey
		}
		hashAlg := resolveSigningHash(algorithmHint, stdcrypto.SHA256)
		digest, err := digestForSigning(data, hashAlg)
		if err != nil {
			return false, err
		}
		if err := rsa.VerifyPSS(pub, hashAlg, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			return false, nil
		}
		return true, nil
	case isECDSAKeyAlgorithm(alg):
		var pub *ecdsa.PublicKey
		if isPublicKeyType(keyType) {
			parsed, err := parseECDSAPublicMaterial(keyMaterial)
			if err != nil {
				return false, err
			}
			pub = parsed
		} else {
			priv, err := parseECDSAPrivateMaterial(keyMaterial)
			if err != nil {
				return false, err
			}
			pub = &priv.PublicKey
		}
		hashAlg := resolveSigningHash(algorithmHint, defaultSigningHashForECDSACurve(pub.Curve))
		digest, err := digestForSigning(data, hashAlg)
		if err != nil {
			return false, err
		}
		return ecdsa.VerifyASN1(pub, digest, signature), nil
	case isEd25519KeyAlgorithm(alg):
		var pub ed25519.PublicKey
		if isPublicKeyType(keyType) {
			parsed, err := parseEd25519PublicMaterial(keyMaterial)
			if err != nil {
				return false, err
			}
			pub = parsed
		} else {
			priv, err := parseEd25519PrivateMaterial(keyMaterial)
			if err != nil {
				return false, err
			}
			pub = priv.Public().(ed25519.PublicKey)
		}
		return ed25519.Verify(pub, data, signature), nil
	default:
		return false, fmt.Errorf("verify is not supported for algorithm %s", keyAlgorithm)
	}
}

func encryptWithKeyAlgorithm(algorithm string, keyType string, keyMaterial []byte, ivMode string, externalIVB64 string, plain []byte, aad []byte) ([]byte, []byte, bool, error) {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(a, "RSA"):
		if len(aad) > 0 {
			return nil, nil, false, errors.New("aad is not supported for RSA-OAEP")
		}
		var pub *rsa.PublicKey
		if isPublicKeyType(keyType) {
			parsed, err := parseRSAPublicMaterial(keyMaterial)
			if err != nil {
				return nil, nil, false, err
			}
			pub = parsed
		} else {
			priv, err := parseRSAPrivateMaterial(keyMaterial)
			if err != nil {
				return nil, nil, false, err
			}
			pub = &priv.PublicKey
		}
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plain, nil)
		if err != nil {
			return nil, nil, false, err
		}
		return ciphertext, nil, false, nil
	case strings.Contains(a, "AES"):
		mode := symmetricCipherMode(a)
		if mode == "" {
			return nil, nil, false, fmt.Errorf("unsupported AES mode for algorithm %s", algorithm)
		}
		key, err := normalizeAESKeyForAlgorithm(keyMaterial, a)
		if err != nil {
			return nil, nil, false, err
		}
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, nil, false, err
		}
		switch mode {
		case "gcm":
			iv, storeIV, err := selectIVWithSize(ivMode, key, externalIVB64, plain, 12)
			if err != nil {
				return nil, nil, false, err
			}
			ciphertext, err := encryptAESGCM(key, iv, plain, aad)
			if err != nil {
				return nil, nil, false, err
			}
			return ciphertext, iv, storeIV, nil
		case "cbc":
			if len(aad) > 0 {
				return nil, nil, false, errors.New("aad is not supported for CBC mode")
			}
			iv, storeIV, err := selectIVWithSize(ivMode, key, externalIVB64, plain, blk.BlockSize())
			if err != nil {
				return nil, nil, false, err
			}
			padded := pkcs7Pad(plain, blk.BlockSize())
			out := make([]byte, len(padded))
			cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, padded)
			return out, iv, storeIV, nil
		case "ctr":
			if len(aad) > 0 {
				return nil, nil, false, errors.New("aad is not supported for CTR mode")
			}
			iv, storeIV, err := selectIVWithSize(ivMode, key, externalIVB64, plain, blk.BlockSize())
			if err != nil {
				return nil, nil, false, err
			}
			out := make([]byte, len(plain))
			stream := cipher.NewCTR(blk, iv)
			stream.XORKeyStream(out, plain)
			return out, iv, storeIV, nil
		default:
			return nil, nil, false, fmt.Errorf("unsupported AES mode for algorithm %s", algorithm)
		}
	case strings.Contains(a, "3DES"), strings.Contains(a, "TDES"):
		if !strings.Contains(a, "CBC") {
			return nil, nil, false, fmt.Errorf("unsupported 3DES mode for algorithm %s", algorithm)
		}
		if len(aad) > 0 {
			return nil, nil, false, errors.New("aad is not supported for 3DES-CBC mode")
		}
		key := normalize3DESKey(keyMaterial)
		blk, err := des.NewTripleDESCipher(key)
		if err != nil {
			return nil, nil, false, err
		}
		iv, storeIV, err := selectIVWithSize(ivMode, key, externalIVB64, plain, blk.BlockSize())
		if err != nil {
			return nil, nil, false, err
		}
		padded := pkcs7Pad(plain, blk.BlockSize())
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, padded)
		return out, iv, storeIV, nil
	default:
		return nil, nil, false, fmt.Errorf("encrypt is not supported for algorithm %s", algorithm)
	}
}

func decryptWithKeyAlgorithm(algorithm string, keyType string, keyMaterial []byte, iv []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(a, "RSA"):
		if isPublicKeyType(keyType) {
			return nil, errors.New("rsa decrypt requires private key material")
		}
		if len(aad) > 0 {
			return nil, errors.New("aad is not supported for RSA-OAEP")
		}
		priv, err := parseRSAPrivateMaterial(keyMaterial)
		if err != nil {
			return nil, err
		}
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
	case strings.Contains(a, "AES"):
		mode := symmetricCipherMode(a)
		if mode == "" {
			return nil, fmt.Errorf("unsupported AES mode for algorithm %s", algorithm)
		}
		key, err := normalizeAESKeyForAlgorithm(keyMaterial, a)
		if err != nil {
			return nil, err
		}
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		switch mode {
		case "gcm":
			return decryptAESGCM(key, iv, ciphertext, aad)
		case "cbc":
			if len(aad) > 0 {
				return nil, errors.New("aad is not supported for CBC mode")
			}
			if len(iv) != blk.BlockSize() {
				return nil, fmt.Errorf("invalid iv length: got=%d want=%d", len(iv), blk.BlockSize())
			}
			if len(ciphertext)%blk.BlockSize() != 0 {
				return nil, errors.New("ciphertext must be block-aligned for CBC mode")
			}
			out := make([]byte, len(ciphertext))
			cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, ciphertext)
			return pkcs7Unpad(out, blk.BlockSize())
		case "ctr":
			if len(aad) > 0 {
				return nil, errors.New("aad is not supported for CTR mode")
			}
			if len(iv) != blk.BlockSize() {
				return nil, fmt.Errorf("invalid iv length: got=%d want=%d", len(iv), blk.BlockSize())
			}
			out := make([]byte, len(ciphertext))
			stream := cipher.NewCTR(blk, iv)
			stream.XORKeyStream(out, ciphertext)
			return out, nil
		default:
			return nil, fmt.Errorf("unsupported AES mode for algorithm %s", algorithm)
		}
	case strings.Contains(a, "3DES"), strings.Contains(a, "TDES"):
		if !strings.Contains(a, "CBC") {
			return nil, fmt.Errorf("unsupported 3DES mode for algorithm %s", algorithm)
		}
		if len(aad) > 0 {
			return nil, errors.New("aad is not supported for 3DES-CBC mode")
		}
		key := normalize3DESKey(keyMaterial)
		blk, err := des.NewTripleDESCipher(key)
		if err != nil {
			return nil, err
		}
		if len(iv) != blk.BlockSize() {
			return nil, fmt.Errorf("invalid iv length: got=%d want=%d", len(iv), blk.BlockSize())
		}
		if len(ciphertext)%blk.BlockSize() != 0 {
			return nil, errors.New("ciphertext must be block-aligned for 3DES-CBC mode")
		}
		out := make([]byte, len(ciphertext))
		cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, ciphertext)
		return pkcs7Unpad(out, blk.BlockSize())
	default:
		return nil, fmt.Errorf("decrypt is not supported for algorithm %s", algorithm)
	}
}

func pkcs7Pad(raw []byte, blockSize int) []byte {
	padLen := blockSize - (len(raw) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(append([]byte{}, raw...), pad...)
}

func pkcs7Unpad(raw []byte, blockSize int) ([]byte, error) {
	if len(raw) == 0 || len(raw)%blockSize != 0 {
		return nil, errors.New("invalid padded payload")
	}
	padLen := int(raw[len(raw)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(raw) {
		return nil, errors.New("invalid padding length")
	}
	for _, v := range raw[len(raw)-padLen:] {
		if int(v) != padLen {
			return nil, errors.New("invalid PKCS#7 padding")
		}
	}
	return append([]byte{}, raw[:len(raw)-padLen]...), nil
}

func computeKCVStrict(algorithm string, keyMaterial []byte) ([]byte, string, error) {
	alg := strings.ToUpper(algorithm)
	switch {
	case strings.Contains(alg, "AES"):
		key, err := normalizeAESKey(keyMaterial)
		if err != nil {
			return nil, "", err
		}
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, "", err
		}
		in := make([]byte, 16)
		out := make([]byte, 16)
		blk.Encrypt(out, in)
		return out[:3], "aes-ecb-zero", nil
	case strings.Contains(alg, "3DES") || strings.Contains(alg, "TDES"):
		key := normalize3DESKey(keyMaterial)
		blk, err := des.NewTripleDESCipher(key)
		if err != nil {
			return nil, "", err
		}
		in := make([]byte, 8)
		out := make([]byte, 8)
		blk.Encrypt(out, in)
		return out[:3], "3des-ecb-zero", nil
	case strings.Contains(alg, "HMAC"):
		mac := hmac.New(sha256.New, keyMaterial)
		_, _ = mac.Write(make([]byte, 32))
		sum := mac.Sum(nil)
		return sum[:3], "hmac-sha256-zero", nil
	default:
		sum := sha256.Sum256(keyMaterial)
		return sum[:3], "sha256-material", nil
	}
}

func encryptAESGCM(key []byte, iv []byte, plain []byte, aad []byte) ([]byte, error) {
	k, err := normalizeAESKey(key)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	if len(iv) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid iv length: got=%d want=%d", len(iv), gcm.NonceSize())
	}
	return gcm.Seal(nil, iv, plain, aad), nil
}

func decryptAESGCM(key []byte, iv []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	k, err := normalizeAESKey(key)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	if len(iv) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid iv length: got=%d want=%d", len(iv), gcm.NonceSize())
	}
	return gcm.Open(nil, iv, ciphertext, aad)
}

func defaultIV(v string) string {
	if v == "" {
		return "internal"
	}
	return strings.ToLower(v)
}

func generateMaterial(algorithm string) ([]byte, error) {
	l := materialLengthForAlgorithm(algorithm)
	out := make([]byte, l)
	_, err := rand.Read(out)
	return out, err
}

func generateMaterialForCreate(algorithm string, keyType string) ([]byte, error) {
	if isRSAKeyAlgorithm(algorithm) {
		bits := 2048
		up := strings.ToUpper(strings.TrimSpace(algorithm))
		switch {
		case strings.Contains(up, "8192"):
			bits = 8192
		case strings.Contains(up, "4096"):
			bits = 4096
		case strings.Contains(up, "3072"):
			bits = 3072
		}
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		if isPublicKeyType(keyType) {
			pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
			if err != nil {
				return nil, err
			}
			return pubDER, nil
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return privDER, nil
	}
	up := strings.ToUpper(strings.TrimSpace(algorithm))
	if strings.Contains(up, "ECDSA") || strings.Contains(up, "ECDH") || strings.Contains(up, "BRAINPOOL") {
		curve := elliptic.P256()
		switch {
		case strings.Contains(up, "521"):
			curve = elliptic.P521()
		case strings.Contains(up, "384"):
			curve = elliptic.P384()
		default:
			curve = elliptic.P256()
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		if isPublicKeyType(keyType) {
			pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
			if err != nil {
				return nil, err
			}
			return pubDER, nil
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return privDER, nil
	}
	if strings.Contains(up, "ED25519") {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if isPublicKeyType(keyType) {
			pubDER, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil {
				return nil, err
			}
			return pubDER, nil
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return privDER, nil
	}
	if strings.Contains(up, "X25519") {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if isPublicKeyType(keyType) {
			pubDER, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
			if err != nil {
				return nil, err
			}
			return pubDER, nil
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return privDER, nil
	}
	if strings.Contains(up, "ED448") || strings.Contains(up, "X448") {
		return nil, errors.New("requested algorithm is not supported in this build")
	}
	kemAlg := normalizeKEMAlgorithm(algorithm)
	if strings.Contains(up, "ML-KEM") && kemAlg == "" {
		return nil, errors.New("ml-kem algorithm must be ML-KEM-768 or ML-KEM-1024")
	}
	if kemAlg == "" {
		return generateMaterial(algorithm)
	}
	isPublic := isPublicKeyType(keyType)
	switch kemAlg {
	case "ml-kem-768":
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, err
		}
		if isPublic {
			return dk.EncapsulationKey().Bytes(), nil
		}
		return dk.Bytes(), nil
	case "ml-kem-1024":
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, err
		}
		if isPublic {
			return dk.EncapsulationKey().Bytes(), nil
		}
		return dk.Bytes(), nil
	default:
		return generateMaterial(algorithm)
	}
}

func normalizeAESKey(k []byte) ([]byte, error) {
	switch len(k) {
	case 16, 24, 32:
		return append([]byte{}, k...), nil
	default:
		return nil, errors.New("invalid AES key length")
	}
}

func normalize3DESKey(k []byte) []byte {
	if len(k) >= 24 {
		return append([]byte{}, k[:24]...)
	}
	if len(k) >= 16 {
		out := make([]byte, 24)
		copy(out, k[:16])
		copy(out[16:], k[:8])
		return out
	}
	out := make([]byte, 24)
	copy(out, k)
	return out
}

func packWrappedDEK(iv []byte, wrapped []byte) []byte {
	out := make([]byte, 0, len(iv)+len(wrapped))
	out = append(out, iv...)
	out = append(out, wrapped...)
	return out
}

func unpackWrappedDEK(raw []byte) ([]byte, []byte, error) {
	if len(raw) <= 16 {
		return nil, nil, errors.New("invalid wrapped dek")
	}
	iv := append([]byte{}, raw[:16]...)
	w := append([]byte{}, raw[16:]...)
	return iv, w, nil
}

func existsToken(tenantID string, keyID string) string {
	return tenantID + ":" + keyID
}

func (s *Service) checkPolicy(ctx context.Context, req PolicyEvaluateRequest) error {
	if s.policy == nil {
		return nil
	}
	resp, err := s.policy.Evaluate(ctx, req)
	if err != nil {
		if s.pf {
			return errors.New("policy evaluation failed: " + err.Error())
		}
		return nil
	}
	switch strings.ToUpper(strings.TrimSpace(resp.Decision)) {
	case "DENY":
		return policyDeniedError{Reason: resp.Reason}
	default:
		return nil
	}
}

func daysSince(ts time.Time) int {
	if ts.IsZero() {
		return 0
	}
	d := time.Since(ts.UTC())
	if d < 0 {
		return 0
	}
	return int(d.Hours() / 24)
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}
