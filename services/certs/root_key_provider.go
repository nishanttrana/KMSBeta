package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"

	"golang.org/x/crypto/argon2"
)

const (
	defaultCRWKSealedPath = "/var/lib/vecta/certs/crwk.sealed"
	defaultCRWKMemKB      = 128 * 1024
	defaultCRWKIterations = 4
	defaultCRWKParallel   = 2
)

type CertRootKeyConfig struct {
	StorageMode string
	RootKeyMode string

	SealedPath string

	BootstrapPassphrase     string
	BootstrapPassphraseFile string

	ArgonMemoryKB   uint32
	ArgonIterations uint32
	ArgonParallel   uint8

	MlockRequired bool
	UseTPMSeal    bool
}

type CertRootKeyStatus struct {
	StorageMode string `json:"storage_mode"`
	RootKeyMode string `json:"root_key_mode"`
	Ready       bool   `json:"ready"`
	State       string `json:"state"`

	KeyVersion  string `json:"key_version"`
	SealedPath  string `json:"sealed_path"`
	UseTPMSeal  bool   `json:"use_tpm_seal"`
	MlockStatus string `json:"mlock_status"`

	LastError string `json:"last_error,omitempty"`
}

type certRootKeyProvider interface {
	WrapDEK(ctx context.Context, dek []byte) (wrapped []byte, iv []byte, keyVersion string, err error)
	UnwrapDEK(ctx context.Context, wrapped []byte, iv []byte, keyVersion string) ([]byte, error)
	Status() CertRootKeyStatus
	Close() error
}

type certRootKeyUnavailable struct {
	status CertRootKeyStatus
}

func (p *certRootKeyUnavailable) WrapDEK(_ context.Context, _ []byte) ([]byte, []byte, string, error) {
	msg := strings.TrimSpace(p.status.LastError)
	if msg == "" {
		msg = "certificate root key provider is unavailable"
	}
	return nil, nil, "", errors.New(msg)
}

func (p *certRootKeyUnavailable) UnwrapDEK(_ context.Context, _ []byte, _ []byte, _ string) ([]byte, error) {
	msg := strings.TrimSpace(p.status.LastError)
	if msg == "" {
		msg = "certificate root key provider is unavailable"
	}
	return nil, errors.New(msg)
}

func (p *certRootKeyUnavailable) Status() CertRootKeyStatus {
	return p.status
}

func (p *certRootKeyUnavailable) Close() error { return nil }

type softwareCRWKProvider struct {
	mu sync.RWMutex

	status CertRootKeyStatus

	crwk []byte
}

type sealedCRWKBlob struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	KeyVersion string `json:"key_version"`
	CreatedAt  string `json:"created_at"`
	UseTPMSeal bool   `json:"use_tpm_seal"`

	SaltB64       string `json:"salt_b64"`
	NonceB64      string `json:"nonce_b64"`
	CiphertextB64 string `json:"ciphertext_b64"`

	ArgonMemoryKB   uint32 `json:"argon_memory_kb"`
	ArgonIterations uint32 `json:"argon_iterations"`
	ArgonParallel   uint8  `json:"argon_parallel"`
}

func newCertRootKeyProvider(cfg CertRootKeyConfig) (certRootKeyProvider, error) {
	cfg.StorageMode = normalizeStorageMode(cfg.StorageMode)
	cfg.RootKeyMode = normalizeRootKeyMode(cfg.RootKeyMode)

	if cfg.StorageMode != "db_encrypted" {
		return &certRootKeyUnavailable{
			status: CertRootKeyStatus{
				StorageMode: cfg.StorageMode,
				RootKeyMode: cfg.RootKeyMode,
				Ready:       false,
				State:       "disabled",
				LastError:   "cert storage mode is not db_encrypted",
			},
		}, nil
	}

	switch cfg.RootKeyMode {
	case "software":
		return newSoftwareCRWKProvider(cfg)
	case "hsm":
		return &certRootKeyUnavailable{
			status: CertRootKeyStatus{
				StorageMode: cfg.StorageMode,
				RootKeyMode: cfg.RootKeyMode,
				Ready:       false,
				State:       "pending_hsm_configuration",
				LastError:   "hsm root key mode is reserved for UI-driven HSM integration",
			},
		}, nil
	default:
		return &certRootKeyUnavailable{
			status: CertRootKeyStatus{
				StorageMode: cfg.StorageMode,
				RootKeyMode: cfg.RootKeyMode,
				Ready:       false,
				State:       "error",
				LastError:   "unsupported root key mode",
			},
		}, nil
	}
}

func newSoftwareCRWKProvider(cfg CertRootKeyConfig) (certRootKeyProvider, error) {
	path := strings.TrimSpace(cfg.SealedPath)
	if path == "" {
		path = defaultCRWKSealedPath
	}
	passphrase, err := readBootstrapPassphrase(cfg.BootstrapPassphrase, cfg.BootstrapPassphraseFile)
	if err != nil {
		return &certRootKeyUnavailable{
			status: CertRootKeyStatus{
				StorageMode: "db_encrypted",
				RootKeyMode: "software",
				Ready:       false,
				State:       "awaiting_bootstrap_passphrase",
				SealedPath:  path,
				UseTPMSeal:  cfg.UseTPMSeal,
				LastError:   err.Error(),
			},
		}, nil
	}
	defer pkgcrypto.Zeroize(passphrase)

	memKB := cfg.ArgonMemoryKB
	if memKB == 0 {
		memKB = defaultCRWKMemKB
	}
	iters := cfg.ArgonIterations
	if iters == 0 {
		iters = defaultCRWKIterations
	}
	parallel := cfg.ArgonParallel
	if parallel == 0 {
		parallel = defaultCRWKParallel
	}

	p := &softwareCRWKProvider{
		status: CertRootKeyStatus{
			StorageMode: "db_encrypted",
			RootKeyMode: "software",
			Ready:       false,
			State:       "initializing",
			SealedPath:  path,
			UseTPMSeal:  cfg.UseTPMSeal,
		},
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		p.status.State = "error"
		p.status.LastError = fmt.Sprintf("prepare sealed path failed: %v", err)
		return p, nil
	}

	if _, statErr := os.Stat(path); statErr == nil {
		blob, readErr := os.ReadFile(path)
		if readErr != nil {
			p.status.State = "error"
			p.status.LastError = fmt.Sprintf("read sealed root key failed: %v", readErr)
			return p, nil
		}
		crwk, keyVersion, unsealErr := unsealCRWKBlob(blob, passphrase, memKB, iters, parallel)
		if unsealErr != nil {
			p.status.State = "error"
			p.status.LastError = fmt.Sprintf("unseal root key failed: %v", unsealErr)
			return p, nil
		}
		p.crwk = crwk
		p.status.KeyVersion = keyVersion
		p.status.State = "ready"
		p.status.Ready = true
	} else if errors.Is(statErr, os.ErrNotExist) {
		crwk := make([]byte, 32)
		if _, randErr := rand.Read(crwk); randErr != nil {
			p.status.State = "error"
			p.status.LastError = fmt.Sprintf("generate root key failed: %v", randErr)
			return p, nil
		}
		keyVersion := fmt.Sprintf("crwk-%d", time.Now().UTC().Unix())
		blob, sealErr := sealCRWKBlob(crwk, passphrase, keyVersion, cfg.UseTPMSeal, memKB, iters, parallel)
		if sealErr != nil {
			pkgcrypto.Zeroize(crwk)
			p.status.State = "error"
			p.status.LastError = fmt.Sprintf("seal root key failed: %v", sealErr)
			return p, nil
		}
		if writeErr := os.WriteFile(path, blob, 0o600); writeErr != nil {
			pkgcrypto.Zeroize(crwk)
			p.status.State = "error"
			p.status.LastError = fmt.Sprintf("write sealed root key failed: %v", writeErr)
			return p, nil
		}
		p.crwk = crwk
		p.status.KeyVersion = keyVersion
		p.status.State = "ready"
		p.status.Ready = true
	} else {
		p.status.State = "error"
		p.status.LastError = fmt.Sprintf("inspect sealed root key failed: %v", statErr)
		return p, nil
	}

	if err := pkgcrypto.Mlock(p.crwk); err != nil {
		if cfg.MlockRequired {
			pkgcrypto.Zeroize(p.crwk)
			p.crwk = nil
			p.status.Ready = false
			p.status.State = "error"
			p.status.LastError = fmt.Sprintf("mlock failed: %v", err)
			p.status.MlockStatus = "failed_required"
			return p, nil
		}
		p.status.MlockStatus = "best_effort_failed"
	} else {
		p.status.MlockStatus = "locked"
	}

	return p, nil
}

func (p *softwareCRWKProvider) WrapDEK(_ context.Context, dek []byte) ([]byte, []byte, string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.status.Ready || len(p.crwk) != 32 {
		msg := strings.TrimSpace(p.status.LastError)
		if msg == "" {
			msg = "software root key is not ready"
		}
		return nil, nil, "", errors.New(msg)
	}
	if len(dek) == 0 {
		return nil, nil, "", errors.New("dek is required")
	}
	wrapped, iv, err := aesGCMEncryptRaw(p.crwk, dek)
	if err != nil {
		return nil, nil, "", err
	}
	return wrapped, iv, p.status.KeyVersion, nil
}

func (p *softwareCRWKProvider) UnwrapDEK(_ context.Context, wrapped []byte, iv []byte, _ string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.status.Ready || len(p.crwk) != 32 {
		msg := strings.TrimSpace(p.status.LastError)
		if msg == "" {
			msg = "software root key is not ready"
		}
		return nil, errors.New(msg)
	}
	if len(wrapped) == 0 || len(iv) == 0 {
		return nil, errors.New("wrapped dek and iv are required")
	}
	return aesGCMDecryptRaw(p.crwk, wrapped, iv)
}

func (p *softwareCRWKProvider) Status() CertRootKeyStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.status
}

func (p *softwareCRWKProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.crwk) > 0 {
		_ = pkgcrypto.Munlock(p.crwk)
		pkgcrypto.Zeroize(p.crwk)
	}
	p.crwk = nil
	p.status.Ready = false
	p.status.State = "closed"
	return nil
}

func readBootstrapPassphrase(inline string, path string) ([]byte, error) {
	if v := strings.TrimSpace(inline); v != "" {
		return []byte(v), nil
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("bootstrap passphrase is required (CERTS_CRWK_BOOTSTRAP_PASSPHRASE or CERTS_CRWK_PASSPHRASE_FILE)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read passphrase file: %w", err)
	}
	v := strings.TrimSpace(string(raw))
	if v == "" {
		return nil, errors.New("bootstrap passphrase file is empty")
	}
	return []byte(v), nil
}

func sealCRWKBlob(crwk []byte, passphrase []byte, keyVersion string, useTPMSeal bool, memKB uint32, iters uint32, parallel uint8) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	kek := argon2.IDKey(passphrase, salt, iters, memKB, parallel, 32)
	defer pkgcrypto.Zeroize(kek)

	ciphertext, nonce, err := aesGCMEncryptRaw(kek, crwk)
	if err != nil {
		return nil, err
	}
	blob := sealedCRWKBlob{
		Version:         1,
		KDF:             "argon2id",
		KeyVersion:      strings.TrimSpace(keyVersion),
		CreatedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		UseTPMSeal:      useTPMSeal,
		SaltB64:         base64.StdEncoding.EncodeToString(salt),
		NonceB64:        base64.StdEncoding.EncodeToString(nonce),
		CiphertextB64:   base64.StdEncoding.EncodeToString(ciphertext),
		ArgonMemoryKB:   memKB,
		ArgonIterations: iters,
		ArgonParallel:   parallel,
	}
	return json.MarshalIndent(blob, "", "  ")
}

func unsealCRWKBlob(raw []byte, passphrase []byte, fallbackMemKB uint32, fallbackIters uint32, fallbackParallel uint8) ([]byte, string, error) {
	var blob sealedCRWKBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return nil, "", err
	}
	if blob.Version != 1 {
		return nil, "", fmt.Errorf("unsupported sealed blob version %d", blob.Version)
	}
	if !strings.EqualFold(strings.TrimSpace(blob.KDF), "argon2id") {
		return nil, "", fmt.Errorf("unsupported kdf %q", blob.KDF)
	}
	salt, err := base64.StdEncoding.DecodeString(strings.TrimSpace(blob.SaltB64))
	if err != nil {
		return nil, "", fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(strings.TrimSpace(blob.NonceB64))
	if err != nil {
		return nil, "", fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(blob.CiphertextB64))
	if err != nil {
		return nil, "", fmt.Errorf("decode ciphertext: %w", err)
	}
	memKB := blob.ArgonMemoryKB
	if memKB == 0 {
		memKB = fallbackMemKB
		if memKB == 0 {
			memKB = defaultCRWKMemKB
		}
	}
	iters := blob.ArgonIterations
	if iters == 0 {
		iters = fallbackIters
		if iters == 0 {
			iters = defaultCRWKIterations
		}
	}
	parallel := blob.ArgonParallel
	if parallel == 0 {
		parallel = fallbackParallel
		if parallel == 0 {
			parallel = defaultCRWKParallel
		}
	}
	kek := argon2.IDKey(passphrase, salt, iters, memKB, parallel, 32)
	defer pkgcrypto.Zeroize(kek)

	crwk, err := aesGCMDecryptRaw(kek, ciphertext, nonce)
	if err != nil {
		return nil, "", err
	}
	if len(crwk) != 32 {
		pkgcrypto.Zeroize(crwk)
		return nil, "", errors.New("invalid root key length in sealed blob")
	}
	keyVersion := strings.TrimSpace(blob.KeyVersion)
	if keyVersion == "" {
		keyVersion = "crwk-v1"
	}
	return crwk, keyVersion, nil
}

func aesGCMEncryptRaw(key []byte, plaintext []byte) ([]byte, []byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func aesGCMDecryptRaw(key []byte, ciphertext []byte, nonce []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length: want %d got %d", gcm.NonceSize(), len(nonce))
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func normalizeStorageMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "db_encrypted":
		return "db_encrypted"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func normalizeRootKeyMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "software":
		return "software"
	case "hsm":
		return "hsm"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func signerFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
