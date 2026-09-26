package main

import (
	"context"
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
	// PreviousPassphraseFile holds the passphrase the CRWK was sealed under
	// before a rotation (default: BootstrapPassphraseFile + ".previous"). It is
	// read only to migrate off it, and deleted once the rotation completes.
	PreviousPassphraseFile string

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

	// RotationPending: the CRWK was re-keyed under a new passphrase and the
	// CA signers are still being rewrapped (docs/SECURITY/SECRET_ROTATION.md).
	RotationPending bool `json:"rotation_pending,omitempty"`

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

	crwk []byte // wraps every new DEK
	// Only during a rotation: the retired CRWK by key version, to unwrap the
	// signers not yet rewrapped. Dropped by CompleteRotation.
	retired  map[string][]byte
	rotation *crwkRotation
}

// crwkRotation is a re-key in progress: the new CRWK is sealed at nextPath
// under the current passphrase, and becomes sealedPath once every CA signer
// is rewrapped under it.
type crwkRotation struct {
	sealedPath, nextPath, previousPassphraseFile string
	fromVersion, reason                          string
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
	// A public or weak passphrase opens every CA key to anyone with a copy of
	// the volume: refuse to start (docs/SECURITY/SECURE_DEFAULTS.md).
	if err := validateCRWKPassphrase(passphrase); err != nil {
		return nil, fmt.Errorf("certs root wrapping key passphrase: %w", err)
	}

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
	fail := func(format string, args ...interface{}) (certRootKeyProvider, error) {
		p.status.State = "error"
		p.status.LastError = fmt.Sprintf(format, args...)
		return p, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fail("prepare sealed path failed: %v", err)
	}

	blob, readErr := os.ReadFile(path)
	switch {
	case errors.Is(readErr, os.ErrNotExist):
		crwk, err := pkgcrypto.RandomBytes(32)
		if err != nil {
			return fail("generate root key failed: %v", err)
		}
		keyVersion := fmt.Sprintf("crwk-%d", time.Now().UTC().Unix())
		sealed, sealErr := sealCRWKBlob(crwk, passphrase, keyVersion, cfg.UseTPMSeal, memKB, iters, parallel)
		if sealErr != nil {
			pkgcrypto.Zeroize(crwk)
			return fail("seal root key failed: %v", sealErr)
		}
		if writeErr := os.WriteFile(path, sealed, 0o600); writeErr != nil {
			pkgcrypto.Zeroize(crwk)
			return fail("write sealed root key failed: %v", writeErr)
		}
		p.crwk, p.status.KeyVersion = crwk, keyVersion
	case readErr != nil:
		return fail("read sealed root key failed: %v", readErr)
	default:
		crwk, keyVersion, unsealErr := unsealCRWKBlob(blob, passphrase, memKB, iters, parallel)
		if unsealErr == nil {
			p.crwk, p.status.KeyVersion = crwk, keyVersion
			// A rotation that completed but crashed before cleaning up.
			_ = os.Remove(path + ".next")
			_ = os.Remove(previousPassphrasePath(cfg))
			break
		}
		// Not sealed under the current passphrase: the operator (or the
		// installer, replacing the retired public default) rotated it.
		if err := p.beginRotation(cfg, path, blob, passphrase, memKB, iters, parallel); err != nil {
			return fail("unseal root key failed: %v; %v", unsealErr, err)
		}
	}
	p.status.Ready = true
	p.status.State = "ready"
	if p.rotation != nil {
		p.status.State = "rotation_pending"
		p.status.RotationPending = true
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

func (p *softwareCRWKProvider) UnwrapDEK(_ context.Context, wrapped []byte, iv []byte, keyVersion string) ([]byte, error) {
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
	// The key named by the version first; a version string from an older
	// release may not match, so the others are tried (GCM authenticates).
	keys := [][]byte{p.crwk}
	if k, ok := p.retired[strings.TrimSpace(keyVersion)]; ok {
		keys = [][]byte{k, p.crwk}
	} else {
		for _, k := range p.retired {
			keys = append(keys, k)
		}
	}
	var err error
	for _, k := range keys {
		var dek []byte
		if dek, err = aesGCMDecryptRaw(k, wrapped, iv); err == nil {
			return dek, nil
		}
	}
	return nil, err
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
	for _, k := range p.retired {
		pkgcrypto.Zeroize(k)
	}
	p.crwk, p.retired = nil, nil
	p.status.Ready = false
	p.status.State = "closed"
	return nil
}

// beginRotation re-keys a CRWK sealed under the previous passphrase: the
// retired CRWK is unsealed with it, and a new random CRWK, sealed under the
// current passphrase at path+".next", wraps everything from now on. A new
// CRWK (not just a re-sealed one) means a copy of the old sealed file stops
// opening the CA signers once they are rewrapped. The next start after a crash
// reuses the same .next key.
func (p *softwareCRWKProvider) beginRotation(cfg CertRootKeyConfig, path string, blob, passphrase []byte, memKB, iters uint32, parallel uint8) error {
	prevPath := previousPassphrasePath(cfg)
	if prevPath == "" {
		return errors.New("no previous passphrase file is configured (CERTS_CRWK_PREVIOUS_PASSPHRASE_FILE)")
	}
	previous, err := readBootstrapPassphrase("", prevPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("the passphrase does not match the sealed key and no previous passphrase file exists")
		}
		return fmt.Errorf("previous passphrase: %w", err)
	}
	defer pkgcrypto.Zeroize(previous)
	old, oldVersion, err := unsealCRWKBlob(blob, previous, memKB, iters, parallel)
	if err != nil {
		return fmt.Errorf("the previous passphrase does not unseal it either: %w", err)
	}
	reason := "passphrase_rotation"
	if isPublicCRWKPassphrase(previous) {
		reason = "public_default_passphrase"
	}
	nextPath := path + ".next"
	var next []byte
	var nextVersion string
	if raw, readErr := os.ReadFile(nextPath); readErr == nil {
		if next, nextVersion, err = unsealCRWKBlob(raw, passphrase, memKB, iters, parallel); err != nil {
			pkgcrypto.Zeroize(old)
			return fmt.Errorf("a pending rotation's new key (%s) does not unseal under the current passphrase: %w", nextPath, err)
		}
	} else {
		if next, err = pkgcrypto.RandomBytes(32); err != nil {
			pkgcrypto.Zeroize(old)
			return err
		}
		nextVersion = fmt.Sprintf("crwk-%d", time.Now().UTC().Unix())
		if nextVersion == oldVersion {
			nextVersion += "-r"
		}
		sealed, sealErr := sealCRWKBlob(next, passphrase, nextVersion, cfg.UseTPMSeal, memKB, iters, parallel)
		if sealErr == nil {
			sealErr = writeFileAtomically(nextPath, sealed, 0o600)
		}
		if sealErr != nil {
			pkgcrypto.Zeroize(old)
			pkgcrypto.Zeroize(next)
			return fmt.Errorf("seal the new root key: %w", sealErr)
		}
	}
	p.crwk, p.status.KeyVersion = next, nextVersion
	p.retired = map[string][]byte{oldVersion: old}
	p.rotation = &crwkRotation{sealedPath: path, nextPath: nextPath, previousPassphraseFile: prevPath, fromVersion: oldVersion, reason: reason}
	return nil
}

// crwkRotator is implemented by a provider that can re-key its CRWK.
type crwkRotator interface {
	PendingRotation() (from, to, reason string, pending bool)
	CompleteRotation() error
}

func (p *softwareCRWKProvider) PendingRotation() (string, string, string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.rotation == nil {
		return "", "", "", false
	}
	return p.rotation.fromVersion, p.status.KeyVersion, p.rotation.reason, true
}

// CompleteRotation makes the new sealed CRWK the only one, deletes the
// previous passphrase file and forgets the retired key. Call it only after
// every signer wrapped by the retired key has been rewrapped.
func (p *softwareCRWKProvider) CompleteRotation() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.rotation
	if r == nil {
		return nil
	}
	if err := os.Rename(r.nextPath, r.sealedPath); err != nil {
		return fmt.Errorf("install the new sealed root key: %w", err)
	}
	if dir, err := os.Open(filepath.Dir(r.sealedPath)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	for _, k := range p.retired {
		pkgcrypto.Zeroize(k)
	}
	p.retired, p.rotation = nil, nil
	p.status.State, p.status.RotationPending = "ready", false
	if err := os.Remove(r.previousPassphraseFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the previous passphrase file: %w", err)
	}
	return nil
}

func previousPassphrasePath(cfg CertRootKeyConfig) string {
	if v := strings.TrimSpace(cfg.PreviousPassphraseFile); v != "" {
		return v
	}
	if v := strings.TrimSpace(cfg.BootstrapPassphraseFile); v != "" {
		return v + ".previous"
	}
	return ""
}

// publicCRWKPassphrases are SHA-256 digests of passphrases that shipped in
// this repository and are therefore public. Digests, so the values
// themselves don't reappear in the source (make conformance,
// no-retired-public-secret).
var publicCRWKPassphrases = map[string]bool{
	"ea55b5cbaeab810eae255287b38a3ad77660bbafe6063af1717d8fa8c8ec031b": true, // removed in 1.10.0-beta
}

const minCRWKPassphraseLen = 32

func isPublicCRWKPassphrase(passphrase []byte) bool {
	sum := sha256.Sum256(passphrase)
	return publicCRWKPassphrases[hex.EncodeToString(sum[:])]
}

// validateCRWKPassphrase refuses the retired public default and anything
// short or repetitive. Installers generate 64 random hex characters. The
// error never contains the passphrase.
func validateCRWKPassphrase(passphrase []byte) error {
	if isPublicCRWKPassphrase(passphrase) {
		return errors.New("it is a public default that shipped in the repository; generate a new one (docs/SECURITY/SECRET_ROTATION.md)")
	}
	if len(passphrase) < minCRWKPassphraseLen {
		return fmt.Errorf("it is shorter than %d characters", minCRWKPassphraseLen)
	}
	distinct := map[byte]bool{}
	for _, c := range passphrase {
		distinct[c] = true
	}
	if len(distinct) < 8 {
		return errors.New("it has fewer than 8 distinct characters")
	}
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
	salt, err := pkgcrypto.RandomBytes(16)
	if err != nil {
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

// AES-GCM via pkg/crypto: the nonce is generated inside the FIPS module, so
// root-key sealing works in every FIPS runtime mode.
func aesGCMEncryptRaw(key []byte, plaintext []byte) ([]byte, []byte, error) {
	nonce, ciphertext, err := pkgcrypto.SealDetached(key, plaintext, nil)
	return ciphertext, nonce, err
}

func aesGCMDecryptRaw(key []byte, ciphertext []byte, nonce []byte) ([]byte, error) {
	return pkgcrypto.OpenDetached(key, nonce, ciphertext, nil)
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
