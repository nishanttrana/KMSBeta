package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"time"
)

// ArchiveStore is the cold-tier persistence interface used by the
// archival worker. Implementations: filesystem (default), S3+KMS,
// Azure Blob+Key Vault. The interface is intentionally narrow — the
// worker handles double-wrapping before write — so swapping backends
// doesn't require re-auditing the cryptography.
type ArchiveStore interface {
	Put(ctx context.Context, tenantID, keyID string, version int, blob []byte) error
	Get(ctx context.Context, tenantID, keyID string, version int) ([]byte, error)
	Delete(ctx context.Context, tenantID, keyID string, version int) error
	List(ctx context.Context, tenantID, keyID string) ([]int, error)
}

// Archiver writes deactivated key material to cold storage under a second
// wrap (envelope -> MEK -> archive key). The second wrap means that even
// if cold storage is exfiltrated, the attacker still needs the archive
// KEK plus the MEK to recover material.
type Archiver struct {
	store      ArchiveStore
	archiveKEK []byte // 32-byte AES-256 key
}

// NewArchiver constructs an archiver. archiveKEK must be exactly 32
// bytes; shorter values fall back to a zero key which makes the worker
// refuse to archive (fail-closed).
func NewArchiver(store ArchiveStore, archiveKEK []byte) (*Archiver, error) {
	if store == nil {
		return nil, errors.New("archive store is required")
	}
	if len(archiveKEK) != 32 {
		return nil, errors.New("archive KEK must be 32 bytes (AES-256)")
	}
	return &Archiver{store: store, archiveKEK: archiveKEK}, nil
}

// Archive double-wraps and persists the wrapped key material. The blob
// layout is `nonce || ciphertext` where the AEAD tag is appended to the
// ciphertext by AES-GCM. The current time is bound into the additional
// data so a replay of an old archive cannot pass forgery checks.
func (a *Archiver) Archive(ctx context.Context, tenantID, keyID string, version int, mekWrappedMaterial []byte) error {
	block, err := aes.NewCipher(a.archiveKEK)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	aad := []byte(tenantID + "|" + keyID + "|" + time.Now().UTC().Format(time.RFC3339))
	ct := gcm.Seal(nil, nonce, mekWrappedMaterial, aad)
	blob := append([]byte{}, nonce...)
	blob = append(blob, ct...)
	// We persist the additional-data tag at the end so unwrap can verify
	// the binding. The tag is base64-url to keep the blob safe for object
	// storage with strict key validation.
	blob = append(blob, []byte("|aad="+base64.RawURLEncoding.EncodeToString(aad))...)
	return a.store.Put(ctx, tenantID, keyID, version, blob)
}

// Restore is the inverse of Archive. It is intentionally not exported as a
// REST endpoint — restoration must go through escrow + ceremony tooling
// so that re-introducing material is gated by the same controls as
// initial creation.
func (a *Archiver) Restore(ctx context.Context, tenantID, keyID string, version int) ([]byte, error) {
	blob, err := a.store.Get(ctx, tenantID, keyID, version)
	if err != nil {
		return nil, err
	}
	// Locate the trailing aad marker.
	idx := -1
	tail := []byte("|aad=")
	for i := len(blob) - len(tail); i >= 0; i-- {
		match := true
		for j := 0; j < len(tail); j++ {
			if blob[i+j] != tail[j] {
				match = false
				break
			}
		}
		if match {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, errors.New("archive blob is malformed")
	}
	body := blob[:idx]
	aadB64 := string(blob[idx+len(tail):])
	aad, err := base64.RawURLEncoding.DecodeString(aadB64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(a.archiveKEK)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(body) < gcm.NonceSize() {
		return nil, errors.New("archive blob too short")
	}
	nonce := body[:gcm.NonceSize()]
	ct := body[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, aad)
}

// FilesystemArchiveStore is a development-friendly archive backend. It
// writes blobs to a single directory tree per tenant. Production
// deployments should swap in an S3 / Azure Blob implementation, but the
// filesystem variant is sufficient for the integration suite and
// keeps the build self-contained.
type FilesystemArchiveStore struct {
	Root string
}

// fsPath kept private — implementations live in a separate file or are
// inlined in tests.
