package imagesign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"vecta-kms/pkg/db"
)

// Signer handles container image signature creation and verification.
type Signer struct {
	signingKey crypto.Signer
	store      *Store
	auditFn    func(ctx context.Context, event string, details map[string]string)
}

// NewSigner creates a Signer with the given key, store, and optional audit callback.
func NewSigner(key crypto.Signer, store *Store, auditFn func(ctx context.Context, event string, details map[string]string)) *Signer {
	if auditFn == nil {
		auditFn = func(context.Context, string, map[string]string) {}
	}
	return &Signer{signingKey: key, store: store, auditFn: auditFn}
}

// SignRequest describes an image to be signed.
type SignRequest struct {
	TenantID     string            `json:"tenant_id"`
	ImageRef     string            `json:"image_ref"`
	Digest       string            `json:"digest"`
	SigningKeyID string            `json:"signing_key_id"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// SignResult is the output of a successful signing operation.
type SignResult struct {
	ID               string    `json:"id"`
	ImageRef         string    `json:"image_ref"`
	Digest           string    `json:"digest"`
	Signature        string    `json:"signature"` // base64-encoded
	SigningKeyID     string    `json:"signing_key_id"`
	SignedAt         time.Time `json:"signed_at"`
	CertificateChain []string  `json:"certificate_chain,omitempty"`
}

// BuildPayload constructs the atomic container signature payload as defined by
// the container image signing specification.
func BuildPayload(imageRef, digest string) ([]byte, error) {
	if imageRef == "" {
		return nil, errors.New("imagesign: image_ref is required")
	}
	if digest == "" {
		return nil, errors.New("imagesign: digest is required")
	}

	payload := map[string]interface{}{
		"critical": map[string]interface{}{
			"identity": map[string]string{
				"docker-reference": imageRef,
			},
			"image": map[string]string{
				"docker-manifest-digest": digest,
			},
			"type": "atomic container signature",
		},
	}
	return json.Marshal(payload)
}

// Sign creates a cryptographic signature for the specified container image.
func (s *Signer) Sign(ctx context.Context, req SignRequest) (*SignResult, error) {
	if req.TenantID == "" {
		return nil, errors.New("imagesign: tenant_id is required")
	}
	if req.ImageRef == "" {
		return nil, errors.New("imagesign: image_ref is required")
	}
	if req.Digest == "" {
		return nil, errors.New("imagesign: digest is required")
	}

	payload, err := BuildPayload(req.ImageRef, req.Digest)
	if err != nil {
		return nil, fmt.Errorf("imagesign: build payload: %w", err)
	}

	hash := sha256.Sum256(payload)

	var sigBytes []byte
	switch key := s.signingKey.(type) {
	case *ecdsa.PrivateKey:
		sigBytes, err = ecdsa.SignASN1(rand.Reader, key, hash[:])
		if err != nil {
			return nil, fmt.Errorf("imagesign: ecdsa sign: %w", err)
		}
	case *rsa.PrivateKey:
		sigBytes, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
		if err != nil {
			return nil, fmt.Errorf("imagesign: rsa-pss sign: %w", err)
		}
	default:
		// Generic crypto.Signer fallback
		sigBytes, err = s.signingKey.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("imagesign: sign: %w", err)
		}
	}

	id := generateID("sig")
	now := time.Now().UTC()

	result := &SignResult{
		ID:           id,
		ImageRef:     req.ImageRef,
		Digest:       req.Digest,
		Signature:    base64.StdEncoding.EncodeToString(sigBytes),
		SigningKeyID: req.SigningKeyID,
		SignedAt:     now,
	}

	// Persist if store is available
	if s.store != nil {
		rec := &SignatureRecord{
			ID:           result.ID,
			TenantID:     req.TenantID,
			ImageRef:     req.ImageRef,
			Digest:       req.Digest,
			Signature:    result.Signature,
			SigningKeyID: req.SigningKeyID,
			Format:       "atomic",
			Payload:      base64.StdEncoding.EncodeToString(payload),
			CreatedAt:    now,
		}
		if err := s.store.Save(ctx, rec); err != nil {
			return nil, fmt.Errorf("imagesign: store signature: %w", err)
		}
	}

	s.auditFn(ctx, "image.signed", map[string]string{
		"tenant_id":      req.TenantID,
		"image_ref":      req.ImageRef,
		"digest":         req.Digest,
		"signing_key_id": req.SigningKeyID,
		"signature_id":   result.ID,
	})

	return result, nil
}

// Verify checks that a signature is valid for the given image reference, digest, and public key.
func Verify(ctx context.Context, imageRef, digest string, signature []byte, publicKey crypto.PublicKey) error {
	payload, err := BuildPayload(imageRef, digest)
	if err != nil {
		return fmt.Errorf("imagesign: build payload for verification: %w", err)
	}

	hash := sha256.Sum256(payload)

	switch pub := publicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, hash[:], signature) {
			return errors.New("imagesign: ECDSA signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		err = rsa.VerifyPSS(pub, crypto.SHA256, hash[:], signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
		if err != nil {
			return fmt.Errorf("imagesign: RSA-PSS signature verification failed: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("imagesign: unsupported public key type %T", publicKey)
	}
}

// generateID produces a unique ID with a prefix using crypto/rand.
func generateID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%x", prefix, b)
}

// GenerateECDSAKey is a helper to generate a P-256 ECDSA key pair for signing.
func GenerateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// NewSignerFromDB creates a Signer backed by a SQL database store.
func NewSignerFromDB(key crypto.Signer, database *db.DB, auditFn func(ctx context.Context, event string, details map[string]string)) *Signer {
	store := NewStore(database)
	return NewSigner(key, store, auditFn)
}
