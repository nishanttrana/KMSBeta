package imagesign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// CosignBundle holds a Sigstore/Cosign-compatible signature bundle.
type CosignBundle struct {
	Base64Signature string            `json:"base64Signature"`
	Payload         string            `json:"payload"` // base64-encoded JSON payload
	Cert            string            `json:"cert,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
}

// CosignPayload is the payload format used in Cosign signatures.
type CosignPayload struct {
	Critical CosignCritical    `json:"critical"`
	Optional map[string]string `json:"optional,omitempty"`
}

// CosignCritical contains the identity and image fields.
type CosignCritical struct {
	Identity CosignIdentity `json:"identity"`
	Image    CosignImage    `json:"image"`
	Type     string         `json:"type"`
}

// CosignIdentity references the image by docker-reference.
type CosignIdentity struct {
	DockerReference string `json:"docker-reference"`
}

// CosignImage references the image by manifest digest.
type CosignImage struct {
	DockerManifestDigest string `json:"docker-manifest-digest"`
}

// CosignSigner wraps a crypto.Signer to produce Cosign-compatible bundles.
type CosignSigner struct {
	key     crypto.Signer
	certPEM string // optional PEM-encoded certificate
}

// NewCosignSigner creates a CosignSigner with the given key and optional certificate PEM.
func NewCosignSigner(key crypto.Signer, certPEM string) *CosignSigner {
	return &CosignSigner{key: key, certPEM: certPEM}
}

// SignCosign creates a Cosign-compatible signature bundle for the given request.
func (cs *CosignSigner) SignCosign(ctx context.Context, req SignRequest) (*CosignBundle, error) {
	if req.ImageRef == "" {
		return nil, errors.New("imagesign/cosign: image_ref is required")
	}
	if req.Digest == "" {
		return nil, errors.New("imagesign/cosign: digest is required")
	}

	cosignPayload := CosignPayload{
		Critical: CosignCritical{
			Identity: CosignIdentity{
				DockerReference: req.ImageRef,
			},
			Image: CosignImage{
				DockerManifestDigest: req.Digest,
			},
			Type: "cosign container image signature",
		},
		Optional: req.Annotations,
	}

	// Add default annotations
	if cosignPayload.Optional == nil {
		cosignPayload.Optional = make(map[string]string)
	}
	cosignPayload.Optional["signed_at"] = time.Now().UTC().Format(time.RFC3339)
	if req.TenantID != "" {
		cosignPayload.Optional["tenant_id"] = req.TenantID
	}

	payloadJSON, err := json.Marshal(cosignPayload)
	if err != nil {
		return nil, fmt.Errorf("imagesign/cosign: marshal payload: %w", err)
	}

	payloadB64 := base64.StdEncoding.EncodeToString(payloadJSON)

	// Sign the base64-encoded payload (Cosign convention)
	hash := sha256.Sum256([]byte(payloadB64))

	var sigBytes []byte
	switch key := cs.key.(type) {
	case *ecdsa.PrivateKey:
		sigBytes, err = ecdsa.SignASN1(rand.Reader, key, hash[:])
		if err != nil {
			return nil, fmt.Errorf("imagesign/cosign: ecdsa sign: %w", err)
		}
	case *rsa.PrivateKey:
		sigBytes, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
		if err != nil {
			return nil, fmt.Errorf("imagesign/cosign: rsa-pss sign: %w", err)
		}
	default:
		sigBytes, err = cs.key.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("imagesign/cosign: sign: %w", err)
		}
	}

	bundle := &CosignBundle{
		Base64Signature: base64.StdEncoding.EncodeToString(sigBytes),
		Payload:         payloadB64,
		Cert:            cs.certPEM,
		Annotations:     req.Annotations,
	}

	return bundle, nil
}

// VerifyCosign verifies a Cosign bundle against a public key.
func VerifyCosign(ctx context.Context, bundle *CosignBundle, publicKey crypto.PublicKey) error {
	if bundle == nil {
		return errors.New("imagesign/cosign: nil bundle")
	}
	if bundle.Payload == "" {
		return errors.New("imagesign/cosign: empty payload")
	}
	if bundle.Base64Signature == "" {
		return errors.New("imagesign/cosign: empty signature")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(bundle.Base64Signature)
	if err != nil {
		return fmt.Errorf("imagesign/cosign: decode signature: %w", err)
	}

	hash := sha256.Sum256([]byte(bundle.Payload))

	switch pub := publicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, hash[:], sigBytes) {
			return errors.New("imagesign/cosign: ECDSA signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		err = rsa.VerifyPSS(pub, crypto.SHA256, hash[:], sigBytes, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
		if err != nil {
			return fmt.Errorf("imagesign/cosign: RSA-PSS verification failed: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("imagesign/cosign: unsupported public key type %T", publicKey)
	}
}
