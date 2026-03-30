package imagesign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// NotaryPayload describes the target being signed in Notary v2 / COSE Sign1 format.
type NotaryPayload struct {
	TargetName     string            `json:"targetName" cbor:"1,keyasint"`
	Digest         string            `json:"digest" cbor:"2,keyasint"`
	Size           int64             `json:"size" cbor:"3,keyasint"`
	CustomMetadata map[string]string `json:"custom,omitempty" cbor:"4,keyasint,omitempty"`
}

// NotarySignature is the result of a Notary v2-compatible signing operation,
// wrapping a COSE Sign1 envelope.
type NotarySignature struct {
	MediaType  string    `json:"mediaType"`
	Envelope   []byte    `json:"envelope"`   // COSE Sign1 raw bytes
	EnvelopeB64 string   `json:"envelopeB64"` // base64 of envelope for transport
	SignedAt   time.Time `json:"signedAt"`
}

// COSESign1 represents a simplified COSE_Sign1 structure: [protected, unprotected, payload, signature].
type COSESign1 struct {
	Protected   []byte `cbor:"1,keyasint"`
	Unprotected map[interface{}]interface{} `cbor:"2,keyasint"`
	Payload     []byte `cbor:"3,keyasint"`
	Signature   []byte `cbor:"4,keyasint"`
}

// coseProtectedHeader encodes the algorithm ID in the protected header.
type coseProtectedHeader struct {
	Algorithm int `cbor:"1,keyasint"` // -7 = ES256, -37 = PS256
}

const (
	coseAlgES256 = -7
	coseAlgPS256 = -37
)

// NotarySigner creates Notary v2 (COSE Sign1) signatures.
type NotarySigner struct {
	key crypto.Signer
}

// NewNotarySigner creates a NotarySigner wrapping the given key.
func NewNotarySigner(key crypto.Signer) *NotarySigner {
	return &NotarySigner{key: key}
}

// SignNotary creates a COSE Sign1 envelope for the given image signing request.
func (ns *NotarySigner) SignNotary(ctx context.Context, req SignRequest) (*NotarySignature, error) {
	if req.ImageRef == "" {
		return nil, errors.New("imagesign/notary: image_ref is required")
	}
	if req.Digest == "" {
		return nil, errors.New("imagesign/notary: digest is required")
	}

	// Determine algorithm from key type
	var algID int
	switch ns.key.Public().(type) {
	case *ecdsa.PublicKey:
		algID = coseAlgES256
	case *rsa.PublicKey:
		algID = coseAlgPS256
	default:
		return nil, fmt.Errorf("imagesign/notary: unsupported key type %T", ns.key.Public())
	}

	// Encode protected header
	protectedHeader := coseProtectedHeader{Algorithm: algID}
	protectedBytes, err := cbor.Marshal(protectedHeader)
	if err != nil {
		return nil, fmt.Errorf("imagesign/notary: marshal protected header: %w", err)
	}

	// Encode payload
	notaryPayload := NotaryPayload{
		TargetName:     req.ImageRef,
		Digest:         req.Digest,
		Size:           0, // Size not available in SignRequest
		CustomMetadata: req.Annotations,
	}
	payloadBytes, err := cbor.Marshal(notaryPayload)
	if err != nil {
		return nil, fmt.Errorf("imagesign/notary: marshal payload: %w", err)
	}

	// Build Sig_structure for COSE Sign1:
	// Sig_structure = ["Signature1", protectedBytes, externalAAD, payload]
	sigStructure := []interface{}{
		"Signature1",
		protectedBytes,
		[]byte{}, // external_aad
		payloadBytes,
	}
	sigStructBytes, err := cbor.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("imagesign/notary: marshal sig structure: %w", err)
	}

	// Hash and sign
	hash := sha256.Sum256(sigStructBytes)
	var sigBytes []byte

	switch key := ns.key.(type) {
	case *ecdsa.PrivateKey:
		sigBytes, err = ecdsa.SignASN1(rand.Reader, key, hash[:])
		if err != nil {
			return nil, fmt.Errorf("imagesign/notary: ecdsa sign: %w", err)
		}
	case *rsa.PrivateKey:
		sigBytes, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
		if err != nil {
			return nil, fmt.Errorf("imagesign/notary: rsa-pss sign: %w", err)
		}
	default:
		sigBytes, err = ns.key.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("imagesign/notary: sign: %w", err)
		}
	}

	// Build COSE_Sign1 = [protected, unprotected, payload, signature]
	// Using cbor Tag 18 for COSE_Sign1
	envelope := []interface{}{
		protectedBytes,
		map[interface{}]interface{}{},
		payloadBytes,
		sigBytes,
	}
	envelopeBytes, err := cbor.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("imagesign/notary: marshal envelope: %w", err)
	}

	return &NotarySignature{
		MediaType:   "application/cose",
		Envelope:    envelopeBytes,
		EnvelopeB64: base64.StdEncoding.EncodeToString(envelopeBytes),
		SignedAt:    time.Now().UTC(),
	}, nil
}

// VerifyNotary verifies a COSE Sign1 envelope against a public key.
func VerifyNotary(ctx context.Context, envelopeBytes []byte, publicKey crypto.PublicKey) error {
	var envelope []cbor.RawMessage
	if err := cbor.Unmarshal(envelopeBytes, &envelope); err != nil {
		return fmt.Errorf("imagesign/notary: unmarshal envelope: %w", err)
	}
	if len(envelope) != 4 {
		return errors.New("imagesign/notary: invalid COSE_Sign1 structure")
	}

	var protectedBytes []byte
	if err := cbor.Unmarshal(envelope[0], &protectedBytes); err != nil {
		return fmt.Errorf("imagesign/notary: unmarshal protected: %w", err)
	}

	var payloadBytes []byte
	if err := cbor.Unmarshal(envelope[2], &payloadBytes); err != nil {
		return fmt.Errorf("imagesign/notary: unmarshal payload: %w", err)
	}

	var sigBytes []byte
	if err := cbor.Unmarshal(envelope[3], &sigBytes); err != nil {
		return fmt.Errorf("imagesign/notary: unmarshal signature: %w", err)
	}

	// Rebuild Sig_structure
	sigStructure := []interface{}{
		"Signature1",
		protectedBytes,
		[]byte{},
		payloadBytes,
	}
	sigStructBytes, err := cbor.Marshal(sigStructure)
	if err != nil {
		return fmt.Errorf("imagesign/notary: marshal sig structure: %w", err)
	}

	hash := sha256.Sum256(sigStructBytes)

	switch pub := publicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, hash[:], sigBytes) {
			return errors.New("imagesign/notary: ECDSA verification failed")
		}
		return nil
	case *rsa.PublicKey:
		err = rsa.VerifyPSS(pub, crypto.SHA256, hash[:], sigBytes, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
		if err != nil {
			return fmt.Errorf("imagesign/notary: RSA-PSS verification failed: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("imagesign/notary: unsupported public key type %T", publicKey)
	}
}
