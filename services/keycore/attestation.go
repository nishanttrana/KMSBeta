package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"time"

	"vecta-kms/pkg/crypto"
)

// Key attestation: keycore produces a signed, independently verifiable
// statement about a key — its identity, properties, and a live integrity
// check — so a relying party can prove the key was generated and held under
// this KMS without trusting the dashboard. The statement is signed with an
// ECDSA P-256 attestation key; the matching public key is published at
// /attestation/public-key for offline verification.

// AttestationStatement is the canonical, signed payload. Field order is fixed
// (it is marshalled deterministically) so the signature is reproducible.
type AttestationStatement struct {
	Issuer           string    `json:"issuer"`
	TenantID         string    `json:"tenant_id"`
	KeyID            string    `json:"key_id"`
	Name             string    `json:"name"`
	Algorithm        string    `json:"algorithm"`
	KeyType          string    `json:"key_type"`
	Purpose          string    `json:"purpose"`
	Status           string    `json:"status"`
	Version          int       `json:"version"`
	Exportable       bool      `json:"exportable"`
	KCV              string    `json:"kcv,omitempty"`
	KCVAlgorithm     string    `json:"kcv_algorithm,omitempty"`
	IntegrityVerified bool     `json:"integrity_verified"`
	IntegrityDetail  string    `json:"integrity_detail"`
	AttestedAt       time.Time `json:"attested_at"`
	Nonce            string    `json:"nonce"`
}

type KeyAttestation struct {
	Statement            AttestationStatement `json:"statement"`
	StatementB64         string               `json:"statement_b64"`         // canonical bytes that were signed
	Signature            string               `json:"signature_b64"`
	SigningAlgorithm     string               `json:"signing_algorithm"`
	PublicKeyFingerprint string               `json:"public_key_fingerprint"`
}

// attestationKeyPair returns the ECDSA P-256 signing key, loading it once from
// KEYCORE_ATTESTATION_PRIVATE_KEY_PEM/_B64 if provided (stable across
// restarts) or generating an ephemeral key otherwise. The public key is always
// retrievable, so attestations remain verifiable for the key's lifetime.
func (s *Service) attestationKeyPair() (*crypto.KeyPair, error) {
	s.attestMu.Lock()
	defer s.attestMu.Unlock()
	if s.attestKP != nil {
		return s.attestKP, nil
	}
	if pemStr := firstNonEmpty(os.Getenv("KEYCORE_ATTESTATION_PRIVATE_KEY_PEM"), decodeB64Env("KEYCORE_ATTESTATION_PRIVATE_KEY_B64")); pemStr != "" {
		kp, err := crypto.ParsePrivateKeyPEM([]byte(pemStr))
		if err != nil {
			return nil, err
		}
		s.attestKP = kp
		return kp, nil
	}
	kp, err := crypto.GenerateKeyPair(crypto.AlgECDSAP256)
	if err != nil {
		return nil, err
	}
	log.Printf("attestation: no KEYCORE_ATTESTATION_PRIVATE_KEY configured; generated an ephemeral key (set the env var for a stable attestation identity across restarts)")
	s.attestKP = kp
	return kp, nil
}

func decodeB64Env(name string) string {
	v := os.Getenv(name)
	if v == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return ""
	}
	return string(raw)
}

func (s *Service) attestationPublicKeyPEM() (string, string, error) {
	kp, err := s.attestationKeyPair()
	if err != nil {
		return "", "", err
	}
	pemBytes, err := crypto.MarshalPublicKeyPEM(kp.Public)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(pemBytes)
	return string(pemBytes), hex.EncodeToString(sum[:]), nil
}

// AttestKey builds and signs an attestation for the key's current version.
func (s *Service) AttestKey(ctx context.Context, tenantID, keyID string) (KeyAttestation, error) {
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return KeyAttestation{}, err
	}
	integrity, err := s.VerifyKeyIntegrity(ctx, tenantID, keyID)
	if err != nil {
		return KeyAttestation{}, err
	}
	kp, err := s.attestationKeyPair()
	if err != nil {
		return KeyAttestation{}, err
	}

	nonce := make([]byte, 16)
	_, _ = crypto.Reader.Read(nonce)
	stmt := AttestationStatement{
		Issuer:            "vecta-keycore",
		TenantID:          tenantID,
		KeyID:             key.ID,
		Name:              key.Name,
		Algorithm:         key.Algorithm,
		KeyType:           key.KeyType,
		Purpose:           key.Purpose,
		Status:            key.Status,
		Version:           key.CurrentVersion,
		Exportable:        key.ExportAllowed,
		KCV:               hex.EncodeToString(key.KCV),
		KCVAlgorithm:      key.KCVAlgorithm,
		IntegrityVerified: integrity.Verified,
		IntegrityDetail:   integrity.Detail,
		AttestedAt:        time.Now().UTC(),
		Nonce:             hex.EncodeToString(nonce),
	}
	canonical, err := json.Marshal(stmt)
	if err != nil {
		return KeyAttestation{}, err
	}
	sig, err := crypto.Sign(kp, canonical)
	if err != nil {
		return KeyAttestation{}, err
	}
	_, fp, err := s.attestationPublicKeyPEM()
	if err != nil {
		return KeyAttestation{}, err
	}
	_ = s.publishAudit(ctx, "audit.key.attested", tenantID, map[string]any{
		"key_id": key.ID, "version": key.CurrentVersion, "integrity_verified": integrity.Verified,
	})
	return KeyAttestation{
		Statement:            stmt,
		StatementB64:         base64.StdEncoding.EncodeToString(canonical),
		Signature:            base64.StdEncoding.EncodeToString(sig),
		SigningAlgorithm:     kp.Algorithm,
		PublicKeyFingerprint: fp,
	}, nil
}
