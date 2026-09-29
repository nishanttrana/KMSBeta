package main

import (
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// An X.509-SVID certificate chain is public: any peer that ever saw it in a
// TLS handshake has it. So a chain alone never buys a token. The workload
// also signs, with the SVID's private key, a statement naming the tenant, the
// leaf certificate and the time, and each signature is accepted once.

// X509SVIDProof is the possession proof sent with x509_svid_chain_pem.
type X509SVIDProof struct {
	// SignedAt is the RFC 3339 UTC time the workload signed at.
	SignedAt string `json:"signed_at"`
	// Signature is base64 over X509ProofMessage: RSA PKCS#1 v1.5 or PSS with
	// SHA-256, ECDSA with SHA-256 (ASN.1), or Ed25519.
	Signature string `json:"signature"`
}

// proofWindow bounds how old, or how far ahead, a proof's signed_at may be.
const proofWindow = 2 * time.Minute

// X509ProofMessage is the exact byte string a workload signs.
func X509ProofMessage(tenantID string, leaf *x509.Certificate, signedAt string) []byte {
	return []byte("vecta-kms/workload-token-exchange/v1\n" +
		"tenant=" + tenantID + "\n" +
		"leaf-sha256=" + sha256Hex(string(leaf.Raw)) + "\n" +
		"signed-at=" + signedAt)
}

// proofCache remembers accepted signatures until they fall out of the
// window, so a captured proof can't be replayed on this node.
type proofCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newProofCache() *proofCache { return &proofCache{seen: map[string]time.Time{}} }

func (p *proofCache) verify(tenantID string, leaf *x509.Certificate, proof *X509SVIDProof, now time.Time) error {
	if proof == nil || strings.TrimSpace(proof.Signature) == "" || strings.TrimSpace(proof.SignedAt) == "" {
		return newServiceError(http.StatusUnauthorized, "svid_proof_required", "x509_svid_proof (signed_at, signature) is required with an X.509-SVID")
	}
	signedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(proof.SignedAt))
	if err != nil {
		return newServiceError(http.StatusUnauthorized, "svid_proof_invalid", "x509_svid_proof.signed_at must be RFC 3339")
	}
	if d := now.Sub(signedAt); d > proofWindow || d < -proofWindow {
		return newServiceError(http.StatusUnauthorized, "svid_proof_expired", "x509_svid_proof.signed_at is outside the accepted window")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(proof.Signature))
	if err != nil || !pkgcrypto.VerifySignatureAny(leaf.PublicKey, X509ProofMessage(tenantID, leaf, strings.TrimSpace(proof.SignedAt)), sig) {
		return newServiceError(http.StatusUnauthorized, "svid_proof_invalid", "x509_svid_proof signature does not verify with the SVID's key")
	}
	id := sha256Hex(string(sig))
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, until := range p.seen {
		if now.After(until) {
			delete(p.seen, k)
		}
	}
	if _, used := p.seen[id]; used {
		return newServiceError(http.StatusUnauthorized, "svid_proof_replayed", "x509_svid_proof was already used")
	}
	p.seen[id] = signedAt.Add(proofWindow)
	return nil
}
