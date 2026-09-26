package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/servicetoken"
)

// CA keys in the tenant's HSM (docs/SECURITY/HSM_INTEGRATION.md). A CA
// created with key_backend "hsm" gets an HSM-resident ECDSA key in keycore:
// generated in the HSM, never leaving it. Certificates, CRLs and OCSP
// responses are signed by that key, certs → keycore → HSM. certs stores no
// private key for it (signer_kek_version "hsm").
//
// HSM CA keys are ECDSA P-256/P-384. The HSM signs RSA only with PSS, and
// OCSP responses (x/crypto/ocsp) can't be RSA-PSS signed.

const signerVersionHSM = "hsm"

// HSMKeyStore is keycore's HSM key API as certs uses it.
type HSMKeyStore interface {
	CreateHSMSigningKey(ctx context.Context, tenantID, algorithm, name string) (keyID string, publicDER []byte, err error)
	SignDigest(ctx context.Context, tenantID, keyID, hash string, digest []byte) ([]byte, error)
}

var errHSMCAAlgorithm = errors.New("HSM CA keys are ECDSA P-256 or P-384 (the HSM signs RSA only with PSS, which OCSP responses can't carry)")

// hsmCAAlgorithm maps a CA algorithm to its HSM form, or "".
func hsmCAAlgorithm(alg string) string {
	if a := hsm.NormalizeAlgorithm(alg); strings.HasPrefix(a, "ECDSA-") {
		return a
	}
	return ""
}

// hsmSigner is a crypto.Signer whose private key is in the tenant's HSM.
type hsmSigner struct {
	keys     HSMKeyStore
	tenantID string
	keyID    string
	pub      crypto.PublicKey
}

func (h *hsmSigner) Public() crypto.PublicKey { return h.pub }

// Sign signs digest in the HSM. The signature is ASN.1 DER ECDSA, as x509
// and ocsp expect.
func (h *hsmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	name := map[crypto.Hash]string{crypto.SHA256: "SHA-256", crypto.SHA384: "SHA-384", crypto.SHA512: "SHA-512"}[opts.HashFunc()]
	if name == "" {
		return nil, fmt.Errorf("HSM CA keys sign SHA-256/384/512 digests, not %v", opts.HashFunc())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return h.keys.SignDigest(ctx, h.tenantID, h.keyID, name, digest)
}

// newHSMCAKey creates a CA key in the tenant's HSM through keycore.
func (s *Service) newHSMCAKey(ctx context.Context, tenantID, algorithm, name string) (*hsmSigner, error) {
	alg := hsmCAAlgorithm(algorithm)
	if alg == "" {
		return nil, errHSMCAAlgorithm
	}
	keys, ok := s.keycore.(HSMKeyStore)
	if !ok {
		return nil, errors.New("HSM CA keys need keycore, which is not configured")
	}
	keyID, pubDER, err := keys.CreateHSMSigningKey(ctx, tenantID, alg, name)
	if err != nil {
		return nil, fmt.Errorf("HSM CA key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, fmt.Errorf("HSM CA key public half: %w", err)
	}
	return &hsmSigner{keys: keys, tenantID: tenantID, keyID: keyID, pub: pub}, nil
}

// hsmCASigner is the signer of an existing HSM CA; its public key is the
// one in the CA certificate.
func (s *Service) hsmCASigner(ca CA) (crypto.Signer, error) {
	keys, ok := s.keycore.(HSMKeyStore)
	if !ok {
		return nil, errors.New("HSM CA keys need keycore, which is not configured")
	}
	cert, err := parseCertificatePEM(ca.CertPEM)
	if err != nil {
		return nil, err
	}
	return &hsmSigner{keys: keys, tenantID: ca.TenantID, keyID: ca.KeyRef, pub: cert.PublicKey}, nil
}

// CreateHSMSigningKey creates an HSM-resident signing key in keycore and
// returns its public half.
func (h *HTTPKeyCoreSigner) CreateHSMSigningKey(ctx context.Context, tenantID, algorithm, name string) (string, []byte, error) {
	var created struct {
		KeyID string `json:"key_id"`
	}
	if err := h.post(ctx, tenantID, "/keys", map[string]interface{}{
		"tenant_id": tenantID, "name": name, "algorithm": algorithm, "key_type": "asymmetric-private",
		"purpose": "sign", "owner": "kms-certs", "iv_mode": "internal", "created_by": "kms-certs", "hsm": true,
	}, &created); err != nil {
		return "", nil, err
	}
	var exported struct {
		PublicKey string `json:"public_key_plaintext"`
	}
	if err := h.post(ctx, tenantID, "/keys/"+created.KeyID+"/export", map[string]interface{}{"export_mode": "public-plaintext"}, &exported); err != nil {
		return "", nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(exported.PublicKey)
	if err != nil || len(pub) == 0 {
		return "", nil, errors.New("keycore returned no public key for the HSM CA key")
	}
	return created.KeyID, pub, nil
}

// SignDigest has keycore sign a digest with an HSM key.
func (h *HTTPKeyCoreSigner) SignDigest(ctx context.Context, tenantID, keyID, hash string, digest []byte) ([]byte, error) {
	var out struct {
		Signature string `json:"signature"`
	}
	if err := h.post(ctx, tenantID, "/keys/"+keyID+"/sign", map[string]interface{}{
		"tenant_id": tenantID, "data": base64.StdEncoding.EncodeToString(digest), "algorithm": hash, "prehashed": true,
	}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Signature)
}

func (h *HTTPKeyCoreSigner) post(ctx context.Context, tenantID, path string, body, out interface{}) error {
	if h == nil || h.baseURL == "" {
		return errors.New("keycore base url is empty")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+path+"?tenant_id="+tenantID, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	servicetoken.Authorize(ctx, req)
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= http.StatusBadRequest {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(payload, &e)
		return fmt.Errorf("keycore %s: %s (%s)", path, strings.TrimSpace(e.Error.Message), e.Error.Code)
	}
	return json.Unmarshal(payload, out)
}
