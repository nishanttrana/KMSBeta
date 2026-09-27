package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// KeyReleaser seals a key to a recipient public key (keycore
// POST /keys/{id}/attested-release).
type KeyReleaser interface {
	AttestedRelease(ctx context.Context, tenantID, keyID string, req keycoreReleaseRequest) (SealedKeyRelease, error)
}

// SetKeyReleaser installs the keycore client used by ReleaseKey.
func (s *Service) SetKeyReleaser(r KeyReleaser) { s.releaser = r }

// recipientBinding checks that cryptographically verified evidence commits to
// the recipient key, and returns the key's binding value. AWS Nitro signs the
// enclave's key into the document (public_key); OIDC attestation tokens
// (Azure MAA, GCP Confidential Space) commit through their verified nonce,
// which must equal base64url(SHA-256(DER)). Unverified or generic evidence
// never binds.
func recipientBinding(in AttestedReleaseRequest, v attestationVerification) (string, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(in.RecipientPublicKey))
	if err != nil {
		return "", errors.New("recipient_public_key must be base64 DER")
	}
	if _, err := pkgcrypto.ParseRecipientPublicKey(der); err != nil {
		return "", err
	}
	binding := pkgcrypto.RecipientKeyBinding(der)
	if !v.CryptographicallyVerified {
		return binding, errors.New("the recipient key is not bound: the evidence was not cryptographically verified")
	}
	if strings.HasPrefix(normalizeProvider(in.Provider), "aws_nitro") {
		if len(v.RecipientKey) == 0 || !bytes.Equal(v.RecipientKey, der) {
			return binding, errors.New("the attestation document's public_key is not the recipient key")
		}
		return binding, nil
	}
	if strings.TrimSpace(v.Nonce) != binding {
		return binding, errors.New("the attestation nonce does not commit to the recipient key (want base64url(SHA-256(DER)))")
	}
	return binding, nil
}

// ReleaseKey evaluates the evidence and, on an allow whose evidence commits to
// the recipient key, has keycore release the key sealed to that key. The
// decision is recorded either way; audit.confidential.key_released or
// audit.confidential.key_release_refused says which.
func (s *Service) ReleaseKey(ctx context.Context, in AttestedReleaseRequest) (AttestedReleaseDecision, error) {
	if strings.TrimSpace(in.RecipientPublicKey) == "" {
		return AttestedReleaseDecision{}, newServiceError(http.StatusBadRequest, "bad_request", "recipient_public_key is required to release a key")
	}
	if in.DryRun {
		return AttestedReleaseDecision{}, newServiceError(http.StatusBadRequest, "bad_request", "dry_run is not allowed on release; use /confidential/evaluate")
	}
	result, record, evaluated, err := s.evaluate(ctx, in)
	if err != nil {
		return AttestedReleaseDecision{}, err
	}
	refusal := ""
	switch {
	case !result.Allowed:
		refusal = "attestation verdict is " + result.Decision
	case s.releaser == nil:
		refusal = "keycore is not configured for attested release"
	default:
		sealed, relErr := s.releaser.AttestedRelease(ctx, in.TenantID, in.KeyID, keycoreReleaseRequest{
			TenantID:           in.TenantID,
			RecipientPublicKey: strings.TrimSpace(in.RecipientPublicKey),
			ReleaseID:          result.ReleaseID,
			AttestationHash:    result.AttestationDocumentHash,
			Provider:           evaluated.Provider,
		})
		if relErr != nil {
			refusal = "keycore refused the release: " + relErr.Error()
		} else {
			result.Released, result.Release = true, &sealed
			record.Released = true
		}
	}
	if !result.Released {
		result.Reasons = uniqueStrings(append(result.Reasons, refusal))
		record.Reasons = result.Reasons
	}
	if err := s.store.InsertReleaseRecord(ctx, record); err != nil {
		return AttestedReleaseDecision{}, err
	}
	details := map[string]interface{}{
		"release_id":                result.ReleaseID,
		"key_id":                    in.KeyID,
		"provider":                  evaluated.Provider,
		"decision":                  result.Decision,
		"recipient_key_binding":     result.RecipientKeyBinding,
		"attestation_document_hash": result.AttestationDocumentHash,
		"workload_identity":         evaluated.WorkloadIdentity,
		"image_digest":              evaluated.ImageDigest,
		"measurement_hash":          result.MeasurementHash,
		"policy_version":            result.PolicyVersion,
	}
	if result.Released {
		details["key_version"] = result.Release.Version
		details["seal_algorithm"] = result.Release.SealAlgorithm
		details["severity"] = "warning"
		_ = s.publishAudit(ctx, "audit.confidential.key_released", in.TenantID, details)
		return result, nil
	}
	details["reason"] = refusal
	details["reasons"] = result.Reasons
	details["result"] = "refused"
	details["severity"] = "warning"
	_ = s.publishAudit(ctx, "audit.confidential.key_release_refused", in.TenantID, details)
	return result, nil
}
