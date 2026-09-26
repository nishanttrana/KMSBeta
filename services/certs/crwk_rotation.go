package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	pkgaudit "vecta-kms/pkg/audit"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
)

// CompleteCRWKRotation finishes a re-key of the certs root wrapping key (see
// softwareCRWKProvider.beginRotation): every CA signer DEK still wrapped by
// the retired CRWK is rewrapped under the new one, the internal PKI cache and
// its in-memory CAs are refreshed, and only then is the new sealed key
// installed and the retired key and previous passphrase file removed. Each
// step is idempotent, so a crash part-way resumes on the next start. The
// outcome is audited as audit.certs.crwk_rotated (docs/SECURITY/SECRET_ROTATION.md).
func (s *Service) CompleteCRWKRotation(ctx context.Context, emit route.Emitter, pki *bootstrapPKI) error {
	rot, ok := s.securityProvider.(crwkRotator)
	if !ok {
		return nil
	}
	from, to, reason, pending := rot.PendingRotation()
	if !pending {
		return nil
	}
	n, err := s.rewrapCRWKSigners(ctx, to)
	if err == nil && pki != nil {
		err = pki.reload(ctx)
	}
	if err == nil {
		err = rot.CompleteRotation()
	}
	evt := pkgaudit.Event{
		TenantID: "root", ActorID: "kms-certs", ActorType: "service",
		TargetType: "certs_root_wrapping_key", TargetID: to, Result: "success",
		Details: map[string]interface{}{
			"from_version": from, "to_version": to, "reason": reason, "ca_signers_rewrapped": n,
			"tenant_scope": "platform",
		},
	}
	if reason == "public_default_passphrase" {
		evt.Details["exposure"] = "the retired CRWK was sealed under a passphrase published in the repository; CA keys it wrapped should be treated as exposed if its sealed file was ever copied"
	}
	if err != nil {
		evt.Result, evt.ErrorMessage = "failure", err.Error()
		evt.Details["reason"] = "rewrap_failed"
		evt.Details["rotation_reason"] = reason
	}
	if emit != nil {
		_ = emit.Emit(ctx, "crwk_rotated", evt)
	}
	return err
}

// rewrapCRWKSigners rewraps each CA signer's DEK under the CRWK version to.
// The signer ciphertext and fingerprint are unchanged; only the envelope
// moves. Legacy (master-key) and HSM signers aren't CRWK-wrapped.
func (s *Service) rewrapCRWKSigners(ctx context.Context, to string) (int, error) {
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, tenantID := range tenants {
		cas, err := s.store.ListCAs(ctx, tenantID)
		if err != nil {
			return n, err
		}
		for _, ca := range cas {
			v := strings.TrimSpace(ca.SignerKeyVersion)
			if v == to || v == signerVersionHSM || strings.HasPrefix(strings.ToLower(v), "legacy") || len(ca.SignerCiphertext) == 0 {
				continue
			}
			dek, err := s.securityProvider.UnwrapDEK(ctx, ca.SignerWrappedDEK, ca.SignerWrappedDEKIV, v)
			if err != nil {
				return n, fmt.Errorf("unwrap signer of CA %s: %w", ca.ID, err)
			}
			wrapped, iv, version, err := s.securityProvider.WrapDEK(ctx, dek)
			pkgcrypto.Zeroize(dek)
			if err != nil {
				return n, fmt.Errorf("rewrap signer of CA %s: %w", ca.ID, err)
			}
			if version != to {
				return n, fmt.Errorf("rewrap signer of CA %s: wrapped under %s, want %s", ca.ID, version, to)
			}
			if err := s.store.UpdateCASignerEncryption(ctx, tenantID, ca.ID, EncryptedSigner{
				WrappedDEK: wrapped, WrappedDEKIV: iv, Ciphertext: ca.SignerCiphertext, DataIV: ca.SignerDataIV,
				KeyVersion: version, Fingerprint: ca.SignerFingerprint,
			}); err != nil {
				return n, fmt.Errorf("store rewrapped signer of CA %s: %w", ca.ID, err)
			}
			n++
		}
	}
	return n, nil
}

// reload replaces the cached root and Sub CA (and the cache file) with the
// database rows, so nothing still refers to a retired wrapping key.
func (b *bootstrapPKI) reload(ctx context.Context) error {
	root, err := b.svc.store.GetCA(ctx, b.tenant, b.root.ID)
	if err != nil {
		return fmt.Errorf("reload runtime root: %w", err)
	}
	sub, err := b.svc.store.GetCA(ctx, b.tenant, b.sub.ID)
	if err != nil {
		return fmt.Errorf("reload internal Sub CA: %w", err)
	}
	if root.CertPEM != b.root.CertPEM || sub.CertPEM != b.sub.CertPEM {
		return errors.New("reload internal PKI: the database CAs differ from the cache")
	}
	if err := savePKICache(b.cachePath, root, sub); err != nil {
		return fmt.Errorf("rewrite internal PKI cache: %w", err)
	}
	b.root, b.sub = root, sub
	return nil
}
