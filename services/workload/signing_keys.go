package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/mek"
	"vecta-kms/pkg/route"
)

// Each tenant's SPIFFE root CA private key and JWT-SVID signer private key
// are sealed together, one envelope per tenant, under the workload service
// master key from keycore (pkg/mek, docs/SECURITY/SERVICE_MASTER_KEYS.md).
// The sealed payload names its tenant, so an envelope copied onto another
// tenant's row doesn't open there. Earlier releases stored both keys as
// plaintext PEM; the primary seals those rows, records each tenant in the
// exposure register, and empties the plaintext columns.

const signingKeysItemType = "workload_signing_keys"

var errSigningKeyUnavailable = errors.New("workload signing keys unavailable: the workload service master key is not open")

type sealedSigningKeys struct {
	TenantID            string `json:"tenant_id"`
	CAKeyPEM            string `json:"ca_key_pem"`
	JWTSignerPrivatePEM string `json:"jwt_signer_private_pem"`
}

// sealSigningKeys seals a tenant's two private keys. Neither set: no envelope.
func sealSigningKeys(k *mek.Keyring, tenant, caKeyPEM, jwtPrivPEM string) (*pkgcrypto.EnvelopeCiphertext, error) {
	if caKeyPEM == "" && jwtPrivPEM == "" {
		return nil, nil
	}
	if k == nil {
		return nil, errSigningKeyUnavailable
	}
	raw, err := json.Marshal(sealedSigningKeys{TenantID: tenant, CAKeyPEM: caKeyPEM, JWTSignerPrivatePEM: jwtPrivPEM})
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(raw)
	return pkgcrypto.EncryptEnvelope(k.Current(), raw)
}

// openSigningKeys returns the CA key and JWT signer key sealed for tenant.
func openSigningKeys(k *mek.Keyring, tenant string, env *pkgcrypto.EnvelopeCiphertext) (string, string, error) {
	if k == nil {
		return "", "", errSigningKeyUnavailable
	}
	raw, err := pkgcrypto.DecryptEnvelope(k.Current(), env)
	if err != nil {
		return "", "", fmt.Errorf("workload signing keys do not open under the workload master key: %w", err)
	}
	defer pkgcrypto.Zeroize(raw)
	var sk sealedSigningKeys
	if err := json.Unmarshal(raw, &sk); err != nil {
		return "", "", err
	}
	if sk.TenantID != tenant {
		return "", "", errors.New("workload signing keys belong to a different tenant")
	}
	return sk.CAKeyPEM, sk.JWTSignerPrivatePEM, nil
}

// envelopeFromColumns reads the four signing_* columns; nil when unsealed.
func envelopeFromColumns(ct, dataIV, dek, dekIV []byte) *pkgcrypto.EnvelopeCiphertext {
	if len(dek) == 0 {
		return nil
	}
	return &pkgcrypto.EnvelopeCiphertext{Ciphertext: ct, DataIV: dataIV, WrappedDEK: dek, WrappedDEKIV: dekIV}
}

// SealPlaintextSigningKeys seals every row an earlier release stored in
// plaintext and empties its plaintext columns. Each tenant goes into the
// exposure register first: a database copy or backup made before this still
// holds the keys, so they count as exposed until rotated. Primary only (the
// table is replicated). Audited per tenant as mek_signing_keys_sealed, or
// mek_signing_keys_seal_refused when a row can't be sealed.
func (s *SQLStore) SealPlaintextSigningKeys(ctx context.Context, primary func(context.Context) bool, audit route.Emitter) (int, error) {
	if !primary(ctx) {
		return 0, nil
	}
	if s.keys == nil {
		return 0, errSigningKeyUnavailable
	}
	rows, err := s.listPlaintextSigningKeys(ctx)
	if err != nil {
		return 0, err
	}
	sealed, failed := 0, 0
	for _, r := range rows {
		err := s.keys.RecordExposure(ctx, r.TenantID, signingKeysItemType, r.TenantID, "plaintext_storage")
		var env *pkgcrypto.EnvelopeCiphertext
		if err == nil {
			env, err = sealSigningKeys(s.keys, r.TenantID, r.CAKeyPEM, r.JWTSignerPrivatePEM)
		}
		ok := false
		if err == nil {
			ok, err = s.replacePlaintextSigningKeys(ctx, r, env)
		}
		switch {
		case err != nil:
			failed++
			emitService(ctx, audit, "mek_signing_keys_seal_refused", r.TenantID, pkgaudit.Event{Result: "refused", ErrorMessage: err.Error()}, map[string]interface{}{
				"severity": "critical", "reason": "seal_failed", "item_type": signingKeysItemType,
			})
		case ok:
			sealed++
			emitService(ctx, audit, "mek_signing_keys_sealed", r.TenantID, pkgaudit.Event{}, map[string]interface{}{
				"severity": "warning", "item_type": signingKeysItemType,
				"sealed":   []string{"spiffe_root_ca_private_key", "jwt_svid_signer_private_key"},
				"exposure": "stored in plaintext by an earlier release; rotate the signing keys (POST /workload-identity/settings/rotate-signing-keys)",
			})
		}
	}
	if failed > 0 {
		return sealed, fmt.Errorf("%d tenant(s) still hold plaintext workload signing keys (see audit.workload.mek_signing_keys_seal_refused)", failed)
	}
	return sealed, nil
}

// sealPlaintextLoop seals plaintext rows every interval, which catches rows
// a restore brings back from an earlier release.
func (s *SQLStore) sealPlaintextLoop(ctx context.Context, primary func(context.Context) bool, audit route.Emitter, interval time.Duration, logf func(string, ...interface{})) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if n, err := s.SealPlaintextSigningKeys(ctx, primary, audit); err != nil {
			logf("workload signing keys: %v", err)
		} else if n > 0 {
			logf("workload signing keys: sealed %d plaintext tenant row(s); recorded in the exposure register", n)
		}
	}
}

func emitService(ctx context.Context, audit route.Emitter, action, tenant string, evt pkgaudit.Event, details map[string]interface{}) {
	if audit == nil {
		return
	}
	evt.TenantID, evt.ActorID, evt.ActorType = tenant, "kms-workload-identity", "service"
	evt.TargetType, evt.TargetID, evt.Details = signingKeysItemType, tenant, details
	if evt.Result == "" {
		evt.Result = "success"
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = audit.Emit(ctx, action, evt)
}
