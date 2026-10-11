package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/mek"
)

// Identity provider secrets (the LDAP and Active Directory bind password,
// the OIDC and Entra client secret, the SAML certificate) are sealed as one
// envelope per (tenant, provider) under the auth service master key from
// keycore (pkg/mek, docs/SECURITY/SERVICE_MASTER_KEYS.md). Until 8.2.0-beta
// they were plaintext JSON in auth_identity_provider_configs.
//
// They stay in auth and not in the credential store (compliance): signing a
// user in can't depend on a service that itself needs auth to be up
// (docs/DECISIONS.md).
//
// Keycore verifies tokens against auth, so auth can't wait for its key
// before it serves. The key opens in the background. Until it does, local
// sign-in, tokens and every provider without a stored secret work as
// before; reading or saving a provider's secrets fails with
// errIDPKeyUnavailable (503), so directory and SSO sign-in fail closed
// rather than run without the secret.

const idpSecretsItemType = "identity_provider_secrets"

var errIDPKeyUnavailable = errors.New("identity provider secrets are unavailable: the auth service master key has not been opened from keycore")

// sealedIDPSecrets is what the envelope holds. It names its row, so an
// envelope copied onto another provider or tenant does not open there.
type sealedIDPSecrets struct {
	TenantID string            `json:"tenant_id"`
	Provider string            `json:"provider"`
	Secrets  map[string]string `json:"secrets"`
}

// idpVault holds the auth master key once it is open.
type idpVault struct {
	mu  sync.RWMutex
	key []byte
	err error // why the key isn't open (nil while still trying)
}

func (v *idpVault) set(key []byte) {
	v.mu.Lock()
	v.key, v.err = key, nil
	v.mu.Unlock()
}

func (v *idpVault) fail(err error) {
	v.mu.Lock()
	v.err = err
	v.mu.Unlock()
}

func (v *idpVault) current() ([]byte, error) {
	if v == nil {
		return nil, errIDPKeyUnavailable
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.key == nil {
		if v.err != nil {
			return nil, fmt.Errorf("%w: %v", errIDPKeyUnavailable, v.err)
		}
		return nil, errIDPKeyUnavailable
	}
	return v.key, nil
}

// idpSecretValues returns the secrets that have a value, as strings.
func idpSecretValues(secrets map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range secrets {
		if s := strings.TrimSpace(anyString(v)); s != "" {
			out[k] = s
		}
	}
	return out
}

// seal returns what is stored for cfg's secrets: their names (as JSON with
// empty values) and the envelope, nil when there is nothing to protect.
func (v *idpVault) seal(cfg IdentityProviderConfig) ([]byte, *pkgcrypto.EnvelopeCiphertext, error) {
	values := idpSecretValues(cfg.Secrets)
	names := make(map[string]string, len(values))
	for k := range values {
		names[k] = ""
	}
	namesJSON, err := json.Marshal(names)
	if err != nil {
		return nil, nil, err
	}
	if len(values) == 0 {
		return namesJSON, nil, nil
	}
	key, err := v.current()
	if err != nil {
		return nil, nil, err
	}
	raw, err := json.Marshal(sealedIDPSecrets{TenantID: cfg.TenantID, Provider: cfg.Provider, Secrets: values})
	if err != nil {
		return nil, nil, err
	}
	defer pkgcrypto.Zeroize(raw)
	env, err := pkgcrypto.EncryptEnvelope(key, raw)
	if err != nil {
		return nil, nil, err
	}
	return namesJSON, env, nil
}

// open returns the secrets env holds for (tenantID, provider).
func (v *idpVault) open(tenantID, provider string, env *pkgcrypto.EnvelopeCiphertext) (map[string]any, error) {
	key, err := v.current()
	if err != nil {
		return nil, err
	}
	raw, err := pkgcrypto.DecryptEnvelope(key, env)
	if err != nil {
		return nil, fmt.Errorf("identity provider secrets do not open under the auth master key: %w", err)
	}
	defer pkgcrypto.Zeroize(raw)
	var s sealedIDPSecrets
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s.TenantID != tenantID || s.Provider != provider {
		return nil, errors.New("identity provider secrets belong to a different provider")
	}
	out := make(map[string]any, len(s.Secrets))
	for k, val := range s.Secrets {
		out[k] = val
	}
	return out, nil
}

// openIDPKeyring opens the auth keyring in the background and keeps trying
// while keycore is unreachable. A key that doesn't match the stored data
// stops it: secrets stay unavailable (fail closed) and mek audits the
// refusal, but auth keeps serving.
func openIDPKeyring(ctx context.Context, vault *idpVault, open func(context.Context) (*mek.Keyring, error), onOpen func(*mek.Keyring), retry time.Duration, logf func(string, ...interface{})) {
	for {
		k, err := open(ctx)
		if err == nil {
			vault.set(k.Current())
			logf("identity provider secrets: master key open (keycore key %s v%d)", k.KeyID(), k.Version())
			if onOpen != nil {
				onOpen(k)
			}
			return
		}
		vault.fail(err)
		if errors.Is(err, mek.ErrMismatch) || ctx.Err() != nil {
			logf("identity provider secrets unavailable: %v", err)
			return
		}
		logf("identity provider secrets: master key not open yet, retrying in %s: %v", retry, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
	}
}

// exposureRecorder is the part of the keyring the migration uses.
type exposureRecorder interface {
	RecordExposure(ctx context.Context, tenant, itemType, itemID, source string) error
}

// sealPlaintextIDPSecrets seals rows an earlier release stored in plaintext
// and records each in the exposure register: a database copy made before
// this still holds the secret, so it counts as exposed until it is changed
// at the identity provider. Primary only (the table is replicated).
func sealPlaintextIDPSecrets(ctx context.Context, store *SQLStore, reg exposureRecorder, primary func(context.Context) bool, audit mek.Emitter) (int, error) {
	if !primary(ctx) {
		return 0, nil
	}
	rows, err := store.listPlaintextIDPSecrets(ctx)
	if err != nil {
		return 0, err
	}
	sealed := map[string][]string{}
	var failed []string
	for _, cfg := range rows {
		id := cfg.TenantID + "/" + cfg.Provider
		// Exposure first: once sealed, the row no longer shows it was plaintext.
		if err := reg.RecordExposure(ctx, cfg.TenantID, idpSecretsItemType, cfg.Provider, "plaintext_storage"); err != nil {
			failed = append(failed, id)
			continue
		}
		ok, err := store.sealPlaintextIDPSecrets(ctx, cfg)
		if err != nil {
			failed = append(failed, id)
			continue
		}
		if ok {
			sealed[cfg.TenantID] = append(sealed[cfg.TenantID], cfg.Provider)
		}
	}
	tenants := make([]string, 0, len(sealed))
	for t := range sealed {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)
	total := 0
	emit := func(action string, ev pkgaudit.Event) {
		if audit != nil {
			ev.Service, ev.ActorID, ev.ActorType, ev.TargetType = "auth", "auth-identity-providers", "service", "identity_provider"
			_ = audit.Emit(ctx, action, ev)
		}
	}
	for _, t := range tenants {
		total += len(sealed[t])
		emit("identity_provider_secrets_sealed", pkgaudit.Event{TenantID: t, Result: "success", Details: map[string]interface{}{
			"severity": "warning", "count": len(sealed[t]), "providers": sealed[t],
			"exposure": "stored in plaintext by an earlier release; change the bind password or client secret at the identity provider",
		}})
	}
	if len(failed) > 0 {
		emit("identity_provider_secrets_seal_refused", pkgaudit.Event{TenantID: "root", Result: "refused", Details: map[string]interface{}{
			"severity": "critical", "reason": "seal_failed", "providers": failed,
		}})
		return total, fmt.Errorf("%d identity provider(s) still hold plaintext secrets", len(failed))
	}
	return total, nil
}

// sealPlaintextIDPLoop seals plaintext rows now and every interval, which
// catches rows a restore brings back from an earlier release.
func sealPlaintextIDPLoop(ctx context.Context, store *SQLStore, reg exposureRecorder, primary func(context.Context) bool, audit mek.Emitter, interval time.Duration, logf func(string, ...interface{})) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := sealPlaintextIDPSecrets(ctx, store, reg, primary, audit); err != nil {
			logf("identity provider secrets: %v", err)
		} else if n > 0 {
			logf("identity provider secrets: SECURITY sealed %d provider(s) an earlier release stored in plaintext; they are in the exposure register", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
