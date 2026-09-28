package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/mek"
)

// Webhook credentials (the signing secret and custom header values such as
// Splunk HEC tokens or Datadog API keys) are sealed as one envelope per
// webhook under the audit service master key from keycore (pkg/mek,
// docs/SECURITY/SERVICE_MASTER_KEYS.md). The sealed payload names its tenant
// and webhook, so a blob copied onto another row does not open there.
//
// The audit service is the platform's audit sink, so it never refuses to
// start over its master key: the key opens in the background, and until it
// does (or if keycore returns a key that doesn't match the stored data)
// writing credentials returns 503 and deliveries that need them fail with
// the reason. Webhooks without credentials are unaffected.

const webhookCredsItemType = "webhook_credentials"

var errCredsKeyUnavailable = errors.New("webhook credentials key unavailable: the audit service master key has not been opened from keycore")

type sealedCreds struct {
	TenantID  string            `json:"tenant_id"`
	WebhookID string            `json:"webhook_id"`
	Secret    string            `json:"secret,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// credVault holds the audit service keyring once it is open.
type credVault struct {
	mu      sync.RWMutex
	keyring *mek.Keyring
	err     error // why the key isn't open (nil while still trying)
}

func (v *credVault) set(k *mek.Keyring) {
	v.mu.Lock()
	v.keyring, v.err = k, nil
	v.mu.Unlock()
}

func (v *credVault) fail(err error) {
	v.mu.Lock()
	v.err = err
	v.mu.Unlock()
}

func (v *credVault) current() (*mek.Keyring, error) {
	if v == nil {
		return nil, errCredsKeyUnavailable
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.keyring == nil {
		if v.err != nil {
			return nil, fmt.Errorf("%w: %v", errCredsKeyUnavailable, v.err)
		}
		return nil, errCredsKeyUnavailable
	}
	return v.keyring, nil
}

// hasCredentials reports whether a webhook carries anything secret.
func hasCredentials(secret string, headers map[string]string) bool {
	if secret != "" {
		return true
	}
	for _, v := range headers {
		if v != "" {
			return true
		}
	}
	return false
}

// headerNames returns headers with every value blanked: what is stored in
// plaintext and returned by the API.
func headerNames(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k := range h {
		out[k] = ""
	}
	return out
}

// Seal puts wh's secret and header values into wh.Sealed and strips the
// plaintext. A webhook with no credentials gets no envelope.
func (v *credVault) Seal(wh *Webhook) error {
	wh.HasSecret = wh.Secret != ""
	if !hasCredentials(wh.Secret, wh.Headers) {
		wh.Sealed, wh.Secret, wh.Headers = nil, "", headerNames(wh.Headers)
		return nil
	}
	k, err := v.current()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(sealedCreds{TenantID: wh.TenantID, WebhookID: wh.ID, Secret: wh.Secret, Headers: wh.Headers})
	if err != nil {
		return err
	}
	defer pkgcrypto.Zeroize(raw)
	env, err := pkgcrypto.EncryptEnvelope(k.Current(), raw)
	if err != nil {
		return err
	}
	wh.Sealed, wh.Secret, wh.Headers = env, "", headerNames(wh.Headers)
	return nil
}

// Open returns wh with its secret and header values in memory. A row an
// earlier release stored in plaintext (not yet sealed) is returned as is.
func (v *credVault) Open(wh Webhook) (Webhook, error) {
	if wh.Sealed == nil {
		return wh, nil
	}
	k, err := v.current()
	if err != nil {
		return wh, err
	}
	raw, err := pkgcrypto.DecryptEnvelope(k.Current(), wh.Sealed)
	if err != nil {
		return wh, fmt.Errorf("webhook credentials do not open under the audit master key: %w", err)
	}
	defer pkgcrypto.Zeroize(raw)
	var sc sealedCreds
	if err := json.Unmarshal(raw, &sc); err != nil {
		return wh, err
	}
	if sc.TenantID != wh.TenantID || sc.WebhookID != wh.ID {
		return wh, errors.New("webhook credentials belong to a different webhook")
	}
	out := wh
	out.Secret = sc.Secret
	out.Headers = make(map[string]string, len(wh.Headers))
	for name := range wh.Headers {
		out.Headers[name] = sc.Headers[name]
	}
	return out, nil
}

// openCredsKeyring opens the audit service keyring in the background and
// keeps retrying while keycore is unreachable. A key that doesn't match the
// stored data stops it: credentials stay unavailable (fail closed) and
// mek_check_refused is audited, but the audit pipeline keeps running.
func (s *Service) openCredsKeyring(ctx context.Context, open func(context.Context) (*mek.Keyring, error), onOpen func(*mek.Keyring), logf func(string, ...interface{})) {
	for {
		k, err := open(ctx)
		if err == nil {
			s.creds.set(k)
			logf("webhook credentials: master key open (keycore key %s v%d)", k.KeyID(), k.Version())
			if onOpen != nil {
				onOpen(k)
			}
			return
		}
		s.creds.fail(err)
		if errors.Is(err, mek.ErrMismatch) || ctx.Err() != nil {
			logf("webhook credentials unavailable: %v", err)
			return
		}
		logf("webhook credentials: master key not open yet, retrying in 1m: %v", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

// sealLegacyWebhooks seals rows an earlier release stored in plaintext and
// records each in the exposure register: a database copy made before this
// still holds the plaintext, so the credentials count as exposed until they
// are rotated. Primary only (the webhooks table is replicated).
func (s *Service) sealLegacyWebhooks(ctx context.Context, k *mek.Keyring, primary func(context.Context) bool, audit func(context.Context, AuditEvent)) (int, error) {
	if !primary(ctx) {
		return 0, nil
	}
	rows, err := s.store.ListPlaintextWebhooks(ctx)
	if err != nil {
		return 0, err
	}
	sealed := map[string][]string{}
	var failed []string
	for _, wh := range rows {
		if !hasCredentials(wh.Secret, wh.Headers) {
			continue
		}
		// Exposure first: once sealed, the row no longer shows it was plaintext.
		if err := k.RecordExposure(ctx, wh.TenantID, webhookCredsItemType, wh.ID, "plaintext_storage"); err != nil {
			failed = append(failed, wh.ID)
			continue
		}
		next := wh
		if err := s.creds.Seal(&next); err != nil {
			failed = append(failed, wh.ID)
			continue
		}
		ok, err := s.store.SealPlaintextWebhook(ctx, next)
		if err != nil {
			failed = append(failed, wh.ID)
			continue
		}
		if ok {
			sealed[wh.TenantID] = append(sealed[wh.TenantID], wh.ID)
		}
	}
	tenants := make([]string, 0, len(sealed))
	for t := range sealed {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)
	total := 0
	for _, t := range tenants {
		ids := sealed[t]
		total += len(ids)
		if audit != nil {
			audit(ctx, AuditEvent{
				TenantID: t, Service: "audit", Action: webhookSelfPrefix + "credentials_sealed",
				ActorID: "audit-webhooks", ActorType: "service", TargetType: "webhook", Result: "success",
				Timestamp: time.Now().UTC(),
				Details: map[string]interface{}{
					"severity": "warning", "count": len(ids), "webhook_ids": ids,
					"exposure": "stored in plaintext by an earlier release; rotate the secret and header tokens",
				},
			})
		}
	}
	if len(failed) > 0 {
		if audit != nil {
			audit(ctx, AuditEvent{
				TenantID: "root", Service: "audit", Action: webhookSelfPrefix + "credentials_seal_refused",
				ActorID: "audit-webhooks", ActorType: "service", TargetType: "webhook", Result: "refused",
				Timestamp: time.Now().UTC(),
				Details:   map[string]interface{}{"severity": "critical", "reason": "seal_failed", "webhook_ids": failed},
			})
		}
		return total, fmt.Errorf("%d webhook(s) still hold plaintext credentials", len(failed))
	}
	return total, nil
}

// sealLegacyLoop seals plaintext rows now and every interval, which catches
// rows a restore brings back from an earlier release.
func (s *Service) sealLegacyLoop(ctx context.Context, k *mek.Keyring, primary func(context.Context) bool, audit func(context.Context, AuditEvent), interval time.Duration, logf func(string, ...interface{})) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := s.sealLegacyWebhooks(ctx, k, primary, audit); err != nil {
			logf("webhook credentials: %v", err)
		} else if n > 0 {
			logf("webhook credentials: sealed %d plaintext webhook(s); recorded in the exposure register", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
