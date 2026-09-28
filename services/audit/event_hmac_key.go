package main

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/mek"
)

// The audit event HMAC key (docs/SECURITY/AUDIT_INTEGRITY.md) is derived
// with HKDF-SHA256 from the audit service master key (pkg/mek, a protected
// keycore system key), so it survives restarts and is the same on every
// cluster node (members follow the primary's MEK version). The key of every
// earlier MEK version is derived too, so older events still verify.
//
// Until the keyring opens, events are stored unsigned (reported "unsigned",
// never as a failure) rather than under a random key that would be lost at
// the next restart and make every earlier event "hmac_key_unknown".

const (
	eventHMACInfo            = "vecta-audit-event-hmac/1"
	actionEventHMACInstalled = "audit.audit.event_hmac_key_installed"
)

func eventHMACKey(masterKey []byte) ([]byte, error) {
	return pkgcrypto.HKDFSHA256(masterKey, nil, []byte(eventHMACInfo), 32)
}

// deriveFunc returns the MEK at a version (mek.Source.Derive).
type deriveFunc func(ctx context.Context, keyID string, version int) ([]byte, int, error)

// installEventHMACKeys installs the HMAC key of every MEK version up to the
// keyring's, the current one last so it signs. A version keycore can't
// derive is reported: events signed under it will show hmac_key_unknown.
func (s *Service) installEventHMACKeys(ctx context.Context, k *mek.Keyring, derive deriveFunc) error {
	sq, ok := s.store.(*SQLStore)
	if !ok {
		return nil
	}
	var unavailable []int
	for v := 1; v < k.Version(); v++ {
		old, _, err := derive(ctx, k.KeyID(), v)
		if err != nil {
			unavailable = append(unavailable, v)
			continue
		}
		key, err := eventHMACKey(old)
		pkgcrypto.Zeroize(old)
		if err != nil {
			return err
		}
		sq.keys.install(key)
		pkgcrypto.Zeroize(key)
	}
	key, err := eventHMACKey(k.Current())
	if err != nil {
		return err
	}
	id := sq.keys.install(key)
	pkgcrypto.Zeroize(key)
	details := map[string]interface{}{
		"key_id": id, "mek_key_id": k.KeyID(), "mek_version": k.Version(),
		"description": "audit event HMAC key derived (HKDF-SHA256) from the audit master key",
	}
	if len(unavailable) > 0 {
		details["unavailable_mek_versions"] = unavailable
	}
	_, err = s.ProcessEvent(ctx, AuditEvent{
		TenantID: checkpointKeyTenant, Service: "audit", Action: actionEventHMACInstalled,
		ActorID: "system", ActorType: "service", TargetType: "audit_hmac_key", TargetID: id, Result: "success",
		Timestamp: time.Now().UTC(), Details: details,
	})
	return err
}

// legacyEventKey returns AUDIT_EVENT_SIGNING_KEY_B64 when an operator set it,
// kept only to verify events earlier releases signed with it. Nothing is
// generated when it is unset.
func legacyEventKey() []byte {
	raw := strings.TrimSpace(os.Getenv("AUDIT_EVENT_SIGNING_KEY_B64"))
	if raw == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) < 16 {
		logger.Printf("WARNING: AUDIT_EVENT_SIGNING_KEY_B64 is set but invalid; ignored")
		return nil
	}
	out := make([]byte, 32)
	copy(out, key)
	return out
}
