package main

import (
	"context"
	"crypto/fips140"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"vecta-kms/pkg/clusterstate"
	pkgcrypto "vecta-kms/pkg/crypto"
)

// Working-key derivation versioning (docs/SECURITY/DATAPROTECT_KEY_DERIVATION.md).
//
//	v1  legacy: HMAC over key identifiers (KCV / key id). Not secret. Kept only
//	    so data protected before 2026-09-25 stays readable until migrated.
//	v2  keycore POST /keys/{id}/service-derive: HKDF over the key's secret
//	    material, bound to kms-dataprotect, tenant, key, pinned version, purpose.
//
// Per-key state machine: legacy -> migrating -> v2 (abort: migrating -> legacy).
// Keys created after the v2 cutoff start in v2 and can never use v1. In FIPS
// strict mode v1 is refused in every state.

const (
	kdfV1 = "v1"
	kdfV2 = "v2"

	kdfStateLegacy    = "legacy"
	kdfStateMigrating = "migrating"
	kdfStateV2        = "v2"

	// KDFVersionHeader lets a client pick the derivation per request while a
	// key is migrating (read old data with v1, write new data with v2).
	KDFVersionHeader = "X-Vecta-KDF-Version"

	legacyUseAuditInterval = 5 * time.Minute
)

type kdfUse struct {
	Version    string
	KeyVersion int
	// State is the key's derivation state when the use was decided.
	State string
}

// kdfForStorage makes server-side stored data (vault tokens) follow the key's
// state rather than the per-request header: a migrating key writes v2.
const kdfForStorage = "storage"

type kdfCtxKey struct{}

func withRequestedKDF(ctx context.Context, version string) context.Context {
	return context.WithValue(ctx, kdfCtxKey{}, strings.ToLower(strings.TrimSpace(version)))
}

func requestedKDF(ctx context.Context) string {
	v, _ := ctx.Value(kdfCtxKey{}).(string)
	return v
}

func metaInt(v interface{}) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	}
	return 0
}

// keyKDFState returns the key's derivation state, recording the initial state
// on first sight: v2 for keys created after the cutoff, legacy otherwise
// (including when creation time or cutoff is unknown — never guess "v2" for a
// key that may already protect v1 data).
func (s *Service) keyKDFState(ctx context.Context, tenantID, keyID string, meta map[string]interface{}) (KeyKDFState, error) {
	st, err := s.store.GetKeyKDF(ctx, tenantID, keyID)
	if err == nil || !errors.Is(err, errNotFound) {
		return st, err
	}
	initial := KeyKDFState{TenantID: tenantID, KeyID: keyID, State: kdfStateLegacy, UpdatedBy: "system"}
	cutoff, cerr := s.store.GetKDFCutoff(ctx)
	created := parseTimeValue(meta["created_at"])
	if cerr == nil && !created.IsZero() && !created.Before(cutoff) {
		initial.State = kdfStateV2
		initial.KeyVersion = metaInt(meta["current_version"])
		if initial.KeyVersion <= 0 {
			initial.KeyVersion = 1
		}
	} else if cerr != nil && !errors.Is(cerr, errNotFound) {
		return KeyKDFState{}, cerr
	}
	// On a cluster member the table is replicated: inserting here would clash
	// with the primary's row and halt replication. The initial state is a pure
	// function of replicated inputs (cutoff, key metadata), so the member uses
	// it unrecorded; the primary records it on its own first sight.
	if clusterstate.Default().Get(ctx).IsMember() {
		return initial, nil
	}
	if err := s.store.InsertKeyKDFIfAbsent(ctx, initial); err != nil {
		return KeyKDFState{}, err
	}
	return s.store.GetKeyKDF(ctx, tenantID, keyID)
}

// effectiveKDF applies the state machine to an optional per-request choice.
func effectiveKDF(st KeyKDFState, requested string) (kdfUse, error) {
	switch requested {
	case "", kdfV1, kdfV2:
	default:
		return kdfUse{}, newServiceError(http.StatusBadRequest, "bad_request", KDFVersionHeader+" must be v1 or v2")
	}
	use := kdfUse{Version: kdfV1, State: st.State}
	switch st.State {
	case kdfStateLegacy:
		if requested == kdfV2 {
			return kdfUse{}, newServiceError(http.StatusConflict, "kdf_migration_not_started", "key "+st.KeyID+" is not migrating; start its key-derivation migration before using v2")
		}
	case kdfStateMigrating:
		if requested == kdfV2 {
			use = kdfUse{Version: kdfV2, KeyVersion: st.KeyVersion, State: st.State}
		}
	case kdfStateV2:
		if requested == kdfV1 {
			return kdfUse{}, newServiceError(http.StatusConflict, "legacy_kdf_retired", "key "+st.KeyID+" completed its key-derivation migration; identifier-derived (v1) keys are no longer accepted")
		}
		use = kdfUse{Version: kdfV2, KeyVersion: st.KeyVersion, State: st.State}
	default:
		return kdfUse{}, fmt.Errorf("unknown key-derivation state %q", st.State)
	}
	if use.Version == kdfV1 && fips140.Enforced() {
		return kdfUse{}, newServiceError(http.StatusConflict, "key_material_unavailable", "key "+st.KeyID+" still uses identifier-derived (v1) working keys, which FIPS strict mode refuses; migrate it to v2")
	}
	return use, nil
}

// deriveWorkingKey returns the working key for one derivation version.
func (s *Service) deriveWorkingKey(ctx context.Context, tenantID, keyID, purpose string, meta map[string]interface{}, use kdfUse) ([]byte, error) {
	switch use.Version {
	case kdfV2:
		if s.keycore == nil {
			return nil, newServiceError(http.StatusServiceUnavailable, "keycore_unavailable", "keycore is required to derive working keys")
		}
		raw, _, err := s.keycore.ServiceDerive(ctx, tenantID, keyID, purpose, use.KeyVersion)
		if err != nil {
			return nil, err
		}
		if len(raw) != 32 {
			pkgcrypto.Zeroize(raw)
			return nil, errors.New("keycore returned a working key of unexpected length")
		}
		return raw, nil
	case kdfV1:
		if fips140.Enforced() {
			return nil, newServiceError(http.StatusConflict, "key_material_unavailable", "FIPS strict mode will not derive a working key from key identifiers")
		}
		key := legacyIdentifierWorkingKey(tenantID, keyID, purpose, meta)
		s.noteLegacyUse(ctx, tenantID, keyID, purpose)
		return key, nil
	}
	return nil, fmt.Errorf("unknown key-derivation version %q", use.Version)
}

// legacyIdentifierWorkingKey reproduces the pre-2026-09-25 derivation so that
// v1 data stays readable during migration. INSECURE: every input is public.
// Never call it for a key in state v2 or in FIPS strict mode.
func legacyIdentifierWorkingKey(tenantID, keyID, purpose string, meta map[string]interface{}) []byte {
	var material []byte
	if m := firstString(meta["material_b64"]); m != "" {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(m)); err == nil && len(raw) > 0 {
			material = raw
		}
	}
	if len(material) == 0 {
		if seed := firstString(meta["material"], meta["wrapped_material"], meta["kcv"], meta["id"]); seed != "" {
			material = []byte(seed)
		}
	}
	if len(material) == 0 {
		material = []byte(tenantID + "|" + keyID + "|" + purpose)
	}
	out := keyFromHash(material, "dataprotect-"+purpose)
	pkgcrypto.Zeroize(material)
	return out
}

// Legacy-use accounting: every v1 derivation is counted; the count is
// persisted and an audit event is emitted at most once per interval per key.
type legacyUseTracker struct {
	mu      sync.Mutex
	pending map[string]*legacyUseEntry
}

type legacyUseEntry struct {
	count    int64
	flushed  time.Time
	purposes map[string]struct{}
}

func (s *Service) noteLegacyUse(ctx context.Context, tenantID, keyID, purpose string) {
	s.legacyUses.mu.Lock()
	if s.legacyUses.pending == nil {
		s.legacyUses.pending = map[string]*legacyUseEntry{}
	}
	k := tenantID + "\x00" + keyID
	e := s.legacyUses.pending[k]
	if e == nil {
		e = &legacyUseEntry{purposes: map[string]struct{}{}}
		s.legacyUses.pending[k] = e
	}
	e.count++
	e.purposes[purpose] = struct{}{}
	now := s.now()
	if !e.flushed.IsZero() && now.Sub(e.flushed) < legacyUseAuditInterval {
		s.legacyUses.mu.Unlock()
		return
	}
	n := e.count
	purposes := make([]string, 0, len(e.purposes))
	for p := range e.purposes {
		purposes = append(purposes, p)
	}
	e.count, e.flushed, e.purposes = 0, now, map[string]struct{}{}
	s.legacyUses.mu.Unlock()

	// dataprotect_key_kdf replicates from the primary; a member must not write
	// it (the row would diverge and later primary updates to it be skipped).
	// A member's legacy use shows in the audit event below.
	if !clusterstate.Default().Get(ctx).IsMember() {
		_ = s.store.AddKeyKDFLegacyUses(ctx, tenantID, keyID, n, now)
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.kdf_legacy_used", tenantID, map[string]interface{}{
		"key_id":         keyID,
		"purposes":       purposes,
		"uses":           n,
		"kdf_version":    kdfV1,
		"severity":       "warning",
		"result":         "success",
		"description":    "working key derived from key identifiers (legacy v1); data protected this way is predictable",
		"recommendation": "migrate the key: POST /kdf/keys/{key_id}/start-migration, re-protect data, then /complete",
	})
}

// noteKDFRefusal audits a refused derivation (v1 after migration, v2 before
// it, v1 in strict mode) at most once per minute per key and reason.
func (s *Service) noteKDFRefusal(ctx context.Context, tenantID, keyID, purpose, state string, err error) {
	var se serviceError
	if !errors.As(err, &se) {
		return
	}
	k := "refusal\x00" + tenantID + "\x00" + keyID + "\x00" + se.Code
	now := s.now()
	s.legacyUses.mu.Lock()
	if s.legacyUses.pending == nil {
		s.legacyUses.pending = map[string]*legacyUseEntry{}
	}
	e := s.legacyUses.pending[k]
	if e == nil {
		e = &legacyUseEntry{}
		s.legacyUses.pending[k] = e
	}
	e.count++
	if !e.flushed.IsZero() && now.Sub(e.flushed) < time.Minute {
		s.legacyUses.mu.Unlock()
		return
	}
	n := e.count
	e.count, e.flushed = 0, now
	s.legacyUses.mu.Unlock()
	severity := "warning"
	if se.Code == "legacy_kdf_retired" {
		severity = "critical" // someone still asks for identifier-derived keys after migration
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.kdf_refused", tenantID, map[string]interface{}{
		"key_id": keyID, "purpose": purpose, "state": state, "code": se.Code, "refusals": n,
		"requested_kdf": requestedKDF(ctx), "severity": severity, "result": "denied",
	})
}

// ---- Admin: migration workflow ----

func (s *Service) ListKeyKDF(ctx context.Context, tenantID string) ([]KeyKDFState, error) {
	items, err := s.store.ListKeyKDF(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for i := range items {
		if items[i].State != kdfStateV2 {
			n, err := s.store.CountLegacyTokensForKey(ctx, tenantID, items[i].KeyID)
			if err != nil {
				return nil, err
			}
			items[i].LegacyVaultTokens = n
		}
	}
	return items, nil
}

func (s *Service) kdfKeyMeta(ctx context.Context, tenantID, keyID string) (map[string]interface{}, error) {
	if s.keycore == nil {
		return nil, newServiceError(http.StatusServiceUnavailable, "keycore_unavailable", "keycore is required")
	}
	return s.keycore.GetKey(ctx, tenantID, keyID)
}

// StartKDFMigration moves a legacy key to migrating and pins the keycore
// version v2 derivation will use.
func (s *Service) StartKDFMigration(ctx context.Context, tenantID, keyID, actor string) (KeyKDFState, error) {
	meta, err := s.kdfKeyMeta(ctx, tenantID, keyID)
	if err != nil {
		return KeyKDFState{}, err
	}
	st, err := s.keyKDFState(ctx, tenantID, keyID, meta)
	if err != nil {
		return KeyKDFState{}, err
	}
	if st.State != kdfStateLegacy {
		return KeyKDFState{}, newServiceError(http.StatusConflict, "invalid_kdf_state", "key is "+st.State+"; only a legacy key can start migration")
	}
	pin := metaInt(meta["current_version"])
	if pin <= 0 {
		pin = 1
	}
	if err := s.store.TransitionKeyKDF(ctx, tenantID, keyID, kdfStateLegacy, kdfStateMigrating, pin, actor); err != nil {
		return KeyKDFState{}, s.kdfTransitionErr(err)
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.kdf_migration_started", tenantID, map[string]interface{}{
		"key_id": keyID, "pinned_key_version": pin, "actor": actor, "from_state": kdfStateLegacy, "to_state": kdfStateMigrating,
		"severity": "info", "result": "success",
	})
	return s.store.GetKeyKDF(ctx, tenantID, keyID)
}

// ReprotectVaultTokens re-protects up to limit stored vault tokens of the key
// from v1 to v2: the original is re-encrypted and the lookup hash recomputed
// under the v2 key. Token strings do not change, so tokens customers hold stay
// valid. Irreversible tokens have no stored original; their v1 hash (an HMAC
// under a predictable key) is dropped. Safe to re-run.
func (s *Service) ReprotectVaultTokens(ctx context.Context, tenantID, keyID string, limit int, actor string) (map[string]interface{}, error) {
	meta, err := s.kdfKeyMeta(ctx, tenantID, keyID)
	if err != nil {
		return nil, err
	}
	st, err := s.keyKDFState(ctx, tenantID, keyID, meta)
	if err != nil {
		return nil, err
	}
	if st.State != kdfStateMigrating {
		return nil, newServiceError(http.StatusConflict, "invalid_kdf_state", "key is "+st.State+"; vault re-protection runs while the key is migrating")
	}
	rows, err := s.store.ListLegacyTokensForKey(ctx, tenantID, keyID, limit)
	if err != nil {
		return nil, err
	}
	converted, dropped := 0, 0
	failed := []string{}
	if len(rows) > 0 {
		v1Key, err := s.deriveWorkingKey(ctx, tenantID, keyID, "tokenize", meta, kdfUse{Version: kdfV1})
		if err != nil {
			return nil, err
		}
		defer pkgcrypto.Zeroize(v1Key)
		v2Key, err := s.deriveWorkingKey(ctx, tenantID, keyID, "tokenize", meta, kdfUse{Version: kdfV2, KeyVersion: st.KeyVersion})
		if err != nil {
			return nil, err
		}
		defer pkgcrypto.Zeroize(v2Key)
		for _, rec := range rows {
			if string(rec.OriginalEnc) == "IRREVERSIBLE" {
				if err := s.store.ReprotectToken(ctx, tenantID, rec.ID, rec.OriginalEnc, "", kdfV1, kdfV2, st.KeyVersion); err == nil {
					dropped++
				}
				continue
			}
			value, err := decryptTokenValue(v1Key, rec.OriginalEnc)
			if err != nil {
				failed = append(failed, rec.ID)
				continue
			}
			enc, err := encryptTokenValue(v2Key, value)
			if err != nil {
				failed = append(failed, rec.ID)
				continue
			}
			hashB := hmacSHA256(v2Key, "token-hash", value)
			hash := hex.EncodeToString(hashB)
			zeroizeAll(hashB)
			if err := s.store.ReprotectToken(ctx, tenantID, rec.ID, enc, hash, kdfV1, kdfV2, st.KeyVersion); err == nil {
				converted++
			} else if !errors.Is(err, errNotFound) {
				return nil, err
			}
		}
	}
	remaining, err := s.store.CountLegacyTokensForKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"key_id": keyID, "converted": converted, "irreversible_hashes_dropped": dropped,
		"failed": len(failed), "failed_token_ids": failed, "remaining": remaining,
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.kdf_vault_reprotected", tenantID, map[string]interface{}{
		"key_id": keyID, "converted": converted, "irreversible_hashes_dropped": dropped, "failed": len(failed),
		"remaining": remaining, "pinned_key_version": st.KeyVersion, "actor": actor,
		"severity": map[bool]string{true: "warning", false: "info"}[len(failed) > 0], "result": "success",
	})
	return out, nil
}

// CompleteKDFMigration retires v1 for the key. Every stored vault token must
// already be v2 unless force is set (for tokens that were unreadable before
// the migration, e.g. after a key rotation under the legacy scheme).
func (s *Service) CompleteKDFMigration(ctx context.Context, tenantID, keyID, actor string, force bool) (KeyKDFState, error) {
	st, err := s.store.GetKeyKDF(ctx, tenantID, keyID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return KeyKDFState{}, newServiceError(http.StatusNotFound, "not_found", "key has no key-derivation record")
		}
		return KeyKDFState{}, err
	}
	if st.State != kdfStateMigrating {
		return KeyKDFState{}, newServiceError(http.StatusConflict, "invalid_kdf_state", "key is "+st.State+"; only a migrating key can complete")
	}
	remaining, err := s.store.CountLegacyTokensForKey(ctx, tenantID, keyID)
	if err != nil {
		return KeyKDFState{}, err
	}
	if remaining > 0 && !force {
		return KeyKDFState{}, newServiceError(http.StatusConflict, "legacy_tokens_remaining", fmt.Sprintf("%d stored vault tokens still use v1; run reprotect-vault first", remaining))
	}
	if err := s.store.TransitionKeyKDF(ctx, tenantID, keyID, kdfStateMigrating, kdfStateV2, st.KeyVersion, actor); err != nil {
		return KeyKDFState{}, s.kdfTransitionErr(err)
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.kdf_migration_completed", tenantID, map[string]interface{}{
		"key_id": keyID, "pinned_key_version": st.KeyVersion, "actor": actor, "forced": force,
		"legacy_vault_tokens_abandoned": remaining, "from_state": kdfStateMigrating, "to_state": kdfStateV2,
		"severity": map[bool]string{true: "warning", false: "info"}[force && remaining > 0], "result": "success",
	})
	return s.store.GetKeyKDF(ctx, tenantID, keyID)
}

// AbortKDFMigration returns a migrating key to legacy. Vault tokens already
// re-protected stay v2 and remain readable (detokenize reads per row).
func (s *Service) AbortKDFMigration(ctx context.Context, tenantID, keyID, actor string) (KeyKDFState, error) {
	st, err := s.store.GetKeyKDF(ctx, tenantID, keyID)
	if err != nil {
		return KeyKDFState{}, err
	}
	if err := s.store.TransitionKeyKDF(ctx, tenantID, keyID, kdfStateMigrating, kdfStateLegacy, st.KeyVersion, actor); err != nil {
		return KeyKDFState{}, s.kdfTransitionErr(err)
	}
	_ = s.publishAudit(ctx, "audit.dataprotect.kdf_migration_aborted", tenantID, map[string]interface{}{
		"key_id": keyID, "actor": actor, "from_state": kdfStateMigrating, "to_state": kdfStateLegacy,
		"severity": "warning", "result": "success",
	})
	return s.store.GetKeyKDF(ctx, tenantID, keyID)
}

func (s *Service) kdfTransitionErr(err error) error {
	if errors.Is(err, errNotFound) {
		return newServiceError(http.StatusConflict, "invalid_kdf_state", "key-derivation state changed concurrently; reload and retry")
	}
	return err
}
