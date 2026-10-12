package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"vecta-kms/pkg/clusterstate"
	"vecta-kms/pkg/crypto"
)

// A software key pair is two key records that share a pair_id label: the
// private key, and a public component whose material is derived from it.
// (An HSM key holds both halves in one record and is not a pair here.)
//
// Until 12.3.0-beta a rotation renewed the private key only, so the public
// component kept the old key, and a public component rotated on its own was
// given the public half of a pair generated for the purpose, whose private
// half was discarded. Now the public component gets a version derived from
// the new private key in the same transaction, a public key is refused a
// rotation of its own, and pairs left out of step are brought back by
// ResyncPairPublicKeys.

const (
	labelPairID        = "pair_id"
	labelComponentRole = "component_role"
)

var (
	// errPublicKeyRotation refuses a rotation of a public key on its own.
	errPublicKeyRotation = errors.New("a public key is not rotated on its own")
	// errPublicKeyAlone refuses generating a public key that has no private key.
	errPublicKeyAlone = errors.New("a public key is created with its private key (pair_id) or imported, not generated on its own")
)

func pairRole(k Key) (pairID, role string) {
	return strings.TrimSpace(k.Labels[labelPairID]), strings.ToLower(strings.TrimSpace(k.Labels[labelComponentRole]))
}

// pairComponent returns the tenant's live key in pairID with the given role.
func (s *Service) pairComponent(ctx context.Context, tenantID, pairID, role string) (Key, bool, error) {
	if pairID == "" {
		return Key{}, false, nil
	}
	const page = 500
	for offset := 0; ; offset += page {
		keys, err := s.store.ListKeys(ctx, tenantID, page, offset)
		if err != nil {
			return Key{}, false, err
		}
		for _, k := range keys {
			if id, r := pairRole(k); id == pairID && r == role && !isDeletedLike(k.Status) {
				return k, true, nil
			}
		}
		if len(keys) < page {
			return Key{}, false, nil
		}
	}
}

// publicComponentOf returns the public component that follows a private key.
func (s *Service) publicComponentOf(ctx context.Context, private Key) (Key, bool, error) {
	pairID, role := pairRole(private)
	if role != "private" {
		return Key{}, false, nil
	}
	return s.pairComponent(ctx, private.TenantID, pairID, "public")
}

// refusePublicRotation audits and returns the refusal of a rotation asked of
// a public key: it follows its private key, or it has none here.
func (s *Service) refusePublicRotation(ctx context.Context, key Key) error {
	details := map[string]any{"key_id": key.ID, "result": "refused", "reason": "public_key_has_no_private_key"}
	msg := "import the new public key as a new key"
	if pairID, _ := pairRole(key); pairID != "" {
		if private, ok, err := s.pairComponent(ctx, key.TenantID, pairID, "private"); err == nil && ok {
			details["reason"], details["private_key_id"] = "public_key_follows_private_key", private.ID
			msg = "rotate its private key " + private.ID + "; the public key follows it"
		}
	}
	_ = s.publishAudit(ctx, "audit.key.rotate_refused", key.TenantID, details)
	return fmtRefusal(errPublicKeyRotation, msg)
}

func fmtRefusal(base error, msg string) error { return &wrappedRefusal{base: base, msg: msg} }

type wrappedRefusal struct {
	base error
	msg  string
}

func (e *wrappedRefusal) Error() string { return e.base.Error() + ": " + e.msg }
func (e *wrappedRefusal) Unwrap() error { return e.base }

// publicVersionFor builds the next version of a public component from the
// private material it follows. alg is the algorithm the pair moves to;
// changed marks a rotation onto a new algorithm.
func (s *Service) publicVersionFor(ctx context.Context, public Key, alg string, privateRaw []byte, reason string, changed bool) (KeyVersion, error) {
	pubRaw, err := derivePublicFromPrivateMaterial(alg, privateRaw)
	if err != nil {
		return KeyVersion{}, err
	}
	kcv, kcvAlg, err := computeKCVStrict(alg, pubRaw)
	if err != nil {
		return KeyVersion{}, err
	}
	ver := KeyVersion{
		ID: newID("kv"), TenantID: public.TenantID, KeyID: public.ID, Version: public.CurrentVersion + 1,
		KCV: kcv, RotatedFrom: public.CurrentVersion, RotationReason: reason, Status: "active",
	}
	if changed {
		ver.Algorithm, ver.KCVAlgorithm = alg, kcvAlg
	}
	if err := s.protectMaterial(ctx, &ver, pubRaw); err != nil {
		return KeyVersion{}, err
	}
	return ver, nil
}

// ResyncPairPublicKeys gives every public component whose key is not the one
// its private key now holds a new version that is, and audits each
// (audit.key.pair_public_resynced). Older versions are kept, deactivated, so
// what they verified still verifies. Idempotent; primary only (keys and
// versions are replicated). It returns how many it brought back.
func (s *Service) ResyncPairPublicKeys(ctx context.Context) (int, error) {
	if !clusterstate.RunsPrimaryJobs(ctx) {
		return 0, nil
	}
	st, ok := s.store.(*SQLStore)
	if !ok {
		return 0, nil
	}
	privates, err := st.listPairPrivateKeys(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, private := range privates {
		public, ok, err := s.publicComponentOf(ctx, private)
		if err != nil {
			return n, err
		}
		if !ok {
			continue
		}
		synced, err := s.resyncPublic(ctx, private, public)
		if err != nil {
			continue // material that can't be read here (another node's MEK, an HSM tenant key that is away)
		}
		if synced {
			n++
		}
	}
	return n, nil
}

func (s *Service) resyncPublic(ctx context.Context, private, public Key) (bool, error) {
	privVer, err := s.GetVersion(ctx, private.TenantID, private.ID, 0)
	if err != nil {
		return false, err
	}
	privRaw, err := s.decryptMaterial(privVer)
	if err != nil {
		return false, err
	}
	defer crypto.Zeroize(privRaw)
	want, err := derivePublicFromPrivateMaterial(private.Algorithm, privRaw)
	if err != nil {
		return false, err
	}
	pubVer, err := s.GetVersion(ctx, public.TenantID, public.ID, 0)
	if err != nil {
		return false, err
	}
	have, err := s.decryptMaterial(pubVer)
	if err != nil {
		return false, err
	}
	if bytes.Equal(have, want) {
		return false, nil
	}
	reason := "resync with private key " + private.ID
	next, err := s.publicVersionFor(ctx, public, private.Algorithm, privRaw, reason, !strings.EqualFold(public.Algorithm, private.Algorithm))
	if err != nil {
		return false, err
	}
	if err := s.store.RotateVersion(ctx, public.TenantID, public.ID, next, reason, "deactivate"); err != nil {
		return false, err
	}
	_ = s.cache.Delete(ctx, public.TenantID, public.ID)
	_ = s.publishAudit(ctx, "audit.key.pair_public_resynced", public.TenantID, map[string]any{
		"key_id": public.ID, "private_key_id": private.ID, "private_version": private.CurrentVersion,
		"from_version": public.CurrentVersion, "version": next.Version,
		"description": "a rotation before 12.3.0-beta renewed the private key only; the public key now holds the key its private key has",
	})
	return true, nil
}

// listPairPrivateKeys lists every live private key that carries a pair_id.
func (s *SQLStore) listPairPrivateKeys(ctx context.Context) ([]Key, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT tenant_id, id, algorithm, status, current_version, labels FROM keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []Key
	for rows.Next() {
		var (
			k      Key
			labels []byte
		)
		if err := rows.Scan(&k.TenantID, &k.ID, &k.Algorithm, &k.Status, &k.CurrentVersion, &labels); err != nil {
			return nil, err
		}
		if len(labels) > 0 {
			_ = json.Unmarshal(labels, &k.Labels)
		}
		if pairID, role := pairRole(k); pairID != "" && role == "private" && !isDeletedLike(k.Status) && k.Labels[labelHSM] != labelHSMResident {
			out = append(out, k)
		}
	}
	return out, rows.Err()
}

// RotatePairVersions rotates a private key and its public component in one
// transaction: both get their new version, or neither does.
func (s *SQLStore) RotatePairVersions(ctx context.Context, tenantID, privateID string, privateVer KeyVersion, publicID string, publicVer KeyVersion, reason, oldVersionAction string) error {
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		if err := rotateVersionTx(ctx, tx, tenantID, privateID, privateVer, reason, oldVersionAction); err != nil {
			return err
		}
		return rotateVersionTx(ctx, tx, tenantID, publicID, publicVer, reason, oldVersionAction)
	})
}
