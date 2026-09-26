package main

import (
	"context"
	"fmt"
	"sort"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
)

// legacyDevMEK is the public key that releases before 1.2.0-beta fell back
// to when SECRETS_MEK_B64 was unset (which no installer ever set). It's used
// only to find values stored under it and re-wrap them, and to refuse it as
// a configured MEK. The runtime read and write paths never use it.
func legacyDevMEK() []byte {
	sum, err := pkgcrypto.Hash("SHA-256", []byte("vecta-secrets-dev-mek")) // conformance:legacy-public-key
	if err != nil {
		panic("secrets: SHA-256 unavailable: " + err.Error())
	}
	return sum
}

// mekStore is what the MEK migration needs from storage.
type mekStore interface {
	PageWrappedDEKs(ctx context.Context, after wrappedDEK, limit int) ([]wrappedDEK, error)
	ReplaceWrappedDEK(ctx context.Context, old wrappedDEK, iv, dek []byte) (bool, error)
	MEKState(ctx context.Context) (mekState, bool, error)
	SaveMEKState(ctx context.Context, st mekState) error
}

// mekPageSize bounds one scan page.
const mekPageSize = 500

// maxAuditedIDs caps the secret IDs listed in one event; the count is exact.
const maxAuditedIDs = 500

// Where a row's DEK was wrapped before it was moved to the configured MEK.
const (
	fromDevMEK      = "dev_mek"
	fromPreviousMEK = "previous_mek"
)

// tenantTally collects one tenant's migration outcome, per secret.
type tenantTally struct {
	rewrapped  map[string]map[string]bool // from -> secret IDs
	versions   map[string]int             // from -> rows rewrapped
	failed     map[string]map[string]bool // from -> secret IDs that could not be rewritten
	failedErr  map[string]string
	unreadable map[string]bool
}

func newTally() *tenantTally {
	return &tenantTally{
		rewrapped:  map[string]map[string]bool{},
		versions:   map[string]int{},
		failed:     map[string]map[string]bool{},
		failedErr:  map[string]string{},
		unreadable: map[string]bool{},
	}
}

func addID(m map[string]map[string]bool, from, id string) {
	if m[from] == nil {
		m[from] = map[string]bool{}
	}
	m[from][id] = true
}

// migrateMEK makes every stored value readable under the configured MEK, and
// only under it. It runs at startup, before the service serves requests:
//
//   - A value wrapped under SECRETS_MEK_PREVIOUS_B64 (a rotation) or under the
//     public development key (legacyDevMEK) has its DEK re-wrapped under the
//     configured MEK. The value's ciphertext is unchanged. Each row is swapped
//     only if it still holds what was read, so concurrent starts are safe.
//   - It is idempotent: rows already under the configured MEK are skipped, and
//     once a scan completes cleanly the MEK's fingerprint is recorded, so later
//     starts skip the scan until a rotation.
//   - A configured MEK that differs from the recorded one (and isn't a
//     rotation from it) is refused, since nothing stored would be readable.
//   - On a cluster member it only checks the fingerprint; the primary migrates
//     and replication delivers the result.
//
// It returns an error when the service must not start: a MEK mismatch, or a
// row that should have been re-wrapped and wasn't (it would stay readable
// with a public or retired key). Every outcome is audited per tenant.
func migrateMEK(ctx context.Context, store mekStore, keys mekKeys, audit route.Emitter, member bool, logf func(string, ...interface{})) error {
	fp := mekFingerprint(keys.Current)
	st, recorded, err := store.MEKState(ctx)
	if err != nil {
		return fmt.Errorf("read MEK state: %w", err)
	}
	if recorded && st.Fingerprint != fp {
		rotating := keys.Previous != nil && st.Fingerprint == mekFingerprint(keys.Previous)
		if member || !rotating {
			hint := "restore the original SECRETS_MEK_B64, or set it as SECRETS_MEK_PREVIOUS_B64 to rotate"
			if member {
				hint = "cluster members must use the primary's SECRETS_MEK_B64"
			}
			emitMEK(ctx, audit, "mek_check_refused", "", pkgaudit.Event{Result: route.ResultRefused}, map[string]interface{}{
				"severity": "critical", "reason": "mek_mismatch", "recorded_fingerprint": st.Fingerprint, "configured_fingerprint": fp,
			})
			return fmt.Errorf("%w (recorded %s, configured %s): %s", errMEKMismatch, st.Fingerprint, fp, hint)
		}
	}
	if member {
		return nil // members never write replicated tables
	}
	if recorded && st.Fingerprint == fp && keys.Previous == nil {
		return nil // clean under this MEK since the last scan
	}

	dev := legacyDevMEK()
	tallies := map[string]*tenantTally{}
	tally := func(tenant string) *tenantTally {
		if tallies[tenant] == nil {
			tallies[tenant] = newTally()
		}
		return tallies[tenant]
	}
	var res mekState
	failed := 0
	after := wrappedDEK{}
	for {
		page, err := store.PageWrappedDEKs(ctx, after, mekPageSize)
		if err != nil {
			return fmt.Errorf("scan secret values: %w", err)
		}
		for _, row := range page {
			env := &pkgcrypto.EnvelopeCiphertext{WrappedDEKIV: row.IV, WrappedDEK: row.DEK}
			if pkgcrypto.EnvelopeWrappedUnder(keys.Current, env) {
				continue
			}
			var from string
			var oldKey []byte
			switch {
			case keys.Previous != nil && pkgcrypto.EnvelopeWrappedUnder(keys.Previous, env):
				from, oldKey = fromPreviousMEK, keys.Previous
			case pkgcrypto.EnvelopeWrappedUnder(dev, env):
				from, oldKey = fromDevMEK, dev
			default:
				tally(row.TenantID).unreadable[row.SecretID] = true
				res.Unreadable++
				continue
			}
			t := tally(row.TenantID)
			out, err := pkgcrypto.RewrapEnvelope(oldKey, keys.Current, env)
			swapped := false
			if err == nil {
				swapped, err = store.ReplaceWrappedDEK(ctx, row, out.WrappedDEKIV, out.WrappedDEK)
			}
			if err != nil {
				addID(t.failed, from, row.SecretID)
				t.failedErr[from] = err.Error()
				failed++
				continue
			}
			if !swapped {
				continue // changed or deleted meanwhile (e.g. another instance re-wrapped it)
			}
			addID(t.rewrapped, from, row.SecretID)
			t.versions[from]++
			if from == fromDevMEK {
				res.DevRewrapped++
			} else {
				res.PreviousRewrapped++
			}
		}
		if len(page) < mekPageSize {
			break
		}
		after = page[len(page)-1]
	}

	emitTallies(ctx, audit, tallies)
	logf("MEK migration: %d value(s) re-wrapped from the public development key, %d from the previous MEK, %d unreadable, %d failed",
		res.DevRewrapped, res.PreviousRewrapped, res.Unreadable, failed)
	if failed > 0 {
		return fmt.Errorf("%d stored value(s) could not be re-wrapped under the configured MEK; they would stay under a public or retired key (see audit.secrets.*_rewrap_refused)", failed)
	}
	res.Fingerprint = fp
	if err := store.SaveMEKState(ctx, res); err != nil {
		return fmt.Errorf("record MEK state: %w", err)
	}
	if keys.Previous != nil {
		logf("every value is under the configured MEK; remove %s", envPreviousMEK)
	}
	return nil
}

func emitTallies(ctx context.Context, audit route.Emitter, tallies map[string]*tenantTally) {
	tenants := make([]string, 0, len(tallies))
	for tenant := range tallies {
		tenants = append(tenants, tenant)
	}
	sort.Strings(tenants)
	for _, tenant := range tenants {
		t := tallies[tenant]
		if ids := t.rewrapped[fromDevMEK]; len(ids) > 0 {
			emitMEK(ctx, audit, "dev_mek_rewrapped", tenant, pkgaudit.Event{}, withIDs(ids, map[string]interface{}{
				"severity": "warning", "from": fromDevMEK, "count": t.versions[fromDevMEK],
				"exposure": "stored under the public development key; rotate these values if the database or its backups may have been read",
			}))
		}
		if ids := t.rewrapped[fromPreviousMEK]; len(ids) > 0 {
			emitMEK(ctx, audit, "mek_rewrapped", tenant, pkgaudit.Event{}, withIDs(ids, map[string]interface{}{
				"severity": "info", "from": fromPreviousMEK, "count": t.versions[fromPreviousMEK],
			}))
		}
		for from, action := range map[string]string{fromDevMEK: "dev_mek_rewrap_refused", fromPreviousMEK: "mek_rewrap_refused"} {
			if ids := t.failed[from]; len(ids) > 0 {
				emitMEK(ctx, audit, action, tenant, pkgaudit.Event{Result: route.ResultRefused, ErrorMessage: t.failedErr[from]}, withIDs(ids, map[string]interface{}{
					"severity": "critical", "reason": "rewrap_failed", "from": from,
				}))
			}
		}
		if len(t.unreadable) > 0 {
			emitMEK(ctx, audit, "mek_unreadable", tenant, pkgaudit.Event{Result: route.ResultFailure}, withIDs(t.unreadable, map[string]interface{}{
				"severity": "warning", "reason": "no_configured_key_opens",
			}))
		}
	}
}

// withIDs adds the sorted secret IDs (capped) and their exact count.
func withIDs(set map[string]bool, details map[string]interface{}) map[string]interface{} {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	details["secret_count"] = len(ids)
	if len(ids) > maxAuditedIDs {
		ids, details["secret_ids_truncated"] = ids[:maxAuditedIDs], true
	}
	details["secret_ids"] = ids
	return details
}

func emitMEK(ctx context.Context, audit route.Emitter, action, tenant string, evt pkgaudit.Event, details map[string]interface{}) {
	if audit == nil {
		return
	}
	evt.TenantID, evt.ActorID, evt.ActorType, evt.TargetType, evt.Details = tenant, "kms-secrets", "service", "secret", details
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = audit.Emit(ctx, action, evt)
}
