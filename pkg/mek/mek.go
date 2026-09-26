// Package mek gives each platform service that stores encrypted data its
// master encryption key (MEK), and keeps its stored data under that key and
// no other (docs/SECURITY/SERVICE_MASTER_KEYS.md).
//
//   - The key comes from keycore: a symmetric system key per service
//     (POST /system-keys/ensure), from which keycore derives the service's
//     MEK bound to its verified identity (POST /keys/{id}/service-derive).
//     There is no environment variable to set and no fallback. Cluster
//     members derive the same MEK, because the join ships keycore's master
//     key.
//   - The key version is pinned in the service's state table. When the
//     keycore key is rotated, the next start re-wraps every row onto the new
//     version.
//   - Rows still under a key earlier releases used (a public development key,
//     or an old environment key) are re-wrapped at startup and again
//     periodically, which catches rows a restore brought back. Items stored
//     under a public key go into the exposure register until the material is
//     replaced.
//
// Every outcome is audited per tenant. A start that would leave data under a
// retired key, or that finds the wrong MEK, is refused.
package mek

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgcrypto "vecta-kms/pkg/crypto"
)

// Emitter is the audit sink; *pkgaudit.Client satisfies it.
type Emitter interface {
	Emit(ctx context.Context, action string, evt pkgaudit.Event) error
}

// Source provides the service's key from keycore.
type Source interface {
	// EnsureKey returns the service's system key and its current version,
	// creating it on first use.
	EnsureKey(ctx context.Context) (keyID string, version int, err error)
	// Derive returns the MEK at version (0 = current) and the version used.
	Derive(ctx context.Context, keyID string, version int) ([]byte, int, error)
}

// Options configures Open.
type Options struct {
	Tables ServiceTables
	Source Source
	DB     *sql.DB
	Audit  Emitter // nil: events are not published (counts stay in the state table)
	// Member reports whether this node is a cluster member. Members never
	// write replicated tables: they check the key and read, and the primary
	// migrates.
	Member func(ctx context.Context) bool
	Logf   func(string, ...interface{})
	// Legacy overrides the legacy keys (tests); nil means Tables' own.
	Legacy []LegacyKey
	// Wait bounds how long Open retries while keycore is unreachable.
	Wait time.Duration
}

// Keyring is a service's open master key.
type Keyring struct {
	opts    Options
	current []byte
	keyID   string
	version int
	legacy  []LegacyKey
	// unreadable is the last reported count of rows no known key opens;
	// they're reported again only when it changes.
	unreadable int
}

// Current is the MEK. Services encrypt and decrypt with it only.
func (k *Keyring) Current() []byte { return k.current }

// KeyID and Version identify the keycore key the MEK comes from.
func (k *Keyring) KeyID() string { return k.keyID }
func (k *Keyring) Version() int  { return k.version }

// ErrMismatch means keycore derives a different MEK than the one the stored
// data is recorded under: the service must not start.
var ErrMismatch = errors.New("keycore returns a different master key than the stored data is under")

var identRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// Validate checks every table and column name in st.
func (st ServiceTables) Validate() error {
	names := []string{st.StateTable, st.ExposureTable}
	for _, t := range st.Tables {
		names = append(names, t.Name, t.Tenant, t.Item, t.WrappedDEK, t.WrappedIV)
		names = append(names, t.Keys...)
		if len(t.Keys) == 0 || t.ItemType == "" {
			return fmt.Errorf("mek: table %q needs Keys and ItemType", t.Name)
		}
	}
	for _, n := range names {
		if !identRE.MatchString(n) {
			return fmt.Errorf("mek: invalid identifier %q", n)
		}
	}
	return nil
}

func fingerprint(key []byte) string {
	sum, err := pkgcrypto.HMAC("SHA-256", key, []byte("vecta/mek-fingerprint/v1"))
	if err != nil {
		panic("mek: HMAC-SHA-256 unavailable: " + err.Error())
	}
	return hex.EncodeToString(sum[:8])
}

// Open resolves the service's MEK from keycore, checks it against the
// recorded one, handles a keycore rotation, and (on the primary) moves every
// row off legacy keys. It returns an error when the service must not start.
func Open(ctx context.Context, opts Options) (*Keyring, error) {
	if err := opts.Tables.Validate(); err != nil {
		return nil, err
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...interface{}) {}
	}
	if opts.Member == nil {
		opts.Member = func(context.Context) bool { return false }
	}
	if opts.Legacy == nil {
		opts.Legacy = opts.Tables.LegacyKeysFromEnv()
	}
	member := opts.Member(ctx)
	st, recorded, err := readState(ctx, opts.DB, opts.Tables.StateTable)
	if err != nil {
		return nil, fmt.Errorf("read MEK state: %w", err)
	}

	var keyID string
	latest := 0
	err = retry(ctx, opts.Wait, opts.Logf, "keycore system key", func() error {
		var err error
		if recorded && member {
			keyID = st.KeyID // members don't need the latest version: they follow the primary's pin
			return nil
		}
		keyID, latest, err = opts.Source.EnsureKey(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	if recorded && st.KeyID != keyID {
		return nil, refuse(ctx, opts, fmt.Errorf("%w: recorded key %s, keycore returned %s", ErrMismatch, st.KeyID, keyID))
	}

	pin := latest
	if recorded {
		pin = st.Version
	}
	var cur []byte
	err = retry(ctx, opts.Wait, opts.Logf, "keycore service-derive", func() error {
		var err error
		cur, pin, err = opts.Source.Derive(ctx, keyID, pin)
		return err
	})
	if err != nil {
		return nil, err
	}
	if recorded && fingerprint(cur) != st.Fingerprint {
		return nil, refuse(ctx, opts, fmt.Errorf("%w (recorded %s, derived %s); on a cluster member, check it joined this primary", ErrMismatch, st.Fingerprint, fingerprint(cur)))
	}

	k := &Keyring{opts: opts, current: cur, keyID: keyID, version: pin, legacy: opts.Legacy, unreadable: st.Unreadable}
	if member {
		return k, nil
	}
	// A rotated keycore key: move everything onto the new version.
	legacy := opts.Legacy
	if latest > pin {
		next, v, err := opts.Source.Derive(ctx, keyID, latest)
		if err != nil {
			return nil, fmt.Errorf("derive rotated MEK: %w", err)
		}
		legacy = append([]LegacyKey{{Name: "previous_version", Key: cur}}, legacy...)
		k.current, k.version = next, v
	}
	res, err := k.scan(ctx, legacy)
	if err != nil {
		return nil, err
	}
	res.KeyID, res.Version, res.Fingerprint = k.keyID, k.version, fingerprint(k.current)
	if err := saveState(ctx, opts.DB, opts.Tables.StateTable, res); err != nil {
		return nil, fmt.Errorf("record MEK state: %w", err)
	}
	return k, nil
}

// Watch re-runs the legacy scan every interval on the primary, so rows a
// restore brings back under a retired key are re-wrapped. It returns when
// ctx ends.
func (k *Keyring) Watch(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if k.opts.Member(ctx) {
				continue
			}
			if _, err := k.scan(ctx, k.legacy); err != nil {
				k.opts.Logf("MEK rescan: %v", err)
			}
		}
	}
}

func refuse(ctx context.Context, opts Options, err error) error {
	emit(ctx, opts.Audit, "mek_check_refused", "", pkgaudit.Event{Result: "refused", ErrorMessage: err.Error()}, map[string]interface{}{
		"severity": "critical", "reason": "mek_mismatch",
	})
	return err
}

func retry(ctx context.Context, wait time.Duration, logf func(string, ...interface{}), what string, fn func() error) error {
	deadline := time.Now().Add(wait)
	delay := time.Second
	for {
		err := fn()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		logf("%s unavailable, retrying in %s: %v", what, delay, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}

// state ---------------------------------------------------------------------

type state struct {
	KeyID       string
	Version     int
	Fingerprint string
	Rewrapped   int // rows moved off a legacy key in the last scan
	Unreadable  int
}

func readState(ctx context.Context, db *sql.DB, table string) (state, bool, error) {
	var st state
	err := db.QueryRowContext(ctx, `SELECT key_id, key_version, mek_fingerprint, rewrapped, unreadable FROM `+table+` WHERE id = 1`).
		Scan(&st.KeyID, &st.Version, &st.Fingerprint, &st.Rewrapped, &st.Unreadable)
	if errors.Is(err, sql.ErrNoRows) {
		return state{}, false, nil
	}
	return st, err == nil, err
}

func saveState(ctx context.Context, db *sql.DB, table string, st state) error {
	_, err := db.ExecContext(ctx, `
INSERT INTO `+table+` (id, key_id, key_version, mek_fingerprint, rewrapped, unreadable, migrated_at)
VALUES (1, $1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
ON CONFLICT (id) DO UPDATE SET key_id = excluded.key_id, key_version = excluded.key_version,
  mek_fingerprint = excluded.mek_fingerprint, rewrapped = excluded.rewrapped,
  unreadable = excluded.unreadable, migrated_at = excluded.migrated_at`,
		st.KeyID, st.Version, st.Fingerprint, st.Rewrapped, st.Unreadable)
	return err
}

// scan ------------------------------------------------------------------------

const pageSize = 500

// maxIDs caps the item IDs listed in one event; counts stay exact.
const maxIDs = 500

type tally struct {
	moved      map[string]map[string]bool // legacy key name -> items
	rows       map[string]int
	failed     map[string]map[string]bool
	failedErr  map[string]string
	unreadable map[string]bool
}

func newTally() *tally {
	return &tally{moved: map[string]map[string]bool{}, rows: map[string]int{}, failed: map[string]map[string]bool{}, failedErr: map[string]string{}, unreadable: map[string]bool{}}
}

func add(m map[string]map[string]bool, k, id string) {
	if m[k] == nil {
		m[k] = map[string]bool{}
	}
	m[k][id] = true
}

type row struct {
	keys   []interface{}
	tenant string
	item   string
	iv     []byte
	dek    []byte
	rawDEK interface{} // as stored, for the conditional update
}

func (k *Keyring) scan(ctx context.Context, legacy []LegacyKey) (state, error) {
	var res state
	tallies := map[string]*tally{} // "tenant\x00itemType"
	get := func(tenant, itemType string) *tally {
		key := tenant + "\x00" + itemType
		if tallies[key] == nil {
			tallies[key] = newTally()
		}
		return tallies[key]
	}
	failed := 0
	public := map[string]bool{}
	for _, l := range legacy {
		public[l.Name] = l.Public
	}
	for _, t := range k.opts.Tables.Tables {
		var after []interface{}
		for {
			page, err := k.page(ctx, t, after)
			if err != nil {
				return res, fmt.Errorf("scan %s: %w", t.Name, err)
			}
			for _, r := range page {
				env := &pkgcrypto.EnvelopeCiphertext{WrappedDEKIV: r.iv, WrappedDEK: r.dek}
				if pkgcrypto.EnvelopeWrappedUnder(k.current, env) {
					continue
				}
				var from *LegacyKey
				for i := range legacy {
					if pkgcrypto.EnvelopeWrappedUnder(legacy[i].Key, env) {
						from = &legacy[i]
						break
					}
				}
				tl := get(r.tenant, t.ItemType)
				if from == nil {
					tl.unreadable[r.item] = true
					res.Unreadable++
					continue
				}
				// Exposure is recorded before the swap: once swapped, the row
				// no longer shows it was ever under a public key.
				var err error
				if from.Public {
					err = recordExposure(ctx, k.opts.DB, k.opts.Tables.ExposureTable, r.tenant, t.ItemType, r.item, from.Name)
				}
				var out *pkgcrypto.EnvelopeCiphertext
				if err == nil {
					out, err = pkgcrypto.RewrapEnvelope(from.Key, k.current, env)
				}
				swapped := false
				if err == nil {
					swapped, err = k.replace(ctx, t, r, out.WrappedDEKIV, out.WrappedDEK)
				}
				if err != nil {
					add(tl.failed, from.Name, r.item)
					tl.failedErr[from.Name] = err.Error()
					failed++
					continue
				}
				if swapped {
					add(tl.moved, from.Name, r.item)
					tl.rows[from.Name]++
					res.Rewrapped++
				}
			}
			if len(page) < pageSize {
				break
			}
			after = page[len(page)-1].keys
		}
	}
	reportUnreadable := res.Unreadable != k.unreadable
	k.unreadable = res.Unreadable
	k.emitTallies(ctx, tallies, public, reportUnreadable)
	if res.Rewrapped+failed > 0 || reportUnreadable {
		k.opts.Logf("MEK scan: %d row(s) re-wrapped onto key %s v%d, %d unreadable, %d failed", res.Rewrapped, k.keyID, k.version, res.Unreadable, failed)
	}
	if failed > 0 {
		return res, fmt.Errorf("%d stored row(s) could not be re-wrapped under the service master key; they would stay under a retired or public key (see audit.%s.mek_rewrap_refused)", failed, k.opts.Tables.Service)
	}
	return res, nil
}

func (k *Keyring) page(ctx context.Context, t Table, after []interface{}) ([]row, error) {
	cols := append(append([]string{}, t.Keys...), t.Tenant, t.Item, t.WrappedIV, t.WrappedDEK)
	var where []string
	if t.Where != "" {
		where = append(where, "("+t.Where+")")
	}
	args := after
	if len(after) > 0 {
		ph := make([]string, len(after))
		for i := range after {
			ph[i] = fmt.Sprintf("$%d", i+1)
		}
		where = append(where, "("+strings.Join(t.Keys, ", ")+") > ("+strings.Join(ph, ", ")+")")
	}
	q := "SELECT " + strings.Join(cols, ", ") + " FROM " + t.Name
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY " + strings.Join(t.Keys, ", ") + fmt.Sprintf(" LIMIT %d", pageSize)
	rows, err := k.opts.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []row
	n := len(t.Keys)
	for rows.Next() {
		vals := make([]interface{}, n+4)
		ptrs := make([]interface{}, len(vals))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := row{keys: vals[:n], tenant: asString(vals[n]), item: asString(vals[n+1]), rawDEK: vals[n+3]}
		if r.iv, err = decodeBlob(vals[n+2], t.Base64); err != nil {
			return nil, err
		}
		if r.dek, err = decodeBlob(vals[n+3], t.Base64); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// replace swaps one row's wrapped DEK only if it still holds what was read.
func (k *Keyring) replace(ctx context.Context, t Table, r row, iv, dek []byte) (bool, error) {
	var ivVal, dekVal interface{} = iv, dek
	if t.Base64 {
		ivVal, dekVal = b64(iv), b64(dek)
	}
	args := []interface{}{ivVal, dekVal}
	conds := make([]string, 0, len(t.Keys)+1)
	for i, c := range t.Keys {
		args = append(args, r.keys[i])
		conds = append(conds, fmt.Sprintf("%s = $%d", c, len(args)))
	}
	args = append(args, r.rawDEK)
	conds = append(conds, fmt.Sprintf("%s = $%d", t.WrappedDEK, len(args)))
	res, err := k.opts.DB.ExecContext(ctx, "UPDATE "+t.Name+" SET "+t.WrappedIV+" = $1, "+t.WrappedDEK+" = $2 WHERE "+strings.Join(conds, " AND "), args...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (k *Keyring) emitTallies(ctx context.Context, tallies map[string]*tally, public map[string]bool, reportUnreadable bool) {
	keys := make([]string, 0, len(tallies))
	for key := range tallies {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		tenant, itemType, _ := strings.Cut(key, "\x00")
		t := tallies[key]
		for _, from := range sortedKeys(t.moved) {
			action, severity := "mek_rewrapped", "info"
			details := map[string]interface{}{"from": from, "count": t.rows[from], "item_type": itemType}
			if public[from] {
				action, severity = "dev_mek_rewrapped", "warning"
				details["exposure"] = "stored under a public key; recorded in the exposure register until the material is replaced"
			}
			details["severity"] = severity
			emit(ctx, k.opts.Audit, action, tenant, pkgaudit.Event{}, withIDs(t.moved[from], details))
		}
		for _, from := range sortedKeys(t.failed) {
			action := "mek_rewrap_refused"
			if public[from] {
				action = "dev_mek_rewrap_refused"
			}
			emit(ctx, k.opts.Audit, action, tenant, pkgaudit.Event{Result: "refused", ErrorMessage: t.failedErr[from]}, withIDs(t.failed[from], map[string]interface{}{
				"severity": "critical", "reason": "rewrap_failed", "from": from, "item_type": itemType,
			}))
		}
		if reportUnreadable && len(t.unreadable) > 0 {
			emit(ctx, k.opts.Audit, "mek_unreadable", tenant, pkgaudit.Event{Result: "failure"}, withIDs(t.unreadable, map[string]interface{}{
				"severity": "warning", "reason": "no_known_key_opens", "item_type": itemType,
			}))
		}
	}
}

func sortedKeys(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func withIDs(set map[string]bool, details map[string]interface{}) map[string]interface{} {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	details["item_count"] = len(ids)
	if len(ids) > maxIDs {
		ids, details["item_ids_truncated"] = ids[:maxIDs], true
	}
	details["item_ids"] = ids
	return details
}

func emit(ctx context.Context, audit Emitter, action, tenant string, evt pkgaudit.Event, details map[string]interface{}) {
	if audit == nil {
		return
	}
	evt.TenantID, evt.ActorType, evt.Details = tenant, "service", details
	if evt.Result == "" {
		evt.Result = "success"
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = audit.Emit(ctx, action, evt)
}

func asString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func decodeBlob(v interface{}, isBase64 bool) ([]byte, error) {
	if !isBase64 {
		switch t := v.(type) {
		case []byte:
			return t, nil
		case string:
			return []byte(t), nil
		case nil:
			return nil, nil
		}
		return nil, fmt.Errorf("unexpected blob type %T", v)
	}
	return unb64(asString(v))
}
