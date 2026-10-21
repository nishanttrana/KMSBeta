// Package clusterstate tells a service whether its node is a cluster member
// and where the primary is (docs/CLUSTERING.md). cluster-manager writes the
// node-local row cluster_local_state when the node joins; every service reads
// it through the process-wide Default reader.
package clusterstate

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	RoleFollower = "follower"
	// RolePrimary is recorded when the first member joins this node, and
	// when a member is promoted (docs/CLUSTERING.md, failover).
	RolePrimary = "primary"
	// RoleFenced is a former primary that learned of a newer one: it makes
	// no lifecycle write and runs no primary job until it rejoins.
	RoleFenced = "fenced"
)

type State struct {
	NodeID             string
	Role               string
	PrimaryNodeID      string
	PrimaryURL         string
	PrimaryFingerprint string
	ForwardCredential  string
	// Epoch counts promotions; a node that sees a higher one than its own
	// follows it, and a primary that does is fenced.
	Epoch int64
	// WritableUntil is a primary's lease in a cluster of three or more
	// voters: lifecycle writes stop when it passes without a majority
	// renewing it. Zero means no lease is needed (standalone, two nodes).
	WritableUntil time.Time
}

// IsMember reports whether lifecycle writes must go to a primary.
func (s State) IsMember() bool {
	return s.Role == RoleFollower && s.PrimaryURL != "" && s.ForwardCredential != ""
}

// WritesAllowed reports whether this node, not being a member, may make
// lifecycle writes itself: refused on a fenced node and on a primary whose
// lease has passed. reason is "node_fenced" or "primary_lease_lost".
func (s State) WritesAllowed(now time.Time) (bool, string) {
	switch {
	case s.Role == RoleFenced:
		return false, "node_fenced"
	case s.Role == RolePrimary && !s.WritableUntil.IsZero() && !now.Before(s.WritableUntil):
		return false, "primary_lease_lost"
	}
	return true, ""
}

// ChainNode is the id under which this node writes shared-append rows (its
// audit chain, login attempts): its cluster node id once it is a primary or a
// member, "" while standalone. "" rows never replicate.
func (s State) ChainNode() string {
	if s.Role == RoleFollower || s.Role == RolePrimary || s.Role == RoleFenced {
		return s.NodeID
	}
	return ""
}

type Reader struct {
	static  *State
	db      *sql.DB
	ttl     time.Duration
	mu      sync.Mutex
	cur     State
	loaded  time.Time
	pending bool
	// tableSeen is set once the table is known to exist; until then Postgres
	// is asked through its catalogue, which doesn't fail when it is absent.
	tableSeen bool
}

// stateTTL is short because a primary's lease is renewed every two seconds.
const stateTTL = 2 * time.Second

func NewReader(db *sql.DB) *Reader { return &Reader{db: db, ttl: stateTTL} }

// NewPendingReader is a reader whose database arrives later (Attach): the
// platform database is reachable only over internal mTLS, once the process
// has enrolled. Until then RunsPrimaryJobs is false, so a cluster member
// never runs primary-only jobs while its role is still unknown.
func NewPendingReader() *Reader { return &Reader{ttl: stateTTL, pending: true} }

// Attach supplies the database of a pending reader.
func (r *Reader) Attach(db *sql.DB) {
	r.mu.Lock()
	r.db, r.pending = db, false
	r.mu.Unlock()
}

func (r *Reader) isPending() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pending
}

// Static returns a reader that always reports s (tests, tools).
func Static(s State) *Reader { return &Reader{static: &s} }

// Get returns the node's state, cached briefly. A missing row or table means a
// standalone node (or a primary): nothing is forwarded.
func (r *Reader) Get(ctx context.Context) State {
	if r == nil {
		return State{}
	}
	if r.static != nil {
		return *r.static
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db == nil {
		return State{}
	}
	if time.Since(r.loaded) < r.ttl {
		return r.cur
	}
	if !r.tableSeen {
		// The table exists only where the cluster manager is deployed. Reading
		// it when absent is a failed query in the database log for every
		// service, every TTL. The catalogue probe fails only on a database
		// without information_schema (SQLite), which then reads the table.
		var one int
		err := r.db.QueryRowContext(ctx, `
SELECT 1 FROM information_schema.tables
WHERE table_schema = current_schema() AND table_name = 'cluster_local_state'`).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			r.cur, r.loaded = State{}, time.Now()
			return r.cur
		}
		r.tableSeen = err == nil
	}
	var s State
	var until sql.NullTime
	err := r.db.QueryRowContext(ctx, `
SELECT node_id, role, primary_node_id, primary_url, primary_fingerprint, forward_credential, epoch, writable_until
FROM cluster_local_state WHERE id = 1`).Scan(&s.NodeID, &s.Role, &s.PrimaryNodeID, &s.PrimaryURL, &s.PrimaryFingerprint, &s.ForwardCredential, &s.Epoch, &until)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// The table as it was before failover (cluster-manager adds the
		// columns when it starts).
		s = State{}
		err = r.db.QueryRowContext(ctx, `
SELECT node_id, role, primary_node_id, primary_url, primary_fingerprint, forward_credential
FROM cluster_local_state WHERE id = 1`).Scan(&s.NodeID, &s.Role, &s.PrimaryNodeID, &s.PrimaryURL, &s.PrimaryFingerprint, &s.ForwardCredential)
	}
	if until.Valid {
		s.WritableUntil = until.Time
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// Keep the last known state, and ask again only after the TTL: where
		// the table doesn't exist (no cluster manager deployed) every call
		// would otherwise be a failed query.
		r.loaded = time.Now()
		return r.cur
	}
	r.cur, r.loaded = s, time.Now()
	return s
}

// RunsPrimaryJobs reports whether this node runs background jobs that write
// replicated state (schedulers, sweeps, reconcilers): true on a standalone
// node or a primary that may write. A member receives the results through
// replication; running them there too would diverge its copy or halt
// replication. A fenced node, or a primary without its lease, runs none.
func RunsPrimaryJobs(ctx context.Context) bool {
	r := Default()
	if r.isPending() {
		return false
	}
	st := r.Get(ctx)
	if st.IsMember() || st.Role == RoleFollower {
		return false
	}
	ok, _ := st.WritesAllowed(time.Now())
	return ok
}

var (
	defMu sync.Mutex
	def   *Reader
)

// SetDefault installs the process-wide reader (pkg/config does this).
func SetDefault(r *Reader) {
	defMu.Lock()
	def = r
	defMu.Unlock()
}

// Default returns the process-wide reader (nil-safe: a nil reader reports a
// standalone node).
func Default() *Reader {
	defMu.Lock()
	defer defMu.Unlock()
	return def
}

// PinnedHTTPClient trusts exactly one TLS certificate, identified by the
// SHA-256 of its DER encoding (from the join bundle). Chain verification is
// replaced by that exact match; nodes typically use self-signed certificates.
func PinnedHTTPClient(fingerprint string, timeout time.Duration) *http.Client {
	pin := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fingerprint), ":", ""))
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, //nolint:gosec // certificate pinning below replaces chain verification
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("peer presented no certificate")
				}
				sum := sha256.Sum256(rawCerts[0])
				if hex.EncodeToString(sum[:]) != pin {
					return errors.New("peer TLS certificate does not match the pinned fingerprint")
				}
				return nil
			},
		}},
	}
}
