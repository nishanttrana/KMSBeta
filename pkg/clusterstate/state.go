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

const RoleFollower = "follower"

type State struct {
	NodeID             string
	Role               string
	PrimaryNodeID      string
	PrimaryURL         string
	PrimaryFingerprint string
	ForwardCredential  string
}

// IsMember reports whether lifecycle writes must go to a primary.
func (s State) IsMember() bool {
	return s.Role == RoleFollower && s.PrimaryURL != "" && s.ForwardCredential != ""
}

type Reader struct {
	static *State
	db     *sql.DB
	ttl    time.Duration
	mu     sync.Mutex
	cur    State
	loaded time.Time
}

func NewReader(db *sql.DB) *Reader { return &Reader{db: db, ttl: 10 * time.Second} }

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
	if r.db == nil {
		return State{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.loaded) < r.ttl {
		return r.cur
	}
	var s State
	err := r.db.QueryRowContext(ctx, `
SELECT node_id, role, primary_node_id, primary_url, primary_fingerprint, forward_credential
FROM cluster_local_state WHERE id = 1`).Scan(&s.NodeID, &s.Role, &s.PrimaryNodeID, &s.PrimaryURL, &s.PrimaryFingerprint, &s.ForwardCredential)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return r.cur // keep the last known state on a transient error
	}
	r.cur, r.loaded = s, time.Now()
	return s
}

// RunsPrimaryJobs reports whether this node runs background jobs that write
// replicated state (schedulers, sweeps, reconcilers): true on a standalone
// node or the primary. A member receives the results through replication;
// running them there too would diverge its copy or halt replication.
func RunsPrimaryJobs(ctx context.Context) bool { return !Default().Get(ctx).IsMember() }

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
