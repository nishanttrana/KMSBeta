package svctls

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// External edge key exchange (docs/SECURITY/INTERNAL_TLS.md, "External edge
// key exchange"). The KMS has two listeners outside the platform network:
// Envoy's HTTPS edge (443) and the KMIP listener (5696). A root
// administrator picks one key-exchange profile for both; certs publishes it
// in the policy file (Edge) and as EdgeCurvesFileName for Envoy, which can't
// read JSON. The KMIP listener applies it on every handshake
// (EdgeServerConfig); Envoy's entry script hot-restarts with the new
// ecdh_curves (infra/envoy/entry.sh). Certs measures both by handshake.

const (
	// EdgeIdentity keys the edge policy in the certs policy table.
	EdgeIdentity = "vecta-edge"
	// EdgeCurvesFileName holds Envoy's ecdh_curves, comma separated.
	EdgeCurvesFileName = "edge-ecdh-curves"
)

// EdgePolicy is the published edge entry.
type EdgePolicy struct {
	KXProfile  string `json:"kx_profile"`
	Generation int64  `json:"generation"`
}

// DefaultEdgePolicy applies when certs has published none.
func DefaultEdgePolicy() EdgePolicy { return EdgePolicy{KXProfile: KXPQCPreferred} }

// ReadEdgePolicy returns the edge entry of the policy file at path, or the
// default when the file or the entry is absent.
func ReadEdgePolicy(path string) (EdgePolicy, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return DefaultEdgePolicy(), nil
	}
	if err != nil {
		return DefaultEdgePolicy(), err
	}
	var f PolicyFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return DefaultEdgePolicy(), fmt.Errorf("mTLS policy %s: %w", path, err)
	}
	if f.Edge == nil {
		return DefaultEdgePolicy(), nil
	}
	if !contains(KXProfiles, f.Edge.KXProfile) {
		return DefaultEdgePolicy(), fmt.Errorf("edge key-exchange profile %q is not one of %s", f.Edge.KXProfile, strings.Join(KXProfiles, ", "))
	}
	return *f.Edge, nil
}

// envoyGroupNames are the groups Envoy's TLS library (BoringSSL) accepts in
// ecdh_curves, by the name it expects.
var envoyGroupNames = map[tls.CurveID]string{
	tls.X25519MLKEM768: "X25519MLKEM768",
	tls.X25519:         "X25519",
	tls.CurveP256:      "P-256",
	tls.CurveP384:      "P-384",
}

// EnvoyCurves are Envoy's ecdh_curves for profile: the groups ServerGroups
// gives a Go listener, less those Envoy can't name.
func EnvoyCurves(profile string) []string {
	var out []string
	for _, g := range EnvoyGroups(profile) {
		out = append(out, envoyGroupNames[g])
	}
	return out
}

// EnvoyGroups are EnvoyCurves as group IDs.
func EnvoyGroups(profile string) []tls.CurveID {
	var out []tls.CurveID
	for _, g := range ServerGroups(profile) {
		if _, ok := envoyGroupNames[g]; ok {
			out = append(out, g)
		}
	}
	return out
}

// EdgeWatcher holds the edge profile a listener applies, re-read from the
// policy file every policyWatchInterval.
type EdgeWatcher struct {
	path    string
	current atomic.Pointer[EdgePolicy]
	logf    func(string, ...interface{})
}

// WatchEdge reads the edge policy at path now and then on a ticker until ctx
// ends. logf may be nil.
func WatchEdge(ctx context.Context, path string, logf func(string, ...interface{})) *EdgeWatcher {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	w := &EdgeWatcher{path: path, logf: logf}
	w.refresh()
	go func() {
		t := time.NewTicker(policyWatchInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				w.refresh()
			}
		}
	}()
	return w
}

func (w *EdgeWatcher) refresh() {
	p, err := ReadEdgePolicy(w.path)
	if err != nil {
		// Keep what is applied rather than fall back to the default.
		if cur := w.current.Load(); cur != nil {
			w.logf("edge key-exchange policy unreadable (%v); keeping %s", err, cur.KXProfile)
			return
		}
		w.logf("edge key-exchange policy unreadable (%v); using %s", err, p.KXProfile)
	}
	if cur := w.current.Load(); cur == nil || *cur != p {
		w.logf("edge key exchange: %s (generation %d)", p.KXProfile, p.Generation)
	}
	w.current.Store(&p)
}

// Policy is the profile in force.
func (w *EdgeWatcher) Policy() EdgePolicy { return *w.current.Load() }

// ServerConfig returns base with the edge profile's groups applied to every
// new handshake, so a change takes effect without a restart.
func (w *EdgeWatcher) ServerConfig(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	cfg.CurvePreferences = ServerGroups(w.Policy().KXProfile)
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		c.CurvePreferences = ServerGroups(w.Policy().KXProfile)
		return c, nil
	}
	return cfg
}

// PolicyFile is where this identity reads the published policy.
func (id *Identity) PolicyFile() string { return id.policyFile }

// ProbeResult is what a listener was measured to accept.
type ProbeResult struct {
	Probed     []tls.CurveID     // groups offered alone (in FIPS mode Go won't offer X25519 alone)
	Accepted   []tls.CurveID     // of Probed, those the server completed a handshake with
	Negotiated tls.CurveID       // chosen when every probed group is offered
	Leaf       *x509.Certificate // the certificate the listener served
}

// ProbeGroups measures which groups the TLS 1.3 server at addr accepts: one
// handshake offering all of them (it must succeed, or the listener is
// unreachable or untrusted), then one handshake per group offering only it.
// No application data is sent; a server that wants a client certificate
// refuses only after the key exchange, which a TLS 1.3 client has finished.
func ProbeGroups(ctx context.Context, addr, serverName string, roots *x509.CertPool, groups []tls.CurveID) (ProbeResult, error) {
	dial := func(offer []tls.CurveID) (tls.ConnectionState, error) {
		d := tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 5 * time.Second},
			Config: &tls.Config{
				MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: serverName,
				CurvePreferences: offer,
			},
		}
		hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		conn, err := d.DialContext(hctx, "tcp", addr)
		if err != nil {
			return tls.ConnectionState{}, err
		}
		defer conn.Close() //nolint:errcheck
		return conn.(*tls.Conn).ConnectionState(), nil
	}
	var res ProbeResult
	for _, g := range groups {
		if g == tls.X25519 && fips140.Enabled() {
			continue
		}
		res.Probed = append(res.Probed, g)
	}
	cs, err := dial(res.Probed)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("edge probe %s: %w", addr, err)
	}
	res.Negotiated = cs.CurveID
	if len(cs.PeerCertificates) > 0 {
		res.Leaf = cs.PeerCertificates[0]
	}
	for _, g := range res.Probed {
		if got, err := dial([]tls.CurveID{g}); err == nil && got.CurveID == g {
			res.Accepted = append(res.Accepted, g)
		}
	}
	return res, nil
}
