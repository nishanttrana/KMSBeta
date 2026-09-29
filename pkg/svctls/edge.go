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

// ProbeGroupsAll is every group a listener is measured for, whatever this
// process's FIPS mode (X25519 is measured through probeGroupHello when Go
// won't offer it).
func ProbeGroupsAll() []tls.CurveID {
	return append(append([]tls.CurveID{}, hybridGroups...), tls.X25519, tls.CurveP256, tls.CurveP384)
}

// ProbeResult is what a listener was measured to accept.
type ProbeResult struct {
	Probed     []tls.CurveID     // groups offered alone
	Accepted   []tls.CurveID     // of Probed, those the server selected
	Negotiated tls.CurveID       // chosen when every group Go can offer is offered
	Leaf       *x509.Certificate // the certificate the listener served (== pin)
}

// errNotPinned refuses a listener that serves another certificate.
var errNotPinned = errors.New("the listener does not serve the installed certificate")

// ProbeGroups measures which groups the TLS 1.3 server at addr accepts: one
// full handshake offering every group Go can offer (it must succeed and the
// server must present exactly pin, so the probe proves the listener runs
// the installed certificate), then one ClientHello per group offering only
// it. Go completes those handshakes itself, except X25519 in FIPS mode,
// which Go won't offer alone: for it the probe sends its own ClientHello
// and reads which group the ServerHello selects (probeGroupHello). No
// application data is sent.
func ProbeGroups(ctx context.Context, addr, serverName string, pin *x509.Certificate, groups []tls.CurveID) (ProbeResult, error) {
	if pin == nil {
		return ProbeResult{}, errors.New("edge probe: no installed certificate to pin")
	}
	dial := func(offer []tls.CurveID) (tls.ConnectionState, error) {
		d := tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 5 * time.Second},
			Config: &tls.Config{
				MinVersion: tls.VersionTLS13, ServerName: serverName, CurvePreferences: offer,
				// Pinned, not chain-verified: the only certificate accepted is
				// the one certs installed (an external CA's root may not be in
				// any pool this process has).
				InsecureSkipVerify: true, //nolint:gosec // replaced by the pin in VerifyConnection
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 || !cs.PeerCertificates[0].Equal(pin) {
						return errNotPinned
					}
					return nil
				},
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
	var goOffers []tls.CurveID
	for _, g := range groups {
		res.Probed = append(res.Probed, g)
		if g == tls.X25519 && fips140.Enabled() {
			continue
		}
		goOffers = append(goOffers, g)
	}
	cs, err := dial(goOffers)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("edge probe %s: %w", addr, err)
	}
	res.Negotiated, res.Leaf = cs.CurveID, cs.PeerCertificates[0]
	for _, g := range res.Probed {
		var ok bool
		if g == tls.X25519 && fips140.Enabled() {
			ok, err = probeGroupHello(ctx, addr, serverName, g)
			if err != nil {
				return ProbeResult{}, fmt.Errorf("edge probe %s (%s): %w", addr, g, err)
			}
		} else {
			got, derr := dial([]tls.CurveID{g})
			ok = derr == nil && got.CurveID == g
		}
		if ok {
			res.Accepted = append(res.Accepted, g)
		}
	}
	return res, nil
}
