package svctls

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func writeEdge(t *testing.T, path string, p EdgePolicy) {
	t.Helper()
	raw, _ := json.Marshal(PolicyFile{Version: 1, UpdatedAt: time.Now().UTC(), Services: map[string]ServicePolicy{}, Edge: &p})
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// edgeListener serves TLS 1.3 with the watcher's edge profile, as the KMIP
// listener does, and returns its address.
func edgeListener(t *testing.T, w *EdgeWatcher, id *Identity) string {
	t.Helper()
	base := &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return id.Certificate() }}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", w.ServerConfig(base))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }(c)
		}
	}()
	return ln.Addr().String()
}

func allGroups() []tls.CurveID { return ProbeGroupsAll() }

// want is what a listener with profile accepts: every group is measured,
// X25519 included in FIPS mode (probeGroupHello).
func want(profile string) []tls.CurveID { return ServerGroups(profile) }

// The edge profile is applied on every new handshake, with no restart, and
// the probe measures exactly the groups the listener accepts: a
// classical-only client is refused under pqc-required, a hybrid-only one
// under classical.
func TestEdgeProfileAppliedPerHandshakeAndMeasured(t *testing.T) {
	old := policyWatchInterval
	policyWatchInterval = 50 * time.Millisecond
	t.Cleanup(func() { policyWatchInterval = old })

	ca := newTestCA(t, "vecta-internal-services")
	id := enrolled(t, ca, "kms-kmip")
	path := filepath.Join(t.TempDir(), PolicyFileName)
	writeEdge(t, path, EdgePolicy{KXProfile: KXPQCRequired, Generation: 1})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	w := WatchEdge(ctx, path, t.Logf)
	addr := edgeListener(t, w, id)
	host, _ := HostFor("kms-kmip")
	pin := id.Leaf()

	measure := func() []tls.CurveID {
		res, err := ProbeGroups(ctx, addr, host, pin, allGroups())
		if err != nil {
			t.Fatal(err)
		}
		if res.Leaf == nil || res.Negotiated == 0 {
			t.Fatalf("probe recorded no certificate or group: %+v", res)
		}
		return res.Accepted
	}
	if got := measure(); !reflect.DeepEqual(got, want(KXPQCRequired)) {
		t.Fatalf("pqc-required accepts %v, want %v", got, want(KXPQCRequired))
	}

	writeEdge(t, path, EdgePolicy{KXProfile: KXClassical, Generation: 2})
	deadline := time.Now().Add(5 * time.Second)
	for w.Policy().Generation != 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := measure(); !reflect.DeepEqual(got, want(KXClassical)) {
		t.Fatalf("classical accepts %v, want %v", got, want(KXClassical))
	}
}

// An unreadable or invalid policy keeps the profile in force; it never
// silently falls back to a weaker one.
func TestEdgePolicyUnreadableKeepsCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), PolicyFileName)
	writeEdge(t, path, EdgePolicy{KXProfile: KXPQCRequired, Generation: 4})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	w := WatchEdge(ctx, path, t.Logf)
	if err := os.WriteFile(path, []byte(`{"edge":{"kx_profile":"none"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	w.refresh()
	if p := w.Policy(); p.KXProfile != KXPQCRequired || p.Generation != 4 {
		t.Fatalf("invalid policy replaced the one in force: %+v", p)
	}
	if _, err := ReadEdgePolicy(path); err == nil {
		t.Fatal("an unknown profile must be an error")
	}
}

// Envoy is given only groups it can name, in ServerGroups' order.
func TestEnvoyCurves(t *testing.T) {
	if got := EnvoyCurves(KXPQCRequired); !reflect.DeepEqual(got, []string{"X25519MLKEM768"}) {
		t.Fatalf("pqc-required: %v", got)
	}
	classical := []string{"X25519", "P-256", "P-384"}
	if fips140.Enabled() {
		classical = []string{"P-256", "P-384"}
	}
	if got := EnvoyCurves(KXClassical); !reflect.DeepEqual(got, classical) {
		t.Fatalf("classical: %v", got)
	}
	if got := EnvoyCurves(KXPQCPreferred); !reflect.DeepEqual(got, append([]string{"X25519MLKEM768"}, classical...)) {
		t.Fatalf("pqc-preferred: %v", got)
	}
}

// A listener serving another certificate than the installed one is not
// measured: the probe pins the certificate certs wrote.
func TestProbeRefusesAnotherCertificate(t *testing.T) {
	ca := newTestCA(t, "vecta-internal-services")
	id := enrolled(t, ca, "kms-kmip")
	other := enrolled(t, ca, "kms-keycore")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	path := filepath.Join(t.TempDir(), PolicyFileName)
	writeEdge(t, path, EdgePolicy{KXProfile: KXPQCPreferred})
	addr := edgeListener(t, WatchEdge(ctx, path, nil), id)
	if _, err := ProbeGroups(ctx, addr, "kmip", other.Leaf(), allGroups()); err == nil {
		t.Fatal("a listener serving another certificate must not be measured")
	}
}

// helloServer serves TLS 1.3 accepting only groups.
func helloServer(t *testing.T, id *Identity, groups []tls.CurveID) string {
	t.Helper()
	base := &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: groups,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return id.Certificate() }}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }(c)
		}
	}()
	return ln.Addr().String()
}

// The hand-built ClientHello reads the group a real TLS 1.3 server selects:
// X25519 when it accepts X25519, not accepted when it answers with a
// HelloRetryRequest for another group or refuses.
func TestHelloProbeReadsSelectedGroup(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("the Go test server can't select X25519 in FIPS mode")
	}
	ca := newTestCA(t, "vecta-internal-services")
	id := enrolled(t, ca, "kms-kmip")
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		groups []tls.CurveID
		want   bool
	}{
		{"x25519 only", []tls.CurveID{tls.X25519}, true},
		{"x25519 among others", []tls.CurveID{tls.CurveP256, tls.X25519}, true},
		{"p-256 only (HelloRetryRequest)", []tls.CurveID{tls.CurveP256}, false},
		{"hybrid only", []tls.CurveID{tls.X25519MLKEM768}, false},
	} {
		got, err := probeGroupHello(ctx, helloServer(t, id, tc.groups), "kmip", tls.X25519)
		if err != nil || got != tc.want {
			t.Fatalf("%s: accepted=%v err=%v, want %v", tc.name, got, err, tc.want)
		}
	}
	if _, err := probeGroupHello(ctx, "127.0.0.1:1", "kmip", tls.CurveP256); err == nil {
		t.Fatal("only X25519 has a hand-built share")
	}
}

// In FIPS mode X25519 is still measured, through the hand-built hello: a
// strict-mode listener (which can't accept it) is measured as refusing it.
func TestProbeMeasuresX25519InFIPSMode(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("runs with FIPS mode on or only (make test-fips-modes)")
	}
	ca := newTestCA(t, "vecta-internal-services")
	id := enrolled(t, ca, "kms-kmip")
	ctx := context.Background()
	res, err := ProbeGroups(ctx, helloServer(t, id, []tls.CurveID{tls.X25519, tls.CurveP256}), "kmip", id.Leaf(), allGroups())
	if err != nil {
		t.Fatal(err)
	}
	probedX := false
	for _, g := range res.Probed {
		probedX = probedX || g == tls.X25519
	}
	for _, g := range res.Accepted {
		if g == tls.X25519 {
			t.Fatal("a FIPS-mode Go server can't accept X25519 alone")
		}
	}
	if !probedX {
		t.Fatalf("X25519 must be measured in FIPS mode: %+v", res)
	}
}
