package svctls

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"crypto/x509"
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

func allGroups() []tls.CurveID {
	return []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024, tls.X25519, tls.CurveP256, tls.CurveP384}
}

// want is ServerGroups(profile) less what the probe can't offer alone.
func want(profile string) []tls.CurveID {
	var out []tls.CurveID
	for _, g := range ServerGroups(profile) {
		if g == tls.X25519 && fips140.Enabled() {
			continue
		}
		out = append(out, g)
	}
	return out
}

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
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	host, _ := HostFor("kms-kmip")

	measure := func() []tls.CurveID {
		res, err := ProbeGroups(ctx, addr, host, roots, allGroups())
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
