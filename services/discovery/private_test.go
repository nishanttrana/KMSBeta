package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

func prefixes(list ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range list {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// A credential goes to a private address only inside a range approved for
// the tenant; public addresses need no approval, and whatever the base
// guard refuses stays refused.
func TestCredentialGuard(t *testing.T) {
	approved := prefixes("10.4.0.0/24", "fd12:3456::/48")
	guard := credentialGuard(nil, approved)
	for addr, ok := range map[string]bool{
		"93.184.216.34:443":        true, // public
		"[2606:2800:220:1::1]:443": true,
		"10.4.0.20:9000":           true, // approved
		"[fd12:3456::9]:443":       true,
		"10.4.1.20:9000":           false, // private, outside the range
		"10.5.0.1:443":             false,
		"172.16.0.9:443":           false,
		"192.168.1.10:443":         false,
		"100.64.0.5:443":           false, // carrier-grade NAT
		"[fd99::1]:443":            false,
		"[::ffff:10.4.1.20]:443":   false, // IPv4-mapped
		"[::ffff:10.4.0.20]:443":   true,
	} {
		err := guard("tcp", addr, nil)
		if (err == nil) != ok || (err != nil && !errors.Is(err, errPrivateNotApproved)) {
			t.Errorf("%s: %v, want allowed=%v", addr, err, ok)
		}
	}
	// Nothing approved: no private address at all.
	if err := credentialGuard(nil, nil)("tcp", "10.4.0.20:443", nil); !errors.Is(err, errPrivateNotApproved) {
		t.Errorf("no approvals: %v", err)
	}
	// The scan's own guard comes first: an approval can't open what it refuses.
	base := guardAddrs(map[netip.Addr]bool{netip.MustParseAddr("10.4.0.7"): true})
	both := credentialGuard(base, prefixes("10.4.0.0/24", "169.254.0.0/16", "127.0.0.0/8"))
	for addr, want := range map[string]error{"10.4.0.7:443": errPlatformTarget, "169.254.169.254:80": errReservedTarget, "127.0.0.1:443": errReservedTarget, "10.4.0.8:443": nil} {
		if err := both("tcp", addr, nil); !errors.Is(err, want) || (want == nil && err != nil) {
			t.Errorf("%s: %v, want %v", addr, err, want)
		}
	}
	var _ dialControl = func(string, string, syscall.RawConn) error { return nil }
}

// privateListener listens on one of this machine's private addresses, when
// it has one.
func privateListener(t *testing.T) (net.Listener, netip.Addr) {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil || !p.Addr().Is4() || !privateAddr(p.Addr()) {
			continue
		}
		if l, err := net.Listen("tcp", net.JoinHostPort(p.Addr().String(), "0")); err == nil {
			return l, p.Addr()
		}
	}
	t.Skip("this machine has no private IPv4 address to listen on")
	return nil, netip.Addr{}
}

// End to end on a real private address: with a connection, a bucket or
// repository there is not dialled until its range is approved; without a
// connection it is reached as before.
func TestCredentialNeverReachesAnUnapprovedPrivateAddress(t *testing.T) {
	l, addr := privateListener(t)
	var accepted atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeXML(w, http.StatusOK, `<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`)
	}))
	srv.Listener = &countingListener{Listener: l, n: &accepted}
	srv.StartTLS()
	defer srv.Close()
	hostport := strings.TrimPrefix(srv.URL, "https://")
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	conn := s3Connection(addr.String())
	gitConn := ResolvedConnection{Type: "git", Endpoint: addr.String(), Fields: map[string]string{"token": "s3cret-token"}}
	b := Bucket{ID: "b1", TenantID: "t1", Provider: "s3", Endpoint: srv.URL, Name: "acme-artifacts", Region: "eu-west-1", ConnectionID: "c1"}
	r := Repository{ID: "r1", TenantID: "t1", URL: "https://" + hostport + "/acme/app", Provider: "gitlab", ConnectionID: "g1"}

	// Not approved: refused before a connection is made, for both sources.
	svc.conns = stubConnections{"c1": conn, "g1": gitConn}
	if _, err := svc.scanBucket(ctx, nil, b, "s", false); err == nil || !strings.Contains(err.Error(), errPrivateNotApproved.Error()) {
		t.Fatalf("bucket on an unapproved private address: %v", err)
	}
	if _, err := svc.scanRepository(ctx, nil, r, "s", 0); err == nil || !strings.Contains(err.Error(), errPrivateNotApproved.Error()) {
		t.Fatalf("repository on an unapproved private address: %v", err)
	}
	// Another network's approval does not cover it.
	conn.PrivateRanges, gitConn.PrivateRanges = []string{"10.255.255.0/24"}, []string{"10.255.255.0/24"}
	if other := netip.MustParsePrefix("10.255.255.0/24"); !other.Contains(addr) {
		svc.conns = stubConnections{"c1": conn, "g1": gitConn}
		if _, err := svc.scanBucket(ctx, nil, b, "s", false); err == nil || !strings.Contains(err.Error(), errPrivateNotApproved.Error()) {
			t.Fatalf("bucket with another range approved: %v", err)
		}
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections reached the private server before approval", n)
	}

	// Approved: the connection is made. (The test server's certificate is
	// not for this address, so the request stops at TLS, after the dial.)
	conn.PrivateRanges, gitConn.PrivateRanges = []string{netip.PrefixFrom(addr, 32).String()}, []string{netip.PrefixFrom(addr, 24).Masked().String()}
	svc.conns = stubConnections{"c1": conn, "g1": gitConn}
	if _, err := svc.scanBucket(ctx, nil, b, "s", false); err == nil || strings.Contains(err.Error(), errPrivateNotApproved.Error()) {
		t.Fatalf("bucket on an approved private address: %v", err)
	}
	if _, err := svc.scanRepository(ctx, nil, r, "s", 0); err == nil || strings.Contains(err.Error(), errPrivateNotApproved.Error()) {
		t.Fatalf("repository on an approved private address: %v", err)
	}
	if n := accepted.Load(); n < 2 {
		t.Fatalf("%d connections reached the approved private server, want 2", n)
	}

	// No connection, no credential: private addresses are scanned as before.
	before := accepted.Load()
	pub := b
	pub.ID, pub.ConnectionID = "b2", ""
	if _, err := svc.scanBucket(ctx, nil, pub, "s", false); err == nil || strings.Contains(err.Error(), errPrivateNotApproved.Error()) || accepted.Load() == before {
		t.Fatalf("public bucket on a private address: %v (%d new connections)", err, accepted.Load()-before)
	}
}

type countingListener struct {
	net.Listener
	n *atomic.Int32
}

func (c *countingListener) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil {
		c.n.Add(1)
	}
	return conn, err
}
