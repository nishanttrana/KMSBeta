// Package clientip answers one question for every service: which address did
// this request come from?
//
// A service never sees the caller's connection; the edge proxy does. Envoy
// appends the address it accepted the connection from to X-Forwarded-For
// (infra/envoy/envoy.yaml, use_remote_address). So the last entry of that
// header is the platform's own observation, and everything before it is
// whatever the caller chose to send. A request without the header came from
// another platform service (service listeners accept only internal mTLS),
// and its address is the connection's.
//
// The first entry was read as the caller's address until 11.8.0-beta: a
// caller who set the header chose its own audit source address, and a fresh
// login lockout counter for every guess. No other package may read
// X-Forwarded-For, X-Real-IP or a request's RemoteAddr: `make conformance`
// (client-address) fails on it.
package clientip

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Header is the header the edge proxy appends the observed address to.
const Header = "X-Forwarded-For"

// From returns the address the request came from, as the platform observed
// it: the entry the edge proxy appended, or the connection's own address
// when no proxy stood in between. It never returns an address the caller
// wrote. A last entry that is not an address is not trusted either: the
// answer is then the connection's address, never an earlier entry.
func From(r *http.Request) string {
	if r == nil {
		return ""
	}
	last := strings.Join(r.Header.Values(Header), ",")
	if i := strings.LastIndexByte(last, ','); i >= 0 {
		last = last[i+1:]
	}
	if addr, err := netip.ParseAddr(strings.TrimSpace(last)); err == nil {
		return addr.Unmap().String()
	}
	return peer(r.RemoteAddr)
}

// Set records addr as the address a forwarded request came from, replacing
// whatever the header held. Only a platform hop that has itself established
// the address calls it (the cluster forwarder, for a member it authenticated).
// An addr that is not an address clears the header.
func Set(r *http.Request, addr string) {
	r.Header.Del(Header)
	if parsed, err := netip.ParseAddr(strings.TrimSpace(addr)); err == nil {
		r.Header.Set(Header, parsed.Unmap().String())
	}
}

func peer(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return ap.Addr().Unmap().String()
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
