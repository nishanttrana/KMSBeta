package ssrfguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// Every name the guard resolves goes through resolveHost, so there is one
// place where a test's lookups are answered.
//
// A test never resolves through real DNS. Until 13.8.0-beta one did
// (compliance registered a connection for s3.eu-west-1.amazonaws.com and
// expected it to be accepted), so the suite failed whenever a CI runner's
// resolver hiccuped and passed on the next run. In a test binary a lookup
// that no test has answered is an error that says so. A test answers names
// with SetResolverForTests; one that is about the real network (the live
// verification runs) asks for the system resolver with
// UseSystemResolverForTests.
var (
	resolverMu     sync.RWMutex
	resolverAnswer func(host string) ([]net.IP, error)
	resolverSystem bool
)

func resolveHost(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	resolverMu.RLock()
	answer, system := resolverAnswer, resolverSystem
	resolverMu.RUnlock()
	if answer != nil {
		return answer(host)
	}
	if testing.Testing() && !system {
		return nil, fmt.Errorf("a test looked up %q in real DNS; answer it with ssrfguard.SetResolverForTests (a test that needs DNS fails whenever DNS does)", host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// LookupNetIP resolves host for a service's own address checks, through the
// same resolver as the guard: a product name lookup has one reader, so a
// test answers it in one place (conformance name-resolution).
func LookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := resolveHost(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return out, nil
}

// SetResolverForTests answers the guard's lookups from names (host to
// addresses) until the returned function is called; any other name does not
// resolve. Tests only: conformance fails on a call outside a _test file.
func SetResolverForTests(names map[string][]string) (restore func()) {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	prevAnswer, prevSystem := resolverAnswer, resolverSystem
	resolverAnswer = func(host string) ([]net.IP, error) {
		addrs, ok := names[host]
		if !ok {
			return nil, &net.DNSError{Err: "no such host (test resolver)", Name: host, IsNotFound: true}
		}
		out := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, net.ParseIP(a))
		}
		return out, nil
	}
	return func() {
		resolverMu.Lock()
		defer resolverMu.Unlock()
		resolverAnswer, resolverSystem = prevAnswer, prevSystem
	}
}

// UseSystemResolverForTests lets a test resolve through the system resolver
// until the returned function is called. For tests that are about the real
// network and are skipped unless someone asks for them.
func UseSystemResolverForTests() (restore func()) {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	prevAnswer, prevSystem := resolverAnswer, resolverSystem
	resolverAnswer, resolverSystem = nil, true
	return func() {
		resolverMu.Lock()
		defer resolverMu.Unlock()
		resolverAnswer, resolverSystem = prevAnswer, prevSystem
	}
}
