package ssrfguard

import (
	"context"
	"net"
	"sync"
	"time"

	"vecta-kms/pkg/svctls"
)

// The KMS's own addresses. Its containers sit on a private network, so a
// range an administrator approves can contain them. An approval is for the
// customer's systems: a dial under an Allow refuses any address a platform
// hostname resolves to, and this host's own, whatever is approved.

// extraPlatformHosts: platform containers pkg/svctls doesn't list because
// they don't enrol for mTLS.
var extraPlatformHosts = []string{"hsm-integration"}

const platformTTL = time.Minute

var (
	platformMu  sync.Mutex
	platformAt  time.Time
	platformSet map[string]bool

	// Variables so a test can answer.
	lookupPlatform = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		ips, err := resolveHost(ctx, host)
		out := make([]net.IPAddr, 0, len(ips))
		for _, ip := range ips {
			out = append(out, net.IPAddr{IP: ip})
		}
		return out, err
	}
	ownAddrs = net.InterfaceAddrs
)

// platformAddr reports whether ip belongs to the platform. The set is
// resolved at most once a minute (container addresses change across
// restarts); a name that doesn't resolve, a service not deployed, is skipped.
func platformAddr(ctx context.Context, ip net.IP) bool {
	platformMu.Lock()
	defer platformMu.Unlock()
	if platformSet == nil || time.Since(platformAt) > platformTTL {
		platformSet, platformAt = resolvePlatform(ctx), time.Now()
	}
	return platformSet[ip.String()]
}

func resolvePlatform(ctx context.Context) map[string]bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		set = map[string]bool{}
	)
	for _, h := range append(svctls.InternalHosts(), extraPlatformHosts...) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, _ := lookupPlatform(ctx, h)
			mu.Lock()
			for _, a := range addrs {
				set[a.IP.String()] = true
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ifs, err := ownAddrs(); err == nil {
		for _, a := range ifs {
			if ip, _, err := net.ParseCIDR(a.String()); err == nil {
				set[ip.String()] = true
			}
		}
	}
	return set
}
