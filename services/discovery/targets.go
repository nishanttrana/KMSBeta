package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"vecta-kms/pkg/svctls"
)

// Tenant-added TLS targets for the network scan (7.11.0-beta). Before, the
// scan read only DISCOVERY_TLS_ENDPOINTS, so a tenant could not name what to
// inventory. A target is a host and port the tenant's discovery.write holder
// chose; the scan only completes a TLS handshake with it and records the
// negotiated parameters and leaf certificate. Private (RFC 1918) addresses
// are allowed: scanning the customer's internal endpoints is the point.
// Refused, both when added and at dial time after DNS resolution: reserved
// addresses (loopback, link-local and cloud metadata, multicast,
// unspecified) and the KMS platform itself (7.13.0-beta), meaning every
// platform host in pkg/svctls and this container's own addresses. The dial
// check covers DISCOVERY_TLS_ENDPOINTS too. A tenant can't use the scan to
// probe keycore, Postgres, NATS or any other internal service, and the
// inventory never lists them: their certificates are in the PKI tab.

const maxTargetsPerTenant = 256

var (
	errInvalidTarget  = errors.New("invalid target")
	errTargetExists   = errors.New("target already added")
	errTargetLimit    = fmt.Errorf("at most %d targets per tenant", maxTargetsPerTenant)
	errReservedTarget = errors.New("address is loopback, link-local, multicast or unspecified")
	errPlatformTarget = errors.New("address belongs to the KMS platform's internal services")

	// extraPlatformHosts: platform containers that pkg/svctls doesn't list
	// because they don't enrol for mTLS (the SSH CLI container).
	extraPlatformHosts = []string{"hsm-integration"}

	reHostname = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$`)
)

// normalizeTarget returns a lower-case host (an IP literal or a DNS name)
// and a port in 1-65535, or errInvalidTarget.
func normalizeTarget(host string, port int) (string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("%w: port must be 1-65535", errInvalidTarget)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if reservedAddr(addr) {
			return "", fmt.Errorf("%w: %v", errInvalidTarget, errReservedTarget)
		}
		return addr.String(), nil
	}
	if isPlatformHost(host) {
		return "", errPlatformTarget
	}
	if len(host) == 0 || len(host) > 253 || !reHostname.MatchString(host) || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "", fmt.Errorf("%w: host must be a DNS name or IP address, without scheme or path", errInvalidTarget)
	}
	return strings.TrimSuffix(host, "."), nil
}

// reservedAddr: an address a tenant's target must never reach.
func reservedAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() ||
		a == netip.MustParseAddr("fd00:ec2::254") // AWS IPv6 instance metadata
}

// isPlatformHost: a bare platform hostname (keycore, postgres). Only the
// bare name: auth.example.com is a customer host. A longer name that
// resolves to the platform is caught at dial time by guardAddrs.
func isPlatformHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, h := range append(svctls.InternalHosts(), extraPlatformHosts...) {
		if host == h {
			return true
		}
	}
	return false
}

type dialControl = func(network, address string, c syscall.RawConn) error

// platformAddrs resolves every platform hostname and adds this container's
// own addresses. It runs once per scan, because container addresses change
// across restarts. A name that doesn't resolve (a service not deployed) is
// skipped.
func platformAddrs(ctx context.Context, lookup func(context.Context, string) ([]netip.Addr, error), own func() ([]net.Addr, error)) map[netip.Addr]bool {
	set := map[netip.Addr]bool{}
	for _, h := range append(svctls.InternalHosts(), extraPlatformHosts...) {
		addrs, _ := lookup(ctx, h)
		for _, a := range addrs {
			set[a.Unmap()] = true
		}
	}
	if ifs, err := own(); err == nil {
		for _, a := range ifs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				set[p.Addr().Unmap()] = true
			}
		}
	}
	return set
}

// newTargetGuard is the dial guard for one network scan.
func newTargetGuard(ctx context.Context) dialControl {
	platform := platformAddrs(ctx, func(ctx context.Context, h string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
	}, net.InterfaceAddrs)
	return guardAddrs(platform)
}

// guardAddrs refuses reserved addresses and those in platform.
func guardAddrs(platform map[netip.Addr]bool) dialControl {
	return func(network, address string, c syscall.RawConn) error {
		if err := refuseReservedAddr(network, address, c); err != nil {
			return err
		}
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if platform[ap.Addr().Unmap()] {
			return fmt.Errorf("refused %s: %w", ap.Addr(), errPlatformTarget)
		}
		return nil
	}
}

// refuseReservedAddr is a net.Dialer Control hook: it checks the address
// actually being dialled, after DNS resolution, so a name that resolves (or
// rebinds) to a reserved address is refused too.
func refuseReservedAddr(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	if reservedAddr(ap.Addr()) {
		return fmt.Errorf("refused %s: %w", ap.Addr(), errReservedTarget)
	}
	return nil
}

func (t ScanTarget) endpoint() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

func (s *Service) AddTarget(ctx context.Context, tenantID, host string, port int, actor string) (ScanTarget, error) {
	host, err := normalizeTarget(host, port)
	if err != nil {
		return ScanTarget{}, err
	}
	existing, err := s.store.ListTargets(ctx, tenantID)
	if err != nil {
		return ScanTarget{}, err
	}
	if len(existing) >= maxTargetsPerTenant {
		return ScanTarget{}, errTargetLimit
	}
	for _, t := range existing {
		if t.Host == host && t.Port == port {
			return ScanTarget{}, errTargetExists
		}
	}
	t := ScanTarget{ID: newID("target"), TenantID: tenantID, Host: host, Port: port, CreatedBy: actor}
	if err := s.store.CreateTarget(ctx, t); err != nil {
		return ScanTarget{}, err
	}
	t.CreatedAt = s.now()
	return t, nil
}

func (s *Service) ListTargets(ctx context.Context, tenantID string) ([]ScanTarget, error) {
	return s.store.ListTargets(ctx, tenantID)
}

func (s *Service) RemoveTarget(ctx context.Context, tenantID, id string) (ScanTarget, error) {
	items, err := s.store.ListTargets(ctx, tenantID)
	if err != nil {
		return ScanTarget{}, err
	}
	for _, t := range items {
		if t.ID == id {
			return t, s.store.DeleteTarget(ctx, tenantID, id)
		}
	}
	return ScanTarget{}, errNotFound
}
