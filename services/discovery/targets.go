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
//
// Since 7.18.0-beta a target can be an SSH endpoint (protocol "ssh") and its
// host an address range in CIDR notation of at most 256 addresses. A range
// containing a reserved address is refused; platform addresses inside one
// are refused at dial time and counted as skipped.

const (
	maxTargetsPerTenant   = 256
	maxAddressesPerTenant = 4096
)

var (
	errInvalidTarget  = errors.New("invalid target")
	errTargetExists   = errors.New("target already added")
	errTargetLimit    = fmt.Errorf("at most %d targets and %d addresses per tenant", maxTargetsPerTenant, maxAddressesPerTenant)
	errReservedTarget = errors.New("address is loopback, link-local, multicast or unspecified")
	errPlatformTarget = errors.New("address belongs to the KMS platform's internal services")

	// extraPlatformHosts: platform containers that pkg/svctls doesn't list
	// because they don't enrol for mTLS (the SSH CLI container).
	extraPlatformHosts = []string{"hsm-integration"}

	reHostname = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$`)
)

// normalizeTarget returns a lower-case host (an IP literal, a DNS name or
// an address range) and checks the port is 1-65535, or errInvalidTarget.
func normalizeTarget(host string, port int) (string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("%w: port must be 1-65535", errInvalidTarget)
	}
	if strings.Contains(host, "/") {
		p, err := netip.ParsePrefix(host)
		if err != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return "", fmt.Errorf("%w: a range is CIDR notation, such as 10.0.4.0/24", errInvalidTarget)
		}
		if p = p.Masked(); p.Addr().BitLen()-p.Bits() > 8 {
			return "", fmt.Errorf("%w: a range is at most 256 addresses (/24, or /120 for IPv6)", errInvalidTarget)
		}
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			if reservedAddr(a) {
				return "", fmt.Errorf("%w: %s: %v", errInvalidTarget, a, errReservedTarget)
			}
		}
		return p.String(), nil
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

func (t ScanTarget) proto() string { return defaultString(t.Protocol, "tls") }

// addresses is how many endpoints the target expands to.
func (t ScanTarget) addresses() int {
	if p, err := netip.ParsePrefix(t.Host); err == nil {
		return len(prefixHosts(p))
	}
	return 1
}

// prefixHosts lists a range's addresses; an IPv4 range of four or more
// leaves out its network and broadcast addresses.
func prefixHosts(p netip.Prefix) []netip.Addr {
	p = p.Masked()
	if p.Addr().BitLen()-p.Bits() > 8 {
		return nil
	}
	var out []netip.Addr
	for a := p.Addr(); p.Contains(a); a = a.Next() {
		out = append(out, a)
	}
	if p.Addr().Is4() && p.Bits() <= 30 {
		out = out[1 : len(out)-1]
	}
	return out
}

func (s *Service) AddTarget(ctx context.Context, tenantID, host string, port int, protocol, actor string) (ScanTarget, error) {
	host, err := normalizeTarget(host, port)
	if err != nil {
		return ScanTarget{}, err
	}
	switch protocol = strings.ToLower(strings.TrimSpace(protocol)); protocol {
	case "":
		protocol = "tls"
	case "tls", "ssh":
	default:
		return ScanTarget{}, fmt.Errorf("%w: protocol must be tls or ssh", errInvalidTarget)
	}
	existing, err := s.store.ListTargets(ctx, tenantID)
	if err != nil {
		return ScanTarget{}, err
	}
	t := ScanTarget{ID: newID("target"), TenantID: tenantID, Host: host, Port: port, Protocol: protocol, CreatedBy: actor}
	addrs := t.addresses()
	for _, e := range existing {
		if e.Host == host && e.Port == port {
			return ScanTarget{}, errTargetExists
		}
		addrs += e.addresses()
	}
	if len(existing) >= maxTargetsPerTenant || addrs > maxAddressesPerTenant {
		return ScanTarget{}, errTargetLimit
	}
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
