package ssrfguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Allow is a set of private networks an administrator approved for outbound
// calls (an on-premises SIEM, git server, object store or mail relay). The
// zero value approves nothing, so every function here then behaves like its
// unparameterised twin.
type Allow []*net.IPNet

// approvable are the only ranges an approval may sit inside: private
// addressing. Loopback, link-local (cloud metadata), multicast, reserved and
// documentation ranges can never be approved.
var approvable = mustCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("ssrfguard: " + err.Error())
		}
		out = append(out, n)
	}
	return out
}

// ParseCIDR returns cidr in canonical form if it may be approved: a network
// wholly inside private addressing.
func ParseCIDR(cidr string) (*net.IPNet, error) {
	ip, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("%q is not a network in CIDR form (10.20.0.0/16)", cidr)
	}
	if !ip.Equal(n.IP) {
		return nil, fmt.Errorf("%s has host bits set; did you mean %s?", cidr, n.String())
	}
	ones, _ := n.Mask.Size()
	for _, a := range approvable {
		aOnes, _ := a.Mask.Size()
		if a.Contains(n.IP) && ones >= aOnes {
			return n, nil
		}
	}
	return nil, fmt.Errorf("%s is not inside private addressing (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7); loopback, link-local and metadata addresses can't be approved", n.String())
}

// ParseAllow parses approved networks, refusing any that may not be approved.
func ParseAllow(cidrs []string) (Allow, error) {
	out := make(Allow, 0, len(cidrs))
	for _, c := range cidrs {
		n, err := ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func (a Allow) permits(ip net.IP) bool {
	for _, n := range a {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// blocked reports whether ip is refused: a blocked address no approval covers.
func (a Allow) blocked(ip net.IP) bool { return isBlockedIP(ip) && !a.permits(ip) }

// ValidateHost refuses a host that is, or resolves to, an address a is not
// allowed to reach.
func (a Allow) ValidateHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("a host is required")
	}
	lower := strings.ToLower(host)
	for _, b := range blockedHosts {
		if lower == b {
			return fmt.Errorf("host %q is blocked (cloud metadata / internal)", host)
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		if a.blocked(ip) {
			return fmt.Errorf("%s is a blocked address", ip)
		}
		return nil
	}
	addrs, err := resolveHost(context.Background(), host)
	if err != nil {
		return fmt.Errorf("host %q does not resolve: %w", host, err)
	}
	for _, ip := range addrs {
		if a.blocked(ip) {
			return fmt.Errorf("host %q resolves to blocked address %s", host, ip)
		}
	}
	return nil
}

// ValidateURL is ValidateWebhookURL with a's networks approved.
func (a Allow) ValidateURL(rawURL string) error {
	if len(a) == 0 {
		return ValidateWebhookURL(rawURL)
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("URL must use http or https scheme")
	}
	return a.ValidateHost(u.Hostname())
}

// DialContext is DialContext with a's networks approved: it resolves addr,
// refuses any address that is blocked and not approved, or that belongs to
// the platform itself (platform.go), and dials the address it checked.
func (a Allow) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := resolveHost(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s resolves to no address", host)
	}
	for _, ip := range ips {
		if a.blocked(ip) {
			return nil, fmt.Errorf("%s resolves to blocked IP %s", host, ip)
		}
		// An approved private address: never one of the platform's own.
		if isBlockedIP(ip) && platformAddr(ctx, ip) {
			return nil, fmt.Errorf("%s resolves to %s, which belongs to the KMS platform's internal services", host, ip)
		}
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}
