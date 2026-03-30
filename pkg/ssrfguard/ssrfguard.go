// Package ssrfguard provides URL validation helpers to prevent Server-Side
// Request Forgery (SSRF) attacks. It blocks requests to private/internal IPs,
// cloud metadata endpoints, and link-local addresses.
package ssrfguard

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Private and reserved CIDR ranges that must never be reached via
// user-controlled URLs.
var blockedCIDRs []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local / cloud metadata
		"0.0.0.0/8",
		"100.64.0.0/10", // CGN
		"192.0.0.0/24",
		"192.0.2.0/24",   // TEST-NET-1
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved
		"::1/128",         // IPv6 loopback
		"fc00::/7",        // IPv6 unique local
		"fe80::/10",       // IPv6 link-local
		"ff00::/8",        // IPv6 multicast
		"::ffff:0:0/96",   // IPv4-mapped IPv6
	} {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil {
			blockedCIDRs = append(blockedCIDRs, network)
		}
	}
}

// blockedHosts are hostname patterns that should always be denied,
// regardless of DNS resolution.
var blockedHosts = []string{
	"metadata.google.internal",
	"metadata.google.com",
	"169.254.169.254",
	"[fd00:ec2::254]",
}

// ValidateWebhookURL checks that a URL is safe to make outbound HTTP requests
// to. It rejects private IPs, cloud metadata endpoints, non-http(s) schemes,
// and hostnames that resolve to internal addresses.
func ValidateWebhookURL(rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return errors.New("webhook URL is required")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errors.New("webhook URL must use http or https scheme")
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return errors.New("webhook URL must have a hostname")
	}

	// Block known metadata hostnames.
	lower := strings.ToLower(hostname)
	for _, blocked := range blockedHosts {
		if lower == blocked {
			return fmt.Errorf("webhook URL hostname %q is blocked (cloud metadata / internal)", hostname)
		}
	}

	// If hostname is a literal IP, check it directly.
	if ip := net.ParseIP(hostname); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("webhook URL resolves to blocked IP %s", ip.String())
		}
		return nil
	}

	// Resolve hostname and check all IPs.
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return fmt.Errorf("webhook URL hostname resolution failed: %w", err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip != nil && isBlockedIP(ip) {
			return fmt.Errorf("webhook URL hostname %q resolves to blocked IP %s", hostname, addr)
		}
	}
	return nil
}

func isBlockedIP(ip net.IP) bool {
	for _, cidr := range blockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
