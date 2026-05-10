package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// resolveCountry returns a two-letter ISO 3166-1 alpha-2 country code for the
// given IP address.  Resolution order:
//  1. Private / RFC-reserved ranges → "internal"
//  2. GEOIP_SERVICE_URL env var → HTTP lookup against a configured sidecar
//     (ipinfo.io API shape: GET /<ip>/country returns a plain two-letter body)
//  3. Falls back to "" (unknown)
func resolveCountry(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if isPrivate(parsed) {
		return "internal"
	}
	if svcURL := strings.TrimSpace(os.Getenv("GEOIP_SERVICE_URL")); svcURL != "" {
		return httpGeoLookup(svcURL, ip)
	}
	return ""
}

// isPrivate returns true for all RFC-reserved address spaces.
func isPrivate(ip net.IP) bool {
	for _, cidr := range reservedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

var reservedCIDRs = func() []*net.IPNet {
	ranges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"169.254.0.0/16",
		"100.64.0.0/10",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
		"255.255.255.255/32",
		"0.0.0.0/8",
	}
	out := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, n, err := net.ParseCIDR(r)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}()

var geoClient = &http.Client{Timeout: 2 * time.Second}

func httpGeoLookup(baseURL string, ip string) string {
	url := strings.TrimRight(baseURL, "/") + "/" + ip + "/country"
	resp, err := geoClient.Get(url) //nolint:noctx
	if err != nil {
		return ""
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8))
	if err != nil {
		return ""
	}
	cc := strings.TrimSpace(strings.ToUpper(string(body)))
	if len(cc) == 2 {
		return cc
	}
	return ""
}
