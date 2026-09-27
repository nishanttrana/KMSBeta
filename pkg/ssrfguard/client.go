package ssrfguard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// errRedirect refuses redirects: an outbound endpoint that redirects could
// point the platform at an address that was never validated.
var errRedirect = errors.New("redirects are not followed for outbound deliveries")

// DialContext resolves addr, refuses any blocked address, and dials the
// address it checked, so a DNS answer cannot change between validation and
// connection (DNS rebinding).
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s resolves to no address", host)
	}
	for _, ip := range ips {
		if isBlockedIP(ip.IP) {
			return nil, fmt.Errorf("%s resolves to blocked IP %s", host, ip.IP)
		}
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

// NewHTTPSClient returns a client for user-configured external endpoints:
// HTTPS only at TLS 1.3, every connection through DialContext, no redirects.
func NewHTTPSClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:         DialContext,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13},
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
			Proxy:               nil, // a proxy would bypass the address check
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
	}
}
