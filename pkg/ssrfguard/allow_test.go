package ssrfguard

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Only private addressing can be approved: an approval for loopback,
// link-local (cloud metadata) or a public range is refused, so the allowlist
// can't be used to reach the platform's own host or a metadata service.
func TestParseCIDRApprovesPrivateAddressingOnly(t *testing.T) {
	for _, ok := range []string{"10.20.0.0/16", "172.16.4.0/24", "192.168.1.10/32", "100.64.0.0/10", "fd12:3456::/32"} {
		if _, err := ParseCIDR(ok); err != nil {
			t.Fatalf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"127.0.0.0/8", "127.0.0.1/32", "169.254.169.254/32", "169.254.0.0/16", "0.0.0.0/0", "8.8.8.0/24",
		"10.0.0.0/7", "::1/128", "fe80::/10", "224.0.0.0/4", "10.20.0.5/16", "not-a-cidr"} {
		if _, err := ParseCIDR(bad); err == nil {
			t.Fatalf("%s was approved", bad)
		}
	}
}

// An approved network is reachable; every other blocked address stays
// refused, at validation and again at dial time.
func TestAllowReachesOnlyApprovedNetworks(t *testing.T) {
	allow, err := ParseAllow([]string{"10.20.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if err := allow.ValidateURL("https://10.20.3.4/hook"); err != nil {
		t.Fatalf("approved address refused: %v", err)
	}
	for _, u := range []string{"https://10.21.0.1/", "https://127.0.0.1/", "https://169.254.169.254/latest", "https://192.168.1.1/"} {
		if err := allow.ValidateURL(u); err == nil {
			t.Fatalf("%s allowed", u)
		}
	}
	if err := (Allow{}).ValidateURL("https://10.20.3.4/hook"); err == nil {
		t.Fatal("an empty allowlist approved a private address")
	}
	if _, err := allow.DialContext(context.Background(), "tcp", "127.0.0.1:9"); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("dial to loopback: %v", err)
	}
	if _, err := allow.DialContext(context.Background(), "tcp", "10.21.0.1:9"); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("dial outside the approved network: %v", err)
	}
}

// An approved range can contain the platform's own containers. A dial under
// it still refuses them, and this host's own address.
func TestAllowNeverReachesThePlatform(t *testing.T) {
	platformMu.Lock()
	platformSet = nil
	platformMu.Unlock()
	oldLookup, oldOwn := lookupPlatform, ownAddrs
	t.Cleanup(func() {
		lookupPlatform, ownAddrs = oldLookup, oldOwn
		platformMu.Lock()
		platformSet = nil
		platformMu.Unlock()
	})
	lookupPlatform = func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host == "keycore" {
			return []net.IPAddr{{IP: net.ParseIP("10.20.0.9")}}, nil
		}
		return nil, errors.New("no such host")
	}
	ownAddrs = func() ([]net.Addr, error) {
		_, n, _ := net.ParseCIDR("10.20.0.7/16")
		return []net.Addr{&net.IPNet{IP: net.ParseIP("10.20.0.7"), Mask: n.Mask}}, nil
	}
	allow, err := ParseAllow([]string{"10.20.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"10.20.0.9:443", "10.20.0.7:443"} {
		if _, err := allow.DialContext(context.Background(), "tcp", addr); err == nil || !strings.Contains(err.Error(), "KMS platform") {
			t.Fatalf("dial to the platform's %s: %v", addr, err)
		}
	}
	// The client built from an allowance dials through the same guard.
	client := allow.NewHTTPSClient(2 * time.Second)
	if _, err := client.Get("https://10.20.0.9/hook"); err == nil || !strings.Contains(err.Error(), "KMS platform") {
		t.Fatalf("client reached the platform: %v", err)
	}
	if _, err := client.Get("https://10.21.0.1/hook"); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("client reached an unapproved private address: %v", err)
	}
}
