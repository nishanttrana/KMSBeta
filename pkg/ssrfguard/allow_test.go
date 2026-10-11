package ssrfguard

import (
	"context"
	"strings"
	"testing"
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
