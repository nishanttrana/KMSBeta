package ssrfguard

import (
	"context"
	"strings"
	"testing"
)

// In a test binary a name nobody answered does not go to real DNS: the
// lookup fails and says what to do. An answered name resolves to the answer,
// an address needs no lookup, and the answers end with the test.
func TestATestNeverResolvesThroughRealDNS(t *testing.T) {
	if _, err := resolveHost(context.Background(), "vecta-unanswered.example"); err == nil || !strings.Contains(err.Error(), "SetResolverForTests") {
		t.Fatalf("an unanswered name: %v", err)
	}
	if err := ValidateWebhookURL("https://vecta-unanswered.example/hook"); err == nil {
		t.Fatal("a URL whose host was never answered was accepted")
	}
	restore := SetResolverForTests(map[string][]string{"hooks.example": {"52.218.0.10", "10.0.0.5"}})
	ips, err := resolveHost(context.Background(), "hooks.example")
	if err != nil || len(ips) != 2 || ips[0].String() != "52.218.0.10" {
		t.Fatalf("an answered name: %v %v", ips, err)
	}
	// One of its addresses is private: the name is refused for that.
	if err := ValidateWebhookURL("https://hooks.example/x"); err == nil || !strings.Contains(err.Error(), "10.0.0.5") {
		t.Fatalf("a name with a private address: %v", err)
	}
	if _, err := resolveHost(context.Background(), "other.example"); err == nil {
		t.Fatal("a name outside the answers resolved")
	}
	if ips, err := resolveHost(context.Background(), "192.0.2.7"); err != nil || len(ips) != 1 {
		t.Fatalf("an address: %v %v", ips, err)
	}
	restore()
	if _, err := resolveHost(context.Background(), "hooks.example"); err == nil {
		t.Fatal("the answers outlived the test that gave them")
	}
}
