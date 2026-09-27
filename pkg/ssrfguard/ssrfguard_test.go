package ssrfguard

import (
	"context"
	"testing"
	"time"
)

func TestValidateWebhookURLAllowsPublicIPv4(t *testing.T) {
	if err := ValidateWebhookURL("http://8.8.8.8/webhook"); err != nil {
		t.Fatalf("expected public IPv4 webhook URL to be allowed, got %v", err)
	}
}

func TestValidateWebhookURLBlocksPrivateAndMappedPrivateIPv4(t *testing.T) {
	tests := []string{
		"http://127.0.0.1/webhook",
		"http://10.0.0.5/webhook",
		"http://[::ffff:127.0.0.1]/webhook",
	}
	for _, rawURL := range tests {
		t.Run(rawURL, func(t *testing.T) {
			if err := ValidateWebhookURL(rawURL); err == nil {
				t.Fatalf("expected %s to be blocked", rawURL)
			}
		})
	}
}

// The dialer refuses a blocked address even when validation was skipped or
// the name now resolves elsewhere; the client refuses plain HTTP redirects.
func TestDialContextRefusesBlockedAddresses(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:443", "169.254.169.254:80", "10.1.2.3:443", "localhost:443"} {
		if c, err := DialContext(context.Background(), "tcp", addr); err == nil {
			c.Close()
			t.Fatalf("dialed blocked %s", addr)
		}
	}
	if NewHTTPSClient(time.Second).CheckRedirect(nil, nil) == nil {
		t.Fatal("client follows redirects")
	}
}
