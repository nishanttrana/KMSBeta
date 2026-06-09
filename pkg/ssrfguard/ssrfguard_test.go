package ssrfguard

import "testing"

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
