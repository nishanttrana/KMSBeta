package main

import (
	"strings"
	"testing"
)

func findingTypes(secs []detectedSecret) map[string]detectedSecret {
	out := map[string]detectedSecret{}
	for _, s := range secs {
		out[s.FindingType] = s
	}
	return out
}

func TestScanDetectsRealSecrets(t *testing.T) {
	content := `
# application config
db_host = localhost
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
github_token=ghp_1234567890abcdefghijklmnopqrstuvwxyz
api_key: "Z9f3Q8vK2mWpX7nL4hB6tR1sY0jD5gA3cE8uH2k"
log_level = debug
`
	secs := scanContent("config/app.conf", []byte(content))
	got := findingTypes(secs)

	for _, want := range []string{"aws_access_key_id", "aws_secret_access_key", "github_token"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected to detect %s, findings=%v", want, got)
		}
	}
	// AWS secret key is critical.
	if s := got["aws_secret_access_key"]; s.Severity != "critical" {
		t.Errorf("aws secret key severity=%q want critical", s.Severity)
	}
	// Location must carry the real line number, not a canned string.
	if s := got["aws_access_key_id"]; !strings.HasPrefix(s.Location, "config/app.conf:") {
		t.Errorf("unexpected location %q", s.Location)
	}
	// Secret must be masked, never echoed in full.
	if s := got["aws_secret_access_key"]; strings.Contains(s.ContextPreview, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") {
		t.Errorf("secret leaked in preview: %q", s.ContextPreview)
	}
}

func TestScanDetectsPrivateKey(t *testing.T) {
	content := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
	secs := scanContent("id_rsa", []byte(content))
	got := findingTypes(secs)
	if s, ok := got["private_key"]; !ok || s.Severity != "critical" {
		t.Fatalf("expected critical private_key finding, got %v", got)
	}
}

func TestScanDetectsJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	secs := scanContent("auth.json", []byte("token = "+jwt))
	if _, ok := findingTypes(secs)["jwt_token"]; !ok {
		t.Fatalf("expected jwt_token finding, got %v", secs)
	}
}

func TestScanIgnoresBenignContent(t *testing.T) {
	content := `
package main

// A perfectly ordinary source file.
func add(a, b int) int { return a + b }

const greeting = "hello, world"
var enabled = true
password = changeme
timeout = 30
`
	secs := scanContent("main.go", []byte(content))
	if len(secs) != 0 {
		t.Fatalf("expected no findings in benign content, got %v", secs)
	}
}

func TestScanGenericSecretRequiresEntropy(t *testing.T) {
	// Low-entropy placeholder must NOT fire...
	low := scanContent("a", []byte(`api_key = "aaaaaaaaaaaa"`))
	if _, ok := findingTypes(low)["generic_secret"]; ok {
		t.Error("low-entropy placeholder should not be flagged as a secret")
	}
	// ...but a genuinely random-looking value must.
	high := scanContent("b", []byte(`client_secret = "9zKf2Qp7Vx4Lm8Wn3Rb6Ht1Ys0Dj5Gc"`))
	if _, ok := findingTypes(high)["generic_secret"]; !ok {
		t.Error("high-entropy secret should be flagged")
	}
}

func TestShannonEntropy(t *testing.T) {
	if h := shannonEntropy("aaaaaaaa"); h != 0 {
		t.Errorf("uniform string entropy=%v want 0", h)
	}
	if h := shannonEntropy("9zKf2Qp7Vx4Lm8Wn"); h < 3.5 {
		t.Errorf("random-ish string entropy=%v want >=3.5", h)
	}
}

func TestMaskSecretRedacts(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	masked := maskSecret(secret)
	if strings.Contains(masked, "MDENG") || len(masked) >= len(secret) {
		t.Errorf("mask did not redact: %q", masked)
	}
	if !strings.HasPrefix(masked, "wJal") {
		t.Errorf("mask should keep short identifying prefix, got %q", masked)
	}
}
