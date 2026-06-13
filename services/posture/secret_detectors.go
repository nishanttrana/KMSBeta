package main

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"strings"
)

// credentialFingerprint is the cross-service join key between a leaked secret
// and the KMS key that protects it. It MUST be computed identically here and
// in keycore's credential-binding registry: lowercase hex SHA-256 of the raw
// secret value (no surrounding quotes or whitespace). It is non-reversible, so
// it is safe to store and pass between services.
func credentialFingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Real secret detection engine. scanContent runs a fixed rule set plus a
// generic high-entropy assignment detector over arbitrary text and returns
// concrete findings with true line numbers, masked previews and measured
// Shannon entropy. No content, no findings — there is no simulation here.

type detectorRule struct {
	findingType string
	severity    string
	description string
	re          *regexp.Regexp
	// secretGroup is the capture group holding the sensitive value used for
	// masking and entropy; 0 means the whole match.
	secretGroup int
	// entropyMin, when > 0, requires the secret group's Shannon entropy to
	// meet this bar before the match is reported (suppresses placeholders).
	entropyMin float64
}

// detectorRules are compiled once at package init. Patterns favour precision
// (anchored prefixes, fixed lengths) to keep the false-positive rate low.
var detectorRules = []detectorRule{
	{
		findingType: "private_key",
		severity:    "critical",
		description: "PEM-encoded private key material",
		re:          regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
	},
	{
		findingType: "aws_secret_access_key",
		severity:    "critical",
		description: "AWS secret access key assignment",
		re:          regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+]{40})["']?`),
		secretGroup: 1,
	},
	{
		findingType: "aws_access_key_id",
		severity:    "high",
		description: "AWS access key ID",
		re:          regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b`),
	},
	{
		findingType: "gcp_service_account_key",
		severity:    "critical",
		description: "GCP service-account private key",
		re:          regexp.MustCompile(`"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----`),
	},
	{
		findingType: "github_token",
		severity:    "high",
		description: "GitHub personal access / OAuth token",
		re:          regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36}\b`),
	},
	{
		findingType: "slack_token",
		severity:    "high",
		description: "Slack API token",
		re:          regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,48}\b`),
	},
	{
		findingType: "slack_webhook",
		severity:    "medium",
		description: "Slack incoming webhook URL",
		re:          regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}`),
	},
	{
		findingType: "google_api_key",
		severity:    "high",
		description: "Google API key",
		re:          regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
	},
	{
		findingType: "stripe_secret_key",
		severity:    "critical",
		description: "Stripe live secret key",
		re:          regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`),
	},
	{
		findingType: "jwt_token",
		severity:    "medium",
		description: "JSON Web Token",
		re:          regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
	},
	{
		// Not a secret in itself, but a Vecta KMS key identifier appearing in
		// source/config/logs is an exposure indicator — and the join key that
		// lets the unified console correlate a leaked reference with anomalous
		// usage of that same key. The id is emitted in clear (see scanContent).
		findingType: "kms_key_reference",
		severity:    "low",
		description: "Vecta KMS key identifier referenced in scanned content",
		re:          regexp.MustCompile(`\bkey_[0-9a-f]{16}\b`),
	},
	{
		// Generic catch-all: a secret-ish identifier assigned a long value.
		// Gated on entropy so things like PASSWORD=changeme don't fire.
		findingType: "generic_secret",
		severity:    "medium",
		description: "High-entropy value assigned to a secret-like identifier",
		re:          regexp.MustCompile(`(?i)(?:secret|token|password|passwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret)["']?\s*[=:]\s*["']?([^\s"'<>{}]{12,})`),
		secretGroup: 1,
		entropyMin:  3.5,
	},
}

// shannonEntropy returns the Shannon entropy (bits/byte) of s.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// maskSecret redacts the middle of a secret, keeping a short identifying
// prefix so findings are actionable without re-exposing the credential.
func maskSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	keep := 4
	if len(secret) > 40 {
		keep = 6
	}
	return secret[:keep] + strings.Repeat("*", 8) + secret[len(secret)-2:]
}

// lineNumberAt returns the 1-based line number for a byte offset in data.
func lineNumberAt(data []byte, offset int) int {
	if offset > len(data) {
		offset = len(data)
	}
	line := 1
	for i := 0; i < offset; i++ {
		if data[i] == '\n' {
			line++
		}
	}
	return line
}

// scanContent runs every detector over data and returns deduplicated findings.
// path is used only to build the human-readable location string.
func scanContent(path string, data []byte) []detectedSecret {
	if len(data) == 0 {
		return nil
	}
	text := string(data)
	seen := map[string]struct{}{}
	var out []detectedSecret

	for _, rule := range detectorRules {
		matches := rule.re.FindAllStringSubmatchIndex(text, -1)
		for _, m := range matches {
			secret := text[m[0]:m[1]]
			secretStart := m[0]
			if rule.secretGroup > 0 && len(m) > 2*rule.secretGroup+1 && m[2*rule.secretGroup] >= 0 {
				secret = text[m[2*rule.secretGroup]:m[2*rule.secretGroup+1]]
				secretStart = m[2*rule.secretGroup]
			}
			entropy := shannonEntropy(secret)
			if rule.entropyMin > 0 && entropy < rule.entropyMin {
				continue
			}
			line := lineNumberAt(data, secretStart)
			// Key references are not secrets: emit the id in clear so the
			// unified console can correlate on it. Everything else is masked.
			preview := maskSecret(secret)
			if rule.findingType == "kms_key_reference" {
				preview = secret
			}
			// Dedupe identical (type, line, preview) hits within a file.
			dk := rule.findingType + "|" + path + "|" + itoa(line) + "|" + preview
			if _, ok := seen[dk]; ok {
				continue
			}
			seen[dk] = struct{}{}
			sev := rule.severity
			// Escalate generic hits that look like real high-entropy keys.
			if rule.findingType == "generic_secret" && entropy >= 4.5 {
				sev = "high"
			}
			out = append(out, detectedSecret{
				FindingType:    rule.findingType,
				Severity:       sev,
				Description:    rule.description,
				Location:       path + ":" + itoa(line),
				ContextPreview: preview,
				Entropy:        round2(entropy),
				Fingerprint:    credentialFingerprint(secret),
			})
		}
	}
	return out
}

type detectedSecret struct {
	FindingType    string
	Severity       string
	Description    string
	Location       string
	ContextPreview string
	Entropy        float64
	Fingerprint    string
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
