package main

import (
	"strings"
	"time"
)

// CryptoperiodPolicy maps a key purpose/algorithm pair to its NIST SP
// 800-57 recommended cryptoperiod. The reconciler consults this table to
// decide when a key must be rotated regardless of operator-set rotation
// dates; it never extends a cryptoperiod, only shortens.
type CryptoperiodPolicy struct {
	defaults map[string]time.Duration
}

// NewCryptoperiodPolicy returns the default NIST 800-57 policy table.
// Operators can override individual entries via SetCryptoperiod but the
// shipped defaults follow:
//
//   symmetric encrypt     2 years
//   symmetric MAC/key-wrap 2 years
//   signing (private)     1 year
//   ephemeral / DEK       30 days
//   master / KEK          5 years
//
// Reasoning: shorter cryptoperiods limit blast radius if material leaks,
// at the cost of more frequent rotations. The values match the upper
// bounds in SP 800-57 Part 1 Rev. 5 §5.3.5 Table 1.
func NewCryptoperiodPolicy() *CryptoperiodPolicy {
	year := 365 * 24 * time.Hour
	return &CryptoperiodPolicy{
		defaults: map[string]time.Duration{
			"symmetric_encrypt": 2 * year,
			"symmetric_mac":     2 * year,
			"key_wrap":          2 * year,
			"signing":           1 * year,
			"ephemeral":         30 * 24 * time.Hour,
			"dek":               30 * 24 * time.Hour,
			"master":            5 * year,
		},
	}
}

// SetCryptoperiod overrides one entry. Zero values are ignored.
func (p *CryptoperiodPolicy) SetCryptoperiod(category string, d time.Duration) {
	if d > 0 {
		p.defaults[strings.ToLower(strings.TrimSpace(category))] = d
	}
}

// For returns the cryptoperiod for a key's category. Unknown categories
// receive the most conservative default (1 year) so a misclassified key
// is rotated more aggressively, not less.
func (p *CryptoperiodPolicy) For(purpose, algorithm, keyType string) time.Duration {
	cat := classifyCategory(purpose, algorithm, keyType)
	if d, ok := p.defaults[cat]; ok {
		return d
	}
	return 365 * 24 * time.Hour
}

// classifyCategory derives the cryptoperiod category from the key's
// purpose, algorithm, and type. Conservative: anything we don't recognise
// is treated as a signing key (the shortest of the long-lived categories).
func classifyCategory(purpose, algorithm, keyType string) string {
	p := strings.ToLower(strings.TrimSpace(purpose))
	a := strings.ToLower(strings.TrimSpace(algorithm))
	t := strings.ToLower(strings.TrimSpace(keyType))
	switch {
	case p == "master" || t == "master" || strings.Contains(p, "kek"):
		return "master"
	case strings.Contains(p, "dek"), strings.Contains(p, "ephemeral"), t == "ephemeral":
		return "ephemeral"
	case strings.Contains(p, "sign"), strings.HasPrefix(a, "rsa-sign"), strings.HasPrefix(a, "ecdsa"),
		strings.HasPrefix(a, "ml-dsa"), strings.HasPrefix(a, "slh-dsa"):
		return "signing"
	case strings.Contains(p, "wrap"), strings.HasPrefix(a, "aes-kw"):
		return "key_wrap"
	case strings.Contains(p, "mac"), strings.HasPrefix(a, "hmac"):
		return "symmetric_mac"
	default:
		return "symmetric_encrypt"
	}
}

// IsExpired returns true when the key's age exceeds its cryptoperiod.
// Zero-valued createdAt is treated as "unknown" and never expires — the
// reconciler logs and audits these so operators can backfill metadata.
func (p *CryptoperiodPolicy) IsExpired(createdAt time.Time, purpose, algorithm, keyType string) bool {
	if createdAt.IsZero() {
		return false
	}
	return time.Since(createdAt) > p.For(purpose, algorithm, keyType)
}
