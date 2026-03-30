package sprawlscanner

// DefaultPatterns returns the built-in set of secret detection patterns.
func DefaultPatterns() []DetectionPattern {
	return []DetectionPattern{
		{
			Name:       "AWS Access Key ID",
			Regex:      `AKIA[0-9A-Z]{16}`,
			SecretType: SecretTypeAPIKey,
			Severity:   SeverityCritical,
		},
		{
			Name:             "AWS Secret Access Key",
			Regex:            `[0-9a-zA-Z/+=]{40}`,
			EntropyThreshold: 4.5,
			SecretType:       SecretTypeAPIKey,
			Severity:         SeverityCritical,
		},
		{
			Name:       "GitHub Personal Access Token",
			Regex:      `gh[ps]_[A-Za-z0-9_]{36,}`,
			SecretType: SecretTypeToken,
			Severity:   SeverityCritical,
		},
		{
			Name:       "GitLab Personal Access Token",
			Regex:      `glpat-[A-Za-z0-9\-]{20,}`,
			SecretType: SecretTypeToken,
			Severity:   SeverityCritical,
		},
		{
			Name:       "Slack Token",
			Regex:      `xox[baprs]-[0-9A-Za-z\-]{10,}`,
			SecretType: SecretTypeToken,
			Severity:   SeverityHigh,
		},
		{
			Name:       "Private Key",
			Regex:      `-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`,
			SecretType: SecretTypePrivateKey,
			Severity:   SeverityCritical,
		},
		{
			Name:       "JWT Token",
			Regex:      `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,
			SecretType: SecretTypeToken,
			Severity:   SeverityHigh,
		},
		{
			Name:             "Generic High-Entropy String",
			EntropyThreshold: 4.5,
			SecretType:       SecretTypeGeneric,
			Severity:         SeverityMedium,
		},
		{
			Name:       "Database Connection String",
			Regex:      `(postgres|mysql|mongodb)://[^\s]+`,
			SecretType: SecretTypeConnectionString,
			Severity:   SeverityHigh,
		},
		{
			Name:       "API Key with Common Prefix",
			Regex:      `(sk_live_|pk_live_|rk_live_|api_key_|apikey-)[A-Za-z0-9]{10,}`,
			SecretType: SecretTypeAPIKey,
			Severity:   SeverityHigh,
		},
		{
			Name:       "Google API Key",
			Regex:      `AIza[0-9A-Za-z\-_]{35}`,
			SecretType: SecretTypeAPIKey,
			Severity:   SeverityHigh,
		},
		{
			Name:       "Heroku API Key",
			Regex:      `[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
			SecretType: SecretTypeAPIKey,
			Severity:   SeverityHigh,
		},
		{
			Name:       "Generic Password in Config",
			Regex:      `(?i)(password|passwd|pwd|secret)\s*[=:]\s*['\"]?[^\s'\"]{8,}`,
			SecretType: SecretTypePassword,
			Severity:   SeverityMedium,
		},
	}
}
