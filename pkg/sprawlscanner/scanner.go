package sprawlscanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"
)

// ScanSource defines the interface for a scannable source of secrets.
type ScanSource interface {
	Scan(ctx context.Context, config ScanConfig) ([]Finding, error)
	Name() string
}

// ScanConfig configures a scan operation.
type ScanConfig struct {
	TenantID         string            `json:"tenant_id"`
	SourceType       string            `json:"source_type"`
	ConnectionConfig map[string]string  `json:"connection_config"`
	Patterns         []DetectionPattern `json:"patterns"`
}

// Finding represents a discovered secret in a scanned source.
type Finding struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	SourceType     string    `json:"source_type"`
	Location       string    `json:"location"`
	LineNumber     int       `json:"line_number"`
	MatchedPattern string    `json:"matched_pattern"`
	Snippet        string    `json:"snippet"` // redacted
	Severity       Severity  `json:"severity"`
	SecretType     SecretType `json:"secret_type"`
	DetectedAt     time.Time `json:"detected_at"`
}

// Severity indicates the severity of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// SecretType categorizes the type of secret found.
type SecretType string

const (
	SecretTypeAPIKey      SecretType = "api_key"
	SecretTypePassword    SecretType = "password"
	SecretTypePrivateKey  SecretType = "private_key"
	SecretTypeToken       SecretType = "token"
	SecretTypeCertificate SecretType = "certificate"
	SecretTypeConnectionString SecretType = "connection_string"
	SecretTypeGeneric     SecretType = "generic"
)

// DetectionPattern defines a pattern for detecting secrets.
type DetectionPattern struct {
	Name             string     `json:"name"`
	Regex            string     `json:"regex"`
	EntropyThreshold float64    `json:"entropy_threshold,omitempty"`
	SecretType       SecretType `json:"secret_type"`
	Severity         Severity   `json:"severity"`
	compiled         *regexp.Regexp
}

// Compile compiles the regex pattern. Must be called before scanning.
func (p *DetectionPattern) Compile() error {
	if p.Regex == "" && p.EntropyThreshold <= 0 {
		return fmt.Errorf("pattern %q must have a regex or entropy threshold", p.Name)
	}
	if p.Regex != "" {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return fmt.Errorf("invalid regex in pattern %q: %w", p.Name, err)
		}
		p.compiled = re
	}
	return nil
}

// Scanner orchestrates secret sprawl detection across multiple sources.
type Scanner struct {
	sources  map[string]ScanSource
	store    FindingsStore
	audit    AuditPublisher
}

// AuditPublisher sends audit events for scanning operations.
type AuditPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

// NewScanner creates a new secrets sprawl scanner.
func NewScanner(store FindingsStore, audit AuditPublisher) *Scanner {
	return &Scanner{
		sources: make(map[string]ScanSource),
		store:   store,
		audit:   audit,
	}
}

// RegisterSource adds a scan source to the scanner.
func (s *Scanner) RegisterSource(source ScanSource) {
	s.sources[source.Name()] = source
}

// Scan runs a scan against the specified source using the given config.
// If no patterns are provided, the built-in default patterns are used.
func (s *Scanner) Scan(ctx context.Context, config ScanConfig) ([]Finding, error) {
	if config.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	source, ok := s.sources[config.SourceType]
	if !ok {
		return nil, fmt.Errorf("unknown source type: %s (registered: %v)", config.SourceType, s.sourceNames())
	}

	// Use default patterns if none provided
	if len(config.Patterns) == 0 {
		config.Patterns = DefaultPatterns()
	}

	// Compile all patterns
	for i := range config.Patterns {
		if err := config.Patterns[i].Compile(); err != nil {
			return nil, fmt.Errorf("failed to compile pattern: %w", err)
		}
	}

	findings, err := source.Scan(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("scan of %s failed: %w", config.SourceType, err)
	}

	// Assign IDs and timestamps to findings
	for i := range findings {
		if findings[i].ID == "" {
			findings[i].ID = generateFindingID()
		}
		if findings[i].TenantID == "" {
			findings[i].TenantID = config.TenantID
		}
		if findings[i].DetectedAt.IsZero() {
			findings[i].DetectedAt = time.Now().UTC()
		}
		// Redact the snippet: keep first 4 and last 4 chars, mask the middle
		findings[i].Snippet = redactSnippet(findings[i].Snippet)
	}

	// Persist findings
	if s.store != nil && len(findings) > 0 {
		if err := s.store.StoreFindings(ctx, findings); err != nil {
			return findings, fmt.Errorf("scan completed but failed to store findings: %w", err)
		}
	}

	// Audit event (best-effort)
	if s.audit != nil {
		auditPayload := fmt.Sprintf(
			`{"event":"sprawl.scan.completed","tenant_id":%q,"source_type":%q,"findings_count":%d}`,
			config.TenantID, config.SourceType, len(findings),
		)
		_ = s.audit.Publish(ctx, "audit.sprawl.scan", []byte(auditPayload))
	}

	return findings, nil
}

func (s *Scanner) sourceNames() []string {
	names := make([]string, 0, len(s.sources))
	for name := range s.sources {
		names = append(names, name)
	}
	return names
}

func generateFindingID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "finding-" + hex.EncodeToString(b)
}

// redactSnippet keeps the first 4 and last 4 chars, masking the middle with asterisks.
func redactSnippet(s string) string {
	if len(s) <= 12 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// ScanLine checks a single line against all compiled patterns and returns any findings.
func ScanLine(line string, lineNum int, location string, patterns []DetectionPattern) []Finding {
	var findings []Finding
	for _, p := range patterns {
		// Regex-based matching
		if p.compiled != nil {
			matches := p.compiled.FindAllString(line, -1)
			for _, m := range matches {
				// If entropy threshold is also set, verify it
				if p.EntropyThreshold > 0 && ShannonEntropy(m) < p.EntropyThreshold {
					continue
				}
				findings = append(findings, Finding{
					SourceType:     "",
					Location:       location,
					LineNumber:     lineNum,
					MatchedPattern: p.Name,
					Snippet:        m,
					Severity:       p.Severity,
					SecretType:     p.SecretType,
				})
			}
		}

		// Pure entropy-based matching (no regex, scan for high-entropy substrings)
		if p.compiled == nil && p.EntropyThreshold > 0 {
			tokens := extractTokens(line)
			for _, tok := range tokens {
				if len(tok) > 20 && ShannonEntropy(tok) > p.EntropyThreshold {
					findings = append(findings, Finding{
						SourceType:     "",
						Location:       location,
						LineNumber:     lineNum,
						MatchedPattern: p.Name,
						Snippet:        tok,
						Severity:       p.Severity,
						SecretType:     p.SecretType,
					})
				}
			}
		}
	}
	return findings
}

// extractTokens splits a line into contiguous non-whitespace tokens for entropy analysis.
func extractTokens(line string) []string {
	var tokens []string
	current := ""
	for _, r := range line {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if current != "" {
				tokens = append(tokens, current)
				current = ""
			}
		} else {
			current += string(r)
		}
	}
	if current != "" {
		tokens = append(tokens, current)
	}
	return tokens
}
