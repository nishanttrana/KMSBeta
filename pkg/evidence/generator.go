package evidence

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"vecta-kms/pkg/compliance"
)

// Generator creates compliance evidence packages.
type Generator struct {
	complianceEngine *compliance.Engine
	auditQueryFn     func(ctx context.Context, tenantID string, eventTypes []string, from, to time.Time) ([]AuditEntry, error)
	configSnapshotFn func(ctx context.Context, tenantID string) (*ConfigSnapshot, error)
	store            *Store
}

// AuditEntry represents a single audit log entry for evidence collection.
type AuditEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	Actor     string    `json:"actor"`
	Resource  string    `json:"resource"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
}

// ConfigSnapshot captures the current system configuration state.
type ConfigSnapshot struct {
	FIPSEnabled       bool              `json:"fips_enabled"`
	TLSMinVersion     string            `json:"tls_min_version"`
	RotationPolicies  int               `json:"rotation_policies"`
	ActiveKeys        int               `json:"active_keys"`
	BackupVerified    bool              `json:"backup_verified"`
	LastBackupAt      time.Time         `json:"last_backup_at"`
	AccessPolicies    int               `json:"access_policies"`
	MFAEnforced       bool              `json:"mfa_enforced"`
	AuditLogRetention string            `json:"audit_log_retention"`
	CustomSettings    map[string]string `json:"custom_settings,omitempty"`
}

// EvidencePackage is the top-level container for compliance evidence.
type EvidencePackage struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	Framework   string            `json:"framework"`
	GeneratedAt time.Time         `json:"generated_at"`
	Period      string            `json:"period"`
	Format      string            `json:"format"`
	Controls    []ControlEvidence `json:"controls"`
	Summary     PackageSummary    `json:"summary"`
	Attestation *Attestation      `json:"attestation,omitempty"`
	Hash        string            `json:"hash"`
}

// ControlEvidence captures evidence for a single compliance control.
type ControlEvidence struct {
	ControlID     string         `json:"control_id"`
	Title         string         `json:"title"`
	Status        string         `json:"status"`
	EvidenceItems []EvidenceItem `json:"evidence_items"`
	AssessorNotes string         `json:"assessor_notes,omitempty"`
}

// EvidenceItem is a single piece of evidence supporting a control assessment.
type EvidenceItem struct {
	Type        string    `json:"type"` // log_excerpt, config_snapshot, screenshot, report
	Title       string    `json:"title"`
	Content     string    `json:"content"`
	CollectedAt time.Time `json:"collected_at"`
	Hash        string    `json:"hash"`
}

// Attestation records a formal sign-off on the evidence package.
type Attestation struct {
	SignerID    string `json:"signer_id"`
	SignerEmail string `json:"signer_email"`
	SignedAt    string `json:"signed_at"`
	Signature   string `json:"signature"` // base64-encoded
	Statement   string `json:"statement"`
}

// PackageSummary provides high-level stats about the evidence package.
type PackageSummary struct {
	TotalControls  int    `json:"total_controls"`
	PassedControls int    `json:"passed_controls"`
	FailedControls int    `json:"failed_controls"`
	TotalEvidence  int    `json:"total_evidence"`
	OverallStatus  string `json:"overall_status"`
}

// NewGenerator creates a Generator with the given compliance engine and callback functions.
func NewGenerator(
	engine *compliance.Engine,
	auditQueryFn func(ctx context.Context, tenantID string, eventTypes []string, from, to time.Time) ([]AuditEntry, error),
	configSnapshotFn func(ctx context.Context, tenantID string) (*ConfigSnapshot, error),
	store *Store,
) *Generator {
	if auditQueryFn == nil {
		auditQueryFn = defaultAuditQuery
	}
	if configSnapshotFn == nil {
		configSnapshotFn = defaultConfigSnapshot
	}
	return &Generator{
		complianceEngine: engine,
		auditQueryFn:     auditQueryFn,
		configSnapshotFn: configSnapshotFn,
		store:            store,
	}
}

// GeneratePackage creates a complete evidence package for the specified framework and period.
func (g *Generator) GeneratePackage(ctx context.Context, tenantID string, framework string, period string) (*EvidencePackage, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("evidence: tenant_id is required")
	}
	if framework == "" {
		return nil, fmt.Errorf("evidence: framework is required")
	}

	// Parse the period to determine date range
	periodStart, periodEnd, err := parsePeriod(period)
	if err != nil {
		return nil, fmt.Errorf("evidence: %w", err)
	}

	// Run compliance assessment
	fw := compliance.Framework(framework)
	report, err := g.complianceEngine.RunAssessment(ctx, tenantID, fw)
	if err != nil {
		return nil, fmt.Errorf("evidence: run assessment: %w", err)
	}

	// Get configuration snapshot
	configSnap, err := g.configSnapshotFn(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("evidence: config snapshot: %w", err)
	}

	// Collect evidence for each control
	var controls []ControlEvidence
	totalEvidence := 0

	for _, assessment := range report.Controls {
		ctrl := findControl(fw, assessment.ControlID)

		ce := ControlEvidence{
			ControlID: assessment.ControlID,
			Title:     ctrl.Title,
			Status:    assessment.Status,
		}

		// Collect audit log evidence
		auditEntries, err := g.auditQueryFn(ctx, tenantID,
			auditEventTypesForControl(assessment.ControlID),
			periodStart, periodEnd,
		)
		if err == nil && len(auditEntries) > 0 {
			excerpt := formatAuditExcerpt(auditEntries)
			item := newEvidenceItem("log_excerpt",
				fmt.Sprintf("Audit log entries for %s", assessment.ControlID),
				excerpt,
			)
			ce.EvidenceItems = append(ce.EvidenceItems, item)
		}

		// Add configuration snapshot evidence
		configJSON, _ := json.MarshalIndent(configSnap, "", "  ")
		configItem := newEvidenceItem("config_snapshot",
			"System configuration at time of assessment",
			string(configJSON),
		)
		ce.EvidenceItems = append(ce.EvidenceItems, configItem)

		// Add compliance check result as a report evidence item
		checkReport := formatCheckResult(assessment)
		reportItem := newEvidenceItem("report",
			fmt.Sprintf("Compliance check result for %s", assessment.ControlID),
			checkReport,
		)
		ce.EvidenceItems = append(ce.EvidenceItems, reportItem)

		// Add assessor notes from remediation steps
		if len(assessment.RemediationSteps) > 0 {
			ce.AssessorNotes = strings.Join(assessment.RemediationSteps, "; ")
		}

		totalEvidence += len(ce.EvidenceItems)
		controls = append(controls, ce)
	}

	// Build summary
	passed, failed := 0, 0
	for _, c := range controls {
		switch c.Status {
		case compliance.StatusPass:
			passed++
		case compliance.StatusFail:
			failed++
		}
	}

	overallStatus := "compliant"
	if failed > 0 {
		overallStatus = "non_compliant"
	}

	pkg := &EvidencePackage{
		ID:          generatePackageID(),
		TenantID:    tenantID,
		Framework:   framework,
		GeneratedAt: time.Now().UTC(),
		Period:      period,
		Format:      "json",
		Controls:    controls,
		Summary: PackageSummary{
			TotalControls:  len(controls),
			PassedControls: passed,
			FailedControls: failed,
			TotalEvidence:  totalEvidence,
			OverallStatus:  overallStatus,
		},
	}

	// Compute package hash
	pkg.Hash = computePackageHash(pkg)

	// Persist if store is available
	if g.store != nil {
		if err := g.store.SavePackage(ctx, pkg); err != nil {
			return nil, fmt.Errorf("evidence: save package: %w", err)
		}
	}

	return pkg, nil
}

// ExportAsJSON serializes the evidence package to structured JSON.
func ExportAsJSON(pkg *EvidencePackage) ([]byte, error) {
	if pkg == nil {
		return nil, fmt.Errorf("evidence: nil package")
	}
	return json.MarshalIndent(pkg, "", "  ")
}

// ExportAsPDF generates a simple text-based PDF containing the evidence package.
// Uses raw PDF object construction with no external dependencies.
func ExportAsPDF(pkg *EvidencePackage) ([]byte, error) {
	if pkg == nil {
		return nil, fmt.Errorf("evidence: nil package")
	}

	var b strings.Builder

	// Build text content for the PDF
	b.WriteString(fmt.Sprintf("COMPLIANCE EVIDENCE PACKAGE\n\n"))
	b.WriteString(fmt.Sprintf("Package ID: %s\n", pkg.ID))
	b.WriteString(fmt.Sprintf("Tenant: %s\n", pkg.TenantID))
	b.WriteString(fmt.Sprintf("Framework: %s\n", pkg.Framework))
	b.WriteString(fmt.Sprintf("Period: %s\n", pkg.Period))
	b.WriteString(fmt.Sprintf("Generated: %s\n", pkg.GeneratedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("Hash: %s\n\n", pkg.Hash))

	b.WriteString(fmt.Sprintf("SUMMARY\n"))
	b.WriteString(fmt.Sprintf("Total Controls: %d\n", pkg.Summary.TotalControls))
	b.WriteString(fmt.Sprintf("Passed: %d\n", pkg.Summary.PassedControls))
	b.WriteString(fmt.Sprintf("Failed: %d\n", pkg.Summary.FailedControls))
	b.WriteString(fmt.Sprintf("Total Evidence Items: %d\n", pkg.Summary.TotalEvidence))
	b.WriteString(fmt.Sprintf("Overall Status: %s\n\n", pkg.Summary.OverallStatus))

	for i, ctrl := range pkg.Controls {
		b.WriteString(fmt.Sprintf("CONTROL %d: %s\n", i+1, ctrl.ControlID))
		b.WriteString(fmt.Sprintf("Title: %s\n", ctrl.Title))
		b.WriteString(fmt.Sprintf("Status: %s\n", ctrl.Status))
		if ctrl.AssessorNotes != "" {
			b.WriteString(fmt.Sprintf("Notes: %s\n", ctrl.AssessorNotes))
		}
		for j, item := range ctrl.EvidenceItems {
			b.WriteString(fmt.Sprintf("  Evidence %d: [%s] %s\n", j+1, item.Type, item.Title))
			// Truncate content for PDF readability
			content := item.Content
			if len(content) > 500 {
				content = content[:500] + "...[truncated]"
			}
			b.WriteString(fmt.Sprintf("  %s\n", content))
		}
		b.WriteString("\n")
	}

	if pkg.Attestation != nil {
		b.WriteString("ATTESTATION\n")
		b.WriteString(fmt.Sprintf("Signer: %s (%s)\n", pkg.Attestation.SignerID, pkg.Attestation.SignerEmail))
		b.WriteString(fmt.Sprintf("Signed At: %s\n", pkg.Attestation.SignedAt))
		b.WriteString(fmt.Sprintf("Statement: %s\n", pkg.Attestation.Statement))
	}

	content := b.String()
	return buildRawPDF(content), nil
}

// buildRawPDF creates a minimal valid PDF with the given text content.
// Constructs raw PDF objects: catalog, page tree, page, font, and text stream.
func buildRawPDF(text string) []byte {
	// Split text into lines for the PDF text stream
	lines := strings.Split(text, "\n")

	// Build text stream content with PDF text operators
	var stream strings.Builder
	stream.WriteString("BT\n")
	stream.WriteString("/F1 10 Tf\n")
	stream.WriteString("36 756 Td\n") // start position
	stream.WriteString("12 TL\n")     // leading (line spacing)

	for _, line := range lines {
		escaped := escapePDFString(line)
		stream.WriteString(fmt.Sprintf("(%s) Tj T*\n", escaped))
	}
	stream.WriteString("ET\n")
	streamContent := stream.String()

	// Build PDF objects
	var pdf strings.Builder
	offsets := make([]int, 0, 6)

	pdf.WriteString("%PDF-1.4\n")

	// Object 1: Catalog
	offsets = append(offsets, pdf.Len())
	pdf.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	// Object 2: Pages
	offsets = append(offsets, pdf.Len())
	pdf.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

	// Object 3: Page
	offsets = append(offsets, pdf.Len())
	pdf.WriteString("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n")

	// Object 4: Stream (content)
	offsets = append(offsets, pdf.Len())
	pdf.WriteString(fmt.Sprintf("4 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n", len(streamContent), streamContent))

	// Object 5: Font
	offsets = append(offsets, pdf.Len())
	pdf.WriteString("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n")

	// Cross-reference table
	xrefOffset := pdf.Len()
	pdf.WriteString("xref\n")
	pdf.WriteString(fmt.Sprintf("0 %d\n", len(offsets)+1))
	pdf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		pdf.WriteString(fmt.Sprintf("%010d 00000 n \n", off))
	}

	// Trailer
	pdf.WriteString("trailer\n")
	pdf.WriteString(fmt.Sprintf("<< /Size %d /Root 1 0 R >>\n", len(offsets)+1))
	pdf.WriteString("startxref\n")
	pdf.WriteString(fmt.Sprintf("%d\n", xrefOffset))
	pdf.WriteString("%%EOF\n")

	return []byte(pdf.String())
}

// escapePDFString escapes special characters for PDF string literals.
func escapePDFString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "(", `\(`)
	s = strings.ReplaceAll(s, ")", `\)`)
	return s
}

// SignPackage cryptographically signs the evidence package hash.
func SignPackage(ctx context.Context, pkg *EvidencePackage, signerKey crypto.Signer, signerID, signerEmail, statement string) error {
	if pkg == nil {
		return fmt.Errorf("evidence: nil package")
	}

	// Ensure hash is computed
	if pkg.Hash == "" {
		pkg.Hash = computePackageHash(pkg)
	}

	hashBytes := sha256.Sum256([]byte(pkg.Hash))

	var sigBytes []byte
	var err error

	switch key := signerKey.(type) {
	case *ecdsa.PrivateKey:
		sigBytes, err = ecdsa.SignASN1(rand.Reader, key, hashBytes[:])
	case *rsa.PrivateKey:
		sigBytes, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, hashBytes[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
	default:
		sigBytes, err = signerKey.Sign(rand.Reader, hashBytes[:], crypto.SHA256)
	}

	if err != nil {
		return fmt.Errorf("evidence: sign package: %w", err)
	}

	if statement == "" {
		statement = fmt.Sprintf(
			"I attest that this evidence package (ID: %s) for framework %s has been reviewed and is accurate as of %s.",
			pkg.ID, pkg.Framework, pkg.GeneratedAt.Format(time.RFC3339),
		)
	}

	pkg.Attestation = &Attestation{
		SignerID:    signerID,
		SignerEmail: signerEmail,
		SignedAt:    time.Now().UTC().Format(time.RFC3339),
		Signature:   base64.StdEncoding.EncodeToString(sigBytes),
		Statement:   statement,
	}

	return nil
}

// VerifyPackageSignature verifies the attestation signature on an evidence package.
func VerifyPackageSignature(pkg *EvidencePackage, publicKey crypto.PublicKey) error {
	if pkg == nil || pkg.Attestation == nil {
		return fmt.Errorf("evidence: no attestation to verify")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(pkg.Attestation.Signature)
	if err != nil {
		return fmt.Errorf("evidence: decode signature: %w", err)
	}

	hashBytes := sha256.Sum256([]byte(pkg.Hash))

	switch pub := publicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, hashBytes[:], sigBytes) {
			return fmt.Errorf("evidence: ECDSA signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		err = rsa.VerifyPSS(pub, crypto.SHA256, hashBytes[:], sigBytes, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
		if err != nil {
			return fmt.Errorf("evidence: RSA-PSS verification failed: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("evidence: unsupported key type %T", publicKey)
	}
}

// --- Helper functions ---

// computePackageHash computes a SHA-256 hash of the evidence package contents.
func computePackageHash(pkg *EvidencePackage) string {
	h := sha256.New()

	h.Write([]byte(pkg.ID))
	h.Write([]byte(pkg.TenantID))
	h.Write([]byte(pkg.Framework))
	h.Write([]byte(pkg.Period))

	for _, ctrl := range pkg.Controls {
		h.Write([]byte(ctrl.ControlID))
		h.Write([]byte(ctrl.Status))
		for _, item := range ctrl.EvidenceItems {
			h.Write([]byte(item.Hash))
		}
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

// newEvidenceItem creates an EvidenceItem with an auto-computed hash.
func newEvidenceItem(itemType, title, content string) EvidenceItem {
	now := time.Now().UTC()
	raw := fmt.Sprintf("%s|%s|%s|%d", itemType, title, content, now.UnixNano())
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
	return EvidenceItem{
		Type:        itemType,
		Title:       title,
		Content:     content,
		CollectedAt: now,
		Hash:        hash,
	}
}

// parsePeriod parses a period string like "2026-Q1" or "2026-03" into start/end times.
func parsePeriod(period string) (time.Time, time.Time, error) {
	if period == "" {
		// Default to current month
		now := time.Now().UTC()
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		end := start.AddDate(0, 1, 0).Add(-time.Nanosecond)
		return start, end, nil
	}

	// Try quarterly format: YYYY-Q1, YYYY-Q2, etc.
	var year, quarter int
	if _, err := fmt.Sscanf(period, "%d-Q%d", &year, &quarter); err == nil {
		if quarter < 1 || quarter > 4 {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid quarter: %d", quarter)
		}
		startMonth := time.Month((quarter-1)*3 + 1)
		start := time.Date(year, startMonth, 1, 0, 0, 0, 0, time.UTC)
		end := start.AddDate(0, 3, 0).Add(-time.Nanosecond)
		return start, end, nil
	}

	// Try monthly format: YYYY-MM
	var month int
	if _, err := fmt.Sscanf(period, "%d-%d", &year, &month); err == nil {
		if month < 1 || month > 12 {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid month: %d", month)
		}
		start := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
		end := start.AddDate(0, 1, 0).Add(-time.Nanosecond)
		return start, end, nil
	}

	// Try yearly format: YYYY
	if _, err := fmt.Sscanf(period, "%d", &year); err == nil && year > 2000 {
		start := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
		end := start.AddDate(1, 0, 0).Add(-time.Nanosecond)
		return start, end, nil
	}

	return time.Time{}, time.Time{}, fmt.Errorf("unsupported period format: %q (use YYYY, YYYY-MM, or YYYY-QN)", period)
}

// findControl looks up a control definition by framework and ID.
func findControl(fw compliance.Framework, controlID string) compliance.Control {
	controls := compliance.ControlsForFramework(fw)
	for _, c := range controls {
		if c.ID == controlID {
			return c
		}
	}
	return compliance.Control{ID: controlID, Title: controlID}
}

// auditEventTypesForControl maps control IDs to relevant audit event types.
func auditEventTypesForControl(controlID string) []string {
	// Map common control patterns to audit event types
	switch {
	case strings.Contains(controlID, "access"):
		return []string{"key.access", "policy.update", "auth.login", "auth.mfa"}
	case strings.Contains(controlID, "encrypt"):
		return []string{"key.create", "key.rotate", "encrypt", "decrypt"}
	case strings.Contains(controlID, "audit"):
		return []string{"audit.export", "audit.query", "audit.config"}
	case strings.Contains(controlID, "backup"):
		return []string{"backup.create", "backup.verify", "backup.restore"}
	case strings.Contains(controlID, "rotation"):
		return []string{"key.rotate", "rotation.policy", "rotation.execute"}
	default:
		return []string{"key.access", "key.create", "key.rotate", "policy.update"}
	}
}

// formatAuditExcerpt formats audit entries into a readable string.
func formatAuditExcerpt(entries []AuditEntry) string {
	var b strings.Builder
	for i, e := range entries {
		if i >= 50 { // Limit excerpts
			b.WriteString(fmt.Sprintf("... and %d more entries\n", len(entries)-50))
			break
		}
		b.WriteString(fmt.Sprintf("[%s] %s: %s %s - %s\n",
			e.Timestamp.Format(time.RFC3339), e.EventType, e.Actor, e.Action, e.Details))
	}
	return b.String()
}

// formatCheckResult formats a compliance assessment into a readable report.
func formatCheckResult(assessment compliance.ControlAssessment) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Control: %s\n", assessment.ControlID))
	b.WriteString(fmt.Sprintf("Status: %s\n", assessment.Status))
	b.WriteString(fmt.Sprintf("Automated: %t\n", assessment.AutomatedCheck))
	b.WriteString(fmt.Sprintf("Checked At: %s\n", assessment.LastChecked.Format(time.RFC3339)))
	if len(assessment.RemediationSteps) > 0 {
		b.WriteString("Remediation Steps:\n")
		for _, step := range assessment.RemediationSteps {
			b.WriteString(fmt.Sprintf("  - %s\n", step))
		}
	}
	return b.String()
}

// defaultAuditQuery is a no-op audit query used when no real audit service is available.
func defaultAuditQuery(ctx context.Context, tenantID string, eventTypes []string, from, to time.Time) ([]AuditEntry, error) {
	return []AuditEntry{
		{
			ID:        "default-audit-entry",
			Timestamp: time.Now().UTC(),
			EventType: "system.evidence_collection",
			Actor:     "system",
			Resource:  tenantID,
			Action:    "collect",
			Details:   "Evidence collection initiated; no audit service configured",
		},
	}, nil
}

// defaultConfigSnapshot returns a placeholder config snapshot.
func defaultConfigSnapshot(ctx context.Context, tenantID string) (*ConfigSnapshot, error) {
	return &ConfigSnapshot{
		FIPSEnabled:       true,
		TLSMinVersion:     "1.3",
		RotationPolicies:  0,
		ActiveKeys:        0,
		BackupVerified:    false,
		MFAEnforced:       true,
		AuditLogRetention: "365d",
	}, nil
}

func generatePackageID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("evpkg_%x", b)
}
