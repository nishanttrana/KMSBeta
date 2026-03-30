package compliance

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// Framework represents a supported compliance framework identifier.
type Framework string

const (
	SOC2TypeII     Framework = "soc2_type_ii"
	ISO27001       Framework = "iso27001"
	PCIDSS4        Framework = "pci_dss_4"
	FedRAMPModerate Framework = "fedramp_moderate"
	HIPAA          Framework = "hipaa"
	NIST80053      Framework = "nist_800_53"
	GDPR           Framework = "gdpr"
	CCPA           Framework = "ccpa"
)

// AllFrameworks returns every supported compliance framework.
func AllFrameworks() []Framework {
	return []Framework{
		SOC2TypeII, ISO27001, PCIDSS4, FedRAMPModerate,
		HIPAA, NIST80053, GDPR, CCPA,
	}
}

// Severity levels for compliance controls.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// AutomationLevel indicates how much of a control's assessment can be automated.
const (
	AutomationFull    = "full"
	AutomationPartial = "partial"
	AutomationManual  = "manual"
)

// Assessment status values.
const (
	StatusPass          = "pass"
	StatusFail          = "fail"
	StatusPartial       = "partial"
	StatusNotApplicable = "not_applicable"
)

// Evidence type values.
const (
	EvidenceTypeLog         = "log"
	EvidenceTypeConfig      = "config"
	EvidenceTypeScreenshot  = "screenshot"
	EvidenceTypeAttestation = "attestation"
)

// Control is a single compliance requirement within a framework.
type Control struct {
	ID              string    `json:"id"`
	Framework       Framework `json:"framework"`
	Category        string    `json:"category"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Severity        string    `json:"severity"`
	AutomationLevel string    `json:"automation_level"`
}

// ControlAssessment holds the result of evaluating a single control.
type ControlAssessment struct {
	ControlID        string     `json:"control_id"`
	Status           string     `json:"status"`
	Evidence         []Evidence `json:"evidence"`
	RemediationSteps []string   `json:"remediation_steps,omitempty"`
	LastChecked      time.Time  `json:"last_checked"`
	AutomatedCheck   bool       `json:"automated_check"`
}

// Evidence is an auditable artefact collected during an assessment.
type Evidence struct {
	Type        string    `json:"type"`
	Source      string    `json:"source"`
	Description string    `json:"description"`
	CollectedAt time.Time `json:"collected_at"`
	Hash        string    `json:"hash"` // SHA-256 integrity hash
}

// NewEvidence creates an Evidence entry and computes its integrity hash from the description and source.
func NewEvidence(evidenceType, source, description string) Evidence {
	now := time.Now().UTC()
	raw := fmt.Sprintf("%s|%s|%s|%d", evidenceType, source, description, now.UnixNano())
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
	return Evidence{
		Type:        evidenceType,
		Source:      source,
		Description: description,
		CollectedAt: now,
		Hash:        hash,
	}
}

// ComplianceReport is the top-level output of a compliance assessment run.
type ComplianceReport struct {
	ID          string              `json:"id"`
	TenantID    string              `json:"tenant_id"`
	Framework   Framework           `json:"framework"`
	GeneratedAt time.Time           `json:"generated_at"`
	Period      string              `json:"period"`
	OverallScore float64            `json:"overall_score"`
	Controls    []ControlAssessment `json:"controls"`
	Summary     ReportSummary       `json:"summary"`
	SignedHash  string              `json:"signed_hash"`
}

// ReportSummary aggregates high-level numbers from a compliance report.
type ReportSummary struct {
	TotalControls int      `json:"total_controls"`
	Passed        int      `json:"passed"`
	Failed        int      `json:"failed"`
	Partial       int      `json:"partial"`
	NotApplicable int      `json:"not_applicable"`
	CriticalGaps  []string `json:"critical_gaps,omitempty"`
}
