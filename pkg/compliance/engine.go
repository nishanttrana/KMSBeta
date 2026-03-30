package compliance

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// AutoChecker is the interface that each automated compliance check must implement.
type AutoChecker interface {
	Check(ctx context.Context, tenantID string) (ControlAssessment, error)
}

// Engine orchestrates automated compliance assessments across multiple frameworks.
type Engine struct {
	mu       sync.RWMutex
	checkers map[string]AutoChecker // controlID -> checker
}

// NewEngine creates a compliance engine with an empty checker registry.
func NewEngine() *Engine {
	return &Engine{
		checkers: make(map[string]AutoChecker),
	}
}

// RegisterChecker binds an AutoChecker to a specific control ID.
func (e *Engine) RegisterChecker(controlID string, checker AutoChecker) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.checkers[controlID] = checker
}

// RunAssessment executes all registered checkers that apply to the given framework
// and returns a ComplianceReport with raw results.
func (e *Engine) RunAssessment(ctx context.Context, tenantID string, framework Framework) (*ComplianceReport, error) {
	controls := ControlsForFramework(framework)
	if len(controls) == 0 {
		return nil, fmt.Errorf("no controls defined for framework %s", framework)
	}

	assessments := make([]ControlAssessment, 0, len(controls))

	e.mu.RLock()
	defer e.mu.RUnlock()

	// Run checks concurrently with a bounded worker pool.
	type result struct {
		assessment ControlAssessment
		err        error
	}

	resultsCh := make(chan result, len(controls))
	sem := make(chan struct{}, 10) // limit concurrency to 10

	var wg sync.WaitGroup
	for _, ctrl := range controls {
		checker, hasChecker := e.checkers[ctrl.ID]
		wg.Add(1)
		go func(c Control, chk AutoChecker, automated bool) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if !automated {
				// No automated checker registered; mark as manual review needed.
				resultsCh <- result{
					assessment: ControlAssessment{
						ControlID:      c.ID,
						Status:         StatusNotApplicable,
						Evidence:       nil,
						LastChecked:    time.Now().UTC(),
						AutomatedCheck: false,
						RemediationSteps: []string{
							"Manual review required: no automated checker registered for this control.",
						},
					},
				}
				return
			}

			a, err := chk.Check(ctx, tenantID)
			if err != nil {
				resultsCh <- result{
					assessment: ControlAssessment{
						ControlID:      c.ID,
						Status:         StatusFail,
						LastChecked:    time.Now().UTC(),
						AutomatedCheck: true,
						RemediationSteps: []string{
							fmt.Sprintf("Automated check failed with error: %v", err),
						},
					},
					err: err,
				}
				return
			}
			a.ControlID = c.ID
			a.AutomatedCheck = true
			resultsCh <- result{assessment: a}
		}(ctrl, checker, hasChecker)
	}

	wg.Wait()
	close(resultsCh)

	for r := range resultsCh {
		assessments = append(assessments, r.assessment)
	}

	report := &ComplianceReport{
		ID:          generateReportID(tenantID, framework),
		TenantID:    tenantID,
		Framework:   framework,
		GeneratedAt: time.Now().UTC(),
		Controls:    assessments,
	}

	report.OverallScore = ScoreReport(report)
	report.Summary = buildSummary(report, controls)
	report.SignedHash = signReport(report)

	return report, nil
}

// GenerateReport runs a full assessment and attaches the reporting period.
func (e *Engine) GenerateReport(ctx context.Context, tenantID string, framework Framework, period string) (*ComplianceReport, error) {
	report, err := e.RunAssessment(ctx, tenantID, framework)
	if err != nil {
		return nil, fmt.Errorf("assessment failed: %w", err)
	}
	report.Period = period
	// Recompute signed hash after period is set.
	report.SignedHash = signReport(report)
	return report, nil
}

// GetGaps returns all control assessments that are not passing.
func GetGaps(report *ComplianceReport) []ControlAssessment {
	var gaps []ControlAssessment
	for _, ca := range report.Controls {
		if ca.Status == StatusFail || ca.Status == StatusPartial {
			gaps = append(gaps, ca)
		}
	}
	return gaps
}

// ScoreReport computes a weighted compliance score (0-100) for the report.
// Critical controls are weighted 3x, high 2x, medium 1x, low 0.5x.
func ScoreReport(report *ComplianceReport) float64 {
	if len(report.Controls) == 0 {
		return 0
	}

	controlDefs := ControlsForFramework(report.Framework)
	severityMap := make(map[string]string, len(controlDefs))
	for _, c := range controlDefs {
		severityMap[c.ID] = c.Severity
	}

	var totalWeight, earnedWeight float64
	for _, ca := range report.Controls {
		if ca.Status == StatusNotApplicable {
			continue
		}

		weight := severityWeight(severityMap[ca.ControlID])
		totalWeight += weight

		switch ca.Status {
		case StatusPass:
			earnedWeight += weight
		case StatusPartial:
			earnedWeight += weight * 0.5
		}
	}

	if totalWeight == 0 {
		return 100
	}
	score := (earnedWeight / totalWeight) * 100
	if score > 100 {
		score = 100
	}
	return score
}

func severityWeight(severity string) float64 {
	switch severity {
	case SeverityCritical:
		return 3.0
	case SeverityHigh:
		return 2.0
	case SeverityMedium:
		return 1.0
	case SeverityLow:
		return 0.5
	default:
		return 1.0
	}
}

func buildSummary(report *ComplianceReport, controls []Control) ReportSummary {
	summary := ReportSummary{
		TotalControls: len(report.Controls),
	}

	// Build a severity lookup for identifying critical gaps.
	sevMap := make(map[string]string, len(controls))
	for _, c := range controls {
		sevMap[c.ID] = c.Severity
	}

	for _, ca := range report.Controls {
		switch ca.Status {
		case StatusPass:
			summary.Passed++
		case StatusFail:
			summary.Failed++
			if sevMap[ca.ControlID] == SeverityCritical {
				summary.CriticalGaps = append(summary.CriticalGaps, ca.ControlID)
			}
		case StatusPartial:
			summary.Partial++
			if sevMap[ca.ControlID] == SeverityCritical {
				summary.CriticalGaps = append(summary.CriticalGaps, ca.ControlID)
			}
		case StatusNotApplicable:
			summary.NotApplicable++
		}
	}

	return summary
}

func generateReportID(tenantID string, fw Framework) string {
	raw := fmt.Sprintf("%s|%s|%d", tenantID, fw, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("rpt-%x", hash[:8])
}

func signReport(report *ComplianceReport) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%.2f|%d",
		report.ID, report.TenantID, report.Framework,
		report.Period, report.OverallScore, report.GeneratedAt.UnixNano(),
	)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash)
}
