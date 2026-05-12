package main

import (
	"context"
	"strings"
	"time"
)

// DryRunRequest asks the service to evaluate a proposed policy YAML against
// historical traffic and report which past operations would have been
// affected. This is the "what would deploying this break?" pre-flight
// check that prevents 3-a.m. incidents.
type DryRunRequest struct {
	TenantID    string `json:"tenant_id"`
	YAML        string `json:"yaml"`
	WindowHours int    `json:"window_hours"`
	Limit       int    `json:"limit"`
}

// DryRunFinding is one past operation whose outcome would change under the
// proposed policy. OldDecision is what the policy engine returned at the
// time; NewDecision is what the proposed policy would return now.
type DryRunFinding struct {
	OccurredAt   time.Time `json:"occurred_at"`
	Operation    string    `json:"operation"`
	KeyID        string    `json:"key_id,omitempty"`
	Algorithm    string    `json:"algorithm,omitempty"`
	OldDecision  Decision  `json:"old_decision"`
	NewDecision  Decision  `json:"new_decision"`
	Reason       string    `json:"reason,omitempty"`
}

// DryRunReport is the summary returned to the operator. It contains
// counts plus a bounded sample of findings; the full set would be too
// large for a synchronous response.
type DryRunReport struct {
	TotalEvaluated int            `json:"total_evaluated"`
	Changed        int            `json:"changed"`
	NewDenies      int            `json:"new_denies"`
	NewAllows      int            `json:"new_allows"`
	NewApprovals   int            `json:"new_approvals"`
	Findings       []DryRunFinding `json:"findings"`
	LintFindings   []LintFinding   `json:"lint_findings,omitempty"`
}

// DryRunSource provides historical evaluation records to the simulator.
// The policy service implements it against its evaluations table; tests
// can substitute an in-memory fake.
type DryRunSource interface {
	ListRecentEvaluations(ctx context.Context, tenantID string, since time.Time, limit int) ([]EvaluationRecord, error)
}

// DryRun simulates the proposed policy against historical traffic.
// It parses+lints the YAML, then evaluates each historical record under
// the candidate policy and reports the deltas. The pure-function shape
// (no side effects, no DB writes) keeps it safe to expose on a read API.
func DryRun(ctx context.Context, src DryRunSource, req DryRunRequest) (DryRunReport, error) {
	doc, _, err := parsePolicyYAML(req.YAML)
	if err != nil {
		return DryRunReport{}, err
	}
	if req.WindowHours <= 0 {
		req.WindowHours = 24
	}
	if req.Limit <= 0 || req.Limit > 5_000 {
		req.Limit = 1_000
	}
	since := time.Now().UTC().Add(-time.Duration(req.WindowHours) * time.Hour)
	records, err := src.ListRecentEvaluations(ctx, req.TenantID, since, req.Limit)
	if err != nil {
		return DryRunReport{}, err
	}

	report := DryRunReport{LintFindings: LintPolicy(doc)}
	for _, rec := range records {
		report.TotalEvaluated++
		simulated := evaluatePolicy(doc, "dry-run", 0, evaluateRequestFromRecord(rec))
		if simulated.Decision == rec.Decision {
			continue
		}
		report.Changed++
		switch simulated.Decision {
		case DecisionDeny:
			report.NewDenies++
		case DecisionRequireApproval:
			report.NewApprovals++
		case DecisionAllow, DecisionWarn:
			if rec.Decision == DecisionDeny || rec.Decision == DecisionRequireApproval {
				report.NewAllows++
			}
		}
		// Cap the embedded findings; counts already tell the headline story.
		if len(report.Findings) < 200 {
			f := DryRunFinding{
				OccurredAt:  rec.OccurredAt,
				Operation:   rec.Operation,
				KeyID:       rec.KeyID,
				OldDecision: rec.Decision,
				NewDecision: simulated.Decision,
			}
			if alg, ok := rec.Request["algorithm"].(string); ok {
				f.Algorithm = alg
			}
			if len(simulated.Outcomes) > 0 {
				f.Reason = simulated.Outcomes[0].Message
			}
			report.Findings = append(report.Findings, f)
		}
	}
	return report, nil
}

// evaluateRequestFromRecord rebuilds an EvaluatePolicyRequest from a stored
// EvaluationRecord. Older records may have been persisted before some
// fields existed; missing fields default to their zero values rather than
// erroring so the dry-run includes as much history as possible.
func evaluateRequestFromRecord(rec EvaluationRecord) EvaluatePolicyRequest {
	out := EvaluatePolicyRequest{
		TenantID:  rec.TenantID,
		Operation: rec.Operation,
		KeyID:     rec.KeyID,
	}
	if rec.Request == nil {
		return out
	}
	if v, ok := rec.Request["algorithm"].(string); ok {
		out.Algorithm = v
	}
	if v, ok := rec.Request["purpose"].(string); ok {
		out.Purpose = v
	}
	if v, ok := rec.Request["iv_mode"].(string); ok {
		out.IVMode = strings.TrimSpace(v)
	}
	if v, ok := rec.Request["key_status"].(string); ok {
		out.KeyStatus = v
	}
	if v, ok := rec.Request["ops_total"].(float64); ok {
		out.OpsTotal = int64(v)
	}
	if v, ok := rec.Request["ops_limit"].(float64); ok {
		out.OpsLimit = int64(v)
	}
	if v, ok := rec.Request["days_since_rotation"].(float64); ok {
		out.DaysSinceRotation = int(v)
	}
	if labels, ok := rec.Request["labels"].(map[string]any); ok {
		out.Labels = labels
	}
	return out
}
