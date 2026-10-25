package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/authority"
	"vecta-kms/pkg/route"
)

// The tenant's compliance assessment schedule (docs/SCHEDULING.md). Since
// 13.66.0-beta it runs on the authority of the person who last saved it,
// asked of auth before each run; a person who is no longer active or no
// longer holds compliance.assessment.write pauses it. Its routes moved
// from the legacy mux to the kernel in the same release: the save took
// tenant_id from the body without checking it against the caller.

const (
	permAssessmentRead  = "compliance.assessment.read"
	permAssessmentWrite = "compliance.assessment.write"
)

var assessmentFrequencies = map[string]bool{"hourly": true, "daily": true, "weekly": true}

// SaveAssessmentSchedule sets the tenant's schedule on by's authority and
// resumes a pause; a changed frequency restarts the clock.
func (s *Service) SaveAssessmentSchedule(ctx context.Context, tenantID, by string, enabled bool, frequency string) (AssessmentSchedule, string, error) {
	frequency = strings.ToLower(strings.TrimSpace(frequency))
	if !assessmentFrequencies[frequency] {
		return AssessmentSchedule{}, "", newServiceError(http.StatusBadRequest, "invalid_schedule", "frequency is hourly, daily or weekly")
	}
	current, err := s.store.GetAssessmentSchedule(ctx, tenantID)
	if err != nil {
		return AssessmentSchedule{}, "", err
	}
	resumed := current.PausedReason
	changed := current.Frequency != frequency
	current.Enabled, current.Frequency, current.AuthorizedBy, current.PausedReason = enabled, frequency, by, ""
	switch {
	case !enabled:
		current.NextRunAt = time.Time{}
	case changed || current.NextRunAt.IsZero():
		base := current.LastRunAt
		if base.IsZero() {
			base = time.Now().UTC()
		}
		current.NextRunAt = nextAssessmentRunTime(base, frequency)
	}
	if err := s.store.UpsertAssessmentSchedule(ctx, current); err != nil {
		return AssessmentSchedule{}, "", err
	}
	updated, err := s.store.GetAssessmentSchedule(ctx, tenantID)
	return updated, resumed, err
}

// runAssessmentSchedule runs the tenant's assessment now on the saved
// authority; by is "schedule" or "manual:<actor>". The outcome is stored
// and audited.
func (s *Service) runAssessmentSchedule(ctx context.Context, item AssessmentSchedule, by string) AssessmentSchedule {
	now := time.Now().UTC()
	_, reason, detail := authority.Check(ctx, s.authority, item.TenantID, item.AuthorizedBy, []string{permAssessmentWrite})
	if reason != "" {
		item.LastResult, item.LastError = "refused", detail
		if reason == authority.ReasonRevoked {
			item.PausedReason = detail
		}
		item.NextRunAt = now.Add(15 * time.Minute)
	} else {
		res, err := s.RunAssessment(ctx, item.TenantID, "scheduled", true, "")
		if err != nil {
			item.LastResult, item.LastError = "failed", err.Error()
		} else {
			item.LastResult, item.LastError, item.LastAssessmentID = "assessed", "", res.ID
		}
		item.NextRunAt = nextAssessmentRunTime(now, item.Frequency)
	}
	item.LastRunAt = now
	_ = s.store.UpsertAssessmentSchedule(ctx, item)
	{
		result := map[string]string{"assessed": "success", "failed": "failure", "refused": "refused"}[item.LastResult]
		details := map[string]interface{}{"frequency": item.Frequency, "authorized_by": item.AuthorizedBy, "trigger": by,
			"result": result, "actor_id": "kms-compliance", "target_type": "assessment_schedule", "target_id": item.TenantID}
		switch item.LastResult {
		case "assessed":
			details["assessment_id"] = item.LastAssessmentID
		case "refused":
			details["reason"], details["description"], details["severity"] = reason, detail, "warning"
		case "failed":
			details["description"], details["severity"] = item.LastError, "warning"
		}
		_ = s.publishAudit(ctx, "audit.compliance.assessment_schedule_run", item.TenantID, details)
	}
	return item
}

// RunDueSchedules runs every due, unpaused schedule (primary only).
func (s *Service) RunDueSchedules(ctx context.Context) error {
	items, err := s.store.ListDueAssessmentSchedules(ctx, time.Now().UTC(), 100)
	if err != nil {
		return err
	}
	for _, item := range items {
		s.runAssessmentSchedule(ctx, item, "schedule")
	}
	return nil
}

// ── routes ───────────────────────────────────────────────────────────

func (h *Handler) assessmentScheduleRoutes(r *route.Router) {
	r.Handle("GET /compliance/assessment/schedule", route.Spec{Action: "assessment_schedule_read", Permission: permAssessmentRead, Resource: "assessment_schedule"}, h.getAssessmentSchedule)
	r.Handle("PUT /compliance/assessment/schedule", route.Spec{Action: "assessment_schedule_updated", Permission: permAssessmentWrite, Resource: "assessment_schedule"}, h.putAssessmentSchedule)
	r.Handle("POST /compliance/assessment/schedule/run", route.Spec{Action: "assessment_schedule_run_requested", Permission: permAssessmentWrite, Resource: "assessment_schedule"}, h.runAssessmentScheduleNow)
}

func (h *Handler) getAssessmentSchedule(c *route.Call) {
	item, err := h.svc.store.GetAssessmentSchedule(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "read_failed", "failed to read the assessment schedule")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"schedule": item})
}

func (h *Handler) putAssessmentSchedule(c *route.Call) {
	var body struct {
		TenantID  string `json:"tenant_id"` // verified by the kernel; c.Tenant is used
		Enabled   bool   `json:"enabled"`
		Frequency string `json:"frequency"`
	}
	if !c.Decode(&body) {
		return
	}
	item, resumed, err := h.svc.SaveAssessmentSchedule(c.R.Context(), c.Tenant, c.Actor(), body.Enabled, body.Frequency)
	if se, ok := err.(serviceError); ok && se.Code == "invalid_schedule" {
		c.Refuse(se.HTTPStatus, se.Code, se.Message)
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "save_failed", "failed to save the assessment schedule")
		return
	}
	if resumed != "" {
		c.Detail("resumed", resumed)
	}
	c.Detail("enabled", item.Enabled)
	c.Detail("frequency", item.Frequency)
	c.JSON(http.StatusOK, map[string]interface{}{"schedule": item})
}

func (h *Handler) runAssessmentScheduleNow(c *route.Call) {
	item, err := h.svc.store.GetAssessmentSchedule(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "read_failed", "failed to read the assessment schedule")
		return
	}
	if item.AuthorizedBy == "" {
		c.Refuse(http.StatusConflict, "not_scheduled", "save the assessment schedule first")
		return
	}
	if item.PausedReason != "" {
		c.Refuse(http.StatusConflict, "schedule_paused", item.PausedReason)
		return
	}
	item = h.svc.runAssessmentSchedule(c.R.Context(), item, "manual:"+c.Actor())
	c.Detail("result", item.LastResult)
	c.JSON(http.StatusOK, map[string]interface{}{"schedule": item})
}
