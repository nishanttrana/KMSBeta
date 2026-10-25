package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/authority"
	"vecta-kms/pkg/route"
)

// Scheduled reports (docs/SCHEDULING.md). A schedule queues a report job for
// its tenant every hour, day or week; reports are not emailed (reporting has
// no mail delivery), they are listed with the other report jobs.
//
// Since 13.66.0-beta a schedule is requested on the authority of the person
// who last saved it, asked of auth before every run; a person who is no
// longer active or no longer holds reporting.write pauses it. A schedule
// can be paused, edited, run now and deleted, and records its last result.

var reportSchedules = map[string]bool{"hourly": true, "daily": true, "weekly": true}

// scheduledReportInput is what a create or edit sends; fields left out keep
// their value on an edit.
type scheduledReportInput struct {
	TenantID   string                  `json:"tenant_id"` // verified by the kernel; c.Tenant is used
	Name       *string                 `json:"name"`
	TemplateID *string                 `json:"template_id"`
	Format     *string                 `json:"format"`
	Schedule   *string                 `json:"schedule"`
	Filters    *map[string]interface{} `json:"filters"`
	Enabled    *bool                   `json:"enabled"`
}

// applyScheduleInput validates in against the template catalogue and
// writes it onto item.
func (s *Service) applyScheduleInput(item *ScheduledReport, in scheduledReportInput) error {
	if in.Name != nil {
		item.Name = strings.TrimSpace(*in.Name)
	}
	if in.TemplateID != nil {
		item.TemplateID = normalizeTemplateID(*in.TemplateID)
	}
	if in.Format != nil {
		item.Format = strings.ToLower(strings.TrimSpace(*in.Format))
	}
	if in.Schedule != nil {
		item.Schedule = strings.ToLower(strings.TrimSpace(*in.Schedule))
	}
	if in.Filters != nil {
		item.Filters = *in.Filters
	}
	if in.Enabled != nil {
		item.Enabled = *in.Enabled
	}
	if item.Name == "" || len(item.Name) > 120 {
		return newServiceError(http.StatusBadRequest, "invalid_schedule", "name is required (at most 120 characters)")
	}
	if !reportSchedules[item.Schedule] {
		return newServiceError(http.StatusBadRequest, "invalid_schedule", "schedule is hourly, daily or weekly")
	}
	for _, t := range s.Templates() {
		if t.ID != item.TemplateID {
			continue
		}
		for _, f := range t.Formats {
			if f == item.Format {
				return nil
			}
		}
		return newServiceError(http.StatusBadRequest, "invalid_schedule", "template "+t.ID+" is produced as "+strings.Join(t.Formats, ", "))
	}
	return newServiceError(http.StatusBadRequest, "invalid_schedule", "unknown template_id "+item.TemplateID)
}

func (s *Service) ScheduleReport(ctx context.Context, tenantID, by string, in scheduledReportInput) (ScheduledReport, error) {
	item := ScheduledReport{ID: newID("sched"), TenantID: tenantID, Enabled: true, Filters: map[string]interface{}{}, AuthorizedBy: by}
	if err := s.applyScheduleInput(&item, in); err != nil {
		return ScheduledReport{}, err
	}
	item.NextRunAt = nextRunTime(time.Now().UTC(), item.Schedule)
	if err := s.store.CreateScheduledReport(ctx, item); err != nil {
		return ScheduledReport{}, err
	}
	return s.store.GetScheduledReport(ctx, tenantID, item.ID)
}

// UpdateScheduledReport edits a schedule. Saving makes the caller its
// authority and resumes a pause; a changed cadence restarts the clock.
func (s *Service) UpdateScheduledReport(ctx context.Context, tenantID, id, by string, in scheduledReportInput) (ScheduledReport, string, error) {
	item, err := s.store.GetScheduledReport(ctx, tenantID, id)
	if err != nil {
		return ScheduledReport{}, "", err
	}
	before := item.Schedule
	if err := s.applyScheduleInput(&item, in); err != nil {
		return ScheduledReport{}, "", err
	}
	resumed := item.PausedReason
	item.AuthorizedBy, item.PausedReason = by, ""
	if item.Schedule != before || item.NextRunAt.IsZero() {
		item.NextRunAt = nextRunTime(time.Now().UTC(), item.Schedule)
	}
	if err := s.store.SaveScheduledReport(ctx, item); err != nil {
		return ScheduledReport{}, "", err
	}
	out, err := s.store.GetScheduledReport(ctx, tenantID, id)
	return out, resumed, err
}

// runSchedule requests one schedule's report now, on its saved authority.
// by is "schedule" or "manual:<actor>". The outcome is stored and audited.
func (s *Service) runSchedule(ctx context.Context, item ScheduledReport, by string) ScheduledReport {
	now := time.Now().UTC()
	_, reason, detail := authority.Check(ctx, s.authority, item.TenantID, item.AuthorizedBy, []string{permWrite})
	switch {
	case reason != "":
		item.LastResult, item.LastError = "refused", detail
		if reason == authority.ReasonRevoked {
			item.PausedReason = detail
		}
		item.NextRunAt = now.Add(15 * time.Minute)
	default:
		job, err := s.GenerateReport(ctx, item.TenantID, item.TemplateID, item.Format, item.AuthorizedBy, item.Filters)
		if err != nil {
			item.LastResult, item.LastError = "failed", err.Error()
		} else {
			item.LastResult, item.LastError, item.LastJobID = "requested", "", job.ID
		}
		item.NextRunAt = nextRunTime(now, item.Schedule)
	}
	item.LastRunAt = now
	_ = s.store.SaveScheduledReport(ctx, item)
	if s.events != nil {
		result := map[string]string{"requested": "success", "failed": "failure", "refused": "refused"}[item.LastResult]
		details := map[string]interface{}{"schedule_id": item.ID, "schedule_name": item.Name, "template_id": item.TemplateID,
			"format": item.Format, "authorized_by": item.AuthorizedBy, "trigger": by}
		switch item.LastResult {
		case "requested":
			details["job_id"] = item.LastJobID
		case "refused":
			details["reason"], details["description"], details["severity"] = reason, detail, "warning"
		case "failed":
			details["description"], details["severity"] = item.LastError, "warning"
		}
		_ = s.events.Emit(ctx, "scheduled_report_run", pkgaudit.Event{
			TenantID: item.TenantID, ActorID: "kms-reporting", ActorType: "service",
			TargetType: "scheduled_report", TargetID: item.ID, Result: result, Details: details,
		})
	}
	return item
}

// RunDueSchedules runs every due, unpaused schedule (primary only, from
// StartScheduler).
func (s *Service) RunDueSchedules(ctx context.Context) error {
	items, err := s.store.ListDueScheduledReports(ctx, time.Now().UTC(), 200)
	if err != nil {
		return err
	}
	for _, item := range items {
		s.runSchedule(ctx, item, "schedule")
	}
	return nil
}

// ── routes ───────────────────────────────────────────────────────────

func (h *Handler) scheduleRoutes(r *route.Router, spec func(action, perm, resource, target string) route.Spec) {
	r.Handle("PATCH /reports/scheduled/{id}", spec("scheduled_report_updated", permWrite, "scheduled_report", "id"), h.updateScheduledReport)
	del := spec("scheduled_report_deleted", permWrite, "scheduled_report", "id")
	del.Severity = "warning"
	r.Handle("DELETE /reports/scheduled/{id}", del, h.deleteScheduledReport)
	r.Handle("POST /reports/scheduled/{id}/run", spec("scheduled_report_run_requested", permWrite, "scheduled_report", "id"), h.runScheduledReport)
}

func (h *Handler) updateScheduledReport(c *route.Call) {
	var in scheduledReportInput
	if !c.Decode(&in) {
		return
	}
	item, resumed, err := h.svc.UpdateScheduledReport(c.R.Context(), c.Tenant, c.R.PathValue("id"), c.Actor(), in)
	if err != nil {
		h.scheduleError(c, err)
		return
	}
	if resumed != "" {
		c.Detail("resumed", resumed)
	}
	c.Detail("schedule", item.Schedule)
	c.Detail("enabled", item.Enabled)
	c.JSON(http.StatusOK, map[string]interface{}{"item": item})
}

func (h *Handler) deleteScheduledReport(c *route.Call) {
	if err := h.svc.store.DeleteScheduledReport(c.R.Context(), c.Tenant, c.R.PathValue("id")); err != nil {
		h.scheduleError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"deleted": true})
}

// runScheduledReport requests the report now, on the saved authority as a
// scheduled run would.
func (h *Handler) runScheduledReport(c *route.Call) {
	item, err := h.svc.store.GetScheduledReport(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		h.scheduleError(c, err)
		return
	}
	if item.PausedReason != "" {
		c.Refuse(http.StatusConflict, "schedule_paused", item.PausedReason)
		return
	}
	item = h.svc.runSchedule(c.R.Context(), item, "manual:"+c.Actor())
	c.Detail("result", item.LastResult)
	c.Detail("job_id", item.LastJobID)
	c.JSON(http.StatusOK, map[string]interface{}{"item": item})
}

// scheduleError answers a missing schedule with 404 and a refused input as
// a refusal with its reason.
func (h *Handler) scheduleError(c *route.Call, err error) {
	var se serviceError
	switch {
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "scheduled report not found")
	case errors.As(err, &se) && se.Code == "invalid_schedule":
		c.Refuse(se.HTTPStatus, se.Code, se.Message)
	default:
		h.serviceError(c, err)
	}
}
