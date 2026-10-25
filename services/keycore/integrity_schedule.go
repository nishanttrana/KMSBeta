package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/authority"
	"vecta-kms/pkg/route"
)

// Key integrity schedules (13.66.0-beta) check, on an interval, that each
// matching active key's current material still decrypts under the master
// key and matches its recorded KCV (VerifyKeyIntegrity). They replace the
// "scheduled jobs" store, which kept jobs nothing ever ran.
//
// A run acts as the person who saved the schedule, re-checked with auth
// first, and checks only the keys that person can see. A key held in an HSM
// is counted as not assessed, never as a failure.

const (
	permIntegrityVerify     = "key.integrity.verify"
	maxIntegrityIntervalHrs = 24 * 90
	integrityFailedListMax  = 50
)

type IntegritySchedule struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	Name         string     `json:"name"`
	TargetFilter string     `json:"target_filter"`
	IntervalHrs  int        `json:"interval_hours"`
	Enabled      bool       `json:"enabled"`
	AuthorizedBy string     `json:"authorized_by"`
	PausedReason string     `json:"paused_reason,omitempty"`
	NextRunAt    *time.Time `json:"next_run_at,omitempty"`
	LastRunAt    *time.Time `json:"last_run_at,omitempty"`
	// LastResult: passed, failed (a key did not verify), refused (the run
	// did not happen) or error (it could not finish); "" before the first.
	LastResult      string    `json:"last_result,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	LastChecked     int       `json:"last_checked"`
	LastFailed      int       `json:"last_failed"`
	LastNotAssessed int       `json:"last_not_assessed"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type integrityScheduleInput struct {
	Name         *string `json:"name"`
	TargetFilter *string `json:"target_filter"`
	IntervalHrs  *int    `json:"interval_hours"`
	Enabled      *bool   `json:"enabled"`
}

// IntegrityOutcome is one run's counts; Failed names up to 50 keys.
type IntegrityOutcome struct {
	Checked     int      `json:"checked"`
	Verified    int      `json:"verified"`
	NotAssessed int      `json:"not_assessed"`
	FailedCount int      `json:"failed"`
	Failed      []string `json:"failed_keys"`
}

// ── store ────────────────────────────────────────────────────────────

const integrityColumns = `id, tenant_id, name, target_filter, interval_hours, enabled, authorized_by, paused_reason,
       next_run_at, last_run_at, last_result, last_error, last_checked, last_failed, last_not_assessed, created_at, updated_at`

func scanIntegritySchedule(row interface{ Scan(...any) error }) (IntegritySchedule, error) {
	var (
		s          IntegritySchedule
		next, last sql.NullTime
	)
	if err := row.Scan(&s.ID, &s.TenantID, &s.Name, &s.TargetFilter, &s.IntervalHrs, &s.Enabled, &s.AuthorizedBy, &s.PausedReason,
		&next, &last, &s.LastResult, &s.LastError, &s.LastChecked, &s.LastFailed, &s.LastNotAssessed, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return IntegritySchedule{}, err
	}
	if next.Valid {
		t := next.Time.UTC()
		s.NextRunAt = &t
	}
	if last.Valid {
		t := last.Time.UTC()
		s.LastRunAt = &t
	}
	s.CreatedAt, s.UpdatedAt = s.CreatedAt.UTC(), s.UpdatedAt.UTC()
	return s, nil
}

func (s *SQLStore) queryIntegritySchedules(ctx context.Context, where string, args ...any) ([]IntegritySchedule, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+integrityColumns+` FROM key_integrity_schedules `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []IntegritySchedule{}
	for rows.Next() {
		sch, err := scanIntegritySchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sch)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListIntegritySchedules(ctx context.Context, tenantID string) ([]IntegritySchedule, error) {
	return s.queryIntegritySchedules(ctx, `WHERE tenant_id=$1 ORDER BY name, id`, tenantID)
}

func (s *SQLStore) GetIntegritySchedule(ctx context.Context, tenantID, id string) (IntegritySchedule, error) {
	items, err := s.queryIntegritySchedules(ctx, `WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return IntegritySchedule{}, err
	}
	if len(items) == 0 {
		return IntegritySchedule{}, errStoreNotFound
	}
	return items[0], nil
}

// ListDueIntegritySchedules returns enabled, unpaused schedules whose time
// has come, across tenants.
func (s *SQLStore) ListDueIntegritySchedules(ctx context.Context, now time.Time, limit int) ([]IntegritySchedule, error) {
	return s.queryIntegritySchedules(ctx, `WHERE enabled = TRUE AND paused_reason = '' AND next_run_at IS NOT NULL AND next_run_at <= $1
ORDER BY next_run_at, id LIMIT $2`, now.UTC(), limit)
}

func (s *SQLStore) PutIntegritySchedule(ctx context.Context, sch IntegritySchedule) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_integrity_schedules (`+integrityColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
ON CONFLICT (tenant_id, id) DO UPDATE SET
    name=EXCLUDED.name, target_filter=EXCLUDED.target_filter, interval_hours=EXCLUDED.interval_hours,
    enabled=EXCLUDED.enabled, authorized_by=EXCLUDED.authorized_by, paused_reason=EXCLUDED.paused_reason,
    next_run_at=EXCLUDED.next_run_at, last_run_at=EXCLUDED.last_run_at, last_result=EXCLUDED.last_result,
    last_error=EXCLUDED.last_error, last_checked=EXCLUDED.last_checked, last_failed=EXCLUDED.last_failed,
    last_not_assessed=EXCLUDED.last_not_assessed, updated_at=EXCLUDED.updated_at`,
		sch.ID, sch.TenantID, sch.Name, sch.TargetFilter, sch.IntervalHrs, sch.Enabled, sch.AuthorizedBy, sch.PausedReason,
		nullableTime(sch.NextRunAt), nullableTime(sch.LastRunAt), sch.LastResult, sch.LastError, sch.LastChecked, sch.LastFailed,
		sch.LastNotAssessed, sch.CreatedAt, sch.UpdatedAt)
	return err
}

func (s *SQLStore) DeleteIntegritySchedule(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM key_integrity_schedules WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

// ── running ──────────────────────────────────────────────────────────

// RunIntegrityCheck verifies every active key the filter selects that the
// acting person in ctx can see.
func (s *Service) RunIntegrityCheck(ctx context.Context, tenantID, filter string) (IntegrityOutcome, error) {
	out := IntegrityOutcome{Failed: []string{}}
	view, err := s.keyViewFor(ctx, tenantID)
	if err != nil {
		return out, err
	}
	keys, err := s.matchingActiveKeys(ctx, tenantID, filter)
	if err != nil {
		return out, err
	}
	for _, k := range keys {
		if !view.sees(k) {
			continue
		}
		res, err := s.VerifyKeyIntegrity(ctx, tenantID, k.ID)
		if err != nil {
			return out, err
		}
		out.Checked++
		switch {
		case res.NotAssessed:
			out.NotAssessed++
		case res.Verified:
			out.Verified++
		default:
			out.FailedCount++
			if len(out.Failed) < integrityFailedListMax {
				out.Failed = append(out.Failed, k.ID)
			}
		}
	}
	return out, nil
}

// runIntegrity runs one schedule now: re-check its authority, verify, and
// record and audit the outcome. by is "schedule" or "manual:<actor>".
func (r *RotationScheduler) runIntegrity(ctx context.Context, sch IntegritySchedule, by string) (IntegrityOutcome, IntegritySchedule) {
	now := time.Now().UTC()
	a, reason, detail := authority.Check(ctx, r.authority, sch.TenantID, sch.AuthorizedBy, []string{permIntegrityVerify})
	var out IntegrityOutcome
	if reason != "" {
		sch.LastResult, sch.LastError = "refused", detail
		retry := now.Add(rotationRetry)
		sch.NextRunAt = &retry
		if reason == authority.ReasonRevoked {
			sch.PausedReason = detail
		}
	} else {
		pctx := contextWithAccessActor(ctx, AccessActor{UserID: sch.AuthorizedBy, Role: a.Role, Permissions: []string{permIntegrityVerify},
			Authenticated: true, Via: rotationSchedulerTag, TenantID: sch.TenantID})
		if adm, err := r.authority.Authority(ctx, sch.TenantID, sch.AuthorizedBy, []string{permInventoryRead}); err == nil && adm.Active && len(adm.Missing) == 0 {
			pctx = contextWithAccessActor(ctx, AccessActor{UserID: sch.AuthorizedBy, Role: a.Role, Permissions: []string{permIntegrityVerify, permInventoryRead},
				Authenticated: true, Via: rotationSchedulerTag, TenantID: sch.TenantID})
		}
		var err error
		out, err = r.svc.RunIntegrityCheck(pctx, sch.TenantID, sch.TargetFilter)
		sch.LastChecked, sch.LastFailed, sch.LastNotAssessed = out.Checked, out.FailedCount, out.NotAssessed
		switch {
		case err != nil:
			sch.LastResult, sch.LastError = "error", err.Error()
		case out.FailedCount > 0:
			sch.LastResult, sch.LastError = "failed", ""
		default:
			sch.LastResult, sch.LastError = "passed", ""
		}
		next := now.Add(time.Duration(sch.IntervalHrs) * time.Hour)
		sch.NextRunAt = &next
	}
	sch.LastRunAt, sch.UpdatedAt = &now, now
	if err := r.svc.store.PutIntegritySchedule(ctx, sch); err != nil {
		r.logger.Printf("integrity schedule %s: %v", sch.ID, err)
	}
	if r.audit != nil {
		result := map[string]string{"passed": "success", "failed": "failure", "error": "failure", "refused": "refused"}[sch.LastResult]
		details := map[string]any{"schedule_name": sch.Name, "target_filter": sch.TargetFilter, "authorized_by": sch.AuthorizedBy,
			"triggered_by": by, "checked": out.Checked, "verified": out.Verified, "not_assessed": out.NotAssessed,
			"failed": out.FailedCount, "failed_keys": out.Failed}
		switch sch.LastResult {
		case "refused":
			details["reason"], details["description"], details["severity"] = reason, detail, "warning"
		case "failed":
			details["severity"] = "critical"
		case "error":
			details["description"], details["severity"] = sch.LastError, "warning"
		}
		_ = r.audit.Emit(ctx, "integrity_check_run", pkgaudit.Event{
			TenantID: sch.TenantID, ActorID: rotationSchedulerTag, ActorType: "service",
			TargetType: "integrity_schedule", TargetID: sch.ID, Result: result, Details: details,
		})
	}
	return out, sch
}

func (r *RotationScheduler) tickIntegrity(ctx context.Context) {
	due, err := r.svc.store.ListDueIntegritySchedules(ctx, time.Now().UTC(), 50)
	if err != nil {
		r.logger.Printf("integrity scheduler: %v", err)
		return
	}
	for _, sch := range due {
		r.runIntegrity(ctx, sch, "schedule")
	}
}

// ── routes ───────────────────────────────────────────────────────────

// integrityScheduleRouter serves the schedules; the run route checks now, on the
// saved person's authority as the tick would.
func (h *Handler) integrityScheduleRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	spec := func(action, resource string) route.Spec {
		return route.Spec{Action: action, Permission: permIntegrityVerify, Resource: resource}
	}
	r.Handle("GET /integrity/schedules", spec("integrity_schedules_listed", "integrity_schedule"), h.listIntegritySchedules)
	r.Handle("POST /integrity/schedules", spec("integrity_schedule_created", "integrity_schedule"), func(c *route.Call) { h.saveIntegritySchedule(c, "") })
	update := spec("integrity_schedule_updated", "integrity_schedule")
	update.TargetParam = "id"
	r.Handle("PATCH /integrity/schedules/{id}", update, func(c *route.Call) { h.saveIntegritySchedule(c, c.R.PathValue("id")) })
	del := spec("integrity_schedule_deleted", "integrity_schedule")
	del.TargetParam, del.Severity = "id", "warning"
	r.Handle("DELETE /integrity/schedules/{id}", del, h.deleteIntegritySchedule)
	run := spec("integrity_schedule_run_requested", "integrity_schedule")
	run.TargetParam = "id"
	r.Handle("POST /integrity/schedules/{id}/run", run, h.runIntegrityNow)
	return r
}

func (h *Handler) listIntegritySchedules(c *route.Call) {
	items, err := h.svc.store.ListIntegritySchedules(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_failed", "failed to list integrity schedules")
		return
	}
	c.JSON(http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) saveIntegritySchedule(c *route.Call, id string) {
	var in integrityScheduleInput
	if !c.Decode(&in) {
		return
	}
	ctx := c.R.Context()
	now := time.Now().UTC()
	sch := IntegritySchedule{ID: newID("kis"), TenantID: c.Tenant, Enabled: true, IntervalHrs: 24, CreatedAt: now}
	if id != "" {
		cur, err := h.svc.store.GetIntegritySchedule(ctx, c.Tenant, id)
		if errors.Is(err, errStoreNotFound) {
			c.Error(http.StatusNotFound, "not_found", "integrity schedule not found")
			return
		}
		if err != nil {
			c.Error(http.StatusInternalServerError, "lookup_failed", "failed to read the integrity schedule")
			return
		}
		sch = cur
	}
	if in.Name != nil {
		sch.Name = strings.TrimSpace(*in.Name)
	}
	if in.TargetFilter != nil {
		sch.TargetFilter = strings.TrimSpace(*in.TargetFilter)
	}
	if in.IntervalHrs != nil {
		sch.IntervalHrs = *in.IntervalHrs
	}
	if in.Enabled != nil {
		sch.Enabled = *in.Enabled
	}
	switch {
	case sch.Name == "" || len(sch.Name) > 120:
		c.Refuse(http.StatusBadRequest, "invalid_schedule", "name is required (at most 120 characters)")
		return
	case sch.IntervalHrs < 1 || sch.IntervalHrs > maxIntegrityIntervalHrs:
		c.Refuse(http.StatusBadRequest, "invalid_schedule", "interval_hours must be 1 to 2160")
		return
	}
	if err := validateRotationFilter(sch.TargetFilter); err != nil {
		c.Refuse(http.StatusBadRequest, "invalid_schedule", err.Error())
		return
	}
	// Saving makes the caller the schedule's authority and resumes a pause.
	if sch.PausedReason != "" {
		c.Detail("resumed", sch.PausedReason)
	}
	sch.AuthorizedBy, sch.PausedReason, sch.UpdatedAt = c.Actor(), "", now
	if sch.NextRunAt == nil || in.IntervalHrs != nil {
		base := now
		if sch.LastRunAt != nil {
			base = *sch.LastRunAt
		}
		next := base.Add(time.Duration(sch.IntervalHrs) * time.Hour)
		if next.Before(now) {
			next = now
		}
		sch.NextRunAt = &next
	}
	if err := h.svc.store.PutIntegritySchedule(ctx, sch); err != nil {
		c.Error(http.StatusInternalServerError, "save_failed", "failed to save the integrity schedule")
		return
	}
	c.Target(sch.ID)
	c.Detail("target_filter", sch.TargetFilter)
	c.Detail("interval_hours", sch.IntervalHrs)
	c.Detail("enabled", sch.Enabled)
	status := http.StatusOK
	if id == "" {
		status = http.StatusCreated
	}
	c.JSON(status, map[string]any{"schedule": sch})
}

func (h *Handler) deleteIntegritySchedule(c *route.Call) {
	err := h.svc.store.DeleteIntegritySchedule(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errStoreNotFound) {
		c.Error(http.StatusNotFound, "not_found", "integrity schedule not found")
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "delete_failed", "failed to delete the integrity schedule")
		return
	}
	c.JSON(http.StatusOK, map[string]any{"status": "deleted"})
}

func (h *Handler) runIntegrityNow(c *route.Call) {
	sched := h.scheduler
	sch, err := h.svc.store.GetIntegritySchedule(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errStoreNotFound) {
		c.Error(http.StatusNotFound, "not_found", "integrity schedule not found")
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "lookup_failed", "failed to read the integrity schedule")
		return
	}
	if sch.PausedReason != "" {
		c.Refuse(http.StatusConflict, "schedule_paused", sch.PausedReason)
		return
	}
	if sched == nil {
		c.Error(http.StatusServiceUnavailable, "scheduler_unavailable", "the integrity scheduler is not running")
		return
	}
	out, saved := sched.runIntegrity(c.R.Context(), sch, "manual:"+c.Actor())
	c.Detail("result", saved.LastResult)
	c.Detail("checked", out.Checked)
	c.Detail("failed", out.FailedCount)
	c.JSON(http.StatusOK, map[string]any{"schedule": saved, "outcome": out})
}
