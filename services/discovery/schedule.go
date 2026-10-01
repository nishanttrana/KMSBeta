package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/route"
)

// Scan schedules (7.20.0-beta). A tenant has one schedule: which sources to
// scan and how often. A scheduled scan runs as the discovery service, with
// no user present, so it runs on the authority of the user who saved the
// schedule (docs/PLATFORM_CONTRACT.md): that user must hold discovery.write
// when saving, and before every run auth is asked whether they are still
// active and still hold it. If not, the schedule pauses with the reason and
// the refusal is audited; saving it again, by someone who holds the
// permission, resumes it. Schedules run on the primary only: the tables
// are replicated.

const (
	schedulePermission  = "discovery.write"
	maxScheduleInterval = 30 * 24 // hours
	// scheduleRetry: how long a due run waits after auth couldn't be
	// reached or another scan was running.
	scheduleRetry = 15 * time.Minute
)

var errInvalidSchedule = errors.New("invalid schedule")

// GetSchedule returns the tenant's schedule; one that was never saved is
// disabled.
func (s *Service) GetSchedule(ctx context.Context, tenantID string) (Schedule, error) {
	sch, err := s.store.GetSchedule(ctx, tenantID)
	if errors.Is(err, errNotFound) {
		return Schedule{TenantID: tenantID, IntervalHours: 24, Sources: []string{}}, nil
	}
	return sch, err
}

// SaveSchedule stores the schedule on userID's authority and clears a pause.
// The first run is one interval from now.
func (s *Service) SaveSchedule(ctx context.Context, tenantID string, enabled bool, intervalHours int, sources []string, userID string) (Schedule, error) {
	if intervalHours < 1 || intervalHours > maxScheduleInterval {
		return Schedule{}, fmt.Errorf("%w: interval_hours must be 1 to %d", errInvalidSchedule, maxScheduleInterval)
	}
	seen := map[string]bool{}
	clean := []string{}
	for _, src := range sources {
		src = strings.ToLower(strings.TrimSpace(src))
		if !containsString(allScanTypes, src) {
			return Schedule{}, fmt.Errorf("%w: unknown source %q", errInvalidSchedule, src)
		}
		if !seen[src] {
			seen[src] = true
			clean = append(clean, src)
		}
	}
	if enabled && len(clean) == 0 {
		return Schedule{}, fmt.Errorf("%w: choose at least one source", errInvalidSchedule)
	}
	prev, _ := s.store.GetSchedule(ctx, tenantID)
	sch := Schedule{
		TenantID: tenantID, Enabled: enabled, IntervalHours: intervalHours, Sources: clean, AuthorizedBy: userID,
		LastRunAt: prev.LastRunAt, LastScanID: prev.LastScanID,
	}
	if enabled {
		sch.NextRunAt = s.now().Add(time.Duration(intervalHours) * time.Hour)
	}
	if err := s.store.PutSchedule(ctx, sch); err != nil {
		return Schedule{}, err
	}
	return s.GetSchedule(ctx, tenantID)
}

// StartScheduler checks for due schedules every minute until ctx ends.
func (s *Service) StartScheduler(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.RunDueSchedules(ctx)
			}
		}
	}()
}

// RunDueSchedules starts the scan of every schedule that is due, on the
// primary only. It returns how many scans it started.
func (s *Service) RunDueSchedules(ctx context.Context) int {
	if s.primary != nil && !s.primary(ctx) {
		return 0
	}
	due, err := s.store.DueSchedules(ctx, s.now())
	if err != nil {
		logger.Printf("schedules: %v", err)
		return 0
	}
	started := 0
	for _, sch := range due {
		if s.runSchedule(ctx, sch) {
			started++
		}
	}
	return started
}

func (s *Service) runSchedule(ctx context.Context, sch Schedule) bool {
	emit := func(result, reason, scanID string) {
		if s.audit == nil {
			return
		}
		details := map[string]interface{}{"sources": sch.Sources, "authorized_by": sch.AuthorizedBy, "interval_hours": sch.IntervalHours}
		if reason != "" {
			details["reason"] = reason
		}
		_ = s.audit.Emit(ctx, "scheduled_scan", pkgaudit.Event{
			TenantID: sch.TenantID, ActorID: "kms-discovery", ActorType: "service", Result: result,
			TargetType: "discovery_scan", TargetID: scanID, Details: details,
		})
	}
	postpone := func() {
		sch.NextRunAt = s.now().Add(scheduleRetry)
		_ = s.store.PutSchedule(ctx, sch)
	}
	if s.authority == nil {
		postpone()
		emit(route.ResultRefused, "authority_unknown", "")
		return false
	}
	active, missing, err := s.authority.Authority(ctx, sch.TenantID, sch.AuthorizedBy, []string{schedulePermission})
	switch {
	case err != nil:
		// Auth didn't answer: neither run on unverified authority nor
		// pause a schedule that may still be valid.
		logger.Printf("schedule %s: authority check: %v", sch.TenantID, err)
		postpone()
		emit(route.ResultRefused, "authority_unknown", "")
		return false
	case !active || len(missing) > 0:
		sch.PausedReason = "the user who saved this schedule is no longer active or no longer holds " + schedulePermission + "; save it again to resume"
		_ = s.store.PutSchedule(ctx, sch)
		emit(route.ResultRefused, "authority_revoked", "")
		return false
	}
	scan, err := s.StartScan(ctx, ScanRequest{TenantID: sch.TenantID, ScanTypes: sch.Sources, Trigger: "scheduled"})
	if errors.Is(err, errScanRunning) {
		postpone() // a scan is already reading the same sources
		return false
	}
	if err != nil {
		logger.Printf("schedule %s: start scan: %v", sch.TenantID, err)
		postpone()
		return false
	}
	sch.LastRunAt, sch.LastScanID = s.now(), scan.ID
	sch.NextRunAt = s.now().Add(time.Duration(sch.IntervalHours) * time.Hour)
	_ = s.store.PutSchedule(ctx, sch)
	emit(route.ResultSuccess, "", scan.ID)
	return true
}
