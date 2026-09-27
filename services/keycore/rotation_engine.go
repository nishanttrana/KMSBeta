package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/clusterstate"
)

// Rotation policies rotate the tenant's keys that match target_filter, through
// the same RotateKey path as a manual rotation (policy check, key access,
// HSM, per-key audit.key.rotate). A run records one row per key with the real
// outcome. Only keys can be rotated here; secrets and certificates have their
// own services.

const (
	rotationTargetKey    = "key"
	maxKeysPerPolicyRun  = 1000
	rotationSchedulerTag = "kms-keycore-rotation-scheduler"
)

var errRotationTargetUnsupported = errors.New("only key rotation policies are supported: secrets and certificates are rotated by their own services")

// validateRotationFilter checks a target_filter: "*" (every active key),
// "tag:<tag>", "id:<key id>", or a glob on the key name.
func validateRotationFilter(filter string) error {
	f := strings.TrimSpace(filter)
	switch {
	case f == "":
		return errors.New("target_filter is required: *, tag:<tag>, id:<key id> or a key-name glob")
	case strings.HasPrefix(f, "tag:") && strings.TrimSpace(f[4:]) == "",
		strings.HasPrefix(f, "id:") && strings.TrimSpace(f[3:]) == "":
		return errors.New("target_filter tag:/id: needs a value")
	}
	if _, err := path.Match(f, ""); err != nil {
		return fmt.Errorf("target_filter is not a valid glob: %w", err)
	}
	return nil
}

func rotationFilterMatches(filter string, k Key) bool {
	f := strings.TrimSpace(filter)
	switch {
	case f == "*":
		return true
	case strings.HasPrefix(f, "tag:"):
		want := strings.TrimSpace(f[4:])
		for _, t := range k.Tags {
			if strings.EqualFold(strings.TrimSpace(t), want) {
				return true
			}
		}
		return false
	case strings.HasPrefix(f, "id:"):
		return k.ID == strings.TrimSpace(f[3:])
	}
	ok, _ := path.Match(f, k.Name)
	return ok
}

// RotationOutcome summarises one policy run.
type RotationOutcome struct {
	Matched int           `json:"matched"`
	Rotated int           `json:"rotated"`
	Failed  int           `json:"failed"`
	Runs    []RotationRun `json:"runs"`
}

// matchingActiveKeys lists the tenant's active keys the filter selects.
func (s *Service) matchingActiveKeys(ctx context.Context, tenantID, filter string) ([]Key, error) {
	var out []Key
	const page = 500
	for offset := 0; ; offset += page {
		keys, err := s.store.ListKeys(ctx, tenantID, page, offset)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			if strings.EqualFold(k.Status, "active") && rotationFilterMatches(filter, k) {
				out = append(out, k)
			}
		}
		if len(out) > maxKeysPerPolicyRun {
			return nil, fmt.Errorf("target_filter matches more than %d active keys; narrow it", maxKeysPerPolicyRun)
		}
		if len(keys) < page {
			return out, nil
		}
	}
}

// RunRotationPolicy rotates every active key the policy matches and records
// the outcome. ctx carries the acting identity: the caller for a manual
// trigger, the scheduler's service identity for a scheduled run.
func (s *Service) RunRotationPolicy(ctx context.Context, p RotationPolicy, triggeredBy string) (RotationOutcome, error) {
	now := time.Now().UTC()
	next := now.AddDate(0, 0, p.IntervalDays)
	var out RotationOutcome
	if p.TargetType != rotationTargetKey {
		_ = s.store.RecordRotationPolicyOutcome(ctx, p.TenantID, p.ID, now, next, 0, "error", errRotationTargetUnsupported.Error())
		return out, errRotationTargetUnsupported
	}
	keys, err := s.matchingActiveKeys(ctx, p.TenantID, p.TargetFilter)
	if err != nil {
		_ = s.store.RecordRotationPolicyOutcome(ctx, p.TenantID, p.ID, now, next, 0, "error", err.Error())
		return out, err
	}
	out.Matched = len(keys)
	var lastErr string
	for _, k := range keys {
		run := RotationRun{
			ID: newID("rr"), TenantID: p.TenantID, PolicyID: p.ID, PolicyName: p.Name,
			TargetID: k.ID, TargetName: k.Name, TargetType: rotationTargetKey,
			TriggeredBy: triggeredBy, StartedAt: time.Now().UTC(),
		}
		_, rerr := s.RotateKey(ctx, p.TenantID, k.ID, "rotation policy "+p.Name, "")
		done := time.Now().UTC()
		run.CompletedAt = &done
		if rerr != nil {
			run.Status, run.Error = "failed", rerr.Error()
			lastErr = k.Name + ": " + rerr.Error()
			out.Failed++
		} else {
			run.Status = "success"
			out.Rotated++
		}
		if saved, err := s.store.CreateRotationRun(ctx, run); err == nil {
			run = saved
		}
		out.Runs = append(out.Runs, run)
	}
	status := "active"
	if out.Failed > 0 {
		status = "error"
	}
	if err := s.store.RecordRotationPolicyOutcome(ctx, p.TenantID, p.ID, now, next, out.Rotated, status, lastErr); err != nil {
		return out, err
	}
	return out, nil
}

// schedulerContext is the identity scheduled runs act under. It is set in
// process, never from a request, so it cannot be forged (CLAUDE.md rule 4).
func schedulerContext(ctx context.Context) context.Context {
	return contextWithAccessActor(ctx, AccessActor{
		ClientID: rotationSchedulerTag, Role: "client-service", Authenticated: true, ServicePrincipal: true,
	})
}

// RotationScheduler runs due auto-rotate policies on the primary.
type RotationScheduler struct {
	svc      *Service
	audit    *pkgaudit.Client
	interval time.Duration
	logger   *log.Logger
	primary  func(context.Context) bool
}

func NewRotationScheduler(svc *Service, audit *pkgaudit.Client, logger *log.Logger) *RotationScheduler {
	return &RotationScheduler{svc: svc, audit: audit, interval: time.Minute, logger: logger, primary: clusterstate.RunsPrimaryJobs}
}

func (r *RotationScheduler) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Tick(ctx)
		}
	}
}

// Tick runs every due policy once. Cluster members never run it: policies
// and runs are replicated tables written only on the primary.
func (r *RotationScheduler) Tick(ctx context.Context) {
	if !r.primary(ctx) {
		return
	}
	due, err := r.svc.store.ListDueRotationPolicies(ctx, time.Now().UTC(), 100)
	if err != nil {
		r.logger.Printf("rotation scheduler: %v", err)
		return
	}
	sctx := schedulerContext(ctx)
	for _, p := range due {
		out, err := r.svc.RunRotationPolicy(sctx, p, "schedule")
		r.emit(ctx, p, out, err)
	}
}

func (r *RotationScheduler) emit(ctx context.Context, p RotationPolicy, out RotationOutcome, err error) {
	if r.audit == nil {
		return
	}
	result, severity := "success", "info"
	details := map[string]interface{}{
		"policy_name": p.Name, "target_filter": p.TargetFilter,
		"matched": out.Matched, "rotated": out.Rotated, "failed": out.Failed, "triggered_by": "schedule",
	}
	switch {
	case err != nil:
		result, severity = "failure", "warning"
		details["error"] = err.Error()
	case out.Failed > 0:
		result, severity = "failure", "warning"
	}
	details["severity"] = severity
	_ = r.audit.Emit(ctx, "rotation_policy_run", pkgaudit.Event{
		TenantID: p.TenantID, ActorID: rotationSchedulerTag, ActorType: "service",
		TargetType: "rotation_policy", TargetID: p.ID, Result: result, Details: details,
	})
}
