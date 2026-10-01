package main

import (
	"context"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/clusterstate"
)

// retentionActor is recorded as who destroyed a secret whose retention
// period ran out.
const retentionActor = "system:retention"

// runRetention destroys deleted secrets whose tenant's retention period has
// passed, once at start and then every interval, until ctx ends.
func (h *Handler) runRetention(ctx context.Context, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		h.purgeExpired(ctx, time.Now().UTC())
		h.checkRuleSubjects(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// purgeExpired is one sweep. Only the primary runs it: a cluster member
// never writes the replicated secrets tables (docs/CLUSTERING.md). Each
// destroyed secret is audited as audit.secrets.retention_purged, and a
// secret that could not be destroyed as a failure. It returns how many it
// destroyed.
func (h *Handler) purgeExpired(ctx context.Context, now time.Time) int {
	if !clusterstate.RunsPrimaryJobs(ctx) {
		return 0
	}
	tenants, err := h.svc.store.RetentionTenants(ctx)
	if err != nil {
		h.logf("retention sweep: %v", err)
		return 0
	}
	purged := 0
	for _, t := range tenants {
		due, err := h.svc.store.ListDeletedBefore(ctx, t.TenantID, now.AddDate(0, 0, -t.DeletedRetentionDays))
		if err != nil {
			h.logf("retention sweep, tenant %s: %v", t.TenantID, err)
			continue
		}
		for _, s := range due {
			evt := pkgaudit.Event{
				TenantID: t.TenantID, ActorID: retentionActor, ActorType: "service", TargetType: "secret", TargetID: s.ID, Result: "success",
				Details: map[string]interface{}{
					"path": s.Path, "deleted_at": toRFC3339(s.DeletedAt), "deleted_by": s.DeletedBy,
					"retention_days": t.DeletedRetentionDays, "versions_destroyed": s.CurrentVersion, "severity": "warning",
				},
			}
			if err := h.svc.DestroySecret(ctx, t.TenantID, s.ID, retentionActor); err != nil {
				evt.Result, evt.ErrorMessage = "failure", err.Error()
			} else {
				purged++
				if h.keyring != nil {
					_, _ = h.keyring.Remediate(ctx, t.TenantID, "secret", s.ID, "deleted", retentionActor)
				}
			}
			if h.audit != nil {
				emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				_ = h.audit.Emit(emitCtx, "retention_purged", evt)
				cancel()
			}
		}
	}
	return purged
}

// checkRuleSubjects looks up the subject of every stored access rule and
// records the ones that have gone: the rule is stamped, and the first time
// it is found gone audit.secrets.access_rule_subject_missing is emitted (a
// Playbooks trigger), so a rule that names nobody is raised, not left for
// someone to notice. A rule is never removed here: a role with no holders
// reads as gone, and deleting its rule would change who is allowed or
// denied if the role is used again. A subject that could not be checked is
// left as it was. Primary only. It returns how many it newly found gone.
func (h *Handler) checkRuleSubjects(ctx context.Context) int {
	if h.directory == nil || !clusterstate.RunsPrimaryJobs(ctx) {
		return 0
	}
	tenants, err := h.svc.store.RuleTenants(ctx)
	if err != nil {
		h.logf("rule subject check: %v", err)
		return 0
	}
	raised := 0
	for _, tenant := range tenants {
		rules, err := h.svc.store.ListAccessRules(ctx, tenant)
		if err != nil {
			h.logf("rule subject check, tenant %s: %v", tenant, err)
			continue
		}
		subjects := make([]subject, 0, len(rules))
		for _, r := range rules {
			subjects = append(subjects, subject{r.SubjectType, r.SubjectID})
		}
		found, _ := h.directory.Lookup(ctx, tenant, subjects)
		for _, r := range rules {
			info, checked := found[subject{r.SubjectType, r.SubjectID}]
			wasMissing := r.SubjectMissingSince != nil
			if !checked || info.Exists == !wasMissing {
				continue
			}
			if err := h.svc.store.SetSubjectMissing(ctx, tenant, r.ID, !info.Exists); err != nil {
				h.logf("rule subject check, rule %s: %v", r.ID, err)
				continue
			}
			if info.Exists || h.audit == nil {
				continue
			}
			raised++
			emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			_ = h.audit.Emit(emitCtx, "access_rule_subject_missing", pkgaudit.Event{
				TenantID: tenant, ActorID: "system:rule-check", ActorType: "service", TargetType: "secret_access_rule", TargetID: r.ID, Result: "success",
				Details: map[string]interface{}{
					"path": r.Path, "subject": r.SubjectType + ":" + r.SubjectID, "effect": r.Effect,
					"capabilities": strings.Join(r.Capabilities, ","), "severity": "warning",
				},
			})
			cancel()
		}
	}
	return raised
}

func (h *Handler) logf(format string, args ...interface{}) {
	if h.logger != nil {
		h.logger.Printf(format, args...)
	}
}
