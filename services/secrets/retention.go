package main

import (
	"context"
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

func (h *Handler) logf(format string, args ...interface{}) {
	if h.logger != nil {
		h.logger.Printf(format, args...)
	}
}
