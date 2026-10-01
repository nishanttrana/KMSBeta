package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

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
		h.reconcileCaps(ctx)
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
				_ = h.audit.Emit(emitCtx, "retention_purged", evt) // kept literal: the playbook catalogue test reads this line
				cancel()
			}
		}
	}
	return purged
}

// checkRuleSubjects looks up the subject of every stored access rule, for
// every tenant that has rules (checkTenantSubjects). It is the backstop:
// watchSubjects runs the same check for one tenant as soon as an event says
// a subject may have gone, and listing rules raises what it sees.
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
		raised += h.checkTenantSubjects(ctx, tenant)
	}
	return raised
}

// checkTenantSubjects records the rules of one tenant whose subject has
// gone: the rule is stamped, and the first time it is found gone
// audit.secrets.access_rule_subject_missing is emitted (a Playbooks
// trigger). A rule is never removed here: a role with no holders reads as
// gone, and deleting its rule would change who is allowed or denied if the
// role is used again. A subject that could not be checked is left as it
// was. Primary only. It returns how many it newly found gone.
func (h *Handler) checkTenantSubjects(ctx context.Context, tenant string) int {
	if h.directory == nil || !clusterstate.RunsPrimaryJobs(ctx) {
		return 0
	}
	rules, err := h.svc.store.ListAccessRules(ctx, tenant)
	if err != nil || len(rules) == 0 {
		if err != nil {
			h.logf("rule subject check, tenant %s: %v", tenant, err)
		}
		return 0
	}
	subjects := make([]subject, 0, len(rules))
	for _, r := range rules {
		subjects = append(subjects, subject{r.SubjectType, r.SubjectID})
	}
	found, _ := h.directory.Lookup(ctx, tenant, subjects)
	return h.recordSubjects(ctx, tenant, rules, found)
}

// recordSubjects stamps and raises the rules whose subject a lookup found
// gone, and clears the stamp of those found again.
func (h *Handler) recordSubjects(ctx context.Context, tenant string, rules []AccessRule, found map[subject]subjectInfo) int {
	if !clusterstate.RunsPrimaryJobs(ctx) {
		return 0
	}
	raised := 0
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
		if info.Exists {
			continue
		}
		raised++
		h.emit(ctx, "access_rule_subject_missing", pkgaudit.Event{
			TenantID: tenant, ActorID: "system:rule-check", ActorType: "service", TargetType: "secret_access_rule", TargetID: r.ID, Result: "success",
			Details: map[string]interface{}{
				"path": r.Path, "subject": r.SubjectType + ":" + r.SubjectID, "effect": r.Effect,
				"capabilities": strings.Join(r.Capabilities, ","), "severity": "warning",
			},
		})
	}
	return raised
}

func (h *Handler) emit(ctx context.Context, action string, evt pkgaudit.Event) {
	if h.audit == nil {
		return
	}
	emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = h.audit.Emit(emitCtx, action, evt)
}

// subjectEvents are the audit subjects after which a rule's subject may no
// longer exist: a user, role or client changed in auth, an access group was
// deleted in keycore, a workload registration was removed.
var subjectEvents = []string{"audit.auth.>", "audit.key.access_group_deleted", "audit.workload.registration_deleted"}

// subjectEventMatters narrows audit.auth.> to the account changes; logins
// and token events are most of that traffic and change no subject.
func subjectEventMatters(subject string) bool {
	if !strings.HasPrefix(subject, "audit.auth.") {
		return true
	}
	action := strings.TrimPrefix(subject, "audit.auth.")
	for _, prefix := range []string{"user_", "role_", "client_revoked", "client_updated", "scim_", "group_role_"} {
		if strings.HasPrefix(action, prefix) {
			return true
		}
	}
	return false
}

// watchSubjects re-checks a tenant's rules as soon as an audit event says
// one of its subjects may have gone, so a stale rule is raised in seconds
// rather than at the next hourly sweep. Events for one tenant within delay
// are checked once. It listens on the live subjects, not a durable
// consumer: every node hears every event and only the primary acts, and an
// event missed while down is covered by the sweep.
func (h *Handler) watchSubjects(ctx context.Context, nc *nats.Conn, delay time.Duration) error {
	var mu sync.Mutex
	pending := map[string]bool{}
	for _, subj := range subjectEvents {
		sub, err := nc.Subscribe(subj, func(msg *nats.Msg) {
			if !subjectEventMatters(msg.Subject) {
				return
			}
			var evt struct {
				TenantID string `json:"tenant_id"`
			}
			if json.Unmarshal(msg.Data, &evt) != nil || evt.TenantID == "" {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if pending[evt.TenantID] {
				return
			}
			pending[evt.TenantID] = true
			time.AfterFunc(delay, func() {
				mu.Lock()
				delete(pending, evt.TenantID)
				mu.Unlock()
				if ctx.Err() == nil {
					h.checkTenantSubjects(ctx, evt.TenantID)
				}
			})
		})
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); _ = sub.Unsubscribe() }()
	}
	return nil
}

// Pruning to a changed version cap runs in the background: the request that
// changes the cap returns at once, and a tenant with very many secrets is
// not kept waiting. One run per tenant at a time; a change during a run
// queues another. The result is audited as audit.secrets.cap_prune_completed
// and readable at GET /secrets/version-caps/prune. If the process stops
// mid-run, the hourly reconcileCaps finishes the job: pruning is idempotent.

type pruneStatus struct {
	State       string     `json:"state"` // idle | running | done | failed
	Secrets     int        `json:"secrets_pruned"`
	Versions    int        `json:"versions_pruned"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	Error       string     `json:"error,omitempty"`
	RequestedBy string     `json:"requested_by,omitempty"`

	again bool
}

func (h *Handler) pruneState(tenant string) pruneStatus {
	h.pruneMu.Lock()
	defer h.pruneMu.Unlock()
	if st, ok := h.prunes[tenant]; ok {
		return *st
	}
	return pruneStatus{State: "idle"}
}

// startPrune begins a background prune of the tenant to its current caps,
// or queues one behind the run in progress.
func (h *Handler) startPrune(tenant, actor string) {
	h.pruneMu.Lock()
	if h.prunes == nil {
		h.prunes = map[string]*pruneStatus{}
	}
	if st, ok := h.prunes[tenant]; ok && st.State == "running" {
		st.again = true
		h.pruneMu.Unlock()
		return
	}
	now := time.Now().UTC()
	h.prunes[tenant] = &pruneStatus{State: "running", StartedAt: &now, RequestedBy: actor}
	h.pruneMu.Unlock()

	run := func() {
		for {
			secrets, versions, err := h.svc.ApplyVersionCaps(h.baseCtx(), tenant, actor)
			h.pruneMu.Lock()
			st := h.prunes[tenant]
			st.Secrets, st.Versions = st.Secrets+secrets, st.Versions+versions
			again := st.again && err == nil
			st.again = false
			if !again {
				done := time.Now().UTC()
				st.FinishedAt, st.State = &done, "done"
				if err != nil {
					st.State, st.Error = "failed", err.Error()
				}
			}
			final := *st
			h.pruneMu.Unlock()
			if again {
				continue
			}
			h.emitPrune(tenant, actor, final.Secrets, final.Versions, err)
			return
		}
	}
	if h.spawn != nil {
		h.spawn(run)
		return
	}
	go run()
}

func (h *Handler) emitPrune(tenant, actor string, secrets, versions int, err error) {
	evt := pkgaudit.Event{
		TenantID: tenant, ActorID: actor, ActorType: "service", TargetType: "secret_version_cap", Result: "success",
		Details: map[string]interface{}{"secrets_pruned": secrets, "versions_pruned": versions, "severity": "warning"},
	}
	if err != nil {
		evt.Result, evt.ErrorMessage = "failure", err.Error()
	}
	h.emit(h.baseCtx(), "cap_prune_completed", evt)
}

// reconcileCaps prunes every tenant that has a cap to it, on the primary.
// It finishes a prune a restart interrupted; when nothing is over its cap it
// removes nothing and emits nothing.
func (h *Handler) reconcileCaps(ctx context.Context) int {
	if !clusterstate.RunsPrimaryJobs(ctx) {
		return 0
	}
	tenants, err := h.svc.store.CapTenants(ctx)
	if err != nil {
		h.logf("version cap reconcile: %v", err)
		return 0
	}
	total := 0
	for _, tenant := range tenants {
		if h.pruneState(tenant).State == "running" {
			continue
		}
		secrets, versions, err := h.svc.ApplyVersionCaps(ctx, tenant, "system:cap-reconcile")
		total += versions
		if versions > 0 || err != nil {
			h.emitPrune(tenant, "system:cap-reconcile", secrets, versions, err)
		}
	}
	return total
}

func (h *Handler) baseCtx() context.Context {
	if h.ctx != nil {
		return h.ctx
	}
	return context.Background()
}

func (h *Handler) logf(format string, args ...interface{}) {
	if h.logger != nil {
		h.logger.Printf(format, args...)
	}
}
