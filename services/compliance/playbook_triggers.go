package main

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/clusterstate"
	pkgevents "vecta-kms/pkg/events"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

const (
	// triggerCooldown stops one playbook firing again while a burst of the
	// same event is still arriving.
	triggerCooldown = 60 * time.Second
	// maxTriggerAge refuses events replayed long after they happened (a
	// consumer catching up after downtime): a response to a days-old event
	// would act on a situation that has moved on.
	maxTriggerAge = 15 * time.Minute
	// runTimeout bounds one run segment, delays included.
	runTimeout = 10 * time.Minute
	// playbookCacheTTL bounds how stale the listener's view of a tenant's
	// playbooks can be; saves on this node invalidate it at once.
	playbookCacheTTL = 30 * time.Second
	// executorClientID is the compliance service identity. Events it caused
	// never fire playbooks (no chains of playbooks triggering each other).
	executorClientID = "kms-compliance"
)

// triggersBySubject indexes the catalogue by audit subject.
var triggersBySubject = map[string][]TriggerSpec{}

func init() {
	for _, t := range playbookTriggers {
		for _, s := range t.Subjects {
			triggersBySubject[s] = append(triggersBySubject[s], t)
		}
	}
}

// governanceDecisions are the governance events that resolve a paused run.
var governanceDecisions = map[string]string{
	"audit.governance.quorum_reached":    "quorum_reached",
	"audit.governance.quorum_denied":     "quorum_denied",
	"audit.governance.request_expired":   "request_expired",
	"audit.governance.request_cancelled": "request_cancelled",
}

// TriggerListener fires playbooks from the audit stream and resumes runs
// paused for approval.
type TriggerListener struct {
	store    Store
	executor *PlaybookExecutor
	logger   *log.Logger
	now      func() time.Time
	// dispatch runs an execution; tests run it inline.
	dispatch func(func())

	mu    sync.Mutex
	cache map[string]cachedPlaybooks
}

type cachedPlaybooks struct {
	at    time.Time
	items []Playbook
}

// NewTriggerListener creates a listener wired to the playbook executor.
func NewTriggerListener(store Store, executor *PlaybookExecutor, logger *log.Logger) *TriggerListener {
	return &TriggerListener{
		store: store, executor: executor, logger: logger, now: time.Now,
		dispatch: func(f func()) { go f() },
		cache:    map[string]cachedPlaybooks{},
	}
}

// StartListening consumes the audit stream until ctx ends. The durable name
// is unchanged since before 2.4.0-beta so the consumer resumes where it was
// rather than replaying the stream.
func (tl *TriggerListener) StartListening(ctx context.Context, js nats.JetStreamContext) {
	if js == nil {
		tl.logger.Printf("playbook triggers: NATS unavailable, automatic runs disabled")
		return
	}
	sub, err := pkgevents.NewSubscriber(js).SubscribeDurable(pkgaudit.SubjectRoot, "playbook-trigger-listener", func(msg *nats.Msg) {
		tl.handle(ctx, msg.Subject, msg.Data)
		_ = msg.Ack()
	})
	if err != nil {
		tl.logger.Printf("playbook triggers: subscribe: %v", err)
		return
	}
	tl.logger.Printf("playbook triggers: listening on %s", pkgaudit.SubjectRoot)
	<-ctx.Done()
	_ = sub.Unsubscribe()
}

// Invalidate drops a tenant's cached playbooks after a save or delete.
func (tl *TriggerListener) Invalidate(tenant string) {
	if tl == nil {
		return
	}
	tl.mu.Lock()
	delete(tl.cache, tenant)
	tl.mu.Unlock()
}

func (tl *TriggerListener) playbooks(ctx context.Context, tenant string) ([]Playbook, error) {
	tl.mu.Lock()
	c, ok := tl.cache[tenant]
	tl.mu.Unlock()
	if ok && tl.now().Sub(c.at) < playbookCacheTTL {
		return c.items, nil
	}
	items, err := tl.store.ListPlaybooks(ctx, tenant)
	if err != nil {
		return nil, err
	}
	enabled := items[:0]
	for _, pb := range items {
		if pb.Enabled {
			enabled = append(enabled, pb)
		}
	}
	tl.mu.Lock()
	tl.cache[tenant] = cachedPlaybooks{at: tl.now(), items: enabled}
	tl.mu.Unlock()
	return enabled, nil
}

// handle processes one audit event.
func (tl *TriggerListener) handle(ctx context.Context, subject string, data []byte) {
	if ownSubject(subject) {
		return
	}
	// Playbook tables are replicated; the primary runs playbooks and sees
	// every node's events through the audit relay (docs/CLUSTERING.md).
	if !clusterstate.RunsPrimaryJobs(ctx) {
		return
	}
	ev, ok := parseEvent(subject, data)
	if !ok {
		return
	}
	if decision, ok := governanceDecisions[subject]; ok {
		tl.resolveApproval(ctx, ev, decision)
		return
	}
	if ev.ActorID == executorClientID || ev.Details["source_actor_id"] == executorClientID || strings.HasPrefix(ev.CorrelationID, "pbrun_") {
		return
	}
	tenant := firstNonEmpty(ev.TenantID, tenantcheck.InternalServiceTenant())
	specs := triggersBySubject[subject]
	pbs, err := tl.playbooks(ctx, tenant)
	if err != nil {
		tl.logger.Printf("playbook triggers: list playbooks tenant=%s: %v", tenant, err)
		return
	}
	for _, pb := range pbs {
		if !triggerMatches(pb.Trigger, specs, ev, tenant == ev.TenantID) || !matchFilters(ev, pb.Trigger.Filters) {
			continue
		}
		if !tl.thresholdReached(ctx, pb, ev) {
			continue
		}
		tl.fire(ctx, pb, ev)
	}
}

// triggerMatches reports whether t fires on ev. Catalogue triggers match
// their subjects (success only where marked; platform triggers only on
// tenant-less events); custom triggers match their subject pattern.
func triggerMatches(t PlaybookTrigger, specs []TriggerSpec, ev RunEvent, tenanted bool) bool {
	if t.Type == customTrigger {
		return subjectMatches(t.Subject, ev.Subject)
	}
	for _, s := range specs {
		if s.Type != t.Type {
			continue
		}
		if s.SuccessOnly && ev.Result != "" && ev.Result != route.ResultSuccess {
			return false
		}
		return tenanted || s.Platform
	}
	return false
}

// thresholdReached counts matching events for playbooks with a threshold
// above 1, per group_by value, in a sliding window. Counts are stored in a
// replicated table the primary writes, so a failover continues them. When
// the count can't be read or written the playbook doesn't fire, and the
// refusal is audited.
func (tl *TriggerListener) thresholdReached(ctx context.Context, pb Playbook, ev RunEvent) bool {
	t := pb.Trigger
	if t.Threshold <= 1 {
		return true
	}
	group := ev.field(t.GroupBy)
	n, err := tl.store.CountThresholdHit(ctx, pb.TenantID, pb.ID, group, tl.now(), time.Duration(t.WindowSeconds)*time.Second)
	if err != nil {
		tl.logger.Printf("playbook triggers: threshold count playbook=%s: %v", pb.ID, err)
		tl.audit(pb, ev, "", reasonThresholdUnavailable, "the threshold count could not be stored")
		return false
	}
	if n < t.Threshold {
		return false
	}
	if err := tl.store.ResetThresholdHits(ctx, pb.TenantID, pb.ID, group); err != nil {
		tl.logger.Printf("playbook triggers: threshold reset playbook=%s: %v", pb.ID, err)
	}
	return true
}

func (tl *TriggerListener) fire(ctx context.Context, pb Playbook, ev RunEvent) {
	src := runSource{Trigger: pb.Trigger.Type, Actor: pb.AuthorizedBy, ActorType: "user", Event: ev}
	stale := false
	if ts, err := time.Parse(time.RFC3339Nano, ev.Timestamp); err == nil {
		stale = tl.now().Sub(ts) > maxTriggerAge
	}
	switch {
	case pb.AuthorizedBy == "":
		tl.audit(pb, ev, "", reasonNotAuthorized, "")
		return
	case stale:
		tl.audit(pb, ev, "", reasonStaleEvent, "")
		return
	}
	claimed, err := tl.store.ClaimPlaybookFire(ctx, pb.TenantID, pb.ID, tl.now(), triggerCooldown)
	switch {
	case err != nil:
		tl.logger.Printf("playbook triggers: cooldown claim playbook=%s: %v", pb.ID, err)
		tl.audit(pb, ev, "", reasonCooldownUnavailable, "the cooldown could not be checked")
		return
	case !claimed:
		tl.audit(pb, ev, "", reasonCooldown, "")
		return
	}
	if reason, msg := tl.executor.checkAuthority(ctx, pb.TenantID, pb.AuthorizedBy, requiredPermissions(pb.Actions)); reason != "" {
		tl.audit(pb, ev, "", reason, msg)
		return
	}
	run, err := tl.executor.Start(ctx, pb, src)
	if err != nil {
		tl.logger.Printf("playbook triggers: start playbook=%s: %v", pb.ID, err)
		return
	}
	tl.audit(pb, ev, run.ID, "", "")
	tl.dispatch(func() {
		rctx, cancel := context.WithTimeout(context.Background(), runTimeout)
		defer cancel()
		tl.executor.Execute(rctx, pb, run)
	})
}

// resolveApproval continues or ends a run paused on the governance request
// the event names.
func (tl *TriggerListener) resolveApproval(ctx context.Context, ev RunEvent, decision string) {
	id := ev.Details["request_id"]
	if id == "" || ev.TenantID == "" {
		return
	}
	run, err := tl.store.GetPlaybookRunByApproval(ctx, ev.TenantID, id)
	if err != nil || run.Status != runAwaitingApproval {
		return
	}
	pb, err := tl.store.GetPlaybook(ctx, run.TenantID, run.PlaybookID)
	if err != nil {
		tl.logger.Printf("playbook triggers: approval %s: playbook %s: %v", id, run.PlaybookID, err)
		return
	}
	run, cont := tl.executor.Resolve(ctx, run, pb, decision)
	if !cont {
		return
	}
	tl.dispatch(func() {
		rctx, cancel := context.WithTimeout(context.Background(), runTimeout)
		defer cancel()
		tl.executor.Execute(rctx, pb, run)
	})
}

// audit records a trigger decision: a run started, or why it didn't.
func (tl *TriggerListener) audit(pb Playbook, ev RunEvent, runID, reason, msg string) {
	result, severity := route.ResultSuccess, "info"
	details := map[string]interface{}{
		"trigger": pb.Trigger.Type, "subject": ev.Subject, "event_target": ev.TargetID,
		"playbook_name": pb.Name, "run_id": runID,
	}
	if reason != "" {
		result, severity = route.ResultRefused, "warning"
		details["reason"] = reason
		if msg != "" {
			details["detail"] = msg
		}
	}
	details["severity"] = severity
	tl.executor.emit("playbook_triggered", pkgaudit.Event{
		TenantID: pb.TenantID, ActorID: pb.AuthorizedBy, TargetType: "playbook", TargetID: pb.ID,
		Result: result, CorrelationID: runID, Details: details,
	})
}
