package main

import (
	"context"
	"encoding/json"
	"log"
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
	// runTimeout bounds one run, delays included.
	runTimeout = 10 * time.Minute
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

// TriggerListener fires playbooks from the audit stream.
type TriggerListener struct {
	store    Store
	executor *PlaybookExecutor
	logger   *log.Logger
	now      func() time.Time
	// dispatch runs an execution; tests run it inline.
	dispatch func(func())

	mu       sync.Mutex
	lastFire map[string]time.Time
}

// NewTriggerListener creates a listener wired to the playbook executor.
func NewTriggerListener(store Store, executor *PlaybookExecutor, logger *log.Logger) *TriggerListener {
	return &TriggerListener{
		store: store, executor: executor, logger: logger, now: time.Now,
		dispatch: func(f func()) { go f() },
		lastFire: map[string]time.Time{},
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

// handle fires every enabled playbook whose trigger matches the event.
func (tl *TriggerListener) handle(ctx context.Context, subject string, data []byte) {
	specs := triggersBySubject[subject]
	if len(specs) == 0 {
		return
	}
	// playbook tables are replicated; the primary runs playbooks and sees
	// every node's events through the audit relay (docs/CLUSTERING.md).
	if !clusterstate.RunsPrimaryJobs(ctx) {
		return
	}
	var evt struct {
		TenantID  string `json:"tenant_id"`
		Result    string `json:"result"`
		TargetID  string `json:"target_id"`
		Timestamp string `json:"timestamp"`
	}
	if json.Unmarshal(data, &evt) != nil {
		return
	}
	stale := false
	if ts, err := time.Parse(time.RFC3339Nano, evt.Timestamp); err == nil {
		stale = tl.now().Sub(ts) > maxTriggerAge
	}
	for _, spec := range specs {
		if spec.SuccessOnly && evt.Result != "" && evt.Result != route.ResultSuccess {
			continue
		}
		tenant := evt.TenantID
		if tenant == "" && spec.Platform {
			tenant = tenantcheck.InternalServiceTenant()
		}
		if tenant == "" {
			continue
		}
		playbooks, err := tl.store.ListPlaybooks(ctx, tenant)
		if err != nil {
			tl.logger.Printf("playbook triggers: list playbooks tenant=%s: %v", tenant, err)
			continue
		}
		for _, pb := range playbooks {
			if !pb.Enabled || pb.Trigger.Type != spec.Type {
				continue
			}
			src := runSource{Trigger: spec.Type, Subject: subject, EventID: evt.TargetID, Actor: pb.AuthorizedBy}
			switch {
			case pb.AuthorizedBy == "":
				tl.audit(pb, src, "", reasonNotAuthorized)
			case stale:
				tl.audit(pb, src, "", reasonStaleEvent)
			case !tl.claim(pb.TenantID + "/" + pb.ID):
				tl.audit(pb, src, "", reasonCooldown)
			default:
				run, err := tl.executor.Start(ctx, pb, src)
				if err != nil {
					tl.logger.Printf("playbook triggers: start playbook=%s: %v", pb.ID, err)
					continue
				}
				tl.audit(pb, src, run.ID, "")
				pb := pb
				tl.dispatch(func() {
					rctx, cancel := context.WithTimeout(context.Background(), runTimeout)
					defer cancel()
					tl.executor.Execute(rctx, pb, run, src)
				})
			}
		}
	}
}

// claim reserves a playbook for the cooldown window.
func (tl *TriggerListener) claim(key string) bool {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	now := tl.now()
	for k, t := range tl.lastFire {
		if now.Sub(t) >= triggerCooldown {
			delete(tl.lastFire, k)
		}
	}
	if _, busy := tl.lastFire[key]; busy {
		return false
	}
	tl.lastFire[key] = now
	return true
}

// audit records a trigger decision: a run started, or why it didn't.
func (tl *TriggerListener) audit(pb Playbook, src runSource, runID, reason string) {
	result, severity := route.ResultSuccess, "info"
	details := map[string]interface{}{
		"trigger": src.Trigger, "subject": src.Subject, "event_target": src.EventID,
		"playbook_name": pb.Name, "run_id": runID,
	}
	if reason != "" {
		result, severity = route.ResultRefused, "warning"
		details["reason"] = reason
	}
	details["severity"] = severity
	tl.executor.emit("playbook_triggered", pkgaudit.Event{
		TenantID: pb.TenantID, ActorID: pb.AuthorizedBy, TargetType: "playbook", TargetID: pb.ID,
		Result: result, CorrelationID: runID, Details: details,
	})
}
