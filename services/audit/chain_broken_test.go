package main

import (
	"context"
	"testing"

	"github.com/nats-io/nats.go"
)

// loopbackPublisher stands in for the AUDIT stream: what is published is
// handed to ingest, as the kms-audit consumer does.
type loopbackPublisher struct {
	svc      *Service
	subjects []string
}

func (l *loopbackPublisher) Publish(ctx context.Context, subject string, payload []byte) error {
	l.subjects = append(l.subjects, subject)
	return l.svc.HandleNATSMessage(ctx, &nats.Msg{Subject: subject, Data: payload})
}

// A broken chain is published to the AUDIT stream, so playbooks and other
// subscribers see it, and is recorded exactly once, by ingest.
func TestChainBrokenPublishedToStream(t *testing.T) {
	_, svc, store, _ := newAuditHandler(t, false, false)
	stream := &loopbackPublisher{svc: svc}
	svc.publisher = stream
	addMerkleSchemaForTest(t, store)
	ids := seedKeyTrail(t, store, "t1")
	mustExec(t, store, `UPDATE audit_events SET actor_id='mallory' WHERE id=$1`, ids[1])

	ok, breaks, err := svc.VerifyChain(context.Background(), "t1")
	if err != nil || ok || len(breaks) == 0 {
		t.Fatalf("verify: ok=%v breaks=%d err=%v", ok, len(breaks), err)
	}
	if len(stream.subjects) != 1 || stream.subjects[0] != "audit.audit.chain_broken" {
		t.Fatalf("published %v", stream.subjects)
	}
	got, err := store.QueryEvents(context.Background(), "t1", EventQuery{Action: "audit.audit.chain_broken", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Result != "failure" || got[0].Details["scope"] != "chain" {
		t.Fatalf("recorded %+v", got)
	}
}

// When the stream refuses the publish, the break is still recorded directly.
func TestChainBrokenRecordedWhenStreamDown(t *testing.T) {
	_, svc, store, _ := newAuditHandler(t, false, true)
	addMerkleSchemaForTest(t, store)
	ids := seedKeyTrail(t, store, "t1")
	mustExec(t, store, `UPDATE audit_events SET actor_id='mallory' WHERE id=$1`, ids[1])
	if ok, _, err := svc.VerifyChain(context.Background(), "t1"); err != nil || ok {
		t.Fatalf("verify: ok=%v err=%v", ok, err)
	}
	got, err := store.QueryEvents(context.Background(), "t1", EventQuery{Action: "audit.audit.chain_broken", Limit: 5})
	if err != nil || len(got) != 1 {
		t.Fatalf("recorded %d, err %v", len(got), err)
	}
}
