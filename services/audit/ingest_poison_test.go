package main

import (
	"context"
	"errors"
	"testing"

	"github.com/nats-io/nats.go"
)

// A platform event without a tenant is recorded under the platform tenant,
// not rejected: a rejected event was redelivered forever and stalled every
// audit event behind it.
func TestTenantlessEventIsRecordedAsPlatformScoped(t *testing.T) {
	ev, err := parseIncomingEvent("audit.cert.internal_enroll", []byte(`{"action":"audit.cert.internal_enroll","service":"cert","result":"refused"}`))
	if err != nil {
		t.Fatalf("a tenantless platform event must be accepted: %v", err)
	}
	if ev.TenantID != platformTenantID || ev.Details["tenant_scope"] != "platform" {
		t.Fatalf("got tenant %q details %v", ev.TenantID, ev.Details)
	}
}

// A message that isn't an event can never be ingested; it is marked so the
// consumer terminates it instead of redelivering it.
func TestUnparseableMessageIsTerminatedNotRedelivered(t *testing.T) {
	err := (&Service{}).HandleNATSMessage(context.Background(), &nats.Msg{Subject: "audit.x.y", Data: []byte("not json")})
	if !errors.Is(err, errUnparseableEvent) {
		t.Fatalf("want errUnparseableEvent, got %v", err)
	}
}

// auth's legacy routes publish {"data": {...}} with the outcome inside it. A
// refusal was stored as "success" (13.14.0-beta found 81 of them on the live
// stack); the envelope's result, actor and address now come from data when
// the envelope has none, and an envelope that has them keeps its own.
func TestDataEnvelopeKeepsItsRefusal(t *testing.T) {
	ev, err := parseIncomingEvent("audit.auth.request_refused", []byte(`{"tenant_id":"t1","data":{"result":"refused","reason":"not_platform_administrator","actor_id":"usr_1","source_ip":"198.51.100.7"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Result != "refused" || ev.ActorID != "usr_1" || ev.SourceIP != "198.51.100.7" {
		t.Fatalf("result %q actor %q ip %q", ev.Result, ev.ActorID, ev.SourceIP)
	}
	ev, _ = parseIncomingEvent("audit.auth.password_change_refused", []byte(`{"tenant_id":"t1","data":{"result":"refused","actor_user_id":"usr_2"}}`))
	if ev.Result != "refused" || ev.ActorID != "usr_2" {
		t.Fatalf("actor_user_id envelope: result %q actor %q", ev.Result, ev.ActorID)
	}
	// A sign-in's session goes to the session column, so the trail can be
	// followed by session (13.42.0-beta).
	ev, _ = parseIncomingEvent("audit.auth.login", []byte(`{"tenant_id":"t1","data":{"user_id":"usr_3","actor_id":"usr_3","session_id":"sess_9"}}`))
	if ev.SessionID != "sess_9" || ev.ActorID != "usr_3" {
		t.Fatalf("login envelope: session %q actor %q", ev.SessionID, ev.ActorID)
	}
	ev, _ = parseIncomingEvent("audit.x.y", []byte(`{"tenant_id":"t1","result":"failure","actor_id":"a","data":{"result":"refused","actor_id":"b"}}`))
	if ev.Result != "failure" || ev.ActorID != "a" {
		t.Fatalf("the envelope's own fields must win: %q %q", ev.Result, ev.ActorID)
	}
}
