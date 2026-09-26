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
