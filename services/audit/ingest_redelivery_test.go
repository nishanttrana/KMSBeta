package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	pkgdb "vecta-kms/pkg/db"
)

// jsMsg is a message as a JetStream push consumer delivers it: the reply
// subject carries the stream, its sequence and the time the server stored it.
func jsMsg(seq uint64, stored int64, data string) *nats.Msg {
	return &nats.Msg{
		Subject: "audit.key.encrypt",
		Reply:   fmt.Sprintf("$JS.ACK.AUDIT.audit-ingest.1.%d.%d.%d.0", seq, seq, stored),
		Data:    []byte(data),
		Sub:     &nats.Subscription{},
	}
}

const redeliveryEvent = `{"tenant_id":"t1","service":"key","action":"audit.key.encrypt","actor_id":"u1","result":"success","timestamp":"2026-10-22T08:00:00.123456789Z"}`

func TestStreamEventIDIsTheMessagesPlaceInTheStream(t *testing.T) {
	stored := time.Date(2026, 10, 22, 8, 0, 0, 123456789, time.UTC).UnixNano()
	id := streamEventID(jsMsg(42, stored, redeliveryEvent))
	if !strings.HasPrefix(id, "evt_") || len(id) != len("evt_")+32 {
		t.Fatalf("id %q", id)
	}
	if again := streamEventID(jsMsg(42, stored, redeliveryEvent)); again != id {
		t.Fatalf("a redelivery got %q, the first delivery %q", again, id)
	}
	for name, other := range map[string]*nats.Msg{
		"sequence": jsMsg(43, stored, redeliveryEvent),
		"time":     jsMsg(42, stored+1, redeliveryEvent),
		"payload":  jsMsg(42, stored, strings.Replace(redeliveryEvent, "u1", "u2", 1)),
	} {
		if streamEventID(other) == id {
			t.Fatalf("another %s gave the same id", name)
		}
	}
	if got := streamEventID(&nats.Msg{Subject: "audit.key.encrypt", Data: []byte(redeliveryEvent)}); got != "" {
		t.Fatalf("a core NATS message has no stream place, got %q", got)
	}
}

// A message delivered twice (its ack was lost, or the consumer's stored
// position was, as on 2026-10-22) is one audit event, not two; a payload
// can't choose the id it is stored under.
func TestRedeliveredMessageIsStoredOnce(t *testing.T) {
	_, svc, store, _ := newAuditHandler(t, true, false)
	checkRedeliveredOnce(t, svc, store, "t1")
}

// The same on real Postgres (CI integration-postgres): the partitioned
// audit_events table and its (tenant_id, id, timestamp) lookup.
func TestRedeliveredMessageIsStoredOncePostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	store := NewSQLStore(conn)
	walPath := filepath.Join(t.TempDir(), "audit-wal.log")
	svc := NewService(store, AuditConfig{FailClosed: true, WALPath: walPath, WALMaxSizeMB: 8, WALHMACKey: testAuditKey},
		NewWALBuffer(walPath, 8, testAuditKey), mockPublisher{})
	checkRedeliveredOnce(t, svc, store, fmt.Sprintf("t-redeliver-%d", time.Now().UnixNano()))
}

func checkRedeliveredOnce(t *testing.T, svc *Service, store *SQLStore, tenant string) {
	t.Helper()
	ctx := context.Background()
	event := strings.Replace(redeliveryEvent, `"t1"`, `"`+tenant+`"`, 1)
	count := func() int {
		var n int
		if err := store.db.SQL().QueryRow(`SELECT COUNT(1) FROM audit_events WHERE tenant_id=$1`, tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	stored := time.Now().UnixNano()
	first := jsMsg(7, stored, event)
	for i := 0; i < 2; i++ {
		if err := svc.HandleNATSMessage(ctx, first); err != nil {
			t.Fatal(err)
		}
	}
	if got := count(); got != 1 {
		t.Fatalf("one message delivered twice: %d events", got)
	}
	var id string
	_ = store.db.SQL().QueryRow(`SELECT id FROM audit_events WHERE tenant_id=$1`, tenant).Scan(&id)
	if id != streamEventID(first) {
		t.Fatalf("stored id %q, want the stream's %q", id, streamEventID(first))
	}

	// The same event published again is a new message, so a new event.
	if err := svc.HandleNATSMessage(ctx, jsMsg(8, stored+1, event)); err != nil {
		t.Fatal(err)
	}
	// A payload naming an existing id is stored under its own.
	named := strings.Replace(event, `{`, `{"id":"`+id+`",`, 1)
	if err := svc.HandleNATSMessage(ctx, jsMsg(9, stored+2, named)); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 3 {
		t.Fatalf("three messages: %d events", got)
	}

	// A WAL record of an event already stored (the WAL was not rewritten
	// after the drain stored it) is not stored again.
	if err := svc.wal.Append("ingest", first.Subject, withEventID(first.Data, id)); err != nil {
		t.Fatal(err)
	}
	if err := svc.DrainWAL(ctx); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 3 {
		t.Fatalf("after draining a stored event's WAL record: %d events", got)
	}
	if ok, breaks, err := store.VerifyChain(ctx, tenant); err != nil || !ok {
		t.Fatalf("chain: ok=%v breaks=%v err=%v", ok, breaks, err)
	}
}
