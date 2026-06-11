# Platform Contract — How Every Feature Wires In

Every capability added to Vecta KMS — whether hand-written, FeatureForge-generated,
or a customer-side agent — integrates through the same spine. This is enforced by
`make conformance` (scripts/conformance.sh); nothing ships without passing it.

## In-cluster feature services

Start from `pkg/platform`:

```go
rt, err := pkgplatform.Boot(pkgplatform.Options{
    ServiceName:   "myfeature",          // lowercase service name
    JWTScope:      "MYFEATURE",          // jwtauth env prefix
    HTTPPort:      "8123",
    GRPCPort:      "18123",
    MigrationsDir: "services/myfeature/migrations", // "" if no DB
})
if err != nil { log.Fatalf("boot failed: %v", err) }
defer rt.Close()
svc := NewService(NewSQLStore(rt.DB), rt.Audit)
if err := rt.Serve(NewHandler(svc)); err != nil { rt.Logger.Fatalf("serve: %v", err) }
```

`Boot` + `Serve` provide, in order: validated config, database with migrations,
NATS/JetStream, the unified audit client, JWT authentication, the HTTP audit
safety net, an mTLS gRPC listener, Consul registration, and graceful shutdown.
`services/secrets/main.go` is the reference implementation.

Rules the conformance check enforces:

1. **Crypto** — only `pkg/crypto` (keygen, sign/verify, hash, HMAC, Seal/Open,
   RandomBytes/Reader, SelfSignedMTLSConfig, envelope encryption). No direct
   `crypto/aes|rsa|ecdsa|ed25519|rand|md5|sha1|des|rc4` imports in services.
2. **Audit** — emit through `rt.Audit.Emit(ctx, action, pkgaudit.Event{...})`.
   Never create AUDIT streams or publish raw `audit.*` subjects. Populate
   `TargetType`, `TargetID`, `CorrelationID` and `RiskScore` wherever known —
   downstream services (dam, governance, reporting, metrics) run on these
   fields alone.

## Customer-side agents and external integrations

Agents cannot reach NATS. They emit through the audit service's authenticated
HTTP ingest using `pkgaudit.HTTPEmitter`, reusing their existing
`pkg/agentauth` credentials (mTLS → JWT → API key → bearer):

```go
emitter, _ := pkgaudit.NewHTTPEmitter(auditBaseURL, "my-agent", agentID, httpClient, authProvider)
_ = emitter.Emit(ctx, "key_exported", pkgaudit.Event{TenantID: t, TargetType: "key", TargetID: id})
```

Events arrive with `origin=agent` and `agent_id` set, land on the same unified
AUDIT stream, and are visible in the dashboard audit log alongside service
events. `services/ekm-agent` is the reference integration.

## Consuming the audit flow (visibility / governance / metrics)

Attach a durable consumer; never re-implement ingestion:

```go
sub, err := pkgaudit.SubscribeDurable(js, "myfeature-consumer", func(evt *pkgaudit.Event, msg *nats.Msg) {
    // evt carries the full wire schema; ack when processed
    _ = msg.Ack()
})
```

Each durable consumer independently receives every event with replay after
restarts, so new analytics/visibility features need zero changes to producers.
