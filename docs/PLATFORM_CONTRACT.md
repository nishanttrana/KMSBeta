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

### Routes: the pkg/route kernel

Register every HTTP route through `pkg/route`. Declare what the route is,
and the kernel applies the platform rules:

```go
h := &Handler{svc: svc, router: route.New("myfeature", rt.Audit, rt.Logger)}
h.router.Handle("POST /widgets", route.Spec{
    Action: "widget_created", Permission: "myfeature.write", Resource: "widget",
}, h.createWidget)
h.router.Handle("DELETE /widgets/{id}", route.Spec{
    Action: "widget_deleted", Permission: "myfeature.delete", Resource: "widget",
    TargetParam: "id", Severity: "warning",
}, h.deleteWidget)

func (h *Handler) createWidget(c *route.Call) {
    var req CreateWidget
    if !c.Decode(&req) { return }          // 400, audited as failure
    w, err := h.svc.Create(c.R.Context(), c.Tenant, req) // c.Tenant is already enforced
    if err != nil { c.Error(http.StatusBadRequest, "create_failed", err.Error()); return }
    c.Target(w.ID)
    c.Detail("kind", w.Kind)               // never a secret value
    c.JSON(http.StatusCreated, map[string]interface{}{"widget": w})
}
```

On every request the kernel does the following, in order:
1. Requires verified claims (unless `Public`), otherwise 401 `unauthenticated`.
2. Requires `Spec.Permission` (`route.Allowed`), otherwise 403
   `permission_denied`.
3. Resolves one tenant from `tenant_id`, `X-Tenant-ID`, `Spec.TenantHeaders`
   and the JSON body, defaulting to the token's tenant. Sources that disagree
   get 403 `tenant_conflict`, and a tenant that isn't the token's gets 403
   `tenant_mismatch` (service principals and tenant-less root tokens act for
   the named tenant).
4. Emits one `audit.<service>.<Action>` event with actor, actor type and
   role, tenant, target, correlation ID, method, endpoint, status, duration,
   `severity`, and `result`: `success` / `failure` (with `error_code`) /
   `refused` (with `reason`).

The service test is one line: `routetest.RefusalsAudited(t, h.router, rec)`.
Permissions are `<domain>.<verb>`. In the data-plane domains listed in
`route.CoarseDomains`, `kms.read` grants `*.read`, and `kms.write` grants
`*.write` / `*.delete`. Administrative domains are never added to that list. A
Spec with `OpaqueBody` doesn't read a tenant from the body, for protocols
whose body is the user's data (Vault KV v1). `services/secrets/handler.go` is the
reference. The migration plan for older services is in
[ARCHITECTURE_MIGRATION.md](ARCHITECTURE_MIGRATION.md).

Rules the conformance check enforces:

1. **Crypto** — only `pkg/crypto` (keygen, sign/verify, hash, HMAC, Seal/Open,
   RandomBytes/Reader, SelfSignedMTLSConfig, envelope encryption). No direct
   `crypto/aes|rsa|ecdsa|ed25519|rand|md5|sha1|des|rc4` imports in services.
2. **Audit** — request activity is audited by the `pkg/route` kernel (above).
   Background jobs emit through `rt.Audit.Emit(ctx, action, pkgaudit.Event{...})`.
   Never create AUDIT streams or publish raw `audit.*` subjects. Populate
   `TargetType`, `TargetID`, `CorrelationID` and `RiskScore` wherever known —
   downstream services (dam, governance, reporting, metrics) run on these
   fields alone.
3. **Routes** — no raw `http.ServeMux` in a service outside
   `scripts/route-kernel-burndown.txt`, which only shrinks.

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
