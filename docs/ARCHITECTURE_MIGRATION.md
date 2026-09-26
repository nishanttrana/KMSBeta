# Architecture migration: from per-handler conventions to a feature kernel

**Status:** phase 0 done (2026-09-26). This is the plan for making
platform-wide rules (audit, tenancy, permissions, policy) apply to every
feature automatically, instead of being re-requested for each one.

## The problem, measured

Features were added one prompt at a time, and each one reimplemented the
cross-cutting rules itself. On 2026-09-26 the services held:

| What | Count | Consequence |
|---|---|---|
| HTTP routes, registered on raw `http.ServeMux` in 31 files | ~960 (517 of them writes) | Nothing checks, at registration time, that a route is guarded or audited |
| Private copies of `writeErr` / `writeJSON` / `requestID` / `decodeJSON` | 26 / 31 / 28 / 28 | A fix to one copy doesn't reach the others |
| Private copies of `mustTenant` | 22 | Each decides where the tenant comes from; only 36 calls to `tenantcheck.Enforce` exist |
| Services with HTTP permission checks | a few (auth, keycore, governance, payment; cluster-manager checks for root admin) | In the rest, any authenticated caller in the tenant can do anything |
| Specific audit events | ad hoc, success path only | Refusals and failures rely on the generic `http_request` record |

A concrete result was that `POST /secrets` took `tenant_id` from the request
body and never compared it with the token, so any tenant could write secrets
into another. The per-handler `mustTenant` was simply not called on that route.
Every one of those 960 routes carries the same risk of a missed check.

## Decision: rebuild the spine, not the product

A ground-up rewrite would throw away the parts that are right and hard-won:
the FIPS module wiring, cluster replication and forwarding, the audit hash
chain, and many security fixes. It would also reintroduce bugs those fixes
closed. What's broken is the *shape*, not the features: the rules live in
each handler instead of one place. So the change is:

1. **Build a kernel** that owns every cross-cutting rule (done: `pkg/route`).
2. **Move services onto it one at a time** ("strangler" migration). Each
   move is a small change that is tested and reviewable on its own, with the
   old and new code side by side.
3. **Make CI enforce it**, so new code can't bypass the kernel and migrated
   code can't regress (done: the `route-kernel` conformance rule).

See [DECISIONS.md](DECISIONS.md) (2026-09-26) for the alternatives we rejected.

## Target layering

```
L3  Edges        dashboard, agents, KMSExtension, SDKs   → call the REST API only
L2  Features     services/<name>: handler (routes + details), service (logic), store
L1  Kernel       pkg/platform (boot), pkg/route (per-request contract),
                 pkg/audit, pkg/config (cluster forwarding, security headers)
L0  Foundations  pkg/crypto, pkg/fips, pkg/db
```

A layer uses only the layer beneath it. A feature (L2) never implements
authentication, tenant resolution, permission checks or request audit. It
declares them, and L1 applies them.

## What the kernel guarantees (pkg/route)

Each route is registered with a `route.Spec`. `Action` and `Permission` are
required, and registration panics at startup without them. On every request
the kernel:

| Concern | How | Refusal (audited, `result: refused`) |
|---|---|---|
| Authentication | verified JWT claims required unless `Public` | 401 `unauthenticated` |
| Authorization | `Spec.Permission`, matched by `route.Allowed` (exact, `*`, `domain.*`, `kms.read`/`kms.write` by verb in `route.CoarseDomains` only, service principals) | 403 `permission_denied` |
| Tenancy | one tenant from query, `X-Tenant-ID`, protocol headers and the JSON body; sources must agree and match the token | 403 `tenant_conflict` / `tenant_mismatch` |
| Audit | exactly one `audit.<service>.<action>` per request with actor, tenant, target, correlation ID, status and outcome | — |

Handlers get a `*route.Call` holding the checked tenant and caller. They add
only domain details (`c.Detail`, `c.Target`) and use `c.Refuse` for their own
refusals (preview, FIPS, integrity).

## Phases

### Phase 0: kernel, reference service, gate (done)
- `pkg/route` and `pkg/route/routetest`.
- `services/secrets` migrated: this closed the cross-tenant write, added
  permissions and specific events for every route, and audits failures and
  refusals.
- `make conformance` rule `route-kernel` with a shrink-only burn-down list
  (`scripts/route-kernel-burndown.txt`).
- Standing rule in `CLAUDE.md`.

### Phase 1: one permission vocabulary
Today's seeded roles only have `*` or `auth.*` permissions, so fine-grained
roles (`readonly`, `audit`) can't be expressed for other domains. The work:
- Publish the permission catalogue from the routers: every
  `Spec.Permission` in use, one list, served by an endpoint.
- Auth seeds the built-in roles from that catalogue (for example, `readonly`
  gets every `*.read` except `*.value.read`), with a migration for existing
  tenants.
- The dashboard role editor lists permissions from the catalogue instead of
  free text.

### Phase 2: migrate the services
Migrate small, sensitive services first, to prove the pattern at low risk,
and the largest last:

1. `software-vault`, `keyaccess`, `signing`, `backup`, `workload`, `confidential`
2. `hyok`, `autokey`, `pqc`, `policy`, `sbom`, `discovery`
3. `reporting`, `posture`, `compliance`, `governance`, `cloud`, `ai-gateway`, `featureforge`
4. `cluster-manager`, `audit`, `dataprotect`, `certs`, `ekm`, `payment`, `kmip` (HTTP API)
5. `auth`, then `keycore` (122 write routes; split by handler file)

**Definition of done for each service:**
- [ ] Every route is registered through `route.Router`; the handler file is
      removed from the burn-down list.
- [ ] The private `mustTenant` / `writeErr` / `requestID` helpers are deleted.
- [ ] Request-scoped `publishAudit` calls in the service layer are deleted.
      The kernel emits the event, and handlers add details. Background jobs
      keep their own `Emit`.
- [ ] Existing audit action names are kept where they exist, so dashboards
      and reports keep working. New names are listed in `docs/API_REFERENCE.md`.
- [ ] `routetest.RefusalsAudited(t, h.router, rec)` passes.
- [ ] Decide, and record in DECISIONS.md, whether the domain joins
      `route.CoarseDomains` (the grants that activated API clients hold).
      Data-plane domains may; administrative domains (auth, cluster,
      governance, audit) never do.
- [ ] A test covers any tenant-from-body or actor-from-body path the old code
      trusted.
- [ ] CHANGELOG lists behaviour changes (new permission requirements,
      tenant defaults).

### Phase 3: more rules in the Spec
Each rule below is added once to the kernel and then reaches every migrated
route:
- `Spec.Preview`: refuse with `409 feature_preview` from `pkg/features`
  automatically.
- `Spec.Approved`: a FIPS algorithm gate that refuses cleanly in strict mode
  and is listed in the impact catalogue.
- `Spec.Policy`: evaluate the policy service before the handler (rules such
  as "no export outside business hours").
- `Spec.Approval`: route through governance approvals for dual control.
- Quotas and rate limits per tenant.
- Generate OpenAPI, the audit-subject reference and the dashboard permission
  list from `Router.Routes()`, so the docs can't drift from the code.

### Phase 4: gRPC and agents
Apply the same `Spec` contract as a gRPC interceptor. Customer-side agents
already use the HTTP audit ingest.

## Adding a feature after this

To add a route to a service that is still on the burn-down list, register it
on a `route.Router` and mount that router on the legacy mux with
`Router.MountOn(mux)`. The new route gets every kernel guarantee now, and the
rest of the file migrates later. Keycore's `POST /system-keys/ensure` and the
`/mek/*` routes on certs, cloud and ekm are added this way.

1. Add routes with a `route.Spec` for each. Choose the action name and
   permission; the kernel does the rest.
2. Add a one-line test: `routetest.RefusalsAudited(t, h.router, rec)`.
3. Add domain tests for the success path.
4. List the new events and permissions in `docs/API_REFERENCE.md`.

Nothing else needs to be requested. A route without an action or permission
won't start, and a raw mux fails CI.
