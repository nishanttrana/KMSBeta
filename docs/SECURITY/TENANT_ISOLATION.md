# Tenant isolation at the HTTP edge of each service

Every request is for exactly one tenant, and the caller must be allowed to
act in it. This document says where that is checked, what was found
unchecked in 13.0.0-beta, and what fails if it comes back.

## Where it is checked

| Service is built on | Token | Tenant | Permission | Audit of refusals |
|---|---|---|---|---|
| `pkg/route` kernel (`platform.Boot`, or `pkgjwtauth.MustWrapRouter`) | kernel | kernel: query, `X-Tenant-ID`, and the body's top-level `tenant_id` must agree with each other and with the token | kernel, from the route's `Spec` | kernel |
| a raw mux behind `pkgjwtauth.MustWrap` (13 files, `scripts/route-kernel-burndown.txt`) | middleware | **each handler**, with `tenantcheck.Enforce` | each handler, if at all | each handler |

Only a platform service identity (`tenantcheck.IsServicePrincipal`) may act
in a tenant other than its token's, with one exception in auth below.

### Tenant administration (auth, 13.14.0-beta)

The tenant list, a tenant's lifecycle and roles (`/tenants...`), and
another tenant's users, groups, identity providers, SCIM settings and
policies (`tenant_id` on `/auth/...`) belong to a **platform
administrator**: a person whose verified token is for the `root` tenant
(`tenantcheck.InternalServiceTenant`) and holds `auth.tenant.read` or
`auth.tenant.write` (`platformAdministrator` in `services/auth/handler.go`).
A REST client's or workload's token (it carries `client_id`) is never one,
whatever role it was granted (13.53.0-beta; the same holds for System
Administration in governance).
Every other caller is refused (`403`, `reason: not_platform_administrator`,
audited `audit.auth.request_refused`).

Before 13.14.0-beta the check was "role is `super-admin`, or holds
`auth.tenant.*` or `*`". Every tenant's own administrator holds `*` in its
tenant, so the administrator of any tenant could list all tenants, create,
disable and delete them, and reset the password of the `root`
administrator; and since a tenant administrator can give a user any role
name, the role `super-admin` was a name anyone could take. Services do not
administer tenants (they list IDs from `/internal/tenant-ids`).

The console's top bar no longer offers a tenant switch: a token is for one
tenant and every service refuses another, so switching produced only
refusals. A platform administrator manages other tenants in Administration;
to work inside another tenant, one signs in to it.

`tenantcheck.Enforce` compares a tenant with a token. With no token in the
context it has nothing to compare and returns nil: it is not an
authentication check and must sit behind one.

## What was found (fixed in 13.0.0-beta)

| Service | Fault | Effect |
|---|---|---|
| KMIP management API | `main.go` served the mux with no token verification | With no token: list any tenant's KMIP clients, profiles and interop targets; create and delete them |
| Autokey | `mustTenantChecked` was defined and called by no handler | A signed-in user of any tenant: read and change another tenant's settings, templates, service policies; read and create its key requests |
| Signing | only sign and verify bound the tenant | The same for another tenant's signing settings, profiles, records and summary |

All three now register every route on the kernel through `route.Legacy`,
with permissions (`kmip.*`, `autokey.*`, `signing.*`;
[docs/API_REFERENCE.md](../API_REFERENCE.md)).

Found by asking the running stack, as a user holding one permission, for
every dashboard route for a tenant the user is not in, and again with no
token.

## What fails if it returns

- `scripts/live-check.py`, run after every deploy: every dashboard GET is
  also sent with no token and for a tenant the account is not in. Any 2xx
  fails unless the route is in the script's `PUBLIC` or
  `SAME_FOR_EVERY_TENANT` list, each with its reason. Against 12.3.0-beta
  it reports 18 failures.
- `TestOnlyAPlatformAdministratorActsAcrossTenants` (auth): a tenant
  administrator holding `*`, and a role named `super-admin`, are refused
  the tenant list, tenant create and disable, and another tenant's users,
  password reset, status and policy; a root administrator is not.
- `routetest.RefusalsAudited` in each kernel service: every route refuses a
  caller with no token, without the permission, and naming another tenant,
  and audits each refusal.
- `make conformance`: `route-kernel` (no new raw mux),
  `server-verifies-tokens` (a service that starts an HTTP server holds a
  token verifier; this proves presence, not coverage).

## Routes that answer every tenant alike, or nobody in particular

| Route | Why |
|---|---|
| `GET /auth/sso/providers` | public: the sign-in page lists a tenant's enabled sign-in buttons (provider, display name, type) before anyone is signed in |
| `GET /audit/config` | the audit service's own settings |
| `GET /certs/protocols/schema`, `GET /certs/security/status` | what the service can speak, and its own crypto state |
| `GET /compliance/frameworks` | the built-in framework catalogue |

## Still open

- **Thirteen handler files are not on the kernel.** Their handlers check
  the tenant one by one, and most check no permission: the bootstrap CLI
  user, holding only `auth.self.read`, gets 200 from 66 of 192 dashboard
  GETs in its own tenant. Each file needs the migration in
  [docs/ARCHITECTURE_MIGRATION.md](../ARCHITECTURE_MIGRATION.md).
- **The live check sends GETs without path parameters only.** Writes and
  `/{id}` routes are covered by `RefusalsAudited` on kernel services and
  by nothing equivalent on the thirteen legacy files.
- **`GET /auth/sso/providers` tells anyone which identity providers a
  tenant uses.** Needed before sign-in; not rate limited separately.
- **KMIP, Autokey and signing emit two events per call**: the kernel's and
  their own domain event.
