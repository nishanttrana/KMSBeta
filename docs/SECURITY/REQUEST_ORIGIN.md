# Where a request came from, and who made it

Two facts about a request end up in audit events, lockout counters and
approval records: the address it came from, and who made it. Both come from
what the platform itself verified or observed. Neither comes from anything
the caller wrote.

| Fact | Source | Never |
|---|---|---|
| Address | `clientip.From(r)` (`pkg/clientip`) | the first `X-Forwarded-For` entry, `X-Real-IP`, a body field, `r.RemoteAddr` |
| Actor | `pkgauth.Actor(ctx)` (`pkg/auth`), or `route.Call.Actor()` on a kernel route | an `X-Actor` / `X-User-*` header, a query parameter, a body field |
| Who a request is made for | `tenantcheck.ActingFor(ctx, named)`; for a requester, `tenantcheck.Requester(r, id, email, ip)` | a body field, unless the caller is a platform service |

`make conformance` fails on a second reader of either (`client-address`,
`caller-named-actor`) and on a handler that takes a person from the request
body (`body-named-person`).

## The address

A service never sees the caller's connection; the edge proxy does. Envoy
runs with `use_remote_address: true` (`infra/envoy/envoy.yaml`): it keeps
whatever `X-Forwarded-For` the caller sent and appends the address it
accepted the connection from. So:

- the **last** entry is the platform's own observation;
- every entry before it is the caller's own text;
- a request with no such header came from another platform service (service
  listeners accept only internal mTLS), and its address is the connection's.

`clientip.From` returns the last entry, or the connection's address. If the
last entry is not an address it does not walk left: the answer is the
connection's address.

`TestEdgeAppendsTheAddressItSawOnRealEnvoy` runs the real Envoy image with
that setting and proves the premise; it also fails if `envoy.yaml` drops the
setting or gains one that changes how the header is built
(`xff_num_trusted_hops`, `skip_xff_append`, an original-IP extension).

### What read the first entry until 12.1.0-beta

| Where | Effect of a caller writing the header |
|---|---|
| auth: login lockout key (`tenant, user, address`) | every guess got a fresh counter; the lockout never came |
| `pkg/route`, `pkg/auditmw`, `pkg/jwtauth`: audit `source_ip` | every audit event named the address the caller chose |
| auth: session address, login and SSO audit details | same |
| keycore: actor address in audit details and threat signals | signals and baselines keyed on a chosen address |
| keycore, cloud: `requester_ip` on a destroy or sync | an approval or access record named a chosen address (the body field came first) |

Three more places used the connection's address, which behind the edge is
the proxy's: backup audit events, HYOK's requester address, and the member's
own cluster-forwarding event. They now name the caller's.

### Cluster members

A member forwards a write to the primary. On the way the primary's own edge
appends the *member's* address, so the header no longer ends with the
caller's. The member therefore states the address its edge saw in
`X-Vecta-Cluster-Client-IP`; the primary's cluster-manager reads it only
after it has authenticated the member, and replaces `X-Forwarded-For` with
it on the request it passes to the local service. A value that is not an
address is dropped. A caller can't supply the header: a member strips every
`X-Vecta-Cluster-*` header it receives before forwarding.

### A load balancer in front of the edge

Then the address the edge sees is the load balancer's. It is still not
forgeable, but it is the same for every caller: lockouts count per user
across all callers, and audit events name the load balancer. Trusting a
configured list of proxies is not built; see "Still open".

## The actor

`pkgauth.Actor` is the verified token's user, else its client, else its
subject. It is empty without a verified token.

Until 12.1.0-beta four services took an audit actor from headers nothing in
the platform sends:

| Where | What it recorded |
|---|---|
| dataprotect: tokenize, detokenize, FPE, mask and redact log | `"dashboard"` for everyone, or `X-Actor` / `X-Username` |
| backup: every backup audit event | empty, or `X-Actor` / `X-Username` |
| cluster-manager: join tokens, node changes, connect | the body's `requested_by`, else `X-User-*` / `X-Actor`, else `"system"` |
| governance: backup deletion | `?actor=`, else `X-User-ID`, else `"system"` |

### The requester of a key destruction

`POST /keys/{id}/destroy` took `requester_id`, `requester_email` and
`requester_ip` from the body, for any caller. Governance keeps the recorded
requester from voting on their own request, so a caller who named somebody
else could approve their own key destruction. The requester is now the
verified caller. A platform service (a `kms-*` identity in the platform
tenant, `tenantcheck.IsServicePrincipal`) may still name the person it acts
for, as a playbook does.

## Who a request is made for (13.0.0-beta)

Request bodies across the services carried fields naming a person:
`requested_by`, `updated_by`, `created_by`, `approved_by`, `actor`,
`requester_id`, `requester_email`, `requester_ip`. About forty handlers
used them as written.

| Kind | Where | Effect of writing somebody else's name |
|---|---|---|
| The requester of something others approve | autokey key requests; ekm TDE wrap, unwrap, rotate; cloud sync; hyok; governance key approvals (email, address) | governance kept the *named* person from approving, so the real requester could approve their own request |
| Who created a key | keycore `POST /keys` | the creator's standing over the key went to the named person; the record of who made it was false |
| Who changed or approved something | settings, policies and profiles in autokey, signing, certs, dataprotect, governance, policy; dataprotect wrapper registration (`approved_by`); signing records (`requested_by`); ekm TDE keys and BitLocker operations; key rotation metrics | a false record |

Each is now set in the handler:

- `tenantcheck.ActingFor(ctx, named)` is the verified caller
  (`pkgauth.Actor`). A platform service (`IsServicePrincipal`) may name the
  person it acts for, as a playbook does. Empty without a token.
- `tenantcheck.Requester(r, id, email, ip)` is the caller, no email, and
  `clientip.From(r)`. A platform service's statement is taken as given.
  Governance resolves a user's email from the account, not from the caller.
- HYOK authenticates its caller in the endpoint's own mode, so its
  requester is that verified identity.

`scripts/check-body-named-people.py` reads every handler that decodes a
body and fails unless each such field is assigned before use. Fields that
are data and not the caller are in
`scripts/body-named-people-allowlist.txt` with a reason: a key's and a
CARAF asset's `owner`, the actor of an ingested posture event, keyaccess
`evaluate` (callable only by the ekm, cloud and hyok platform identities),
and two handlers that bind through a helper the script can't follow.

The values recorded are IDs from the token (a user ID or client ID). The
token carries no username or email.

## Still open

- **Trusted proxies in front of the edge** (above). Needs a deployment
  setting and the same rule applied in Envoy.
- **The dashboard still sends `updated_by`, `created_by` and requester
  fields.** They are ignored. Screens that show "updated by" now show the
  caller's ID, not a name.
- **A platform service's statement of who it acts for is taken as given**
  everywhere, as in governance below.
- **Governance's own `POST /governance/requests`** binds a user's requester
  ID, email and (now) address to the caller. A platform service's statement
  is taken as given.

## Which request an event belongs to (13.42.0-beta)

`correlation_id` links one request's audit events across services. The
route kernel takes it from `X-Correlation-ID` when another platform service
sent one, otherwise it uses its own request ID, and puts it in the handler's
context (`pkg/correlation`). Every internal call sends it through
`servicetoken.Authorize`, which every internal client already calls
(conformance `service-token`). The edge drops `X-Correlation-ID` from every
outside request with `x-vecta-delegated-token` and `x-vecta-key-usage`, so
the header a service receives was set by a platform service
(`TestEdgeRemovesTheCorrelationHeader`, and on a real Envoy). It labels
events and decides nothing: it is never used for identity, tenancy or a
permission.

