# Where a request came from, and who made it

Two facts about a request end up in audit events, lockout counters and
approval records: the address it came from, and who made it. Both come from
what the platform itself verified or observed. Neither comes from anything
the caller wrote.

| Fact | Source | Never |
|---|---|---|
| Address | `clientip.From(r)` (`pkg/clientip`) | the first `X-Forwarded-For` entry, `X-Real-IP`, a body field, `r.RemoteAddr` |
| Actor | `pkgauth.Actor(ctx)` (`pkg/auth`), or `route.Call.Actor()` on a kernel route | an `X-Actor` / `X-User-*` header, a query parameter, a body field |

`make conformance` fails on a second reader of either (`client-address`,
`caller-named-actor`).

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

## Still open

- **Trusted proxies in front of the edge** (above). Needs a deployment
  setting and the same rule applied in Envoy.
- **Other "who asked" fields in request bodies.** `requested_by`,
  `created_by` and `requester_id` are accepted in several services' bodies
  (certs, signing, autokey, hyok, ekm, cloud, keyaccess, posture). Some are
  the end requester in an upstream system, stated by an authenticated
  integration, and belong there; others should be the verified caller. They
  have not been reviewed one by one.
- **Governance's own `POST /governance/requests`** binds a user's requester
  ID, email and (now) address to the caller. A platform service's statement
  is taken as given.
