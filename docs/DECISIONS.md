# Decisions

The approaches this product is built on, and why. Newest first. Add an entry
whenever you choose between real alternatives, so the choice isn't argued again
or quietly undone. Each entry covers the decision, why it was made, what was
rejected, and how it's enforced.

---

## 2026-09-28 — One home per kind of view (2.12.0-beta)

**Decision.** Charts and trends live only in Overview → Analytics (Key
inventory, Operations, Audit activity, Alerts). Alerts are triaged only in the
Alert Center (reporting's store). The Audit Log is the record and its
integrity (Events, Forensics, Merkle). Compliance shows what the compliance
assessment measured, plus its reports. Posture keeps operational drift cards.
The cryptographic asset inventory is SBOM / CBOM.

**Why.** The owner found Analytics in two places, alerts in two places, and a
Compliance page full of numbers that weren't compliance: alert MTTD/MTTR,
operational cards copied from Posture, a phantom FROST card and a
browser-scored inventory. Each copy drifted and none was obviously the real
one.

**Rejected.** Keeping the Audit Log Alerts tab as a second view of the audit
service's own alert table. It is a separate store from the Alert Center's,
so the two lists disagreed. Retiring or merging that backend store is a
separate change; the UI no longer shows it.

**Enforced by** `tests/smoke-tabs.spec.ts` ("analytics, alerts and audit each
have a single home") and the CLAUDE.md rule under "How we build".

## 2026-09-28 — Webhooks and SIEM are Playbooks connections; compliance holds every outbound credential (2.10.0-beta)

**Decision.** The owner asked for webhooks and SIEM inside Playbooks, not a
separate tab. There is one store of outbound endpoints and credentials:
compliance's sealed connections. It holds Slack, Teams, webhook, Jira,
ServiceNow, and the SIEM types from `pkg/siem`. Three things use it:

- playbook actions, including the new `send_siem_alert`;
- audit event streams, shown under Playbooks → Event streaming;
- governance approval notices.

The audit service and governance hold a connection ID only. They open the
connection through `POST /compliance/connections/{id}/resolve`, which
admits only their service identities and audits every release.

**Why.** The same kind of credential lived in three places with three
security postures: sealed and exposure-tracked in compliance, sealed
separately in audit, and plaintext in governance. One store gives one
validation path, one exposure register, one rotation story and one screen.

**Rejected.**
- *Continuous SIEM streaming as a playbook action.* A SIEM needs every
  event, not incidents. As a playbook it would create one run per audit
  event, and each unattended run re-checks the person's authority with
  auth. Each delivery also emits an audit event, so a playbook matching
  every event would trigger itself. Streaming stays in the audit service,
  which already excludes its own delivery events. Only its credentials and
  UI moved.
- *Compliance delivers on the audit service's behalf* (a `deliver` endpoint,
  so secrets never leave compliance). The kernel audits every call, so each
  streamed event would add a compliance event, and a `*` stream would loop.
  It would also add a per-event internal hop. The audit service now opens
  the connection itself, caches it for 60 seconds, and one
  `connection_resolved` event covers many deliveries.
- *Connections owned by the audit service.* Compliance already had the
  sealed store, tests, exposure register, the jira/servicenow types, and the
  UI. Moving it would have been the larger migration for the same result.

**Enforced by.**
- `TestConnectionResolveRestrictedToAuditAndGovernance`: every other
  caller, admins included, is refused and audited.
- `TestStreamAPIRequiresConnection`: inline URLs and secrets are refused.
- `TestGovernanceSettingsRequireNotifyConnection`.
- The migration tests in audit and governance.
- The Playwright spec `playbook-streams.spec.ts`: the Webhooks tab is gone,
  and a stream sends no credential.

---

## 2026-09-28 — The generated product map is checked, not auto-committed (2.9.0-beta)

**Decision.** `make conformance` runs `generate_product_map.py --check` and
fails when `docs/generated/` is stale. The author reruns the generator and
commits the result with the change.
*Rejected:*
- CI regenerating and committing to `main` (a bot writing to `main`, and a
  commit that didn't pass the checks run on its parent).
- Not committing the output (reviewers and other tools read it from the
  repo).
- A warning instead of a failure (it drifted for five releases while
  nothing failed).

---

## 2026-09-28 — Playbook follow-ups: stored thresholds, required approval policy, tampering on the stream (2.6.0-beta)

- **Threshold counts are stored, in a replicated table the primary
  writes.** This supersedes 2.5.0's in-memory counts. Only events that
  match a threshold playbook's trigger and filters are written, not every
  audit event, which was the cost that earlier decision avoided. Rows older
  than the window are pruned on each write. *Rejected:* rebuilding counts on
  a new primary by replaying the stream (the durable consumer has already
  acknowledged those messages).
- **The playbook approval policy is required.** Disabling or narrowing it is
  refused, and a copy disabled under 2.5.0 is switched back on (audited).
  *Rejected:* letting admins disable it and making gated steps skip
  approval (that removes dual control without anyone deciding to), and
  leaving it disableable with a warning (a silent outage of every gated
  step).
- **The cooldown is stored too (2.7.0-beta)**, as `last_fired_ms` on the
  playbook row and claimed with a conditional `UPDATE ... WHERE
  last_fired_ms <= now - cooldown`. That makes it atomic without a lock
  table. *Rejected:* a separate firings table (one row per playbook is
  enough).
- **`chain_broken` goes through the stream.** Ingest records it once, the
  same way every other event is recorded. If the publish fails, it is
  written directly, so a break is never lost. *Rejected:* recording it
  directly and also publishing it (ingest would store it twice).

---

## 2026-09-28 — Playbooks as the response layer (2.5.0-beta)

**Decision.**
- **Incidents stay in reporting.** Playbooks respond to its
  `incident_opened` and `alert_created` events, act on incidents and alerts
  through its routes, and record the incident on the run. The dashboard
  joins them (incident → runs). *Rejected:* a playbook-owned incident
  record, which would be a second, competing incident list.
- **Authority is re-checked by auth at run time.** Auth owns users and roles
  (`POST /auth/delegated/authority`, kms-compliance only), and an
  unreachable auth fails the run closed. *Rejected:* storing the saver's
  token or a refresh token (a long-lived user credential at rest), and
  copying role data into compliance.
- **Delegated operations** (disable user, revoke API key or client) are
  auth routes that only kms-compliance may call, naming the person. Auth
  verifies that person now, and never targets the person themself, the last
  full administrator or a platform identity. The person is a delegation
  auth verifies, not an identity it trusts: the caller's identity is its
  verified token (CLAUDE.md rule 4). *Rejected:* letting auth admit the
  compliance identity on its admin routes (power over every user in every
  tenant).
- **Approvals are governance requests, resumed from governance's own
  events.** `quorum_reached` only prompts compliance to read the request
  back; the run continues if it is approved and bound (target, action,
  requester, payload hash of the action as now defined). *Rejected:*
  governance callbacks that execute on approval (the approver's vote would
  become the executor), and polling.
- **Credentials live in connections under the compliance MEK** (`pkg/mek`,
  like audit webhooks), and existing inline values are migrated and
  recorded as exposed. *Rejected:* sealing values in place inside
  `actions_json` (every playbook edit would handle secrets), and dropping
  existing values (a silent outage).
- **Email goes through governance's SMTP**, only to active users of the
  tenant. *Rejected:* an SMTP client in compliance (a second mail
  configuration), and arbitrary recipients (a mail relay for anyone who can
  write a playbook).
- **Thresholds count in memory on the primary** (superseded in 2.6.0-beta:
  now stored). A lost count after a failover delays a threshold trigger; it
  never invents one. *Rejected:* a
  replicated counter table written on every audit event.
- **No chains.** Events whose actor is kms-compliance, correlated to a run,
  or alerts raised from them don't fire playbooks; the per-playbook cooldown
  is the backstop for legacy emitters that carry neither.

---

## 2026-09-28 — Playbooks run on a person's authority, from a catalogue of real events (2.4.0-beta)

**Decision.** Playbook actions keep running as the compliance service
identity (keycore and certs admit service principals), but a playbook
borrows that identity only on the authority of a person who holds the same
permissions. Saving an enabled playbook, or running one by hand, needs every
permission its actions use; `authorized_by` records the saver, and automatic
runs are refused while it is empty. Triggers and actions come from one
catalogue (`playbook_catalog.go`) that the API validates against, the
executor runs from and the dashboard renders from `GET .../catalog`. A
trigger lists only subjects a service emits, checked by
`TestTriggerSubjectsAreEmitted`.

*Rejected:*
- **Running actions with the saver's own token.** Tokens expire, and a
  stored refresh token would be a long-lived user credential at rest. This
  is the right end state for actions whose target service won't admit a
  service principal (`disable_user`, `revoke_api_key`); it needs delegated,
  scoped credentials (step 2), so those actions are removed until then.
- **Letting auth admit the compliance identity for user and API key
  changes.** It would give one service account power over every user in
  every tenant.
- **Keeping `destroy_key` and ticking keycore's pre-destroy
  acknowledgements automatically.** Those checks exist so a person confirms
  an irreversible act; a playbook confirming them defeats them.
- **Keeping trigger names nothing emits "for later".** A trigger that can't
  fire is a feature that pretends (rule 8).
- **Rewriting stored action names in a migration.** The tables are
  replicated, so a data rewrite would also run on members; names are mapped
  on read instead.
- **Re-checking the saver's current grants at trigger time.** It needs a
  service-side lookup of another user's permissions that auth doesn't offer
  yet. Until then a playbook keeps its authorization after its author loses
  the permissions; saving it again, or disabling or deleting it, is the
  control. Closed in 2.5.0-beta: auth re-checks the person before every automatic run.

**Also:** outbound actions go through `pkg/ssrfguard`, not the svctls
router, so they never present the service's mTLS certificate; triggered runs
happen on the primary only; events older than 15 minutes don't fire. The
watchdog raises incidents and acts on nothing; its `audit.health.incident`
is the `service_health_degraded` trigger.

---

## 2026-09-28 — Operations metrics: any metered event, cluster-wide on the primary, no backfill (2.2.0-beta)

**Decision.** An event is counted when its details carry
`pkg/audit.MeteredOp`. Each operation is metered once, by the service
whose code does the cryptography. The primary counts members' operations
from the relay of their replicated events, and history before 2.1.0 is not
backfilled.

**Why.** A metering flag on the event, instead of a list of actions in the
audit service, lets every service and every kernel route (`Spec.Metered`)
join without changing the consumer. Metering where the crypto runs keeps one
request from being counted by both the front service and keycore. The relay
cursor already delivers each member event to the primary exactly once. Doing
the metric write in the same transaction as the cursor gives the same
guarantee with no new transport or node-to-node endpoint. The primary's
ingest still skips the relayed copy, so nothing is counted twice.

**Rejected.**
- Metering from `pkg/auditmw`'s generic request event. It is whole-ms, can
  be switched off with `AUDIT_CAPTURE_HTTP_REQUESTS`, cannot tell a refusal
  from a failure, and misses payment's TCP server.
- Replicating `ops_metrics_hourly`. Rows are upserted on every node, which
  logical replication with a single writer per row doesn't allow.
- Computing metrics by query over `audit_events`. It reads millions of rows
  per page load, and percentiles need Postgres-only functions.
- Backfilling from old events. Before 2.1.0 a wrap was logged as an
  encrypt, a MAC as a sign, with no duration and no refusals, so the
  history would be relabelled guesses (CLAUDE.md rule 8). The dashboard
  shows `recorded_since` instead.

**How.** `TestOpsMetricsCountAnyServicesMeteredEvents`,
`TestRelayCountsMemberOperationsOnce`, `TestMeteredRouteMarksEveryEvent`,
`TestDataProtectOperationsMetered`, `TestPaymentOperationsAuditedAndMetered`,
`TestLocalCertificateSigningMetered`, `TestCryptoOpsAuditedWithOutcomeAndDuration`.

**Closed in 2.3.0-beta.** A member forwards its Operations metrics reads to
the primary (`clusterroute.ForwardReads`). Batch calls add their `count`
to `value_count`. An operation is still one request, and values are
reported next to it rather than inflating the operation count or
distorting per-operation latency.

## 2026-09-28 — Operations metrics come from audit events, shown in Analytics (2.1.0-beta)

**Decision.** Key-operation throughput, latency and errors are the
Operations section of Analytics, not a tab of their own. The audit service
builds them from the `audit.key.<op>` events keycore emits for every key
operation. Latency percentiles come from a fixed-bucket histogram.

**Why.** The owner asked whether the tab needed to be separate. Analytics
already answers "how are our keys doing", and operations are the usage half
of that answer. The audit event is the one record every operation already
has to produce (CLAUDE.md rule 2), so deriving metrics from it gives one
source of truth and no second write path to drift from it.

**How.** Keycore's crypto entry points defer `auditCryptoOp`, which names
the event after the operation that ran and carries `duration_ms` and
`result`. Audit's `ProcessEvent` calls `recordOpMetric` after the event is
persisted, so an event that fails to persist is not counted. Enforced by
`TestCryptoOpsAuditedWithOutcomeAndDuration` (keycore) and
`TestOpsMetricsBuiltFromIngestedKeyOpEvents` (audit).

**Rejected.** Keeping the removed record endpoint (`/ops-metrics/record`) and having keycore call
it: that is a second path, and any authenticated caller could post
numbers. Estimating percentiles from the average: that is fabricated data
(rule 7). Storing every sample for exact percentiles: that is unbounded
growth on a hot path. Histogram bounds are the honest resolution.

**Closed in 2.2.0-beta.** Metrics were per node; see the next entry.

---

## 2026-09-28 — Threat & Exposure folded into Keys, Posture and Reporting; leak scanner removed (2.0.0-beta)

**Decision.** The Threat & Exposure tab is removed.
- Keycore keeps threat detection, because the usage trail lives there, and
  runs it every minute on every node.
- Signals leave keycore only as `audit.keycore.threat_signal_raised`.
  Posture raises a finding per signal, and Reporting raises critical and
  high signals as alerts, both from the audit pipeline they already
  consume.
- Canary keys are created from Keys.
- The leak scanner and the credential → key binding registry are deleted.

**Why:**
- Detection that ran only while the tab was open could not alert anyone.
- Posture already has findings, risk scoring, remediation and approvals,
  and Reporting already feeds the header's unread count. A separate
  console duplicated both.
- A KMS scanning pasted text or a folder on its own host is not credible
  secret scanning. That belongs in CI tooling that sees repositories and
  images, and the owner's rule is to remove what isn't really built
  rather than leave it half-done.

*Rejected:*
- **Posture calls a keycore threat API.** That adds a second client and
  identity, where the audit pipeline already carries the signal to Posture
  and Reporting by construction.
- **Sweeping only on the primary.** `key_usage_events` and
  `threat_signals` are node-local and crypto runs on every node, so a
  primary-only sweep would miss member traffic. Every node sweeping its
  own trail writes nothing replicated. The cost is that volume baselines
  are per node.
- **A canary as a real key with material.** A decoy that resolves would
  answer the attacker's crypto requests. The not-found decoy trips on the
  first reference and reveals nothing.
- **Keeping the leak scanner as a Posture sub-view.** The owner chose
  removal.

**Enforced by:**
- `TestThreatSweepCoversEveryTenantSeparately` and the `TestThreat*` tests
  (keycore);
- `TestThreatSignalBecomesFindingOnce` (posture);
- `TestThreatSignalsBecomeAlertsOnScheduledSync` and
  `TestListAlertsDoesNotSyncOnMember` (reporting);
- `TestCanaryRoutesRefusalsAudited`.
## 2026-09-28 — One Health view, in Administration (1.39.0-beta)

**Decision.** Platform > Health and Administration > Health are merged into
Administration > Health. The live service list (auth's discovery and TCP
checks, with restart) stays on top. Watchdog heartbeats, incidents and
reconciler status sit under it as their own sections.

**Why.** They answer the same operator question ("is the platform up?")
from different signals: probes from outside versus liveness each service
reports. Two tabs with one name that disagreed was confusing, and one of
them never worked. Restart is an administration action, so the merged view
belongs there.

**How.** The watchdog and reconciler serve their reads through `pkg/route`
with a new `health.read` permission, instead of reusing `auth.self.read` as
`/auth/system-health` does. Incidents and controller errors are operational
detail, not something every user needs. The dashboard calls them directly
through Envoy (`/svc/watchdog`, `/svc/reconciler`); auth does not proxy
them.

**Rejected.** Aggregating everything in auth's `/auth/system-health`: it
would couple auth to two more services and hide which one failed.

## 2026-09-27 — A key's history comes from its audit trail, shown on the key (1.38.0-beta)

**Decision.** Source Traceability (a discovery-owned `lineage_events` store
with its own graph, provenance, custody and tamper-check views) is removed.
A key's history is its audit events. They are verified per key by the audit
service (`GET /audit/targets/{id}/integrity`), and its callers come from
keycore's `key_usage_events` (`GET /keys/{id}/consumers`). Both appear in
one **History & usage** panel in the key detail view, where people look
before they rotate or delete.

**Why:** lineage had one writer, a manual form, so it recorded claims, not
events. Its tamper check could not fail. The audit trail already records
every key operation with an actor, and it is already tamper-evident (hash
chain, per-event HMAC, Merkle epochs), so a second store would only drift
from it. The usage trail is what keycore itself writes on every crypto
operation.

*Rejected:*
- fixing lineage in place (it would still need a real writer that duplicates
  audit, and a second integrity scheme to certify);
- a separate "history" tab (the question comes up on a key, right before a
  rotate or delete);
- verifying on every panel open (each run is itself audited against the
  key; verification runs when the user asks);
- merging usage across cluster nodes in this change (`key_usage_events` is
  node-local by design; the response says `node_local: true`).

Enforced by `TestTargetIntegrityRejectsTampering` (each way stored data can
be altered is rejected), `TestEventMerkleProofUsesSealedRoot`, and
`TestKeyConsumersFromUsageTrail`.

---

## 2026-09-27 — Built-in approval policy for posture escalation (1.35.0-beta)

**Decision.** Governance creates **Posture escalation (built-in)** in a
tenant on the first escalation that finds no active covering policy. Its
approvers are tenant administrators (`admin`, `tenant-admin`) other than the
requester, and one approval is enough. The policy has a fixed per-tenant ID.
Editing or disabling it is the administrator's choice and is kept (a
disabled one is never recreated); deleting it is refused.

**Why:** 1.34.0-beta made escalation dual-controlled, but a fresh tenant had
no policy, so the feature was refused everywhere until someone found the
setup step. Tenant admins are the one role every tenant has, and requiring
a second admin keeps the dual control real.

*Rejected:*
- seeding at tenant creation (tenants live in auth; governance learns of a
  tenant only when it is used);
- a code-only fallback with no row (`approval_requests.policy_id` references
  a policy, and admins could not see or change it);
- recreating after a delete (it would silently undo an administrator's
  decision);
- letting posture create the policy (policy changes need a tenant
  administrator, never a service).

Creation runs on the primary only (`approval_policies` is replicated).

---

## 2026-09-27 — Posture remediation: one real executor, governance-bound approvals (1.34.0-beta)

**Decision.** Posture executes only action types it can perform against a
named object. Today that is `escalate_remediation`, which changes the overdue
finding it names. The other eight types are no longer created: their
findings are aggregate counts, so there is no connector, client, credential,
HSM profile or certificate to act on. The unconsumed
`audit.posture.runbook.execute` event and `POSTURE_AUTO_REMEDIATE` are
removed. Approvals are governance requests posture opens as its service
identity, with the verified caller as requester, bound by target and payload
hash to one action. The executor must be the requester. *Rejected:*
- a labelled preview for the eight types (rule 8 prefers removal, and the
  finding's recommended action already carries the guidance);
- executors that guess a target (for example quarantining the most active
  client);
- governance callbacks that execute on approval (the executor would be the
  approver's vote, not a verified caller);
- trusting a client-supplied approval ID, as before;
- letting any user run on another user's approval (dual control means one
  person asks, another approves, and the asker executes).

Legacy rows are corrected by an idempotent primary-only job, since
`posture_actions` is replicated and a SQL migration would also run on
members.

---

## 2026-09-27 — sbom and reporting on the route kernel (1.33.0-beta)

**Decision.** Both handler files are migrated whole to `pkg/route`, not
patched with `tenantcheck.Enforce` on the three routes that lacked it. The
tenant and actor come from the kernel; the old `requested_by` / `actor` body
fields are rejected (400) rather than silently ignored, so a client relying
on them learns it. A body `tenant_id` is still accepted when it matches the
token, since the kernel verifies it.

**Alert operations share one pattern,** `PUT /alerts/{id}/{op}`, audited as
`alert_updated` with `operation`. Four literal patterns
(`/alerts/{id}/resolve`, ...) conflict with `PUT /alerts/rules/{id}` in Go's
mux (neither is more specific), and moving rule updates would break clients.

**The platform SBOM needs the platform tenant to change.** Snapshots and
manual advisories are shared by every tenant; a tenant admin elsewhere holds
`sbom.write` through `*` and must not change what all tenants see. Rejected:
a new platform-admin permission (no role grants it yet, so it would lock
everyone out).

**Request audit moves from the service to the kernel.** Where the reporting
service published `audit.reporting.<x>` for an API request, the kernel now
emits the same subject (with the verified actor), so consumers keep working
and nothing is emitted twice. Events for background work (scheduled runs,
alert ingestion, snapshot generation) stay in the service.

---

## 2026-09-27 — Posture on the route kernel (1.32.0-beta)

**Decision.** All posture routes are kernel routes with three permissions:
`posture.read`, `posture.write` and `posture.action.execute`. Posture does
**not** join `route.CoarseDomains`: it is an analytics and remediation plane
whose actions change controls, so `kms.read`/`kms.write` API-client grants
don't reach it. The wildcard tenants `*` and `all` are refused on every
engine route, including for tenant-less root tokens and service principals,
because the kernel binds exactly one tenant and `*` is the row key of the
cross-tenant aggregate snapshot; the all-tenant scan runs only in the
in-process scheduler. `main` wraps the kernel in a claims-only middleware
that forwards a missing or invalid token without claims, so the kernel
refuses it and audits it under the route's action, and posture refuses to
start without a JWT key. *Rejected:* `jwtauth.MustWrap` (its 401 is only
seen by the generic request log, not as `audit.posture.<action>`
`unauthenticated`); keeping an unauthenticated path for reporting (it has a
provisioned `kms-reporting` identity); serving `*` to root admins (no UI
uses it, and it would be the only cross-tenant read in the API). A batch
item naming another tenant refuses the whole batch rather than being
dropped, so a caller never gets a partial success it didn't ask for.

---

## 2026-09-27 — Attested key release: seal to a key the evidence commits to

**Decision** (1.30.0-beta). A release goes to a public key generated inside
the enclave and committed to by *verified* evidence (Nitro `public_key`; OIDC
nonce = base64url(SHA-256(DER))). Keycore seals the material to it with
RSA-OAEP-256 + AES-256-GCM (SP 800-56B key transport, approved in FIPS mode),
and only the confidential service identity may ask.

**Why.** Binding the output to the enclave's own key makes the release safe
against replayed evidence and a compromised caller: the sealed blob is useless
outside the enclave. RSA is what Nitro recipients use (AWS KMS's own Nitro
recipient flow), and the hybrid construction carries any key size.

**Rejected.** Returning plaintext to the caller after an allow (anyone with
the evidence could fetch the key); HPKE/X25519 (not approved in FIPS strict
mode); letting any `kms-*` service release keys.

---

## 2026-09-27 — OpenAPI specs: remove the fabricated one, check the rest (1.29.0-beta)

**Decision.** The `ai` OpenAPI spec is deleted rather than rewritten as an
`ai-gateway` spec, and the other four specs are checked by
`scripts/check-doc-routes.py` in conformance: servers must be edge
`/svc/<name>` paths and every operation must be a registered route of that
service. **Why:** rule 8 prefers removing what is not real, and a new
hand-written spec for 30 ai-gateway routes would be another unchecked
contract (only paths are checked today). `ai-gateway` routes are listed in
the generated route index in `docs/API_REFERENCE.md`. *Rejected:* keeping
`http://localhost:<port>` servers labelled "direct" (services are reached
through Envoy, not plain HTTP); a separate OpenAPI checker (it would duplicate
the route and Envoy-prefix resolution the doc check already has).

---

## 2026-09-27 — Closing the 1.27 open items (1.28.0-beta)

**Microsoft DKE.** Entra ID tokens are verified with `pkg/oidc` against the
Entra tenant's key set, which is derived from the issuer's tenant ID on
`login.microsoftonline.com` (never from a URL in the token). The issuer has to
be listed in the endpoint's `valid_issuers`, and audience and authorized users
are required, not optional. An Entra token without them would admit anyone
the tenant can mint a token for. The Vecta tenant is found from the
endpoint that trusts the issuer, because Office calls the key URL as
configured in the label and sends no Vecta tenant. Several tenants
trusting one issuer is refused, not guessed. The wire format follows
Microsoft's reference service. The public key is anonymous only on the
configured DKE host. *Rejected:* discovering keys through the token's `iss`
URL (an unverified value would choose the key server); decrypting a
non-current version with the current key (a wrong key, not a real
decrypt).

**Google CSE authentication audience.** Explicit
`authentication_client_ids` per config; existing configs fail closed until
set. *Rejected:* accepting any Google ID token for the domain, which is
what the missing check allowed.

**Governance approver roles.** Roles are expanded to users when the request
opens and stored as its approvers (tokens), consistent with "approvers are
fixed by the request". *Rejected:* checking the voter's role at vote time,
because email-link votes carry no token claims and a later role change would
shift a running quorum.

**JCA provider.** Offer only what the KMS API does: key wrapping under a TDE
key (`Cipher.VectaKeyWrap`). *Rejected:* keeping AES-GCM, Signature and
KeyStore by adding server routes to match. They were never real, and a
remote `AES/GCM/NoPadding` that cannot honour caller IVs is a mislabel. The
SDK zip embeds the source (`go:embed`) so it cannot drift. The provider runs
on OpenJDK; Oracle JDK needs an Oracle JCE signing certificate.

**Docs.** A route-existence check in conformance instead of hand review:
`scripts/check-doc-routes.py` reads the routers and Envoy prefixes. A plain
word matches a route parameter only when no sibling route has a literal
there. Invented sections are removed, not marked.

---

## 2026-09-27 — Second fake sweep: identity only from verified credentials; remove what cannot load

**Context.** The second sweep (1.27.0-beta) found services that took identity
from the TLS peer (hyok, EKM), from request bodies (governance votes, signing),
or from unverified tokens (SAML, OIDC, KACLS), and client artefacts that no
consumer could use (PKCS#11 provider, JCA `VectaQRNG`).

**Decisions.**
- *Identity comes only from a credential the service verifies* (a JWT against
  the platform key or an IdP's JWKS, an XML signature against a configured
  certificate). The internal mTLS peer identifies the calling service; behind
  Envoy it is always Envoy, so it is never a user or tenant identity. Customer
  client-certificate auth (hyok `mtls`) is refused rather than kept, because the
  edge does not verify client certificates; it can return when Envoy validates
  them and services check `x-forwarded-client-cert` from the Envoy peer only.
- *One verifier package.* `pkg/oidc` does discovery, JWKS and claim checks for
  SSO, signing and KACLS, so the rules (asymmetric algorithms only, exact
  issuer, audience, expiry) are the same everywhere.
- *SAML uses goxmldsig* (v1.6.1, with beevik/etree) rather than hand-written
  canonicalisation: XML-DSig is easy to get subtly wrong, and the library returns
  the verified element so signature wrapping cannot slip values past it.
- *Remove, don't rebuild, the PKCS#11 provider.* A correct module (function
  list, attributes, mechanisms, sessions, tested with pkcs11-tool and
  SunPKCS11) is a project of its own. REST, KMIP and the JCA provider cover
  application access; rebuilding it is for the owner to request.
- *TDE via KMIP only.* Vecta's real path for a database's master key is its
  KMIP server; engines without a KMIP key manager are documented as unsupported.

**Rejected.** Keeping peer-certificate identity "for direct connections":
services only accept internal-CA clients, so no customer can connect directly.

## 2026-09-27 — Fake capabilities: make real where the path exists, otherwise remove
**Decision** (1.26.0-beta, owner directive "fix all of this"):
- **Made real** where a real dependency already existed:
  - FF1 (NIST SP 800-38G on the module's AES);
  - `hsm-trng` (the tenant HSM's `C_GenerateRandom` through hsm-connector);
  - discovery (TLS handshakes, the cloud service's live inventory, the certs
    list, a mounted code tree);
  - PQC migration (successor keys in keycore);
  - playbook `trigger_assessment` / `snapshot_posture` (run in-process);
  - AI gateway health (a database ping and detector self-checks).
- **Removed** where no real path exists:
  - Feature Forge, which had no environments to stage or deploy to;
  - FF3-1, withdrawn by NIST's SP 800-38G Rev. 1 draft;
  - the QKD and QRNG random sources;
  - playbook actions without an executor;
  - the SBOM fallback CVE list;
  - the invented cost figure and "entropy" score;
  - dead code (`pkg/hwtoken`, `pkg/caim`, unwired keycore types).
- **Relabelled** where the capability is real but was overclaimed:
  confidential compute returns a *verdict*, not a key release; watchdog
  incidents are alerts with a recommendation.

**Why:** CLAUDE.md rule 8 (preferring removal over a stand-in) and rule 7
(never fabricate evidence), including audit events that certified work that
never happened.

**Rejected:**
- *Keeping Feature Forge with a "preview" label.* It stored nothing a preview
  could honestly describe, and its guardrails and apply path were broken.
- *Mapping FF3-1 to FF1.* Its ciphertext would silently change meaning.
- *Building attested key release now* (wrapping to the enclave's public key).
  It needs a keycore export-to-recipient endpoint restricted to the
  confidential service identity; it is recorded as open in
  REAL_CAPABILITY.md.
- *Deleting keys whose material was faked.* They are relabelled
  (`INVALID-MATERIAL`, or the real algorithm) and audited instead, so nothing
  is destroyed without the customer's decision.

**Migration:** pre-1.26.0 FPE ciphertext is readable through decrypt-only
`LEGACY-FF1` / `LEGACY-FF3-1` (audited), then re-encrypted with FF1. This is a
per-value migration, never a silent switch (CLAUDE.md rule 6).

**Enforced by:**
- NIST FF1 vector tests;
- refusal tests for each removed path;
- a real TLS server in the discovery tests and real SoftHSM2 in the HSM
  random tests;
- `make conformance` `real-capability` (now also `MOCK_*` constants and
  `newMock…` constructors).

## 2026-09-27 — Webhook credentials: one sealed envelope, key opened in the background

- **Decision:** the secret and all header values of a webhook go into one
  envelope under a `pkg/mek` master key for the audit service. Header names
  stay in plaintext (the API shows them).
- **Rejected: one envelope per field.** `pkg/mek` tracks one wrapped DEK per
  row, and a single envelope keeps rotation and the backup re-wrap simple.
- **Binding:** the sealed payload includes the tenant and webhook ID, which
  are checked on open. That gives the effect of AAD without changing the
  shared envelope format.
- **Rejected: refuse to start until the key is open**, as secrets, certs,
  cloud and ekm do. Audit is the sink, and blocking it on keycore would
  suspend the audit trail during exactly the incidents it must record.
  Instead, credential writes and credentialed deliveries fail closed until
  the key is open, and a key mismatch disables them without stopping ingest.
- **Existing plaintext rows:** sealed on the primary, and recorded in the
  exposure register (`plaintext_storage`) before sealing, because a database
  copy made before the change still has them.
- **Retiring an entry:** the entry is retired only when every credential has
  been replaced. Rotating the secret alone leaves a Splunk token exposed.

---

## 2026-09-27 — Rotation policies and webhook delivery: how they run

**Rotation.** A trigger rotates keys *as the caller*, so the caller's key
grants and the policy service decide each key. A scheduled run needs an
identity with no user present. It uses an in-process keycore service
principal, set in code, never from a request, so it can't be forged (rule 4).
The rejected alternative was to replay the policy creator's identity: a user
removed later would still rotate keys, and a stored identity can be spoofed.
The authority therefore comes from `key.rotation.write`, which only admins
hold by default, and every scheduled run is audited with its counts. Only
keys are supported. Secrets and certificates rotate in their own services;
a policy there would be a record with nothing behind it. The scheduler runs
on the primary only, because policies and runs are replicated tables.

**Webhooks.** Delivery hooks into `ProcessEvent` after the event is
persisted, so only events in the chain are delivered, and each one exactly
once, on the node that ingested it. Relayed duplicates are skipped before
processing. A separate JetStream consumer was rejected: it would see
unpersisted and duplicate events. Subscriptions are audit action patterns
(`audit.key.*`) rather than a parallel event vocabulary. The old names
(`key.created`) matched nothing and would have needed a mapping kept in sync
by hand. Delivery audits (`audit.audit.webhook_*`) are excluded from matching
so a `*` subscription can't loop. Members record attempts in node-local
`webhook_deliveries` and leave the replicated `webhooks` row to the primary.
The outbound client dials only SSRF-checked addresses, follows no redirects
and requires TLS 1.3, so a validated URL can't be re-pointed at an internal
host by DNS or redirect.

---

## 2026-09-27 — Service mTLS: per-service policy by published file, restart to apply
**Decision:**
- **Where the policy lives:** each internal identity's certificate key and
  key-exchange profile are stored in certs (`cert_internal_mtls_policy`,
  replicated) and published as a public file on the trust volume every
  service already mounts.
- **Applying it:** a service reads it before enrolling and restarts itself
  when its entry changes. A rotation is a generation bump: the old
  certificate is revoked and the service restarts.
- **Reporting:** services report what they run to `platform_mtls_observed`
  through the connection they already use for the FIPS mode.

**Why:**
- **Before enrolment.** A file can be read before the service has a
  certificate. A policy endpoint would need mTLS to fetch the policy that
  mTLS depends on.
- **No audit noise.** A polling route would audit about one event a second.
- **Restart, not hot swap.** A restart drops every session made with the
  old key, and it is the same graceful path the FIPS mode change already
  uses.
- **The page shows reports.** It shows what services report, not what was
  requested.

**The profile governs the server side.** Clients always offer every group.
- Envoy offers only `X25519MLKEM768` among the post-quantum groups. If the
  choice restricted clients too, or ML-KEM-1024 were offered as a profile,
  one click could make services unreachable through the gateway.
- "PQC required" is enforced where it can't break a caller: the service
  refuses classical-only peers.

**Rejected:**
- A policy endpoint on the enrolment listener.
- Hot-swapping certificates without a restart: sessions under the old key
  would survive.
- Per-group lists: they can break callers.
- ML-DSA certificate keys: the certified module v1.0.0 has none.

**Resolved (owner, 2026-09-27): PQC certificates removed** (1.19.0-beta).
Certificates and CAs requested as PQC (ML-DSA, SLH-DSA, XMSS/LMS) or hybrid
got ECDSA keys while recorded and audited as PQC (rule 8). They can't be made
real on the certified module, so the feature is removed rather than kept as
a preview:
- Such requests are refused and audited (`audit.cert.pqc_issuance_refused`).
- The PQC routes, profiles and stateful-signature counters are gone.
- Existing records are relabelled to their real key and deleted PQC
  profiles are audited.

---

## 2026-09-27 — Envelope encryption: KMS generates and wraps DEKs, never stores them
**Decision:** envelope encryption is `POST /keys/{id}/generate-data-key`
(fresh DEK, plus the DEK wrapped under a keycore key) and `/unwrap` to recover
it. The caller stores the wrapped DEK with its data. The keycore KEK/DEK
"hierarchy" tables are removed.

**Why:**
- Envelope encryption exists so bulk data never crosses the wire to the KMS.
  Only the 32-byte DEK is wrapped and unwrapped.
- The KEK is an ordinary keycore key, so it gets real versions, rotation,
  access policy, FIPS mode, HSM backing and audit for free.
- A KMS-side DEK registry would either hold wrapped DEKs the KMS cannot
  usefully rewrap without the data owner, or leak usage metadata. AWS KMS,
  GCP KMS and Vault Transit don't keep one either.

**Rejected:**
- Making the old `/envelope/*` tables real. That would duplicate keycore key
  lifecycle in a second, weaker model.
- A separate `decrypt-data-key` route: `/unwrap` already does exactly this
  and is audited.

**Enforced by:** `TestGenerateDataKeyRoundTripsThroughUnwrap`,
`TestGenerateDataKeyRefusalIsAudited`, `TestDataKeyRoutesRefusalsAudited`.

---

## 2026-09-26 — Re-key the CRWK on a passphrase change, don't just re-seal it
**Decision:** when the certs CRWK passphrase changes, including the
migration off the retired public default, certs:
1. generates a **new random CRWK**;
2. rewraps every CA signer's DEK and the internal PKI cache under it;
3. only then replaces `crwk.sealed` and deletes the retired key and the
   previous passphrase.

**Why:**
- Re-sealing the same CRWK under the new passphrase would be one file
  write. But any copy of the old `crwk.sealed` (a volume backup or
  snapshot) would still open, with the public passphrase, every CA signer
  in the current and future database.
- With a new CRWK, an old sealed file only opens database rows from before
  the rotation. Those are covered by rotating the CAs, which the docs say
  to do if such copies may exist.

**Also decided:**
- **Resumable in place.** Both keys are held, selected by
  `signer_kek_version`, while the rewrap runs. `crwk.sealed.next` survives
  a crash. Nothing is deleted until every row is rewrapped, so a failure
  loses nothing and is retried on the next start.
- **The passphrase is generated inside the volume** by a script the start
  scripts and installer share (`infra/scripts/crwk-passphrase.sh`). It
  never crosses the host, and there's no `.env` copy to leak.
- **The retired value is recognised by its SHA-256.** The literal can then
  be banned from code by `no-retired-public-secret`.

**Rejected:**
- A startup flag to "accept" the public passphrase for a grace period: that
  is a fallback, which rule 3 forbids.
- Rewrapping in the helper container: it has no Argon2id, and the rewrap
  needs the database.

**Open:**
- The passphrase file sits on the same volume as `crwk.sealed`, so the
  volume alone opens the CRWK. A host-held or TPM-sealed passphrase would
  separate them.
- ~~`CERTS_CRWK_USE_TPM_SEAL` isn't real~~ **Resolved in 1.15.0-beta:**
  it only recorded a flag, so it was removed rather than implemented (rule
  8). Real TPM sealing would be a new feature, built end to end.
- Cluster members don't rewrap; the primary's rows replicate.

---

## 2026-09-26 — Internal PKI before the database; FIPS mode from a file (slice 2)
**Decision:**
- **Internal PKI:** the certs service keeps the runtime root and Sub CA in a
  sealed cache on its key volume (signing keys wrapped by the certs root
  wrapping key, as in the database). It issues its own and the daemons'
  certificates before connecting to Postgres, then records them.
- **Existing installs:** the start script exports the two CA rows once, over
  Postgres' Unix socket.
- **FIPS mode:** services read the platform mode from a file governance
  writes, not from the database.

**Why:** Postgres now requires internal mTLS, which creates two cycles.
- *CA ↔ database:* the CA lived only in the database the CA now secures.
- *FIPS mode ↔ TLS:* reading the mode needed a TLS handshake, which is
  cryptography done before the mode is decided.

**Rejected:**
- *A bootstrap self-signed Postgres certificate pinned by certs*: certs
  would still have no client certificate, so it couldn't do mTLS.
- *Retiring the existing root and starting a new one*: every client trusting
  it (payment terminals, KMIP) would break.
- *Keeping the database read with a TLS fallback*: that is plaintext by
  another name.

**Also removed:**
- etcd (no consumer).
- pgbouncer (no DSN pointed at it).
- The Consul Connect bootstrap (no service used Connect).

A daemon nothing uses is still an open port.

**Enforced by:**
- `TestBootstrapCreatesThenReusesTheInternalPKI`,
  `TestPKICacheReadsPsqlRowToJSON`,
  `TestBootstrapEnrolmentAndInfraCertsBeforeTheDatabase`,
  `TestReconcileRecordsBootstrapStateAndSwitchesToTheDatabase`,
  `TestReconcileRefusesADifferentCAWithTheSameName`;
- `TestPlatformFIPSModeFromFile`, `TestSyncPlatformFIPSModeFile`,
  `TestPendingReaderHoldsPrimaryJobs`;
- the live wire checks recorded in `docs/SECURITY/INTERNAL_TLS.md`.

## 2026-09-26 — How internal mTLS is wired (slice 1)
**Decision:**
- **Enrolment proof:** an HMAC over the CSR under the identity's
  platform-derived API key (`servicetoken.DeriveAPIKey`). The certs service
  checks it itself, so enrolment doesn't depend on auth, which needs a
  certificate too.
- **Clients:** one routing transport installed as `http.DefaultTransport`
  instead of editing about 60 client call sites. Platform hosts go over mTLS
  and plain `http://` to them is refused; other hosts keep public-CA trust.
- **Envoy:** it routes `/svc/*` and `/auth` straight to the services, so it
  is the only component holding an internal client identity for UI traffic.
  The dashboard's nginx serves static files only.
- **Certificate reload:** Envoy's certificates reload through file-based SDS
  with a watched directory, and nginx through a certificate-watch reload.

**Why:**
- The shared transport changes every client at once, and the refusal
  enforces the rule at runtime.
- One owner of the internal client identity for UI traffic means one place
  to rotate it.
- Certificates renew every few days, so every consumer has to reload them.

**Rejected:**
- *Trusting both public roots and the internal CA in one pool*: an internal
  certificate could then pass as a public host. Trust is split by host
  instead.
- *Making nginx an mTLS proxy to every service*: it would be a second client
  identity, and duplicate Envoy's routing.
- *Enrolling through auth-issued JWTs*: a cyclic dependency at start-up.

**Enforced by:** `pkg/svctls` tests (real handshakes: missing, foreign or
plain; the hybrid group asserted), the certs enrolment tests, and the
`make conformance` `tls-only` rule.

## 2026-09-26 — Internal mTLS from an internal-services Sub CA, keys enrolled by CSR
**Decision:** every internal connection moves to mTLS.
- **CAs:** a new Sub CA, `vecta-internal-services`, is created under the
  existing `vecta-runtime-root` at deployment, and every internal
  certificate comes from it.
- **Enrolment:** each service generates its key and enrols with a CSR,
  authenticated by its platform service identity.
- **Controls:** rotation and mechanism choice (including the PQC hybrid
  groups `X25519MLKEM768`, `SecP256r1MLKEM768` and `SecP384r1MLKEM1024`) are
  per service in the dashboard. The swap is a graceful drain and re-exec,
  or a forced restart.

**Why:**
- The owner's directive: nothing is HTTP, and internal traffic uses
  internal-CA mTLS.
- Service calls carry key material today over plain HTTP. The fake "mTLS
  Mesh" hid that gap.
- A Sub CA keeps the root out of daily issuance, and lets the internal
  certificate estate be rotated or revoked on its own.

**Rejected:**
- *Issuing from the root directly*: it puts the root in the hot path.
- *Writing every service's key into the shared `runtime-certs` volume*: one
  compromised service could read every key.
- *A sidecar mesh (Istio or Consul Connect)*: it adds a second, unmanaged
  PKI and control plane. Go's TLS in the certified module already covers
  the need.
- *ML-DSA certificates*: the certified Go Cryptographic Module v1.0.0 has no
  ML-DSA (Go's TLS supports it from module v1.26.0). PQC is offered for key
  exchange only, and labelled that way.

**Plan:** four slices (docs/SECURITY/INTERNAL_TLS.md), each tested against
real TLS handshakes and real dependencies.

## 2026-09-26 — Replace the fabricated DR drill with backup verification
**Decision:** delete keycore's DR drill, which marked every step passed with
synthetic RTO/RPO. Add `POST /governance/backups/verify`, which opens a real
backup through restore's own code path (`openBackup`) and reports what it
holds, without applying it.

**Why:**
- Rule 7: no fabricated evidence.
- "Can we recover?" is answered by "does our backup open with the keys we
  hold?", and the platform can prove that for real.

**Rejected:**
- *A full restore drill into a throwaway environment*: restore overwrites
  the live database, so isolating it needs new work across governance and
  keycore (several days).
- *Scheduled automatic drills*: software-mode backup keys aren't stored and
  may be split across guardians, so an unattended job can't open them.
- *Keeping the drill as a preview*: its schedules never ran, so nothing of
  value would remain.

**Open:**
- Verify doesn't prove services can re-wrap retired-key rows; restore
  checks that before applying.
- A timed, isolated restore (real RTO) is still future work.

**Enforced by:** `TestVerifyBackupPostgres`,
`TestVerifyBackupRouteAuthAndActor`.

## 2026-09-26 — Remove the CT log monitor rather than label it a preview
**Decision:** delete the CT log monitor (backend, tables, dashboard tab). It
generated synthetic certificates and mis-issuance alerts. Certs migration
011 drops its tables, and with them every fabricated entry.

**Why:**
- CLAUDE.md rule 7: a feature must never invent security evidence.
- A preview may store settings, but it may not produce results.
- Removing the simulator would have left only a domain list that does
  nothing.

**Rejected:**
- *Keep it as a preview*: without the simulator nothing is left to show.
- *Build real RFC 6962 / crt.sh polling now*: it only matters for public
  domains, while Vecta mostly manages internal and private PKI.

**Later:** the owner may add certificate discovery and scanning (network
TLS scan, CT for public domains, inventory reconciliation). If CT returns,
it must:
- read real logs over TLS 1.3 and verify signed tree heads;
- take the tenant from the verified caller;
- audit every action and alert;
- test against a real log client.

## 2026-09-26 — Guardian shares for the backup key instead of a general escrow workflow
**Decision:** remove keycore's escrow workflow entirely. Instead, a
software-mode backup key can be split M-of-N with Shamir secret sharing, one
share per named guardian, at backup creation. Restore needs M shares, and the
rebuilt key must match the stored fingerprint.

**Why:**
- The escrow workflow only kept records, and its votes were forgeable.
- The real recovery risk is the backup key: one operator holds the only
  copy, so it can be lost, or that one person can restore everything.
- A split covers both risks with no new stored secret.

**Rejected:**
- *Fixing the escrow workflow* (binding votes, sealing per-key shares to
  guardians with ML-KEM): per-key and legal-hold recovery is worth that cost
  only when customers need it.
- *Splitting in keycore over REST*: the backup key would travel to another
  service. Shamir moved into `pkg/crypto`, so governance splits locally.
- *Splitting an HSM-bound key*: it never leaves the HSM, so the request is
  refused.
- *Storing shares for later redistribution*: that would put the key back in
  the database.
- *Guarding the split behind `fips140.Enforced()`*: secret sharing isn't an
  encryption algorithm. It uses the module DRBG and splits a key that
  software mode already hands out whole, so it stays available in `only`
  mode (docs/SECURITY/FIPS.md). A reviewer may classify it differently.

**Enforced by:** `TestSplitBackupKeyRestorePostgres`,
`TestSplitBackupKeyNeedsThresholdShares`,
`TestValidateBackupKeySplitRejectsBadSplits` and the `pkg/crypto` Shamir
tests ([SECURITY/BACKUP_KEYS.md](SECURITY/BACKUP_KEYS.md)).

## 2026-09-26 — Every KMS change bumps the minor version
**Decision:** any change to code or deployment raises MINOR in `VERSION` (MAJOR
for breaking changes) and adds a matching `## [x.y.z]` CHANGELOG section. The
dashboard shows the version, commit and build time behind the ⓘ button by the
clock.
**Why:** a deployment tagged with an unchanged version can't be told apart from
the previous one. The owner took a current build for a stale one.
**Rejected:** patch bumps (the owner asked for minor); bumping per commit
(granularity is the change being merged, compared with the base branch);
version derived from git only (the `VERSION` file stays the source of truth
for image tags and `BUILD_VERSION`).
**Enforced by:** `scripts/check-docs.sh` (`version-bump`), which fails if
VERSION's MAJOR.MINOR didn't increase over the merge base or the CHANGELOG has
no section for it. Test-only changes are exempt, as for the docs gate.

## 2026-09-26 — One HSM per tenant; partition objects listed, not adopted; HSM CAs are ECDSA
**Decision:**
- A tenant has one HSM profile (one PKCS#11 slot). Redundancy comes from the
  vendor's HA/cluster behind that slot (Securosys, Luna HA groups, nShield
  Security World), not from the KMS choosing among HSMs.
- Each HSM key records the device (serial, token, model) that generated it.
  A key whose object is missing on the configured device is refused with
  `hsm_key_not_found` naming that serial; rotation onto another device is
  audited (`audit.key.hsm_device_changed`).
- Objects already in the partition are listed read-only in Keys and
  Certificates. Adopting them as KMS keys is not built yet.
- HSM CA keys are ECDSA P-256/P-384 only.

**Why:** choosing an HSM per key needs placement rules, per-key routing and
a story for keys that exist on only one device; vendor HA already
replicates keys across devices under one slot. Recording the device makes a
misconfigured profile obvious instead of a generic PKCS#11 error. Adoption
needs decisions about labels, usage flags and extractable keys (an
extractable key isn't HSM-protected in the sense the KMS promises), so it
is listed, not guessed. The HSM signs RSA only with PSS, and OCSP responses
(x/crypto/ocsp) can't carry RSA-PSS.

**Rejected:** several HSM profiles per tenant with a per-key picker
(placement and failover complexity for what vendor HA already does);
silently adopting every partition key (would put keys the KMS didn't create
and can't vouch for under its audit claims); RSA PKCS#1 v1.5 signing in the
HSM for CAs (the connector implements RSA signing with PSS only; adding v1.5 is a separate, reviewable change).

**Enforced by:** `TestHSMKeyProvenance`, `TestPartitionListing`,
`TestGeneratedKeysHaveHSMAttributes`, `TestHSMCAKeysSignInTheHSM` (RSA
refused).

## 2026-09-26 — Customer HSMs through their own PKCS#11 library, in a separate connector
**Decision:** HSMs are integrated through the vendor's PKCS#11 library (owner's
choice over a vendor REST API). The library loads in a dedicated
`hsm-connector` service (cgo, Debian), which keycore and governance call with
their service identities. Per tenant, two switches: a tenant key in the HSM
that protects new key versions (owner: "new keys only"), and HSM-resident
keys created per key. There is no Vecta or software HSM (owner), and
`software-vault` was removed. HSM-bound backups are wrapped by
the tenant key in the HSM.

**Why:**
- One integration serves every vendor that ships a PKCS#11 library, and the
  owner requires real integrations, no fakes.
- Vendor libraries are glibc builds and can't load into keycore's static
  Alpine binary. A separate process also keeps a crashing vendor library and
  the HSM PIN away from keycore.
- A per-tenant key gives each tenant its own root of trust in the HSM
  without moving every operation into the HSM. HSM-resident keys cover the
  keys that must never leave it.

**Rejected:**
- cgo in keycore: glibc libraries, a larger FIPS build surface, and a
  vendor crash would take down the KMS.
- Securosys REST (TSB) API: it covers one vendor, and the owner chose
  PKCS#11.
- Re-wrapping existing keys under the tenant key on enable: the owner chose
  new keys only. Turning it off doesn't touch existing keys either.
- Refusing HSM operations in FIPS `only` mode as "third-party crypto": they
  run in the HSM's own module with approved mechanisms. The KMS doesn't
  claim that module's validation; the customer checks it.
- A software HSM for demos: nothing may pose as an HSM. Tests use SoftHSM2,
  a real PKCS#11 library, only in tests.

**Enforced by:** `pkg/hsmconnector` tests on SoftHSM2 (isolation, callers,
confinement, `routetest.RefusalsAudited`), the keycore and governance HSM
tests through the real connector, `TestHSMStoragePostgres`, and
`TestHSMBoundBackupPostgres` (docs/SECURITY/HSM_INTEGRATION.md).

---

## 2026-09-26 — Governance fails closed; services are admitted per route
**Decision:** governance refuses to start without a token-verification key
(read through `pkg/jwtauth`, so the shared `JWT_PUBLIC_KEY_*` works). System
administration needs a verified root administrator. A platform service is
admitted only on a route named for its identity in
`systemAdminServiceCallers`, and every refusal is audited.

**Why:** a missing key disabled authentication, and in compose the key was
always missing. Service callers need exactly one read (state) and one write
(posture controls), so a per-route identity list grants that and nothing
more. Backups, restore and the FIPS mode stay administrator-only.

**Rejected:**
- Admitting any service principal on system-admin routes: that would let
  any compromised internal service restore backups or change the FIPS mode.
- Migrating governance to the `pkg/route` kernel in the same change: that's
  the right end state (phase 2), but the auth hole needed closing now. The
  refusal reasons match the kernel's so the migration keeps them.
- Keeping `POSTURE_GOVERNANCE_BEARER_TOKEN` as the only posture credential:
  nothing ever set it.

**Enforced by:** `TestMissingJWTKeyRefusesStart`,
`TestSystemAdminRoutesRequireVerifiedToken`, `TestSystemAdminRefusalReasons`,
`TestSystemAdminServiceCallersAreRouteBound`, and
`TestGovernanceCallsCarryServiceIdentity` in keycore, policy and posture.

---

## 2026-09-26 — Governance never stores a key that opens its backups
**Decision:** a software-mode backup key is returned once, in the create
response, and never stored. The platform keeps only its fingerprint. An
HSM-bound key is stored wrapped under
`HKDF-SHA256(BACKUP_HSM_WRAP_SECRET, binding, tenants)`, with the secret at
least 32 characters. Migration 013 removes existing stored keys, and v1
(raw SHA-256) packages are refused. Master-key re-wrapping of backup
contents moves from an hourly job over stored backups to capture time.

**Why:** a key in the same row as the artifact makes the encryption
decorative for anyone with the database. The owner accepted that backups
from the old version won't restore (none were taken).

**Rejected:**
- Wrapping software keys under a governance master key from `pkg/mek`: a
  database copy plus a running keycore would still open them. A backup has
  to survive the loss of the platform, so the operator must hold its key.
- Keeping v1 unwrap as a fallback: it keeps the raw-hash derivation
  reachable, and there were no v1 backups to keep.
- Keeping the stored-backup re-seal job: without stored keys it has
  nothing to open. Re-wrapping at capture covers every new backup.
- Deleting old backup rows: scrubbing the key keeps the artifact usable
  with a key file saved earlier.

**Enforced by:** `TestSoftwareBackupKeyIsNotStored`,
`TestSoftwareBackupKeyNotRetainedPostgres`,
`TestMigrationScrubsStoredBackupKeysPostgres`, `TestHSMBoundBackupKeyUsesHKDF`,
`TestHSMBoundV1PackageIsRefused`, `TestBackupWrapSecretStrength`
([SECURITY/BACKUP_KEYS.md](SECURITY/BACKUP_KEYS.md)).

---

## 2026-09-26 — No anonymous key use in keycore
**Decision:** every key operation needs a verified identity. The
"backward-compatible" branch that let a caller with no token use any key
without grants (when deny-by-default was off) is removed. Keycore refuses to
start without its token-verification key. Platform callers that relied on
anonymous access get service identities: compliance playbooks call as
`kms-compliance` (token confined to platform service hosts), and reconciler
calls as the new `kms-reconciler`.

**Why:** an unauthenticated request is not a tenant's caller. Deny-by-default
being off should mean "creator and admins may use ungranted keys", not
"anyone who can reach the port may". Rule 4 already forbids unverified
identity, and anonymity is the extreme case.

**Rejected:**
- Keeping anonymous access behind a flag: its only users were the two
  internal callers above, and they're fixed.
- Accepting the shared internal API token as an identity: every internal
  caller holds it, so it can't say who acted.
- Requiring a token at the handler for every route: the internalauth routes
  (reconciler's due-for-lifecycle and archive) and health checks don't carry
  a JWT, and key access is where identity matters.

**Enforced by:** `TestAnonymousKeyUseIsRefused`,
`TestPlaybookSendsServiceTokenOnlyToPlatformServices`,
`TestLifecycleCallsCarryServiceIdentityAndTenant`.

## 2026-09-26 — Service master keys come from keycore; exposure is tracked until material is replaced
**Decision:**
- secrets, certs, cloud and ekm get their master key from keycore through
  `pkg/mek`: a protected system key per service (`POST /system-keys/ensure`),
  service-derive bound to the service identity, and the version pinned in
  `<svc>_mek_state`. There is no environment variable and no fallback.
- Rows under any key an earlier release used are re-wrapped at startup and
  by a periodic rescan.
- Items that were under a public key go into an exposure register until the
  material is replaced.
- Governance re-protects its stored backups, and re-wraps restores before
  writing.

**Why:**
- All four services fell back to public keys, and nothing ever configured
  the real ones. A required env var (tried first, in the same unreleased
  branch) would still:
  - break a plain `docker compose up` on upgrade;
  - need copying to every cluster member by hand;
  - make every installer, backup runbook and rotation step carry a
    data-destroying secret.
- Keycore already holds key material under its master key, which the cluster
  join ships. Deriving from it satisfies rule 6 and makes members work with
  nothing to copy.
- **Protection at keycore's storage layer:** destroying a system key would
  crypto-shred a service's whole store, and every destroy path (API, bulk,
  scheduled sweep) funnels through a few store methods.
- **Exposure register:** re-wrapping can't touch copies made before (dumps,
  snapshots, downloaded backups). The only real remedy is to replace the
  material. A register that closes itself when the material is rotated or
  deleted turns "treat these as exposed" into tracked work.
- **Backups:** governance keeps backup artifacts, and for software-mode
  backups their keys, in the database. So the live database kept exposing
  the old values until its backups were re-protected too.

**Rejected:**
- Required `<SERVICE>_MEK_B64` (for the reasons above).
- Generating a key file per node: backup/DR and cluster members would need
  it copied, and losing it loses the data.
- Re-encrypting values with new DEKs instead of re-wrapping: a pre-upgrade
  copy already holds the old ciphertext and a public-key-wrapped DEK, so it
  adds nothing.
- Rotating exposed material automatically: CA keys, cloud credentials and
  BitLocker recovery keys are in use outside the platform, and replacing them
  blind would break their users.
- Deleting pre-upgrade backups: destructive, and a downloaded copy survives
  anyway.

**Enforced by:**
- `no-literal-key-material` (the only public keys are marked lines in
  `pkg/mek/catalog.go`).
- `TestCatalogIsValidAndMigrated`, `TestMEKLifecycle*`,
  `TestSystemKeyIsProtectedFromDestruction`, the per-service
  `TestUpgradeMoves*` tests and `TestBackupReprotectPostgres`.
- docs/SECURITY/SERVICE_MASTER_KEYS.md.

## 2026-09-26 — Feature kernel (pkg/route): rules are declared per route, applied in one place
**Decision:** every HTTP route is registered through `pkg/route` with a
`route.Spec` (audit action, permission, resource, tenancy). The kernel
authenticates, resolves and enforces one tenant, checks the permission, and
emits exactly one `audit.<service>.<action>` event per request, including
failures and refusals (with `reason`). Services move onto it one at a time
([ARCHITECTURE_MIGRATION.md](ARCHITECTURE_MIGRATION.md)); `services/secrets`
is the reference.

**Why:**
- Cross-cutting rules lived in about 960 hand-written handlers, with 22
  private `mustTenant` copies. Each new feature had to be reminded of audit,
  tenancy and permissions, and some missed them: `POST /secrets` accepted a
  body `tenant_id` without checking it (a cross-tenant write).
- A rule in the kernel reaches every migrated route. A rule in a handler
  reaches one.
- Specific events for refusals were owner policy (2026-09-25), but nothing
  guaranteed them.

**Rejected:**
- Rewriting the product from scratch: it would lose the FIPS, clustering and
  audit-chain work and the security fixes, and ship months of unreviewable
  change at once.
- Relying on the generic `auditmw` `http_request` record: it has no action
  semantics, target or refusal reason, so governance and DAM can't run on it.
- Per-service middleware: the same duplication at a different layer.
- Emitting from the service layer: it can't see refusals that happen before
  the service is called, and it duplicates events when one service method
  calls another (generate → create).
- Letting `kms.read` / `kms.write` match any domain by verb: once auth
  migrates, API clients would gain `auth.*.write`. The coarse grants apply
  only to domains listed in `route.CoarseDomains` (today, `secrets`).
- Resolving the tenant only from query/header (as `mustTenant` did): body
  tenants are how the dashboard sends writes, so the body must be checked,
  not ignored.

**Enforced by:**
- Registration panics without an action or permission.
- `make conformance` rule `route-kernel`: a raw `http.ServeMux` in a service
  file fails unless the file is on `scripts/route-kernel-burndown.txt`, which
  only shrinks.
- `routetest.RefusalsAudited` proves each route refuses and audits the three
  refusal cases.
- `pkg/route` tests: cross-tenant body, conflicting sources, service
  principals, and failure/refusal events.

## 2026-09-26 — Cluster write forwarding: member verifies, primary re-mints
**Decision:** on a member, every service's HTTP wrapper forwards lifecycle
writes to the primary's cluster-manager.
- The member verifies the caller's token and sends the claims, authenticated
  by a per-member credential issued at join.
- The primary has its own auth mint a 5-minute token (`fwd_node` set) and
  proxies to the service.
- Writes are forwarded by default; `pkg/clusterroute.Local` lists the
  exceptions.

**Why:**
- Verification keys differ per node, so the user's token can't be replayed on
  the primary.
- Re-minting keeps every service's own authorization and audit untouched.
- Default-forward means a new endpoint can't diverge a member.

**Rejected:**
- Sharing one JWT key cluster-wide: a member compromise would forge tokens
  for every node.
- Proxying the raw user token.
- An allowlist of forwarded writes: a new write would silently diverge.
- Letting members write and reconcile later (split-brain on key state).

**Enforced by:** `TestClusterForwarding`, `TestLocalRoutesExist`,
`TestSecureJoinEndToEnd`, and the rule in CLUSTERING.md that background jobs
check `RunsPrimaryJobs`.

## 2026-09-25 — Documentation ships with the change
**Decision:** every change updates CHANGELOG.md, learning.md, this file and/or
`docs/SECURITY/` in the same commit. Standing instructions live in `CLAUDE.md`.
**Why:** the owner shouldn't have to repeat instructions, and FIPS reviewers
need a written trail of why each security control exists.
**Rejected:** documenting at release time (context is lost by then).
**Enforced by:** `scripts/check-docs.sh` in CI on pull requests, plus the
"Documentation is part of done" table in `CLAUDE.md`.

## 2026-09-25 — Cluster join: master key moves keycore-to-keycore under ML-KEM; join pinned by bundle
**Decision:**
- **Master key:** the member's keycore creates a one-time ML-KEM-768 key,
  and the primary's keycore seals its master key to it, bound to the join
  context. Only the cluster-manager service identity may drive this. The
  member stores the key on its own volume and restarts on it.
- **Replication access:** it gets a dedicated role with SELECT only on the
  member's component tables, plus `BYPASSRLS`. Its credentials are sealed to
  the member's cluster-manager.
- **Trusting the primary:** the member pins the primary's TLS certificate from
  the join bundle and authenticates with a one-time token.
- **cluster-manager:** now requires a root admin or a service identity on
  every admin route.

**Why:**
- A member can't use replicated key material without the master key, and the
  plaintext key must never exist outside a keycore process.
- Pinning plus a one-time token needs no pre-shared CA, like
  `kubeadm join`.

**Rejected:**
- **Moving the master key through cluster-manager in plaintext:** it widens
  exposure.
- **The existing `CLUSTER_SYNC_SHARED_SECRET` as the join credential:** a
  long-lived shared secret on every node.
- **A superuser replication connection:** far more than the member needs.

**Enforced by:** `TestClusterMEKTransfer*` (keycore),
`TestSecureJoinEndToEnd` (two real Postgres servers, real TLS, wrong-pin
refusal) and `TestClusterRoutesRequireRootAdmin`.

## 2026-09-25 — Clustering: one lifecycle writer, per-component Postgres logical replication
**Decision (customer's choice):**
- The primary is the only lifecycle writer; members forward lifecycle writes
  and run crypto operations locally.
- Failover is manual, plus a majority vote at 3+ nodes, with fencing.
- Replication is Postgres 17 logical replication with one publication per
  component; members subscribe only to their assigned components.
- Every table is classified replicated / node-local / shared-append in
  `pkg/clustercatalog`, and a test enforces it.

**Why:**
- The existing framework recorded sync events that nothing ever applied.
  Writing apply logic for about 250 tables in 30 services would be large and
  fragile.
- Logical replication gives a transactional initial copy and streaming for
  free, and each service already owns its tables, so the per-component split
  is natural.

**Rejected:**
- **Active-active multi-writer:** concurrent rotate/destroy on two nodes can
  diverge key state, and unique-name collisions stall replication.
- **Physical streaming replication / Patroni for the whole database:** it
  can't replicate selectively per feature, and it would clone node-local data.
- **Per-entity event apply handlers:** see Why.

**Enforced by:** `TestEveryTableIsClassified`, the two-node integration test,
and status that comes only from the database.
## 2026-09-25 — Record-only features are labelled "preview" from one catalogue, not deleted
**Decision:**
- Features that store configuration without enforcing it are listed in
  `pkg/features.Preview`.
- Every response of such a feature is labelled, and the dashboard mirrors the
  list (checked by conformance).
- Operations they cannot perform refuse with `409 feature_preview`.
- Fabricated data they had produced is relabelled, not deleted: simulated
  backup runs, fake Merkle roots.
- The simulated backup scheduler stays a preview; real backup is governance.

**Why:** the owner's options were "finish or mark preview". Marking is honest
today and keeps the APIs stable for the teams that will finish them. Finishing
federation or edge is product work, not a fix.

**Rejected:**
- **Deleting the features:** they break API clients and lose work.
- **A "preview" note in the docs only:** API consumers never see it.
- **Keeping the backup simulation:** it produced evidence of backups that never
  happened.
- **Rewiring the scheduler to governance backups now:** it needs
  service-to-service backup authorisation and restore of HSM-bound key
  packages. That's tracked as the way to finish it.

**Enforced by:** conformance `preview-catalogue`, keycore and backup tests.

## 2026-09-25 — Security-critical paths get integration tests against real dependencies
**Decision:** backup/restore, signing and the KMIP wire protocol are tested
against real Postgres and a real TLS KMIP client. The Postgres tests run in CI
job `integration-postgres` (disposable database, serial run).
**Why:** each of these paths hid a defect that only real dependencies expose:
JSONB key order, information_schema, TRUNCATE CASCADE, and TLS client-cert
authentication.
**Rejected:** SQLite-only tests for these paths (they would have passed with
the signing bug in place).

## 2026-09-25 — FIPS mode is changed in the UI and applied by staggered self-restart
**Decision:**
- The platform FIPS mode is a governance setting, changed by a root admin in
  System Administration. The deployment variable only seeds it.
- Every service applies a change itself: it polls the setting, waits its
  restart tier, sends itself SIGTERM (graceful shutdown), and is restarted by
  its supervisor.
- At startup the service re-executes itself with the matching `GODEBUG`
  before any cryptography runs.
- Before confirming, the UI shows the features that stop and start and the
  services that restart. The change is audited, with severity critical for a
  downgrade.

**Why:** the customer asked for the choice to live in the product, not in the
deployment. Go fixes the FIPS mode at process start, so a restart is
unavoidable; making each service apply the change itself needs no Docker
socket or orchestrator access.

**Rejected:**
- **Governance restarting containers through the Docker socket:** that hands
  root on the host to a web-facing service.
- **Restarting only the "affected" services:** the mode covers every Go
  process's cryptography, so a partial restart leaves a mixed posture.
- **Restarting everything at once:** a full outage. Tiers keep the platform
  up.
- **Switching modes without a restart:** Go doesn't support it.

**Enforced by:** `pkg/config.RequireFIPSRuntime` (by construction), the
conformance `fips-module` rule (common env and a restart policy on every Go
service), governance tests, and a real-container end-to-end check
(docs/SECURITY/FIPS.md).

## 2026-09-25 — dataprotect working keys come from keycore (service-derive), with a per-key migration
**Decision:**
- keycore gets `POST /keys/{id}/service-derive`: HKDF over the key's secret
  material, bound to the verified calling service, tenant, key, pinned
  version and purpose.
- dataprotect derives every working key through it (v2).
- Identifier-derived keys (v1) survive only per key, in state
  `legacy`/`migrating`, until an operator completes that key's migration.
- New keys are v2 from birth. Strict FIPS mode refuses v1 everywhere.

**Why:** the working key was HMAC over the public KCV, so it was predictable.

**Rejected:**
- **Running tokenize/FPE inside keycore:** a large move of format-preserving
  code into the crypto boundary, with a keycore round trip per value.
  Service-derive keeps the algorithms in dataprotect while the secret stays
  in keycore.
- **Exporting raw key material to dataprotect:** it would spread the root
  secret. A purpose-bound HKDF subkey can't be turned back into the key.
- **Switching every key to v2 at upgrade:** FPE and vaultless outputs carry no
  version marker and aren't authenticated, so old ciphertexts would decrypt to
  wrong values with no error.
- **A version marker inside outputs:** impossible for format-preserving
  tokens and FPE.
- **Trial decryption with v2, falling back to v1:** it gives wrong plaintext
  without any error for unauthenticated formats.

**Enforced by:** the state machine in `services/dataprotect/kdf.go`, the
generic-derive reserved-prefix check, tests in all three FIPS modes, and
`audit.dataprotect.kdf_legacy_used` on every legacy use.

## 2026-09-25 — FIPS 140-3: certified Go module always, runtime mode is the customer's choice
**Decision:** every binary links the CMVP-certified Go Cryptographic Module
(`GOFIPS140=v1.0.0`). The customer chooses `VECTA_FIPS_MODE` = `on` (default),
`only` or `off`, passed to Go as `GODEBUG=fips140`. Services refuse to start
when the runtime doesn't match. Every mode is tested in CI.
**Why:** `pkg/fips` was an in-app allowlist with no validated module behind
it, and the "FIPS mode" variable never reached the containers. A lab asks
which validated module does the cryptography; the answer must be true in the
build and visible at runtime.
**Rejected:**
- BoringCrypto (cgo, a different module, and the Go team now points to the
  native module).
- Hard-wiring strict mode (it would break customers' legacy payment TDES and
  X25519 integrations; the customer decides).
- A per-tenant runtime toggle (Go fixes the mode at process start; per-tenant
  rules stay in the governance FIPS Policy).
- Wrapping everything in `fips140.WithoutEnforcement` to make strict mode pass
  (that would be strict in name only). `WithoutEnforcement` is used only for
  known-answer self-tests with published vectors.
**Enforced by:** conformance `fips-module`, `config.RequireFIPSRuntime`, the
CI `fips-modes` matrix, and `TestBuiltWithCertifiedModule`.

## 2026-09-25 — Placeholder secrets are rejected in the shared config loader
**Decision:** `pkg/config` rejects placeholder secret values (`your-...`,
`change-me`, `replace-me`) at startup, from `Load` and `NewHTTPServer`, rather
than each service validating its own variables.
**Why:** plain `docker compose up` bypasses the deploy scripts, and a
per-service check would be forgotten in the next new service. Putting it in
the shared loader gives every `pkg/platform` service the check by
construction.
**Rejected:** a check only in `deploy-local.sh` (bypassed by plain compose);
auto-replacing placeholders on a live stack (a baked-in Postgres password
would break the database).
**Exception:** customer-side `ekm-agent` reads a config file, not the
environment.
**Extended (same day):** connection-string env vars (`*_DSN`,
`*DATABASE_URL`) are parsed, and a default, username-equal, empty or
placeholder password is rejected. A missing `POSTGRES_DSN` is an error rather
than a built-in localhost default.

## 2026-09-25 — Secrets: fail fast or generate, never a public fallback
**Decision:** no secret may default to a value in the repo. Weak values stop
the service at startup, and credentials derived from a removed default are
revoked on startup.
**Why:** a `-change-me` fallback for `INTERNAL_SERVICE_BOOTSTRAP_SECRET` let
anyone derive every internal service's API key on installer-based deployments.
**Rejected:** a startup warning (ignored in practice); "tokenless" degraded mode
for a weak secret (degraded identity is no identity).
**Exception:** admin `changeit`, seeded with a forced password change.
**Enforced by:** `make conformance` rule 3, which also runs in CI. See
[SECURITY/SECURE_DEFAULTS.md](SECURITY/SECURE_DEFAULTS.md).

## 2026-09-25 — Service principals are keyed on unforgeable claims
**Decision:** a caller may bypass tenancy only with role `client-service` AND
the reserved `service.internal` permission AND a `kms-*` client id AND the
internal tenant. The reserved permission is stripped at every API write path.
**Why:** the role alone is carried by every client-credentials token, so keying
on it would have been a cross-tenant bypass.
**Rejected:** role-only checks; trusting `X-Actor-*` headers.
**Enforced by:** `tenantcheck.IsServicePrincipal` and
`pkg/tenantcheck/service_principal_test.go`.

## 2026-06-18 — Service-to-service auth: per-service JWTs from one bootstrap secret
**Decision:** each service derives its API key as
`HMAC(bootstrap secret, service name)` and exchanges it at auth for a
short-lived JWT. The rollout is phased (attach, then enforce).
**Why:** one secret to distribute instead of 20, while every service still gets
a distinct, auditable identity.
**Rejected:** a shared static bearer token for everything (no per-service
attribution); per-service secrets in `.env` (secret sprawl).
**Rotation:** auth bootstrap retires every service key that doesn't match
the current secret, so rotation locks out the old value on the next auth start
(added 2026-09-25). Service JWTs already minted live out their TTL (≤ 1 h).

## 2026-09-26 — Cut features are removed; all work happens in KMSBeta
**Decision:** a feature cut from the core is deleted from KMSBeta and
recovered from its git history if it's ever wanted again. Nothing is
committed to `KMSExtension` any more (owner: "all the work have to be done on
KMS beta only", "stop touching KMSExtension"). Supersedes the 2026-06-12
entry below.
**Why:** one repository to develop, review and certify. A second repo of
parked code that nobody builds only looks like a product. Git history
already keeps every removed line.
**Rejected:** keeping KMSExtension as a read-only archive of cut code.
**Enforced by:** CLAUDE.md ("All work happens in KMSBeta").

## 2026-06-12 — Cut features move to KMSExtension, not the bin (superseded 2026-09-26)
**Decision:** features removed from the core move to the sibling
`KMSExtension` repo and integrate over REST (`pkg/kmsclient`), holding no key
material.
**Why:** it keeps the core's certification boundary small without losing work.

## 2026-06-11 — One crypto library, one audit pipeline
**Decision:** all primitives come from `pkg/crypto` (FIPS-gated). All audit
events go through `pkg/audit` onto the single `AUDIT` stream.
**Why:** about 34 services had duplicated crypto helpers and private audit
streams, which is impossible to certify or reason about.
**Enforced by:** `make conformance` rules 1–2, with a burn-down allowlist that
only shrinks.
