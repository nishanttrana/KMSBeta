# Learnings

Running log of non-obvious operational and architectural learnings for Vecta KMS.
Newest entries on top.

## 2026-09-28

### The service that detects tampering was the one event nobody could hear
- **What happened:** `audit.audit.chain_broken`, the most critical event on
  the platform, was written by the audit service straight into its own
  chain with `ProcessEvent`. Every other service's events reach the chain
  through the `AUDIT` stream, so only this one never appeared on the stream.
  Playbooks, SIEM subscribers and anything else listening could not react
  to tampering.
- **Why it slipped through:** the event was in the register and had a test,
  but the test only asked "is it in the chain?". Nobody asked "who else
  receives it?". Other detectors inside the audit service (quarantine, HNDL)
  already published to the stream; this one took the shortcut.
- **Rule:** an event is emitted when it's on the stream, not just stored.
  A service that records its own events publishes them like any other, and
  the test proves delivery (`TestChainBrokenPublishedToStream`).

### A safety policy with an off switch is a silent outage
- **What happened:** 2.5.0-beta's built-in "Playbook actions" approval
  policy could be disabled like any other policy. Every step that must be
  approved (deactivating keys, revoking certificates and access) would then
  fail with "no active approval policy", and nothing warned the admin who
  switched it off.
- **Rule:** a policy that other features depend on for dual control is
  required. Its approvers can change, but disabling or narrowing it is
  refused and audited.

### An exposure register nobody could see
- **What happened:** migrating inline playbook credentials recorded each
  one as exposed, but the dashboard's list of services to query for
  exposures (`EXPOSURE_SERVICES`) didn't include compliance. The record was
  real; no screen showed it.
- **Rule:** when a service starts recording exposures, add it to
  `web/dashboard/src/lib/mekExposure.ts` in the same change, and show the
  flag where the item is managed.


### An update that matched nothing reported success (reporting incidents)
- **What happened:** `PUT /incidents/{id}/status` and `/assign` ran an
  `UPDATE` and returned 200 without checking that a row changed, and stored
  any status string. A playbook step "set incident status" would have
  succeeded against an incident that doesn't exist.
- **Why it slipped through:** nothing but a human in the dashboard called
  these routes, and the dashboard never did: reporting incidents weren't
  shown anywhere in the UI. Wiring playbooks to them was the first real
  caller, and its test asked for a 404.
- **Rule:** a write reports what it changed. Check `RowsAffected` (or read
  back) and return 404 for nothing, and validate enumerated values at the
  service, not in a UI.

### A "catalogue" that lists what could exist, not what does (audit events)
- **What happened:** looking for a list of real audit subjects to offer as
  custom playbook triggers, the audit service's `event_catalog.go` turned out
  to be every service crossed with every verb (`audit.qrng.rotated`, ...):
  hundreds of subjects nothing emits. And `audit.audit.chain_broken`, a real
  event, never reaches the stream: the audit service writes it straight into
  its chain.
- **Rule:** a list offered to users as "events" comes from emitters
  (`TestTriggerSubjectsAreEmitted` names the file of each). A custom subject
  is labelled as firing only if something emits it.

### Authority checked once is authority kept forever (playbooks, 2.4.0-beta)
- **What happened:** 2.4.0-beta checked the saver's permissions when a
  playbook was saved, and an automatic run then acted on them indefinitely,
  including after the person left or lost the role.
- **Rule:** unattended work re-checks the person's authority when it runs,
  with the service that owns it (auth), and fails closed when it can't ask.

### A trigger map that listened for subjects nobody sends (playbooks)
- **What happened:** the playbook listener mapped 40 trigger types to audit
  subjects like `audit.keycore.key_rotated`, `audit.infra.cluster_node_down`
  and `audit.ops.latency_spike`. Keycore actually emits `audit.key.rotate`;
  the `infra`, `ops` and `data` services don't exist. Only a canary trip
  (through a wildcard fallback) and `auth_failure_spike` could fire, the
  latter on every single failed login because its threshold was never read. Five actions called
  routes that don't exist, `destroy_key` omitted keycore's required
  acknowledgements, and `disable_user` / `revoke_api_key` were refused by
  auth for every service identity. The dashboard showed all of it as working.
- **Why it slipped through:** the subject map was written from what events
  *should* be called, and the tests checked the executor sent a token, never
  that a subject was emitted or a route existed. Nothing connected the two
  sides of the bus.
- **Rule:** a consumer of an event names its producer. A trigger catalogue
  entry needs its emitter in `TestTriggerSubjectsAreEmitted`, and an action
  needs a test against the route it calls.

### A service identity lent to anyone who can write a record (playbooks)
- **What happened:** playbook actions run as the compliance service, which
  passes tenant and permission checks everywhere. The playbook API checked
  only that a JWT was valid and took the tenant from the body, so any user
  could have the service rotate or disable keys in any tenant.
- **Why it slipped through:** the review of 1.26.0 fixed the *outbound*
  side (the service token only goes to platform hosts) and missed the
  *inbound* side: who may tell the service what to do.
- **Rule:** stored work that runs as a service checks the verified caller's
  own permission for each operation when saved and when started, and records
  who authorized it (docs/PLATFORM_CONTRACT.md).

### "Everything else calls keycore" was an assumption, and it hid unaudited crypto
- **What happened:** 2.1.0-beta said only keycore's operations mattered for
  metrics because "everything else calls keycore". It was never checked.
  Payment runs PIN, CVV, MAC, LAU and TR-31 with local TDES and CMAC, and
  dataprotect runs FF1 and AES-GCM with derived working keys. Checking also
  showed that payment's MAC, LAU, TR-31 validate and ISO 20022
  verify/decrypt emitted no audit event at all. No refused or failed
  operation in payment or dataprotect was audited. Their publishers never
  set `result`, so the audit record said `success` even for a refusal.
- **Why it slipped through:** the audit register listed the events that
  existed, and nothing listed the operations that should have one. A grep
  for `"audit\.[a-z_]+\.[a-z_]+"` skips subjects with digits (`tr31`,
  `iso20022`), so the survey under-counted what was audited.
- **Rule:** before claiming coverage, list the operations (routes and
  service methods) and check each one against its event, not the events
  against themselves. A crypto operation's event is emitted from a deferred
  call on the method's named `err`, so no return path can skip it.

### A metrics tab read a table that nothing wrote (Operations Metrics)
- **What happened:** Operations Metrics was always empty. Its only writer
  was `POST /ops-metrics/record`, and no service called it. The latency
  "percentiles" were `p90 = 2 × avg` and `p99 = 4 × avg`, labelled as
  measurements. Latency was summed in whole milliseconds, so sub-millisecond
  crypto rounded to 0. Keycore audited only successful key operations, and
  audited a wrap as an encrypt and a MAC as a sign.
- **Why it slipped through:** the endpoints, schema and UI all existed, so
  the feature looked finished. Nobody followed the data back to a producer.
  The fabricated percentiles sat in the store layer behind a comment calling
  them "heuristics", where the `real-capability` scan (function names) can't
  see them.
- **Rule:** a metric comes from the event of the work that produced it,
  never from a record endpoint callers post to. Before calling a read view
  done, find what writes its table. A number derived from another number is
  not a measurement: measure it (histogram) or don't show it.

### Detection that runs on read never alerts anyone (threat signals)
- **What happened:** keycore's threat rules were real, but they ran only
  when `GET /threat/signals` or `/threat/dashboard` was called, which the
  Threat & Exposure tab did on open. Nobody watching the tab meant no
  detection. Reporting had the same shape: alerts were created from audit
  only when the Alert Center was listed, so the header's unread count
  could not rise on its own.
- **Why it slipped through:** each piece was tested by calling it directly,
  so every test passed. Nothing checked what triggers the call in
  production.
- **Rule:** a detection or alerting path needs a scheduler, a
  primary-only gate if it writes replicated data, and a test that drives
  the scheduler's tick, not the function beneath it.

### A "test" endpoint that writes a real event is a fake (canary trip)
- **What happened:** `POST /canary/{id}/trip` recorded a trip and audited
  `audit.keycore.canary_tripped` for a probe that never happened. The
  canary UI also sent an `alert_on_use` flag that nothing stored, and
  canary IDs began with `canary_`, which told an attacker it was a decoy.
- **Why it slipped through:** the endpoint was labelled "for testing" in a
  comment, and the real trip path (GetKey's not-found branch) was added
  later, next to it.
- **Rule:** test paths live in `_test` files. Anything reachable over HTTP
  that emits a security event must correspond to the event happening.

### A node-local log must not update a replicated row (canary trips)
- **What happened:** recording a trip inserted into node-local
  `canary_trip_events` and then incremented `trip_count` on the replicated
  `canary_keys` row, which a cluster member must never write.
- **Rule:** derive counters from the node-local log at read time. Don't
  denormalise them onto replicated rows.

### A "No data yet" empty state hid a tab that could never load (Platform > Health)
- **What happened:** Platform > Health always said "No heartbeats received
  yet" while Administration > Health showed every service. The tab called
  `/api/watchdog/*` and `/api/reconciler/*`, which Envoy never routed, with
  a plain `fetch` and no token, and `.catch(() => [])` turned each failure
  into an empty list. The watchdog and reconciler endpoints were also
  unauthenticated raw muxes.
- **Why it slipped through:** the empty state reads like a quiet system, so
  a broken wire looked like "nothing to report". The dashboard did not use
  `serviceRequest`, so the `/svc/<name>` routing check never saw the calls.
- **Rule:** never catch a fetch into an empty list; show "Unavailable:
  <error>". Dashboard calls go through `serviceRequest` (`/svc/<name>`), and
  one concept gets one screen: a second screen with the same name is merged,
  not kept.

## 2026-09-27

### SQLite returns MIN/MAX of a time column as Go's `time.String()` text
- **What happened:** `GET /keys/{id}/consumers` groups the usage trail
  with `MIN(occurred_at)`/`MAX(occurred_at)`. On SQLite the aggregate loses
  the column type and comes back as `2026-09-27 18:26:27.888827 +0000 UTC`.
  `parseDBTime` did not know that layout, so every first/last-seen time was
  zero and the consumer order (sorted by last seen) was random. The test
  failed only sometimes, and only in the full `make test-fips-modes` run.
- **Rule:** when parsing a DB time fails, don't carry on with a zero value.
  `parseDBTime` now accepts that layout. A test that sorts by time asserts
  the times themselves, and ties sort on a stable key.

### Two integrity checks compared a value with itself (lineage tamper check, Merkle proof root)
- **What happened:** the lineage "tamper check" hashed a key's lineage
  events, then called `buildChainOfCustody` on the same events, which ran
  the same hash, and compared the two. They could only match, so every key
  was "verified". It also hashed only event IDs, so edited contents were
  invisible, and every custody handoff was hardcoded `Verified: true`.
  While replacing it, the audit service's own `GetEventMerkleProof` turned
  out to do the same thing one level down: it rebuilt the tree from the
  stored leaves and returned *that* tree's root, not the root stored when
  the epoch was sealed, so a proof over an altered leaf still verified.
- **Why it slipped through:** both looked like verification: a hash, a
  comparison, a boolean. No test altered stored data and expected a
  failure. The only tests fed in good data, and a check that always passes
  passes those. The lineage data was also never observed: the tab's own
  form was the only writer, so there was nothing real to tamper with.
- **Rule:** an integrity check compares with a record the checked data
  cannot produce: a neighbour's link, an HMAC under a key the database
  doesn't hold, or a root stored at sealing time. Every integrity check
  ships with a test that alters the stored data (row, recomputed row, leaf,
  root, a deleted neighbour) and expects rejection
  (`TestTargetIntegrityRejectsTampering`, `TestEventMerkleProofUsesSealedRoot`).
  To confirm that test has teeth, break the comparison and watch it fail.

### A "bootstrap on first read" is a write (sbom CBOM history)
- **What happened:** `ListCBOMHistory` generated a snapshot when none
  existed, so a GET wrote a replicated table, on cluster members too.
- **Why it slipped through:** it looked like a UX convenience inside a read
  function, and the member-mode rule is checked for background jobs and
  forwarded writes, not for reads. Tests seeded data first.
- **Rule:** a read handler never creates data; return empty and let the
  write path create it. Test the empty case (`TestCBOMHistoryReadWritesNothing`).

### Filling in the register's test column found five real audit gaps
- **What happened:** the earlier register tables listed each event and
  when it fires, but no test. Finding or writing a test for every row
  turned up five problems no reviewer had caught:
  - publications created during a cluster join were never audited;
  - a refused service derive had no specific event;
  - `ocsp_refused` reported `result: denied`, not `refused`;
  - the HSM create event lacked a field the register said it carried;
  - the rotation scheduler's audit could not be observed by any test.
- **Why it slipped through:** the register was written from the code that
  emits events, so each row described an intention. A search for the
  event name in test files was also misleading:
  `audit.key.hsm_settings_update` "matched" a test only because it is a
  prefix of `hsm_settings_updated`. Some event names are built from a
  prefix (`webhookSelfPrefix + "credentials_seal_refused"`), so a grep for
  the full name finds nothing even when the event is emitted.
- **Rule:** a row is proven only by a test that fails when the event
  disappears or changes its `result` or `reason`. Check the assertion
  itself, not a string match. An emitter a test cannot observe (a concrete
  NATS client) is itself a gap: take an interface.
- **Trap when checking locally:** setting `VECTA_TEST_POSTGRES_DSN` for
  `make test-fips-modes` makes unrelated Postgres tests fail at random,
  because packages run in parallel against one database and the certs
  helper drops the schema. CI runs the Postgres tests on their own with
  `-p 1`, and so should local runs.

### A dual-control check that matches on one field misses the other (governance requester)
- **What happened:** governance left the requester out of a request's
  approvers by comparing emails, and refused a requester's vote by
  comparing email *or* user ID. Posture opens requests as a service and
  names the requester by user ID only, so the exclusion missed them. A
  requesting admin got approval links for their own escalation; only the
  vote check stopped them.
- **Why it slipped through:** every earlier request came either from a
  user (governance filled in the email from the token) or from keycore
  (which names no user). The first service to name a user by ID exposed it.
  The vote test passed, so the invariant looked covered.
- **Rule:** resolve an identity to every form a check uses before running
  the check. When a service names a user, look up the rest (email) rather
  than trusting the caller to send each form. Test the approver list, not
  only the vote refusal.

### An event with no consumer is not an action (posture remediation)
- **What happened:** posture's "execute" published
  `audit.posture.runbook.execute` and marked the action `executed`, with an
  optional auto-remediate mode doing the same unattended. No service
  subscribed to that subject, so nothing was ever remediated. The approval
  gate accepted any non-empty string as `approval_request_id`.
- **Why it slipped through:** publishing succeeded, so every signal looked
  green: a 200, an audit event, an `executed` row with an executor. Nobody
  followed the event to a consumer. The approval field *looked* like a
  governance reference, and nothing compared it with governance. The action
  types also read as concrete ("fail over HSM profile") though the findings
  behind them held only counts, with no target anything could act on.
- **Rule:** before calling an action real, name the code that performs it
  and the object it changes. If the finding doesn't identify the object, the
  action can't exist; keep the recommendation as text. An approval reference
  from a client is only a lookup key: verify with the approving service that
  the request is approved, bound to this exact operation, and opened by the
  caller who executes.

### A tenant check on some handlers is not a tenant check (sbom, reporting)
- **What happened:** reporting and sbom read handlers called
  `mustTenant` (which runs `tenantcheck.Enforce`), but the generate handlers
  took `tenant_id` from the body and skipped it, and the report `requested_by`
  and delete `actor` came from the body, query or `X-Actor-ID`. Worse, sbom
  had no JWT middleware at all, so `tenantcheck.Enforce` always saw no claims
  and passed: its "A01 fix" comment described a check that could never fire.
- **Why it slipped through:** the check was opt-in per handler, so every new
  handler had to remember it, and a reviewer reading one handler saw the
  guard. Nothing tested the service as deployed (with its middleware stack),
  and `Enforce` returns nil when there are no claims, which looks like
  success.
- **Rule:** don't hand-roll tenancy. Migrate the file to `pkg/route`, where
  an unauthenticated request is refused and the tenant is bound before the
  handler runs, and prove it with `routetest.RefusalsAudited` plus a
  cross-tenant test per write route. When migrating, check the service's
  `main.go` for `jwtauth` first: the kernel refuses everything without it,
  which is the point, but it must be wired.
- **Also:** a response wrapper that embeds `http.ResponseWriter` hides
  `Flush`; SSE through it silently degrades to one chunk. Wrappers implement
  `Unwrap()` and handlers use `http.NewResponseController`. The feed test
  must wait for a live event, not just the first chunk, or it passes
  without the fix.

### "Optional auth so internal callers keep working" is no auth (posture)
- **What happened:** posture's `optionalJWTMiddleware` parsed a token when
  one was sent and let every other request through, so reporting could call
  without a token. Each handler then read the tenant from the query and
  called `tenantcheck.Enforce`, which skips the check when there are no
  claims. Five routes didn't even call that, and defaulted to `*`. With no
  auth at Envoy either, anyone reaching `/svc/posture/` could read every
  tenant's risk, trigger scans and write events, and choose the executor
  name recorded on a remediation.
- **Why it slipped through:** the comment said tenant-scoped handlers
  "gate themselves", and the leak scanner (added later, on the kernel) did.
  The older routes looked the same from outside, and `tenantcheck.Enforce`
  succeeding without claims reads like a pass. The internal caller that
  motivated the bypass had a service identity provisioned all along
  (`kms-reporting` is in auth's bootstrap list); it was simply never used.
  The same service's own call to audit had the mirror bug: it sent no
  token to a service that requires one, so every audit sync failed with
  `401`, logged and swallowed, and risk was computed without audit events.
- **Rule:** an internal caller is authenticated with its service token and
  admitted by `tenantcheck.IsServicePrincipal`, never by leaving a path
  open. A middleware that passes tokenless requests is acceptable only
  in front of the kernel, which then refuses and audits them. Also: a
  handler that returns success for a no-op (re-executing an executed action)
  or a failure it swallowed (runbook publish error) becomes a false
  `result: success` audit event once the kernel audits the route; check
  every nil return when migrating.

### An audit register row must name a test, not the code that emits
- **What happened:** the 1.27.0-beta register listed
  `audit.signing.request_refused` with "handler `bindTenant`" as its proof.
  `sign_refused` pointed at a service test that checks error codes but never
  looks at the events. Both events were emitted, but a regression that
  dropped either one would have passed CI.
- **Why it slipped through:** naming the line that emits an event reads like
  evidence. The events were added in a large sweep, and the register was
  filled from the diff, not from the tests.
- **Rule:** every register row names a test that fails if the event
  disappears, checking its `result` and `reason` too. When a refusal is
  emitted by the handler, the test goes through the handler
  (`TestTenantMismatchRefusedAndAudited`, `TestSignRefusalAuditedPostgres`).

### A release gate must bind its output to the verified party
- **What happened:** confidential compute verified attestations well but had
  nowhere to send a key, so it returned a verdict and the feature was
  "attested release" in name only (1.26.0-beta relabelled it honestly).
- **Rule:** a release is real only when the output is bound to the party the
  evidence proves: the enclave's key must be inside the signed evidence, and
  the key is sealed to it. Test that a key the evidence does not name gets
  nothing (`TestReleaseRefusedWithoutBindingAllowOrKeycore`).

### A generated doc is only as true as its input (OpenAPI specs)
- **What happened:** `docs/openapi/ai.openapi.*` documented a `/svc/ai`
  service with six operations. No such service exists; the AI service is
  `ai-gateway` under `/ai-gateway/v1/`. Every spec also listed a
  `http://localhost:<port>` server, though services are reached only
  through the Envoy edge.
- **Why it slipped through:** the specs are generated, and CI's "Validate
  OpenAPI artifacts" step proves the committed files match the generator.
  That reads like verification, but the generator's input is hand-written
  definitions, so the check only proved the fiction was consistent.
  `check-doc-routes.py` covered Markdown only.
- **Rule:** anything that describes an API is checked against the routers,
  whatever its format. `check-doc-routes.py` now reads
  `docs/openapi/*.openapi.json` too. When adding a new doc format that names
  routes, add it to that script in the same change.
- **Also:** the "Validate OpenAPI artifacts" step was already failing: a
  dependency update committed the new Swagger UI bundle but not its CSS and
  preset. Run `validate:openapi` after `npm ci` in a clean worktree, since a
  stale local install hides or invents drift.

### A JCA provider is proven only by a JCA consumer (jca-provider)
- **What happened:** the Java provider registered AES-GCM, two signature
  algorithms and a key store. None could work: it called ekm routes that do
  not exist, its cipher dropped data passed to `update()`, its cache was
  never filled, and it could not load on Oracle JDK at all ("JCE cannot
  authenticate the provider"). The SDK download shipped a different,
  hand-written Java client embedded in Go strings.
- **Why it slipped through:** no test ever called `Cipher.getInstance` on it.
  The code compiled and looked like a provider, and the SDK zip was built from
  strings, so nothing tied it to the source in the repo.
- **Rule:** a client SDK has a test that uses it the way a customer does,
  through the platform API (`javax.crypto.Cipher`), against the real server
  API. Ship the source by embedding it, never by retyping it. A `Cipher`
  provider on Oracle JDK needs an Oracle-signed jar, so test on OpenJDK.

### "Implements protocol X" needs the protocol's reference, not our guess (DKE)
- **What happened:** the Microsoft DKE adapter returned a flat JWK with the
  key ID as `kid` and decrypted at `/keys/{id}/decrypt` in base64url. Office
  expects `{"key", "cache"}`, a `kid` URL it posts `/decrypt` to, standard
  base64, and an anonymous public-key fetch. Adding Entra tokens alone would
  still have left DKE unusable.
- **Why it slipped through:** the tests checked our own idea of the format.
  Nobody compared it with Microsoft's reference service or ran an Office
  client.
- **Rule:** for a vendor protocol, check the wire format against the vendor's
  reference implementation or spec, and pin it in a test (field names, types,
  encodings, URL shape).

### SQLite accepts SQL that Postgres rejects on every call (ekm)
- **What happened:** `last_activity_at = CASE WHEN $8::TEXT = '' THEN
  last_activity_at ELSE $8 END` fails on Postgres (`CASE types text and
  timestamp`), so updating a Google CSE or Azure EKM config never worked in
  production. The CSE key count update swallowed the error (`_ =`).
- **Why it slipped through:** the only tests ran on SQLite, which does not
  type-check a CASE, and the caller ignored the error.
- **Rule:** a new or changed SQL statement is run once against Postgres
  (the migrations plus the statement) before it ships. Do not discard a
  store error.

### Docs drifted into describing services that do not exist
- **What happened:** API_REFERENCE.md documented 151 endpoints no service
  registers, including whole MPC, QKD, QRNG and AI services, some with full
  request and response bodies. Other guides did the same.
- **Why it slipped through:** nothing compared the docs with the routers, and
  the prose read as authoritative.
- **Rule:** `scripts/check-doc-routes.py` (in `make conformance`) fails on a
  documented route that is not registered. When a feature is cut, cut its
  docs in the same change.

### "Last event" is not an assertion when work continues in the background (posture)
- **What happened:** a test asserted `rec.Last()` was `leak_scan_started`, but
  the scan runs in a goroutine and sometimes emitted `leak_scan_completed`
  first, failing `make test-fips-modes` intermittently.
- **Rule:** when anything runs asynchronously after the request, assert that
  the event is among those recorded, not that it is the last one.

### A stored policy field must be read where the decision is made (governance)
- **What happened:** `approver_roles` was stored and shown for months, but
  approvers came only from `approver_users`. The dashboard also dropped the
  field on save, so the roles an API client set were silently wiped.
- **Why it slipped through:** tests set the field but never gave a role to a
  user who was not otherwise listed.
- **Rule:** for every policy field, a test shows the field changes the
  decision: a user allowed only by it gets in, and one without it is refused.

### Behind Envoy, the TLS peer is Envoy (hyok, EKM)
- **What happened:** hyok and EKM read `r.TLS.PeerCertificates[0]` as the
  customer's client certificate. Every request arrives through Envoy over
  internal mTLS, so the peer is `vecta-envoy`: hyok authenticated every caller
  as "mtls" for any tenant it named, and EKM rejected every edge request with
  401 because `vecta-envoy` has no `tenant:role` CN. hyok also trusted
  `X-Client-CN` headers.
- **Why it slipped through:** unit tests called handlers directly with a
  hand-made peer certificate or header, a path production never takes; nobody
  sent a request through the real edge.
- **Rule:** identity comes only from a verified credential (a JWT the service
  verifies). The internal mTLS peer identifies the calling *service*, never
  the end user. Probe a changed route through Envoy on a running stack.

### A signature field that is collected must be checked (SAML, OIDC, KACLS)
- **What happened:** the SAML form collected `idp_certificate` and the SP
  metadata advertised `WantAssertionsSigned`, but `parseSAMLResponse` never
  verified a signature. OIDC read ID-token claims "without full signature
  validation for now". EKM's KACLS decoded Google's authorization token without
  verifying it.
- **Why it slipped through:** the parsing worked, so logins "worked". No test
  sent a forged assertion or token.
- **Rule:** every token or assertion that grants access has a test that sends
  a forged, tampered, expired, mis-addressed and replayed copy and proves each
  is refused. "For now" in a verification path is a blocker, not a TODO.

### A quorum is only as real as the voter's identity (governance)
- **What happened:** the approval API needed no token, and a dashboard vote
  counted as the `approver_email` in the body; the dashboard even offered a
  free-text "your email" box and fell back to the first allowed approver.
  Users could also add their own `approver_emails` and a gRPC callback.
- **Why it slipped through:** tests drove the service with email-link tokens
  (which are real) and never checked who a dashboard vote was cast as.
- **Rule:** an M-of-N control binds each vote to a verified identity, refuses
  the requester, and never lets the requester choose approvers or side effects.

### A placeholder string is not an approval (auth)
- **What happened:** client activation stored `TODO-GOVERNANCE-HOOK` as the
  approval ID and activated. The test asserted the activation succeeded.
- **Why it slipped through:** the test encoded the stub's behaviour as the
  requirement.
- **Rule:** grep for `TODO` in security paths before a release; a test that
  passes because of a stub is a bug in the test.

### Delivery status must come from the delivery (reporting)
- **What happened:** alerts recorded `sent` for email, Slack, Teams and SIEM
  from a severity rule; no code sent anything. Schedule `recipients` were
  stored and never mailed.
- **Why it slipped through:** "sent" was computed where the channel list was
  filtered, and the dashboard showed the field.
- **Rule:** a status like sent/delivered/applied is written only by the code
  that did it, from its result.

### A settings form is not a feature (governance FDE, network, license)
- **What happened:** FDE returned a hard-coded LUKS volume and "passed" for any
  input; network apply returned `applied: true`; license, backup schedule,
  DNS/NTP, proxy, TLS profile and RNG mode were stored and never read. A TLS
  private key sat in the settings table unused.
- **Why it slipped through:** each had a form, a save and an audit event, so it
  looked finished; nobody grepped for a consumer of the stored value.
- **Rule:** for each stored setting, name the code that reads and applies it.
  No consumer, no setting.

### A module is real only if its consumers can load it (PKCS#11, JCA)
- **What happened:** the PKCS#11 provider exported no `C_GetFunctionList`, so
  OpenSSL, SunPKCS11, pkcs11-tool and databases could not load it; docs gave
  RPM/DEB/Homebrew packages that never existed and TDE recipes around it. The
  JCA `VectaQRNG` called a missing endpoint and silently used the JVM RNG.
- **Why it slipped through:** it compiled and had samples; nobody loaded it
  with a real consumer.
- **Rule:** a client library is tested by a real consumer (pkcs11-tool,
  SunPKCS11, the JCA test harness). Docs name only packages that exist.

### Two sides of a protocol drift unless one test holds both (BitLocker)
- **What happened:** the agent polled jobs with GET (the route is POST), read
  the wrong JSON shape, sent `completed` and a string result; no remote
  BitLocker operation or recovery-key escrow ever completed. Installers wrote
  `mode` while the agent reads `agent_mode`.
- **Why it slipped through:** the agent and service were tested separately.
- **Rule:** an agent/service contract has a test that decodes the agent's
  request with the service's type and `DisallowUnknownFields`
  (`TestBitLockerJobRoundTripMatchesServiceContract`).

### Advertise only what is routed (KMIP Query)
- **What happened:** Query listed 32 operations; 15 were routed, and the rest
  lived in a build-tagged file that no longer compiled.
- **Why it slipped through:** the build tag hid the file from every build and
  test.
- **Rule:** a capability list is derived from, or tested against, the router
  (`TestQueryAdvertisesOnlyRoutedOperations`). A build-tagged file nobody
  builds is dead code.

### Smaller fakes in the same sweep
- Secrets "PPK" was not PuTTY's format and PGP armor double-wrapped armored
  keys: format tests checked a prefix string, not a round trip.
- Signing identities came from the request body; `require_transparency`
  gated an empty `if`.
- Autokey template versioning had no caller and no table.
- EKM health said "within threshold" with no metrics; new BitLocker clients
  were "healthy" before a heartbeat.
- `pkg/tsa` used an invented policy OID; `pkg/compliance` returned "pass" with
  invented evidence. Neither was imported: unused packages still read as
  capability to a reviewer.

### A cipher named after a standard must pass the standard's vectors
- **What happened:** "FF1" had tests, but they only round-tripped (encrypt
  then decrypt). An additive keystream round-trips perfectly, and it leaked
  plaintext differences for years.
- **Rule:** a primitive named after a standard is tested against that
  standard's published vectors (NIST FF1 samples 1–9, RFC KATs). A test also
  proves the known weakness is absent (`TestFF1IsNotAnAdditiveKeystream`).

### A default branch that "generates something" is a fake-key factory
- **What happened:** `generateMaterialForCreate` ended with "otherwise,
  return random bytes of a default length". Every algorithm nobody had
  written a branch for silently became 32 random bytes under its name:
  XMSS, LMS, DSA, DH, hybrids, and eleven of the twelve SLH-DSA sets.
- **Also hidden:** SLH-DSA parsing panicked (circl needs the parameter set
  before `UnmarshalBinary`), so the one "real" SLH-DSA key could never sign.
  No test ever signed with one.
- **Rule:** a generator switches on an explicit plan
  (`planKeyGeneration`) and refuses by default. Every algorithm the UI offers
  has a sign/verify or encrypt/decrypt test.

### Record the source that produced the bytes, not the one requested
- **What happened:** `Random()` accepted `hsm-trng` and `qkd-seeded-csprng`,
  used the OS CSPRNG, and returned and audited the requested label.
  `SetQRNGClient` existed and was never called.
- **Rule:** provenance fields (source, algorithm, provider) are set from what
  actually ran. An integration nothing wires in is dead code. A source
  unavailable in every mode is refused before mode-specific checks, so the
  refusal names the real reason (the strict-mode run caught the reverse
  order).

### A status code is not a policy decision
- **What happened:** Feature Forge's policy guardrail treated any HTTP 200 as
  "permitted", but the policy service answers 200 with `decision: deny`. Its
  apply body also carried fields the policy service rejects
  (`DisallowUnknownFields`), so nothing was ever applied. The feature
  "deployed to prod" by changing a status field.
- **Rule:** a client reads the decision in the body, and a feature's
  end-to-end path is exercised against the real peer, not a stub, before it
  ships. A pipeline with no real environment behind its stages is removed,
  not relabelled.

### A fallback list is fabricated evidence
- **What happened:** when OSV or Trivy failed, the SBOM answered from a
  built-in two-entry CVE list with wrong facts, and audited
  `vulnerability_cnt: 0` whenever lookups failed. Discovery did the same with
  invented endpoints, cloud keys and certificates.
- **Rule:** when a source fails the result is "not assessed" with the error,
  and a composite with any failed source is an error, never a partial answer
  presented as complete. A zero count is only reported when a check ran.

### "Completed" must mean the thing changed
- **What happened:** PQC migration marked steps `completed` after a
  same-algorithm rotate, or after nothing at all for certificates. Playbook
  aliases reported OK after only logging, and the watchdog emitted
  "page-oncall" and "freeze-mutations" that nothing consumed.
- **Rule:** a step's status names what actually happened
  (`successor_created`, `rotated`, `manual_required`). Advice is labelled a
  recommendation. An action list contains only what the executor performs,
  and the save-time allow-list and the UI match it.

### Conformance by name misses fakery by value
- **What happened:** the `real-capability` check matched `mockX(` calls only.
  `MOCK_*` constants, `newMockProvider` (no word boundary) and a hostname
  byte-sum "scanner" all passed.
- **Rule:** the check now also covers constants and constructors, but review
  still follows the data: where did this value come from, and did anything
  observe it?

### No mock, synthetic, fake or simulated data, features or audit
- **What happened:** a code-wide sweep found about 20 features that
  invented their output while looking finished:
  - **Fake crypto:**
    - FF1/FF3-1 was a per-position additive keystream, not SP 800-38G.
    - Non-consistent "shuffle" masking was a no-op.
    - Unimplemented algorithms (XMSS, LMS, DSA, DH, Camellia) were stored
      as 32 random bytes; Brainpool keys were generated on P-256.
    - "HSM TRNG", "QKD" and "QRNG" random output was the OS CSPRNG.
  - **Fake data:**
    - Discovery picked each TLS algorithm by hashing the endpoint name and
      invented cloud keys.
    - The SBOM fell back to a two-entry CVE list with wrong facts.
    - Three dashboard tabs rendered `MOCK_*` data on API failure.
  - **Fake success:**
    - PQC "migration" rotated keys within the same algorithm.
    - Feature Forge "deployed to prod" without touching anything.
    - Playbook actions reported OK after only logging.
    - Watchdog actions were never consumed.
    - The AI gateway health check was hard-coded.
  - **Fake audit:** each of these also emitted a success audit event
    (`audit.pqc.migration_executed`, `audit.crypto.random` with a false
    `source`, playbook `status=OK`). So the audit trail certified work that
    never happened, which is worse than no event at all.
- **Why it survived:** the `real-capability` gate matches only function
  names (`mockX(`). It misses `MOCK_*` constants, `newMock…` (no word
  boundary), and fabrication logic that isn't named for it. Fallbacks
  ("graceful", "local catalog") hid broken integrations. Labels were
  recorded from the request, not read back from the result.
- **Rule:** never mock, synthesise, fake or simulate a feature, its data or
  its audit. See CLAUDE.md rule 8 and
  [REAL_CAPABILITY.md](docs/SECURITY/REAL_CAPABILITY.md).
  - On failure, show "unavailable" with the error.
  - Without measurement, show "not assessed".
  - Without implementation, remove the feature or return
    `409 feature_preview`.
  - Emit audit events and `result: "success"` only after the real effect.
    Read the label back from the artifact that was produced.
  - Keep mocks in `_test` files only.
- **Resolved in 1.26.0-beta:** every finding was made real or removed; see
  CHANGELOG 1.26.0-beta and the table in REAL_CAPABILITY.md. The lessons
  from fixing them are the entries below.

### A sink can't have a hard startup dependency
- **Context:** every other `pkg/mek` service refuses to start until keycore
  gives it its master key. That is the safe default for a service whose whole
  job is the encrypted data.
- **The trap:** copied to the audit service, the same rule would stop audit
  ingest whenever keycore is down or returns a mismatched key. Durable
  JetStream would hold events, but the platform would lose its audit trail
  exactly when something is wrong.
- **What we did:** the key opens in the background, and only the feature that
  needs it fails closed (webhook credential writes return 503, and
  deliveries that need credentials fail with the reason).
- **Rule:** fail closed at the smallest scope that protects the secret. Never
  let a feature's key take down the audit pipeline.
- **Also:** plaintext storage is an exposure like a public key. Seal the
  rows, and record them in the register so someone rotates the material. A
  copy made before sealing still has it.
### information_schema lists partitions as tables
- **What happened:** the backup engine enumerated `information_schema.tables`
  (`BASE TABLE`), which includes both a partitioned parent and every
  partition, and backed up each. Every row of the partitioned tables
  (keycore `keys`, audit `audit_events`) was captured twice, so a restore
  failed on keys and would have doubled audit events.
- **How it surfaced:** only when another package's test left keycore's
  partitions in the shared test database. On a fresh database the tests
  passed.
- **Rule:** enumerate tables from `pg_class` with `relkind IN ('r','p') AND
  NOT relispartition`, and read and write through the parent. Treat a
  failure "only on a shared database" as a hint about production, where
  every service's tables share one database, not as noise.

### Never let a failing check reach a push
- **What happened:** the command ran tests, then `;`, then commit and push.
  The certs suite printed `FAIL` and the push happened anyway.
- **Also:** the new test passed when run alone and failed in the full
  suite, because an earlier test left a process-wide svctls identity behind.
- **Rule:** chain verification and push with `&&` (or `set -e`), and gate
  on the full package run, not a `-run` subset. A test that sets
  process-wide state resets it in `t.Cleanup`.

### A plausible screen can hide a missing backend twice
- **What happened:** removing the `MOCK_*` fallbacks from the Webhooks and
  Rotation Scheduler tabs showed that the mocks hid more than a failing
  call:
  - the webhook dispatcher was fully written and never constructed, so no
    event was ever delivered;
  - "trigger rotation" inserted a run row marked `running`, rotated nothing,
    and no scheduler existed.
- **Also hidden:** the webhook list returned signing secrets and Splunk and
  Datadog tokens to every reader, and the leak scanner accepted any
  `resolved_by` from the client.
- **Rule:** after removing a fallback, follow the data for each action to the
  side effect (the key version, the outbound request), not to the row that
  records it. A run row, a delivery log or a status field is evidence only if
  the code that writes it also did the work.
- **Closed in 1.25.0-beta:** webhook credentials are now sealed under an
  audit service master key (see the entry above).

### A test that doesn't exist also passes
- **What happened:** 1.16.0-beta cited two tests as proof, and a filtered
  `go test -run` printed `ok`. The test file had never been written: the
  command creating it was chained after a failing `go build`. A `-run`
  pattern that matches nothing still reports `ok` (`[no tests to run]`).
- **Rule:** before citing a test as evidence, see it run: `-v` and its
  `--- PASS` line, and the file in `git status`. Never chain a file write
  after a command that may fail.

### A post-quantum label needs a post-quantum key
- **What happened:** "PQC" certificates were ECDSA certificates with an
  ML-DSA label, and the certified module has no ML-DSA to make them real.
- **Rule:** a feature that names an algorithm reads the algorithm back from
  what it produced (the certificate's public key), and refuses when the
  library can't produce it.

### A "fallback" that renders sample data hides a broken integration
- **What happened:** the Crypto Agility tab caught any keycore error and
  rendered `MOCK_SCORE`, `MOCK_ALGORITHMS` and `MOCK_PLANS` as the tenant's
  data. The tab's types also didn't match keycore's response. Against a
  live keycore it rendered zeros and blanks. Plan creation always failed
  (date format), and the catch added a fabricated plan.
- **Why nobody noticed:** the mocks made the page look finished. The
  fallback hid both the broken contract and the failing create.
- **Also hidden underneath:** the create handler trusted body `tenant_id`
  with no token check. That was cross-tenant writes on a route no one
  exercised for real.
- **Rule:** a dashboard fetch failure renders "not assessed / unavailable"
  with the error, never constants. Type the client from the Go structs, and
  check the page against a real backend response, not the mock.
- **Same pattern, still open:** `WebhooksTab.tsx` (`MOCK_WEBHOOKS`,
  `MOCK_DELIVERIES`, and a fabricated webhook on a failed create),
  `LeakScannerTab.tsx` (`MOCK_TARGETS`, `MOCK_FINDINGS`, `MOCK_JOBS`) and
  `RotationSchedulerTab.tsx` (`MOCK_POLICIES`, `MOCK_UPCOMING`,
  `MOCK_RUNS`). The `real-capability` conformance check only scans function
  names (`mock*`), so it misses `MOCK_*` constants. Extending it to the
  dashboard would catch these.

### A label is not the key: check what was generated, not what was asked
- **What happened:** `generateLeafKey` and `generateSigningKey` switched on
  "RSA" or "ECDSA" and ignored the size. Every "RSA-3072" certificate had a
  2048-bit key, and "ECDSA-P384" had P-256.
- **The same path faked PQC:** an "ML-DSA-65" certificate without a CSR fell
  through to ECDSA and was still recorded and audited as PQC.
- **How it surfaced:** only when a test read the key back out of the
  certificate that the Service mTLS page wrote.
- **Rule:** a test of key generation asserts on the generated key
  (`pkgcrypto.DescribePublicKey`), never on the stored name. When records
  and reality disagree, correct the records from the certificate and audit
  each correction.

### Check the toolchain before repeating a limitation
- **What happened:** the docs said Go's TLS can't use ML-DSA certificates.
  Go 1.27 can.
- **The real constraint:** the certified Go Cryptographic Module v1.0.0 that
  this platform must use has no ML-DSA (`crypto/mldsa` returns an error).
- **Rule:** state the actual constraint, and re-check it when the toolchain
  changes.

### A post-quantum choice must fit every caller
- **The constraint:** Envoy (BoringSSL) offers only `X25519MLKEM768` among
  the post-quantum groups.
- **What that rules out:** a per-service list that let a server accept only
  ML-KEM-1024 would have made that service unreachable through the gateway.
- **Rule:** before offering a crypto choice per service, list every client
  of that service and what it can negotiate.

### Postgres tests that share a database can collide
- **What happened:** governance's backup test restores every public table
  with `TRUNCATE ... CASCADE`, in parallel with other packages' tests on the
  same database. It put back rows the certs test had just truncated.
- **Rule:** a Postgres test creates its own schema (`search_path` in the
  DSN), runs the migrations there, and drops it afterwards.

### A config flag copied into a status response is a claim
- **What happened:** `use_tpm_seal` passed from the installer through
  `.env` into the sealed blob and the status API, and nothing read it for
  any decision. The status reported `use_tpm_seal: true` for a key that was
  never near a TPM.
- **Rule:** when a status or report field names a protection, trace it to
  the code that enforces it. If there is none, remove the field (rule 8).
  Keep reading old data that carries it, and warn operators who had turned
  it on, since they believed they had that protection.

### A test that greps for registrations goes blind to kernel routes
- **What happened:** `TestLocalRoutesExist` (pkg/clusterroute) proved that
  each cluster-local route exists by grepping for `HandleFunc("...")`. The
  first keycore route registered through the `pkg/route` kernel
  (`r.Handle("POST /keys/{id}/generate-data-key", ...)`) looked unregistered.
- **Fix:** the pattern now matches `Handle(` and `HandleFunc(`.
- **Also fixed (1.14.0-beta):** `scripts/generate_product_map.py` had the
  same blind spot, so 52 kernel routes were missing from `docs/generated/`.
  It now parses `route.Spec` registrations and records permission and
  action.
- **Trap when matching the kernel:** `pkg/route`'s own `Router.Handle`
  forwards its `pattern` parameter to `mux.HandleFunc`. A scanner that binds
  call-site arguments to parameters (needed for `pkg/mek`'s
  `Routes(r, domain)`) then "finds" every kernel route a second time, inside
  `pkg/route`. Registrations whose pattern has no string literal are
  wrappers and are skipped.
- **Lesson:** anything that discovers routes by text search has to change
  when registration changes shape. Look for the other scanners (tests,
  generators, conformance) whenever a new registration API lands.

### "Envelope encryption" can be faked with nothing but metadata
- A KEK/DEK table with names, versions and a "rewrap job" queue looks like a
  key hierarchy but holds no keys. To check, follow the data: is there key
  material, does anything insert DEKs, does anything process the job?

## 2026-09-26

### A README can hold a live credential, and the path to it can be indirect
- **What happened:** the hsm-integration README listed `VectaCLI@2026` as
  SSH "default credentials" long after the code stopped using it, so the
  secret checks, which scan code, never saw it.
- **It was still reachable, indirectly:**
  - the SSH password is copied from the KMS CLI user;
  - CLI users seeded before the earlier fix still had that password;
  - nothing revoked it.

  Removing a default has to include finding what it already produced, not
  just where it is read.
- **The same path leaked every password it copied.** Base64 inside a
  `docker exec` command line is still the password, in `docker inspect` and
  `ps`. Pass secrets to an exec through its environment, and read them with
  a shell builtin.
- **"Hardened" images must be run.** Adding `USER hsm` to the Dockerfile
  made the root-only entrypoint fail, so the container had not started since.
  Separately, uploaded libraries were readable only by the SSH user, so the
  connector couldn't load them. Neither showed up without running the
  container. Run the image and exercise the flow: log in, upload, read it
  from the consumer.

### A secret default in a start script escaped every secret check
- **What happened:** `start-kms.sh` and `start-kms.ps1` fell back to a
  literal CRWK passphrase, `${CERTS_CRWK_BOOTSTRAP_PASSPHRASE:-vecta-dev-passphrase}`,
  in two places each: the variable, and the in-container `printf`. Rule 3's
  checks scanned compose files and Go, not the scripts that seed volumes, so
  the key protecting every CA key shipped public on every script-based
  install. The same scripts also put the passphrase on the `docker run`
  command line, where `ps` shows it.
- **Rule:** secrets seeded into volumes are secrets too.
  - Generate them inside the container (`/dev/urandom`), so they never cross
    the host.
  - Pass an operator's value by variable name (`-e NAME`), never
    `-e NAME=value`.
  - Scan every script that seeds state, not just compose and Go
    (`no-secret-fallback-scripts`).
- **Rule:** once a secret has shipped, ban its value everywhere
  (`no-retired-public-secret`). Code that must recognise it, to migrate off
  it, compares a SHA-256 digest.
- **Changing the passphrase isn't enough:** re-sealing the same CRWK under
  a new passphrase leaves every old copy of `crwk.sealed` able to open
  current and future signers. Re-key to a new CRWK and rewrap, then delete
  the old key only after the last row moves.

### An audit consumer that NAKs a permanent error stalls the whole stream
- Platform events without a tenant were rejected with "tenant_id is
  required" and NAK'd to be redelivered, forever. Once enough were in
  flight, JetStream stopped delivering anything else. For about 3.5 hours
  no audit event was stored, and nothing alerted.
- **Rule:** separate transient errors (NAK: database down) from permanent
  ones (terminate: can never be ingested). Don't reject a valid event for a
  missing field you can default: platform events belong to the platform
  tenant.
- **Check:** `select max(timestamp) from audit_events` should be seconds
  old on a live stack.

### Turning on TLS for the database exposes everything that read it before identity
- The FIPS mode read in `pkg/config` ran at configuration load, before
  enrolment. With Postgres on mTLS it would have failed quietly and fallen
  back to the seed mode, ignoring the administrator. Anything read before
  enrolment must come from a local, trusted source (here, a file governance
  writes).
- The CA lived only in the database it now protects. A sealed cache on the
  CA's own key volume breaks that cycle; existing installs are exported
  once over the Unix socket.

### Infrastructure daemons and TLS files
- Postgres, Valkey and Consul check key ownership or run as their own user.
  Files written by the certs user need copying by a root wrapper
  (`tls-entry.sh`) before the image's entrypoint, and a reload signal on
  renewal:
  - Postgres, NATS and Consul reload on SIGHUP;
  - Valkey reloads on `CONFIG SET tls-cert-file`.
- Compose volume `subpath` mounts fail if the subdirectory doesn't exist,
  so create them in volume preparation.
- In compose, `depends_on: !reset {}` did **not** override a dependency
  merged in from a `<<:` anchor; `depends_on: {}` did.
- OpenSSL (Postgres, Valkey) needs the client chain up to a self-signed
  root, so they verify against the root too. Go servers (NATS, Consul)
  can pin the Sub CA.


### Five traps turning on internal mTLS
- **Start-up deadlock.** Certs fetched its master key from keycore before
  serving, but keycore now needs a certs-issued certificate first. Fix: the
  internal CAs sign with certs' own root wrapping key, so certs runs its PKI
  and enrolment before loading keycore's key. Legacy signers fail closed
  until the key arrives.
- **New named volumes are root-owned.** Services that don't run as root
  can't write them. The existing volumes worked only because
  `start-kms.sh` chowns them, so every new volume needs a line there.
- **Envoy's upstream TLS maximum defaults to 1.2.** Setting only
  `tls_minimum_protocol_version: TLSv1_3` fails every handshake with
  `NO_SUPPORTED_VERSIONS_ENABLED`, and Envoy's own stats show only
  `ssl.connection_error`. Set the maximum too. `--mode validate` doesn't
  catch this.
- **OpenSSL (nginx) won't accept an intermediate as a trust anchor.** Go and
  BoringSSL (Envoy) accept the Sub CA alone. nginx needs the chain up to the
  self-signed root, and then a check on `$ssl_client_i_dn` so root-issued
  certificates are still refused.
- **The Mac's system Python (LibreSSL) can't speak TLS 1.3**, so it can't
  reach the edge. Use Go or `curl` to test.

### The internal calls that were quietly wrong
- Several `*_URL` defaults were `http://127.0.0.1:<port>`. Inside a
  container that is the container itself, and three pointed at the wrong
  service port: compliance's `AUTH_URL` at 8020, `BACKUP_URL` at 8090,
  posture's `GOVERNANCE_URL` at 8030. They only worked because compose set
  the real value.
- Governance dialed approval callbacks with `insecure.NewCredentials()` to
  any address in the request.
- Payment served terminals on plaintext TCP on `0.0.0.0:9170`.


### "mTLS verified" means a handshake was observed, never that it was configured
- The mTLS Mesh page showed every service pair as mutually authenticated.
  The value was hardcoded `MTLSVerified: true` over a static dependency
  list, and its "renew" discarded the certificate and key it generated.
  Meanwhile every service called the others over `http://`.
- **Check the wire, not the diagram.** Look for the `*_URL` scheme in
  compose, for `ClientAuth: tls.RequireAndVerifyClientCert` on the
  listeners that actually carry traffic, and for who dials which port. A
  per-service self-signed "mTLS" config that trusts only itself
  authenticates nothing.

### Every connection is TLS; internal ones are mTLS from the internal Sub CA
- **Owner directive (CLAUDE.md rule 10, docs/SECURITY/INTERNAL_TLS.md):**
  nothing is HTTP.
  - Internal traffic (services, Envoy, Postgres, NATS, Valkey, Consul,
    health checks) uses mTLS with certificates from a
    `vecta-internal-services` Sub CA under `vecta-runtime-root`. Both CAs
    are created at deployment and are visible in the PKI tab's CA hierarchy.
    Every new internal feature takes its certificates from that Sub CA.
  - External endpoints use TLS, with a certificate from the internal or an
    external CA, chosen in the PKI tab.
- **Operating model:**
  - Service mTLS certificates are listed in the dashboard.
  - Each can be rotated with one click: the old certificate is revoked and
    removed, and the service swaps to the new one by a graceful drain and
    re-exec, or by a forced restart.
  - The mechanism is chosen per service with one click. PQC is available as
    hybrid ML-KEM key exchange; ML-DSA certificates aren't supported by
    Go's TLS, and the UI says so.
- **Why a Sub CA:** internal certificates are issued daily and must be easy
  to rotate or revoke as a set. Keeping that off the root limits the blast
  radius, and gives future internal features one issuer.


### Never mimic or fake a feature: it must be 100% real capability
- **Owner directive:** every KMS feature does what its UI and API say, end
  to end. A UI with no real backend behind it, or a backend that invents
  results, is not a feature. (CLAUDE.md rule 8,
  docs/SECURITY/REAL_CAPABILITY.md.)
- **Why it became a rule:** in one day three features turned out to be
  fake, and a fourth was a weak security fallback:
  - key escrow stored records and released nothing;
  - the CT log monitor invented certificates and "unknown CA" alerts;
  - the DR drill marked every step passed with made-up RTO/RPO;
  - the tokenize nonce fell back to `Math.random`.
  Each looked complete in the UI and in a skim of its handlers.
- **How to tell:** follow the data. Is the real key or secret touched? Is
  the real network call made? Does the check actually run? If not, remove
  it, or label it a preview returning `409 feature_preview`. It is never
  "almost done".
- **Enforced:** `make conformance` rule `real-capability`. It flags
  `simulate*` / `synthetic*` / `fabricate*` / `fake*` / `mock*` functions
  outside tests, and `Math.random` byte generation. It flagged every fake
  function in the removed code.

### The local Postgres password was exposed in an assistant session
- **What happened:** our local Postgres password was exposed in an AI
  assistant session.
  - One of the assistant's commands failed and printed the
    `POSTGRES_PASSWORD` value from `.env` in its error output.
  - Nothing ran against the database, and the password was only visible in
    that session's output.
  - It's a local development password, but rotating it is still worth
    doing (docs/SECURITY/SECRET_ROTATION.md).
- **Cause:** the command was stored in a zsh variable,
  `X="docker exec -e PGPASSWORD=$P ... psql"`, and run as `$X`. zsh doesn't
  word-split variables, so it looked for a command named after the whole
  string, and "command not found" printed that string, password included.
  The password was also inline (`-e PGPASSWORD=<value>`), so any echo of the
  command line would have leaked it.
- **Rule (owner directive):** NEVER expose a password, JWT, token, API key,
  private key or any other sensitive value, in commands, logs, errors,
  output, chat, commits or URLs (CLAUDE.md rule 9,
  docs/SECURITY/SECRET_HANDLING.md).
  - Pass secrets by environment variable name (`-e PGPASSWORD`), file or
    stdin.
  - Wrap commands in shell functions.
  - If a secret leaks anyway, say so immediately and rotate it.


### `go build ./...` inside a service writes a binary that `git add <dir>` commits
- Running `go build ./...` inside a single-package service directory writes
  a binary named after the directory (`services/governance/governance`).
  The root `.gitignore` only covered the root-level outputs and two service
  paths, so `git add services/governance/` committed a 35 MB binary (in
  1.4.0-beta), and later `services/certs/certs` (1.5.0-beta).
- Fixed in 1.6.0-beta: both are untracked, and `.gitignore` lists
  `services/<name>/<name>` for every service. They stay in history; purging
  them means rewriting the published `main`.
- Stage named files, or check `git status` for `Bin` entries, before
  committing a directory.

### Split "open" from "apply" to get honest verification cheaply
- Restore already did every hard check: key resolution, guardian shares,
  the HSM unwrap, AES-GCM under the AAD, and the snapshot parse. Splitting
  it into `openBackup` plus apply let "Verify Backup" reuse the exact same
  path instead of copying it. Verify can't drift from restore, and restore
  has one fewer place to get wrong.
- The fabricated DR drill had also let restore trust `created_by` from the
  body. Look for actor and tenant fields in request bodies whenever a
  handler is touched: `verifiedActor(r)` in governance takes them from
  claims.


### Grep for "simulate", "synthetic", "fake" and "mock" outside tests
- **What we found:** the CT log monitor's only data source was a function
  literally named `simulateCTFetch`. It invented certificates and
  high-severity alerts on every new domain. Code review of the handlers
  missed it because the store, API and UI were all real.
- **Check:** `grep -rn -i 'simulat\|synthetic\|fake' services pkg | grep -v _test.go`
  before calling a feature real. Any hit that produces user-visible
  results breaks rule 7.
- **zsh doesn't word-split variables:** `X="docker exec ..."; $X` runs a
  command named after the whole string, and the "command not found" error
  prints it, secrets included. Use a shell function, and pass secrets
  through the environment (`-e PGPASSWORD`), never inline.


### An escrow feature that stores records is not escrow
- **What we found:** keycore's escrow workflow looked complete (guardians,
  policies, recovery requests, M-of-N approvals), but "escrowing" a key
  stored its ID and name, and an approved recovery released nothing.
  Guardian votes also took `guardian_id` from the request body.
- **How to spot it:** follow the key material, not the workflow. If no code
  path touches the secret, the feature is a record-keeper, whatever the UI
  says.
- **Shamir recovery never fails loudly.** Combining fewer shares than the
  threshold returns a wrong secret, not an error. Always check the result
  against a stored fingerprint before use.
- **A dropped table stays in the cluster catalogue.**
  `TestEveryTableIsClassified` scans every `CREATE TABLE` in the
  migrations, including ones a later migration drops (as with
  `kdf_configs`). Replication publishes only tables that still exist.
- **`generate:openapi` copies Swagger UI from `node_modules`.** A stale
  local install (5.32.6 against the pinned 5.33.0) rewrites the committed
  assets. Run `npm ci` or revert them; it isn't a spec change.


### Version every build, or you can't tell what's running
- **What happened:** the owner deployed, saw no visible change, and reported
  the running KMS as old. It wasn't: the code was merged at 00:46 and the
  images were built at 00:51 (compare `git reflog --date=iso` with
  `docker inspect <image> --format '{{.Created}}'`). But every build was tagged
  `1.2.0-beta` and the UI showed no version, so nothing told the two apart.
- **A wrong turn to avoid:** grepping the minified bundle for a component name
  (`ClusterJoinPanel`) is not proof a build is stale. Minification drops
  component names, and new chunk hashes after a `--no-cache` rebuild don't
  prove the old build lacked the code either. Compare timestamps first.
- **Fix:** every KMS change bumps MINOR in `VERSION` (enforced by
  `scripts/check-docs.sh`), and the dashboard ⓘ button shows version, commit
  and build time. The build time is a build arg placed after `npm ci`, so it
  only re-runs the Vite build and never serves an old bundle under a new
  version.

### Check compose with the profiles installers actually use
`docker compose config` with no profiles fails ("envoy depends on undefined
service certs"). This isn't a bug: `certs` sits behind a profile, and
`install.sh` always enables it through `infra/scripts/parse-deployment.sh`.
Validate with `COMPOSE_PROFILES=$(bash infra/scripts/parse-deployment.sh
infra/deployment/deployment.yaml)`, once with `hsm_mode: software` and once
with `hsm_mode: hardware`.

### A backend name is not a backend
certs accepted `key_backend: "hsm"` and the dashboard showed "HSM-backed",
but `normalizeKeyBackend` folded "hsm" into "keycore", which generated a
software key like every other CA. When a CRL failed to sign, certs wrapped a
JSON note in `X509 CRL` PEM headers and published it. Both looked like
working features. Grep a feature's name down to the call that does the work
before trusting a label, and a failure path must fail, not produce something
shaped like success.

### Don't query the store inside a crypto transaction
Keycore's HSM failure handler looked the key up again (`GetKey`) to name
its device in the error. It ran inside `runCryptoTx`, which holds the
connection; with SQLite's single connection the test hung forever (on
Postgres it would take a second connection per failing request). Use the
`Key` the callback already has.

### `_` is a wildcard in LIKE
The audit `action_prefix` filter matches `audit.key.hsm_`. Unescaped,
`_` matches any character, so `audit.key.hsmX...` would match too. Escape
`\`, `%` and `_` and say `ESCAPE '\'` (Postgres and SQLite both honour it).

### Proving a key was generated in the HSM
The HSM itself says so: `CKA_LOCAL` is true only for keys generated on the
token, and `CKA_NEVER_EXTRACTABLE`/`CKA_ALWAYS_SENSITIVE` show it never left
in the clear. Read attributes one at a time: `C_GetAttributeValue` returns
an error for the whole call when one attribute is invalid for the object or
sensitive, and miekg/pkcs11 then returns none of them. Never ask for
`CKA_VALUE`.

### A settings page is not an integration
The HSM tab let a tenant upload a PKCS#11 library, pick a slot and save a
profile. That looked like HSM support, but no code ever opened the library.
The compose entry for `hsm-connector` pointed at an image with no build.
"HSM-bound" backups derived a key from an environment secret and only mixed
the HSM's slot name into it. The menu even offered a "Vecta KMS HSM" that
doesn't exist. The test for a security integration is whether one call goes
through the vendor's library. Running the real protocol in tests (SoftHSM2
is a real PKCS#11 implementation) is what makes that visible. A few traps
from building it:
- Vendor libraries are glibc builds, so they can't load into an Alpine or
  static binary. That's why the connector is a separate cgo service.
- A PKCS#11 token logs out when its last session closes, so keep one anchor
  session per slot.
- Vendors report a GCM tag failure differently: SoftHSM2 says
  `CKR_GENERAL_ERROR`.
- A distro's library path can be a symlink that leaves the allowed
  directory, so resolve before you confine.

### An optional verifier is an open door, and a missing env var is enough to open it
Governance treated a missing JWT key as "auth disabled" and let every
system-administration call through. It also read the key from variable
names no deployment set: compose provides `JWT_PUBLIC_KEY_B64`, and
governance looked for `GOVERNANCE_*`, `KEYCORE_*` or a file. So the fallback
wasn't an edge case. It was how every compose deployment ran, and backups,
restore and the FIPS switch were open to anyone who could reach the port.
Two lessons:
- Load keys through the shared loader (`pkg/jwtauth`), so every service
  reads the same variable names.
- Fail closed at startup, as `jwtauth.MustWrap` does.

Closing the door then showed who had been walking through it. keycore and
policy read the system state, and posture wrote posture controls, all
without tokens. keycore and policy had also asked for per-tenant state,
which governance only serves for root, so for every non-root tenant they
had silently got 403s. So before closing an unauthenticated path, list its
callers (same lesson as keycore's anonymous key use).

### A key stored next to what it protects is not protection
Governance "encrypted" software-mode backups and kept the key in the same
row. The key package even said "store this separately from the artifact",
and then the platform didn't. Encryption at rest only counts when the key
lives somewhere the ciphertext's reader can't reach. Here that means the
operator's saved key file, or a wrap secret outside the database. It
compounded the master-key issue: the "re-protect stored backups" job only
worked because the keys were there to read. Once the keys stopped being
stored, that job had nothing to open, and the simpler fix was to re-wrap at
capture. Separately, "key_derivation: v1" was a raw SHA-256 of
`secret|fingerprint|tenants`, and restore tried three input variants.
Candidate-guessing across derivations is a sign the format was never pinned.
Version the package and accept exactly one derivation.

### "Backward compatible" anonymous access hides the callers that depend on it
Keycore let a request with no token use any key that had no grants. The
branch was labelled backward-compatible, and nobody knew what depended on it.
Auditing every keycore caller found two: compliance playbooks (no token on
internal calls) and the reconciler (only the shared internal token, and no
tenant, so keycore was already rejecting its lifecycle calls, and scheduled
rotation had silently never worked). So before closing an anonymous path,
list its callers and give each a real identity. The audit also shows which
features were quietly broken. And fail closed at startup when the verifier
is missing: keycore used to start without its JWT key and then treat
everyone as anonymous.

### "Fall back to the header" is "let the caller choose"
keycore built its actor from the verified token, then filled any empty field
from `X-Actor-*` headers, presumably so a trusted proxy could pass a user on.
No proxy ever did. The service-principal flag had already been fixed to
ignore the headers, but role, permissions, groups and user ID hadn't. So a
token with no permissions could send `X-Actor-Permissions: *` and be an
admin. The lesson generalises: a fallback for a *security* field is an
override for whoever controls the fallback's source. Identity fields have
one source, the verified token; everything else is audit context, kept in a
separate struct no policy reads, so a future edit can't quietly start
trusting it again.

### A default that nobody overrides is the only value in production
Four services had a "dev" master-key fallback that logged "not for
production". Nothing ever set the real variable (compose never even passed
it into the containers), so every production deployment ran on public keys.
What we learned fixing it:
- **Check what a value is derived from, not how it's spelled.** The
  secure-defaults check looked for `("VAR", "default")` pairs; the fallback
  was `Hash([]byte("…-dev-mek"))`.
- **An environment-variable key is the wrong fix for data at rest.** The
  first attempt (a required env key) broke plain `compose up`, needed manual
  copying to cluster members, and turned every backup and rotation step into
  a way to lose data. Deriving from keycore needs no configuration, and
  members get it through the join.
- **Re-wrapping doesn't reach copies made before.** Dumps, snapshots and
  downloaded backups still open with the public key. Only replacing the
  material helps there, so the fix has to track which items were exposed
  (the exposure register) and close each entry when it's rotated.
- **Look where else the old data lives.** Governance stores backups, and for
  software-mode backups their keys, in the same database, so the live
  database kept exposing old values until those were re-protected too.
- **A 403 isn't a 401.** Once routes enforce permissions, a dashboard that
  signs users out on 403 logs out anyone who opens a page they can't use.

### A rule every handler must remember is a rule some handler forgets
`services/secrets` had a `mustTenant` helper that checked the request tenant
against the token, and most routes called it. `POST /secrets` didn't: it read
`tenant_id` from the body, which `mustTenant` never looks at, so any tenant
could create secrets in another. The same pattern was copied 22 times across
services, with about 960 routes each choosing whether to check the tenant,
the permission and the audit. Code review can't hold that many conventions.
The fix is structural: `pkg/route` makes the rule part of registering a
route, and a conformance rule stops new code from registering routes any
other way. The same applies to any cross-cutting rule. If it has to be
remembered, put it in the kernel. Also check the body, because that's where
the dashboard puts the tenant on writes.

### "Flaky" test was a 2% product bug: never trim binary data
`TestImportKeyPEMAutodetect` failed about once in 40 runs, and it was written
off as flaky. The cause was `bytes.TrimSpace` on DER. Random key bytes end in
one of the six ASCII whitespace values about 2.3% of the time, and that
trailing byte was cut. Trim text (a PEM envelope, a pasted string), never the
bytes it decodes to. An intermittent crypto-test failure with random keys
points at data-dependent handling, so find the input that triggers it instead
of re-running.

### A member's write to a replicated table can stop replication, not just diverge
With logical replication, a subscriber's local row isn't protected. A member
that inserts a row the primary later inserts too (for example dataprotect's
lazy "first sight" `dataprotect_key_kdf` row) hits a unique-key conflict in the
apply worker. That component's replication then stops until someone fixes it
by hand. A member that updates a row (a counter) makes the row differ, and
with `REPLICA IDENTITY FULL` the primary's next update to it is skipped.

So the rule is broader than "crypto-path tables are node-local". Anything a
member does without a user request counts too: schedulers, sweeps,
reconcilers, and lazy "record on first use" inserts. The fix pattern is
`clusterstate.RunsPrimaryJobs(ctx)` or `IsMember()`, plus a test that runs the
path as a member (`clusterstate.Static`) and proves no replicated row was
written.

### Forward by default, not by allowlist
The first draft listed the writes to forward, and every endpoint added later
would have written locally on members. Inverting it, so every write is
forwarded except a short `Local` list checked against real routes, makes the
safe behaviour the default.

## 2026-09-25

### Four things the first real two-node join taught
- **Postgres defaults can't run a multi-component member.** The default is 4
  logical replication workers in total. With 4 component subscriptions, every
  worker was an apply worker and none could copy tables: 3 of 4 components
  sat in "initializing" forever while auth, which started first, finished. A
  member needs about one apply worker per component plus copy workers, so
  `max_logical_replication_workers=64`, `max_worker_processes=96`.
- **Row-level security hides rows from a replication role.** The auth tables
  use RLS, so a non-superuser replication role copies nothing. It needs
  `BYPASSRLS`. The first engine test connected as a superuser and could never
  have seen this.
- **Resetting a member without cascades.** Deleting the member's root tenant
  would cascade into its own local admin. Run the reset with
  `session_replication_role = replica`, as the apply worker does, and delete
  only the rows the row filters say replicate.
- **cluster-manager had no authentication at all**, while it was about to
  authorize master-key transfers. Tenant enforcement quietly passes when a
  request carries no token. Check who can call a service before adding power
  to it.

### Recording sync events is not replication
cluster-manager had join tokens, profiles, a sync-event log and per-node
checkpoints, and the overview told users "Nodes sync only the state for their
enabled components…". But nothing ever applied an event on another node, and a
join moved no data. Check that both ends of a data path exist, the writer and
the applier, before believing a feature, and derive status text from the
system's real state rather than writing it by hand. The dashboard carried its
own copy of the claim as a fallback string, so grep the UI too.

### "Documented and audited" needs a check, not a memory
Asked whether every change was documented and audited, the honest answer was
no. The design docs were complete, but `API_REFERENCE.md` lacked every new
endpoint, and several security actions (revoking leaked service keys,
services applying a FIPS mode, reserved-prefix derive attempts) only logged a
line. Verify with a grep over the docs and a count of audit emissions in the
changed files before claiming either. Also, marking audit rows by re-matching
a scanned timestamp failed on SQLite (the types differ); an atomic
`UPDATE … RETURNING` claim is portable and can't double-emit.
### "Is it audited?" must be checked, not assumed
Asked whether the new work reached the audit log, a check found two gaps:
- **The backup service** emitted only the generic HTTP request log, with no
  event saying which policy changed or that a run or restore was refused.
- **Governance restore** audited successful restores but **not refused ones**
  (tampered artifact, wrong key, changed scope). Those are exactly the events
  an investigator needs.

Both now emit specific events, and the integration tests assert them. The
Audit Action Subject Reference had also drifted from the code (it listed
`backup_completed`, which no code emits) and was corrected. Rule: every
activity *and every refusal* gets its own event plus a test (CLAUDE.md rule 2).

### The first real test of a path found a bug each time
Backup, signing and KMIP had no tests of their main path, and each hid a
serious defect:
- **Backup:** it was entirely simulated. Random key counts, a "checksum" over
  its own invented metadata, and a restore that did nothing. The real backup
  engine was elsewhere (governance).
- **Signing:** verification could never succeed. `JSONB` reorders object keys,
  so re-marshalling a stored envelope never reproduces the signed bytes. Store
  the exact signed bytes. And test against Postgres, not SQLite: SQLite keeps
  JSON text verbatim and hides this.
- **KMIP:** one role-denied request crashed the service (a middleware returned
  `(nil, err)` and kmip-go dereferenced it). Revoked keys still encrypted, and
  destroyed keys were still returned.

Lessons:
- A feature isn't done until a test drives its main path end to end, with real
  dependencies where the behaviour depends on them (Postgres, TLS, the real
  protocol client).
- "Implemented as control records" means "stores a row". Say preview, or build
  it.

### Two sessions in one checkout: use a worktree
Another session was editing the same working tree (CHANGELOG, CLAUDE.md,
services) while this work started. Concurrent edits to shared files silently
overwrite each other. Do parallel work in its own `git worktree` and branch,
and merge.

### A symlinked node_modules is not matched by `node_modules/`
Linking the main checkout's `node_modules` into a worktree created a symlink,
which a directory pattern (`node_modules/`) does not ignore. Remove it before
committing, or stage paths explicitly. And never let `npx <tool>` run without
`--no-install`: with no local install it fetched an unrelated npm package
called `tsc`.

### A process-start setting can still be a runtime choice: re-exec plus supervised restart
Go reads `GODEBUG=fips140` only at process start, and container env vars are
fixed at container creation. Two moves give a UI toggle anyway:
1. **Change the mode:** the service SIGTERMs itself (so its normal graceful
   shutdown runs) and lets the restart policy bring it back.
2. **Pick up the new mode:** at startup it `syscall.Exec`s itself with the new
   `GODEBUG` before touching any crypto.

Guards that matter:
- A re-exec marker, so a mismatch is fatal instead of an exec loop.
- Re-reading the setting after the tier delay, so a quickly reverted change
  doesn't restart anything.
- Conformance that every Go service has a restart policy.

Proven in real containers: 55 s from the UI change to keycore running and
reporting `only`.

### Test goroutines that loop forever make other tests slow and racy
The first watcher tests left a zero-interval polling goroutine spinning for
the rest of the test binary, and read its results while it was still running.
Give long-running loops a quit channel and wait for exit before asserting.
`go test -race` confirms.

### A fallback chain can end in a public value, and production takes that path
dataprotect's key resolution tried `material_b64 → material → wrapped_material
→ kcv → id`. keycore never returns the first three, so **every production
working key was HMAC(KCV)**, and the KCV is shown in the UI and API. No test
caught it, because the test fake returned the same metadata shape and the
round trips worked. Lessons:
- Trace a fallback to what the real upstream returns before trusting it.
- "It encrypts and decrypts" proves nothing about where the key came from.
  Assert that the working key differs from anything computable from public
  data (`legacyKeyForCompare` in the tests).
- Unauthenticated formats (FPE, format-preserving tokens) can't detect a key
  change: decrypting with the wrong key returns a plausible wrong value. So a
  migration needs explicit per-key state, not trial decryption.

### `go build ./services/<name>` bit twice in one day
Recording the trap wasn't enough; the same mistake happened again hours later.
For compile checks use `go build -o /dev/null ./services/<name>` or
`go vet`, never a bare single-package `go build` from the repo root.

### "FIPS mode" means nothing without the module, and it must reach the process
`VECTA_FIPS_MODE` toggled an in-app allowlist, compose never passed it, and no
binary was built with `GOFIPS140`. So the product had no validated module, and
governance still reported `fips_library_validated=true` whenever
`fips140.Enabled()` was true, which is also true for the unvalidated `latest`
module. Validated means the certified snapshot is linked **and** FIPS mode is
on (`fips.ModuleValidated()`). Mismatches now stop the service at startup.

### Strict mode (`fips140=only`) found real bugs, not just policy
- **GCM IVs:** `cipher.NewGCM` with any caller-supplied nonce is refused
  (IG C.H: the module must generate the IV). The fix is
  `cipher.NewGCMWithRandomNonce`. Its output (`nonce||ct||tag`) is
  wire-identical to our `Seal`, so no data migration was needed.
- **Stored formats:** keycore persists envelope IVs as a fixed 16-byte prefix,
  of which the old code used only the first 12 bytes. A stricter 12-byte check
  broke every stored key in *all* modes; the test suite caught it. Keep 16 on
  disk (nonce + zero padding) and decrypt with the first 12.
- **OCSP:** the responder always used a SHA-1 CertID whatever the client
  asked for. That was a real protocol bug, and a panic in strict mode.
- **Panics, not errors:** Go *panics* on SHA-1 and on HMAC keys under 112 bits
  in strict mode. Guard with `fips140.Enforced()` before the call.
- **Third-party crypto bypasses the runtime:** `age` generated X25519 keys
  happily under `fips140=only`, and `circl` does ML-DSA/SLH-DSA. The runtime
  can't see crypto that isn't in the module, so it needs explicit guards.
- **Identifier-derived keys:** dataprotect derives keys from key IDs when no
  material is available. Strict mode now refuses; the general fix is tracked
  with a migration.

### Run the matrix, not one mode
The suite passed in `on` from the start; only `only` exposed the issues above,
and only the full run caught the envelope regression. `make test-fips-modes`
and the CI matrix run all three. A test that needs a non-approved algorithm
skips in strict mode *and* has a paired strict test proving the clean refusal.

### Small traps
- In YAML, bare `on` / `off` can parse as booleans; quote matrix values.
- macOS has no `timeout` command, so a `timeout 8 docker run …` silently runs
  nothing. Use `docker run -d` + `docker logs`.
- `go build ./services/<name>` (a single main package) writes an executable
  named `<name>` into the current directory, which is the repo root. To check
  that something compiles, use `go build ./...`, `go vet`, or `-o /dev/null`.

### Secret rules keyed on variable names miss connection strings
The secure-defaults rules matched `*SECRET*`, `*PASSWORD*` and similar names, so
`POSTGRES_DSN` falling back to `postgres://postgres:postgres@…` slipped through
both the conformance scan and the runtime placeholder check. Credentials hide
inside values too: URLs with `user:pass@`. Rules now also inspect the
**shape** of values (URL userinfo in Go and compose literals) and parse
`*_DSN` / `*DATABASE_URL` values at startup.

### Example files are deployment inputs, not documentation
`.env.example` held values like `your-workload-identity-secret`, and
`deploy-local.sh` copies it to `.env` on a fresh install, so those public
strings became live secrets that passed every "is it set?" check. An example
file must ship secrets **empty** (compose `:?` then stops), and services must
reject placeholder-looking values themselves. Now enforced by conformance
`env-example-no-secret-values` and `pkg/config.RejectPlaceholderSecrets`.

### Rotation that only adds is not rotation
Auth bootstrap only created service keys, so rotating the bootstrap secret left
every old service identity valid. Rotating a derived-credential secret must
retire what the old value produced. Auth now deletes a service's keys that
don't match the current derivation (`DeleteClientAPIKeysExcept`).

### bash 3.2: quotes inside `${var//\'/''}` within `$(...)` break the whole file
macOS `/bin/bash` 3.2 misparses single quotes in a pattern substitution inside
command substitution. The error surfaces hundreds of lines later
(`install.sh: line 775: syntax error near unexpected token ';;'`), far from the
cause (line 419). To find it, bisect by truncating the file at function ends
and running `/bin/bash -n` on each prefix. Escape with `sed` instead. CI runs
bash 5, which doesn't catch this; conformance runs `/bin/bash -n` locally.

### Never use `git stash` as a scratch tool in a dirty tree
`git stash push <path> --` with bad syntax stashed nothing, and the `pop` that
followed applied an old, unrelated stash, causing conflicts. To try something
out, use a throwaway `git worktree add` instead.

### A public default secret is a credential every attacker already has
`INTERNAL_SERVICE_BOOTSTRAP_SECRET` fell back to
`vecta-internal-svc-dev-secret-change-me` in compose, and `install.sh` never
wrote it to `.env`, so **every installer-based deployment** derived all 20
internal service API keys from a string in the public repo. Anyone could
compute `HMAC(default, "kms-keycore")` and mint a service JWT. Three lessons:
(1) A "-change-me" fallback is never changed; require the secret
(`${VAR:?}`) or generate it. (2) Check every installer writes every secret
compose needs; `deploy-local.sh` did, `install.sh` didn't, and nobody noticed
because the fallback hid it. (3) Removing a bad default isn't enough: auth now
**revokes** keys derived from the placeholder on every start, or upgraded
deployments would stay open. Now enforced by conformance rule 3
(`no-secret-fallback-*`), documented in `docs/SECURITY/SECURE_DEFAULTS.md`.
The same sweep found the CLI user seeded with a hardcoded `VectaCLI@2026`
fallback; unset now means a random, unknowable password.

### "role == client-service" is NOT a service identity
Phase 2 of the s2s-JWT rollout trusted any token with role `client-service` as
an internal service (tenant-unrestricted + key-grant bypass). But
`IssueClientJWT` stamps that role on **every** client-credentials token —
customer apps included — so it would have been a cross-tenant bypass the moment
tokens were attached. The durable rule: a privilege that bypasses tenancy must
be keyed on something **only the platform can mint**. Now:
`tenantcheck.IsServicePrincipal` = role `client-service` AND reserved perm
`service.internal` AND `kms-*` client id AND internal tenant; the reserved
permission is stripped at every API write path (API keys, tenant roles, user
perms, client-token scope) so only the auth bootstrap can grant it. keycore
derives it from verified claims only — `X-Actor-*` headers are spoofable.
Verified live: an admin-created API key requesting `service.internal` is
stored with it removed; kms-certs mints a token and keycore accepts it for
create+sign.

### Fresh volume ⇒ JWT_PUBLIC_KEY_B64 mismatch ⇒ "invalid token" everywhere
auth generates `jwt_private.pem` on first boot if the volume is empty; every
verifier uses `JWT_PUBLIC_KEY_B64` from `.env`. If the two came from different
installs, login works but every service call returns 401 `invalid token`.
Fix: derive the public key from the auth volume and write it to `.env`
(`deploy-local.sh` does this automatically and restarts verifiers).

### Apple Silicon was running every service under emulation
Dockerfiles hard-coded `GOARCH=amd64`, and `compose-kms.sh` pins each service
to the platform of its existing image — so once built amd64, images stayed
amd64 forever. Dockerfiles now use BuildKit's `TARGETARCH`; `deploy-local.sh`
removes `.tmp_compose.platform.override.yml` before building so arm64 images
replace the emulated ones.

### Published ports were LAN-reachable
Compose published every service port as `"8010:8010"` (0.0.0.0), including
Valkey and NATS. All non-edge ports now bind `${KMS_INTERNAL_BIND:-127.0.0.1}`;
Envoy is the only public listener.

### govulncheck ./... OOMs on this repo
A single `govulncheck ./...` needs > 7 GB. Run it per path
(`./pkg/...` then each `./services/<svc>/...`) and aggregate.

### Recommendation engine: "unknown" is a first-class state
The Command Center never infers a pass or fail from missing data: each source
loads independently and a failure marks its checks "not assessed" and excludes
them from the score. Same principle as "never fabricate security data in a KMS
UI" (2026-06-17).

## 2026-06-18

### JWT service-to-service auth — per-service identities (phased rollout)
Moving internal auth from "mTLS / shared static INTERNAL_API_TOKEN" to per-
service JWTs. Landscape found: validation is universal (every service has the
cluster `JWT_PUBLIC_KEY_B64` + `pkgjwtauth`); minting exists (`POST
/auth/client-token`: API-key-authenticated client-credentials → JWT); the only
prior s2s auth was a narrow shared static token (`pkg/internalauth`, reconciler
→ keycore/kmip privileged endpoints).
- **Provisioning without secret sprawl:** one shared `INTERNAL_SERVICE_BOOTSTRAP_SECRET`;
  each service derives its own API key = HMAC-SHA256(secret, "kms-service-api-key:"+name)
  (`pkg/servicetoken.DeriveAPIKey`). auth bootstrap pre-registers a client +
  key-hash per service from the same derivation, so no per-service secret is
  distributed. `pkg/servicetoken.Source` mints/caches/refreshes the JWT and
  attaches it Bearer (best-effort: errors leave the call unauthenticated so a
  rollout-in-progress never hard-fails).
- **The crux (not yet done):** internal services are multi-tenant but a client-
  token is tenant-bound, and `tenantcheck.Enforce` 403s a root-tenant token
  acting for tenant X (only bypasses an *empty* tenant claim). So a `service`
  principal must be treated as tenant-unrestricted (acts for the request's
  tenant) AND authorized in keycore's `enforceKeyAccess` — else attaching a
  token would *deny* crypto that currently works tokenless. This is why it's
  phased: attach (non-enforcing) first, flip enforcement last.
- **Gotcha:** a directly-inserted *approved* client registration left
  `api_key_prefix` NULL (the normal flow sets it during approval), and
  `GetClientRegistration` scanned it into a plain string → 500. Fixed with
  `COALESCE(api_key_prefix,'')` in the read queries.
- **Phase 1 (done, non-breaking, verified):** pkg/servicetoken + auth
  provisions 20 per-service identities; verified kms-ekm mints a JWT
  (client_id=kms-ekm, role=client-service). Nothing attaches/enforces yet.
- **Remaining:** (2) tenantcheck + keycore access-control trust the service
  principal across tenants; (3) wire `servicetoken.FromEnv(name)` into the ~14
  per-service internal HTTP clients (attach-only); (4) flip enforcement,
  retiring the static INTERNAL_API_TOKEN path.

## 2026-06-17

### mTLS mesh topology edges = the configured call graph (honest, not faked)
"Which service talks to which" has no clean runtime source here: consul Connect
intentions are wildcard allow-all (no real edges) and envoy per-edge telemetry
isn't scraped. The honest source is the **configured dependency graph** — each
service's `*_URL` wiring (`grep -rn 'envOr("[A-Z_]*_URL"' services/*/main.go`),
which are exactly the mTLS HTTP calls. The discovery reconciler holds that graph
(`meshDependencyGraph`, display names) and upserts an edge only when BOTH
endpoints are present in the catalog, so the graph grows with the mesh and never
shows phantom edges. Edges are `mtls_verified=true` (every mesh hop is mutually
authenticated) with no `last_handshake_at` (we don't observe handshakes — UI
shows "No handshake"), which is truthful about provenance. Watch the display-
name mapping: consul names are `kms-hyok-proxy`/`kms-workload-identity`, not
`hyok`/`workload`. Full observed topology would need envoy stats scraping.

### mTLS mesh auto-discovers internal services from consul (live, self-updating)
The mesh view must reflect the *live* internal mTLS fabric, not a manual
registry. Source of truth = the **consul catalog** (`GET /v1/catalog/services`,
`/v1/catalog/service/{name}`): every KMS service self-registers there
(`pkgconsul.NewRegistrar`), so it lists all `kms-*` services and updates as they
come and go. The `certs` service runs a 60s discovery reconciler
(`ReconcileMeshFromConsul` → `UpsertDiscoveredMeshService`, keyed on
(tenant,name)) that records each as a mesh service under the root/platform
tenant (`MESH_DISCOVERY_TENANT`, default `root`; gate `MESH_DISCOVERY_ENABLED`).
New services appear automatically; no manual entry. consul runs at
`CONSUL_HTTP_ADDR` (consul:8500). Discovery is best-effort — a consul outage
never breaks certs. Note: the platform mesh is global infrastructure, so it's
recorded under the root tenant (customer/workload mesh entries stay per-tenant).

### "Showing mock data" ≠ no backend — check before judging a feature fake
The mTLS Mesh tab looked fake, but the `certs` service has a real backend
(`/mesh/services|certificates|trust-anchors|topology`, `…/renew`) — renew
actually generates an EC P-256 key and issues an X.509 leaf from the internal
CA. The tab only *looked* fake because it seeded state with `MOCK_*` and fell
back to mock on empty/error. Real use-case: SPIFFE-style **workload mTLS
identity lifecycle** for the consul/envoy service mesh — register a service,
issue it a short-lived mTLS cert from the KMS CA, track expiry, auto-renew,
manage trust anchors, view the verified-handshake topology. Verdict: KEEP;
removed the mock seed/fallback so it shows real registered services or an
honest empty state. Lesson: a `MOCK_*` fallback masks whether the backend is
real — always trace the lib → route → server handler before deciding to cut.

### Per-key operations belong in Key Management's row actions, not their own tabs
Verify-integrity and Attest are operations *on a key*, so they live in the Key
Management row action menu (alongside Rotate/Export/Destroy), not as a separate
top-level tab. Pattern: add a typed client fn in `lib/keycore.ts`, a handler in
KeysTab that calls it and reports via `onToast` (verify) or a small overlay
(attest, which returns a signed document to view/download). One fewer tab, and
the action is where the user already is.

### Distinguishing a real feature from a redundant management surface
When auditing "advanced feature" tabs, the test is whether the tab adds anything
beyond an operation/interface that already exists:
- **Key Derivation (KDF) tab** managed named `kdf_configs`, but derivation is
  the `POST /keys/{id}/derive` crypto op exposed via REST/PKCS#11/JCA — the
  configs were a redundant surface. Removed the tab + the `/kdf/configs`
  backend (handlers, routes, store methods, types, migration 017 dropping
  `kdf_configs`/`kdf_derivation_log`); the derive op stays.
- **Advanced Encryption tab** POSTed to `/encryption/encrypt|decrypt` which
  **never existed** in keycore (the real path is the Workbench's
  `/keys/{id}/encrypt`). Dead tab → removed; no backend to clean.
- **Envelope Encryption tab**: KEEP. It is a genuinely distinct feature — a KEK
  wraps many DEKs and rotating the KEK triggers bulk *rewrap* of the small DEKs
  instead of re-encrypting the underlying data. Backend is real
  (`/envelope/keks|deks|hierarchy|rewrap|rewrap-jobs`). The only problem was the
  tab fell back to fabricated KEK/DEK rows on load failure — replaced with an
  honest empty state + error (never fabricate security data in a KMS UI).

### Quick test for "is this tab backed by anything"
`grep -n "fetch(\`\${base}" Tab.tsx` then `grep -rn "<that route>" services/<svc>` —
if the route isn't registered server-side, the tab is dead (Advanced Encryption
hit non-existent `/encryption/*`). Mock fallbacks (`MOCK_*`, "showing mock
data") are the other tell.

## 2026-06-16

### Tenant enforcement: data-scoping is not the same as access-enforcement
All these features store data per tenant (RLS + `WHERE tenant_id`), but that
alone does not stop a caller from *asking* for another tenant's data. The
enforcement points and their gaps:
- `mustTenant` → `tenantcheck.Enforce` binds `tenant_id` to the JWT's tenant
  claim — but **only when a token is present**; with no claims it skips by
  design (so the outer layer is expected to require auth).
- **keycore does not require auth globally** (only rate-limit + audit
  middleware), and ~10 internal services (ekm, kmip, signing, payment, …) call
  its `/keys` crypto routes with a `tenant_id` and **no token**. So a blanket
  "require auth" would break platform crypto.
- **posture never parsed JWTs at all** → `tenantcheck.Enforce` was a no-op
  there → the leak scanner had *zero* tenant binding (any `tenant_id` returned
  that tenant's targets/findings).
- Fix without breaking tokenless internal callers: a `requireAuthedTenant`
  helper (reject if no claims, then `mustTenant`) applied to the *dashboard-only*
  feature endpoints (threat, credential-bindings, attest, verify, and posture
  `/leaks/*`). posture also gained an **optional** JWT-parse middleware
  (populate claims if present, 401 if invalid, pass through if absent) so
  `tenantcheck` works for token-bearing dashboard calls while tokenless
  `/posture/*` calls from reporting keep working.
- Check before tightening auth: who calls the endpoint? `grep <SVC>_URL`.
  Shared crypto/report routes have tokenless internal callers; feature routes
  are dashboard-only and safe to require auth on. Health probes use the gRPC
  port (18xxx), so requiring auth on the HTTP handler never breaks healthchecks.

### A tab showing "No keys found" while Key Management has keys = wrong list call
The Key Verification tab raw-fetched `/svc/keycore/keys`, read `d.keys`, and
searched/displayed `label`. But the keys endpoint needs `?tenant_id=` and
returns `{items: [...]}`, and keys have **`name`**, not `label`. Result: no
keys (or none matching a name search). Fix: use the same typed `listKeys(session)`
lib that Key Management uses, and search on `id`+`name`. Lesson: per-tab raw
fetches drift from the canonical client — reuse `lib/keycore` so every view
sees the same data.

### Key attestation (signed, offline-verifiable)
Added `POST /keys/{id}/attest`: builds a canonical statement (key identity,
properties, exportability, KCV, and a live integrity result) and signs it with
an ECDSA P-256 attestation key; `GET /attestation/public-key` publishes the
verifying key. Notes:
- **Central crypto only:** keycore must not import `crypto/ecdsa` directly
  (the `make conformance` central-crypto rule). Use `pkg/crypto`'s
  `GenerateKeyPair`/`Sign`/`MarshalPublicKeyPEM`/`ParsePrivateKeyPEM`.
- Signing key loads from `KEYCORE_ATTESTATION_PRIVATE_KEY_PEM/_B64` for a
  stable identity across restarts; falls back to an ephemeral key (logged) so
  the feature works out of the box. The pubkey endpoint always reflects the
  active key, so attestations verify for the key's lifetime.
- Statement is marshalled deterministically and the **exact signed bytes** are
  returned (`statement_b64`) so a relying party verifies the signature without
  re-serialising. Tested: signature verifies; a tampered statement does not.

## 2026-06-15

### Auto-generated "advanced feature" tabs were mostly decorative — keep only what's enforced
The "20 advanced features" batch (migration 012) produced several tabs that
looked functional but didn't actually do anything on real keys. Audit each
against "is it enforced / does it solve a real problem?" before trusting it:
- **Key Binding** (TPM PCR / region / IP-CIDR): config was stored in
  `key_binding_configs` but **never read at crypto time** — no enforcement
  anywhere outside its own CRUD. Decorative. Removed.
- **Key Metadata Extension**: duplicated fields the key already carries
  (`owner`, `tags`, `labels`, `compliance`) in a parallel `key_metadata_ext`
  table. Redundant. Removed.
- **Key Verification**: the handler hard-coded `"verified": true` and
  fingerprinted the *encrypted* material (meaningless — ciphertext changes on
  re-wrap). It never proved anything.
- **Decision:** merge to the one genuinely strong capability — real key
  integrity verification — and delete the rest (frontend tabs + libs, backend
  handlers/routes/store methods/types, and a migration dropping the tables).

### Real key-integrity verification
A meaningful integrity check decrypts the current version's material under the
MEK (an AES-GCM auth-tag failure = corruption / tampering / wrong-or-rotated
MEK) and, for keys with a KCV, recomputes the KCV from the live material and
constant-time compares it to the recorded value. Gotcha: the **authoritative
KCV lives on the key _version_** (`key_versions.kcv`), not the `keys` row — the
key row's `kcv` is a denormalised copy only updated on rotation, so it can be
empty on first create. Compare against `version.KCV` (fall back to `key.KCV`).
Reuse `decryptMaterial` + `computeKCVStrict` so the check matches creation
exactly. The old placeholder could never fail; the real one can and does
(tested by corrupting `key_versions.encrypted_material`).

### Removing a feature is a full-stack sweep
Per feature: frontend tab + lib + shell wiring (lazy import, component map,
TITLES, nav) + `moduleRegistry` gate; backend routes + handlers + `Store`
interface methods + SQLStore impls + types; a migration to drop the table; and
the **generated REST catalog** (`restApiCatalog.generated.ts`) which the
`build` script regenerates via `generate:rest-catalog` — so a plain
`npm run build` drops stale endpoints automatically.

## 2026-06-14

### "Create key failed: policy evaluator unavailable; fail-closed"
- **Cause:** keycore reads `POLICY_ENGINE_URL` to find the policy service. It was
  never set in `docker-compose.yml`, so keycore's policy evaluator fell back to
  the **deny-all** evaluator (because `KEYCORE_POLICY_FAIL_CLOSED` defaults true)
  and denied *every* key operation with this exact message.
- **Second layer:** the policy service requires a valid **Bearer JWT** on every
  request (`pkgjwtauth.MustWrap`), but keycore's `HTTPPolicyClient` only set
  `Content-Type` — so even with the URL set it would get `401` and still fail
  closed.
- **Fix:** set `POLICY_ENGINE_URL=http://policy:8040` in keycore's compose env,
  and make the policy client **forward the caller's bearer token** (and
  `X-Tenant-ID`). keycore already stashes the raw token in context as
  `rawBearerTokenCtxKey`; the client now reads it and sets `Authorization`.
- **Why forwarding works:** all services share the cluster-wide
  `JWT_PUBLIC_KEY_B64`, so a token signed by the auth service validates at the
  policy service unchanged. Service-to-service identity = propagate the caller's
  JWT, not a separate service token.
- **General principle:** fail-closed services turn *missing wiring* into a total
  outage, not a silent bypass. When "every operation is denied," suspect an
  unwired/unreachable dependency before suspecting data/permissions.

### Verifying auth paths without clobbering a user's credential
- To confirm keycore→policy auth, don't reset the admin password (the user may
  have already set their own). Any **valid JWT** satisfies the policy
  middleware, so log in as the bootstrap **cli-user** (password in `.env` as
  `AUTH_BOOTSTRAP_CLI_PASSWORD`) and call `/policy/evaluate` directly — a `200`
  with a `decision` proves the path; a `401` proves it's still broken.

### Default admin credential & forced first-login change
- Default is `admin`/`admin`, safe only because the seeded admin has
  `MustChangePassword=true` and login then issues a JWT **scoped to
  `auth.password.change`** — the default can do nothing but rotate itself.
- `bootstrapDefaultAdmin` is **one-shot / idempotent**: it never overwrites an
  existing user. On an upgraded deployment the old admin password persists and
  `admin`/`admin` is rejected. Recover with `AUTH_BOOTSTRAP_RESET_ADMIN=true`
  for one restart, then unset it (so a later restart can't clobber the rotated
  password). Keep `AUTH_BOOTSTRAP_FORCE_PASSWORD_CHANGE=true` in real envs.

### The dashboard is a build artifact — "I don't see it" usually means stale build
- Source changes (tab merges, the Threat & Exposure console, etc.) are **not
  live until the dashboard container is rebuilt and redeployed**:
  `docker compose up -d --build dashboard`. Then hard-refresh the browser
  (Cmd/Ctrl+Shift+R) to drop the cached bundle.
- Verify what's actually served by grepping the bundle inside the container
  (`/usr/share/nginx/html/assets/*.js`) for expected/removed label strings,
  rather than trusting the source tree.
- The dashboard auth path is controlled by `public/config/ui-auth.json`:
  `prefer_backend_auth` (use the real auth service) vs `allow_local_fallback`
  (local `ui-auth.json` credentials). Backend mode relies on the auth service's
  `must_change_password` response.

### Merging dashboard tabs
- A "merge" is a wrapper component with a segmented control that renders the
  existing child tabs as sub-views, plus cleanup of every reference:
  `VectaDashboardV3Shell.tsx` (lazy import, component map, TITLES, nav array),
  `config/moduleRegistry.ts` (feature gate), and the FeatureKey/TabId unions.
  Remove genuinely redundant tabs entirely (e.g. Shamir Key Recovery is
  subsumed by guardian-quorum Escrow); fold unique functionality, drop overlap
  (e.g. the `rotate` action left scheduled-jobs once rotation policies own it).
