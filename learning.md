# Learnings

Running log of non-obvious operational and architectural learnings for Vecta KMS.
Newest entries on top.

## 2026-10-24

### Each runtime has its own way of being old (13.55.0-beta)
- macOS's system Python 3.9 links LibreSSL 2.8, which has no TLS 1.3: it
  can't reach the KMS at all, and even setting the minimum version raises.
  The Python SDK refuses such a Python with a message saying why; its unit
  tests stub the SSL context, and the real-TLS contract runs where Python
  has OpenSSL 3 (CI, or a Linux container locally).
- Python 3.9's `fromisoformat` takes at most six fractional digits; the KMS
  sends nine. The first trim collected every digit after the dot, timezone
  included, and only 3.9 noticed. Testing on the oldest supported version
  found it.
- `node --test <directory>` fails on Node 24; name the file.

## 2026-10-23

### A local module replace reaches every Dockerfile (13.54.0-beta)
- The SDK is its own module so customers can fetch it, and the main module
  replaces it from `./sdk/go` so the platform's tests can run it against
  the real routes. Every service Dockerfile copies `go.mod` and `go.sum`
  and runs `go mod download` before copying the tree: without
  `sdk/go/go.mod` that fails ("reading sdk/go/go.mod: no such file"). All
  28 now copy it; a keycore image build proved it.
- `go test ./...` from the root doesn't enter a nested module; CI runs the
  SDK's tests as their own step.
- Reading the CI integration list for that step showed `services/certs`
  missing: its Postgres tests had never run in CI.

### Check what a token kind carries before keying a rule on it (13.53.0-beta)
- A client token sets `UserID` to the client's subject, not just
  `ClientID`. The first version of the client grant matcher treated "has a
  user ID" as "is a person" and would never have matched a client. The
  discriminator is `client_id`: person logins never set it; client and
  workload tokens always do.
- Giving machines roles reopened a door 13.48 had closed with
  permissions: a root-tenant client granted `*` would have passed the
  platform-administrator checks. Those checks now also require no
  `client_id`.
- KeysTab and RestAPITab may not grow (`component-size-burndown.json`). New
  UI goes in its own module, and `--tighten` lowers the ceilings of files
  that shrank.

### An offline device needs keys it can prove, not a promise (13.52.0-beta)
- An edge lease puts a data key on a device that may never call back. The
  KMS can bound it (lease length, revocation at next contact, keys checked
  as the administrator who allowed them) and can make what the device
  reports verifiable (signed, numbered receipts that show gaps), but it
  can't prove the device reported everything. The docs say so.
- `crypto/ecdsa` is banned in services, so the service can't type-check a
  device's public key. A signature with it over the token proves the key
  type and possession at once, and is what enrolment asks for.
- The tables were first named `edge_devices`, `edge_leases`,
  `edge_receipts`. `TestCatalogHasNoStaleOrDuplicateEntries` caught that
  keycore once had an `edge_devices` (migration 012) that its migration 013
  drops: on a fresh install where ekm migrates first, keycore would have
  dropped ekm's table. A service's new table carries its prefix
  (`ekm_edge_*`).
- A receipt batch moves the device's sequence only from the number it was
  checked against (`WHERE last_receipt_seq = $from`), so two batches racing
  can't both be stored; the Postgres test runs the race.

### Find what the request really carries before naming a condition (13.51.0-beta)
- keycore sets every HTTP caller's interface to `rest`: KMIP, EKM and the
  other front-ends reach it as verified service identities, and a header
  can't move a request to another interface. A binding on "interface" would
  have matched nothing. The channel is the verified service identity (or
  the delegating service), which is what a request actually proves.
- Service principals skip key grants. A binding that let them skip it too
  would bind nothing a platform service touches, so bindings are checked
  before that shortcut.
- The replication catalogue keeps `key_binding_configs`, though
  migration 016 dropped it: `TestEveryTableIsClassified` reads every
  migration, so a table any migration creates stays classified. I removed
  it as stale and the test failed; it is back, next to the new table.

### Retiring a preview is more than deleting its catalogue entry (13.50.0-beta)
- The generic `/enterprise/controls` route stores any category name. With
  `metadata_profile` simply removed from the preview catalogue, a record
  of that category would have been stored again and shown as available.
  A retired category now has its own status: writes are refused with
  `feature_retired`, old records read as `retired`.
- keycore's legacy route wrapper writes straight to the response, so the
  kernel can't record a reason for a refusal it makes. A refusal that must
  be audited with a reason goes in a kernel-level wrapper in front of it.
- In keycore tests the full handler drops kernel events (no audit
  client); assert them on the router built with a routetest recorder.

### Test a protocol format with the protocol's own tool (13.49.0-beta)
- The KRL is a binary format written by hand from `PROTOCOL.krl`. A Go
  round trip would only prove the writer agrees with itself; the test
  runs `ssh-keygen -Q` against it and `ssh-keygen -L` against the
  certificates, so OpenSSH says whether a server would honour them.
- A new kind of sealed key must join the root wrapping key's rotation.
  SSH CA keys are sealed like X.509 CA keys, but rotation only walked
  `cert_cas`; without adding them, the first rotation would have left
  every SSH CA unable to sign. The rotation test now includes one.
- SQLite hands back a time it was given as Go's `String()` text, which
  the certs parser didn't accept, so the revocation time read as empty.

### A rule found in one place is usually broken in others (13.48.0-beta)
- The governance role-name check was the one noted, but a search for
  comparisons against "admin" role names found the same pattern in keycore
  (key access without grants) and auth (five CLI routes). Each was its own
  copy of "admin means the role is called admin".
- The fix broke tests, not users: test tokens had a role name and no
  permissions, which no real token has (the built-in admin roles hold
  `*`). The fixtures now carry the permissions a real token would.
- Each fix has a test that fails on the old code: a role name alone,
  without the permission, is refused.

## 2026-10-22

### A live test proves only the client it uses (13.47.0-beta)
- The opt-in test against a real time-stamp authority passed, but it
  built its own HTTP client. Production goes through `pkg/ssrfguard`
  (TLS 1.3 only, public addresses only), which no test had exercised
  against a real authority. The live test now uses the production client,
  with `ssrfguard.UseSystemResolverForTests` (the guard refuses real DNS in
  tests otherwise, which is what a quick throwaway test first ran into).
- That matters in practice: Sectigo's public authority offers only
  TLS 1.2, so the platform refuses it, while FreeTSA, Microsoft and
  SwissSign accept TLS 1.3. The error now says why ("unreachable: …")
  instead of only "unreachable".
- An event the audit service writes straight into its chain never reaches
  the stream, so no playbook sees it. A trigger on an event audit raises
  itself needs the publish-then-record path (`reportOnStream`), and a test
  with the loopback publisher.
- Each Credentials type needs an answer for "Test". A type tested by the
  service that uses it refuses there with `connection_test_elsewhere`;
  otherwise the button records a false failure.

### A refusal a library makes for us is invisible unless we record why (13.46.0-beta)
- Go 1.27.3 refuses chains through the compromised eMudhra intermediates,
  but its error is the generic "certificate signed by unknown authority".
  Discovery stored only `chain_trusted: false`, so nobody could tell which
  certificates were affected or why, and certificates scanned earlier kept
  their old "trusted" result. Discovery now keeps the presented chain and
  the verification error, and matches distrusted keys when read.
- The platform's list is a copy of the toolchain's. A test reads the
  toolchain's own source and fails when the copy drifts, so a Go update
  that distrusts another CA can't pass unnoticed.
- Seven CHANGELOG sections had lost their headings (13.22-13.25 and
  13.42-13.44, the last three mine): a script inserted a new section by
  replacing the next one's heading instead of adding before it, and the
  docs gate only checked that the new heading existed.
  `scripts/check-docs.sh` now fails on a section left with only its date.
- The two small CI fixes (13.44, 13.45) were pushed after vet, tests and
  the docs gate, without conformance, and 13.44 left `docs/generated`
  stale. A fix of a red run goes through the same checks as any change,
  conformance included.

### The rule was written down and still missed (13.45.0-beta)
- CLAUDE.md already says a value compared with a stored time is truncated
  to microseconds. The schedule test broke it and passed on macOS, whose
  clock gives microseconds, then failed on CI's Linux, whose clock gives
  nanoseconds. It was proven by adding 123 ns to the test clock on the Mac,
  which fails at the same line CI did. A Postgres test that compares times
  is checked against that rule before it ships, not after CI reads it.

### A shared database showed a bug the clean one hid (13.44.0-beta)
- CI's integration job runs every package against one Postgres database.
  Another package leaves an enabled HSM profile for `root`, so the backup
  schedule test, which assumed `root` had none, failed there and passed on
  a fresh local database. Reproducing CI's state (that row) also showed a
  real fault: a recipient-sealed schedule on a tenant with an HSM failed on
  every run, because backups bind to the HSM by default.
  **A Postgres test that depends on what a tenant lacks uses a tenant of
  its own; and a feature is tried with the platform's optional pieces
  present, not only absent.**

### An unattended job must say where a secret goes (13.43.0-beta)
- A governance backup with `bind_to_hsm` and no enabled HSM quietly becomes
  a software-mode backup, whose key is returned once, to the caller. A
  schedule calling the same function would have taken backups whose only
  key went nowhere. The schedule now states its key protection, and the
  HSM path refuses (`RequireHSM`) instead of falling back.
  **Work that runs with nobody present never takes a path that hands a
  secret to a person: it names where the secret goes, and refuses when
  that place isn't there.**
- `pkg/crypto` already had a recipient seal (`SealToRecipient`, for
  attested key release). Its AES-GCM layer can't be opened with the openssl
  command line, the path a disaster recovery needs, so the backup reuses
  its key parser, fingerprint and RSA-OAEP wrap instead. Search
  `pkg/crypto` before adding a primitive.
- `gofmt -w` on a whole directory rewrites files the change never touched;
  format the files you edited.

### The audit trail's links were never tested end to end (13.42.0-beta)
- Building Investigate meant reading what the trail can actually link, on
  the live database. Four faults showed up, none of them caught by a test:
  - Verify Chain failed on Postgres for every event with an address
    (`/32`: `INET` read back as text), and the full walk had never passed.
    No Postgres chain test stored an address.
  - `session_id` was empty on all 32,827 events of the week: no token carried
    a session, so Forensics → Session could never return anything.
  - Logout was refused (the console sends no body; the handler required
    one), so sign-out ended nothing and was never audited. `auth_sessions` was
    written and never read.
  - Correlation IDs didn't cross services: the kernel read the header, but
    no client ever sent it.
- **A row's hash input is read in the form it was hashed in, and the
  Postgres test of a hash stores every field the hash covers.**
- **A field the audit trail records to link events (session, request) is
  tested from where it starts to the stored event in the next service**
  (`TestCorrelationFollowsTheRequestToTheNextService`,
  `TestSessionFollowsRefreshAndEndsAtSignOut`).
- docs/GOVERNANCE_AND_COMPLIANCE.md listed audit query parameters that
  don't exist (`min_risk_score`, `date_from`, `tag`, `has_approval`,
  `actor_type`, ...). They are corrected against `eventQueryFrom`. The
  DSAR walkthrough relied on `tag` and is rewritten.

### Dead code hid an unenforced control and a forgeable key (13.41.0-beta)
- `deadcode -test ./...` listed `IsIPAllowed` in auth: the only check of a
  REST client's `ip_whitelist`, which the REST API tab let an admin set.
  The setting was stored and displayed, and nothing read it. **A security
  check with no caller is a control that isn't enforced**: an unreachable
  check is a finding, not tidying. The rule "a setting has code that
  reads and applies it" existed; no tool found the setting that broke it.
- In dataprotect, reading the code around another unreachable helper found
  the wrapper token key fallback: HKDF over `tenant|wrapper|app`, used
  whenever an environment variable was unset, and no deployment set it.
  This is the same fault rule 6 was written for in 2026-09 (v1 working
  keys), in a second copy nobody searched for. **A fix of a key-derivation
  fault searches every `pkgcrypto.HKDFSHA256`/`Hash` call whose input is
  built from IDs**, not just the one reported.
- Two files nobody could account for were in the tree: a 27 MB Windows
  binary added by a `git add -A` after a local cross-build (13.33.0-beta),
  and a pg_dump of a development CA table from February under `backups/`.
  `git add -A` stages whatever a build or a dump left in the checkout;
  stage paths by name, and add build and dump outputs to `.gitignore` when
  they first appear.
- The gate now exists: `scripts/check-dead-code.sh` in CI. It skips
  `node_modules`: a dashboard dependency (flatted) ships Go sources, and
  `./...` reads them once `npm ci` has run.
- Not fixed here: a client's `rate_limit` is stored and never applied
  either. Enforcing it needs a limit shared by every service the token
  reaches, which is a design decision, not a cleanup.

### A file we ship is built the way the customer builds it (13.40.0-beta)
- The SDK's JCA provider pom named a Maven plugin
  (`net.nicholaswilliams…:maven-checksum-plugin:1.0.1`) that Maven Central
  doesn't have, so `mvn package`, the README's only build step, failed for
  every customer. The real-consumer test (`jca_consumer_test.go`) compiles
  the Java sources with `javac` and never runs Maven, and nothing else read
  the pom. **A build file we ship is exercised by its own tool in CI**
  (`mvn verify` step in ci-quality.yml).
- `GOOS=windows go build ./services/ekm-agent/...` with one main package
  writes `ekm-agent.exe` into the working directory, overwriting the
  tracked copy. Cross-build checks use `-o /dev/null`, or run in a scratch
  tree.
- One smoke spec (`rotation schedule is offered only to a caller who may
  set one`) timed out at 5 s while the three-mode FIPS suite was using
  the CPU. It passed alone and in a full re-run (121/121). It's recorded
  here, not fixed: if it fails in CI, its wait is the assumption to remove.
- The eMudhra intermediates are refused by Go's verifier itself (Go
  1.27.3), so the fix reached every chain the KMS checks with no product
  code. Only rebuilding the images puts it into the running binaries.

### A stream consumer's writes must survive a redelivery (13.39.0-beta)
- After a restart, NATS could not load the `audit-ingest` consumer: its
  `o.dat` was 24 zero bytes, a rewrite interrupted at 17:51:43 UTC with an
  empty `o.dat.tmp` beside it (`corrupt state file (10104)`). Audit exited
  on `subscribe failed`, and every service that depends on it stayed down.
  The stream itself (134,798 messages) was intact.
- The usual fix, deleting the consumer, would have replayed the whole
  stream into the chain: the ingest skipped an event it already had only
  when the event was a cluster relay carrying its id. Every other event got
  a random id at insert, so the same message delivered twice was two rows.
  The same was true of the ordinary case, a crash between the commit and
  the ack. **A consumer that writes a row per message keys the row on the
  message's identity**, here its stream position, so a redelivery finds
  what it wrote.
- The position was recovered exactly instead: the last row in Postgres
  matched stream sequence 134307 on action and timestamp to the
  microsecond, all 41 events from 17:40 up to it were stored, and a 16-byte
  state file acknowledging through 134307 made NATS deliver only the 722
  events after it.
- The playbook listener has the same consumer shape, but a replay can't
  re-run playbooks: events older than `maxTriggerAge` are refused as stale
  and audited, and fires have a cooldown.

## 2026-10-21

### Install it, don't just render it (13.38.0-beta)
- The chart linted and its manifests validated against the Kubernetes
  schema, and the node still could not start: Postgres admitted only the
  Docker network, kmip and Envoy both wanted port 5696 once they shared a
  pod, and keycore parsed the JWT key with its own copy of the parser that
  refused the certificate the shared one accepted. Each surfaced only on a
  real install (`scripts/test-helm-kind.sh`). **A deployment artifact is
  tested by deploying it.** Reading pg_hba.conf for the pod also showed that
  cluster members on other hosts were refused too: the join tests run on
  Postgres without the product's pg_hba.conf.
- **A second copy of a parser drifts**: fix the shared one, then
  `git grep` for the error message to find the copies.


### A control that changes a label is not failover (13.37.0-beta)
- Node Management had a Leader/Follower select whose Apply changed
  `cluster_nodes.role` and nothing else: no node stopped or started
  writing. It read as failover. Building the real thing also showed the
  primary had never recorded its own role, which the shared-append audit
  replication depended on. **Before building on cluster state, read where
  it is written, not only where it is read.**
- docs/INFRASTRUCTURE.md described Raft, witness nodes, consistency modes
  and cluster ports 5173-5175, none of which ever existed, with curl
  examples against the label route. The doc-route gate found it only when
  the route was removed. **A design doc written before the code is checked
  against the code when the feature lands, or it is deleted.**

### A lost election must not leave a trace that fences (13.37.0-beta)
- The first design raised a candidate's epoch when it stood. A member cut
  off alone would lose, keep the higher epoch, and fence the healthy primary
  with its next heartbeat. The epoch now changes only on a promotion; the
  vote table alone remembers the epochs a node stood or voted in. Caught by
  `TestPartitionedMemberCannotDisruptAHealthyPrimary`, written as an attack
  on the design before trusting it.

### Wait for the position the primary reports, not the one it applied (13.37.0-beta)
- For a switchover the member must hold the primary's last write. The
  replication origin's LSN is the last *applied* commit and stays behind
  `pg_current_wal_lsn()` forever when the tail of the WAL is other tables;
  `pg_stat_subscription.latest_end_lsn` follows the publisher's keepalives
  and reaches it. The three-Postgres test proved which one completes.


### Two bearer tokens on one service (13.36.0-beta)
- hyok's kernel wrapper parses every `Bearer` token as a Vecta JWT and marks
  a failure invalid, which XKS never hit (SigV4 isn't Bearer). OCI's
  identity domain token is Bearer, so every OCI call would have been a 401
  before its route verified it. The wrapper now leaves `/oci/` to its
  route, and the OCI tests run through `MountKernel`, not the handler.
  **When a second issuer's tokens share a scheme, the path decides which
  verifier owns them, and a test sends that issuer's token through the
  real middleware.**

### A caller's nonce is a request to reuse one (13.36.0-beta)
- The OCI vendor API lets the caller send an `iv` with encrypt. Honouring
  it would let any caller with a token pick a repeated GCM nonce under the
  customer's key. keycore draws every nonce; the answer carries it, and the
  audit event notes `caller_iv_replaced`. **Never take an AEAD nonce from
  the network.**


### Run the job, not the checks I remember (13.35.0-beta)
- Before pushing 13.33.0 I ran conformance, the tests and the dashboard
  steps, but not the backend job's first step (`check-runtimecfg.sh`), and
  CI went red on the new plugin; reading that job's steps for the fix also
  showed a stdlib advisory govulncheck had not reported a day earlier. **The
  pre-push list is the workflow's own steps, read from
  `.github/workflows/ci-quality.yml`, not a remembered subset.**

### A test server that accepts anything proves nothing (13.34.0-beta)
- The disposable Postgres used elsewhere runs with trust authentication,
  where any password logs in, so "the issued login works" would have passed
  with a wrong password. The database credential test runs on a server with
  a password (scram) and asserts that a wrong password is refused before it
  trusts the right one. **A test of a credential first proves the server
  checks it.**

### A shared client nobody had pointed at the real server (13.33.0-beta)
- `pkg/agentauth` had a JWT exchange whose request and response matched no
  route in auth, and a fallback that sent the API key on every request to
  services that ignore it. Both looked like working auth: no error, a header
  set. Found when the Kubernetes plugin needed the exchange. **A client
  for another service's route has one test against that route's real
  handler** (`TestAgentAuthExchangesAnAPIKeyWithTheRealHandler`), and **a
  credential fallback that no server accepts is an unauthenticated call**:
  fail instead.

### Playwright answers with the last matching route (13.33.0-beta)
- A catch-all `**/auth/**` stub registered after `**/svc/**` swallowed
  `/svc/auth/auth/clients`. Register catch-alls first, specific stubs last.

### A role name was still deciding access (13.32.0-beta)
- HYOK let anyone whose token said role "admin" or "super-admin" change
  endpoints; a role name grants nothing elsewhere since 13.14.0-beta, but
  this service was never checked for it. Found while adding a permission
  check for XKS credentials. **`grep -rn '"super-admin"\|Role ==' services`
  is part of reviewing any service's access code.**

### A middleware for one credential refuses another (13.32.0-beta)
- `jwtauth.MustWrapRouter` treats any Authorization header as a bearer
  token and marks a parse failure invalid, so an AWS SigV4 header would
  have been refused before the XKS route verified it. hyok's kernel wrapper
  parses only `Bearer` and leaves other schemes to the route that owns
  them. **A route with its own credential is tested through the service's
  real middleware chain, not by calling the handler.**

### The spec's vector, and the SDK as the client (13.32.0-beta)
- The XKS integrity value is checked against the spec's Appendix C bytes,
  and SigV4 against requests signed by the AWS SDK's own signer, which
  signs `content-length` (kept outside Go's header map) — a hand-written
  signer would have shared the verifier's blind spot.

### Rendering every view found what per-page tests missed (13.31.0-beta)
- Two pages crashed and one threw when a service answered with an empty
  object or a 503. Each page had smoke tests, all of them with well-formed
  stubs. A loader that returns a response without its list hands the page
  `undefined`. **A client function checks the shape it returns and fails
  like a network error; every view is opened against empty and failing
  services** (`tests/no-crash.spec.ts`, which reads the view list from the
  navigation, so a new view is covered without being listed).
- The rule "hue marks only attention" was written down, but the shared
  tile coloured its icon by whatever `c` a caller passed (30 blue, 18
  green, 5 purple), and six pages had their own coloured tiles. A rule that
  depends on every caller choosing the right argument isn't enforced; the
  primitive now decides.

### A feature named for a protocol it didn't speak (13.30.0-beta)
- "Azure EKM" created keys in Azure and called it an import; the Vecta key
  in each mapping was never read, and the Managed HSM path sent empty key
  material. Nothing tested the import against what Azure received. Asked
  to move it under HYOK, reading the code showed it wasn't HYOK at all.
  **Before moving or relabelling a feature, trace what it sends; a label
  is a claim.** The rebuild is tested over real mutual TLS, and the wire
  value is opened directly with the key the KMS holds.

### Three faults the old tests hid (13.30.0-beta)
- HYOK's keycore double returned `public_key_pem` on `GET /keys/{id}`,
  which keycore never does, so DKE public-key reads passed in tests and
  failed for real. The double now answers only what the route returns.
- Google CSE events went to `google_cse.*`, a subject outside `audit.>`:
  every Workspace key unwrap was unaudited. A test now reads the subject
  on the stream. **An audit event's subject starts with `audit.`.**
- The console's HYOK client mapped any protocol it didn't know to
  `generic`, so saving the ServiceNow card replaced the Generic endpoint.
  **A client never turns an unknown name into a default; it fails.**

## 2026-10-20

### A request log is a copy of the request (13.29.0-beta)
- HYOK logged `mustJSON(req)` and `mustJSON(resp)` for every call. For a
  key-wrapping proxy the request *is* a key and the unwrap response *is*
  the key, so the log was a second, unsealed key store, shown in the
  console. Found while reading the path for Azure EKM, not by a check.
  **A log or history of a crypto call names its sizes and outcome, never
  the bytes in or out;** `TestRequestLogHoldsNoKeyBytes` reads the stored
  rows after a wrap and unwrap.

### A second copy of the deployment showed a module that wasn't there (13.28.0-beta)
- The Cluster page answered 503 on every load. cluster-manager wasn't
  running because `infra/deployment/deployment.yaml` says `clustering:
  false`, but the console read its own `public/config/deployment.yaml`,
  baked into the image with every feature on, and fell back to a hard-coded
  all-on list when even that failed. The baked copy also invented a
  `key_analytics` feature no deployment file had. **The console's feature
  set is the stack's deployment file, mounted into the container; an
  unreadable file is unknown, never "everything on".** The test reads the
  compose mount and the absence of a copy.
- Fixing the file wasn't enough: the smoke test written for it still showed
  Cluster, because `canAccessModule` let a platform administrator skip the
  feature check ("sees full platform module set"). A permission decides who
  sees a deployed module; it never makes an undeployed service appear.
- The page toasted its load error on every ten-second poll. A load failure
  is page state shown once with a retry, not a toast per poll.

### A choice list is a claim (13.27.0-beta)
- Administration's trigger checklist named twelve-odd actions; a scan of
  the Go code found almost none sent for approval. The replacement list was
  built by tracing every `CreateApprovalRequest` / `ensureApproval` caller,
  and a test reads the Go source for each entry. **A list of options in a
  form is proven against the code that acts on it, or it is a free-text
  field.**
- Tracing showed the matching is narrower than the guide said: triggers
  decide only when the caller names no policy, and a named policy is used
  even when inactive. The guide had also invented quorum modes and weights.
  Area documents are checked against the code when a feature they describe
  is touched.

### Two editors for one record drift apart (13.26.0-beta)
- Approval policies had an editor in Approvals and one in Administration.
  Merging them showed each had bugs the other did not: Approvals forced
  `status: active` on every save, listed only active policies, and its
  channel checkboxes could only add; Administration's enable toggle sent
  only `status` to an endpoint that replaces the whole policy, offered a
  "hold" box nothing read, and a trigger list mostly unknown to any service.
  `// @ts-nocheck` on the Approvals file hid the checkbox bug: the handler
  read a click event as a boolean. **Moving code out of a `@ts-nocheck`
  file into a typed one is a review: read every error it raises.**
- An update endpoint that replaces the record (PUT) is never sent a partial
  body; a toggle sends the whole record with one field changed.

### A search is a list with a filter, so it inherits the list's faults (13.25.0-beta)
- Planning search over keys found the Keys page itself loaded the first
  100 keys at sign-in (a separate call from 13.24.0-beta's), and a failure
  of an unrelated call in the same `Promise.all` left it saying "No keys
  yet". **A page's main list has its own error, never shared with
  side calls in one `Promise.all`.**
- Search was put on the services, not on lists the browser holds, so it
  covers the whole set and the same access scope as the list it filters.
  Each search is tested with a restricted user and with `%` / `_` in the
  text, on Postgres for the SQL one.

### A bug fixed in one place, and sixteen more copies (13.24.0-beta)
- 13.21.0-beta found the certificate store answering 5000-row requests with
  100 and fixed certs. Planning a key search showed keycore did the same,
  and a scan for the pattern found seventeen calls in nine services,
  including compromise-advisory ingest. The first fix added a test for one
  package; the class was in every store copied from the same template.
  **Rule (CLAUDE.md): a fault found once is searched for everywhere, and
  the check that finds it runs in conformance (`list-cap`).**
- The first version of the check matched same-named functions and took the
  largest maximum, so HTTP clients with their own generous clamp hid the
  store's 500 and the check passed on broken code. It was run against the
  unfixed tree before trusting it: a check is proven by failing on the bug
  it targets.
- Counting a 24-hour window by listing rows and counting in Go caps the
  count at the list's size. Counts are a `GROUP BY ... COUNT(*)` in the
  database, tested on Postgres with more rows than one page.
- I ran `git stash` in a worktree by mistake (CLAUDE.md forbids it). The
  stash list is shared with the main checkout, which held an older stash;
  mine was popped by its index after checking which entry it was. Compare
  trees with a throwaway `git worktree` instead.

## 2026-10-18

### A simpler sidebar breaks every test that clicks by name (13.23.0-beta)
- Starting groups collapsed failed 88 of 95 browser tests: specs open a
  module by clicking its name, and a collapsed group renders no names. The
  specs now start with every group open through Playwright's
  `storageState`, and one spec checks the real default with an empty
  state. A change to what the shell shows by default is tested once for
  the default and once for the behaviour the other specs rely on.
- Moving a page's tab strip into the sidebar gives its sections new names
  in the sidebar, which can collide with buttons inside the page
  (Administration → Backup and Tenant Administration's own Backup tab).
  Tests scope such clicks to `main`.
- Links between pages now carry a sub-option ("admin/users");
  `tests/unit/navTargets.test.ts` checks both parts against `NAV` and
  `SUB_PANES`, recommendation actions included.

### A vendor schedule inside an issuance path (13.22.0-beta)
- The certificate lifetime policy shortened certificates on dates a
  standards body chose, and warned every tenant at a preset 47 days without
  anyone choosing it. The directive "the customer decides what to migrate
  and when" was read as being about algorithms, and certificates were never
  checked against it. It surfaced only by searching the served dashboard
  for the citations removed in 13.19.0-beta. **Rule: after removing a
  class of content, search the built product for it, not only the files
  changed.**
- Three audit events and the whole feature were in no document, and a
  "renew before" field was saved and shown but read by nothing. Removing a
  rule is a moment to read the feature end to end.
### Three numbers for one quantity, and a cap nobody saw (13.21.0-beta)
- Command Center, Operations and Certificates each fetched a certificate
  list and counted "expiring" themselves, with different filters, over a
  list capped at 500: 49, 500 and 723 for the same tenant. Each page's
  tests passed because each checked its own arithmetic, never that the
  pages agreed. **Rule (CLAUDE.md): a number on a page is counted by its
  service over the whole set.**
- Following the count to the store showed `ListCertificates` turns any
  request above 500 rows into 100 rows, silently. Five callers asked for
  1000 to 10000; the expiry sweep, renewal intelligence and internal
  certificate supersession had only ever seen the newest 100. A clamp that
  returns less than asked, without an error, looks like a complete answer.
  The cap now has a test that reads every call site.
- The console's "System Admin" was "signed in to the root tenant", not the
  server's rule (root and `auth.tenant.*`). The bootstrap CLI account, with
  one permission, was shown every module and pages of refusals; the live
  check signs in as that account, so this was in every screenshot and
  read as "the console is complicated". **A UI rule that mirrors a server
  rule is written from the server's code, not from the role's name.**
- The page-height measurement I first reported (Certificates 45,000 px)
  was an inner scroll box's height, not the page's. Measure the document,
  not the tallest element, before calling a page too long.

### A check that grew with the log, and a buffer that forgot its key (13.20.0-beta)
- The chain verification walked every row on each request. It passed every
  test (a few rows) and every deploy until the log reached about 78,000
  rows, then timed out in the live check. Its run time had been creeping up
  in the edge log (15, 17, 19 seconds) for days; nothing watched it. **Rule:
  a check whose cost grows with stored data has a bounded request form and
  a scheduled full form, and reports which ran.**
- The quick walk first compared the signed row's stored hash with the
  signature and not with the row's own content, so an edit to that one row
  would have passed. Writing the test case list ("the signed row's
  content") found it before shipping.
- The write-ahead buffer's key came from an environment variable no
  installer set, through a helper whose name (`LoadKey32`) did not say it
  makes a random key when the variable is missing. Recorded as open on
  2026-09-28; nothing tracked it. The buffer file also sat outside the
  volume. **Rule: a key that must verify data later is never a fallback; a
  helper that can return a random key is removed, not reused.**
### A rule followed everywhere but the home page (13.19.0-beta)
- "The customer decides what to migrate and when" (2026-09-29) was applied
  to Crypto Agility, the CBOM and keycore, but the Command Center kept its
  own algorithm regexes, a "deprecated after 2030" sentence and a list of
  standards per recommendation. The rule named the API and UI, but every
  check for it looked at the services; the dashboard's recommendation
  engine was a second algorithm list nobody tied to the catalogue.
- **Rule: a page that judges an algorithm reads the catalogue's facts from
  a service; it never matches the name itself.** A unit test now scans the
  engine and the Command Center for citations, deadline years and
  algorithm patterns.
- The rule catalogue in the document had drifted from the code (a rule that
  never existed). A document's table of rules is checked against the code
  when the rules change, not copied forward.

## 2026-10-17

### Lessons that stayed in learning.md (13.18.0-beta)
- learning.md held 197 "Rule:" lines; most were in no rule file, so a new
  session did not read them. The open item in one of them (the audit WAL
  HMAC key, 2026-09-28) sat for three weeks because a learning has no
  owner. **Rule: a lesson that applies to later work is added to CLAUDE.md
  in the same commit, and an open item it names goes in the "Still open"
  list of its `docs/SECURITY/` or area page**, where it is seen and tracked.
- A rule copied into CLAUDE.md is checked against the code before it is
  copied: the redirect rule's examples differed (one client refuses
  redirects, one does not follow them, one follows and drops the header).

### A gate that never ran (13.17.0-beta)
- The owner noticed before any check did: thirteen changes since
  2026-10-11 carried a CHANGELOG and learning entry and no other document.
  The docs gate existed, but its CI job had `if: github.event_name ==
  'pull_request'`, and every change goes straight to `main`, so it showed
  as "skipped" in every run, which reads like "nothing to check". Locally
  it passed on CHANGELOG.md alone.
- **Rule: when the way work flows changes (here, main only with no pull
  requests), check that every gate's trigger still fires on it.** A
  "skipped" job in `ci-status.sh` output is a question to answer, not a
  pass.
- **Rule: a learning entry is not the documentation.** It records why
  something went wrong; the operations guide, the testing rules and the
  security docs are where the next reader looks for how it works now.

### A learning nobody is bound by (13.16.0-beta)
- 13.14.0 and 13.15.0 recorded their lessons in learning.md and the
  decision log, but not in CLAUDE.md or the security index, and the owner
  asked whether any of it had been added. learning.md explains; CLAUDE.md
  binds. **Rule: a fix whose lesson is a rule for future changes adds that
  rule to CLAUDE.md, and a security fix adds to its `docs/SECURITY/` page,
  in the same commit as the fix.**

### A refusal audited as success (13.15.0-beta)
- auth's legacy `publishAudit` nests the outcome in `data`; the audit
  service only read the envelope's `result` and defaulted it to `success`.
  The tests asserted the published payload, never the stored row, so every
  legacy refusal looked audited and was filed as a success. Seen only by
  querying the live `audit_events` after a deploy. **Rule: an audit test of
  a new event checks the row as stored (result, actor) at least once, and
  the ingest normalises both envelope shapes.**

### "All broken": tenant and user management (13.14.0-beta)
- **`*` is not "everything everywhere".** A tenant's own administrator
  holds `*` inside that tenant, and three checks read it as more: auth's
  cross-tenant check (any tenant's admin could administer every tenant and
  reset root's password), the console's module-deny rule (`*` matched
  `ui.module.deny:<tab>`, so a non-root admin saw no modules), and a role
  name (`super-admin`) that any tenant admin could assign. **Rule: a grant
  that crosses tenants is tied to the verified token's tenant
  (`platformAdministrator`), and a deny rule matches only when granted by
  name.**
- **A client list of server values drifts.** The console's role list
  (`viewer`, `operator`, ...) and status list (`disabled`) matched nothing
  auth stores, so new users could not sign in and existing ones were shown
  with another role; the admin guide had the same invented roles. **Rule: a
  selector of server values is loaded from the server** (`GET
  /auth/roles`), the server refuses values it doesn't define, and a stored
  value outside the list is shown as it is, never replaced by the first
  option.
- **A form that sends back what it loaded fails against a strict
  decoder.** Policy and HSM saves spread the loaded record (with
  `tenant_id`, `updated_at`) into the request, and auth's
  `DisallowUnknownFields` refused every save. No test had ever saved. The
  client now sends only the route's fields, and the smoke spec asserts the
  exact keys sent.
- **A per-tenant view built by swapping `X-Tenant-ID`.** Tenant
  Administration made a copy of the session with another `tenantId` and
  called tenant-scoped routes with it; auth ignored the header and used the
  token's tenant (wrong tenant changed), governance refused it. A view of
  another tenant names it in the query, on routes that admit a platform
  administrator.
- How it slipped through: no test drove these screens or wrote through
  them; the tenant tests used a `super-admin` token in a non-root tenant,
  which was itself the bad case.

### A column name read as an error (13.13.0-beta)
- The sweep greps logs for words like "error". Postgres's slow-query log
  prints each statement in full on tab-indented lines, and the audit read
  selects `error_message`, so a few slow reads made a "repeating error".
  **Rule: a log scan matches the line that states the event, not text that
  continues it.**

### A popover that only its own button closes (13.12.0-beta)
- The ⓘ build popover, the timezone menu and the SBOM Export menu were each
  a `useState(false)` flag and an absolutely positioned `<div>`, so nothing
  but the trigger closed them. The shared `Select` already closed on an
  outside press and Escape, but that logic lived inside it, so hand-made
  menus never got it. **Rule: a floating panel takes its state from
  `usePopover`**; `tests/unit/popoversClose.test.ts` finds the old pattern.

### Test state that outlives the test (13.11.0-beta)
- Three times now a test met leftovers of an earlier run on something that
  lives for the whole process: a SQL driver name, HSM key labels in the
  certificate tests, and key labels on the connector's own tokens. The fix
  that holds is to start each test from a clean resource (here: empty
  tokens), not to make every name unique by hand.
- **A repeat check that skips the tests it should repeat proves nothing.**
  CI's run-twice step had no SoftHSM, so the very tests that could not run
  twice were skipped there. It installs SoftHSM now.

### What the annotation said (13.10.0-beta)
- The first readable failure of the no-network step was not a test at all:
  `mkdir .../golang.org/fips140: read-only file system`. Go unpacks the
  certified module the first time something is built with `GOFIPS140`, and
  this Mac's cache had it from earlier builds. **Rule: reproduce a CI step
  from CI's starting state (an empty cache), not from a warm laptop.**

### A new check must report the way the old ones do (13.9.0-beta)
- The no-network step was added on the day the rule "a failing test names
  itself" was written, and did not follow it: it called `go test` inside a
  container instead of the wrapper. It failed on its first CI run with
  nothing to read. **Rule: every step that runs tests goes through
  `scripts/ci-go-test.sh`, also inside a container.**


### Hunting a failure that would not happen again (13.8.0-beta)
- **Repeating did not find it; changing the conditions did.** Twenty-odd
  full runs on Linux, with two CPUs and with one, passed. What found causes
  was running the suite *differently*: under the race detector (two data
  races), with the network switched off (one test that needed DNS), and
  twice in one process (two tests that could not be repeated). **Rule: a
  flaky test is found by removing an assumption, not by rolling the dice
  again.**
- **A test that needs DNS is a flaky test.** It registered a connection for
  a real AWS host name and expected success. The guard resolves names; on
  a CI runner, now and then, resolution fails. Inside a test binary the
  guard now refuses real DNS unless the test answered the name or is about
  the real network (`testing.Testing()`), and CI runs the whole suite with
  no network.
- **A library's bug reached the product through its tests.** The KMIP
  rejection test showed a data race inside the kmip-go client. Reading it
  showed the client can panic when a server hangs up, and that the same
  client validates customers' KMIP servers. A test that only checked "an
  error came back" passed either way. Catching the panic would have left
  the race; the check now does its one request at a time on one goroutine,
  and the race detector is clean.
- **A test written to prove one fix found two worse faults.** A test that
  the interop check reports success against our own KMIP server failed
  with EOF: the check had not spoken TLS since the client library was
  upgraded (a custom dialer now means "do your own TLS"), and its verdict
  was set in a `defer` after an unnamed result had been returned, so it was
  always "not verified". **Rule: a feature with no test of its success
  path has not been shown to succeed.** Nobody had ever seen this check
  pass.
- **A test double that resets per test, beside a resource that lives per
  process, collides on the second run.** The HSM CA tests numbered keys per
  test on a SoftHSM token shared by the whole process.

## 2026-10-13

### The first green run, and what it does not show (13.7.0-beta)
- Run 38299770169 on `36ee776b5` is the first of 277 to pass.
- The run before it failed one job of three on code that then passed
  unchanged, and that five local runs passed too. **A test suite that
  passes most of the time has a fault in it; green is not the end of the
  work.** The fault is unnamed because the job could not say which test
  failed; it can now.
- **A helper must fit the limit of what it calls.** `ci-status.sh --wait`
  made about five API calls every 30 seconds against an allowance of 60 an
  hour, and spent it in six minutes. The verdict arrived only because the
  allowance reset while it was still waiting.


### A red job that cannot say why (13.6.0-beta)
- With the install fixed, one test job of three failed and the other two
  passed on the same commit: a test that fails sometimes, or only in that
  mode on that machine. The job's log needs a login; the public API gave
  the step name and "exit code 1". Two local Linux runs of the same mode
  passed, so there was nothing to go on.
- **Rule: a check that can fail must say what failed, somewhere the people
  fixing it can read.** GitHub shows a job's annotations to anyone; the
  test steps now write one per failing test (`scripts/ci-go-test.sh`).


### "It works in my container" was run as root (13.5.0-beta)
- The SoftHSM install script passed every local run and failed on its
  first run in CI. The container ran it as root; a GitHub runner is an
  ordinary user with `sudo`. SoftHSM's build defaults its configuration
  directory to `/etc` and its state to `/var` whatever the prefix, and the
  script used `sudo` only for a prefix it could not write.
- **Rule: reproduce CI as CI runs: the same user, not only the same
  operating system.** The check that found it is a container with an
  unprivileged user and passwordless `sudo`, which installs and then runs
  the HSM tests.
- **`scripts/ci-status.sh` earned its place the first time it was used.**
  The failure was visible two minutes after the push, with the step named.
  Without it this would have been one more "CI: can't see it from here".


### CI had failed 274 times out of 274 (13.4.0-beta)
- **How it stayed unseen.** The work is done from a terminal with no
  GitHub login, so "I can't see CI" was written at the end of report after
  report, and accepted. The repository is public: its Actions results are
  one unauthenticated API call away. **Rule: "I can't see it" is a claim to
  test, like any other.** `scripts/ci-status.sh` now prints the verdict;
  it is run after every push (CLAUDE.md).
- **A gate that always fails is the same as no gate, and worse: it hides
  the ones behind it.** The runtime-config gate failed from the day four
  services moved to `platform.Boot`. It was step 5 of 9 in its job, so
  conformance, `go vet`, the tests and the vulnerability scan never ran in
  CI. When it was fixed, the scan failed at once on a toolchain with 11
  advisories. **Rule: when a job is red, read which steps did not run.**
- **The gate matched words, not behaviour.** It looked for
  `ValidateServiceConfig(` in `main.go`. A service that validates inside
  the shared boot code failed it; a `func validateConfig` nobody called
  would have passed it. It now looks for a call (not a definition, not a
  comment) in the service's non-test files, and is shown to fail when the
  call is removed.
- **"Passes on my machine" was true and beside the point.** The HSM tests
  need SoftHSM, which this Mac does not have, so they skipped locally and
  every local run was green. The earlier Linux runs used a SoftHSM built
  from the head of its main branch and recorded it as "2.7.0", which is
  what that build calls itself. The 2.7.0 *release* cannot do RSA-OAEP with
  SHA-256 either: the support (SoftHSMv2 #833) came after it. **Rule: pin a
  dependency built from source by commit, and write the commit down, not
  the version string it prints.**
- **A skip is a pass.** `go test` reports a skipped test as ok. In CI a
  test that cannot run must fail: `VECTA_REQUIRE_SOFTHSM=1`, like
  `VECTA_REQUIRE_JDK` and `VECTA_REQUIRE_CERTIFIED_MODULE` before it. One
  test (`TestWatchSubjectsNATS`) had no job that gave it what it needs and
  ran nowhere.
- **A relocated build is not the same build.** `softhsm2-util` loads its
  library from the prefix it was compiled for. A copy restored to another
  path installs "successfully" and fails every test, so the install script
  records the prefix beside the commit and rebuilds when either differs.

### What an emulator did and did not tell us about BYOK (13.4.0-beta)
- **The first check by code we did not write.** Our AWS stand-in and the
  product share an author; if both misread the protocol, the tests agree.
  LocalStack's KMS is someone else's reading of it: it unwraps the import
  with its own RSA key and encrypts with the result. Import, use, rotation
  and revoke pass there.
- **It also showed where our stand-in was too kind.** After a revoke ours
  accepts any material back. LocalStack fails the restore, for a reason of
  its own (it treats every import as new material waiting for a rotation,
  whatever `ImportType` says), so that step is evidence of nothing either
  way and is left out in emulator mode, in so many words.
- **No test imported a private key into any cloud.** The engine has
  offered RSA and EC specs since 10.0.0-beta; every test used AES-256. The
  Azure path worked the first time it was tried, which is luck, not proof
  that it was tested.
- **A vendor limit found by reading, not running.** AWS allows 25
  on-demand rotations per key. A "rotate every 30 days" rule reaches it in
  about two years. Now in the BYOK document; the product does not yet warn.

## 2026-10-12

### A run against real clouds, and a claim that was not checked (13.3.0-beta)
- **"There is no test for X" is a claim like any other.** The 13.2.0-beta
  BYOK document said the console's Azure and Alibaba operations had no
  test against a stand-in. Both tests exist, in the file that holds those
  two stand-ins rather than in `console_test.go`, where I had looked.
  **Rule: before writing that a test is missing, search every test file
  for the function, not the file where it would be expected**
  (`grep -rn 'func Test' services/<svc>`).
- **The live sequence is tested where it is free.** A live check runs
  rarely and against accounts that cost money, so a mistake in its own
  order of steps would first show as a key left in somebody's account.
  `TestLiveFlowRunsOnTheDoubles` runs the same function on the AWS and
  Alibaba stand-ins in every test run, and checks the key ends pending
  deletion.
- **That found a stand-in unlike its cloud.** The Alibaba stand-in returned
  a ciphertext of the form `<key id>.<base64>`. Alibaba returns one base64
  blob, and the console checks that a ciphertext is base64 before sending
  it, so decrypting through the console failed on the stand-in and no test
  had tried it. The stand-in now returns one base64 blob. **Rule: a
  stand-in's outputs have the shape of the real service's, or the code that
  consumes them is not tested.**
- **A cleanup registered in the function under test runs after the
  caller's.** Go runs `t.Cleanup` functions last in, first out. A check
  that the key was scheduled for deletion, registered by the caller, ran
  before the deletion itself. The run now has a subtest of its own, and the
  caller looks once it has finished.
- **The wrong-credential step is the one part only a real cloud
  exercises.** The stand-ins do not verify request signatures. The altered
  credential keeps its length and alphabet so the request is well formed
  and only the cloud can tell it is wrong.


### BYOK console, key settings and automation (13.2.0-beta)
- **A create that verifies must fail when the verification fails.**
  `CreateBYOK` ran its steps, recorded the failed verify in the run, and
  returned `nil`. The route answered 201 and the audit event said success
  for a key that could not encrypt. Every other BYOK operation already
  returned the run's error; create was written first and never revisited.
  **Rule: a run with a failed step is a failed call, whichever step it
  was.** `TestConsoleGoogleCloud` and the Google lifecycle test now use the
  key after creating it.
- **Google Cloud does not make an imported version primary.** A new
  symmetric CryptoKey created for import has no primary version, and
  importing one does not set it. Encrypt then fails with "no primary
  version". The double accepted the import, so only a test that encrypts
  with the key finds this. **Rule: a protocol double proves the wire
  format; a test must still use what was made.**
- **The sweep announces, a playbook acts.** The automation sweep could have
  called rotate itself. It would then act on nobody's authority and need its
  own approval and failure handling. It emits
  `audit.cloud.byok_material_expiring` and `byok_rotation_due` instead, and
  a tenant playbook runs the action as the person who created it, with the
  permission check and approvals playbooks already have.
- **Once per piece of material.** The sweep runs every 15 minutes; without
  a mark it would announce the same expiry each time. The mark is the
  material ID and its expiry, stored on the key, so new material (or a new
  expiry) is announced afresh. It runs on the primary only, because the mark
  is replicated state.
- **A catalogue, not a command line.** The owner's reference console takes
  shell-like commands. Here an operation is a route with a permission and
  typed parameters, so what a role may do in a cloud is a permission, an
  audit record names the operation, and nothing a caller types is passed
  through. Generating a data key is left out: it would hand plaintext key
  material to the browser.
- **Three gates caught the dashboard code on the way in,** all added after
  it was written: a response body read with `.json()` (Go zero times), a
  paragraph of explanation on the page, and unformatted new Go files.


### Checking the other 159 API examples (13.1.0-beta)
- **A third of the unchecked examples were wrong.** 51 of 159 requests
  needed correcting before the service took them as written. The services decode
  strictly, so an extra field is a 400; a reader copying the example gets
  an error on the first try. Labelling them "not checked" in 12.3.0-beta
  was honest and still left them wrong.
- **The generator was a second catalogue.** `generate-rest-catalog.mjs`
  held 21 hand-written examples in `ENDPOINT_OVERRIDES`, outside the file
  the checks read. **Rule: a generator holds no content of its own;** they
  are in `restApiCatalog.ts` now.
- **A body the route never reads is also a wrong example.** Audit search
  takes its filters from the query and token refresh from the cookie; both
  examples showed a JSON body. Nothing refuses it, so only the static
  check (body fields must exist in the service's request types) finds this
  kind.
- **A response is taken from the service or not shown.** The helper writes
  each real answer out (`REST_EXAMPLES_OUT`), and the examples were filled
  from that file with token, key and certificate values replaced. Where a
  handler test cannot get an answer (KMIP client enrolment needs the certs
  service, a network scan needs a network, a vote needs a second person)
  the example shows the standard note, and the test accepts only that note
  on a call that fails.
- **Strict FIPS mode refuses some calls by design** (dataprotect without
  approved key material). The helper does not hold a refusal against the
  example in `only` mode; `off` and `on` still require the shown answer.
- **Order matters for examples that use each other's IDs.** The helper
  runs creates first, remembers the IDs they return and fills later paths
  and bodies with them; a service names its own first steps (`First`).


### A service with no token check, and two that never compared the tenant (13.0.0-beta)
- **How it was found.** Reviewing which body fields name a person, I asked
  the running stack, signed in as a user with one permission, for every
  dashboard route *for a tenant the user is not in*. 19 of 192 answered
  200. Then with no token: KMIP's four answered 200. Nothing in the test
  suite, conformance or the live check asked either question.
- **KMIP: nothing verified a token.** `services/kmip/main.go` passed its
  mux straight to the audit middleware. Every other service wraps its
  handler with `pkgjwtauth.MustWrap`. The handlers did call
  `tenantcheck.Enforce`, which is why it looked guarded when read.
- **`tenantcheck.Enforce` passes when the context has no claims.** It
  compares a tenant with a token; with no token there is nothing to compare
  and it returns nil. It is a tenant check, never an authentication check.
  **Rule: a guard that needs a precondition must fail without it, or its
  name must say what it doesn't do.** The kernel refuses in both cases; the
  legacy helper is left as it is for the thirteen files that still use it,
  each behind `MustWrap`.
- **Autokey: the guard existed and was never called.** `mustTenantChecked`
  was defined in the handler file and used by no handler. A grep for the
  function finds it and reads as "this service checks the tenant". **Rule:
  count a guard's callers, not its definition.**
- **Signing: the dangerous routes were guarded, so the rest looked done.**
  `bindTenant` covered sign and verify (added after an earlier finding).
  Settings, profiles, records and summary were never looked at again.
  **Rule: a fix to one route of a service is a reason to list every route
  of that service, not a reason to stop.**
- **What now fails if this returns.** Conformance `server-verifies-tokens`
  (a service starting an HTTP server with no verifier; the old KMIP has
  none). `scripts/live-check.py` asks every dashboard GET with no token and
  for another tenant; on 12.3.0-beta it prints the 18 faults. Per service,
  `routetest.RefusalsAudited`. The first is a presence check and proves
  little alone; the live check is the one that asks the real question.
- **`route.Legacy` moved 38 handlers behind the kernel without rewriting
  them.** The kernel resolves and checks the tenant (query, header and the
  body's top-level `tenant_id`), then the adapter writes it to
  `X-Tenant-ID`, where the old handlers already look. Each handler's
  tenant helper was reduced to read only that header. The handlers still
  emit their own domain events, so a call produces the kernel's event and
  the service's; the kernel's action names differ so nothing counts twice.

### Who asked (13.0.0-beta)
- **Forty body fields, three kinds.** A record of who did something
  (`updated_by`, `created_by`): falsifiable, and a key's creator has
  standing over the key. A requester that governance acts on: the named
  person is the one kept from approving, so naming somebody else let the
  real requester approve. And data that is not the caller at all (a key's
  `owner`, the actor of an ingested event), which stays and is listed with
  its reason in `scripts/body-named-people-allowlist.txt`.
- **The dashboard sent `session.username`; the token carries a user ID.**
  keycore matches a key's creator against the token's user ID, so a key
  created in the dashboard never matched its creator unless the two were
  equal. Binding the creator to the token fixes that as a side effect.
- **A scanner reading source with regular expressions needs the binding
  where it can see it.** Three handlers were already right but passed the
  verified value as an argument; they now assign the field first. One that
  binds in a helper is on the allowlist.

### The items I had listed as "found, not fixed" (12.3.0-beta)
- **A public key rotated alone was worse than one left behind.**
  `RotateKeyTo` called `generateMaterialForCreate(alg, key.KeyType)` for
  every software key. For a public component that generates a whole pair
  and keeps the public half: after "rotating" it, the stored public key
  belonged to no private key anywhere. I had reported only the milder half
  of this (the private key rotates, the public key stays). **Rule: when a
  record is derived from another, read what an operation does to the
  derived record on its own, not only to the source.**
- **Two writes that must agree go in one transaction.** The store's
  rotation was one transaction per key. The pair uses the same step twice
  inside one (`rotateVersionTx`), and the Postgres test forces the second
  insert to fail and checks the first rolled back. SQLite would have passed
  a version that committed them separately.
- **An example nobody runs is a guess.** The REST tab's keycore examples
  were written from what such an API usually looks like. keycore decodes
  with `DisallowUnknownFields`, so 15 of 21 were refused outright. Reading
  18 handlers to correct them by hand would have produced a second guess;
  sending each example to the real handler (`REST_EXAMPLES_DUMP=1 go test
  -run TestRESTExamplesMatchTheService -v`) printed what the service
  answers, and the examples were written from that. The same test now fails
  when one drifts.
- **Seventeen services still have unchecked examples.** They are labelled in
  the tab, and `restCatalog.test.ts` holds the list, which only shrinks.
  Labelling was chosen over deleting 137 entries or pretending they were
  checked.
- **A catalogue of services had three copies.** The REST playground's
  allowlist, the generator's directory names and the edge's route prefixes
  disagreed: the allowlist named `ai`, `qkd`, `qrng` and `mpc` (no such
  services) and the generator called the cluster service `cluster-manager`,
  a prefix the edge does not route. The allowlist is now the generator's
  output, and the generator knows the edge name.
- **Dead client code pointed at routes that never existed.** kmip's keycore
  client had `CreateKeyPair`, `HMAC`, `HMACVerify`, `DeriveKey` and
  `ExportKeyMaterial`, none called. The new test records every request the
  client makes and looks each up in `docs/generated/backend-routes.csv`; it
  also fails when a method is added without being exercised.
- **Another session fixed one of the faults I found while I was reading it**
  (the destroy handler taking the requester from the body, 12.1.0-beta).
  Fetching before starting each item, not only before pushing, would have
  saved the read.

### A backup that never restored, hidden by where its tests ran (12.2.0-beta)
- **Restore named every column, and one table computes a column itself.**
  `INSERT INTO t SELECT * FROM json_populate_recordset(NULL::t, …)` supplies
  a value for a `GENERATED ALWAYS` column, which Postgres refuses.
  `auth_users.username_lower` is one, since 2026-03. So for seven months no
  backup of a real database could be restored, and the product's own
  backup tests said otherwise.
- **How it slipped through: the tests pass alone.** Run by itself,
  governance's package migrates only governance's tables, and none has a
  generated column. The failure needs auth's tables in the same database,
  which is what a real stack has and what CI's `integration-postgres` job
  builds by running every package in turn in one database. CI can't be read
  from this machine (private repository, no `gh`), and the local habit was
  `go test -run Postgres ./services/<the one I touched>`. **Rule: run the
  CI step as CI runs it: one command, its package order, one fresh
  database.** A test of something that acts on "every table" must put a
  foreign table in front of it; `TestBackupRestoresGeneratedColumnsPostgres`
  makes its own.
- **A stand-in table left behind breaks the service that owns it.** Three
  governance tests ran `CREATE TABLE IF NOT EXISTS` for another service's
  table with only the columns they needed. Governance runs before workload
  in CI, so workload's own `CREATE TABLE IF NOT EXISTS` was then a no-op and
  its test failed on a missing column. `standInTable` makes the table only
  when it is absent and drops it afterwards.
- **macOS's clock hides a precision bug.** `time.Now()` has microseconds on
  macOS and nanoseconds on Linux; Postgres stores microseconds. Two tests
  compared a stored time with an untruncated `time.Now()`: green here, red
  in CI. One was mine, written the day before. **Rule: truncate to
  microseconds whatever is compared with a stored time, and run the touched
  packages in a Linux container before pushing** (the SoftHSM container in
  the local test notes does both).
- **Not fixed:** `TestBackupReprotectPostgres` needs its own shape of
  `secret_values`, so it fails if the secrets package ran first in the same
  database. CI runs governance first.

### "Where from" and "who" were read from what the caller wrote (12.1.0-beta)
- **Nine readers of one header, each with its own copy of the same
  mistake.** `X-Forwarded-For` is a list; Envoy appends the address it saw,
  so only the last entry is the platform's. Eight places took the first
  (`pkg/route`, `pkg/auditmw`, `pkg/jwtauth`, auth, keycore twice, cloud,
  and keycore's destroy handler took the whole header), and each had its own
  helper named `clientIP`, `sourceIP` or `requestIP`. How it slipped
  through: "first entry is the client" is true behind a chain of honest
  proxies and is what most examples show; every test sent a request with
  no header at all, so first and last were the same. **Rule: one reader,
  `clientip.From`; conformance `client-address` fails on a second.**
- **The worst consequence was not the one first reported.** It was found as
  "the audit source address can be forged". The same value was the third
  part of the login lockout key, so a header that changes on every guess
  meant no lockout at all. A fault in evidence is worth following to every
  decision that reads the same value.
- **Next to it, a body field decided who may approve.** Keycore's destroy
  handler read `requester_id` from the body before the verified actor, on
  the same line as the header. Governance refuses a vote from the recorded
  requester, so naming somebody else made the caller eligible to approve
  their own key destruction. Rule 4 already said identity never comes from
  a body field; nothing checked it for this handler because the field looked
  like metadata. **A field that another service uses to decide something is
  identity, whatever it is called.**
- **Four services logged an actor from headers nobody sends.** No caller in
  the repository sets `X-Actor`, `X-Username` or `X-User-*`. So dataprotect
  logged every operation as `dashboard` (an invented default), backup
  logged an empty actor, and all four logged whatever a caller typed. The
  check that found them: for each header a handler reads, grep for who sets
  it. Conformance `caller-named-actor` fails on a new one.
- **A proxy's append behaviour is a fact to test on the proxy.** The
  real-Envoy test has Envoy answer the request itself and return the
  `X-Forwarded-For` it would have sent upstream in a response header
  (`%REQ(X-FORWARDED-FOR)%`). The first version pointed Envoy at a listener
  on the host and failed on Docker Desktop for reasons unrelated to the
  question.
- **A full deploy from this checkout shipped my uncommitted fix.** Another
  session ran `./deploy-local.sh` at 12.0.0-beta while these edits were on
  disk, so the live auth already had the fix and the lockout bypass could
  not be reproduced live any more. The proof that the old code failed is
  the new test run in a worktree at the previous commit (sixth guess: 401).
- **Not reviewed:** `requested_by`, `created_by` and `requester_id` in other
  services' request bodies (docs/SECURITY/REQUEST_ORIGIN.md, "Still open").

### Three fields the dialog used to fake, built for real (12.0.0-beta)
- **A "replace everything" update can't carry one new field safely.**
  `PUT /keys/{id}` rewrites name, purpose, owner, cloud, region, labels,
  compliance and tags from the request. The dashboard cannot send a key
  back whole: the key response has no owner, cloud, region or compliance,
  so an edit from the UI would blank them. The description therefore has
  its own route, like export policy, approval and IV mode. **Rule: a field
  edited on its own gets its own route; a replace-all update is not a
  place to add an optional field.**
- **Rotation renews half of a software key pair.** The dashboard creates a
  pair as two keys (private, and a public component with a `pair_id`).
  `RotateKeyTo` makes new private material and never touches the second
  key, so the stored public key no longer matches. Found while deciding
  where a schedule may be offered; it is why the create dialog offers none
  for a software pair. Not fixed here: it predates this change and affects
  manual rotation too.
- **keycore's SQLite test schema is written by hand** (`store_test.go`),
  not built from `migrations/`. A new column passes every unit test with
  the migration file missing or wrong. Only the Postgres test runs the
  migration; `TestKeyDescriptionPostgres` is what proves `035`.
- **A caller's reason and a refusal's reason are different facts.** The
  first draft recorded the export reason under `reason`, the key refusals
  use for *why keycore said no*. Anything reading events by that key would
  have read a justification as a refusal cause. It is `export_reason`.
- **The schedule needed no new keycore code.** Rotation policies already
  take `id:<key id>`. The create dialog makes the key, then the policy,
  through the routes an API client would use; the question "does this need
  a backend change" was answered by reading the engine, not assumed.
- **Dead code that looks like a caller.** `kmip`'s `ExportKeyMaterial` sends
  `GET /keys/{id}/export` to a POST-only route and nothing calls it. It
  would have looked like a client to update for the new required field.
- **The dashboard's REST catalogue is written by hand and drifts**: its
  export entries named fields and an HSM export that never existed.
- **A test that ranged over a map of ordered steps.**
  `TestBYOKRoutesAuditEachOperation` (cloud) ran rotate, verify, sync,
  revoke and restore from a map literal; Go starts a map's iteration at a
  random element, so restore sometimes ran before revoke and the suite
  failed about one run in five. It showed up only in the full three-mode
  run. Steps that depend on order go in a slice.

### EKM clients: three fakes on the page being replaced, and what the rebuild taught (11.7.0-beta)
- **"Deploy Agent" recorded a connection that never happened.** The dialog
  called `POST /ekm/agents/register`, which stamps `status: connected` and
  `last_heartbeat_at: now` because it was written for an agent announcing
  itself. From a browser it made a client "connected, 0s ago" before any
  agent existed. How it slipped through: the route can't tell who is calling
  (it takes any token of the tenant), and the test registered an agent and
  checked it was listed, which a fake also satisfies. **Rule: a record of
  contact is written only on a credential the contacting party holds.** A
  client is now pending until its agent presents a one-time token, and a
  pending client refuses the token-authenticated calls
  (`TestClientIsPendingUntilItsAgentEnrols`).
- **"Verify Connection" called `GET .../validate-deploy`; only `POST`
  exists.** It always failed, so nobody saw that the POST it meant would
  have marked the client connected on the dashboard's own word and answered
  "deployment validated successfully". A broken control hid a fake one. The
  wizard now waits for the service to report the enrolment.
- **The packaged heartbeat scripts sent `"tde_state":"enabled"` as a
  literal.** They can't read the database. They now send `unknown`
  (`TestDeployScriptsDoNotClaimTDEIsEnabled`). The class: grep a generated
  script for the states it reports and ask where each value is measured.
- **A poll inside a component whose parent re-renders every second never
  fired.** The wizard's `setInterval(…, 3000)` listed the parent's
  `onChanged` in its effect dependencies; the parent keeps a one-second
  clock for "18s ago", so the effect was torn down and rebuilt every second
  and three seconds never elapsed. Type-check and unit tests passed; the
  smoke test that waits for a real enrolment caught it. **Rule: a timer's
  effect depends on values, not on a callback prop; read the callback
  through a ref.** The drawer's own poll is now asserted too
  (`expect.poll` on the request count).
- **An agent's credential can't ride in `Authorization`.** On a cluster
  member `pkg/config/clusterforward.go` verifies that header as an
  auth-service token before forwarding a write, and answers 401 for
  anything else. The client key has its own header, `X-EKM-Client-Key`.
- **`X-Forwarded-For`'s first entry is the caller's claim.** Envoy
  (`use_remote_address: true`) appends the address it saw, so the last entry
  is the trustworthy one; a client can prepend anything. The client's
  "Source IP" uses the last entry. Left open here, the first entry was still
  read for the audit event's `source_ip` and more; fixed for every reader
  in 12.1.0-beta (`pkg/clientip`, entry above).
- **`document.elementFromPoint` answers null below the fold.** The
  covered-controls sweep reported every off-screen row as "covered by
  undefined" on a thousand-row table. It now skips points outside the
  window, and the crowded test scrolls to the last rows and sweeps again
  (`tests/fixtures/layout.ts`).
- **Two rule changes landed mid-task from another session in the same
  tree** (neutral counts on the shared `Stat`, no explanatory text on a
  page). The page had been built with coloured numbers and hint lines and
  was rebuilt before it was committed. `git fetch` and re-read `CLAUDE.md`
  before the final checks, not only before pushing.

### Controls that did nothing, and four reports that were each a class (11.6.0-beta)
- **A selector's choice was read from a button.** The SCEP and CMPv2
  wizards read `document.getElementById("…").value` from the shared `Sel`,
  which renders a `<button>` and a listbox: a button has no value, so the
  code fell back to its default and every request was PKCSReq or IR. How
  it slipped through: the wizards were written against a native `<select>`
  and `Sel` replaced it later; the files are `@ts-nocheck`, and no test
  chose a second option. **Rule: a control's value lives in state; nothing
  reads a `Sel` by id** (`controlsAreReal.test.ts`).
- **The owner reported one redundant field; the dialog had seven dead
  ones.** The Tenant selector had one option. Beside it sat Key Derivation,
  Auto-Rotation and its schedule, Description, an always-ticked "FIPS-only
  algorithms enforced", and in Export a Justification "required for audit":
  none had state, and keycore's `CreateKeyRequest` has no field for any of
  them. They had sat there because each *rendered*; nothing compared the
  form to the request. The check is mechanical: a `Sel`, `Chk`, `Inp` or
  `Txt` with no handler is a fake. The smoke test also reads the POST body.
- **`Stat` dropped every icon passed to it.** It tested
  `typeof i === "function"`; lucide icons are `forwardRef` objects. Sixty-two
  callers passed an icon and got the label-guessed default, so "Revoked"
  showed a ticked shield. Seen only by looking at the rendered tile.
  The first fix (`i || …`) crashed the Keys tab: four tiles there passed
  `i="?"`, the remains of an emoji, which the old test had also hidden. The
  full smoke run caught it; the one spec I had been re-running did not.
  **Rule: after the last edit, the whole suite runs again, not the test of
  the thing just touched.**
- **The paragraph gate had two holes.** It skipped prose containing `;` (a
  guard against matching code) and any expression longer than a name, so
  four of the five Service mTLS paragraphs and 22 others passed. A guard
  written to cut false positives is a hole: measure what it excludes.
- **A badge positioned over its icon covers it at some count.** The bell's
  count was `position: absolute` at the icon's corner; "99+" is wider than
  the icon. Same shape as the collapsed sidebar toggle: two things given
  one box. The top bar now runs through the same `coveredControls` sweep as
  the sidebar.
- **Each fix was tested against the old build.** A worktree at the previous
  commit with only test hooks added: all four new smoke tests fail there.
  The first bell test failed on a locator instead of the overlap, which
  would have passed for the wrong reason on a different regression.
- **Another session had uncommitted work in the checkout.** Checks,
  generated docs and the commit were made in a clean worktree; a full
  `deploy-local.sh` from the shared tree would have shipped that session's
  unfinished service code.

## 2026-10-11

### A collapsed rail nobody rendered (11.5.0-beta)
- **Collapsed, the sidebar toggle was drawn on top of the mark.** The header
  kept both in one row: 60px rail, 15px padding each side, so 30px for a
  26px mark, a 10px gap and a 22px button. The mark's wrapper was
  `flex: 1; min-width: 0`, so it shrank to nothing and the mark spilled out
  of it under the button. How it slipped through: 11.1 to 11.3 restyled the
  shell and were looked at expanded only; no test ever collapsed the
  sidebar. **Rule: a control that changes the layout is rendered and tested
  in each state it produces.**
- **The check is geometric, not a snapshot.** The smoke test asks the
  browser what is drawn at the centre of every icon, button and input in
  the sidebar (`elementFromPoint`), expanded and collapsed, and fails when
  the answer is some other control or when one spills out of the rail. It
  was run against the old header first and failed there on the mark.
- **Two finders for the same list.** The ⌘K palette and the sidebar's
  "Filter modules" both searched the module names and nothing else, while
  docs/GETTING_STARTED.md described the palette as a search "across keys,
  certificates, audit events, users", which it never was. The palette, its
  shortcut and its component are deleted and the docs corrected.

### A fix tested against a value I made up (11.4.0-beta)
- **11.3.0-beta's posture fix did not work on a real stack.** It read
  `captured_at` from `GET /posture/risk` as "a scan is on record". For a
  tenant with no snapshot the handler returns `RiskSnapshot{TenantID: ...}`,
  and Go writes the unset `time.Time` as `"0001-01-01T00:00:00Z"`: a
  non-empty string, so the rule passed again. How it slipped through: the
  test handed `evaluate` a boolean (`postureEvaluated: true/undefined`) and
  never the service's response; the smoke mocks answer `{}`. I read the
  TypeScript type (`captured_at?: string`) and not the Go handler.
  **Rule: a test of "is X on record" uses the bytes the service sends for
  "no X".** `zeroTime.test.ts` does, from `handleLatestRisk`.
- **The class:** any Go response with an unset time carries year 1. The
  dashboard had one local guard (`discovery/meta.ts`, year < 2000) and
  showed "Captured: 1/1/1" in Posture. Every response body is now read with
  `parseServiceJSON` (`lib/wire.ts`), which turns that value into `""`.
  Ten clients read bodies with `response.json()` and bypassed
  `serviceRequest`; a test lists the three that still may (the API
  playground, sign-in, SSO) and fails on any other.
- **A local view over a sidebar sub-option needs a way out.** The Playbooks
  editor sat on top of the "Playbooks" sub-option; choosing that sub-option
  again changed nothing, so the click was dead. The shell now passes a
  click count (`subViewTick`) beside `subView`.

### A dark sidebar beside a light page; a font decision reversed (11.3.0-beta)
- **The owner rejected the ink sidebar on the light theme** ("do not
  match") and the system fonts (wanted an "enterprise text font"), both
  chosen in 11.1.0-beta. What went wrong: the sidebar was themed by putting
  `data-theme="dark"` on it, which looked deliberate in one screenshot and
  split the shell in two in use; and "the CSP refuses Google Fonts" was read
  as "no web font", when the CSP only refuses another host. A bundled font
  on our own origin was always allowed. Both are now rules in CLAUDE.md.
- **The posture rule had no way to know a scan had run.** The snapshot held
  findings only. It now also reads the latest risk snapshot: a scan stores
  one, so `captured_at` tells "none found" from "never evaluated".
- **A fixer and its gate must share the pattern.** The Perl pass that folded
  mixed paragraphs missed two that the test's regex then caught (a `{value}`
  inside the text). The test is the authority; run it after any bulk edit.
- **Trap: clicking a module's name twice folds its sub-options.** A smoke
  test reloaded, clicked "Playbooks" again and lost the view it wanted. The
  module is still open after a reload; tests go straight to
  `subnav-<module>`.
- **Bulk corner-radius edit:** a radius of at least half the element's
  height is a deliberate dot, avatar, toggle or progress track and is left
  alone; everything else maps to the scale.

### "Every key has X" passed with no keys (11.2.0-beta)
- **The second copy of the "ALL OK" fault below.** The recommendation engine
  already reported a missing source as "not assessed", but an empty one
  passed: five key rules, the PQC-path rule and the certificate-expiry rule
  were green on a tenant with nothing to judge, and counted in "N of M
  controls passing". How it slipped through: the test for the honesty
  contract covered `undefined` sources, never `[]`. A rule of the form
  "every X has Y" is assessed only when there is an X.
  Gate: `recommendations.test.ts` ("does not pass key or certificate rules
  on a tenant that has none"). **Open:** the posture-findings rule still
  passes on `[]`; the snapshot can't tell "none found" from "never run".
- **About 120 lines used palette keys that don't exist** (`C.textDim`, `C.textMuted`,
  `C.line`, `C.fg`): borders, dividers and colours silently dropped in EKM,
  Tokenize, KMIP and the Audit Log. How it slipped through: those files are
  `@ts-nocheck`, so the misspelling compiles, and `border: 1px solid
  undefined` fails without an error. Gate: "uses only palette keys that
  exist".
- **A fixed hex hue reaches text through props** (`color={C.blue}`, a
  `tone` passed down), where no style check can follow it. The hues are now
  mid-tones that read on both cards, with a contrast test, instead of
  dark-theme tints.
- **Folding text: warnings are not explanation.** The first pass folded a
  red "joining replaces this node's master key" notice to one line. A
  warning or confirmation carries `data-keep` and stays open; the gate
  accepts either marker, so the choice is made for each new paragraph.
- **Trap:** in zsh `path` is tied to `PATH`. `for path in ...` in a check
  script emptied it and every later command was "not found".

### The console's own CSP refused its fonts and its theme script (11.1.0-beta)
- **`index.css` imported Inter and JetBrains Mono from Google Fonts, and
  `index.html` set the theme with an inline script.** nginx sends
  `style-src 'self' 'unsafe-inline'; script-src 'self'`, which refuses both.
  A deployed console never had its fonts and flashed dark for a light-theme
  user. How it slipped through: `vite dev` and `vite preview` send no CSP, so
  every local run and every smoke test looked right. Fonts are now the
  system's; the theme script is `public/theme-boot.js`.
  Gate: `brandAndLegibility.test.ts` (no remote stylesheet, no inline script).
- **A label that was true of nothing.** System Health showed "ALL OK" with
  zero components, because "none degraded and none down" holds for an empty
  list. The sign-in page carried a fixed "256-bit AES-GCM · FIPS 140-3 ·
  TLS 1.3" line whatever FIPS mode was chosen. How they slipped through:
  both were written as decoration, so nobody asked what they measured. A
  status badge needs a non-empty set; a claim on a page needs a source.
- **"NaN / undefined" on the Command Center.** The PQC tile trusted any
  non-null scan summary. The smoke mocks answer `{}` to everything, so the
  tile rendered NaN in every run and no test looked at it.
- **Hex colours as text.** `C.green` and the other hues in `theme.ts` are
  fixed dark-theme hex (kept so `${C.green}33` works); `C.greenFg` follows
  the theme. About 360 style objects used the hex for text, unreadable on
  the light theme. The gate reads one line at a time, so a `color:` on its
  own line inside a multi-line style object is **not** caught yet.
- **Traps met while drawing the mark and fonts:**
  - A CSS `transform` animation replaces an SVG element's `transform`
    attribute: the mark's core lost its 45° turn while animated. The diamond
    is now drawn as a path.
  - `@font-face { src: local("Menlo") }` matches nothing. `local()` takes a
    full or PostScript name ("Menlo Regular", "Menlo-Regular").
  - Chrome does not resolve `ui-monospace`; the stacks fell to Courier.
  - Tailwind's preflight makes `svg` a block, so `text-align: center` does
    not centre an icon; it needs `margin: 0 auto`.
  - Scoping the dark tokens to one subtree (`data-theme="dark"` on the
    sidebar) re-themes it without touching its styles.

### Buttons for something the service could never do (11.0.0-beta)
- **Restart and Network Interfaces needed the Docker socket; compose never
  mounts it into auth.** The restart call always returned "unavailable" and
  the Interfaces panel was always empty. Removed, with ~550 lines of
  container-state code in `services/auth/system_health.go`.
  How it slipped through: the tests handed the checker a fake Docker
  transport, so the code path passed while the deployed service had no
  socket. Nothing checked the deployment the feature assumed.
- **A guide that documented an invented API.** docs/ADMINISTRATION.md
  section 9 showed a response with `healthy`/`unavailable` statuses, an
  `http_health_check` source and a `payment` service; none exist.
  `check-doc-routes.py` checks that named routes are registered, not that
  example payloads match.
- **Still dependent on the socket:** auth's CLI/HSM functions
  (`execComposeServiceCommandEnv`: the SSH password sync and lock for
  hsm-integration, and the CLI command runner) look the container up through
  the same client. Without the socket they fail with "container runtime
  unavailable". Not changed here; owner decision.

### Closing the open faults (10.4.0-beta)
- **Dead clients for routes that never existed.** Eight files in
  `web/dashboard/src/lib` called 15 keycore routes with no handler
  (`/ml/anomalies`, `/cost/metrics`, `/federation/peers`, ...). Nothing
  imported them, so no page broke and no test failed.
  How it slipped through: the product map lists frontend calls and backend
  routes side by side but nothing failed on a call without a route, and the
  files used `trackedFetch` directly. `scripts/live-check.py` now fails on
  the router's own 404.
- **A catalogue probe instead of a failing read.** Caching the failed read
  of `cluster_local_state` (10.3.0) still left one failed query per service
  per 10 seconds. Asking `information_schema.tables` first costs one cheap
  query and fails nothing; SQLite has no such catalogue, so there the probe
  errors and the table is read directly. Tested on real Postgres by counting
  rolled-back transactions (`TestMissingTableThenCreatedPostgres`).
- **macOS tooling and TLS 1.3.** The system Python (LibreSSL) can't speak
  TLS 1.3 and the system curl (SecureTransport) rejects `--tlsv1.3`, though
  it negotiates 1.3 without the flag. The live check drives curl and passes
  the URL, token and body on stdin (`--config -`), never on the command
  line.
- **401 where the session is not the credential.** The workload token
  exchange is authenticated by the SVID in its body; its 401 is correct for
  a workload and wrong for the dashboard's session logic. The client call
  opts out (`keepSessionOn401`) rather than the server changing its status.

### Why the owner was the one finding the bugs (10.3.0-beta)
- **Nothing looked at the running product.** The HYOK sign-out and the
  short health list both passed every gate: unit tests inject their own
  parser and their own lists, conformance reads source, and the container
  health checks are TCP probes. Both were visible in seconds on the live
  stack. learning.md only records a fault after someone reports it; it does
  not find one. The first run of a log sweep (`scripts/live-sweep.sh`) found
  a third fault nobody had reported: `pkg/clusterstate` returned on a query
  error without recording the attempt, so its cache never applied where the
  table is missing.
- **Fixes stopped at the reported instance.** The rule now: name the class,
  search for its other copies, fix or list them, and add the test or gate
  that fails if it comes back (CLAUDE.md, "Before calling a change done").

### A health list that drifted from what runs (10.2.0-beta)
- **28 of 32.** `services/auth/system_health.go` builds System Health from
  three sources: the container runtime, Consul, and a hard-coded TCP probe
  list. The runtime source needs `/var/run/docker.sock`, which compose does
  not mount into auth, so it fails on every call (logged, never shown on the
  Health panel). That left Consul (25 services) plus PostgreSQL, Valkey and
  NATS. Envoy, the dashboard, the reconciler and the watchdog register
  nothing in Consul and were not in the probe list; the list still named
  three services that no longer exist.
  How it slipped through: the probe list was a second copy of the service
  inventory with nothing tying it to `pkg/svctls.Services`. It now has
  `TestHealthTargetsCoverEveryPlatformIdentity`.
- **Still open:** the runtime path in auth (container states, published
  ports, the restart button's container lookup) can't work without the
  socket, and mounting it would give auth control of the host's containers.
  Either remove that code and the Network Interfaces panel, or decide on a
  narrower source. Owner decision.

### A service that started without its token key (10.1.0-beta)
- **HYOK signed the dashboard out.** `services/hyok` had its own
  `loadJWTParser` that read only `HYOK_JWT_PUBLIC_KEY_*`. Compose sets the
  shared `JWT_PUBLIC_KEY_B64`, so the parser was nil, the service started
  healthy, and every request got `401 jwt parser is not configured`. The
  dashboard clears the session on any 401 (`lib/serviceApi.ts`), so one
  misconfigured service looked like a logout bug.
  How it slipped through: the handler tests inject a parser, so nothing
  exercised the loader, and the health check is a TCP probe that can't see
  it. keycore, governance, ekm, posture and cluster-manager already refuse
  to start without a key; HYOK was the one copy that returned `nil, nil` and
  carried on. Fix: `pkg/jwtauth.LoadParser` plus a fatal on nil, with
  `TestSharedJWTKeyLoadedAndMissingKeyRefusesStart`.
- **401 means "this session is dead" to the dashboard.** A service must keep
  it for a missing or unverifiable token. A valid token in the wrong tenant
  is 403 (HYOK returned 401). Still open: auth answers 401 for a wrong
  current password, MFA code or CLI credential from a signed-in user
  (`services/auth/handler.go`), and workload for a disallowed audience;
  if the dashboard reaches those through `serviceRequest` they sign out too.

### Cloud "BYOK" that brought no key (10.0.0-beta)
- **An import that called the cloud's `CreateKey`.** Every provider's
  `ImportKey` created a native key in the cloud; the cloud generated the
  material and the KMS key's ID only went into a tag. The step that fetched
  the material (`ExportKey` without a wrapping key) failed in keycore, and its
  result was passed to providers that ignored it, so nothing noticed. The UI
  said "Import Key to Cloud", the audit said `key_imported`.
  How it slipped through: the tests used a provider double that returned a
  made-up cloud key ID, so no test ever looked at what material the cloud
  held. The fix is the test shape: each cloud double now unwraps what it
  receives with its own private key and the test compares it to the KMS
  version's bytes.
- **A rotate that rotated nothing.** AWS `RotateKey` called
  `EnableKeyRotation` and `UpdateKeyDescription`, discarded both errors, and
  reported success with `rotation_mode: native`. For an imported key AWS
  refuses automatic rotation, so the call failed and was hidden.
- **Providers no account could reach.** `normalizeProvider` didn't list
  `alibaba` or `servicenow`, so registering either failed, while the UI
  offered both. ServiceNow's "import" posted to `/api/now/encryption/key`,
  which ServiceNow doesn't have; Salesforce's posted the KMS's own AES-GCM
  envelope (useless to Salesforce) to operator-configured paths. A provider
  listed in the UI needs a test that drives its real protocol.
- **`common.PointerString` is not a dereference.** In the OCI SDK it is a
  reflection pretty-printer, and on a `*string` it panics. The OCI double
  caught it on the first run; use a plain deref.
- **HSM keys can't be made to leave by policy.** Extractability is fixed
  when the HSM generates the key, so cloud import is a property chosen at
  creation (`export_allowed` with `hsm: true` → `CKA_EXTRACTABLE`, sensitive).
  Turning export on later is refused by the HSM itself
  (`TestCloudWrapHSMKey`).
- **A route's own audit and the service's must not share a subject.** The
  first keycore cloud wrap emitted `audit.key.cloud_wrapped` from the kernel
  and again from the service. The kernel event carries the details now
  (`c.Detail`); the service emits none.

### "I said last time to not have sub tab" (9.6.0-beta)
- **An instruction that was acted on but never written down came back.**
  The owner had already asked for a module's views to be sub-options in the
  sidebar instead of a separate sub-tab column. Nothing in CLAUDE.md,
  DECISIONS.md or here recorded it, so the column of cards stayed and the
  owner had to repeat it. A UI instruction is a standing rule like any
  other: it goes into CLAUDE.md in the same change, with a test.
- **The rule needs a test, or the next module brings the column back.**
  `SUB_PANES` and the sidebar list now live in one file
  (`components/v3/SidebarSubNav.tsx`), and the smoke test "a module's
  sub-options expand under its name in the sidebar" asserts the list, the
  fold, the selected view and that no `.vk-subcard` column exists.
- **A longer breadcrumb pushed the header buttons off screen.** Forcing
  "group / module / view" onto one line at 1280px hid the info, alerts and
  theme buttons. With a view open the breadcrumb is "module / view". Look
  at the whole header, not only the part that changed.
- **Moving a list broke a generator that passed anyway.**
  `generate_product_map.py` found the nav by searching the shell for
  `const NAV` up to `const SUB_PANES`. With the list moved it wrote a map
  with 0 navigation items and 0 view groups, and `make conformance`
  (`product-map`) passed, because it only compares the output with what
  the generator writes. The staged diff stat (thousands of lines for a UI
  change) was the signal. It had also been matching `NAV_GROUPS_KEY`, not
  `NAV`, and worked by luck. The generator now anchors on `const NAV = [`,
  reads the views from `SidebarSubNav.tsx`, and exits with an error when
  either is empty. A generated file is checked for content, not only for
  freshness; read the diff of generated files before committing.
- **`open(f, "w").write(open(f).read()...)` empties the file.** The write
  handle truncates before the read runs; `VERSION` was committed-ready as
  zero bytes. Read first, then write.
- **The size burn-down made the right design the easy one.** The shell was
  one line under its ceiling, so the list had to go in its own file; the
  shell dropped from 1224 to about 1130 lines and its ceiling with it.

### "It doesn't accept the default password" (9.5.0-beta)
- **A documented default that three things could silently replace.** The
  rule said the admin is seeded as `changeit`; the code read
  `AUTH_BOOTSTRAP_ADMIN_PASSWORD` first. `rotate-secrets.sh` wrote a random
  value there, the installer prompted for one, and compose passed it on. A
  fresh database was then seeded with a password nobody had chosen or seen.
  A default that is a rule is a constant, not a fallback.
- **I answered the question asked instead of the rule broken.** Told "the
  default is overridden in .env, read it there", the owner had to restate
  the rule. When behaviour contradicts a standing rule, the behaviour is the
  bug: fix it, don't explain it.
- **"Rotating" a seed value rotates nothing.** The bootstrap password only
  applies to an empty database, so a new one in `.env` never changed a live
  admin and only broke the next fresh install.

### Every service 401s after the volumes are removed (9.4.0-beta)
- **Symptom far from the cause.** `compose up` said only "container certs
  is unhealthy". certs was waiting for its master key; keycore refused it
  with `401 invalid token`; auth's own call was refused the same way. When
  the issuer's own token is refused, compare the fingerprint of the
  verification key in the services' environment with the public half of
  auth's signing key before reading any handler.
- **Two copies of one fact, reconciled only when one was empty.**
  `deploy-local.sh` minted the signing key only if `.env` had no
  `JWT_PUBLIC_KEY_B64`, and synced only if the auth volume existed. Volumes
  removed, `.env` kept: neither branch ran, and auth quietly generated a
  key nobody else knew. The key in the volume is the source; `.env` is
  always derived from it, and a missing key is minted whatever `.env` says.
- **Tell the keys apart without printing them.** Compare SHA-256
  fingerprints of the public key (DER); the private key goes through a
  pipe to `openssl pkey -pubout` and never reaches the terminal.

### "Fix what needs the owner's accounts" (9.3.0-beta)
- **Asked to fix the unproven, with nothing to prove it against.** No
  settings file, no cloud CLI, no credential on the machine. The choices
  were to say "verified" on the strength of more stand-ins (fabricated
  evidence), to go looking for credentials nobody offered, or to say plainly
  what can't be done here and remove every other obstacle. The third: the
  table still says "not yet run".
- **Make the owner's step as small as the secret itself.** A script that
  needs a checkout, Go and a correctly permissioned file is three chances
  to give up. A manual workflow needs only the secrets, runs the same
  script, and leaves a dated summary that can be cited as the evidence.
- **Half a flow can be proven where the whole can't.** Entra ID has no
  emulator, but Azure Blob's acceptance of a Bearer token does (Azurite,
  `--oauth basic`). The label says exactly that: "Bearer token from a
  stand-in issuer", not "Entra ID". I first printed it as "Entra ID" and
  changed it before committing: an output line is a claim too.
- **Check that the checker checks.** Before counting the Azurite pass, the
  same server was shown to refuse no token, a malformed token and a token
  for another audience. A server that accepts anything proves nothing.
- **Two sessions took the same version number.** The other session pushed
  its 9.2.0-beta minutes before mine; the push was refused, and I had
  already removed the worktree the commit was made in. The commit was still
  in the object store by its hash and was cherry-picked onto the new main
  as 9.3.0-beta. Fetch immediately before pushing, and keep the worktree
  until the push has succeeded.
- **A test added after the "nothing configured" skip never runs.** The new
  case was appended below the skip check and the first run "passed" by
  skipping. Read the verbose output, not the exit code.

### Discovery: names across files, large objects, no-ETag checks (9.2.0-beta)
- **"Resolving across files breaks skipping unchanged objects" had an
  answer.** The objection was real: object B's findings would depend on
  object A. Record, per object, the constants it defines, the names it
  could not resolve, and a hash of what those names stood for; read B
  again when the hash differs. No source line is stored. The cost is one
  scan of delay: A is read first, B on the scan after.
- **Report what a statement adds, not what it gives.** Statements kept for
  a second look with the whole table must not repeat what the first look
  found. The second look replays the first into the same `seen` set and
  keeps only new findings; resolving twice returns nothing.
- **An unfilled placeholder is not an unknown algorithm.** "Unknown names
  are recorded and not assessed" turned `"$family/CBC"` into an asset
  called `$FAMILY`. It only showed once interpolation was resolved and the
  same line produced both the real name and the junk one.
- **`encoding/pem` only sees a block at the start of a line**, and so did
  every "contains a key marker" pre-check that then handed the bytes to
  it. Search for the marker, cut to the END line, decode from there.
- **Two failing tests were the feature working.** `TestDeepScanReadsByContent`
  and `TestStorageWithoutETags` asserted the old limits (a key deep in a
  large object not found; a same-time, same-size replacement unseen). A
  test that pins a limitation should say so in its name or comment, or the
  next change reads its failure as a regression.
- **Without an ETag there is no free answer.** Trusting the listing misses
  a replaced key; reading everything costs the bucket every scan. One
  kilobyte per object per scan is the middle: it turns "same time and
  size" into "same time, size and first kilobyte", which a replaced key
  does not survive, for a ranged request each.
### Verifying storage credentials for real (9.1.0-beta)
- **"Not proven" is fixed by a run, not by more tests of the same kind.**
  The stand-ins for STS checked the signature with the AWS SDK's signer and
  passed a GET request. A real implementation (MinIO) only routes a form
  POST, which is what every SDK sends. The stand-in was faithful to what I
  wrote, not to what servers accept. Role assumption is now a signed POST
  and is run against MinIO.
- **MinIO community builds can be pulled again** from other registries
  (`pgsty/minio`, `pgsty/mc`); the original image names are gone. Its admin
  client reads a new user's keys from standard input, so they need not be
  on a command line.
- **Read-only is not list.** The scan needs `s3:ListBucket` and
  `s3:GetObject`; a policy called `readonly` that lacks the first is
  refused at the listing. The error already said "list and read".
- **What can't be run here has to be made easy to run elsewhere.** Entra ID
  and Google's token exchange have no emulator. The honest state is a
  script the account's owner runs, and a table that says "not yet run".
- **zsh still does not split `$var`.** `git diff -- $files` with four paths
  in one variable matched nothing and wrote an empty patch; because the
  commands were chained with `&&`, the restore that followed never ran.
  List the paths, or use an array. Second time this month.
- **Another session was editing the same package.** The build broke between
  two of my runs on a symbol I had not touched. The work moved to a
  worktree of the pushed commit, and only the four files I had changed
  were restored in the shared tree.

### Identity provider secrets, the external token vault, HSM import (9.0.0-beta)
- **"It takes a `password_ref` nothing resolves" was the small end of a
  fake.** The tokenization "External DB vault" stored a host, user and
  password reference, generated per-database setup SQL, labelled the vault
  `external` in the list and in each token's metadata, and never opened a
  connection: `CreateToken` writes to `token_vault_records` whatever the
  vault says. How it slipped through every sweep: it validates carefully
  (refuses an inline password, requires host and database), which reads as
  a feature with a missing detail, not a feature with no body. **Rule:**
  when a reference "resolves nothing", look for the code that would have
  used the resolved value before wiring the resolver.
- **A patch that writes into the map it was read from can't be compared
  with "before".** The provider upsert merges the request into
  `existing.Secrets`, so "did every secret change?" compared a map with
  itself and never closed an exposure entry. Copy the values you will
  compare before the merge. The test caught it; the first draft did not.
- **Auth can use `pkg/mek` only lazily.** Keycore verifies the service
  token against auth's JWKS, so auth must be serving before its own key
  can open. The audit service's pattern (open in the background, 503 for
  what needs the key, everything else unaffected) fits; refusing to start
  would deadlock the platform.
- **A legacy mux that authenticates per route gives a mounted kernel no
  claims.** `route.Router.MountOn` assumes a middleware has already put the
  claims in the context. Auth wraps each handler instead, so the mounted
  `/mek/*` routes would have answered 401 to everyone. `MountOnWith` takes
  the service's own wrapper.
- **`CKA_VALUE_LEN` is the HSM's to set on an unwrapped key.** Supplying it
  in the `C_UnwrapKey` template is `CKR_ATTRIBUTE_READ_ONLY`. And SoftHSM2
  leaves it unset afterwards, so `inspect` reports 0 bits for an unwrapped
  key there; the check value is what proves the length.
- **The packaged SoftHSM2 (2.6.1) can't verify RSA-OAEP with SHA-256.** It
  answers `CKR_ARGUMENTS_BAD`. Rather than add a SHA-1 path to make the
  test run, the unwrap is verified against 2.7.0 built from source, and the
  test skips, saying why, on a library that refuses the mechanism. CI
  therefore does not prove the unwrap until its image has 2.7.
- **A weak-key fixture can't be made in strict FIPS mode.** `rsa.GenerateKey`
  refuses 1024 bits under `fips140=only` and returns nil; a test that
  ignores the error dereferences it. Make the "refused weak key" case
  conditional on being able to produce the key.

### Discovery limits and private destinations (8.1.0-beta)
- **A rule that matched "some number after the call" labelled the wrong
  number.** `RSA_generate_key(?:_ex)?\(\s*[^,]*?,?\s*(\d{3,5})\s*,` was
  written to cover both argument orders. When the size was a name it
  skipped to the next number, the public exponent, and reported
  `RSA-65537`. It surfaced only when variables started being resolved and
  one line produced two sizes. **Rule:** one rule per signature; a pattern
  loose enough to "find the number" will find a different one.
- **A shared HTTP client is a shared permission.** Letting a tenant reach
  an approved private range by passing the allowance per request would
  have been wrong: a kept-alive connection is reused with no new dial, so
  tenant B's delivery to the same host would ride a connection dialled
  under tenant A's approval. The allowance lives in the client's dialer,
  and a client with one is built for a single tenant (or connection) and
  closed.
- **An approved range can contain the platform.** The containers sit on a
  private network, so "10.0.0.0/8 minus what is not approved" still
  includes keycore's address if an administrator approves that subnet.
  Discovery already refused platform addresses at the dial; `ssrfguard`
  did not need to until it could dial private addresses at all. Now
  `Allow.DialContext` does the same.
- **A check made before the request is not a check on the request.**
  Governance validated the notice URL, then sent it with a default client:
  a redirect, or a name that resolved differently a moment later, went
  unchecked. Found while moving it to the dial-guarded client. Validate at
  the dial, and follow no redirect.
- **"Rejected" in DECISIONS.md is an argument, not a wall.** Nested
  archives were rejected because size multiplies per level, and the
  last-modified fallback because two writes can share a timestamp. Both
  objections are met by a narrower design (one allowance for the whole
  tree; trust a time only once it has settled, and not for long). Read the
  reason and answer it, and record the supersession.
- **`pem.Decode` finds a block only at the start of a line.** A key
  embedded in a binary with no line break before `-----BEGIN` is not
  decoded, so a deep scan that reads the whole object still misses it.
  Stated as a limit, not fixed.

### Credentials in one store (8.0.0-beta)
- **Two services verified no token at all.** `cloud` and `autokey` wrapped
  their handlers in the request-audit middleware and nothing else. Every
  handler called `tenantcheck.Enforce`, which *skips* when no claims are in
  the context, so the tenant check read as present and did nothing. How it
  slipped through: each service's tests call the handler directly, the edge
  only requires an `X-Tenant-ID` header, and nothing in conformance asks
  "does `main` verify a token". **Rule:** a tenant check that passes on
  missing claims is not a check; look for `jwtauth.MustWrap` (or
  `platform.Boot`) in `main.go`, not for `Enforce` in handlers.
- **"Masked in the API" is not "sealed".** The Azure EKM client secret and
  the governance SMTP password were plaintext columns whose handlers
  blanked or masked them on the way out. A reviewer reading the handler
  sees a careful service. Check the migration and the INSERT.
- **A collected secret nothing uses is still a stored secret.** The Google
  CSE dialog asked for a service account key, the column comment said
  "encrypted at rest", and no code read it. Removed, not migrated. Grep for
  the field's *readers* before deciding how to protect it.
- **A whole-object metadata update can erase system state kept in the same
  object.** Keycore kept "this key is in an HSM, and which" in the key's
  labels, and `UpdateKey` replaced every label. Editing a key's owner
  could orphan its HSM objects at destroy time. System labels are now
  carried over and never taken from the caller.
- **A PKCS#11 login belongs to the process, not to the request.** The
  connector keeps one logged-in session per slot. A second configuration
  for the same slot inherited that login whatever PIN it carried. With
  per-tenant credentials that is a way in, so the PIN used for the anchor
  is remembered as a keyed digest and a different one is refused.
- **Optional transport security is plaintext.** The mailer did STARTTLS
  "if enabled and offered"; a relay that didn't offer it got the password
  in the clear, silently. TLS is now required and the test speaks SMTP to
  a real listener to prove nothing but EHLO reaches a plaintext relay.
- **A test double at an interface hides everything behind it, including
  whether the caller has a credential.** The HSM connector got a client for
  the credential store and a fake of it in tests; it had never called
  another service, so it had no service identity and auth provisioned none.
  Every HSM credential would have been refused in a deployment, with every
  test green. Conformance `service-token` checks that a call *attaches* a
  token, not that the process can get one. Found by reading `main.go`, not
  by a test; `TestEveryCredentialUserHasAServiceIdentity` now ties the
  admission list to auth's identities and each service's `main`.
- **Two sessions built the same thing.** While this change was open,
  7.40.0-beta shipped approved private endpoints; this change had its own
  list, table and UI. Rebased onto theirs and deleted mine. Fetch before
  building anything cross-cutting, not only before pushing.
- **Overwriting a file to replace one function loses the others.** Writing
  a new `mailer.go` dropped `buildApprovalEmailBody`, which lived below the
  function being replaced. The build caught it; a file with only helpers
  and no caller in the package would not have.
- **The shared `Chk` toggles on its box, not its label**, and the shared
  `Sel` is a custom listbox over a hidden `<select>`. A smoke test that
  clicks the label or calls `selectOption` does nothing and waits.

### Private endpoints for source connections (7.40.0-beta)
- **Checking an address when a connection is saved says nothing about where
  its credential goes later.** The save-time check resolved the name once.
  Discovery's dial guard allows private addresses on purpose (scanning the
  customer's network is the point), so a name that later resolved to a
  private address would have taken the token with it. The rule belongs at
  the dial, on the address actually connected to, and only for requests
  that carry a credential.
- **A shared HTTP client shares its connections.** With one client per scan,
  a keep-alive connection opened for a bucket with no credential could be
  reused for one with a credential to the same address, without a dial and
  so without the guard. Each credentialed bucket and repository now builds
  its own client.
- **An allowlist needs an owner who is not the one it constrains.** If a
  tenant's administrator could approve ranges, the list would constrain
  nothing. The route checks the caller's own tenant is the root tenant, on
  top of a permission that the coarse `kms.write` grant does not cover
  (its name does not end in `.write`).
- **A real private address was available to test with.** The machine's own
  LAN address gives a listener on RFC 1918 space, so the test proves "no
  connection is accepted before approval, one is after" on the real dial
  path instead of asserting on a function's return value. It skips where
  no such address exists.
- **The size gate counts differently from `wc -l`.** A file ending in a
  newline has one more line to the gate than to `wc`. Check with the gate.
- **UI modules don't call `serviceRequest`.** The lint rule wants a typed
  client in `src/lib`; the panel's three calls live in
  `lib/privateEndpoints.ts`.

### Discovery: storage credentials (7.39.0-beta)
- **A zero time is not empty.** `json:",omitempty"` does nothing for
  `time.Time`, so a bucket never scanned said `"last_pass_at":
  "0001-01-01T00:00:00Z"`, which the dialog would have shown as a pass. It
  went out in 7.38.0-beta because the smoke fixture set the field by hand.
  `Bucket.MarshalJSON` now omits unset times and a route test reads the
  real response.
- **The first label of a host is an account name only for a name.** For
  `127.0.0.1` it is `127`, which passed the account-name pattern. An IP
  endpoint needs `account_name` stated.
- **Each provider signs something different, and none needs the secret on
  the wire.** SigV4 (S3, and STS with the session token as a signed header),
  Shared Key (a fixed twelve-line string, then the x-ms headers and the
  resource with its sorted query), and a JWT for Google. Only the Entra
  client secret is itself sent, and only to the token endpoint.
- **A test double is only evidence if it checks independently.** The STS and
  S3 doubles compare against the AWS SDK's signer; the Shared Key double
  recomputes with the standard library; the Google double verifies the
  assertion with the public key. Where a real service exists locally
  (Azurite) the live test is the proof; where none does (STS, Entra, Google
  token exchange) the changelog says so.
- **Live cases must not share state.** Two live cases against the same
  container shared scan state, so the second "read nothing" and looked like
  a pass. Each case now has its own tenant and bucket ID.
- **A pinned test CA breaks public endpoints.** The live script's CA pool
  for the local servers made Google's certificate unverifiable; public
  services are run without it.

## 2026-10-10

### Discovery: incremental, resumable bucket scans (7.38.0-beta)
- **A cap that fails is a cap that hides.** "More objects than the limit"
  ended every scan of a big bucket with an error, and the objects past the
  cap were never read, on any scan. A budget per run with a saved cursor
  reads the same bucket to the end.
- **The cursor must outlive the run.** An S3 continuation token is the
  service's and may expire; `start-after=<last key>` is ours and is valid
  forever. Azure has only its marker, which names the next blob.
- **Skipping needs proof that what was found is still held.** Recording "read,
  ETag X" before the assets are stored means a crash in between, or an
  operator removing an asset, makes the scan skip that object for good. An
  existing test that called the bucket scan without storing assets caught
  it. The skip now requires every recorded asset to exist.
- **"Not seen by the last scan" is false for a source read over several
  scans.** Staleness for bucket assets is measured against the start of the
  last complete pass, and is undefined (nothing is stale) until one exists.
- **Skipping by ETag freezes the parser's knowledge.** Unchanged objects
  would never get new rules. Each object row carries the rule set it was
  read with (`scanRules`); raising it re-reads everything.
- **Files placed on a gateway's disk have no ETag.** The Versity posix
  backend keeps ETags in extended attributes written on upload; files
  copied in by `docker cp` list with none, and are (correctly) re-read every
  time. The live test uploads through the S3 API (`curl --aws-sigv4` with
  the credential in a config file).
- **Compare timestamps in Go, not SQL** (again): SQLite stores them as text
  and Postgres as timestamps; pruning "seen before the pass started" reads
  the rows and compares parsed values.

### Discovery: content detection, archives, deep scan (7.37.0-beta)
- **A file name is a claim, not a fact.** Selection by extension missed
  every keystore and key someone had renamed. Magic bytes are cheap: JKS
  `FEEDFEED`, JCEKS `CECECECE`, PKCS#12 `SEQUENCE { INTEGER 3`.
- **An archive's header is also a claim.** A zip member's declared size is
  what the archive says; the read is bounded by `io.LimitReader` whatever
  the header says, and the total unpacked bytes are capped separately.
- **"Deep" has to be a choice with its cost stated.** One ranged GET per
  object is nothing for a config bucket and a bill for a data lake. Both
  real servers (Versity S3 gateway, Azurite) honour `Range: bytes=0-1023`
  with 206; a service that ignores it answers 200 and the reader's limit
  still bounds what is held.
- **An assertion that can't fail proves nothing.** My first deep-scan test
  checked "not downloaded in full" with a helper that returned true for
  every request to that object; it would have passed with a full download.
  It now counts requests per object.
- **Text in the same element changes exact-text matches.** Adding a "deep ·"
  marker inside the span that held the connection name broke the smoke
  test's exact match on the name. Each fact gets its own element.
- **A service's log echoes request URLs.** Tailing the Azurite container log
  printed a SAS signature into the session output. It was an emulator token
  from the published development key, but the habit is wrong: don't tail
  the log of a service whose URLs carry credentials; ask it a question
  (`curl -o /dev/null -w '%{http_code}'`) instead.

### Discovery: crypto usage rules (7.36.0-beta)
- **Match the call, not the word.** A rule is a call, import or directive
  with the algorithm as its argument, per language, and comment lines are
  skipped. Matching `MD5` anywhere would have listed every README and
  changelog. The cost is stated: one line at a time, no data flow.
- **A library's default is a fact worth recording.** `Cipher.getInstance
  ("AES")` gives AES/ECB/PKCS5Padding in the JDK. The name says "AES"; the
  behaviour is ECB. The label follows the behaviour.
- **`crypto/des` is not DES.** The Go package also provides 3DES, so the
  import alone names neither; the rule reads the constructor called.
- **The catalogue had no entry for a mode without a size.** `AES-ECB` was
  "not assessed" because it names no key size, though ECB is weak at every
  size. A fact that holds for every parameter set does not need one.
- **One asset per algorithm per line.** The asset ID was built from file,
  line and fingerprint; usage has no fingerprint, so `RC4` and `3DES` on one
  `ssl_ciphers` line were one asset until the algorithm joined the ID. IDs
  of existing kinds are unchanged, so a rescan does not duplicate them.
- **Test tokens are assembled at run time.** A token-shaped literal in a
  test file is a finding for every secret scanner, including the hosting
  service's push protection.

## 2026-10-01

### Documentation tab removed (7.35.0-beta)
- **Hand-written docs inside the bundle go stale by construction.**
  `DocsTab.tsx` was 3,344 lines of endpoint and env-var tables typed into
  JSX under `@ts-nocheck`, with nothing tying them to the routes or the
  config they described (its footer said "Generated from platform source";
  it was not). Nothing failed when a route changed, so it drifted. What
  the product shows about itself must be generated from the source (the
  REST catalogue, the OpenAPI spec) or live elsewhere.
- **Removing a tab id needs a `RETIRED_TABS` entry.** `devsecops` already
  redirected to `docs`; both now point at `home`, otherwise a saved hash
  relies on the silent unknown-tab fallback.

### Discovery: object storage source, and two dead links (7.34.0-beta)
- **A string tab id fails silently.** `onNavigate("byok")` compiled, and the
  shell's "unknown tab → first tab" recovery turned a wrong id into a visit
  to the Command Center with no error anywhere. `byok` is a sub-pane of
  `cloudctl` and `certificates` is a module id in `config/tabs.ts`; both
  look right. The smoke test never clicked those two buttons. Now
  `tests/unit/navTargets.test.ts` checks every `onNavigate("…")` literal
  against the shell's `NAV`, and the smoke test clicks both.
- **A fallback button duplicates the thing it falls back to.** "Upload files
  instead" in the Mounted code dialog was a second entry to the File upload
  card beside it. A dependency's dialog shows how to set that dependency
  up; alternatives already have their own card.
- **Two wire APIs cover most object storage.** S3's ListObjectsV2 and
  GetObject with Signature V4 reach AWS, MinIO, Ceph, R2 and Google Cloud
  Storage (HMAC keys, region `auto`); Azure Blob needs only a SAS token in
  the query. Both are a few GETs, so no cloud SDK was added.
- **Signature V4 is all about escaping.** The signature covers the path and
  query in one strict encoding (everything but unreserved characters
  percent-encoded, a space as `%20`), and Go's default URL encoding leaves
  `+`, `=`, `&`, `:` and others alone. The request URL is built in the
  canonical encoding and parsed, so the bytes sent are the bytes signed.
  `TestSignV4MatchesTheAWSSDK` compares each header with the AWS SDK's own
  signer for names with spaces, `+`, `=`, `#`, `?` and non-ASCII letters.
- **HMAC key floor.** In FIPS-only mode an HMAC key under 112 bits panics.
  The V4 signing key is `"AWS4" + secret`, so a secret under 10 characters
  is refused when the connection is saved and again before signing.
- **A SAS token is in the URL, so the URL can't reach an error.** Transport
  errors are unwrapped from `*url.Error` before they are reported, redirects
  are not followed, and of a storage service's error body only its `<Code>`
  is kept. Tests search every error and audit event for the token.
- **MinIO's community images are gone** (both registries refuse the pull).
  The live test ran against the Versity S3 gateway, which verifies
  signatures, and Azurite; and unsigned against public buckets on AWS S3 and
  Google Cloud Storage.
- **zsh does not word-split `$var`.** `set -- $spec` put the whole string in
  `$1`; the live test then parsed an endpoint with spaces in it. Pass each
  value in its own variable.

### Event-driven check and background job in secrets (7.33.0-beta)
- **A durable consumer shared by cluster nodes would have lost events.** With
  one durable name, each event goes to one node; when that node is a member
  it must not write, so the check never runs. The watcher subscribes to the
  live subjects instead: every node hears, only the primary acts, and the
  hourly sweep covers what was missed while down.
- **Moving work out of a request moves its audit record too.** The counts
  that were details of `settings_updated` now belong to a separate
  `cap_prune_completed` event; tests that read `rec.Last` had to look the
  event up by action. A background job with no event of its own would have
  been unaudited destruction.
- **A background job needs a finisher.** In-memory "running" state dies with
  the process. Pruning is idempotent, so the hourly sweep re-applies every
  tenant's caps and emits only when it removed something.
- **React: a callback prop in an effect's dependencies restarts the timer on
  every parent render.** The shell re-renders each second for the header
  clock, so a 2-second `setTimeout(onChanged)` never fired and the "running"
  line stayed forever. The browser test caught it; the callback is read
  through a ref.

### Deleting a restriction is a grant (7.32.0-beta)
- With "an allow rule restricts", deleting the last allow rule over a path
  widens access to everyone with the permission. It looked like cleanup and
  was audited as a delete. A delete that grants needs the same care as a
  grant: say what opens, require the caller to confirm it, record it.
- "Missing" is not "never coming back". A role exists only while defined or
  held; auto-removing rules for missing subjects would lift a deny on a
  role between its last holder leaving and its next one arriving. Detect,
  stamp, alert; leave the decision to a person.
- A setting that "applies at the next write" is a setting that does not
  apply to the secrets nobody writes, which are the old ones the cap was
  meant for. Applying it in the request made the test for the old behaviour
  fail (`TestVersionCap` expected two versions pruned at the rotate; one
  goes at the settings change now), which is how the change was confirmed.

### A rule that names nobody is a lockout, not a no-op (7.31.0-beta)
- **What was wrong:** an access rule's subject was free text. With "allow
  restricts", one mistyped role as the only allow rule on `/finance/*` made
  the folder unreadable by everyone, and the refusal (`not_in_access_rule`)
  gave no hint that the rule itself was the mistake.
- **Fix shape:** validate identifiers against the service that owns them,
  at write time, and fail closed when it cannot be asked. Re-check on read
  and flag, because the subject can disappear later.
- **Trap:** auth's existing list routes were unusable for this. `GET
  /auth/clients` lists the *caller's* tenant, so a service token would have
  listed the internal service tenant and reported every customer client as
  missing. A purpose-built, caller-restricted endpoint that takes the tenant
  explicitly was needed.
- **Trap:** "unchecked" must never collapse into "found". The annotation
  treats a subject absent from the lookup result as unchecked; a partial
  outage (workload identity down) leaves the other owners' answers intact
  (`TestPlatformDirectory`).
- **Built-in roles are not rows.** `tenant-admin` is not in the tenant's
  role table, so a role exists if the table has it or a user holds it.

### Secrets hardening follow-ups (7.30.0-beta)
- **"Ignores a parameter" is a tenancy-shaped bug.** The Vault KV handlers
  recorded the mount in metadata and audit details and then looked the
  secret up by path alone. Everything looked mount-aware; nothing was. A
  path parameter that is logged but never used in the lookup deserves a test
  with two values (`TestMounts`).
- **Fixing a key means migrating the rows.** Making the mount part of the
  name without renaming existing secrets would have made every one written
  under `kv/` unreachable at its URL. The rename is in the SQL migration,
  skips a taken name, and is tested from a 7.29.0-shaped database on real
  Postgres (`TestMigration005Postgres`).
- **A migration that references a column it then drops cannot be re-run.**
  `UPDATE ... SET value_hash` followed by `DROP COLUMN IF EXISTS` fails the
  second time. pkg/db tracks migrations, but the test that applied it twice
  found it; the pair is now inside a `DO` block guarded on the column.
- **Unknown is not "no".** For group subjects, treating a failed membership
  lookup as "not a member" would silently skip a deny rule. The decision
  tracks "unknown" separately for allow and deny and refuses with a 503 that
  says so, so an outage reads as an outage, not as a policy.
- **Default-deny hides what you would need to count.** Under it, uncovered
  secrets are invisible to every caller, so the page cannot count them
  afterwards. The count is shown before switching, and the hint says why it
  is unavailable after.
- **Dropping a column does not erase it.** Postgres keeps dropped-column
  data in existing rows. The migration empties the column first so live rows
  hold no hash; dead rows go at the next vacuum. Old backups still hold it.

### Secrets access rules and soft delete: what bit (7.29.0-beta)
- **A recoverable delete changes what "deleted" proves.** The exposure
  register closed an entry when its secret was deleted, because the material
  was gone. With soft delete it is not gone, so the entry now closes on
  destroy. `TestUpgradeMovesSecretsOffPublicKey` caught it; any "X is
  remediated when deleted" logic has to be re-read when delete stops
  destroying.
- **Filtering after paging breaks pagers.** Hiding rows a caller may not see
  after `LIMIT/OFFSET` returns short pages, and the dashboard's "stop when a
  page is short" loop then silently drops the rest. The limit and offset
  count visible rows (`ListVisible`, `TestListPagesCountVisibleSecrets`).
- **A move is a write to the destination.** Access by path means a rename or
  a label change relocates the secret. Checking only the old path would let
  a caller move a secret out of (or plant one into) a restricted folder.
- **Counts leak.** `/secrets/stats` was a SQL aggregate over the tenant; it
  would have told a caller how many secrets a folder they cannot see holds.
  It is now computed over the same visible set as the list.
- **Read-then-update is not a version check.** The store read
  `current_version`, then updated unconditionally; the new `UPDATE ... WHERE
  current_version = $read` is what makes `expected_version` (and plain
  concurrent rotates) safe.
- **UI trap:** the shared `Chk` toggles only when its box is clicked, not
  its label. A browser test that clicked the label text found it; the rule
  form's labels toggle too.

### A zero that means "the call failed" (7.28.0-beta)
- **What was wrong:** the Operations Status loader awaited keys, secrets,
  certificates, alert counts and the expiry policy in one `Promise.all`
  with no catch on those five. One failure threw away every result, and the
  cards kept the zeros the state was initialised with: "0 keys", "0
  critical" for a service that was down.
- **How it slipped through:** the zero came from `useState({keys:0,...})`
  and `|| 0` at the render site, so there was no line that said "on error,
  show 0". The smoke test mocks every call with 200.
- **Rule of thumb:** initialise a measured value to `null`, not 0; let each
  source fail alone (`.catch(()=>null)`); render null as "—" with
  "Unavailable". The smoke test now fails keycore and reporting and asserts
  no 0 on those cards.

### Fake removed: the Secret Vault's OpenBao panel, folders and form options (7.27.0-beta)
- **What was fake:** a panel listing Vault endpoints the service never
  registered (`sys/policies/acl`, `secret/undelete`, `sys/mounts`) and seven
  event hooks nothing emits, with a pointer to an "Event Hooks" admin page
  that does not exist. A "+ Folder" dialog whose "Create & Navigate" only
  changed a React state. A "lease-based access" checkbox and a "delivery
  format" select that were stored as metadata and read by nothing. In the
  service: KV writes always answered `created: true`, `lookup-self` returned
  `policies: ["default"]` and `creation_time: now`, deletes were logged as
  `system`, and `GetStats` discarded every scan error (`_ = row.Scan`) so a
  broken table read as 0.
- **How it slipped through:** all of it is prose, JSX literals and response
  maps, none of it a `mock*` function, so `real-capability` passes. The
  panel copied a competitor's feature list as if it were ours. The form
  options looked real because the request did carry them; nobody followed
  the field to a reader. The Vault responses were written to satisfy a
  client's parser, not to say what happened.
- **How to catch the next one:** for each control, find the code that reads
  what it writes; a field with a writer and no reader is decoration. For
  each endpoint a page names, grep the router. For a compatibility response,
  every field must come from a variable, not a literal. `_ = row.Scan` on a
  count is a zero waiting to be shown as a fact.
- **Also found:** the version list returned an unsalted SHA-256 of each
  value to callers who may not read values. A digest shown "for integrity"
  is a guessing oracle for a password. Removed from the API; the stored
  column is still open.
- **Trap:** opening the detail dialog fetched the value up front, so every
  click on a card was audited as a `value_read` warning. A page must not
  read a secret to show its metadata.

### Fake removed: placeholder cards on the Operations Status view (7.26.0-beta)
- **What was fake:** a Disk Encryption card (cipher, `34.2 / 120 GB`,
  "Integrity passed | Recovery: 3-of-5"), a Network card ("TLS 1.3 mTLS ·
  ML-KEM", always OK), a FIPS "Violations 0 (24h)" row, a `vecta-kms-01`
  leader shown when the cluster returned no nodes, `auditChainOk: true` set
  in the loader and shown as "INTACT / Chain verified", an "Other 100%"
  algorithm bar, a compliance score of 0 before any assessment, and KPI
  bars with constant or invented scales (`barPct={62}`). In the loader:
  "+N this week" was `keyCount * 0.0045`, Ops / Day was a count of the
  newest 500 audit events of any kind, and "critical" alerts fell back to
  the high count.
- **How it slipped through:** they are JSX literals and `||` fallbacks, not
  functions. `real-capability` looks for `simulate*`/`mock*`/`fake*` names
  and `Math.random`, so a string in markup or a default object in a ternary
  passes. The smoke test only checked that the tab rendered. The cards were
  design placeholders from the first dashboard that no backend ever fed.
- **How to catch the next one:** on any page, ask of each value "which
  response field is this?". A literal number, a `?? "ok"`, a `!== false`
  and a `list.length ? list : [{...}]` are the shapes to grep for. The smoke
  test now asserts these strings are absent with an empty cluster.

### A red CI step hides every step after it, and a gate that can only fail is not a gate
- **What happened:** the dashboard CI job stopped at lint on every commit
  since 6.25.0-beta. Nobody saw the steps after it, so a stale browser test
  (6.11.0-beta), a stale generated REST catalogue and a size gate with 30
  violations all sat unnoticed. In 7.15.0 to 7.19.0 I ran type-check, lint on
  the files I touched and one smoke spec, and reported the dashboard as
  passing. I never ran the CI job's own sequence, and I discarded the
  regenerated REST catalogue as a "build artefact" when it was a committed
  file that had drifted. I also wrote Postgres tests "for CI
  integration-postgres" in packages that job never ran.
- **How it slipped through:** each check I ran was real but narrower than
  CI's. Lint on touched files passes while the repo's lint fails. A test
  that skips without a DSN looks green everywhere it isn't given one. The
  size gate had an empty allowlist and 30 offenders, so its failure carried
  no information and was ignored.
- **Rule:** before pushing a dashboard change, run the CI job's steps as CI
  runs them, in order, on the locked dependencies (`npm ci` first: a stale
  `node_modules` produced a false OpenAPI drift here). A regenerated file
  that differs from the committed one is a finding, not noise: commit it or
  explain it. A new test that needs a service only counts once CI's job
  lists its package. A gate with standing violations becomes a ratchet
  (ceilings that only go down), so that it can fail for a reason.
- **Trap:** `gh` is not installed here and the repo is private, so CI results
  can't be read from this machine. Reproduce the workflow locally instead.

### The Playwright smoke test runs the last build, not the source
- **What happened:** after merging Overview → Analytics into Operations
  (7.24.0-beta), the updated smoke test failed with the Analytics menu entry
  still on the page. `playwright.config.ts` serves `vite preview`, which is
  whatever is in `dist/`. The test was checking the previous build.
- **Trap:** the reverse case is silent: a test that still passes against a
  stale `dist/` says nothing about the change. Run `npm run build` before
  `npm run test:smoke`. The build also rewrites
  `src/generated/restApiCatalog.generated.ts` when routes have been added
  since it was last committed; that drift is not part of a UI change.

### The external edge certificate, run on the live stack: what it showed
- **What was run:** root admin chose `external` for the HTTPS listener,
  requested a CSR, a throwaway CA outside the KMS signed it, it was
  installed, and the stack was fully stopped and started. Envoy served the
  same serial from the emptied tmpfs, `edge_tls_certificate_restored` was
  audited, the certificate certs had issued was revoked as `superseded`,
  and switching back to `runtime` discarded the kept key.
- **Trap:** the first two installs were refused with `bad_chain`, both
  correctly, and the message did not say why. A CA made by `openssl req
  -x509` without `basicConstraints=CA:TRUE` is not an issuer; and macOS's
  LibreSSL signs `openssl x509 -req` with SHA-1 unless `-sha256` is given,
  which Go rejects. A customer hitting either sees only "the first chain
  certificate did not sign the certificate". Open: name the cause in the
  refusal (not a CA, or a signature algorithm that isn't accepted).
- **Secret exposed:** asked how to grant admin access, the owner typed the
  admin password into the chat. A question that needs a secret must not be
  answerable in free text: ask the owner to create the file first and only
  confirm it exists (docs/SECURITY/SECRET_HANDLING.md, Incidents).

### A deploy script that builds "what is checked out" can ship an old release for days
- **What happened:** the owner reported `deploy-local.sh` deploying 7.15.0
  while main was at 7.21.0. Sessions had been committing from throwaway
  worktrees and pushing; the checkout the deploy runs from was never moved,
  and it also held stale pre-commit copies of files that had since been
  pushed (they still said 7.15.0). The script read `VERSION` from that
  checkout and reported nothing odd.
- **Fix:** `deploy-local.sh` fetches and fast-forwards to `origin/main`,
  re-executes itself, and when it can't it names the version it deploys and
  why. The closing message prints version and commit.
- **Rule:** a session that pushes from a worktree leaves the main checkout
  behind. Before telling the owner a change is live, compare
  `git rev-parse HEAD` in the deploy checkout with `origin/main`. Stale
  uncommitted files there are checked against origin by hash and file time,
  saved as a patch, then replaced; never left for the owner to trip on.

### "Revoke what you replace" needs the thing being replaced on day one
- **What happened:** 7.22.0-beta made certs record each edge certificate it
  issues and revoke the one before it. Checked on the live stack after the
  upgrade, the record was empty: the certificate in service predated the
  record, so its replacement would not have revoked it.
- **Rule:** a tracker introduced by an upgrade adopts the state that already
  exists (here: look the served certificate up by serial). The unit test
  started from a fresh fixture and could not see this; the live check did.

### install.sh never got the volume layout start-kms.sh prepares
- **What happened:** internal mTLS (1.9.0-beta) added the `infra-tls`
  subdirectories and the `platform-state` owner to `start-kms.sh` only.
  `install.sh` starts the stack with its own `compose up`, so a fresh
  install failed at the first daemon with a subpath mount.
  `scripts/test-volume-repair.sh` now reproduces that failure and the fix.
- **How it slipped through:** two scripts each prepared volumes with their
  own copy of the steps, and every test of the change ran through
  `deploy-local.sh`, which uses `start-kms.sh`.
- **Rule:** one function per bootstrap step, called by every path that
  starts the stack (`prepare_shared_volumes` in
  `infra/scripts/compose-volumes.sh`). `install.sh` resets all data, so it
  can't be tried on a developer's stack: its steps need a test that runs
  without it.

### A Compose volume option does nothing if a script creates the volume first
- **What happened:** the owner pasted four `docker compose up` warnings:
  `volume "…_runtime-certs" already exists but was not created by Docker
  Compose` (also `infra-tls`, `platform-state`, `certs-key-data`). The start
  and install scripts ran `docker volume create` before `compose up` so a
  helper container could set owners and seed the CRWK passphrase. A volume
  made that way has no Compose labels, and Compose uses an existing volume
  as it finds it: it warns and ignores the `driver_opts` in the compose
  file. `runtime-certs` is declared tmpfs there. On every scripted install
  it was an ordinary on-disk volume holding the edge, KMIP and Envoy-client
  private keys.
- **How it slipped through:** the tmpfs claim was in three places
  (`docker-compose.yml`, `RUNTIME_CONTROL_FLOW.md`, a note in the certs
  protocol schema) and nothing checked the mounted filesystem. The warning
  that pointed at it printed on every start and was read as noise. A later
  feature then came to depend on the bug: the external edge certificate
  (6.13.0-beta) kept its only copy of the key on `runtime-certs`, and its
  tests passed because the test directory, like the real volume, persisted.
- **Fix:** scripts create volumes with Compose's labels and never create
  `runtime-certs`. `start-kms.sh` repairs an existing install once
  (`infra/scripts/compose-volumes.sh`). Certs keeps an external certificate
  on the certs key volume and restores it into tmpfs at start.
- **Rule:** a storage property stated in a doc or the compose file (tmpfs,
  read-only, encrypted) is checked where it takes effect: `mount` inside the
  container, not the YAML. `scripts/test-volume-repair.sh` reads the
  `runtime-certs` block from the real compose file and asserts the mount is
  tmpfs. Treat a warning that repeats on every start as a defect report.
- **Rule:** when a script must touch a Compose volume before `up`, create it
  with `compose_volume_create` (labels `com.docker.compose.project` and
  `com.docker.compose.volume`). `docker run -v name:/x` also creates a
  missing volume, unlabelled. Conformance `compose-volumes` enforces both.
- **Trap:** volume labels can't be changed. Adopting a volume means copy,
  verify, remove, re-create, copy back, verify; `docker volume rm` needs the
  containers removed, not just stopped.
- **Trap:** making a broken security property real can break what grew on
  top of the bug. Before enforcing tmpfs, list what writes to the volume
  and ask which of it can be regenerated.
- **Closed in 7.22.0-beta:** `install.sh` did not prepare the `infra-tls`
  subdirectories or the `platform-state` owner (entry above).

### Go keeps Authorization across a redirect to the same host on another port
- **What happened:** the repository scan follows the hosting API's redirect
  to its download host. Go's client drops `Authorization` only when the
  redirect leaves the original host name or its subdomains; the port is not
  compared, and a custom header (GitLab's `PRIVATE-TOKEN`) is never dropped.
- **How it was caught:** the redirect test used two servers on 127.0.0.1
  with different ports, and the second one received the token.
- **Rule:** when a credential rides on a request that may be redirected,
  use `Authorization` only and delete it in `CheckRedirect` whenever
  `req.URL.Host` differs from the first request's. Test with a redirect
  between two servers and assert what the second one received.

### A stand-in server proves what you send, not that the provider accepts it
- **What happened:** the hosting API tests serve an archive at the path and
  with the header the code builds, which only shows the code is consistent
  with itself.
- **Rule:** for a third-party API, add an opt-in live test
  (`VECTA_TEST_LIVE_GIT=1`) against public endpoints and run it before
  shipping. It was run for GitHub, GitLab, Bitbucket and Codeberg. Say in
  the change what was verified live (public repositories) and what was not
  (tokens against real private repositories).

### Fake fixed: posture's "baseline" was yesterday, its score was event volume, and most signals counted nothing
- **What happened:** the owner asked how many events posture needs for a
  baseline. There was no baseline. Each signal was compared with the previous
  24 hours, so a new install raised "spike" findings on day one. With no
  finding the risk score was `events / 200`, so a busy healthy tenant scored
  as risky. The audit sync took the newest 500 events a minute and dropped
  the rest. And the signal patterns (`auth.login_failed%`, `key.delete%`,
  `cert.expiry%`, `result IN ('failure', ...)`) matched almost nothing the
  platform emits: subjects carry an `audit.` prefix, key destruction is
  `audit.key.destroyed`, and raw publishes have no result, which the audit
  service defaults to `success`. Failed logins had always counted zero.
- **How it slipped through:** every test fed the engine hand-made events
  shaped to match the patterns (`auth.login_failed`, `result: failure`), so
  the tests proved the patterns against themselves. Nothing compared a
  pattern with a subject a service really publishes. A score always
  appeared, so the page looked alive. My first version of the corrected
  catalogue repeated the mistake: four of its subjects came from test files.
  `TestSignalSubjectsAreEmitted` caught them.
- **Rule:** a detection is only as real as its input. A signal's subjects
  are checked against the non-test source of the services that emit them, by
  a test. A comparison needs a stated minimum history (days covering the
  weekly cycle, and events for a rate) and reports "not assessed" until it
  has it. An event count alone is never the gate. A score never falls back
  to activity volume. Details: docs/SECURITY/POSTURE_BASELINE.md.
- **Trap:** `grep -h ... | grep -v _test` filters lines, not files. Once
  `-h` drops the file names, nothing is left to filter on, and test fixtures
  come back as "emitted subjects". Exclude test files with `--exclude`.

### A rescan erased every asset review
- **What happened:** discovery stored an operator's review ("accepted risk",
  notes) in the asset's `status` and `metadata`, the same columns every scan
  rewrites with what it observed. The next scan reset the review to
  `active` and dropped the notes. The review value also flowed into the CBOM
  as the key's status.
- **How it slipped through:** the review test checked the row right after the
  review and never scanned again. One column held two things: what the
  scanner saw and what a person decided.
- **Rule:** a person's decision and a machine's observation never share a
  column. A test of anything a person records must run the job that
  rewrites the record afterwards and read it back
  (`TestReviewSurvivesRescan`).

### A scan that answers in the request times out as soon as a source is slow
- **What happened:** `POST /discovery/scan` returned `202 Accepted` but did
  all the work before answering. The HTTP server's 60-second write timeout
  and the 30-second cloud call meant one slow account failed the request
  while the scan kept running, and an address range could not fit at all.
- **How it slipped through:** every test used one loopback endpoint and
  finished in milliseconds. The status code said "accepted" while the code
  behaved as "done".
- **Rule:** work whose duration depends on someone else's network runs in
  the background with a deadline, records progress as it goes, and refuses
  a second run instead of stacking them. A row left "running" by a restart
  must read as interrupted, derived from its start time, never stay
  "running" forever.

### Counting in the browser is still a sample, even when the cap is 10000
- **What happened:** the first version of the new discovery charts counted
  in the browser over the assets it had loaded, and the service's own
  summary read the newest 10000 rows. Both look exact until a tenant has
  more assets than the cap; a /24 sweep, a few cloud accounts and a
  certificate estate reach it.
- **How it slipped through:** the rule (7.17.0-beta, above) was written for
  time windows, and an inventory has no window, so it did not look like the
  same case. It is: a list with a cap is a sample.
- **Rule:** the service counts with one predicate and lists with the same
  one (`AssetFilter.match`), streaming every row. A test puts more rows
  than any old cap in the store and checks the count
  (`TestInventoryIsNeverASample`), and another checks every chart number
  against its list (`TestSummaryCountsEqualFilteredLists`).

### Two status colours that pass in one theme can merge in the other
- **What happened:** "weak" was orange and "quantum-vulnerable" amber. In
  the light theme the two tokens are `#b8500f` and `#a86400`: a colour
  difference of 5.4, below what full colour vision separates, and 0.7 for
  red-green colour blindness. The first screenshot showed two legend
  entries that looked the same.
- **How it slipped through:** the tokens are tuned as text colours (dark
  enough to read on white), which pushes neighbouring hues together. Nobody
  looks at a legend in both themes.
- **Rule:** chart fills are their own tokens (`--cls-*`), chosen per theme
  and checked with a palette validator for colour-blind and normal-vision
  separation. Text colours are not reused as fills. Look at the rendered
  page in both themes before calling a chart done.

### `pemLine` gave every certificate in a chain the first one's line
- **What happened:** the code scan found a PEM block's line by searching the
  file for its `BEGIN` marker from the top, so the second and third block of
  the same type reported the first one's line, and their asset IDs (which
  include the line) depended on it.
- **How it slipped through:** the test file held one key.
- **Rule:** locate a parsed item by the offset the parser was at, never by
  searching again for text that can repeat (`TestFindMaterialFormats`).

## 2026-09-30

### A chart window longer than a page must be counted by the server
- **What happened:** the owner asked for analytics windows from a day to a
  year and since uptime. The Activity charts paged the newest 2000 audit
  events into the browser and counted those, and the alert statistics read
  the newest 5000 alerts. At a week that is fine; at a year it charts a
  sample and labels it the total.
- **How it slipped through:** with short windows the sample was the whole
  window, so the numbers looked right in every test and demo. The
  "window has more" badge existed but nothing forced a real count.
- **Rule:** a chart's numbers come from the service that owns the data,
  counted over the whole window in SQL or a streaming scan. The browser
  never aggregates a sample. When something must stay bounded (MTTD's
  per-alert audit lookup), the response says how much it measured, and the
  UI shows it. Time buckets for the whole window use portable SQL: one
  `SUM(CASE WHEN ts >= start_k ...)` column per bucket, with differences
  giving each count. `date_trunc` and `strftime` are dialect-specific.

### Fake fixed: client key rotation returned a key that never worked, and audited success
- **What happened:** `RotateClientAPIKey` updated
  `auth_client_registrations.api_key_hash`, but `/auth/client-token`
  validates against `auth_api_keys`. The new key was dead, the old key
  stayed live, and `audit.auth.client_key_rotated` said `success`. Revoking
  also left the key row, although the status check happened to block it.
- **How it slipped through:** two tables hold key hashes, and the test
  called `RotateClientAPIKey` and checked only that it returned no error.
  Nothing exchanged the rotated key for a token. The UI never called rotate,
  so no one saw it fail.
- **Rule:** a credential operation's test must use the credential: after
  rotate, the new key gets a token and the old one gets 401. When two
  tables carry the same secret, find the one the verifier reads
  (`GetAPIKeyByHash`) and write that one.

### A concurrent session's commit swept in my in-progress doc edits
- **What happened:** while I was rewriting `docs/API_REFERENCE.md` in the
  shared checkout, another session committed that file as part of
  458de9a7b. Half my edits shipped under its message. The generated route
  index I refreshed also listed a route that existed only in that session's
  uncommitted code.
- **Rule:** when another session is active, do multi-step doc edits in a
  worktree from the start, not only at commit time
  ([[feedback_concurrent_session_staging]]). Regenerate generated files
  (`docs/generated/`, the route index) in the clean worktree, never in the
  shared checkout.


### Charts must drill into the entries they count, and a server clamp had hidden most alerts
- **What happened:** the owner asked that clicking any graph or bar show the
  entries behind it, and that each chart live beside its entries (audit
  charts in the Audit Log, alert charts in the Alert Center). Building the
  alert drill-down meant listing the same alerts the statistics count. That
  exposed a bug: `AlertStats`, `MTTRStats`, `MTTDStats` and `TopSources`
  asked the store for 5000 alerts, but `SQLStore.ListAlerts` reset any limit
  over 1000 to 100. Every alert chart, the MTTR figure and the report
  summaries counted only the newest 100 alerts, while the UI called the
  result the total.
- **How it slipped through:** the clamp belonged to the HTTP page size but
  lived in the store, which every internal caller shares. Nothing ever
  compared a statistic with the rows behind it, and test data never had more
  than 100 alerts. A chart you can't click into can be wrong silently.
- **Rule:** every chart segment is clickable and lists exactly the entries
  it counts, through one predicate shared by the chart and the drill-down
  (`components/v3/chartDrill.tsx`). When a chart comes from a server
  aggregate, the drill-down reads the same set the aggregate reads, so a
  mismatch shows up on screen. Page limits belong to the HTTP handler, not
  the store. `TestAlertStatsCountBeyondOneHundred` covers the clamp.
- **Test trap:** Playwright clicks the centre of an element's bounding box,
  and for a donut slice that is the hole, so the SVG takes the click.
  Dispatch the click on `.recharts-pie-sector path` instead.

### Fake removed: the DevSecOps / IaC tab advertised a Terraform provider, SDKs and a sidecar that never existed
- **What happened:** the tab was about 1,000 lines of hard-coded snippets
  with no API calls. It showed install commands for four SDKs and a
  registry provider, a sidecar image, dead buttons, and a REST table with
  unregistered routes. It looked like product documentation, so nobody
  checked that any of it existed.
- **How it slipped through:** `real-capability` conformance looks for
  `mock*`/`fake*`/`simulate*` functions and `Math.random`. A static page of
  code samples naming non-existent packages trips none of those. The product
  map showed it with **0 API calls**, and that was the tell.
- **Rule:** a dashboard tab with zero backend calls is documentation, and it
  belongs in the Documentation tab and `docs/`. Every package, image, route
  and field a doc names must be found in the repo first (`grep` the route
  registration, the request struct's JSON tags). Two more drifts turned up
  while checking: login returns `access_token`, not `token`, and a client
  token's `kms.read`/`kms.write` only reach the `secrets` domain
  (`pkg/route.CoarseDomains`), so a registered REST client cannot rotate
  keys.


### Never again: resetting a shared doc in a checkout another session is using
- **What happened:** after pushing 8f0dd192c from a worktree, I ran
  `git checkout HEAD -- <my files>` in the shared checkout. The list
  included CHANGELOG.md, learning.md, API_REFERENCE.md and
  AUDIT_EVENTS_2026-09.md, which another session had just edited. Its
  uncommitted entries were destroyed and it had to re-add them (4c08e84da).
- **How it slipped through:** a pre-check printed "DIFFERS" for those four
  files, but the loop kept going. CLAUDE.md already forbids scratch resets
  in a dirty tree; a checkout of named files is the same thing.
- **Rule:** never run `git checkout --`, `git restore` or `git reset` on a
  file in the shared checkout. Commit and push from a worktree, then only
  `git merge --ff-only` in the shared checkout once it holds none of your
  edits. If it does, wait or ask; don't reset.

### A name check for "internal" would have blocked auth.example.com
- **What happened:** the first draft of the platform-host check matched a
  target's first DNS label against the service names. `auth`, `certs`,
  `cloud`, `backup` and `policy` are ordinary customer hostnames, so it
  would have refused `auth.example.com`.
- **Rule:** refuse only bare platform names at input. Catch everything else
  by address: resolve the platform's hostnames and compare them with the
  address the dialer actually connects to.

### The last unaudited refusal was in the middleware every service shares
- **What happened:** after 7.10.0-beta, kernel services audited token
  refusals, but `MustWrap` still answered 401 silently for the rest. The
  gap sat in shared middleware, so every service's own refusal tests missed
  it.
- **Rule:** middleware that refuses a request takes an audit emitter and
  emits the refusal (`request_refused` with its reason); a refusal that
  happens before any handler is still a refusal.


### One label for two facts hides the one that matters
- **What happened:** the catalogue reported "weak" and "quantum-vulnerable"
  as one class, `vulnerable`. Discovery showed an ECDSA-P256 certificate in
  red beside RSA-1024, and its "Quantum-vulnerable" card counted weak
  algorithms. The catalogue already kept `Weak` and `QuantumVulnerable` as
  separate flags; only `Assess` merged them. pqc even had a `weak` branch
  that never fired.
- **Rule:** a class is a fact the reader acts on. Don't fold two facts with
  different urgency into one label. When a stored label is derived, derive
  it on read so a catalogue change never leaves stale rows.

### An SSRF guard on the hostname is not a guard
- **What happened:** adding tenant TLS targets needed a block on loopback and
  metadata addresses. Checking the typed host alone misses a DNS name that
  resolves, or rebinds, to 127.0.0.1 or 169.254.169.254.
- **Rule:** check the literal when it's added, for a clear error, and check
  the resolved address in the dialer's `Control` hook, which sees what is
  actually dialled.

### A refusal before the kernel is a refusal nobody audits
- **What happened:** `pkg/jwtauth.MustWrap` returned 401 before the route
  kernel ran, so a missing or forged token on a kernel service left only the
  generic request log, not `audit.<service>.<action>`.
- **Rule:** in front of a kernel router, verify the token and pass the
  outcome on (`route.WithInvalidToken`); let the kernel refuse. Only a
  request that matches no route is refused before it, because there's no
  action to audit it under.


### Never again: a working service with no page, and a tenant check with no token
- **What happened:** Workload Identity, Confidential Compute and Discovery ran
  in every deployment with no dashboard page. Two UI cleanups (f8e7162c4,
  1980954dd) removed the tab registration or the tab holding the view, and
  left the backend, the feature flag and the module gate in place, so nothing
  failed. The owner noticed only because the cluster replication profiles
  still listed them.
- **Also found:** discovery called `tenantcheck.Enforce`, which returns nil
  when there are no claims in the context. The service had no JWT middleware,
  so the check never ran, and the code read as if it did.
- **How it slipped through:** no check ties a deployed feature to a page.
  `Enforce` fails open by design (for service-internal calls), so it proves
  nothing unless something verifies the token first.
- **Rule:** when you remove a tab, either remove its feature or move its view
  (CLAUDE.md "One home per view"). Treat a tenant check as real only when a
  verified-JWT layer (`pkg/jwtauth`) sits in front of it. The route kernel
  gives both, because it refuses a request that has no claims.


### Never again: an internal call without a service token (enforced)
- **What happened:** the Alert Center was empty because reporting read
  audit with no token (7.6.0-beta). Once `service-token` checked every
  client, it found nine more doing the same: compliance → certs and policy,
  dataprotect/discovery/kmip/sbom → certs, hyok → policy, pqc/sbom →
  discovery. Each of those reads was refused and treated as "no data".
- **Why a learning wasn't enough:** 7.6.0-beta's entry said "grep every
  client". Nobody did, and the next check found nine. A rule only holds if a
  check fails the build.
- **Enforced by:** `make conformance` `service-token`. Every
  `services/*/*client*.go` that builds an HTTP request calls
  `servicetoken.Authorize`, or carries a `servicetoken-exempt:` comment
  naming the credential it uses instead (the caller's own verified token,
  or workload's shared secret).
- **Also:** after fixing a service, rebuild it and check the live result
  (logs and audit trail), not only the tests. The 7.7.0-beta fix sat
  undeployed until the owner asked.

### `return empty, nil` on an upstream error is a fake result
- **What happened:** compliance scored posture and listed anomalies over zero
  events whenever audit refused it, and asked audit for a reporting route, so
  alert stats were always empty.
- **How it slipped through:** each fetch helper swallowed its error "to keep
  the page up", so every failure looked like a quiet tenant and nothing
  failed.
- **Rule:** a fetch helper returns its error; the caller decides, and a
  computed score fails rather than using missing data.

### Fixing one client of a service leaves its siblings broken
- **What happened:** the Alert Center was empty for every tenant. Reporting's
  audit client never sent a service token. When audit started requiring a
  JWT, every alert sync got `401 unauthorized` in plain text and logged it
  as `invalid character 'u'`, a JSON error that hid the refusal.
- **How it slipped through:** when posture moved onto the route kernel,
  reporting's posture client got `servicetoken.Authorize` and a test, but
  the audit and compliance clients next to it didn't get the same review.
  The sync error only went to the log, and the empty tab looked like "no
  alerts yet".
- **Rule:** when a service starts refusing tokenless callers, grep every
  client of it (`<service>_client.go` in each caller) and add the token and
  a test to all of them in the same change. Check the status before
  decoding an error body: gates may answer in plain text.

### A feature that sounds like security isn't a security feature
- **What happened:** the AI gateway shipped for months as "prompt-injection
  protection" and "encrypted" provider keys. It was a list of regexes, and the
  keys sat in plaintext under a schema comment saying `encrypted at rest`.
- **How it slipped through:** it lived on the route-kernel burn-down list,
  so it never got per-route audit or permission review, and nobody asked
  whether content inspection belonged in a KMS at all. The comment was
  trusted instead of the store code.
- **Rule:** ask "is this a key, secret, identity or signature job?" before
  hardening a feature. If not, cut it (CLAUDE.md). Check an "encrypted"
  claim by following the value into the `INSERT`.

### Authenticated is not authorised: dataprotect's second gap
- **What happened:** after 7.2.0-beta closed the tokenless hole, a readonly
  token could still change dataprotect's policy, delete vaults, detokenize or
  complete a wrapper registration. The service was on the route-kernel
  burn-down list, so no route declared a permission.
- **How it slipped through:** the burn-down list records "not migrated yet",
  and nothing forced the question "what does a low-privilege token reach
  meanwhile?". Fixing authentication alone looked like the whole fix.
- **Rule:** when closing an authentication hole in a service on the
  burn-down list, move it onto the kernel in the same stretch of work, and
  test a low-privilege token against its writes
  (`TestDataProtectRoutesNeedTheirPermission`).

### A documented parameter the code never read
- **What happened:** the API reference said decrypt and verify accept a key
  version, but `RunCryptoTx` always loaded the current version. After any
  rotation, ciphertext and signatures from older versions could not be
  processed through `/decrypt` or `/verify`, and "rotation keeps old versions
  for decryption" was true only in the database.
- **How it slipped through:** every test encrypted and decrypted under the
  same version; none rotated between the two. The doc was written from the
  intended design, not from the handler's request struct.
- **Rule:** a test of any versioned operation rotates between producing and
  consuming the data. Document a request field only after reading the struct
  that decodes it.

### Progress inferred from aggregate counts is not progress
- **What happened:** keycore migration plans measured progress as "live keys
  on the source algorithm now" against the count at creation. Deleting a key
  counted as migrated; creating one moved progress backwards; nothing linked
  a plan to the keys it covered.
- **Fix:** removed; the pqc engine tracks each key as a step with its own
  outcome. Progress is measured per item that was actually changed.
### "Authenticates per-route" was a comment, not code: dataprotect was open
- **What happened:** dataprotect booted with `SkipJWT` and a comment saying
  "operator APIs validate platform JWTs in handlers". No handler did.
  `mustTenant` calls `tenantcheck.Enforce`, which skips when there are no
  claims, so a request with no token passed every check. A tokenless
  `POST /fpe/encrypt` returned ciphertext through the public gateway route.
- **Knock-on:** 6.0.0-beta delegation was documented as done for dataprotect,
  but `delegation.Attach` found no verified token and silently sent every
  call as the bare service. Its tests fed a token straight into the context,
  so they never went through the way requests actually arrive.
- **How it slipped through:** `SkipJWT` is a documented burn-down exception,
  and its justifying comment was trusted rather than tested. No test sent a
  request without a token.
- **Rule:** a service that opts out of the platform JWT middleware needs a
  test that a tokenless call to a crypto route is refused
  (`TestUnauthenticatedRequestsAreRefusedAndAudited`). A delegation claim
  needs a test that runs from the HTTP entry point to the keycore call
  (`TestVerifiedTokenReachesTheService`), not one that puts the token into
  the context by hand.

### Finish or discard: a half-done removal sat uncommitted for a day
- **What happened:** a session deleted the payment service in the shared
  checkout (108 files, about 14,600 lines) but never documented, versioned or
  committed it. Meanwhile `main` moved on by 23 commits.
- **Also found:** the session had rewritten a standing rule in CLAUDE.md
  (moving cut features to KMSExtension) without a recorded owner decision.
- **Rule:** a change that removes a product surface is finished in one sitting
  (code, docs, version, commit) or not started. Never edit CLAUDE.md rules
  without the owner's words in the same change.

### An "open item" can be a rule, not a gap
- **What happened:** the automation guide listed XMSS/LMS as "not
  implemented", inviting a software implementation. NIST SP 800-208 requires
  those keys to be generated and to sign inside a hardware module, so
  building them in keycore would have made the product non-compliant.
- **Rule:** before building an open item, check whether the standard
  forbids the obvious place to build it; record the decision
  (docs/DECISIONS.md) instead of leaving it as "open".

## 2026-09-30

### Removing a check leaves its input behind
- **What happened:** 5.4.0-beta removed the minimum-tier check, but the
  posture field it read stayed parsed in `posture_controls.go`, still
  suggesting governance supplies it.
- **Rule:** when a check goes, remove the field that fed it in the same
  commit (grep for readers of the field, not just the check).

## 2026-09-30

### A service that learns tenants from its own tables never sees a new one
- **What happened:** reporting's scheduled alert sync listed tenants from
  its own tables. A tenant with no alert, rule or channel was never synced,
  so its first threat alert waited until someone opened its Alert Center.
- **Rule:** a job that must cover every tenant gets the list from auth, the
  owner of tenants, through a caller-restricted internal route, and falls
  back to what it knows when auth is down.

### Fix the pattern, not the instance (sbom bootstrap-on-read)
- **What happened:** 1.37.0-beta removed the first-read snapshot generation
  from `ListCBOMHistory` but left the same `"bootstrap"` generation in
  `GetLatestCBOM`, `GetLatestSBOM` and `ListSBOMHistory`.
- **Why it slipped through:** the fix targeted the one function named in the
  open item instead of grepping for the pattern (`"bootstrap"`).
- **Rule:** when fixing a bug class, grep for every instance and test each
  read path's empty case.

### A fail-open switch survives the fix for its sibling
- **What happened:** 6.10.0-beta made HYOK key-access checks fail closed and
  said `HYOK_POLICY_FAIL_CLOSED` "governs only the policy engine". The
  switch still let an outage of the policy service become an allow, and
  that refusal path emitted no audit event.
- **Why it slipped through:** the fix was scoped to key access. The setting
  defaulted to `true`, so it looked safe, and the fail-open branch was never
  tested.
- **Rule:** when one dependency check is made fail closed, grep the same
  service for every `fail_open` / `FAIL_CLOSED` branch and remove them
  together. A customer-settable outage-becomes-allow switch isn't a choice
  we offer.

### A state table only protects the paths that consult it

`lifecycle_state.go` said a compromised key could only be destroyed, and the
docs quoted it, but only the automatic suspend called `CanTransition`.
`SetKeyStatus` and `ConfigureKeyActivation` each wrote status directly, so
compromised → active worked from the API and from playbook `activate_key`.
The second path was easy to miss: `activate_key` calls `/activate`, which
goes through activation, not `SetKeyStatus`. When a rule lives in a table,
find every writer of the column (`store.SetKeyStatus`, `SetKeyActivation`)
and put the check in front of each, with a test per path.

### A create-only apply against a unique key is a one-shot, not a reconciler

The tenant reconciler "applied" manifest policies by POSTing them every
tick. The unique (tenant, name) index turned every tick after the first into
a 400, and because the error was only logged the controller reported healthy
while manifest edits were silently dropped. A declarative controller must
read current state and diff (create / update / no-op), and its failures must
reach the controller's status, not the log. The fix matches on the key the
store is unique on (`metadata.name`), not the manifest's own `id`.

## 2026-09-29

### A field on a record isn't a field of every record
- **What happened:** the plan for keycore's public-key route was "return
  `KeyVersion.PublicKey`". Only HSM key pairs fill it. A software key pair
  (every EKM TDE key: RSA-3072) stores only its encrypted PKCS#8 private
  key, so the field is empty and the route would have refused the keys it
  was built for. The route derives the public half from the private
  material instead, and the test compares the result with the stored
  private key's own public key, not just "it parses".
- **Also found:** ekm's public-key getter served its cached copy first.
  After a rotation that copy was the previous version's key, and serving it
  skipped keycore's decision for the user. A cache in front of a
  decision is a second decision; the getter now always asks keycore.
- **Why it slipped through:** the ekm keycore fake returned
  `public_key_pem` from `GET /keys/{id}`, which the real keycore never did,
  so no test could see that there was no route to read a public key. **Rule:**
  a fake answers only what the real route answers (compare with
  `renderKey`), and the HTTP client gets a test against the real response
  and error shape.

### A setting with a default and no reader looks like a feature
- The EKM agent's `rotate_path` had a config field, an env override and a
  per-mode default, but no code used it. Found while removing the dead
  export path (6.15.0-beta). **Rule:** a config field is removed with the
  last code that reads it.


### A client of a route nobody registered fails quietly for ever
- **What happened:** the EKM agent's local key cache fetched
  `GET /ekm/tde/keys/{id}` and then `POST .../export`. The EKM service never
  registered either route, and TDE keys have no export setting. The failure
  was logged as "will use remote" and start-up carried on, so the feature
  looked optional rather than broken. `Encrypt`/`Decrypt`, which read the
  cache, had no callers, so no test ever reached the export.
- **How it slipped through:** `check-doc-routes.py` checks that routes named
  in docs and OpenAPI are registered, but not routes a Go client builds with
  `fmt.Sprintf`. A dashboard guide and a sample described the feature as
  working.
- **Fix:** the path is removed. The TDE key stays in the KMS, which is also
  the stronger design. `TestAgentCallsOnlyRegisteredEKMRoutes` checks every
  agent path against the EKM route table.
- **Rule:** a client that calls another service gets a contract test against
  that service's route table. A fallback that swallows "route not found" is
  a bug report nobody reads.


### A "dev" fallback in a production code path is the production behaviour
- **What happened:** KMIP's TLS loader returned a self-generated
  development config, with `RequireAnyClientCert`, whenever the configured
  certificate files failed to load, for example if KMIP started before
  certs wrote them. KMIP takes the caller's identity from the client
  certificate, so for that run any certificate was accepted unverified.
  Nothing logged it. A configured CRL that failed to load was skipped the
  same way.
- **How it slipped through:** each fallback looked like a convenience for
  local runs, and compose always set the file paths, so nobody saw the
  failure branch. It turned up only because making the KMIP certificate
  choosable meant reading the loader.
- **Rule:** a security listener has one config path. A missing input waits
  or refuses to start; it never swaps in a weaker config. Grep for
  `dev`/`fallback`/`Any` in TLS setup when touching a listener.

### A probe list built from a filtered list can't find what the filter removed
- The edge probe measured `svctls.ServerGroups(pqc-preferred)`, which drops
  X25519 in FIPS mode. So even after the hand-built hello made X25519
  measurable, it was never probed with FIPS on. Only the real Envoy test in
  FIPS mode showed it. **Rule:** a measurement's input list is the fixed
  universe (`svctls.ProbeGroupsAll`), never a policy's output.

### Envoy's SDS watch needs a rename it can see
- `watched_directory` reloads on a move into the directory. certs renames
  atomically, and on a Linux named volume Envoy sees `MOVED_TO`. A macOS
  bind mount delivers the same host rename as `CREATE`/`MODIFY`, so the
  real Envoy test waited forever for a reload. Checked with `inotifywait`
  in a container: bind mount no, named volume yes. The test now uses a
  named volume and copies with a rename, as compose does.

### An upload that verifies a key and then drops it
- `POST /certs/upload-3p` checks that the private key matches the
  certificate, then stores only the certificate. So no uploaded certificate
  could ever be served. The edge takes the other route: the node makes its
  key and a CSR, and only the certificate travels.
### A fallback for missing key material becomes the only path when the source never had it
- **What happened:** ekm's TDE public key getter and key creation fell back
  to `buildPublicKeyFallback`, `"EKM-PUBLIC-"` plus a hash of tenant and key
  ID, when keycore's key metadata had no public key. Keycore's
  `GET /keys/{id}` never returns one, so every EKM TDE key got the invented
  value, which was stored as `format: opaque` and audited as a successful
  access. Removed in 6.12.0-beta: the endpoint refuses with
  `424 public_key_unavailable`, audits the refusal, and migration 007 clears
  the stored values.
- **Why it slipped through:** the test keycore fake always returned a PEM
  public key, so no test ever reached the fallback, and nothing checked the
  fake's response shape against keycore's `renderKey`. The name "fallback"
  and the `opaque` format label made an identifier hash read like a key
  encoding. The dashboard only read the algorithm from the response, so no
  one looked at the key. Conformance's crypto-import rule does not list
  `crypto/sha256` (hashing is allowed in services), so nothing flagged a
  hash standing in for key material.
- **Rule:** a test fake of another service answers with that service's real
  response shape, including the fields it doesn't return. A value presented
  as key material comes only from the key's owner; when it isn't there, the
  answer is a refusal, never a stand-in.

### An "open item" in the docs is not a fix, and a store is the only safe place to seal
- **What happened:** the workload service kept every tenant's SPIFFE root
  CA and JWT-SVID signer private keys as plaintext PEM. It was listed under
  "Open" in two releases (6.8.0, 6.9.0) while the rule it broke (CLAUDE.md
  rule 6) was already enforced for six other services. Fixed in 6.11.0-beta.
- **Why it slipped through:** `pkg/mek` covered services that already
  envelope-encrypted something (the catalog listed tables with a wrapped
  DEK). A service that stored secrets in plain `TEXT` had no wrapped-DEK
  column, so nothing flagged it; the `json:"-"` tags kept the keys out of
  API responses, which made the storage look handled.
- **Rule:** grep new tables for private keys, tokens and passwords in
  `TEXT` columns, not only for wrapped DEKs. Seal in the store (the one
  place every read and write passes), never in handlers. When plaintext
  existed, a backup is also a copy: `mek.Table.Plaintext` makes governance
  refuse to capture it. Also: `ADD COLUMN IF NOT EXISTS` doesn't parse on
  SQLite; plain `ADD COLUMN` is safe because `schema_migrations` applies a
  file once, and it lets the same migration run the SQLite test.

### An optional dependency needs a deployment signal, or its callers fail open
- **What happened:** ekm, cloud and hyok allowed key operations whenever
  keyaccess returned an error, because keyaccess is optional (compose
  profile `key_access_justifications`) and compose set `KEY_ACCESS_URL` for
  them unconditionally. "Not deployed" and "down" looked the same, so the
  callers chose the convenient answer. Fixed in 6.10.0-beta: compose passes
  `COMPOSE_PROFILES` as `VECTA_DEPLOYED_PROFILES`, and `pkg/keyaccess.Gate`
  allows only when the profile is known to be off.
- **Why it slipped through:** a URL looks like a deployment signal but isn't
  one when compose sets it for every profile. hyok's fail-closed switch was
  named for the policy engine, so it read as covering key access too.
- **Rule:** a caller of an optional service reads whether it is deployed
  from the deployment itself. Unknown fails closed, and "not deployed" is
  recorded as the reason on the allowed operation.

### A client that never authenticates turns a fail-open fallback into the normal path
- **What happened:** `pkg/keyaccess.HTTPClient` never set an
  `Authorization` header, while keyaccess wrapped every route in
  `jwtauth.MustWrap`. Every evaluation from ekm, cloud and hyok got 401.
  EKM and cloud map any error to `Action: "allow"` ("justifications service
  unavailable"), so key-access justifications were never enforced there,
  and nothing looked broken. Fixed in 6.9.0-beta.
- **Why it slipped through:** each side was tested alone. The keyaccess
  service had no tests, the callers stub `pkg/keyaccess.Client`, and the
  fail-open branch made a 401 indistinguishable from an outage.
- **Rule:** an internal client test asserts the credential it sends
  (`TestEvaluateSendsServiceToken`). A fallback taken on every call is a
  bug, not resilience; count or audit fallbacks so a 100% rate shows.

### A certificate is not a credential, and a registration ID is not an identity
- **What happened:** the workload token exchange accepted an X.509-SVID
  chain with no proof of possession (anyone who saw the certificate in a TLS
  handshake could exchange it), took `registration_id` from the body without
  checking it belonged to the verified SPIFFE ID (any SVID bought any
  workload's permissions), skipped the tenant's audience policy whenever the
  request named an audience, and used federated bundles with federation off.
  Found while deciding how the route authenticates without a bearer token,
  fixed in 6.9.0-beta.
- **Why it slipped through:** the route sat behind "no authentication at
  all" (the whole service was unauthenticated), so its own checks were never
  treated as the security boundary. There were no workload tests.
- **Rule:** when a route's credential is something other than a bearer
  token, list what that credential proves and bind every request field to
  it. Public data (a certificate, an ID) needs a signature; a selector in
  the body must match the verified subject.
### A settings page is not a listener
- **What happened:** System Administration > Interfaces let an admin set a
  bind address, port, protocol, "enabled" and a certificate source per
  interface, and said the TLS defaults were "applied to TLS-enabled
  interfaces". Keycore stored them; nothing else read them. Ports came from
  docker-compose, the edge and KMIP certificates from certs' runtime
  materializer, and Envoy's edge had no key-exchange setting at all, so it
  ran BoringSSL's defaults while the product showed a "Quantum Mode".
- **How it slipped through:** the feature looked complete from the UI and
  the API down to the table, with audit events and RLS. Nobody followed the
  value to the place that opens the socket. 6.4.0-beta removed one field
  (`pqc_mode`) and kept the rest of the record without asking the same
  question of it.
- **Rule:** before calling a listener setting real, find the code that
  builds the listener (`tls.Config`, Envoy's `DownstreamTlsContext`, the
  compose port) and show it reads the value; then prove the result with a
  handshake against the real server, not a check of the stored value. When
  one field of a record turns out to be fake, check every field.

### certs' observed-row upsert silently dropped two columns
- `UpsertMTLSObserved` wrote every column except `last_handshake_group` and
  `last_handshake_at`; the services report through a different statement,
  so nothing noticed until the edge probe needed them. Tests compared the
  fields they set, not what came back from the store. The edge tests now
  read the row back.

### A guard that returns early can hide the failure it guards
- **What happened:** `destroyHSMObjects` began with
  `if !resident || s.hsm == nil { return }`. The first condition means
  "nothing to do"; the second means "can't do it". Folding them into one
  early return made a destroyed HSM key with no connector look exactly like
  a software key: objects left on the token, no event. Found while building
  the destruction check (6.5.0-beta), fixed in 6.7.0-beta.
- **Why it slipped through:** the unreachable-HSM test set a connector
  pointing at a dead address, so the nil-connector branch was never run.
- **Rule:** in a guard clause, keep "not applicable" and "unable" apart.
  Only the first may return quietly; the second is a failure to audit.

### A reference guide drifts into a spec when nobody follows its examples to a route
- **What happened:** `docs/IDENTITY_AND_PQC.md` (3,100 lines) presented as
  product capability a SPIFFE agent with seven attestors, RFC 8693 exchange
  into AWS/GCP/Azure, TDX and SEV-SNP quote verification with server-issued
  nonces, 17 built-in justification codes enforced on keycore decrypt through
  an `X-Key-Access-Justification` header, and hybrid keys
  (`HYBRID_X25519_MLKEM768`, `hybridMode`, `componentKeyIds`) wrapping
  7-year backups and signing a hybrid root CA. None of it existed. Keycore
  refuses every algorithm containing `+`, certs refuses PQC certificates, and
  backups are AES-256-GCM. The same inventions were in `API_REFERENCE.md`.
  The page's real content (routes that exist) sat under field names and
  response shapes that didn't match the handlers.
- **Why it slipped through:** the guide was written as a vendor-style
  reference (complete schemas, sample responses with request IDs,
  compliance mappings), so it read as authoritative. Every later fix was
  scoped to one claim that surfaced elsewhere: 5.2.0 to 6.3.0-beta
  corrected the PQC endpoint stubs, so the page looked maintained. Nothing
  checks a doc's example bodies against handler structs:
  `check-doc-routes.py` only proves a named route is registered, and every
  route here was, while its request fields, headers and response keys were
  fiction. The PQC sizes table held pre-standard Dilithium numbers that
  looked plausible.
- **What following the data found:** tracing each claim to a handler turned
  up real gaps the old prose had covered over. The workload, keyaccess and
  most confidential routes verify no caller at all (legacy mux, tenant from
  a header, no gateway JWT filter). The workload CA key is stored as
  plaintext PEM. EKM and cloud allow the operation when the justification
  service is down.
- **Rule:** when auditing a doc, open the handler for every example, not
  just the route table. Check the decoded struct's JSON tags against the
  request body, the `writeJSON` keys against the response, and the
  middleware chain against "requires a bearer token". Background theory
  (what a TEE is, what Shor's algorithm does) stays; any sentence whose
  subject is "Vecta" or "the KMS" needs a caller. List removed claims at
  the bottom of the page so a reader who remembers them learns why they are
  gone.
### A "verified" label on a check that looked somewhere else
- **What happened:** `POST /keys/{id}/zeroize-verify` (263893d12, "stringent
  FIPS 140-3 posture") returned `zeroization_verified` from
  `ConfirmKeyMaterialZeroized`, which only asked whether the key cache had
  an entry and returned true when there was no cache. The cache holds
  `Key` metadata; material lives in `key_versions` and the HSM, which it
  never read. Worse, the success path was unreachable: destroy writes
  status `deleted`, the handler required `destroyed`, and `GetKey` 404s a
  deleted key. Nobody had ever received the answer. Replaced by
  `POST /keys/{id}/destruction-check` (6.5.0-beta).
- **Why it slipped through:** the doc comment quoted the standard
  ("satisfies FIPS 140-3 §4.9.2"), and a citation reads like evidence. No
  test called the route with a destroyed key, so neither the overclaim nor
  the dead path showed. The 5.3.0-beta cleanup removed the zeroization
  scheduler for doing nothing and explicitly kept this route ("stays")
  without following its data. The kernel migration then gave it a
  permission and an audit event, which made it look reviewed.
- **Rule:** a field named for a guarantee (`verified`, `zeroized`,
  `validated`) must name the thing it read. Follow the data to where the
  secret actually lives. Test the success path with the state the real
  lifecycle produces (here a key destroyed by `DestroyKeyImmediately`), not
  a status string typed into a fixture.

### A field that follows a removed policy is a dangling switch
- **What happened:** keycore's interface `pqc_mode` was added with the pqc
  tenant policy, whose default mode `inherit` resolved to. The only reader
  was the pqc inventory, which turned `inherit` into "hybrid" and reported
  that as the interface's key exchange. 6.3.0-beta removed the policy and
  made interfaces "not assessed", but the field, its column, its audit
  detail and its selector stayed, now pointing at nothing. The UI
  honestly said "Recorded only", which kept it from looking broken, and so
  from being removed.
- **How it slipped through:** "no listener reads it" was never checked when
  the field was added; an audit event (`pqc_mode` in
  `interface_port_upserted` details) and a Postgres column made it look
  like a control. The real listener setting, svctls `kx_profile`, was built
  later in a different tab and nobody joined the two.
- **Rule:** when a policy or reader is removed, `git grep` every field that
  refers to it and remove, preview or enforce each in the same change. A
  "recorded only" label is a to-do, not a resolution. Before building a
  per-listener setting, find the code that configures that listener's
  `tls.Config` or Envoy context; if it doesn't read the setting, the
  setting isn't real.

### Hiding a switch in the UI doesn't remove it
- **What happened:** 5.4.0-beta deleted the Post-Quantum tab and hid the
  pqc policy switches and readiness score in the new panel, because they
  enforced nothing and the score had no basis. The API, table and service
  code stayed. So `PUT /pqc/policy` still accepted
  `require_pqc_for_new_keys: true` with a success audit event, the inventory
  still used `interface_default_mode` to report unmeasured interfaces as
  hybrid, the `flag_*` switches could still hide findings, and ComplianceTab
  (a second consumer nobody checked) still showed the score as "x/100" and
  the policy profile.
- **Why it slipped through:** the fix was scoped to the tab being replaced,
  and the leftover was written down as "Open" in the CHANGELOG instead of
  being removed. The policy was only ever read inside its own service, so no
  cross-service search flagged it. Nothing links a removed UI control to the
  API field behind it.
- **Rule:** when a control is found to be fake, remove it at the source
  (route, store, table, types), then grep every consumer of its fields,
  including other tabs, generated catalogues and docs. Hiding it in one view
  only moves the fake. For each field, check whether anything outside the
  owning service reads it; if nothing does, it is record-only.

### A benchmark labels its row with the name the user typed, not what ran
- **What happened:** the first cut of the swap drill accepted `RSA`. Keycore
  generated its default RSA size and the drill history would have shown a
  measurement for "RSA", a label that doesn't say which key size produced
  those numbers. The engine test caught it only because it listed `RSA` as
  a name that must fail.
- **Why it slipped:** `planKeyGeneration` is lenient on purpose (key
  creation has always accepted bare names), and the drill reused it
  without asking whether the label matches the work.
- **Rule:** anything that records a measurement against an algorithm name
  requires a name `pkg/cryptocatalog.Lookup` accepts (a parameter set), and
  its test includes a bare family name that must be refused.

### A fake that answers what the code expects hides a contract nobody kept
- **What happened:** payment fetched key material with `POST
  /keys/{id}/export` and read a plaintext `material` field. Keycore's export
  has only ever returned material wrapped under a `wrapping_key_id`, and
  fails without one, so every payment operation naming a key by ID failed
  against the real keycore; only inline `material_b64` worked. Payment's
  tests used a fake keycore whose `ExportKey` returned `material`, so they
  all passed. Found while wiring delegation, when a keycore test of the same
  call returned `400 wrapping_key_id is required`.
- **Why it slipped through:** the fake was written from the client's
  expectations, not from the server's contract, and no test called the real
  keycore handler the way payment did.
- **Rule:** a fake of another service returns exactly what that service's
  handler returns; for each client call, one test drives the real handler
  with the client's request shape.

### crypto.Signer drops the request, and with it the user
- **What happened:** certs' HSM CA signer implements `crypto.Signer`, whose
  `Sign` has no context; it signed under `context.Background()`, so the user
  who issued the certificate never reached keycore.
- **Rule:** a `crypto.Signer` backed by a remote key is built per request and
  carries that request's context and usage (`hsmSigner.ctx`, `.usage`).

### A check that reads a setting nobody can write is dead code with a test
- **What happened:** 5.1.0-beta enforced a tenant "minimum algorithm tier"
  read from governance posture, and a unit test injected the value and
  passed. Governance has no such column, API or UI, so in a deployment the
  value was always empty and the check never ran. The parallel docs audit
  found it.
- **Rule:** a control is real only if the setting it reads can be set in
  the product; trace a new control back to the screen or API that writes
  it, not just to a test fixture.
### A feature table written with the code, never re-read against it
- **What happened:** `docs/AUTOMATION_ALKM_PQC.md` was written in one
  "hardening wave" alongside the code it described. Of its 27 "At a glance"
  rows, about half were false by 5.0.0-beta: composite keys (creation
  refuses `+`), Y2Q scoring and a keycore migration planner (never
  constructed), PQC KCV, dependency-aware destroy, self-test on wake,
  workflow templates and auto-tagging (never called), a stateful HBS
  tracker, composite signatures and PQC HSM attestation (no code at all), a
  zeroization scheduler that listed destroyed keys through a store method
  that didn't exist, and five posture toggles governance never stored. Its
  caveats were stale the other way: "PQC primitives are interface only" when
  keycore already generated ML-KEM/ML-DSA/SLH-DSA keys, and "the lifecycle
  scan is a stub" when it had been real for months.
- **Why it slipped through:** each row named a symbol (`RotationForecaster`,
  `DependencyChecker`, `WakeSelfTestRegistry`), and a named symbol reads as
  evidence. Nobody checked for a caller. Most of the code compiled and some
  had its own unit test (`pqc_primitives_test.go` tested wrappers nothing
  used), so `go test` and `make conformance` were green. The event
  catalogue had the same shape: severities for `wake_kat_failed` and
  `hbs_exhausted` looked like emitted events and were quoted as "the most
  important to alert on".
- **What was worse than dead:** three pieces ran. The KMIP auto-decommission
  took `updated_at` as "last seen", and KMIP traffic never writes it, so every
  client was set dormant (and refused at connect) 90 days after creation.
  `POST /tenants/onboard` did nothing but emit `audit.tenant.onboarded` every
  30 s. The audit "auto-quarantine" quarantined nothing, and the "HNDL
  detector" counted all encrypt volume.
- **Rule:** before a doc row, catalogue entry or CHANGELOG line names a
  capability, follow it to a caller in a running path: `main.go` wiring,
  a registered route, or a scheduler. A symbol with no caller outside its
  own file (and its own test) is dead, and gets removed rather than
  documented. When a value stands in for a measurement ("last seen",
  "verified", "quarantined"), check what actually writes that value.
- **Same trap, one commit earlier:** 5.1.0-beta (below) made keycore enforce
  governance posture's minimum algorithm tier, on the premise that the tier
  "was saved". Governance has no such field: keycore's parser named
  `posture_min_algorithm_tier`, and nothing in governance stores or returns
  it. The enforcement is correct and tested with an injected value, but in a
  deployment it never fires. A control's test must start from where the
  value is really set, not from the struct that receives it.

### A service nobody's UI called still served its API unauthenticated
- **What happened:** the pqc service's tab was orphaned, so its routes looked
  dormant, but they were live behind Envoy with no JWT check: tenant from the
  query, no permission, and a body-supplied actor on plan execution, which
  creates keys in keycore with pqc's service identity.
- **Why it slipped through:** reviews followed the UI; a service with no
  screen got none. The 4.0.0-beta keycore fix didn't sweep other raw muxes.
- **Rule:** when an auth hole is fixed in one raw-mux service, check every
  service still on `scripts/route-kernel-burndown.txt` for the same shape.

### A posture control that is stored but never read is a promise, not a control
- **What happened:** governance posture's `MinAlgorithmTier` ("the
  tenant-wide crypto-agility floor") was saved, synced to keycore and shown
  in the docs, but no keycore code path compared an algorithm with it.
- **Why it slipped through:** the struct field, the sync and the docs
  existed, so it looked wired; nothing tested a refusal.
- **Rule:** a control ships with a test that proves it refuses the bad case
  (`TestTenantMinAlgorithmTierEnforced`), or it is a labelled preview.

### Dates the vendor picks are the customer's decision
- **What happened:** 3.2.0-beta put standards-body transition dates into
  the product as the migration schedule. The owner reversed it: customers
  migrate on their own policy, and quoting drafts and references in the
  product is not our place.
- **Rule:** the product states technical facts and enforces the customer's
  policy; it doesn't decide dates for them (CLAUDE.md, 2026-09-29).

### Closing a hole in two route families left the rest of the mux open
- **What happened:** 4.0.0-beta put keycore's access and key-management
  routes behind permissions, but the same raw mux still let any verified
  token report a compromise (which suspends the key), rotate any key through
  `POST /enterprise/orchestration/runs`, read another key's KCV through the
  fingerprint check, and run ceremonies, scheduling and enterprise controls.
  They were found only while mapping reads for key visibility, and fixed in
  5.0.0-beta.
- **Why it slipped through:** the 4.0.0 fix was scoped to what the probe had
  shown, and "rotate" was fixed on `/keys/{id}/rotate` without asking what
  else calls `RotateKey`.
- **Rule:** when a route layer is found without permission checks, list
  every route on it (`grep HandleFunc`) and account for each one in the same
  change: moved to the kernel, or guarded another way and saying how. For a
  sensitive operation, grep for every caller of the service method, not just
  the obvious route.

### A hidden resource has to look exactly like a missing one
- **What happened:** building key visibility, three easy versions would each
  have confirmed that a hidden key exists: answering `403`; answering `404`
  with a different error code from the handler's own not-found; and looking
  the key up before checking the tenant (another tenant's existing key gave
  404, a non-existent one 403).
- **Rule:** the wrapper answers both "missing" and "hidden" itself with one
  response, checks the tenant before any lookup, and a test compares the two
  responses byte for byte on the error code.

### A route-registration helper hid routes from the product map
- **What happened:** 4.0.0-beta registered keycore's key-management routes
  through a local `add(...)` helper. `scripts/generate_product_map.py`
  recognises only literal `x.Handle(...)` / `x.HandleFunc(...)` calls, so 19
  routes (rotate, destroy, export policy, ...) silently vanished from
  `docs/generated/`; 5.0.0-beta's first draft would have dropped 60 more.
  Noticed because "unmatched frontend call sites" rose from 58 to 80.
- **Why it slipped through:** conformance `product-map` checks that the map
  matches the source, not that the source's routes are all in it.
- **Rule:** register every route with a literal `r.Handle("METHOD /path",
  route.Spec{...}, fn)` line (wrap legacy handlers with `legacy(...)`), and
  after regenerating, compare the service's route count with the previous
  map.

### SQLite can't prove a (created_at, id) cursor
- **What happened:** a scoped cursor-paging test repeated rows on SQLite.
  keycore's `created_at` there is second-resolution text, so `(created_at,
  id) < (?, ?)` against a Go time parameter doesn't order rows; the query is
  correct on Postgres.
- **Rule:** test cursor paging on Postgres (`VECTA_TEST_POSTGRES_DSN`,
  `TestKeyVisibilityPostgres`); on SQLite, page by offset.

### Key access overhaul: build it to the model, strictly
- **What happened:** the owner asked for CipherTrust-level key granularity
  (per-key matrix, label-selector policies, KMIP properties, full key usage,
  enforced dates), "not copied" and without losing existing features. The
  review behind it found the gaps below.
- **Rule:** every key-access or key-metadata change follows
  [docs/SECURITY/KEY_ACCESS_MODEL.md](docs/SECURITY/KEY_ACCESS_MODEL.md)
  section 10. In short: one decision path for every interface; a usage, date
  or field is offered only with the code that enforces it and a test of the
  refusal; identity only from a verified credential; every route on
  `pkg/route`; every change and refusal audited; deny wins; per-record
  migrations. A departure updates the model doc in the same commit.

### Hardening the crypto path hid an open management path
- **What happened:** keycore's crypto operations were carefully guarded
  (`enforceKeyAccess`, refusal audit, header spoof tests), but its
  management routes had no permission check and accepted requests with no
  token at all. A probe test showed that without a token `PUT
  /keys/{id}/export-policy`, `PUT /keys/{id}/access-policy`, `PUT
  /access/settings` and `PUT /keys/{id}/approval` returned 200, and a
  readonly user's token did the same. Envoy routes `/svc/keycore/` from the
  public listener without validating JWTs, so this was reachable from
  outside. Fixed in 4.0.0-beta.
- **Why it slipped through:** three reasonable-looking choices combined.
  `tenantcheck.Enforce` skips when there is no token ("so tokenless internal
  crypto callers keep working"), keycore's middleware only parsed a token if
  one was sent, and `docs/ARCHITECTURE_MIGRATION.md` listed keycore among
  services "with HTTP permission checks" because its crypto path had them.
  Every test of access control exercised key *use*; none tried to *change* a
  key without a token.
- **Rule:** for each service, test the management writes (policy, grants,
  settings, export, destroy) with no token and with a no-permission token,
  not just the data plane. A "skip if unauthenticated" branch in a shared
  check is a bypass unless the caller refuses tokenless requests first.

### A body field that names the actor is identity from the body
- **What happened:** `PUT /keys/{id}/access-policy` and `POST /access/groups`
  took `updated_by` / `created_by` from the JSON body and wrote it to the
  grant records and the audit event, so the record of who changed access
  could be forged.
- **Why it slipped through:** it was framed as a display convenience ("who
  to show"), not as identity, so the rule-4 sweep of headers didn't look at
  body fields.
- **Rule:** attribution is identity. Take it from the verified token, and
  reject a body that names an actor (the kernel's `Decode` refuses unknown
  fields; don't add the field back "for compatibility").

### A usage checkbox without an enforcement point is a fake feature
- **What happened:** reviewing CipherTrust's key-usage list for Vecta found
  that keycore's own `purpose` was never enforced (an `encrypt-decrypt` key
  also wraps and MACs), KMIP's usage mask was flattened into that string,
  and CipherTrust-style "Generate / Validate Cryptogram" has no
  implementation anywhere in the repo.
- **Why it slipped through:** `ensureKeySupportsOperation` checks what the
  *algorithm* can do, which reads like a usage check. Nobody asked what the
  *key* was allowed to do.
- **Rule:** list each usage with the function that refuses it before adding
  it to a mask or UI (KEY_ACCESS_MODEL.md section 4). No enforcement point
  means it isn't offered.

### A trusted service principal erases the user behind it
- **What happened:** dataprotect (FPE), payment (TR-31 / PIN translate) and
  certs (CA signing) call keycore with their own service JWT, and service
  principals skip per-key grants. So keycore can't tell which user asked or
  for which usage, and anyone who can reach dataprotect can FPE with any key
  in the tenant. Fixed in 6.0.0-beta (`pkg/delegation`); bare service
  identities are not yet limited to their usages.
- **Rule:** a service acting for a user forwards the user's verified token
  and the intended usage; keycore checks both. A bare service identity is
  limited to the usages listed for it.

### Assurance level from a header is identity from a header
- **What happened:** keycore's posture step-up check is satisfied by an
  `X-Step-Up-Auth: true` request header; tokens carry no MFA claim. Open;
  phase 0 in KEY_ACCESS_MODEL.md.
- **Rule:** MFA / step-up comes from a claim auth signs after the second
  factor, never from a header the caller sets.

### Four algorithm lists, four answers, and one of them enforced policy
- **What happened:** keycore agility, pqc, discovery and `pkg/cbom` each kept
  their own algorithm classifier. They disagreed on almost every row:
  RSA-2048 was "legacy" (keycore), "weak" (pqc) and `classical-128` (cbom)
  when NIST rates it 112-bit and acceptable through 2030; RSA-4096 and ECDSA
  were "strong" in pqc and discovery although a quantum computer breaks
  both; SLH-DSA was not recognised as post-quantum anywhere but cbom. The
  cbom one drove the policy floor, so a `classical-192` floor let RSA-3072
  (128-bit) through and HMAC was refused under every floor.
- **Why it slipped through:** each list was written for one screen, with
  numbers that looked plausible (QSL 88, grade A–F) and no cited source, so
  review checked the code path, never the value. The policy floor had no
  test at all, and a stored floor that wasn't a tier silently enforced
  nothing.
- **Rule:** an algorithm fact (strength, quantum status, NIST status or
  date) comes only from `pkg/cryptocatalog`, and each row cites the NIST
  table it was copied from, pinned by a test. A name the catalogue cannot
  parse is "not assessed", never classified by substring.

### A deadline is evidence: it needs a source you can open
- **What happened:** the pqc timeline showed "CNSA 2.0 classical to hybrid by
  2028-12-31", an "EU crypto-agility baseline 2029-06-30" and an EU target
  of 2031-12-31, none of which any published roadmap sets, and plans
  defaulted to them. Their status came from the readiness score, not from
  whether any asset was affected.
- **Why it slipped through:** round dates next to real programme names read
  as fact; nobody asked for the document. The same happened to CSWP 39's
  own "112-bit disallowed in 2031", which NIST withdrew in the 2026-06-29
  update (Appendix C).
- **Rule:** a date shown as a regulatory or NIST deadline carries its
  document, revision and table, and a draft is labelled proposed. With no
  source, ask the operator for the date instead of supplying one.

### A catalogued alert that nothing emits is a silent gap
- **What happened:** `audit.policy.crypto_floor_violation` was in the audit
  catalogue (HIGH) and in docs/AUTOMATION_ALKM_PQC.md as an event to alert
  on, but the policy service only emitted `audit.policy.violated`, with
  `result: success`.
- **Rule:** when a doc or catalogue names an event, grep for its emitter; a
  test must assert it is emitted (AUDIT_EVENTS_2026-09.md).

## 2026-09-28

### A preview named after a guarantee outlives the real thing
- **What happened:** keycore's "External audit-chain anchors" preview kept
  a hash chain of its own anchor records and a free-text reference. It was
  labelled preview in 1.x after it was caught reporting a fake root, but
  stayed after 3.0.0-beta shipped real signed checkpoints, so the product
  offered two "audit anchoring" features, one of them hollow.
- **Why it slipped through:** a preview label makes a hollow feature
  honest, so nobody revisits it; and it lived in keycore, not in audit, so
  the audit work didn't find it until the owner asked.
- **Rule:** when a real capability lands, grep for previews and roadmap rows
  that promise the same thing and remove them in the same release.

### A tamper-evidence layer that never leaves the database proves nothing extra
- **What happened:** the audit and certs services built Merkle epochs for
  releases. Both `…/merkle/verify` endpoints recomputed a proof and compared
  it with the root **in the request**, so any self-built proof passed, and
  no root was ever exported, so anyone able to rewrite events could rewrite
  the epochs too. The tree also duplicated odd leaves with no leaf/node
  domain separation (the CVE-2012-2459 shape).
- **Why it slipped through:** the feature had the right vocabulary (roots,
  inclusion proofs, epochs) and a passing verify test; nobody asked what
  independent value the verifier compared against. 1.38.0-beta fixed the
  proof endpoint for the same reason but left `verify` taking the root from
  the caller.
- **Rule:** for every integrity check, name the trusted input that the
  attacker can't write (a key they don't hold, a copy outside their reach).
  If there is none, the check is decoration: remove it. Signed checkpoints
  replace it (docs/SECURITY/AUDIT_INTEGRITY.md).

### A key that silently falls back to random is lost at every restart
- **What happened:** the audit event HMAC key came from
  `AUDIT_EVENT_SIGNING_KEY_B64` via `pkgcrypto.LoadKey32`, which generates an
  ephemeral key when the variable is unset. No installer or compose file
  set it, so every deployment signed with a new random key after each
  restart and every earlier event verified as `hmac_key_unknown`.
- **Why it slipped through:** tests always installed a fixed key, and the
  fallback only logs a warning. Found while checking what the new
  checkpoints' key trust depended on.
- **Rule:** a key that must verify data later can't have a random fallback.
  Derive it from the service master key (`pkg/mek`) or fail; grep
  `LoadKey32` for other keys with the same shape (the audit WAL HMAC key is
  one: still open).

### Removing a route means removing it from the cluster routing table too
- **What happened:** 2.14.0-beta and 2.16.0-beta removed audit's alert-rule
  and channel routes, but `pkg/clusterroute.Local` kept listing two of them.
  `TestLocalRoutesExist` caught it, yet both changes were pushed with only the
  touched packages tested, so `make test-fips-modes` was red on `main` for
  three releases.
- **Rule:** when you remove a route, grep for its path across `pkg/` (the
  cluster routing table, the playbook action catalogue, docs), and run the full
  `make test-fips-modes` before pushing, not just the service's own tests.

### A feature outside the product's job grows its own fakes
- **What happened:** the KMS matched its SBOM against OSV, a bundled Trivy
  and hand-entered "offline advisories". Keeping that honest took a
  1.26.0-beta fix (a built-in CVE list returned when sources failed), and
  compliance still had a second SBOM with hard-coded versions and a
  `/sbom/vulnerabilities` route that turned a posture score below 60 into
  the "vulnerability" `CRYPTO-DEPRECATED-ALGO`. No screen called it.
- **Why it slipped through:** the compliance routes were on the legacy mux,
  so the route kernel's audit and the real-capability checks never looked at
  them. Their names (`GenerateSBOM`, `SBOMVulnerabilities`) matched none of
  the `simulate*`/`fake*`/`mock*` patterns conformance searches for.
- **Rule:** before hardening a feature, ask whether it is the product's job.
  CVE tracking belongs to vulnerability management; the KMS hands over an
  SBOM. When a capability is removed, look for a second copy in another
  service and remove it in the same change.

### A second store of the same thing outlives its last reader
- **What happened:** audit wrote an alert row for every event it ingested,
  with its own dedup and escalation, while reporting raised the real alerts
  from the same events. After 2.12.0-beta nothing read audit's table, but
  every ingest still paid for a second insert in the event's transaction,
  and `/audit/stats` kept returning alert counts under a name that promised
  event statistics, which the REST explorer documented with invented numbers.
- **Why it slipped through:** each removal (the UI tab in 2.12, the rules in
  2.14) took away one reader and left the writer, because the writer sat
  inside the ingest path and looked essential.
- **Rule:** when you remove the last reader of a store, remove the writer,
  the routes, the settings and the table in the same change, and add a test
  that the routes are gone.

### A fallback that invents events hides that the real path never worked
- **What happened:** the dashboard's live feed opened WebSockets to
  `/alerts/stream` and `/audit/stream` at the site root. Envoy sent those to
  nginx, and the audit service speaks SSE, not WebSocket, so every connection
  failed. The error handler started a `simulation` interval that pushed an
  invented `audit.dashboard.heartbeat` audit event every 20 seconds. Nothing
  read the store, so nobody noticed either problem.
- **Why it slipped through:** conformance matched `simulateX(` functions and
  `mockX` variables, not a variable called `simulation`. The fallback made a
  dead path look alive, and no test asserted a real event arrived. The CSP
  kept `ws: wss:` open for it.
- **Rule:** when a data path fails, show that it failed; never fill it. A
  client and server must agree on path, route and protocol, checked end to
  end. Code with no reader gets removed, not kept "for later". Conformance
  now fails on any `simulat*` or `synthetic*` variable outside tests.

### Two engines for one job: only one is ever maintained
- **What happened:** audit and reporting each had alert rules. Reporting's
  got the parser, thresholds, UI and now a test route. Audit's kept a
  three-phrase substring matcher, a stub test route, and an effect (alert
  severity) that no screen showed.
- **Rule:** when two services grow the same feature, pick the one the UI
  uses and remove the other in the same change that makes it redundant,
  with a migration for its table and a test that its routes are gone.

### A rule language documented from a different product
- **What happened:** the alert-rule guide described CEL (`&&`, `count()`,
  `hour()`, `is_new_source_ip()`) and built-in templates. Reporting's
  engine is a small language with `AND`/`OR` and seven fields. The
  dashboard's example patterns used `auth.login_failed`, which never
  matches the real `audit.auth.login_failed`. A rule written from the guide
  would fail to save, and one written from the examples would save and
  silently never fire.
- **Why it slipped through:** nothing let anyone run a rule before relying
  on it, and audit's `test-rule` returned `dry-run-ok` for any input.
- **Rule:** a detection feature ships with a way to check it against real
  data (`POST /alerts/rules/test` replays recent audit events), and examples
  in docs and UI use real action names.

### A card that renders zeros for a service that doesn't exist looks healthy
- **What happened:** Posture and Compliance each had a "Threshold Signing /
  FROST" card fed by `Promise.resolve(null)`. No MPC service exists, so it
  showed 0 keys, 0 failures and "No active keys" on every tenant. Compliance's
  Crypto Inventory scored a browser-side formula and returned 100 when the
  key and cert fetches failed (`.catch(() => [])`). The Audit Log badge said
  "250+ event types", counted from a service × verb product that includes
  services we don't ship. The Audit Log analytics charted one page of 100
  events and labelled it "Total Events".
- **Why it slipped through:** none of them has a `fake*` or `mock*` name, and
  `Number(x || 0)` turns "no data" into a real-looking zero. The same charts
  were copied into three tabs (Audit Log, Compliance, Analytics), so each
  copy looked like it had a source somewhere else.
- **Rule:** a missing or failed source renders "unavailable" or "not
  assessed", never 0 or 100. A count names what it counted ("events
  analysed"). A view has one home; before adding a chart, check whether
  Analytics already has it.

### "Queued" is a claim, and nothing checked it
- **What happened:** audit alerts recorded email, SMS, PagerDuty, SIEM and
  webhook as `queued` on every alert, and audit exposed channel settings
  and a test route (`test-sent`). There was no sender behind any of them.
  The earlier PagerDuty cleanup (2.4.0) removed the playbook action and hid
  reporting's channels, but it didn't find these, because they held the
  word in a status map and a default config rather than in a delivery
  function.
- **Why it slipped through:** the real-capability check looks for
  `simulate*` / `fake*` functions. A status string is data, and a handler
  that returns a fixed success body has neither name.
- **Rule:** a status like `queued`, `sent` or `test-sent` needs code that
  makes it true. When removing an integration, search for its name in
  every form (config maps, status keys, UI filters, docs) and add a
  conformance rule so it can't return (`no-pagerduty`).

### An unused package can hold the worst code in the repo
- **What happened:** `pkg/siem` had Splunk, Datadog, Elastic, Sentinel and
  QRadar exporters and a buffered exporter, and nothing imported them. They
  sent plain UDP/TCP syslog, used `http.Client{}` with no address guard,
  signed with `crypto/hmac` directly, and called Sentinel's HTTP Data
  Collector API, which Microsoft retired on 14 September 2026. The Elastic
  exporter treated a Bulk answer of 200 as success even when every
  document was rejected.
- **Why it slipped through:** conformance scans imports and calls, but an
  unreferenced package never runs, so nothing exercised it. "We have SIEM
  exporters" rested on files existing.
- **Rule:** a package counts as a capability only when something wires it
  and a test drives it against a receiver. Unreferenced code is removed or
  wired, never left as evidence.

### A credential can hide in a URL, and in the error that quotes it
- **What happened:** governance stored Slack and Teams incoming-webhook
  URLs in plaintext and returned them from `GET /governance/settings`. The
  audit dispatcher returned Go's `*url.Error`, which quotes the full URL,
  into the delivery log and the audit event.
- **Why it slipped through:** the fields were named `*_url`, so they read
  as configuration. For Slack and Teams the URL is the credential.
- **Rule:** treat a webhook URL as a secret. It lives only in a sealed
  connection, and outbound errors name the host (`unwrapURLError` in
  compliance, the dispatcher in audit).

### The same credential in three stores drifts three ways
- **What happened:** outbound endpoints lived in compliance connections
  (sealed, exposure-tracked), audit webhooks (sealed separately) and
  governance settings (plaintext). Each had its own validation, rotation
  story and UI.
- **Rule:** one store. A new outbound integration is a connection type, and
  a service that needs one holds its ID and asks compliance to open it
  (docs/SECURITY/CONNECTIONS.md).

### A guide can describe a feature that was never built
- **What happened:** `docs/GOVERNANCE_AND_COMPLIANCE.md` documented CSV,
  JSONL, CEF and LEEF exports from `/audit/events` with sample output, a
  QRadar pipe over plain UDP, and webhook fields (`min_risk_score`,
  `retry_attempts`, `X-Vecta-Signature`). None existed. It also listed a
  PagerDuty channel for governance.
- **Why it slipped through:** `check-doc-routes.py` checks that a documented
  route exists, not what its parameters do. The page used an existing route
  with invented query values.
- **Rule:** when changing a feature, re-read every guide that mentions it
  against the code. Other PagerDuty mentions remain in the reporting
  sections of that guide and need the same check.

### A generated file nobody is made to regenerate goes stale
- **What happened:** `docs/generated/` (routes, request flows, the product
  map) was last regenerated at 2.2.0-beta and missed five releases of
  routes. Regenerating was a manual step no check asked for.
- **Rule:** generated files that are committed get a freshness check in
  `make conformance`. A generator used this way needs output that doesn't
  depend on the machine: sorted walks, git-scoped inputs, and timestamps
  masked when comparing.


### `@ts-nocheck` hides the one type error that crashes at runtime
- **What happened:** a scan of the 36 `@ts-nocheck` dashboard files with
  the marker lifted found about 1,300 type errors. All but two were loose
  typing. The two were undefined names: `getPaymentPolicy` and
  `updatePaymentPolicy`, called without an import in a panel nothing
  rendered anymore. The same scan also flags `{ pqc }` (TS18004), the 2.7.0
  Certificates crash. Reading the same files by hand turned up bugs no type
  checker sees: CSS values written as `"${C.x}"` in plain quotes (the
  browser got the literal text), and protocol data dropped before
  rendering.
- **Why it slipped through:** `@ts-nocheck` turns off every diagnostic in
  the file, and typescript-eslint turns off `no-undef` for TS files, so
  nothing checked names at all.
- **Also found:** the dashboard unit-test job in CI was red. A test pinned
  the exposure-register service list, and nobody updated it when `audit`
  joined. A test that copies a list from the backend goes stale; it now
  reads `pkg/mek/catalog.go`.
- **Rule:** undefined names are checked even where types aren't
  (`scripts/check-nocheck-names.mjs`, in `npm run typecheck`). When
  deleting a variable, search the file for its last use: shorthand
  properties (`{ pqc }`) are easy to miss.


### A smoke test that never got past the sign-in page hid a broken tab for months
- **What happened:** the Certificates / PKI tab crashed on every render
  (`ReferenceError: pqc is not defined`) from 1.21.0-beta onward. Commit
  `b3c87986f` removed the fake PQC certificate count but left `pqc` in a
  returned object. CI's Playwright smoke test (`tests/smoke-tabs.spec.ts`)
  was meant to catch exactly this.
- **Why it slipped through:** two gaps stacked up.
  - `CertsTab.tsx` is `@ts-nocheck`, so `tsc` doesn't report undefined
    names there.
  - The smoke test wrote its session to `localStorage` after the dashboard
    had moved sessions to `sessionStorage`. The app stayed on the sign-in
    page, and the test skipped every tab button it couldn't find.
    Sidebar entries aren't `button`s either, so it would have skipped them
    anyway. It passed while clicking nothing.
- **Rule:** a test that skips what it can't find must also assert that it
  did something. The smoke test now fails on the sign-in page and requires
  more than 10 tabs opened. Found while exercising the 2.6.0 playbook UI in
  a real browser.


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
