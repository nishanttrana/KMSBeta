# Learnings

Running log of non-obvious operational and architectural learnings for Vecta KMS.
Newest entries on top.

## 2026-09-26

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
