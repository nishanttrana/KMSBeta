# Vecta KMS — engineering rules

Standing rules for all development on this repo, by people and by AI
assistants. The product targets FIPS 140-3 Level 1, so assume every crypto,
TLS, auth or audit change will be read by a certification reviewer.

**The owner should never have to repeat an instruction.** When they give a
standing instruction, add it to this file in the same change. When they correct
an approach, record it here or in the matching doc below.

## Non-negotiable

1. **One crypto library.** Primitives come only from `pkg/crypto`
   (FIPS-gated by `pkg/fips`). Never import `crypto/rand`, `crypto/aes`, etc.
   in a service. Never use `math/rand` for anything security-relevant.
2. **One audit pipeline.** Events go through `pkg/audit` `Client.Emit` onto the
   single `AUDIT` JetStream stream. No private streams, no raw publishes.
   Events carry actor, resource, severity and correlation, detailed enough for
   governance, reporting and DAM to run on them alone.
   **Every activity is audited with its own event, and new activity must keep
   adding them** (owner directive, 2026-09-25):
   - Every create, update or delete, and every security-relevant operation,
     emits a specific `audit.<service>.<action>` event. The generic HTTP
     request log alone is not enough.
   - **Every refusal is audited too**, with its `reason` and `result:
     "refused"`: denied permission, tamper or integrity failures, preview
     refusals, and FIPS refusals.
   - A test asserts that each new event is emitted, including for the refused
     case. Its row in `docs/SECURITY/AUDIT_EVENTS_2026-09.md` names that
     test; naming the code that emits it is not proof (1.36.0-beta).
   - New subjects are listed in `docs/API_REFERENCE.md` (Audit Action Subject
     Reference).
   - **Routes get this by construction** (owner directive, 2026-09-26:
     "anything that's added to platform should have audit activity as per
     the rules we have created", without being prompted each time). Every
     HTTP route is registered through `pkg/route` with a `route.Spec`
     (action, permission, resource). The kernel authenticates, enforces the
     tenant and permission, and emits the specific event, refusals included.
     Handlers add details with `c.Detail` / `c.Target` and use `c.Refuse` for
     their own refusals. They never read a tenant themselves, and the service
     layer doesn't emit request audit. `routetest.RefusalsAudited` is the
     per-service test. A raw `http.ServeMux` fails `make conformance`
     (`scripts/route-kernel-burndown.txt` only shrinks). To add a route to a
     service still on the list, register it on a `route.Router` and mount it
     on the legacy mux with `Router.MountOn`, or migrate the handler file
     ([docs/ARCHITECTURE_MIGRATION.md](docs/ARCHITECTURE_MIGRATION.md)).
3. **Secure defaults** ([docs/SECURITY/SECURE_DEFAULTS.md](docs/SECURITY/SECURE_DEFAULTS.md)):
   - No secret falls back to a value in the repo. Require it (`${VAR:?}`) or
     generate it at random.
   - Validate strength, fail closed on weak values, and revoke anything a
     removed default already produced.
   - Every installer generates every secret compose requires.
   - The only repo-visible default is admin `changeit`, which is always seeded
     with a forced password change. It is fixed, not configurable (owner
     directive, 2026-10-11: "the default password for stack is changeit and
     then after change it should keep the user specified password"): no
     installer, script or `.env` value sets a different seed, and nothing
     replaces the password the admin then chooses.
4. **Tenancy bypass must be unforgeable.** A privilege that skips tenant checks
   is keyed on something only the platform can mint (see
   `tenantcheck.IsServicePrincipal`), never on a role name or an `X-Actor-*`
   header. **Identity comes only from a credential the service verifies** (a
   JWT, an XML signature, a JWKS-verified token): never from a request body
   field, an `X-Client-*` header, or the TLS peer certificate — behind Envoy
   the peer is always Envoy (1.27.0-beta, docs/DECISIONS.md).
   **Where a request came from and who made it each have one reader:**
   `clientip.From(r)` (the address the edge appended, never the first
   `X-Forwarded-For` entry or `RemoteAddr`) and `pkgauth.Actor(ctx)` (never
   an `X-Actor` / `X-User-*` header, a query parameter or a body field). A
   field another service uses to decide something, such as the requester on
   an approval, is identity whatever it is called (12.1.0-beta,
   [docs/SECURITY/REQUEST_ORIGIN.md](docs/SECURITY/REQUEST_ORIGIN.md);
   conformance `client-address`, `caller-named-actor`).
   **A request body never says who is asking.** `requested_by`,
   `updated_by`, `created_by`, `requester_id` and the like are assigned in
   the handler from `tenantcheck.ActingFor` / `tenantcheck.Requester` (or
   `c.Actor()`); only a platform service may name the person it acts for
   (13.0.0-beta; conformance `body-named-person`, whose allowlist only
   shrinks).
5. **FIPS 140-3 is the customer's choice (made in the KMS UI), on the certified module**
   ([docs/SECURITY/FIPS.md](docs/SECURITY/FIPS.md)):
   - Every binary builds with `GOFIPS140` = `pkg/fips.CertifiedModuleVersion`.
   - A root admin picks `on` | `only` | `off` in System Administration.
     Services apply it by a staggered self-restart and re-exec;
     `VECTA_FIPS_MODE` only seeds it. Every feature must work, or refuse
     cleanly, in each mode.
   - A feature that behaves differently in strict mode must appear in the
     impact catalogue (`pkg/fips/impact.go`) that the UI shows before a
     change.
   - AES-GCM uses module-generated IVs.
   - Non-approved or third-party crypto gets a `fips140.Enforced()` guard that
     returns an error, never a panic.
   - Claim "validated" only when `fips.ModuleValidated()` is true.
6. **Keys are derived from secret material, never from identifiers.** A
   service that needs a working key gets it from keycore
   (`POST /keys/{id}/service-derive`, bound to the verified service identity).
   A service's master key for data at rest comes from `pkg/mek` (a protected
   keycore system key), never from an environment variable or a fallback
   ([docs/SECURITY/SERVICE_MASTER_KEYS.md](docs/SECURITY/SERVICE_MASTER_KEYS.md)).
   The one exception is a key that must open before keycore can be
   reached, such as the audit write-ahead buffer's HMAC key (owner, 2026-10-17:
   "yes do it"): it is made once and kept on the service's own volume, and a
   damaged key stops the service (docs/DECISIONS.md).
   A KCV, key ID or other metadata is never key material. Changing how
   existing data is keyed needs a per-key migration, never a silent switch
   ([docs/SECURITY/DATAPROTECT_KEY_DERIVATION.md](docs/SECURITY/DATAPROTECT_KEY_DERIVATION.md)).
7. **Never fabricate security evidence.** No invented versions, scan results,
   certifications or "5/5 production-ready" claims. The UI shows "not assessed"
   rather than guessing. Evidence lives in `docs/SECURITY/` and comes from real
   tool output. No simulated results: a feature that only stores
   configuration is a **preview**, listed in `pkg/features.Preview` (mirrored in
   the dashboard, [docs/PREVIEW_FEATURES.md](docs/PREVIEW_FEATURES.md)). Its
   responses are labelled, and operations it can't perform return
   `409 feature_preview`.
8. **Every feature is 100% real capability, never mimicked or faked** (owner
   directive, 2026-09-26). A feature must actually do what its UI and API say,
   end to end, not just look like it does
   ([docs/SECURITY/REAL_CAPABILITY.md](docs/SECURITY/REAL_CAPABILITY.md)).
   - Forbidden: simulated or synthetic results, "demo" data shown as real,
     steps marked passed that never ran, UI-only features with no backend
     effect, and records presented as enforcement.
   - A capability that isn't built yet is either removed (preferred) or a
     labelled preview returning `409 feature_preview`. It never pretends.
   - **No mock, synthetic, fake or simulated data, features or audit**
     (owner directive, 2026-09-27). This covers:
     - **Data:** no `MOCK_*`/sample constants rendered when an API call
       fails; show "unavailable" with the error. No built-in fallback
       catalogues, invented defaults, or scores for assets that were never
       measured (show "not assessed").
     - **Labels:** an algorithm, key size, RNG source or provider label
       must match what was actually produced or called.
     - **Audit:** events and `result: "success"` fire only for work that
       actually happened. A no-op, a log-only action, or a same-algorithm
       rotate is never audited as the operation it names.
     - **Tests:** mocks belong in `_test` files only, and HSM and wire
       protocols are tested against the real thing.
     - **Learnings:** every fake that is fixed or removed adds a learning.md
       entry naming how it slipped through (owner directive, 2026-09-27:
       "keep adding the learning").
   - Before calling any feature real, follow the data: the secret, the
     network call, the check. `make conformance` (`real-capability`) fails on
     `simulate*`, `synthetic*`, `fake*` or `mock*` functions outside tests,
     and on `Math.random` bytes.
9. **Never expose a secret** (owner directive, 2026-09-26). Passwords, JWTs
   and tokens, API keys, private keys and key material, credentialed DSNs and
   `.env` values never appear in command lines, echoed commands, logs, error
   messages, tool output, chat, commits or URLs
   ([docs/SECURITY/SECRET_HANDLING.md](docs/SECURITY/SECRET_HANDLING.md)).
   - Pass them by environment variable name, file or stdin, never inline.
   - Wrap commands in shell functions, not word-split strings: zsh prints the
     whole string on failure.
   - Redact them in logs and errors.
   - If one is exposed anyway: say so at once, name the secret (not its
     value), recommend rotation, and record the cause in learning.md.
10. **Every connection is TLS; every internal one is mTLS** (owner directive,
    2026-09-26; [docs/SECURITY/INTERNAL_TLS.md](docs/SECURITY/INTERNAL_TLS.md)).
    Nothing speaks plain HTTP or another unencrypted protocol.
    - **Internal** traffic (service to service, Envoy to service,
      Postgres/NATS/Valkey/Consul, health checks) uses mTLS with certificates
      from the internal Vecta CA. The root and an internal-services Sub CA are
      created at deployment and shown in the PKI tab's CA hierarchy.
      Internal certificates, including those for future features, come from
      that Sub CA.
    - **External** endpoints use TLS, with a certificate from the internal CA
      or an external CA, chosen in the PKI tab.
    - Service mTLS certificates are shown in the dashboard, with one-click
      rotation (old certificate revoked and removed, then a graceful or
      forced restart to swap it) and one-click per-service mechanism choice,
      including PQC hybrid key exchange. Everything is real and audited.
    - A new service or feature is TLS/mTLS from its first commit.
      `platform.Boot` enrols it automatically; a service with its own
      `main` calls `svctls.Init` before serving. Every identity is listed
      in `pkg/svctls.Services`, and `make conformance` (`tls-only`) fails
      on a plain listener or on `http://` to a platform host.

## Crypto and transport standards

- TLS 1.3 minimum (`MinVersion: tls.VersionTLS13`). Where an external protocol
  forces less (LDAP/AD, KMIP, Alibaba HMAC-SHA1), add a comment
  `FIPS exception: external protocol mandate` explaining why.
- Algorithms must be on the approved list in `pkg/fips/fips.go`.
- **The customer decides what to migrate and when** (owner directive,
  2026-09-29: "avoid quoting direct sources, drafts, references let
  customer decide when and what he wants to migrate as per his policy").
  The product states only technical facts about an algorithm (strength,
  post-quantum category, quantum vulnerability, weak), from
  `pkg/cryptocatalog` alone; no service or dashboard page keeps its own
  algorithm list or score (a page reads the facts a service returns, as the
  recommendations do since 13.19.0-beta), and a name without a parameter set is "not assessed". Migration
  statuses and dates come only from the tenant's own policy rules, which
  keycore enforces. No standards citations, draft references or vendor-set
  deadlines in the UI or API
  ([docs/SECURITY/ALGORITHM_TRANSITIONS.md](docs/SECURITY/ALGORITHM_TRANSITIONS.md)).
- Key derivation uses HKDF-SHA256 or Argon2id, never a raw hash.
- Audit records are immutable and tamper-evident: hash chain, per-event HMAC
  under a key derived from the audit master key, and ECDSA-P384 signed
  checkpoints of each chain head
  ([docs/SECURITY/AUDIT_INTEGRITY.md](docs/SECURITY/AUDIT_INTEGRITY.md)).
- Every HTTP response carries `pkg/securityheaders`.

## How we build

- Code is tight, light and secure: no bloat, no speculative abstraction, no
  half-measures. Apply fixes directly rather than proposing them.
- New features and customer-side agents wire into the central spine
  (`pkg/crypto`, `pkg/audit`, auth service tokens) by construction. Agents
  that can't reach NATS use the audit service's authenticated HTTP ingest.
- When a backend capability is added or missing, build both the backend and
  the dashboard side.
- Shell scripts that users run (`install.sh`, `deploy-local.sh`) must work on
  macOS's bash 3.2 unless they explicitly re-exec under bash 4+.
- Don't use `git stash` as a scratch tool in a dirty working tree. Use a
  throwaway `git worktree` instead.
- **Work on `main` only** (owner directive, 2026-09-26: "just have main and
  no branch"). Commit and push straight to `main` after the checks in
  "Before calling a change done" pass. Don't create feature branches or
  pull requests unless the owner asks. Before pushing, fetch and
  integrate `origin/main`, then re-run the checks on the combined tree.
- Every new database table is classified for clustering in
  `pkg/clustercatalog/tables.go`: replicated under its component, node-local
  with a reason, or shared-append. Tables written during crypto operations
  are node-local. `TestEveryTableIsClassified` enforces this
  (docs/CLUSTERING.md).
- Cluster members never write replicated tables. A new write endpoint is
  forwarded to the primary by default; add it to `pkg/clusterroute.Local`
  only if it writes nothing replicated. A background job (scheduler, sweep,
  reconciler, lazy first-use insert) that writes replicated state checks
  `clusterstate.RunsPrimaryJobs(ctx)` / `IsMember()`, with a member-mode test
  (docs/CLUSTERING.md).
- **Every internal call carries a credential** (owner directive,
  2026-09-30: "never let it break", after a tokenless client emptied the
  Alert Center). A service calling another sends
  `servicetoken.Authorize`, or the caller's own verified token with a
  `servicetoken-exempt:` comment. Conformance `service-token` enforces it.
  After a fix, rebuild the service and check the live result.
- An internal endpoint that moves secrets or grants cluster access must
  restrict its caller: a specific service identity or a root administrator,
  never "any authenticated caller". Node-to-node endpoints authenticate
  themselves (one-time token, HMAC, pinned TLS).
- **Every KMS change bumps the minor version** (owner directive, 2026-09-26):
  raise MINOR in `VERSION` (MAJOR if breaking) and add a `## [x.y.z]` section
  to CHANGELOG.md in the same change. The dashboard's ⓘ button (next to the
  header clock) shows the version, commit and build time.
  `scripts/check-docs.sh` enforces this.
- **Development happens in KMSBeta; cut features may move to KMSExtension**
  (owner directive, 2026-09-26, "all the work have to be done on KMS beta
  only"; amended 2026-09-29 when the owner chose to move Payments there).
  Build and fix only in KMSBeta. When the owner cuts a feature, it is
  removed from KMSBeta, and, if the owner asks, its sources are copied as a
  seed into `KMSExtension/seeds/` (with its promotion caveats in
  `seeds/README.md`), committed and pushed there. Don't otherwise develop in
  KMSExtension. Name the removing commit in CHANGELOG.md either way.
- **HSMs are real integrations only** (owner directive, 2026-09-26: "there is
  no vecta HSM", "it has to be actual integration no fake"). Every HSM
  goes through the customer's own PKCS#11 library in `hsm-connector`
  ([docs/SECURITY/HSM_INTEGRATION.md](docs/SECURITY/HSM_INTEGRATION.md)).
  Nothing may present itself as an HSM, whether a "Vecta HSM" or a software
  vault. A vendor listed in the UI must work through that same path. HSM
  tests run against a real PKCS#11 library (SoftHSM2), never a mock of the
  HSM API.
  **Two roles** (owner directive, 2026-10-10): the tenant's HSM profile in
  the HSM tab is the root of trust that protects the KMS's keys (it also
  still holds keys where the tenant turned HSM keys on there). HSMs that
  hold keys are added as `pkcs11_hsm` credentials; the
  create, form and import key dialogs and the CA dialog offer "Create in
  HSM" and list every HSM (single or HA group) with its live status. A key
  records its HSM and never moves.
- **Cloud BYOK is a real import into every cloud, in KMS terms** (owner
  directive, 2026-10-11: BYOK "exactly implemented on the KMS similar to
  AWS but for every cloud but without TSB logic", material "via HSM (if
  PKCS11 HSM is added) or via the entropy of the KMS", replacing the old
  logic; [docs/SECURITY/CLOUD_BYOK.md](docs/SECURITY/CLOUD_BYOK.md)). Each
  cloud is driven through its own import protocol, never by creating a
  cloud-native key. Material leaves only through keycore
  `POST /keys/{id}/cloud-wrap` (wrapped in keycore, or inside the HSM for a
  key generated there with cloud import allowed); no TSB or vendor REST.
  Every step is recorded with its CLI equivalent, custody per KMS version.
  An operation a cloud lacks is refused and not offered. Tests drive each
  cloud's wire protocol with a double that unwraps what it receives.
  The key pages and the cloud console (13.2.0-beta) send only operations
  from the fixed catalogue in `services/cloud/console.go`: a new cloud
  operation is a catalogue entry with its own route, permission and audit
  action, never a free-form command, and never one that returns key
  material. BYOK automation only announces (expiring, rotation due);
  playbook actions do the work.
- **Every external credential is added once, in Playbooks → Credentials**
  (owner directive, 2026-09-28: webhooks and SIEM "should not be separate
  tab, just part of" Playbooks; widened 2026-10-10: credentials for
  "Bitlocker service account BYOK, HYOK, or crypto discovery or anything in
  KMS, external HSM creds, EKM" are "in a tab centrally as a single location
  where credentials to be added first before it can be used", "under
  playbooks credentials"). Every URL, account, PIN, key or token the KMS
  uses to reach an external system (notification, ticketing, SIEM, scan
  sources, cloud accounts, Azure EKM, mail relay, PKCS#11 HSMs) lives only
  in compliance's sealed connections. A feature never takes a secret in its
  own form or API: it holds the credential's ID, checks the caller holds
  `compliance.connection.use` when it is attached, and opens it for each use
  through `pkg/credstore` (`POST /compliance/connections/{id}/resolve`). A
  new integration is a credential type with its service added to
  `connectionUsers`, a usage lookup for the delete guard, and a real test
  ([docs/SECURITY/CONNECTIONS.md](docs/SECURITY/CONNECTIONS.md)). Its UI is
  a `CredentialPicker`, linking to Credentials when none exists. Two
  exceptions: the tenant's HSM profile (root of trust), whose PIN stays on
  the connector host; and identity provider secrets (LDAP and AD bind
  passwords, OIDC and Entra client secrets), which auth seals itself under
  its own master key, because signing in can't depend on compliance
  (9.0.0-beta, docs/DECISIONS.md).
- **Playbooks are the platform's response layer** (owner directive,
  2026-09-28: "playbook should be fundamental part of the KMS for any and
  every action incident"). An event that signals an incident or a
  security-relevant change joins the trigger catalogue
  (`services/compliance/playbook_catalog.go`), with its emitter listed in
  `TestTriggerSubjectsAreEmitted`. A remediating operation joins as an action
  that names the permission it needs, tested against the route it calls. A
  playbook acts only on the authority of someone who holds those permissions
  (docs/PLATFORM_CONTRACT.md), re-checked with auth before every unattended
  run. Irreversible or access-removing steps pause for a governance approval
  that the person the playbook acts for can't give. Notification credentials
  live only in sealed connections (`pkg/mek`), never in a playbook. No
  PagerDuty integration (owner, 2026-09-28: "no one uses it"; "remove
  pager completely"): conformance `no-pagerduty` fails on any mention in
  code.
- **No vulnerability management in the KMS** (owner, 2026-09-28: "its not
  the job of enterprise key management product to keep track of
  vulnerabilities it has to be vulnerability management"). No CVE feeds,
  scanners or advisory stores in the product. The SBOM is exported
  (CycloneDX/SPDX) for the customer's vulnerability-management tool. Key
  compromise advisories, quantum-vulnerable classification and CI scans of
  our own release are not this and stay (docs/DECISIONS.md).
- **Key access follows one model, strictly** (owner directive, 2026-09-29:
  key management as granular as CipherTrust, "not directly copied", no
  existing feature lost, "implemented properly and strictly"). Every change
  to key access, key usage, key metadata or the key management UI follows
  [docs/SECURITY/KEY_ACCESS_MODEL.md](docs/SECURITY/KEY_ACCESS_MODEL.md)
  and its section 10 rules. In short: one keycore decision for every
  interface; a usage, date or field is offered only with the code that
  enforces it and a test of the refusal; services acting for a user pass the
  user's verified token and the usage; deny wins. A departure updates that
  document and docs/DECISIONS.md in the same commit.
- **No content inspection in the KMS** (owner, 2026-09-30: the AI security
  gateway "seems to be like gimmick", "not in purview of KMS"). No LLM
  proxy, prompt or response scanning, toxicity or topic filters, or token
  budgets. AI workloads are served through secrets, workload identity,
  dataprotect, signing and BYOK/HYOK ([docs/AI_WORKLOADS.md](docs/AI_WORKLOADS.md)).
  The removed gateway is a KMS Extension seed (docs/DECISIONS.md).
- **One home per view** (owner, 2026-09-28: Analytics under both Audit Log
  and Overview, Alerts under both Audit Log and Alert Center, and a
  Compliance page that "is not accurate"; amended 2026-09-30: charts live
  with their data; amended 2026-10-01: Overview → Analytics merged into
  Overview → Operations). Charts sit in a tab beside the entries they count:
  audit charts in Audit Log → Activity, alert charts and triage in Alert
  Center → Analytics / Alerts, posture charts in Posture, and key and
  operations trends in Overview → Operations (Key inventory, Operation
  metrics). The audit record stays in the
  Audit Log, and Compliance shows only assessed compliance. Don't copy a view
  into another tab; link to its home. A failed or missing source shows
  "unavailable" or "not assessed", never 0 or 100 (docs/DECISIONS.md).
  Settings follow the same rule (owner, 2026-10-20: "under approvals under
  backups"): approval policies live only in Approvals → Policies, and
  encrypted backups only in Backup & Restore → Encrypted Backups; nothing in
  Administration repeats them. A choice list in a form offers only values the
  server acts on: approval triggers come from `lib/approvalActions.ts`, each
  proven against the Go code that submits it; a new approval-guarded
  operation adds its action there (13.27.0-beta).
- **Every chart drills into its entries** (owner directive, 2026-09-30:
  "clicking on graphs / bar should show related entries"). Every bar, slice,
  point and legend row with a count is clickable and lists exactly the
  entries it counts, and each entry opens its detail view. Use
  `components/v3/chartDrill.tsx`: a `Drill` predicate over the same rows the
  chart was computed from, shared bucket functions for the chart and the
  drill, and `DrillPanel`. When a chart comes from a server aggregate, the
  drill-down pages over the same set the aggregate reads, so the list length
  equals the number on the bar. A new chart without a drill-down is not done.
  Every analytics view offers the same windows (owner directive, 2026-09-30):
  since uptime, last day, week, month, 6 months and year (`WINDOWS` in
  `chartDrill.tsx`), and the server counts the whole window, never a sample.
  Its buckets come from `pkg/timebucket`.

- **A number on a page is counted by its service over the whole set**
  (13.21.0-beta, after the Command Center, Operations and Certificates
  showed 49, 500 and 723 expiring certificates for one tenant). A page
  never counts over a list it fetched: lists are paged and capped. A store
  call that is asked for more rows than it returns is a fault: callers page
  through (certs `allCertificates`, keycore `allKeys`, the `All*` HTTP
  clients). Conformance `list-cap` (`scripts/check-list-caps.py`) fails on
  any call asking a capped list for more than its maximum (13.24.0-beta, after
  it found seventeen such calls in nine services).
  Two pages showing the same quantity read the same endpoint.

- **The console shows a module only to someone who can read its data**
  (13.21.0-beta). A module whose data needs a permission names it in
  `MODULE_READ` (`web/dashboard/src/config/moduleRegistry.ts`;
  `tests/unit/moduleAccess.test.ts` checks the permission guards a real GET
  route). "System Admin" in the console is the server's platform
  administrator (root tenant and `auth.tenant.read`/`write`), never the
  tenant alone. Every view has an address (`#module/sub-option`) with real
  history; the shell writes it, and nothing else does. Searching objects
  (`components/v3/SidebarSearch.tsx`) is a `q` on the service's own list,
  inside that list's access scope, over the whole set (13.25.0-beta); a
  failed source reads "unavailable", never "no match".

- **Sub-options live in the sidebar** (owner directive, 2026-10-11: "not
  have sub tab", "the options should be as a sub option on the left when I
  expand", "for every sub tab", "click on the name to expand"). A module
  with several views lists them in `SUB_PANES`
  (`components/v3/SidebarSubNav.tsx`). Clicking the module's name in the
  sidebar unfolds them under it, and the module receives the choice as
  `subView`. The shell has no second column, card list or tab strip for a
  module's views, and a new module with views is added to `SUB_PANES`, not
  given its own switcher. The smoke test "a module's sub-options expand
  under its name in the sidebar" enforces this. A settings page's section
  strip counts too: System Administration's twelve tabs became
  Administration sub-options (13.23.0-beta). Modules sit in six groups by
  job (`NAV` in `components/v3/shellNav.ts`); a new module joins one. A
  link to another page may name its sub-option (`onNavigate("admin/users")`,
  a recommendation's `action.tab`), and `tests/unit/navTargets.test.ts`
  checks both parts exist.

- **Dashboard pages are visual first, with little text** (owner directive,
  2026-10-01, on Crypto Discovery: "immature buggy and not esthetic", "bar
  charts missing", "good UI, less text", "how to add other sources is
  missing"). A page leads with numbers, cards and charts. Explanations go
  in labels, tooltips or one short hint, not paragraphs. Everything a
  feature depends on (a source, an integration, a mount) shows its state on
  that page with the action that sets it up, or a link to its home. Chart
  fills are their own theme tokens (`--cls-*` in `index.css`), checked for
  separation in the light and dark themes. Look at the rendered page in
  both themes before calling it done.
  **A page shows state and controls; what they mean goes in the docs**
  (owner directive, 2026-10-12, on Service mTLS: "too much text for no
  reason", "very less text or no text", "can be added in documentation
  later on what it means"). No paragraph explains a feature on its page:
  the explanation is in the feature's document, or a `title` tooltip when
  one line is enough. A warning appears with the choice it warns about.

- **The console has its own look, one plane per theme** (owner directive,
  2026-10-11: a dark sidebar beside a white page "do not match"; wants an
  "enterprise text font"; "the UI should be unique", not look generated).
  - Sidebar, top bar and page share the theme's plane. No part of the shell
    carries the other theme.
  - The typeface is IBM Plex Sans and IBM Plex Mono, bundled and served
    from the console's own origin. Components name fonts only through
    `--font-sans` and `--font-mono`.
  - Colour, corner radius and shadow come from the tokens in `index.css`
    (Basalt and Limestone, a petrol accent, brass only in the mark). A
    component doesn't hard-code a family, text below 10px, or a fixed hue as
    text colour.
  - An explanatory paragraph folds to one line (`.vk-fold`); a warning or
    confirmation stays open (`data-keep`).
  - **One palette** (owner directive, 2026-10-12: the tinted certificate
    tiles "do not match with the colour of KMS, it should be uniform").
    Every surface is a flat token, never a gradient. Counts use the shared
    `Stat` tile. A count's number is neutral; hue marks only a state that
    needs attention, never one tile from another.
  - `web/dashboard/tests/unit/brandAndLegibility.test.ts` enforces these
    (docs/DECISIONS.md).


## Documentation is part of done

Every change is documented in the same commit. Don't leave it for later, and
don't wait to be asked. **A change to code, scripts, deployment or CI updates
three things: its CHANGELOG section, a learning.md entry, and the document of
the area it changed** (owner directive, 2026-10-17: "havent been adding to
learning and other documentation"; thirteen changes had updated only the
first two). A script or a check is documented where an operator or developer
looks for it (`docs/OPERATIONS_GUIDE.md`, `docs/TESTING_AND_CI.md`), not
only in its own header. **A lesson that applies to later work becomes a rule
in this file, and a security lesson goes on its `docs/SECURITY/` page, in
the same commit** (owner directive, 2026-10-17: "whatever the changes,
learning and things to be noted it has to be done in claude, documentation
... from previous changes"; the backfill is "Rules learned from faults"
below). Where each kind of change goes:

| What changed | Document it in |
|---|---|
| Anything a user, operator or buyer would notice (features, fixes, security changes, defaults, breaking config) | [CHANGELOG.md](CHANGELOG.md), under the current version |
| A non-obvious lesson: root cause of a bug, a trap, why something failed | [learning.md](learning.md), newest on top under today's date |
| An approach or design decision (why X over Y, what was rejected) | [docs/DECISIONS.md](docs/DECISIONS.md) |
| A security practice or rule | `docs/SECURITY/` (for example `SECURE_DEFAULTS.md`), linked from its README |
| A standing instruction from the owner | this file |
| Operating steps (deploy, rotate, recover), live checks, troubleshooting | the matching guide in `docs/`, for example `SECRET_ROTATION.md` or `OPERATIONS_GUIDE.md` |
| CI, test rules, repository scripts | [docs/TESTING_AND_CI.md](docs/TESTING_AND_CI.md) |
| A dashboard behaviour or rule | the feature's document, or `docs/DECISIONS.md` for a console-wide rule |
| API surface | `docs/API_REFERENCE.md` and the OpenAPI spec |

Write what a reviewer six months from now needs: what changed, why, how it's
enforced, and what's still open. `scripts/check-docs.sh` fails a change to
code without a VERSION bump and CHANGELOG section, without a learning.md
entry, or without an area document (`docs/`, not `docs/generated/`, or this
file; `Docs: n/a — <reason>` waives only the last). CI runs it on every push
to `main` (13.17.0-beta); run it before pushing.

## Before calling a change done

- **Find faults before the owner does** (owner directive, 2026-10-11: "why
  all these things are not part of learning and I have to keep giving
  commands to fix it"). A reported bug is a class, not an instance:
  - Fix the class. Search for every other copy of the fault, fix or list
    them, and add the test or conformance check that fails if it returns. A
    learning.md entry without that check is not a fix.
  - After every deploy or rebuild, and before calling a fix done, run
    `scripts/live-sweep.sh` (unhealthy containers, repeating errors) and
    `scripts/live-check.py` (every dashboard GET, signed in: no 401, 5xx or
    unregistered route) against the running stack and fix what they report,
    asked or not. Then check the changed feature on the live stack,
    not only in tests.
  - A service refuses to start without something it needs to answer
    requests (a verification key, a required URL); it never starts healthy
    and refuses every call.
  - A list of services, routes or features has one source (`pkg/svctls`,
    `pkg/route`, `pkg/features`). A second copy needs a test tying it to the
    source.
  - The dashboard ends a session on 401, so a service returns 401 only for a
    missing or unverifiable token; a refusal to a signed-in caller is 403 or
    4xx. A dashboard call whose credential is in its body, not the session
    token, sets `keepSessionOn401`.
  - A dashboard client file with no importer is deleted, not kept.
  - Every route needs a verified token and the caller's own tenant
    ([docs/SECURITY/TENANT_ISOLATION.md](docs/SECURITY/TENANT_ISOLATION.md)).
    `scripts/live-check.py` asks every dashboard route with no token and for
    another tenant; a route that answers by design is added to its `PUBLIC`
    or `SAME_FOR_EVERY_TENANT` list with the reason. A guard is judged by
    its callers, not its definition: KMIP served with no verifier and
    Autokey defined a tenant check nothing called (13.0.0-beta).
  - **`*` is everything inside the caller's own tenant, never across
    tenants** (owner report 2026-10-17, tenant and user management "all
    broken"). Acting on another tenant, the tenant list or a tenant's
    lifecycle needs a person whose verified token is for `root` and who
    holds the permission (`platformAdministrator` in auth); a role name
    (`super-admin`) grants nothing. A deny rule (`ui.module.deny:*`,
    `feature.deny.*`) matches only when granted by name, never through `*`
    ([docs/SECURITY/TENANT_ISOLATION.md](docs/SECURITY/TENANT_ISOLATION.md);
    `TestOnlyAPlatformAdministratorActsAcrossTenants`,
    `moduleRegistry.test.ts`).
  - **A selector of values the server stores is loaded from the server**
    (roles from `GET /auth/roles`, never a list in the dashboard or a doc),
    the server refuses a value it doesn't define, and a stored value outside
    the list is shown as it is, never replaced by the first option.
  - **A form sends only the fields its route accepts.** Services refuse
    unknown fields, so a record loaded and sent back whole fails every
    save; a smoke test that saves asserts the exact keys sent. Every
    write a page offers is exercised by a smoke test at least once.
  - **A page that shows another tenant names it in the request** (query
    `tenant_id`, on a route that admits a platform administrator), never
    by changing `X-Tenant-ID` on a copy of the session.
  - A control on a page has an effect (owner, 2026-10-12: in the key dialog
    "the tenant name display is not required"). No selector with one
    option, no field its request leaves out, no box that is always ticked;
    a dialog acts in the tenant chosen in the top bar and doesn't show it
    again. A control's value lives in state, never read from the DOM by
    id. `tests/unit/controlsAreReal.test.ts` enforces this.
  - An example of an API is checked by a test or says it isn't. A
    hand-written request or response (the REST API tab, a doc) is sent to
    the real handler by the service's `rest_examples_test.go`
    (`routetest.Examples`); a service without that test has its examples
    labelled as not checked (`VERIFIED_EXAMPLE_SERVICES`,
    `tests/unit/restCatalog.test.ts`). A response shown is one the service
    gave; where none could be obtained the example says so, never a guess.
  - A layout is rendered and tested in every state it has: collapsed and
    open, empty and crowded (a count of 4,200, not 3). A badge sits beside
    its icon, never over it. The smoke tests' `coveredControls` sweep
    (`web/dashboard/tests/fixtures/layout.ts`) fails when one control is
    drawn over another.
  - A popover or menu closes on a press outside it and on Escape, not only
    on its own button: its state comes from `components/v3/usePopover.ts`
    (13.12.0-beta; `tests/unit/popoversClose.test.ts`).

- **CI's verdict is read after every push** (2026-10-13: CI had failed on
  every one of its 274 runs and nobody had looked). Run
  `scripts/ci-status.sh --wait`; it needs no login. A red run is fixed
  before anything else, and when a job is red, check which of its later
  steps never ran. Before pushing a change to HSM, PKCS#11 or build files,
  run CI's Go job in a Linux container with `scripts/install-softhsm.sh`:
  the HSM tests skip on a Mac.
- **Tests are hermetic** (2026-10-17, after an intermittent CI failure).
  No test needs the Internet or DNS: names are resolved only through
  `pkg/ssrfguard`, which refuses real DNS in a test binary; answer names
  with `ssrfguard.SetResolverForTests`. A test can run twice in one process
  and has no data race. CI checks all three (`scripts/test-hermetic.sh`,
  `-count=2`, `-race`).
- **A test never passes in CI by skipping.** A dependency a test needs is
  required there (`VECTA_REQUIRE_SOFTHSM=1`, `VECTA_REQUIRE_JDK=1`), and a
  test that waits for an environment variable has a CI step that sets it.
- `make conformance` passes. It enforces rules 1–3 and 5, that routes use
  the `pkg/route` kernel, that every shell script parses under macOS
  bash 3.2, and that every route a doc or OpenAPI spec names is registered
  (`scripts/check-doc-routes.py`; `--write-index` refreshes the route index
  in `docs/API_REFERENCE.md`), and that `docs/generated/` (the route and
  product map) matches the source: after changing routes, handlers or
  dashboard calls, run `python3 scripts/generate_product_map.py` and commit
  the result.
- `make test-fips-modes` passes: the suite runs in FIPS modes `off`, `on` and
  `only`. A test of a non-approved feature calls `fipstest.SkipIfStrict` and
  is paired with a `fipstest.StrictOnly` test proving the clean refusal. Its allowlist only
  shrinks, and a new entry needs a crypto-boundary justification.
- `go vet` and `go test` pass for the touched packages. New security behaviour
  gets a test that proves the bad case is rejected.
- A dashboard change passes the CI dashboard job's own steps, run in order
  on the locked dependencies (`npm ci`): `generate:rest-catalog`,
  `validate:openapi`, `lint`, `check:component-size`, `typecheck`,
  `test:unit`, `build`, `test:smoke` (every spec). Commit the regenerated
  REST catalogue when it changes. The component size burn-down list
  (`web/dashboard/scripts/component-size-burndown.json`) only shrinks: put new
  code in its own file, never raise a ceiling. A test that needs Postgres
  counts only once CI's `integration-postgres` job lists its package.
- The documentation above is updated in the same change. New or changed
  endpoints, headers and env vars also go in `docs/API_REFERENCE.md`.
- Every security-relevant action and refusal emits a specific audit event
  (the HTTP middleware's generic request record isn't enough). New events are
  listed in `docs/SECURITY/` and proven by a test. Something that can't be
  audited (for example a service refusing to start) must say how it shows
  instead.
- A security-critical path is tested end to end with its real dependencies:
  Postgres for storage behaviour (`VECTA_TEST_POSTGRES_DSN`, CI
  `integration-postgres`) and the real protocol client for wire protocols (for
  example the KMIP TLS tests). SQLite alone is not evidence for
  JSONB/information_schema behaviour.
- The documentation above is updated in the same change.

## Rules learned from faults

Each rule below comes from a fault recorded in [learning.md](learning.md)
(2026-09-25 to 2026-10-17, version in brackets) and binds every later
change (owner directive, 2026-10-17: "whatever the changes, learning and
things to be noted it has to be done in claude, documentation"). A new
learning whose lesson applies to later work adds its rule here, and a
security one adds to its `docs/SECURITY/` page, in the same commit.
Security rules are explained in
[docs/SECURITY/FAIL_CLOSED_AND_VERIFICATION.md](docs/SECURITY/FAIL_CLOSED_AND_VERIFICATION.md).

**A claim is real only when its effect is traced**
- A setting has code that reads and applies it; a listener setting is
  proven by a handshake against the real server, not by the stored value
 . A config field goes with the last code that reads it.
- A status (`queued`, `sent`, `completed`, `applied`, `verified`) is written
  only by the code that did the work, from its result. A field named for a
  guarantee names what it read.
- Provenance and labels (algorithm, source, provider, key size) are read
  back from what was produced, never from what was asked; a benchmark or
  measurement needs a name `pkg/cryptocatalog.Lookup` accepts.
- A metric comes from the event of the work, never from a record callers
  post. A number derived from another number is not a measurement.
- Before a doc row, catalogue entry, capability list or CHANGELOG line names
  a capability, find its caller in a running path (`main.go` wiring, a
  registered route, a scheduler). Code with no caller outside its own file
  and test is removed, not documented. A capability list (KMIP Query, event
  catalogues, playbook triggers) is derived from or tested against what is
  routed or emitted (`TestQueryAdvertisesOnlyRoutedOperations`,
  `TestTriggerSubjectsAreEmitted`).
- A request field is documented only after reading the struct that decodes
  it; a doc example is checked against the handler (JSON tags, response
  keys, middleware), and every route a doc names is registered
  (`check-doc-routes.py`). When a feature is cut, its docs and guides go in
  the same change.
- A claim about the system ("I can't see it", "no test covers it", "the
  toolchain can't") is checked like any other: grep every test file, see
  the test run with `-v`, re-check the toolchain (13.3, 13.4).

**Tests prove the success path and the refusal**
- A feature with no test of its success path has not been shown to
  succeed (13.8). A credential or key operation's test uses the result: a
  rotated key gets a token and the old one 401; a generated key is checked
  by its actual public key; a versioned operation rotates between producing
  and consuming.
- A double of another service answers exactly that service's response
  shape, including fields it doesn't return; each client call has one test
  against the real handler, and an agent/service contract decodes the
  agent's request with the service's type and `DisallowUnknownFields`
  (`TestBitLockerJobRoundTripMatchesServiceContract`). A protocol double
  proves the wire format; the test still uses what was made, and a run with
  a failed step is a failed call (13.2).
- A third-party API gets an opt-in live test run before shipping; a vendor
  protocol is pinned against the vendor's reference; a primitive named
  after a standard passes the standard's vectors (`TestFF1IsNotAnAdditiveKeystream`);
  a client SDK or PKCS#11/JCA module is tested by a real consumer.
- A control or policy field ships with a test that the field changes the
  decision (allowed only by it gets in, without it refused). A test of "is
  X on record" uses the bytes the service sends for "no X" (11.4).
- A test that skips what it can't find also asserts it did something; a
  test asserting an asynchronous event checks it is among those recorded,
  not that it is the last; a test that sets process-wide state resets it in
  `t.Cleanup`.
- SQL is run once against Postgres before it ships; Postgres tests use their
  own schema; cursor paging is tested on Postgres; a value compared with a
  stored time is truncated to microseconds; a failed time parse is an error,
  never a zero value (12.2).

**Fail closed, show failure**
- No fail-open switch, no `dev`/`Any`/weaker fallback in TLS or listener
  setup, no random fallback for a key that must verify data later (derive
  it from `pkg/mek`), no `return empty, nil` on an upstream error. Fail
  closed at the smallest scope that protects the secret; a feature's key
  never takes down the audit pipeline.
- In a guard, "not applicable" may return quietly; "unable" is a failure
  and is audited.
- A missing or failed source reads "unavailable" or "not assessed" with the
  error; a composite with a failed source is an error; a zero is shown only
  when a check ran. The dashboard never catches a fetch into an empty list
  or renders constants.
- A write reports what it changed (`RowsAffected`, 404 for nothing) and
  validates enumerated values at the service. A read handler never creates
  data (`TestCBOMHistoryReadWritesNothing`).
- A caller of an optional service reads whether it is deployed from the
  deployment; unknown fails closed. A fallback taken on every call is a bug:
  count or audit fallbacks.

**Identity, credentials and outbound calls** (rule 4, rule 9)
- A route whose credential isn't a bearer token lists what that credential
  proves and binds every request field to it. MFA or step-up comes from a
  claim auth signs, never a header. Every token or assertion that grants
  access has tests with forged, tampered, expired, mis-addressed and
  replayed copies; "for now" in a verification path is a blocker.
- An M-of-N control binds each vote to a verified identity and refuses the
  requester; an identity is resolved to every form a check compares (ID and
  email) before the check.
- An internal client sends its service token and its test asserts the
  credential sent (`TestEvaluateSendsServiceToken`). When a service starts
  refusing tokenless callers, every client of it is fixed and tested in the
  same change.
- A credential on a request that may be redirected rides only in
  `Authorization` and is dropped on a host change (`CheckRedirect`). An
  outbound address is checked where it is dialled (`pkg/ssrfguard`), not by
  hostname. A URL that carries a credential is a secret, and errors name
  only its host.
- A secret in a new table is sealed in the store, never a `TEXT` column; a
  backup is a copy too. A secret that ever shipped is banned by value
  (`no-retired-public-secret`); secrets seeded into volumes are secrets.

**Integrity and audit** (rule 2)
- An integrity check names the trusted input an attacker can't write, and
  ships with a test that alters the stored data (row, recomputed row,
  deleted neighbour, root) and expects rejection. A check with no such
  input is removed.
- An audit register row names a test that fails when the event disappears
  or changes its `result` or `reason`, and checks the stored row at least
  once (13.15). An event counts as emitted when it is on the stream
  (`TestChainBrokenPublishedToStream`). A crypto operation's event is
  emitted from a deferred call so no return path skips it.
- Middleware in front of the kernel verifies and passes the outcome on
  (`route.WithInvalidToken`) so the kernel audits the refusal. A stream
  consumer terminates permanent errors and NAKs only transient ones.
- A service that opts out of the platform JWT middleware has a test that a
  tokenless call is refused and audited
  (`TestUnauthenticatedRequestsAreRefusedAndAudited`).
- A check whose cost grows with stored data has a bounded form for
  requests and a full form on a schedule, and says which one ran and when
  the full one last passed; it never stops early or samples and reports
  everything as checked (13.20).
- Data kept for an outage (a write-ahead buffer) and the key that protects
  it live on the service's own volume together; a record that fails its
  check is quarantined and audited, never skipped (13.20).

**Fix the class; remove completely**
- A hole found in one route means every route of that service is listed
  and accounted for, every service on `scripts/route-kernel-burndown.txt` is
  checked for the same shape, and for a sensitive operation every caller of
  the service method is found. Management writes are tested with no token
  and with a no-permission token, not only the data plane.
- A removal is finished in one sitting: the route, its entry in the cluster
  routing table and playbook catalogue, the store, settings, fields that
  fed it, previews or roadmap rows promising it, a second copy in another
  service, docs and guides, with a test that the routes are gone. Hiding a
  control in one view does not remove it. When a real capability lands,
  previews promising it go in the same release.
- Two engines or stores for one job: keep the one the UI uses, remove the
  other with a migration.

**Data**
- A person's decision and a machine's observation never share a column; the
  test runs the rewriting job afterwards (`TestReviewSurvivesRescan`).
- A node-local log never updates a replicated row; counters are derived at
  read. Tables are enumerated from `pg_class` (partitions), not
  `information_schema`.
- A job that must cover every tenant gets the tenant list from auth
  (`/internal/tenant-ids`) and falls back to what it knows when auth is
  down.
- A chart's numbers are counted by the owning service over the whole window
  with one predicate shared by count and list (`TestInventoryIsNeverASample`).
- Work whose duration depends on someone else's network runs in the
  background with a deadline and progress, refuses a second run, and a row
  left `running` by a restart reads as interrupted.
- Unattended work (playbooks, schedulers) re-checks the person's authority
  when it runs and fails closed when it can't ask; a detection runs on a
  scheduler, primary-only if it writes replicated data, tested by driving
  the tick.

**Dashboard**
- The console's feature set is the stack's own deployment file, mounted
  into the dashboard container; the image carries no copy, and an
  unreadable file is "unknown", never every feature on (13.28.0-beta,
  `deploymentSource.test.ts`). No role or allow rule shows a module the
  deployment leaves out. A load failure is page state shown once
  with a retry, never a toast on every poll.
- Every call goes through `serviceRequest` (`/svc/<name>`); one concept has
  one screen. A timer reads its callback through a ref. Undefined names are
  checked even in `@ts-nocheck` files (`check-nocheck-names.mjs`). A
  removed tab either removes its feature or moves its view.

**CI, process and deploy**
- Reproduce CI as CI runs it: the same unprivileged user, an empty cache,
  one command, its package order, a fresh database; every test step runs
  through `scripts/ci-go-test.sh`. When the way work flows changes, check
  every gate's trigger still fires; a skipped job is a question, not a pass
  (13.5, 13.10, 13.17).
- A flaky test is found by removing an assumption, not by rerunning. After
  the last edit the whole suite runs again. Verification and push are
  chained with `&&`.
- A dependency built from source is pinned by commit. A committed generated
  file has a freshness check; its generator is deterministic and holds no
  content of its own.
- A stack bootstrap step is one function every start path calls; a storage
  property (tmpfs, read-only) is checked where it takes effect (`mount` in
  the container); a script that creates a Compose volume uses
  `compose_volume_create`.
- A log scan matches the line that states the event, not text that
  continues it (13.13).
- With another session active, work in a worktree from the start,
  regenerate generated files there, push `HEAD:main`, and only
  `git merge --ff-only` in the shared checkout; never `checkout --`,
  `restore` or `reset` a file there. Before saying a change is live, the
  deploy checkout's `HEAD` equals `origin/main`.
