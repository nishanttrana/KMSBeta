# Changelog

All notable changes to Vecta KMS are recorded here. Versions follow the
`MAJOR.MINOR.PATCH[-beta]` scheme; the canonical version lives in the
[`VERSION`](VERSION) file and is published as a git tag (`vX.Y.Z`).

## [1.2.0-beta] — 2026-09-25

### Security
- **Closed a service-impersonation loophole.** `INTERNAL_SERVICE_BOOTSTRAP_SECRET`
  defaulted to a public placeholder (and `install.sh` never generated it), so
  anyone could derive every internal service's API key. Compose now requires
  the secret. `servicetoken.ValidateBootstrapSecret` rejects the placeholder and
  secrets shorter than 32 characters. Auth refuses to start on a weak value and
  revokes service keys derived from the placeholder on startup. `install.sh` and
  `run-local.sh` generate the secret.
- Rotating `INTERNAL_SERVICE_BOOTSTRAP_SECRET` now works: on start, auth
  retires every service API key derived from a previous secret, and
  `scripts/rotate-secrets.sh` rotates it.
- Placeholder secrets are rejected. `.env.example` values such as
  `your-workload-identity-secret` had been accepted as real secrets (and
  `deploy-local.sh` copied them into new `.env` files). `.env.example` now
  ships every secret empty. Every service refuses to start with a `your-...` /
  `change-me` secret (`pkg/config`). `deploy-local.sh` refuses placeholders and
  generates every missing secret, including the auth JWT signing key.
  `POSTGRES_PASSWORD` is now required by compose.
- Bootstrap admin default password is now `changeit` (forced change on first
  login, unchanged). The CLI user no longer falls back to the hardcoded
  `VectaCLI@2026`; unset means a random password.
- `make conformance` rule 3 (secure defaults) fails the build on any secret
  with a hardcoded fallback in compose or Go. See
  `docs/SECURITY/SECURE_DEFAULTS.md`.

### Process
- Documentation now ships with every change. `CLAUDE.md` holds the standing
  engineering rules and a table of where each kind of change is documented.
  `docs/DECISIONS.md` records design decisions and rejected alternatives. The
  CI job `docs-with-change` (`scripts/check-docs.sh`) fails a pull request
  that changes code without a CHANGELOG, learning, decisions, security or
  CLAUDE.md update. `make conformance` now also runs in CI.

### Fixed
- `install.sh` failed to parse on macOS's bash 3.2 (`syntax error near
  unexpected token ';;'`). The cause was PowerShell quote-escaping
  (`${var//\'/''}`) inside `$(...)`. It's replaced with a `ps_quote` helper,
  and conformance now runs `bash -n` over every shell script.
- **Fixed a cross-tenant authorization flaw in the (unreleased) service-to-service
  JWT work.** Service principals were recognised by role `client-service`
  alone, but *every* external client-credentials token carries that role, so
  any registered client could have bypassed tenant binding and per-key grants.
  A caller is now a service principal only if its verified JWT has role
  `client-service` **and** the reserved `service.internal` permission **and** a
  `kms-*` client id **and** the internal service tenant. The reserved
  permission is stripped from API-key creation, tenant-role writes, user login
  tokens and client-token requests from non-service clients; only the auth
  bootstrap can grant it. keycore decides service-principal status from JWT
  claims only (never from `X-Actor-*` headers). Covered by
  `pkg/tenantcheck/service_principal_test.go` and verified end-to-end.
- Service JWTs are now attached on internal keycore calls from autokey, certs,
  cloud, compliance, dataprotect, discovery, ekm, hyok, kmip, payment, pqc, sbom
  and signing (`servicetoken.SetDefault`), still non-enforcing (phase 3 of 4).
- Go vulnerabilities: **29 → 0** reachable (`govulncheck`). Toolchain
  1.26.0 → 1.27.1 fixes 25 stdlib advisories (crypto/x509, crypto/tls,
  net/http, html/template, net/url, encoding/asn1, encoding/xml, os);
  `golang.org/x/text` 0.39; gRPC pinned to the upstream fix for GO-2026-6443 /
  GO-2026-6348 / GO-2026-6061; unmaintained `golang.org/x/crypto/openpgp`
  replaced by `github.com/ProtonMail/go-crypto` in the secrets service.
- Dashboard: `npm audit` reports 0 vulnerabilities (previously 8 advisories, including high-severity ones in postcss, nanoid, browserslist and brace-expansion).
- Internal service ports (every `8xxx`/`18xxx`, NATS, Valkey, Consul, etcd) are
  now published on `127.0.0.1` only (`KMS_INTERNAL_BIND`); only Envoy
  (80/443/5696) listens on all interfaces. Previously Valkey, NATS and every
  service's HTTP/gRPC port were reachable from the LAN.

### Added
- **Security Command Center** home page and **Recommendations** page: live
  posture score, KPIs and ~30 rules over keys, certificates, access control,
  rotation, backups, cluster, posture and PQC state, each mapped to NIST SP
  800-57 / 800-131A / IR 8547, PCI DSS 4.0, DORA, CNSA 2.0 and CA/B Forum.
  Unassessable sources are shown as "not assessed" — never guessed. See
  [docs/RECOMMENDATIONS.md](docs/RECOMMENDATIONS.md).
- `deploy-local.sh`: one-command, re-runnable local deployment (adds new
  required secrets without touching existing ones, native-arch builds, JWT key
  sync, waits for health, prints the URL).

### Changed
- New design system: **Graphite** (dark) and **Paper** (light) themes — neutral
  surfaces, a single accent, colour reserved for status, larger type (11–14 px
  instead of 9–10 px), no gradients/neon glow. All modules inherit it through
  the existing tokens.
- Navigation: task-oriented groups in sentence case, sidebar module filter,
  breadcrumb in the top bar, search-first ⌘K button; duplicate user/logout pill
  removed from the top bar.
- Go 1.27.1; all Go modules updated (`go get -u ./...`); dashboard deps
  updated (React 19.3, Vite 8.3, Vitest 5, TanStack Query 5.103, Recharts 3.10,
  lucide 1.48, ESLint 10.11, Playwright 1.63).
- Images: golang 1.27.1, alpine 3.24, node 24.21 LTS, nginx 1.30.5, trivy
  0.74.0, postgres 17.11, pgbouncer 1.25.2, NATS 2.14.7, Valkey 9.0.6, Consul
  1.22.7, etcd 3.6.15, Envoy 1.39.1.
- Dockerfiles build for the host architecture (`TARGETARCH`) instead of forcing
  `amd64` — native arm64 on Apple Silicon instead of emulation — and use
  BuildKit cache mounts, so rebuilds reuse module and compile caches.
  `.dockerignore` now excludes `.gomodcache` (multi-GB) and stray binaries.
- CI: Node 24, actions/checkout v5, setup-node v5, setup-go v6.

### Fixed
- Key Management table showed `-` for Algorithm, Size/Curve and KCV on first
  load (the shell's key catalog dropped those fields).
- Three tabs (Key Analytics, Key Scheduling, Threat Protection) called `fetch`
  directly, failing lint; now use the tracked client.
- A 32 MB `workload` build artifact was committed to the repo; removed and
  ignored.

## [1.1.0-beta] — 2026-06-09

### Added
- Enterprise key-audit tier and enterprise controls + DSPM feed (keycore).
- Post-quantum readiness DSPM finding (`quantum_vulnerable_algorithm`): maps
  in-use classical asymmetric algorithms (RSA/ECC/DH) to a NIST PQC migration
  recommendation.
- Repeatable secret rotation tooling: [`scripts/rotate-secrets.sh`](scripts/rotate-secrets.sh)
  and [`docs/SECURITY/SECRET_ROTATION.md`](docs/SECURITY/SECRET_ROTATION.md).
- Version tracking: `VERSION` file, versioned image tags
  (`vecta/<svc>:${VECTA_VERSION}`), `BUILD_VERSION` stamped into services, and
  this changelog.
- Installer (`install.sh`) now provisions every secret the compose file
  requires — `POSTGRES_PASSWORD`, `NATS_AUTH_TOKEN`,
  `WORKLOAD_IDENTITY_SHARED_SECRET`, `SOFTWARE_VAULT_PASSPHRASE`,
  `INTERNAL_API_TOKEN`, `AUTH_BOOTSTRAP_CLI_PASSWORD` — plus a generated JWT
  signing keypair (public key in `.env`, private key seeded into the auth
  volume) and `VECTA_VERSION`. Image presence checks are version-aware.
- FeatureForge wired through the full deployment surface: `feature_forge` is
  now in the installer `FEATURE_KEYS` registry (data-driven features block, so
  it flows into `recommended`/`all`/`custom` profiles automatically); its
  tenant-scoped `ff_*` tables are surfaced in governance backup coverage under
  the `feature_intent_classification_and_promotion_governance` capability; and
  it is a first-class HA replication component (in `cluster-profile-full`).
- Custom HA cluster profile: `install.sh` can build a `cluster-profile-custom`
  by selecting individual services to replicate; the selection is passed via
  `CLUSTER_BOOTSTRAP_COMPONENTS` and seeded by cluster-manager. Core services
  (auth, keycore, policy, governance) are always replicated.
- `deployment.schema.json` updated to accept `metadata.install_mode` and the
  `spec.cluster_bootstrap` block (mode, replication_profile_id,
  replication_components, join_endpoint, join_token) that the installer emits.

### Changed
- Refreshed dashboard UI: centered minimal login (static brand glyph, reduced
  motion) and a premium dark-theme polish.
- Dependencies pinned to verified latest-stable registry versions (Go + npm).
- Dashboard ESLint debt cleared; `npm run lint` passes at `--max-warnings=0`.
- REST API catalog regenerated (945 routes) to match current services.

### Fixed
- Consolidated the worktree into a single package; replaced fabricated
  dependency versions that did not resolve on the public registries and left
  the tree un-buildable.
- Stopped tracking `.env` (it had leaked dev secrets); secrets rotated.
- Excluded `.git` (~900MB) and local state from the Docker build context via
  `.dockerignore`; it was being shipped to the daemon on every root-context
  service build and dominated (and stalled) image builds.

### Security
- Removed fabricated "security scan" reports that cited non-existent versions
  as safe; replaced with honest stubs pointing to real tooling
  (`govulncheck` / `npm audit` / `osv-scanner`).
- All tenant-scoped HTTP services require JWT; reconciler endpoints gated behind
  a shared internal token.

## [1.0.0-beta] — prior
- Initial beta: 30+ Go microservices, React dashboard, KMIP, PQC primitives,
  FIPS 140-3 target. See git history before `v1.1.0-beta`.
