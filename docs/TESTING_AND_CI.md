# Testing and CI

How this repository's own changes are tested before and after they reach
`main`, and how to read the result. (For pipelines that *use* the KMS, see
[CI_CD_AUTOMATION.md](CI_CD_AUTOMATION.md).) The rules behind it are in
[CLAUDE.md](../CLAUDE.md), "Before calling a change done".

## The jobs

`.github/workflows/ci-quality.yml` runs on every push to `main` and on every
pull request.

| Job | What it proves |
|---|---|
| Documentation ships with the change | `scripts/check-docs.sh` over the pushed commits ([below](#the-documentation-gate)) |
| Go tests — FIPS mode off / on / only | the whole suite in each customer-selectable FIPS mode, on the certified module, with SoftHSM and a JDK required |
| Go tests — race detector | the whole suite under `-race` (13.8.0-beta) |
| Backend RuntimeCfg/Vet/Test/Security | runtime config validation, `scripts/conformance.sh`, `go vet`, every test run twice (`-count=2`), the suite with no network, `govulncheck` |
| Integration tests (Postgres) | storage behaviour SQLite cannot prove, a real NATS, an AWS KMS emulator (LocalStack) for BYOK, a real Envoy |
| Cluster replication and failover (three-node Postgres) | joining, replication, election, re-subscription, switchover and fencing between three databases |
| Helm chart | the chart matches docker-compose.yml, lints, and renders manifests valid for Kubernetes 1.31 (`scripts/check-helm-chart.sh`); the install itself is `scripts/test-helm-kind.sh`, run locally with built images |
| Volume repair (Docker Compose) | the volume scripts against real Docker volumes |
| Dashboard Lint/Type/Unit/Build/Smoke | the dashboard steps in order on the locked dependencies, then every Playwright spec |

The Kubernetes plugin is tested through `k8s.io/kms`'s own gRPC server on
a Unix socket with the generated KMS v2 client (`pkg/kmsplugin`), the same
pair kube-apiserver and real plugins use; no cluster is needed.

Before pushing, run the backend job's steps in order: `check-runtimecfg.sh`,
`scripts/conformance.sh`, `go vet ./...`, the tests, `scripts/test-hermetic.sh`
and `govulncheck ./...` (13.35.0-beta: skipping the first turned CI red).

`tests/no-crash.spec.ts` (13.31.0-beta) opens every module and sidebar
sub-option, read from `shellNav.ts` and `SUB_PANES`, twice: with every
service answering `{}` and with every service answering 503. A view that
falls into the error boundary or throws an uncaught error fails it. A new
view is covered without being listed.

## Reading the verdict

Run `scripts/ci-status.sh --wait` after every push. It needs no login for
this repository and prints each job and the step that failed. It asks
GitHub once a minute, which stays within the 60 unauthenticated calls an
hour (13.7.0-beta). A job's log needs a GitHub login; its annotations don't. Go
tests in CI run through `scripts/ci-go-test.sh`, which repeats each failing
test and what it printed as an annotation, and names a compile error or the
last lines of a run that failed before any test did (13.6.0-beta,
13.9.0-beta). Every step that runs Go tests uses it, also inside a
container.

When a job is red, check which of its later steps never ran: from the first
run until 13.4.0-beta one failing gate hid conformance, `go vet`, the tests and
the vulnerability scan behind it.

## Rules a test follows

- **Hermetic.** No test needs the Internet or DNS. Names are resolved only
  through `pkg/ssrfguard`, which refuses real DNS in a test binary; a test
  answers names with `ssrfguard.SetResolverForTests`. `make conformance`
  (`name-resolution`) fails on any other lookup. `scripts/test-hermetic.sh`
  runs the suite in a container with loopback only. It unpacks the
  certified FIPS module into the module cache first, because the container
  sees the cache read-only and an empty cache, as on GitHub's runner, has
  it packed (13.10.0-beta).
- **Repeatable.** A test can run twice in one process. It starts from a
  clean resource rather than from what an earlier run left behind: the HSM
  tests empty their SoftHSM tokens first (13.11.0-beta).
- **No data race.** The race detector job runs everything.
- **Never passes by skipping.** A dependency a test needs is required in CI
  (`VECTA_REQUIRE_SOFTHSM=1`, `VECTA_REQUIRE_JDK=1`), and a test that waits
  for an environment variable has a CI step that sets it.
- **Real dependencies.** HSM tests use a real PKCS#11 library: SoftHSM,
  built by `scripts/install-softhsm.sh` from one pinned commit, because no
  SoftHSM release does RSA-OAEP with SHA-256. It installs under its own
  prefix and needs no root (13.5.0-beta). Storage behaviour is tested on
  Postgres, wire protocols with the real client.

## Before pushing

- `make conformance` includes `list-cap` (13.24.0-beta): a call that asks a
  capped list (`if limit > N { limit = ... }`) for more than N rows fails,
  because the list answers with fewer and no error. Page through instead.
- Run the checks for what you touched: `make conformance`, `go vet` and
  `go test` for the touched packages, the dashboard steps above for a
  dashboard change, and `scripts/check-docs.sh`.
- A change to HSM, PKCS#11 or build files: run CI's Go job in a Linux
  container with `scripts/install-softhsm.sh`. The HSM tests skip on a Mac.
- Reproduce a CI step from CI's starting state (an empty module cache, a
  fresh database, no network), not from a warm laptop.

## The documentation gate

`scripts/check-docs.sh [base]` fails a change to code, scripts, deployment
or CI that does not ship with:

1. a minor `VERSION` bump with its `## [x.y.z]` section in `CHANGELOG.md`;
2. a `learning.md` entry;
3. an update to the document of the area it changed: something under `docs/`
   (not `docs/generated/`, which is regenerated) or `CLAUDE.md`.

A commit whose change has no area document can say why in a line
`Docs: n/a — <reason>`; that waives (3) only. Until 13.17.0-beta the gate
ran on pull requests only, and changes reach `main` without one, so it never
ran; it also passed on a CHANGELOG line alone.
