# Version Updates & Changelog

Dependency versions are tracked in the manifests themselves and in git history;
this directory does not maintain a hand-written package inventory (those drift
and become inaccurate).

> A previous `UPDATE_SUMMARY.md` here claimed "202 packages updated" to
> dependency versions that **do not exist** on the public registries (the same
> fabricated set flagged in [../SECURITY/README.md](../SECURITY/README.md)). It
> has been **removed**.

## Where to look instead

- **Go:** `go.mod` / `go.sum`; update with `go get -u ./... && go mod tidy`,
  then `go build ./... && go test ./...`.
- **Dashboard (npm):** `web/dashboard/package.json` / `package-lock.json`;
  check with `npx npm-check-updates`, apply, then
  `npm ci && npm run typecheck && npm run build`.
- **Java provider:** `services/jca-provider/pom.xml`.
- **Changelog:** `git log` (commit messages document each dependency change and
  its verification).

## 2026-09 refresh (v1.2.0-beta)

Toolchain, modules, npm packages, container base images and CI actions were all
moved to current stable releases; see the `1.2.0-beta` entry in
[`CHANGELOG.md`](../../CHANGELOG.md) for the exact versions and why. Container
images are pinned in the Dockerfiles, `docker-compose.yml`, `install.sh` and
`deploy-local.sh` — update all four together.

Deliberately **not** upgraded:
- **PostgreSQL major version** (stays 17.x): a major upgrade needs a
  `pg_upgrade`/dump-restore of the existing data volume; do it as a planned
  migration.
- **TypeScript 7** (native compiler): typescript-eslint does not support it
  yet; stays on 6.0.x.
- **Debian bookworm** runtime for the HSM integration images (CGO/PKCS#11
  vendor libraries are validated against bookworm).

