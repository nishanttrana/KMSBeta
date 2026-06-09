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
