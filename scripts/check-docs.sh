#!/usr/bin/env bash
# Documentation gate: a change to code or deployment must ship with its docs
# (CHANGELOG.md, learning.md, docs/DECISIONS.md, docs/SECURITY/ or CLAUDE.md).
# See "Documentation is part of done" in CLAUDE.md.
#
# Usage: scripts/check-docs.sh [base-ref]   (default: origin/main)
# A genuinely doc-free change (pure refactor, test-only) can opt out with a
# "Docs: n/a — <reason>" line in any commit message in the range.
set -euo pipefail
cd "$(dirname "$0")/.."

BASE="${1:-origin/main}"
RANGE="$(git merge-base "$BASE" HEAD)..HEAD"
CHANGED="$(git diff --name-only "$RANGE")"

CODE='^(services/|pkg/|proto/|web/dashboard/src/|infra/|workload/|scripts/|docker-compose[^/]*\.yml$|install[^/]*$|deploy-local\.sh$|run-local\.sh$|Makefile$|go\.mod$)'
DOCS='^(CHANGELOG\.md|learning\.md|CLAUDE\.md|docs/DECISIONS\.md|docs/SECURITY/)'

code=$(printf '%s\n' "$CHANGED" | grep -E "$CODE" | grep -v '_test\.go$' || true)
docs=$(printf '%s\n' "$CHANGED" | grep -E "$DOCS" || true)

# Every KMS change bumps the minor version (or major), with a CHANGELOG heading.
if [ -n "$code" ]; then
  old_v="$(git show "$(git merge-base "$BASE" HEAD):VERSION" 2>/dev/null | tr -d '[:space:]')"
  new_v="$(tr -d '[:space:]' < VERSION)"
  old_mm="$(printf '%s' "$old_v" | sed -E 's/^([0-9]+)\.([0-9]+).*/\1 \2/')"
  new_mm="$(printf '%s' "$new_v" | sed -E 's/^([0-9]+)\.([0-9]+).*/\1 \2/')"
  set -- $old_mm; om=${1:-0}; on=${2:-0}
  set -- $new_mm; nm=${1:-0}; nn=${2:-0}
  if [ "$nm" -lt "$om" ] || { [ "$nm" -eq "$om" ] && [ "$nn" -le "$on" ]; }; then
    echo "FAIL [version-bump]: code changed but VERSION ($old_v -> $new_v) has no minor bump. Bump MINOR in VERSION."
    exit 1
  fi
  if ! grep -qF "## [$new_v]" CHANGELOG.md; then
    echo "FAIL [version-bump]: CHANGELOG.md has no '## [$new_v]' section."
    exit 1
  fi
  echo "PASS [version-bump] $old_v -> $new_v"
fi

if [ -z "$code" ] || [ -n "$docs" ]; then
  echo "PASS [docs-with-change]"
  exit 0
fi
if git log --format=%B "$RANGE" | grep -qiE '^Docs: n/a'; then
  echo "PASS [docs-with-change] (opted out via 'Docs: n/a')"
  exit 0
fi
echo "FAIL [docs-with-change]: code changed but no CHANGELOG.md / learning.md / docs/DECISIONS.md / docs/SECURITY/ / CLAUDE.md update."
printf '  %s\n' $code | head -20
echo "Document the change (see CLAUDE.md), or add 'Docs: n/a — <reason>' to a commit message."
exit 1
