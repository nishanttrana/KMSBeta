#!/usr/bin/env bash
# Documentation gate: a change to code, scripts, deployment or CI ships with
#   1. a minor VERSION bump and its CHANGELOG.md section,
#   2. a learning.md entry, and
#   3. the document of the area it changed: docs/ (not docs/generated/) or
#      CLAUDE.md.
# See "Documentation is part of done" in CLAUDE.md and docs/TESTING_AND_CI.md.
# Owner, 2026-10-17: "havent been adding to learning and other documentation"
# (the gate ran only on pull requests, and a CHANGELOG line alone passed it).
#
# Usage: scripts/check-docs.sh [base-ref]   (default: origin/main)
# A change with no area document can say why in a "Docs: n/a — <reason>"
# line in a commit message in the range; that waives (3) only.
set -euo pipefail
cd "$(dirname "$0")/.."

BASE="${1:-origin/main}"
# A push that creates the branch has no previous commit: check the last one.
git rev-parse -q --verify "${BASE}^{commit}" >/dev/null || BASE=HEAD~1
RANGE="$(git merge-base "$BASE" HEAD)..HEAD"
CHANGED="$(git diff --name-only "$RANGE")"

CODE='^(services/|pkg/|proto/|web/dashboard/src/|infra/|workload/|scripts/|\.github/workflows/|docker-compose[^/]*\.yml$|install[^/]*$|deploy-local\.sh$|run-local\.sh$|Makefile$|go\.mod$)'
AREA='^(docs/|CLAUDE\.md$)'

code=$(printf '%s\n' "$CHANGED" | grep -E "$CODE" | grep -v '_test\.go$' || true)

# Every section keeps its heading. Inserting a section by replacing the
# next one's heading left only its date: 13.22-13.25 and 13.42-13.44 lost
# theirs this way, and the version check below still passed (13.46.0-beta).
if orphans=$(grep -nE '^ — [0-9]{4}-[0-9]{2}-[0-9]{2}' CHANGELOG.md); then
  echo "FAIL [changelog-headings]: a CHANGELOG section lost its '## [version]' heading:"
  echo "$orphans"
  exit 1
fi
echo "PASS [changelog-headings]"

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

if [ -z "$code" ]; then
  echo "PASS [docs-with-change] (no code changed)"
  exit 0
fi
if ! printf '%s\n' "$CHANGED" | grep -qx 'learning.md'; then
  echo "FAIL [learning]: code changed but learning.md has no entry. Add what was learned under today's date (CLAUDE.md)."
  printf '  %s\n' $code | head -20
  exit 1
fi
echo "PASS [learning]"
area=$(printf '%s\n' "$CHANGED" | grep -E "$AREA" | grep -v '^docs/generated/' || true)
if [ -n "$area" ]; then
  echo "PASS [area-docs] $(printf '%s ' $area)"
  exit 0
fi
if git log --format=%B "$RANGE" | grep -qiE '^Docs: n/a'; then
  echo "PASS [area-docs] (waived: $(git log --format=%B "$RANGE" | grep -iE '^Docs: n/a' | head -1))"
  exit 0
fi
echo "FAIL [area-docs]: code changed but no document of its area (docs/, not docs/generated/, or CLAUDE.md) changed."
printf '  %s\n' $code | head -20
echo "Update the area's guide (see the table in CLAUDE.md), or add 'Docs: n/a — <reason>' to a commit message."
exit 1
