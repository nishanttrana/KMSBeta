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
