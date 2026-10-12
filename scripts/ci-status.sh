#!/usr/bin/env bash
# Says what GitHub Actions made of a commit: every job, and the step that
# failed. Run it after every push (CLAUDE.md): until 13.4.0-beta nobody
# looked, and CI had failed on all 274 runs it ever made.
#
#   scripts/ci-status.sh [commit]         default: origin/main
#   scripts/ci-status.sh --wait [commit]  poll until the runs finish (30 min)
#
# Exits 0 when every run for the commit succeeded, 1 when one failed, 2 when
# none is finished (or none exists yet). It reads GitHub's public API, so it
# needs no login for a public repository; for a private one put a token in
# GITHUB_TOKEN (it is sent as a header and never printed). Job logs need a
# login whatever the repository: this prints the failing step's name, and
# the steps themselves are in .github/workflows/ to run locally.
#
# Works under macOS's bash 3.2.
set -u

WAIT=""
if [ "${1:-}" = "--wait" ]; then
  WAIT=1
  shift
fi
cd "$(dirname "$0")/.." || exit 2
SHA="$(git rev-parse "${1:-origin/main}" 2>/dev/null)" || { echo "unknown commit: ${1:-origin/main}" >&2; exit 2; }
REPO="$(git remote get-url origin | sed -E 's#^.*[:/]([^/:]+/[^/]+)$#\1#; s#\.git$##')"

api() {
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    curl -fsS -H "Accept: application/vnd.github+json" -H "Authorization: Bearer ${GITHUB_TOKEN}" "https://api.github.com/repos/${REPO}/$1"
  else
    curl -fsS -H "Accept: application/vnd.github+json" "https://api.github.com/repos/${REPO}/$1"
  fi
}

report() {
  runs="$(api "actions/runs?head_sha=${SHA}&per_page=50")" || { echo "GitHub did not answer for ${REPO}" >&2; return 2; }
  ids="$(printf '%s' "$runs" | python3 -c 'import json,sys
for r in json.load(sys.stdin).get("workflow_runs", []): print(r["id"])')"
  if [ -z "$ids" ]; then
    echo "no run for ${SHA:0:9} in ${REPO} yet"
    return 2
  fi
  status=0
  for id in $ids; do
    api "actions/runs/${id}/jobs?per_page=100" | RUNS="$runs" RUN_ID="$id" python3 -c '
import json, os, sys
jobs = json.load(sys.stdin).get("jobs", [])
run = next(r for r in json.loads(os.environ["RUNS"])["workflow_runs"] if str(r["id"]) == os.environ["RUN_ID"])
print("%s  %s  %s  %s" % (run["name"], run["head_sha"][:9], run["status"], run["conclusion"] or "-"))
for j in jobs:
    print("  %-10s %s" % (j["conclusion"] or j["status"], j["name"]))
    for s in j.get("steps", []):
        if s.get("conclusion") == "failure":
            print("             failed at step %d: %s" % (s["number"], s["name"]))
print("  " + run["html_url"])
if run["status"] != "completed":
    sys.exit(2)
sys.exit(0 if run["conclusion"] in ("success", "skipped") else 1)
'
    rc=$?
    if [ "$rc" -eq 1 ]; then
      status=1
    elif [ "$rc" -eq 2 ] && [ "$status" -eq 0 ]; then
      status=2
    fi
  done
  return "$status"
}

if [ -z "$WAIT" ]; then
  report
  exit $?
fi
tries=0
while :; do
  out="$(report)"
  rc=$?
  if [ "$rc" -ne 2 ] || [ "$tries" -ge 60 ]; then
    printf '%s\n' "$out"
    exit "$rc"
  fi
  tries=$((tries + 1))
  sleep 30
done
