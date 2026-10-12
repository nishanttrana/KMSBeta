#!/usr/bin/env bash
# Says what GitHub Actions made of a commit: every job, and the step that
# failed. Run it after every push (CLAUDE.md): until 13.4.0-beta nobody
# looked, and CI had failed on all 274 runs it ever made.
#
#   scripts/ci-status.sh [commit]         default: origin/main
#   scripts/ci-status.sh --wait [commit]  poll until the runs finish (40 min)
#
# Exits 0 when every run for the commit succeeded, 1 when one failed, 2 when
# none is finished (or none exists yet). It reads GitHub's public API, so it
# needs no login for a public repository; for a private one put a token in
# GITHUB_TOKEN (it is sent as a header and never printed). Job logs need a
# login whatever the repository, so this prints the failing step's name and
# the job's annotations: scripts/ci-go-test.sh writes one for each failing
# test, with what it printed.
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
    jobs="$(api "actions/runs/${id}/jobs?per_page=100")" || { echo "GitHub did not answer for run ${id}" >&2; return 2; }
    # What a failed job said about itself: its annotations are public, its
    # log is not. scripts/ci-go-test.sh writes one for each failing test.
    notes="$(for job in $(printf '%s' "$jobs" | python3 -c 'import json,sys
for j in json.load(sys.stdin).get("jobs", []):
    if j.get("conclusion") == "failure": print(j["id"])'); do
      api "check-runs/${job}/annotations?per_page=50" | JOB="$job" python3 -c 'import json,os,sys
for a in json.load(sys.stdin):
    m = (a.get("message") or "").strip()
    if a.get("annotation_level") == "failure" and not m.startswith("Process completed with exit code"):
        print(json.dumps({"job": int(os.environ["JOB"]), "title": a.get("title") or "", "message": m}))'
    done)"
    printf '%s' "$jobs" | RUNS="$runs" RUN_ID="$id" NOTES="$notes" python3 -c '
import json, os, sys
jobs = json.load(sys.stdin).get("jobs", [])
run = next(r for r in json.loads(os.environ["RUNS"])["workflow_runs"] if str(r["id"]) == os.environ["RUN_ID"])
print("%s  %s  %s  %s" % (run["name"], run["head_sha"][:9], run["status"], run["conclusion"] or "-"))
for j in jobs:
    print("  %-10s %s" % (j["conclusion"] or j["status"], j["name"]))
    for s in j.get("steps", []):
        if s.get("conclusion") == "failure":
            print("             failed at step %d: %s" % (s["number"], s["name"]))
    for line in os.environ.get("NOTES", "").splitlines():
        note = json.loads(line)
        if note["job"] == j["id"]:
            print("             " + (note["title"] + ": " if note["title"] else "") + note["message"].replace("\n", "\n               "))
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
# GitHub allows 60 calls an hour without a login. Waiting costs one call a
# minute (the list of runs); the full report is made once, at the end. The
# first version polled the whole report every 30 seconds and was cut off.
tries=0
while [ "$tries" -lt 40 ]; do
  pending="$(api "actions/runs?head_sha=${SHA}&per_page=50" 2>/dev/null | python3 -c 'import json,sys
runs = json.load(sys.stdin).get("workflow_runs", [])
print("none" if not runs else sum(1 for r in runs if r["status"] != "completed"))' 2>/dev/null)"
  if [ "$pending" = "0" ]; then
    break
  fi
  tries=$((tries + 1))
  sleep 60
done
report
exit $?
