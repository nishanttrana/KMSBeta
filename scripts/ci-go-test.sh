#!/usr/bin/env bash
# go test for CI: the arguments go to `go test` unchanged, and when it fails
# every failing test is repeated as a GitHub annotation with the lines it
# printed. A job's log needs a GitHub login to read; its annotations do not,
# and scripts/ci-status.sh prints them. Until 13.6.0-beta a red test job
# said only "Process completed with exit code 1".
#
#   scripts/ci-go-test.sh ./pkg/... ./services/...
#
# Outside GitHub Actions it is plain `go test`.
set -u

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
go test "$@" 2>&1 | tee "$log"
status="${PIPESTATUS[0]}"
if [ "$status" -eq 0 ] || [ -z "${GITHUB_ACTIONS:-}" ]; then
  exit "$status"
fi

# One annotation per failing test (GitHub shows ten a step): its name as the
# title, the lines under it as the message. Then the packages that failed.
awk '
  function esc(s) { gsub(/%/, "%25", s); gsub(/\r/, "%0D", s); return s }
  function flush() { if (title != "" && n < 8) { printf "::error title=%s::%s\n", esc(title), body; n++ } title = ""; body = "" }
  /\.go:[0-9]+:[0-9]+: / && title == "" && n < 8 { printf "::error title=build::%s\n", esc($0); n++; next }
  /^--- FAIL: / { flush(); title = $3; body = esc($0); lines = 0; next }
  /^panic: / { flush(); title = "panic"; body = esc($0); lines = 0; next }
  /^(FAIL|ok|---|===|\?)/ { flush(); if ($1 == "FAIL" && NF >= 2) pkgs = pkgs " " $2; next }
  title != "" && lines < 12 { body = body "%0A" esc($0); lines++ }
  END { flush(); if (pkgs != "") printf "::error title=packages that failed::%s\n", esc(pkgs); if (n == 0 && pkgs == "") exit 3 }
' "$log" || {
  # No test failed: the build or the run itself did. Say how it ended.
  printf '::error title=go test failed before any test did::%s\n' "$(tail -n 15 "$log" | sed 's/%/%25/g' | awk '{printf "%s%%0A", $0}')"
}
exit "$status"
