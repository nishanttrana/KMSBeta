#!/usr/bin/env bash
# Fails when any Go function, type, variable or constant is unreachable from
# every main and every test (docs/TESTING_AND_CI.md, "No unreachable code").
# Until 13.41.0-beta the repository carried six packages nothing imported and
# about 160 functions nothing called, among them the only check of a client's
# ip_whitelist. Code with no caller is removed, not kept "for later".
#
#   scripts/check-dead-code.sh
#
# The tools are pinned so a new release can't change the verdict.
set -euo pipefail

cd "$(dirname "$0")/.."
bin="$(mktemp -d)"
trap 'rm -rf "$bin"' EXIT
GOBIN="$bin" go install golang.org/x/tools/cmd/deadcode@v0.52.0
GOBIN="$bin" go install honnef.co/go/tools/cmd/staticcheck@v0.8.2

# Not ./...: a dashboard dependency ships Go sources under node_modules.
pkgs=()
while IFS= read -r p; do pkgs+=("$p"); done < <(go list ./... | grep -v /node_modules/)

status=0
dead="$("$bin/deadcode" -test "${pkgs[@]}")"
if [ -n "$dead" ]; then
  printf 'Functions nothing calls (remove them):\n%s\n' "$dead"
  status=1
fi
if ! "$bin/staticcheck" -checks U1000 -tests=true "${pkgs[@]}"; then
  echo "Unused types, variables or constants (remove them)."
  status=1
fi
exit "$status"
