#!/usr/bin/env bash
# Every service checks its configuration before it serves (CI "Runtime
# config validation gate"). A service passes when its own code calls one of:
#   - platform.Boot, which validates the shared configuration itself
#     (pkg/platform: pkgruntimecfg.ValidateServiceConfig);
#   - pkgruntimecfg.ValidateServiceConfig or ValidateHTTPPort;
#   - a validateConfig of its own (the customer-side agent, which reads a
#     file, not the platform environment).
# A call counts, a definition does not. Until 13.4.0-beta this looked for the
# words in main.go only: it failed four services that validate through
# platform.Boot, so it failed every run and nobody read it.
#
# Works under macOS's bash 3.2.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

missing=()
while IFS= read -r -d '' main; do
  dir="$(dirname "$main")"
  found=""
  for f in "$dir"/*.go; do
    case "$f" in *_test.go) continue ;; esac # a test does not start the service
    if grep -E 'platform\.Boot\(|ValidateServiceConfig\(|ValidateHTTPPort\(|validateConfig\(' "$f" 2>/dev/null | grep -Evq '^[[:space:]]*(func |//)'; then
      found=1
      break
    fi
  done
  if [ -z "$found" ]; then
    missing+=("${dir#services/}")
  fi
done < <(find services -mindepth 2 -maxdepth 2 -type f -name 'main.go' -print0)

if ((${#missing[@]} > 0)); then
  echo "[runtimecfg] Missing startup config validation in:"
  for item in "${missing[@]}"; do
    echo " - ${item}"
  done
  exit 1
fi

echo "[runtimecfg] Startup config validation present in all services."
