#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

missing=()
while IFS= read -r -d '' file; do
  if ! grep -Eq 'ValidateServiceConfig\(|ValidateHTTPPort\(|validateConfig\(' "$file"; then
    missing+=("$(dirname "$file" | sed 's#^services/##')")
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
