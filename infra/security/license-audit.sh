#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=infra/security/common.sh
source "${SCRIPT_DIR}/common.sh"

CHECK_NAME="license"
CHECK_DIR="$(init_check_dir "${CHECK_NAME}")"
BLOCKED_FILE="${BLOCKED_LICENSES_FILE:-${SECURITY_DIR}/blocked-licenses.txt}"
GO_BIN="${GO_BIN:-$(detect_go_bin)}"

if [[ -z "${GO_BIN}" ]]; then
  write_status "${CHECK_NAME}" "FAIL" "go toolchain not found in PATH"
  printf 'go command is required for license audit.\n' > "${CHECK_DIR}/error.txt"
  exit 1
fi

mapfile -t BLOCKED_PATTERNS < <(grep -Ev '^\s*(#|$)' "${BLOCKED_FILE}" | tr '[:upper:]' '[:lower:]')

detect_license_id() {
  local file="$1"
  if grep -Eiq 'mozilla public license|mpl-2\.0' "${file}"; then
    echo "MPL-2.0"
    return
  fi
  if grep -Eiq 'business source license|bsl 1\.1|bsl-1\.1|bsl-1\.0' "${file}"; then
    echo "BSL-1.1"
    return
  fi
  if grep -Eiq 'gnu affero general public license|agpl' "${file}"; then
    echo "AGPL"
    return
  fi
  if grep -Eiq 'server side public license|sspl' "${file}"; then
    echo "SSPL"
    return
  fi
  if grep -Eiq 'gnu lesser general public license|lgpl' "${file}"; then
    echo "LGPL"
    return
  fi
  if grep -Eiq 'gnu general public license|gpl' "${file}"; then
    echo "GPL"
    return
  fi
  if grep -Eiq 'apache license.*2\.0' "${file}"; then
    echo "Apache-2.0"
    return
  fi
  if grep -Eiq 'mit license' "${file}"; then
    echo "MIT"
    return
  fi
  if grep -Eiq 'bsd 3-clause|redistribution and use in source and binary forms' "${file}"; then
    echo "BSD-3-Clause"
    return
  fi
  if grep -Eiq 'bsd 2-clause|simplified bsd license' "${file}"; then
    echo "BSD-2-Clause"
    return
  fi
  if grep -Eiq '\bisc license\b' "${file}"; then
    echo "ISC"
    return
  fi
  if grep -Eiq 'unlicense' "${file}"; then
    echo "Unlicense"
    return
  fi
  if grep -Eiq 'creativecommons|cc0' "${file}"; then
    echo "CC0-1.0"
    return
  fi
  if grep -Eiq 'zlib license' "${file}"; then
    echo "Zlib"
    return
  fi
  if grep -Eiq 'postgresql licence|postgresql license' "${file}"; then
    echo "PostgreSQL"
    return
  fi
  echo "UNKNOWN"
}

is_blocked() {
  local license_id="$1"
  local file="$2"
  local norm
  norm="$(echo "${license_id}" | tr '[:upper:]' '[:lower:]')"
  for pattern in "${BLOCKED_PATTERNS[@]}"; do
    if [[ "${norm}" == *"${pattern}"* ]]; then
      return 0
    fi
  done

  if [[ "${license_id}" == "UNKNOWN" && -f "${file}" ]]; then
    local text
    text="$(tr '[:upper:]' '[:lower:]' < "${file}" | head -c 8192)"
    for pattern in "${BLOCKED_PATTERNS[@]}"; do
      if [[ "${text}" == *"${pattern}"* ]]; then
        return 0
      fi
    done
  fi
  return 1
}

"${GO_BIN}" mod download >/dev/null
"${GO_BIN}" list -m -f '{{if not .Main}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}' all > "${CHECK_DIR}/modules.txt"
cp "${ROOT_DIR}/go.mod" "${CHECK_DIR}/go.mod.snapshot"
cp "${ROOT_DIR}/go.sum" "${CHECK_DIR}/go.sum.snapshot"

printf 'module,version,license_file,license_id,status\n' > "${CHECK_DIR}/license-results.csv"

total=0
blocked=0
unknown=0
warnings=0

while IFS='|' read -r module version module_dir; do
  [[ -z "${module}" ]] && continue
  total=$((total + 1))

  if [[ -z "${module_dir}" || ! -d "${module_dir}" ]]; then
    status="WARN"
    warnings=$((warnings + 1))
    unknown=$((unknown + 1))
    printf '%s,%s,%s,%s,%s\n' "${module}" "${version}" "N/A" "UNKNOWN" "${status}" >> "${CHECK_DIR}/license-results.csv"
    continue
  fi

  license_file="$(find "${module_dir}" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'COPYRIGHT*' -o -iname 'NOTICE*' \) | head -n 1 || true)"
  status="PASS"
  license_id="UNKNOWN"

  if [[ -z "${license_file}" ]]; then
    status="WARN"
    warnings=$((warnings + 1))
    unknown=$((unknown + 1))
    printf '%s,%s,%s,%s,%s\n' "${module}" "${version}" "N/A" "${license_id}" "${status}" >> "${CHECK_DIR}/license-results.csv"
    continue
  fi

  license_id="$(detect_license_id "${license_file}")"
  if [[ "${license_id}" == "UNKNOWN" ]]; then
    status="WARN"
    warnings=$((warnings + 1))
    unknown=$((unknown + 1))
  fi

  if is_blocked "${license_id}" "${license_file}"; then
    status="FAIL"
    blocked=$((blocked + 1))
  fi

  printf '%s,%s,%s,%s,%s\n' "${module}" "${version}" "${license_file}" "${license_id}" "${status}" >> "${CHECK_DIR}/license-results.csv"
done < "${CHECK_DIR}/modules.txt"

if grep -Eiq 'agpl|sspl|gnu general public license|gnu affero general public license|\bgpl-?[0-9.]*\b' "${ROOT_DIR}/go.mod"; then
  blocked=$((blocked + 1))
  printf 'go.mod,N/A,%s,%s,%s\n' "${ROOT_DIR}/go.mod" "BLOCKED_PATTERN" "FAIL" >> "${CHECK_DIR}/license-results.csv"
fi

summary="checked ${total} modules, blocked=${blocked}, unknown=${unknown}, warnings=${warnings}"
printf '%s\n' "${summary}" > "${CHECK_DIR}/summary.txt"

if (( blocked > 0 )); then
  write_status "${CHECK_NAME}" "FAIL" "${summary}"
  exit 1
fi

write_status "${CHECK_NAME}" "PASS" "${summary}"
