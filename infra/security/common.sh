#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SECURITY_DIR="${ROOT_DIR}/infra/security"
REPORT_ROOT="${REPORT_ROOT:-${SECURITY_DIR}/reports/latest}"

timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

detect_go_bin() {
  if has_cmd go; then
    echo "go"
    return
  fi
  if [[ -x "/c/Program Files/Go/bin/go.exe" ]]; then
    echo "/c/Program Files/Go/bin/go.exe"
    return
  fi
  if [[ -x "/usr/local/go/bin/go" ]]; then
    echo "/usr/local/go/bin/go"
    return
  fi
  echo ""
}

extract_vecta_images() {
  awk '/^[[:space:]]*image:[[:space:]]*/ { gsub(/"/, "", $2); print $2 }' "${ROOT_DIR}/docker-compose.yml" \
    | grep '^vecta/' \
    | sort -u
}

init_check_dir() {
  local check="$1"
  local dir="${REPORT_ROOT}/${check}"
  mkdir -p "${dir}"
  printf '%s\n' "$(timestamp_utc)" > "${dir}/started_at.txt"
  echo "${dir}"
}

write_status() {
  local check="$1"
  local status="$2"
  local summary="$3"
  local dir="${REPORT_ROOT}/${check}"
  mkdir -p "${dir}"
  printf '%s\n' "${status}" > "${dir}/status.txt"
  printf '%s\n' "${summary}" > "${dir}/summary.txt"
  printf '%s\n' "$(timestamp_utc)" > "${dir}/completed_at.txt"
}

sha256_file() {
  local file="$1"
  if has_cmd sha256sum; then
    sha256sum "${file}" | awk '{print $1}'
    return 0
  fi
  if has_cmd shasum; then
    shasum -a 256 "${file}" | awk '{print $1}'
    return 0
  fi
  if has_cmd openssl; then
    openssl dgst -sha256 "${file}" | awk '{print $2}'
    return 0
  fi
  return 1
}

json_escape() {
  local raw="$1"
  raw="${raw//\\/\\\\}"
  raw="${raw//\"/\\\"}"
  raw="${raw//$'\n'/\\n}"
  raw="${raw//$'\r'/}"
  printf '%s' "${raw}"
}
