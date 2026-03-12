#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${KMS_ROOT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
STATIC_OVERRIDE_FILE="${ROOT_DIR}/docker-compose.override.yml"
PLATFORM_OVERRIDE_FILE="${ROOT_DIR}/.tmp_compose.platform.override.yml"

read -r -a DOCKER_CMD <<< "${KMS_DOCKER_BIN:-docker}"

host_platform() {
  case "$(uname -m)" in
    arm64|aarch64)
      echo "linux/arm64/v8"
      ;;
    x86_64|amd64)
      echo "linux/amd64"
      ;;
    *)
      "${DOCKER_CMD[@]}" version --format '{{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null || true
      ;;
  esac
}

normalize_platform() {
  case "${1:-}" in
    ""|"/")
      host_platform
      ;;
    linux/arm64|linux/aarch64)
      echo "linux/arm64/v8"
      ;;
    linux/aarch64)
      echo "linux/arm64/v8"
      ;;
    *)
      echo "$1"
      ;;
  esac
}

image_platform() {
  local image="$1"
  local detected=""
  detected="$("${DOCKER_CMD[@]}" image inspect --format '{{.Os}}/{{.Architecture}}' "${image}" 2>/dev/null | head -n 1 || true)"
  normalize_platform "${detected}"
}

update_platform_override() {
  [[ -f "${COMPOSE_FILE}" ]] || return 0

  local -a file_args=(-f "${COMPOSE_FILE}")
  if [[ -f "${STATIC_OVERRIDE_FILE}" ]]; then
    file_args+=(-f "${STATIC_OVERRIDE_FILE}")
  fi

  local config_output=""
  if ! config_output="$("${DOCKER_CMD[@]}" compose "${file_args[@]}" config 2>/dev/null)"; then
    rm -f "${PLATFORM_OVERRIDE_FILE}"
    return 0
  fi

  local host=""
  host="$(host_platform)"
  local tmp_file=""
  tmp_file="$(mktemp)"
  local wrote=0
  local service="" image="" platform=""

  while IFS='|' read -r service image; do
    [[ -n "${service}" && -n "${image}" ]] || continue
    image="${image%\"}"
    image="${image#\"}"
    image="${image%\'}"
    image="${image#\'}"
    platform="$(image_platform "${image}")"
    [[ -n "${platform}" ]] || continue
    if [[ "${platform}" == "${host}" ]]; then
      continue
    fi
    if [[ "${wrote}" -eq 0 ]]; then
      printf "services:\n" > "${tmp_file}"
    fi
    printf "  %s:\n    platform: %s\n" "${service}" "${platform}" >> "${tmp_file}"
    wrote=1
  done < <(
    printf '%s\n' "${config_output}" | awk '
      /^services:[[:space:]]*$/ {
        in_services=1
        next
      }
      in_services == 1 && /^[^[:space:]]/ {
        in_services=0
        current=""
      }
      in_services == 1 && /^[[:space:]]{2}[[:alnum:]_.-]+:[[:space:]]*$/ {
        current=$1
        sub(":$", "", current)
        next
      }
      in_services == 1 && current != "" && /^[[:space:]]{4}image:[[:space:]]*/ {
        image=$0
        sub(/^[[:space:]]{4}image:[[:space:]]*/, "", image)
        print current "|" image
      }
    '
  )

  if [[ "${wrote}" -eq 1 ]]; then
    mv "${tmp_file}" "${PLATFORM_OVERRIDE_FILE}"
  else
    rm -f "${tmp_file}" "${PLATFORM_OVERRIDE_FILE}"
  fi
}

update_platform_override

compose_args=(-f "${COMPOSE_FILE}")
if [[ -f "${STATIC_OVERRIDE_FILE}" ]]; then
  compose_args+=(-f "${STATIC_OVERRIDE_FILE}")
fi
if [[ -f "${PLATFORM_OVERRIDE_FILE}" ]]; then
  compose_args+=(-f "${PLATFORM_OVERRIDE_FILE}")
fi

exec "${DOCKER_CMD[@]}" compose "${compose_args[@]}" "$@"
