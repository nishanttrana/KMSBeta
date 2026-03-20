#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PARSER="${ROOT_DIR}/infra/scripts/parse-deployment.sh"
PROJECT_NAME="vecta-kms"
NETWORK_NAME="${PROJECT_NAME}_kms_net"
COMPOSE_WRAPPER="${ROOT_DIR}/infra/scripts/compose-kms.sh"
BASH_BIN="${BASH:-bash}"

DEPLOYMENT_FILE="/etc/vecta/deployment.yaml"
FORCE=0

for arg in "$@"; do
  case "${arg}" in
    --force)
      FORCE=1
      ;;
    *)
      DEPLOYMENT_FILE="${arg}"
      ;;
  esac
done

wait_docker() {
  local timeout_seconds="${1:-45}"
  local deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    if docker info >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "docker daemon is not reachable after ${timeout_seconds}s" >&2
  return 1
}

purge_project_resources() {
  local ids
  ids="$(docker ps -aq --filter "label=com.docker.compose.project=${PROJECT_NAME}" || true)"
  if [[ -n "${ids}" ]]; then
    docker rm -f ${ids} >/dev/null 2>&1 || true
  fi
  docker network rm "${NETWORK_NAME}" >/dev/null 2>&1 || true
}

wait_docker 45

if [[ ! -f "${DEPLOYMENT_FILE}" ]]; then
  DEPLOYMENT_FILE="${ROOT_DIR}/infra/deployment/deployment.yaml"
fi

if [[ -f "${DEPLOYMENT_FILE}" ]]; then
  COMPOSE_PROFILES="$("${BASH_BIN}" "${PARSER}" "${DEPLOYMENT_FILE}")"
  export COMPOSE_PROFILES
fi

echo "stopping KMS stack"
set +e
"${BASH_BIN}" "${COMPOSE_WRAPPER}" down --remove-orphans
down_status=$?
set -e

if [[ "${down_status}" -ne 0 ]]; then
  echo "docker compose down returned exit code ${down_status}" >&2
fi

if [[ "${FORCE}" -eq 1 || "${down_status}" -ne 0 ]]; then
  purge_project_resources
fi

if [[ "${down_status}" -ne 0 && "${FORCE}" -ne 1 ]]; then
  exit "${down_status}"
fi

echo "KMS stack stopped"
