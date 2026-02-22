#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOYMENT_FILE="/etc/vecta/deployment.yaml"
SKIP_HEALTH=0

for arg in "$@"; do
  case "${arg}" in
    --skip-health)
      SKIP_HEALTH=1
      ;;
    *)
      DEPLOYMENT_FILE="${arg}"
      ;;
  esac
done

PARSER="${ROOT_DIR}/infra/scripts/parse-deployment.sh"
STOP_SCRIPT="${ROOT_DIR}/infra/scripts/stop-kms.sh"
MESH_BOOTSTRAP="${ROOT_DIR}/infra/consul/bootstrap-mesh.sh"
HEALTH_SCRIPT="${ROOT_DIR}/infra/scripts/healthcheck-enabled-services.sh"
CERT_SCRIPT="${ROOT_DIR}/infra/certs/generate-mtls.sh"
CERTS_OUT_DIR="${VECTA_CERTS_OUT:-infra/certs/out}"
if [[ "${CERTS_OUT_DIR}" != /* ]]; then
  CERTS_OUT_DIR="${ROOT_DIR}/${CERTS_OUT_DIR#./}"
fi
ENVOY_CERT="${CERTS_OUT_DIR}/envoy/tls.crt"
ENVOY_KEY="${CERTS_OUT_DIR}/envoy/tls.key"

wait_docker() {
  local timeout_seconds="${1:-90}"
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

if [[ ! -f "${DEPLOYMENT_FILE}" ]]; then
  DEPLOYMENT_FILE="${ROOT_DIR}/infra/deployment/deployment.yaml"
fi
if [[ ! -f "${DEPLOYMENT_FILE}" ]]; then
  echo "deployment file not found" >&2
  exit 1
fi

wait_docker 90

extract_cert_security_field() {
  local key="$1"
  awk -v wanted="${key}" '
    BEGIN { in_cert=0 }
    /^[[:space:]]*cert_security:[[:space:]]*$/ { in_cert=1; next }
    in_cert == 1 {
      if ($0 !~ /^[[:space:]]{4,}/) { in_cert=0; next }
      if ($0 ~ "^[[:space:]]{4,}" wanted ":[[:space:]]*") {
        line=$0
        gsub("#.*$", "", line)
        sub("^[^:]*:[[:space:]]*", "", line)
        gsub(/[[:space:]]+$/, "", line)
        print line
        exit
      }
    }
  ' "${DEPLOYMENT_FILE}" 2>/dev/null || true
}

if [[ ! -f "${ENVOY_CERT}" || ! -f "${ENVOY_KEY}" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    bash "${CERT_SCRIPT}" "${CERTS_OUT_DIR}"
  else
    echo "missing envoy TLS certs and openssl is unavailable; run ${CERT_SCRIPT} on a machine with openssl" >&2
    exit 1
  fi
fi

COMPOSE_PROFILES="$("${PARSER}" "${DEPLOYMENT_FILE}")"
export COMPOSE_PROFILES

HSM_MODE="$(awk '
  /^[[:space:]]*hsm_mode:/ {
    gsub("#.*$", "", $0)
    sub(/^[^:]*:[[:space:]]*/, "", $0)
    gsub(/[[:space:]]+$/, "", $0)
    print tolower($0)
    exit
  }
' "${DEPLOYMENT_FILE}")"

if [[ -n "${HSM_MODE}" ]]; then
  export HSM_MODE
fi

if [[ -z "${HSM_ENDPOINT:-}" ]]; then
  case "${HSM_MODE:-software}" in
    hardware)
      export HSM_ENDPOINT="hsm-connector:18430"
      ;;
    software)
      export HSM_ENDPOINT="software-vault:18440"
      ;;
    auto)
      export HSM_ENDPOINT="hsm-connector:18430"
      ;;
  esac
fi

CERTS_STORAGE_MODE_CFG="$(extract_cert_security_field cert_storage_mode)"
CERTS_ROOT_KEY_MODE_CFG="$(extract_cert_security_field root_key_mode)"
CERTS_CRWK_SEALED_PATH_CFG="$(extract_cert_security_field sealed_key_path)"
CERTS_CRWK_PASSPHRASE_FILE_CFG="$(extract_cert_security_field passphrase_file_path)"
CERTS_CRWK_USE_TPM_SEAL_CFG="$(extract_cert_security_field use_tpm_seal)"

if [[ -n "${CERTS_STORAGE_MODE_CFG}" ]]; then
  export CERTS_STORAGE_MODE="${CERTS_STORAGE_MODE_CFG}"
fi
if [[ -n "${CERTS_ROOT_KEY_MODE_CFG}" ]]; then
  export CERTS_ROOT_KEY_MODE="${CERTS_ROOT_KEY_MODE_CFG}"
fi
if [[ -n "${CERTS_CRWK_SEALED_PATH_CFG}" ]]; then
  export CERTS_CRWK_SEALED_PATH="${CERTS_CRWK_SEALED_PATH_CFG}"
fi
if [[ -n "${CERTS_CRWK_PASSPHRASE_FILE_CFG}" ]]; then
  export CERTS_CRWK_PASSPHRASE_FILE="${CERTS_CRWK_PASSPHRASE_FILE_CFG}"
elif [[ -f "/etc/vecta/certs-bootstrap.secret" ]]; then
  export CERTS_CRWK_PASSPHRASE_FILE="/etc/vecta/certs-bootstrap.secret"
fi
if [[ -n "${CERTS_CRWK_USE_TPM_SEAL_CFG}" ]]; then
  export CERTS_CRWK_USE_TPM_SEAL="${CERTS_CRWK_USE_TPM_SEAL_CFG}"
fi

echo "starting KMS with COMPOSE_PROFILES=${COMPOSE_PROFILES}"
if ! docker compose -f "${ROOT_DIR}/docker-compose.yml" up -d --remove-orphans; then
  echo "startup failed, attempting one forced recovery pass" >&2
  bash "${STOP_SCRIPT}" "${DEPLOYMENT_FILE}" --force || true
  sleep 2
  docker compose -f "${ROOT_DIR}/docker-compose.yml" up -d --remove-orphans
fi

if [[ -f "${MESH_BOOTSTRAP}" ]]; then
  CONSUL_HTTP_ADDR="${CONSUL_HTTP_ADDR:-http://127.0.0.1:8500}" sh "${MESH_BOOTSTRAP}" || true
fi

if [[ "${SKIP_HEALTH}" -ne 1 ]]; then
  bash "${HEALTH_SCRIPT}" "${DEPLOYMENT_FILE}"
fi

echo "KMS startup completed"
