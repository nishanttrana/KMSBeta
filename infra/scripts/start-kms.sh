#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOYMENT_FILE="/etc/vecta/deployment.yaml"
SKIP_HEALTH=0
REMOVE_ORPHANS="${START_KMS_REMOVE_ORPHANS:-true}"

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
COMPOSE_WRAPPER="${ROOT_DIR}/infra/scripts/compose-kms.sh"
BASH_BIN="${BASH:-bash}"

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

prepare_certs_volumes() {
  local project_name="${COMPOSE_PROJECT_NAME:-vecta-kms}"
  local certs_volume="${project_name}_certs-key-data"
  local runtime_volume="${project_name}_runtime-certs"
  local passphrase_path="${CERTS_CRWK_PASSPHRASE_FILE:-/var/lib/vecta/certs/bootstrap.passphrase}"
  local bootstrap_secret="${CERTS_CRWK_BOOTSTRAP_PASSPHRASE:-vecta-dev-passphrase}"
  local prepared=0 helper_image=""

  docker volume create "${certs_volume}" >/dev/null 2>&1 || true
  docker volume create "${runtime_volume}" >/dev/null 2>&1 || true

  for helper_image in postgres:16.13-alpine alpine:3.20 busybox:1.36; do
    if docker run --rm \
      --volume "${certs_volume}:/data" \
      --volume "${runtime_volume}:/runtime" \
      --env "CERTS_CRWK_PASSPHRASE_FILE=${passphrase_path}" \
      --env "BOOTSTRAP_SECRET=${bootstrap_secret}" \
      "${helper_image}" \
      sh -lc '
        set -eu
        mkdir -p /data /runtime
        chown -R 100:101 /data /runtime
        chmod 700 /data /runtime
        case "${CERTS_CRWK_PASSPHRASE_FILE:-/var/lib/vecta/certs/bootstrap.passphrase}" in
          /var/lib/vecta/certs/*)
            target="/data/${CERTS_CRWK_PASSPHRASE_FILE#/var/lib/vecta/certs/}"
            mkdir -p "$(dirname "$target")"
            if [ ! -s "$target" ]; then
              printf %s "${BOOTSTRAP_SECRET:-vecta-dev-passphrase}" > "$target"
            fi
            chown 100:101 "$target"
            chmod 600 "$target"
            ;;
        esac
      ' >/dev/null 2>&1; then
      prepared=1
      break
    fi
  done

  if [[ "${prepared}" -ne 1 ]]; then
    echo "unable to prepare certificate bootstrap volumes" >&2
    return 1
  fi
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

extract_cert_security_acme_field() {
  local key="$1"
  awk -v wanted="${key}" '
    BEGIN { in_cert=0; in_acme=0 }
    /^[[:space:]]*cert_security:[[:space:]]*$/ { in_cert=1; next }
    in_cert == 1 {
      if ($0 !~ /^[[:space:]]{4,}/) { in_cert=0; in_acme=0; next }
      if ($0 ~ /^[[:space:]]{8,}acme_renewal:[[:space:]]*$/) { in_acme=1; next }
      if (in_acme == 1) {
        if ($0 !~ /^[[:space:]]{12,}/) { in_acme=0; next }
        if ($0 ~ "^[[:space:]]{12,}" wanted ":[[:space:]]*") {
          line=$0
          gsub("#.*$", "", line)
          sub("^[^:]*:[[:space:]]*", "", line)
          gsub(/[[:space:]]+$/, "", line)
          print line
          exit
        }
      }
    }
  ' "${DEPLOYMENT_FILE}" 2>/dev/null || true
}

json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '"%s"' "${value}"
}

apply_acme_renewal_policy() {
  local ari_enabled="${CERTS_ENABLE_ARI:-true}"
  local poll_hours="${CERTS_ARI_POLL_HOURS:-24}"
  local window_bias="${CERTS_ARI_WINDOW_BIAS_PERCENT:-35}"
  local emergency_hours="${CERTS_EMERGENCY_ROTATION_THRESHOLD_HOURS:-48}"
  local mass_threshold="${CERTS_MASS_RENEWAL_RISK_THRESHOLD:-8}"
  local config_json body attempt http_code response_file

  if ! command -v curl >/dev/null 2>&1; then
    echo "warning: curl not available; skipping ACME renewal policy bootstrap" >&2
    return 0
  fi

  config_json=$(printf '{"challenge_types":["http-01","dns-01","tls-alpn-01"],"auto_renew":true,"enable_ari":%s,"ari_poll_hours":%s,"ari_window_bias_percent":%s,"emergency_rotation_threshold_hours":%s,"mass_renewal_risk_threshold":%s,"require_eab":false,"allow_wildcard":true,"allow_ip_identifiers":false,"max_sans":100,"default_validity_days":397,"rate_limit_per_hour":1000}' \
    "${ari_enabled}" "${poll_hours}" "${window_bias}" "${emergency_hours}" "${mass_threshold}")
  body=$(printf '{"enabled":true,"updated_by":"start-kms","config_json":%s}' "$(json_escape "${config_json}")")
  response_file="$(mktemp)"

  for attempt in $(seq 1 20); do
    http_code="$(curl -sS -o "${response_file}" -w "%{http_code}" \
      -H 'Content-Type: application/json' \
      -X PUT \
      --data "${body}" \
      'http://127.0.0.1:8030/certs/protocols/acme?tenant_id=root' || true)"
    if [[ "${http_code}" == "200" ]]; then
      rm -f "${response_file}"
      return 0
    fi
    sleep 2
  done

  echo "warning: unable to apply ACME renewal policy from deployment config" >&2
  cat "${response_file}" >&2 || true
  rm -f "${response_file}"
  return 0
}

COMPOSE_PROFILES="$("${BASH_BIN}" "${PARSER}" "${DEPLOYMENT_FILE}")"
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
CERTS_ENABLE_ARI_CFG="$(extract_cert_security_acme_field enable_ari)"
CERTS_ARI_POLL_HOURS_CFG="$(extract_cert_security_acme_field ari_poll_hours)"
CERTS_ARI_WINDOW_BIAS_PERCENT_CFG="$(extract_cert_security_acme_field ari_window_bias_percent)"
CERTS_EMERGENCY_ROTATION_THRESHOLD_HOURS_CFG="$(extract_cert_security_acme_field emergency_rotation_threshold_hours)"
CERTS_MASS_RENEWAL_RISK_THRESHOLD_CFG="$(extract_cert_security_acme_field mass_renewal_risk_threshold)"

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
if [[ -n "${CERTS_ENABLE_ARI_CFG}" ]]; then
  export CERTS_ENABLE_ARI="${CERTS_ENABLE_ARI_CFG}"
fi
if [[ -n "${CERTS_ARI_POLL_HOURS_CFG}" ]]; then
  export CERTS_ARI_POLL_HOURS="${CERTS_ARI_POLL_HOURS_CFG}"
fi
if [[ -n "${CERTS_ARI_WINDOW_BIAS_PERCENT_CFG}" ]]; then
  export CERTS_ARI_WINDOW_BIAS_PERCENT="${CERTS_ARI_WINDOW_BIAS_PERCENT_CFG}"
fi
if [[ -n "${CERTS_EMERGENCY_ROTATION_THRESHOLD_HOURS_CFG}" ]]; then
  export CERTS_EMERGENCY_ROTATION_THRESHOLD_HOURS="${CERTS_EMERGENCY_ROTATION_THRESHOLD_HOURS_CFG}"
fi
if [[ -n "${CERTS_MASS_RENEWAL_RISK_THRESHOLD_CFG}" ]]; then
  export CERTS_MASS_RENEWAL_RISK_THRESHOLD="${CERTS_MASS_RENEWAL_RISK_THRESHOLD_CFG}"
fi

prepare_certs_volumes

echo "starting KMS with COMPOSE_PROFILES=${COMPOSE_PROFILES}"
up_args=(-d)
if [[ "${REMOVE_ORPHANS}" == "true" ]]; then
  up_args+=(--remove-orphans)
fi

if ! "${BASH_BIN}" "${COMPOSE_WRAPPER}" up "${up_args[@]}"; then
  echo "startup failed, attempting one forced recovery pass" >&2
  "${BASH_BIN}" "${STOP_SCRIPT}" "${DEPLOYMENT_FILE}" --force || true
  sleep 2
  "${BASH_BIN}" "${COMPOSE_WRAPPER}" up "${up_args[@]}"
fi

if [[ -f "${MESH_BOOTSTRAP}" ]]; then
  CONSUL_HTTP_ADDR="${CONSUL_HTTP_ADDR:-http://127.0.0.1:8500}" sh "${MESH_BOOTSTRAP}" || true
fi

apply_acme_renewal_policy

if [[ "${SKIP_HEALTH}" -ne 1 ]]; then
  "${BASH_BIN}" "${HEALTH_SCRIPT}" "${DEPLOYMENT_FILE}"
fi

echo "KMS startup completed"
