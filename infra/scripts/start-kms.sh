#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"
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

resolve_project_name() {
  local value=""
  if [[ -n "${COMPOSE_PROJECT_NAME:-}" ]]; then
    printf '%s\n' "${COMPOSE_PROJECT_NAME}"
    return 0
  fi
  if [[ -f "${ENV_FILE}" ]]; then
    value="$(awk -F= '
      /^[[:space:]]*COMPOSE_PROJECT_NAME[[:space:]]*=/ {
        value=$0
        sub(/^[^=]*=/, "", value)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
        if (value != "") {
          print value
          exit
        }
      }
    ' "${ENV_FILE}" 2>/dev/null || true)"
    if [[ -n "${value}" ]]; then
      printf '%s\n' "${value}"
      return 0
    fi
  fi
  printf '%s\n' "vecta-kms"
}

# The certs service loads the internal root and Sub CA from a cache on its key
# volume before it can reach Postgres (docs/SECURITY/INTERNAL_TLS.md). On the
# first start of that version on an existing install, copy the two CA rows out
# of the running database over its Unix socket (no network; the signing keys
# stay wrapped by the certs root wrapping key). A fresh install has nothing
# to export: certs creates the CAs itself.
export_internal_pki_cache() {
  local certs_volume="$1" pg_user pg_db pg_password cache
  if docker run --rm --volume "${certs_volume}:/data:ro" alpine:3.24 test -s /data/internal-pki.json >/dev/null 2>&1; then
    return 0
  fi
  if ! "${BASH_BIN}" "${COMPOSE_WRAPPER}" ps --status running --services 2>/dev/null | grep -qx postgres; then
    return 0
  fi
  pg_user="$(sed -n 's/^POSTGRES_USER=//p' "${ROOT_DIR}/.env" 2>/dev/null | tail -n 1)"
  pg_db="$(sed -n 's/^POSTGRES_DB=//p' "${ROOT_DIR}/.env" 2>/dev/null | tail -n 1)"
  pg_password="$(sed -n 's/^POSTGRES_PASSWORD=//p' "${ROOT_DIR}/.env" 2>/dev/null | tail -n 1)"
  cache="$(PGPASSWORD="${pg_password}" "${BASH_BIN}" "${COMPOSE_WRAPPER}" exec -T -e PGPASSWORD postgres \
    psql -U "${pg_user:-postgres}" -d "${pg_db:-vecta}" -tA -v ON_ERROR_STOP=1 -c \
    "select json_build_object('root', (select row_to_json(c) from cert_cas c where c.tenant_id = 'root' and c.name = '${CERTS_RUNTIME_ROOT_CA_NAME:-vecta-runtime-root}' and c.status = 'active' limit 1), 'sub', (select row_to_json(c) from cert_cas c where c.tenant_id = 'root' and c.name = '${CERTS_INTERNAL_SUBCA_NAME:-vecta-internal-services}' and c.status = 'active' limit 1))" 2>/dev/null || true)"
  pg_password=""
  if [[ -z "${cache}" || "${cache}" == *'"root" : null'* || "${cache}" == *'"root":null'* ]]; then
    return 0
  fi
  printf '%s' "${cache}" | docker run --rm -i --volume "${certs_volume}:/data" alpine:3.24 \
    sh -c 'cat > /data/internal-pki.json && chown 100:101 /data/internal-pki.json && chmod 600 /data/internal-pki.json' \
    && echo "exported the internal PKI (runtime root and Sub CA) for the certs bootstrap"
}

prepare_certs_volumes() {
  local project_name
  project_name="$(resolve_project_name)"
  if [[ -z "${project_name}" ]]; then
    project_name="vecta-kms"
  fi
  local certs_volume="${project_name}_certs-key-data"
  local runtime_volume="${project_name}_runtime-certs"
  # Internal mTLS (docs/SECURITY/INTERNAL_TLS.md): the public trust bundle
  # every service reads, and the dashboard's TLS files (certs writes both).
  local trust_volume="${project_name}_internal-trust"
  local dashboard_tls_volume="${project_name}_dashboard-tls"
  # Server certificates for Postgres, NATS, Valkey and Consul; each daemon
  # mounts only its own subdirectory, which must exist before it starts.
  local infra_tls_volume="${project_name}_infra-tls"
  # Platform FIPS mode, written by governance (uid 10001), read by every
  # service before any cryptography (pkg/config).
  local platform_state_volume="${project_name}_platform-state"
  local passphrase_path="${CERTS_CRWK_PASSPHRASE_FILE:-/var/lib/vecta/certs/bootstrap.passphrase}"
  local prepared=0 helper_image="" helper_out=""

  docker volume create "${certs_volume}" >/dev/null 2>&1 || true
  docker volume create "${runtime_volume}" >/dev/null 2>&1 || true
  docker volume create "${trust_volume}" >/dev/null 2>&1 || true
  docker volume create "${dashboard_tls_volume}" >/dev/null 2>&1 || true
  docker volume create "${infra_tls_volume}" >/dev/null 2>&1 || true
  docker volume create "${platform_state_volume}" >/dev/null 2>&1 || true

  # The CRWK passphrase is generated inside the volume and never crosses the
  # host (infra/scripts/crwk-passphrase.sh). An operator-supplied one is
  # passed by variable name only (CLAUDE.md rule 9).
  for helper_image in postgres:16.13-alpine alpine:3.24 busybox:1.36; do
    if helper_out="$(docker run --rm \
      --volume "${ROOT_DIR}/infra/scripts/crwk-passphrase.sh:/crwk-passphrase.sh:ro" \
      --volume "${certs_volume}:/data" \
      --volume "${runtime_volume}:/runtime" \
      --volume "${trust_volume}:/trust" \
      --volume "${dashboard_tls_volume}:/dashboard-tls" \
      --volume "${infra_tls_volume}:/infra-tls" \
      --volume "${platform_state_volume}:/platform-state" \
      --env "CERTS_CRWK_PASSPHRASE_FILE=${passphrase_path}" \
      --env CERTS_CRWK_BOOTSTRAP_PASSPHRASE \
      "${helper_image}" \
      sh -lc '
        set -eu
        mkdir -p /data /runtime
        chown -R 100:101 /data /runtime
        chmod 700 /data /runtime
        mkdir -p /trust /dashboard-tls
        chown 100:101 /trust /dashboard-tls
        chmod 755 /trust
        chmod 750 /dashboard-tls
        mkdir -p /infra-tls/postgres /infra-tls/nats /infra-tls/valkey /infra-tls/consul
        chown -R 100:101 /infra-tls
        chmod 700 /infra-tls /infra-tls/postgres /infra-tls/nats /infra-tls/valkey /infra-tls/consul
        mkdir -p /platform-state
        chown 10001 /platform-state
        chmod 755 /platform-state
        sh /crwk-passphrase.sh
      ' 2>/dev/null)"; then
      prepared=1
      break
    fi
  done
  case "${helper_out}" in
    *crwk-public-default-retired*)
      echo "the certs CRWK passphrase was the retired public default: a new one was generated; certs re-keys the CRWK and rewraps every CA signer on start (audit.certs.crwk_rotated, docs/SECURITY/SECRET_ROTATION.md)" ;;
    *crwk-passphrase-written*)
      echo "certs CRWK passphrase generated in the certs key volume" ;;
  esac

  if [[ "${prepared}" -ne 1 ]]; then
    echo "unable to prepare certificate bootstrap volumes" >&2
    return 1
  fi
  export_internal_pki_cache "${certs_volume}"
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

  # These are also the certs service's built-in defaults (services/certs/
  # service_renewal.go). When the deployment doesn't override them there is
  # nothing to apply — and the PUT needs an authenticated admin, which a
  # startup script doesn't have.
  if [[ "${ari_enabled}" == "true" && "${poll_hours}" == "24" && "${window_bias}" == "35" \
        && "${emergency_hours}" == "48" && "${mass_threshold}" == "8" ]]; then
    return 0
  fi

  if ! command -v curl >/dev/null 2>&1; then
    echo "warning: curl not available; skipping ACME renewal policy bootstrap" >&2
    return 0
  fi

  config_json=$(printf '{"challenge_types":["http-01","dns-01","tls-alpn-01"],"auto_renew":true,"enable_ari":%s,"ari_poll_hours":%s,"ari_window_bias_percent":%s,"emergency_rotation_threshold_hours":%s,"mass_renewal_risk_threshold":%s,"require_eab":false,"allow_wildcard":true,"allow_ip_identifiers":false,"max_sans":100,"default_validity_days":397,"rate_limit_per_hour":1000}' \
    "${ari_enabled}" "${poll_hours}" "${window_bias}" "${emergency_hours}" "${mass_threshold}")
  body=$(printf '{"enabled":true,"updated_by":"start-kms","config_json":%s}' "$(json_escape "${config_json}")")
  response_file="$(mktemp)"
  # Services only speak mTLS; go through the HTTPS edge and verify it against
  # the internal root CA (docs/SECURITY/INTERNAL_TLS.md).
  edge_ca="$(mktemp)"
  "${BASH_BIN}" "${COMPOSE_WRAPPER}" exec -T certs cat /run/vecta/trust/root-ca.crt >"${edge_ca}" 2>/dev/null || true

  for attempt in $(seq 1 20); do
    http_code="$(curl -sS -o "${response_file}" -w "%{http_code}" \
      --cacert "${edge_ca}" \
      -H 'Content-Type: application/json' \
      -X PUT \
      --data "${body}" \
      'https://localhost/svc/certs/certs/protocols/acme?tenant_id=root' || true)"
    if [[ "${http_code}" == "200" ]]; then
      rm -f "${response_file}" "${edge_ca}"
      return 0
    fi
    sleep 2
  done
  rm -f "${edge_ca}"

  if [[ "${http_code}" == "401" || "${http_code}" == "403" ]]; then
    echo "note: custom ACME renewal settings in deployment.yaml need an admin session;" >&2
    echo "      set them in the dashboard: Certificates / PKI -> Enrollment Protocols -> ACME." >&2
    rm -f "${response_file}"
    return 0
  fi
  echo "warning: unable to apply ACME renewal policy from deployment config (HTTP ${http_code})" >&2
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

apply_acme_renewal_policy

if [[ "${SKIP_HEALTH}" -ne 1 ]]; then
  "${BASH_BIN}" "${HEALTH_SCRIPT}" "${DEPLOYMENT_FILE}"
fi

echo "KMS startup completed"
