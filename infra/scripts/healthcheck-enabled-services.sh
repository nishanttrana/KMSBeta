#!/usr/bin/env bash
set -euo pipefail

DEPLOYMENT_FILE="${1:-infra/deployment/deployment.yaml}"
RETRIES="${RETRIES:-20}"
RETRY_DELAY_SECONDS="${RETRY_DELAY_SECONDS:-3}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROFILE_PARSER="${SCRIPT_DIR}/parse-deployment.sh"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"

if [[ ! -f "${DEPLOYMENT_FILE}" ]]; then
  DEPLOYMENT_FILE="${ROOT_DIR}/infra/deployment/deployment.yaml"
fi
if [[ ! -f "${DEPLOYMENT_FILE}" ]]; then
  echo "deployment file not found" >&2
  exit 1
fi

PROFILES="$("${PROFILE_PARSER}" "${DEPLOYMENT_FILE}")"

declare -A PROFILE_TO_SERVICE=(
  [secrets]="secrets"
  [certs]="certs"
  [governance]="governance"
  [cloud_byok]="cloud"
  [hyok_proxy]="hyok"
  [kmip_server]="kmip"
  [qkd_interface]="qkd"
  [qrng_generator]="qrng"
  [ekm_database]="ekm"
  [payment_crypto]="payment"
  [compliance_dashboard]="compliance"
  [sbom_cbom]="sbom"
  [reporting_alerting]="reporting"
  [posture_management]="posture"
  [ai_llm]="ai"
  [pqc_migration]="pqc"
  [crypto_discovery]="discovery"
  [mpc_engine]="mpc"
  [data_protection]="dataprotect"
  [clustering]="cluster-manager etcd"
  [hsm_hardware]="hsm-connector"
  [hsm_software]="software-vault"
)

enabled_services=(auth keycore audit policy)
IFS=',' read -r -a profile_list <<< "${PROFILES}"
for profile in "${profile_list[@]}"; do
  mapped="${PROFILE_TO_SERVICE[${profile}]:-}"
  if [[ -n "${mapped}" ]]; then
    for svc in ${mapped}; do
      enabled_services+=("${svc}")
    done
  fi
done

declare -A wanted=()
ordered=()
for svc in "${enabled_services[@]}"; do
  if [[ -z "${wanted[${svc}]:-}" ]]; then
    wanted["${svc}"]=1
    ordered+=("${svc}")
  fi
done

for ((attempt = 1; attempt <= RETRIES; attempt++)); do
  declare -A state_by_service=()
  declare -A health_by_service=()

  while IFS='|' read -r service state health; do
    service="${service//[[:space:]]/}"
    state="${state//[[:space:]]/}"
    health="${health//[[:space:]]/}"
    [[ -z "${service}" ]] && continue
    state_by_service["${service}"]="${state,,}"
    health_by_service["${service}"]="${health,,}"
  done < <(docker compose -f "${COMPOSE_FILE}" ps --format '{{.Service}}|{{.State}}|{{.Health}}')

  unhealthy=()
  healthy=()
  for svc in "${ordered[@]}"; do
    if [[ -z "${state_by_service[${svc}]:-}" ]]; then
      unhealthy+=("${svc} (missing)")
      continue
    fi

    state="${state_by_service[${svc}]}"
    health="${health_by_service[${svc}]:-}"

    if [[ "${state}" != "running" ]]; then
      unhealthy+=("${svc} (state=${state})")
      continue
    fi

    if [[ -n "${health}" && "${health}" != "healthy" ]]; then
      unhealthy+=("${svc} (health=${health})")
      continue
    fi

    healthy+=("${svc}")
  done

  if [[ "${#unhealthy[@]}" -eq 0 ]]; then
    for svc in "${healthy[@]}"; do
      echo "healthy: ${svc}"
    done
    exit 0
  fi

  if (( attempt < RETRIES )); then
    sleep "${RETRY_DELAY_SECONDS}"
  else
    echo "health checks failed: ${unhealthy[*]}" >&2
    exit 1
  fi
done
