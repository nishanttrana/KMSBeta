#!/usr/bin/env bash
set -euo pipefail

FILE="${1:-infra/deployment/deployment.yaml}"
if [[ ! -f "${FILE}" ]]; then
  echo "deployment file not found: ${FILE}" >&2
  exit 1
fi

FEATURE_ORDER=(
  secrets
  certs
  governance
  cloud_byok
  hyok_proxy
  kmip_server
  qkd_interface
  ekm_database
  payment_crypto
  compliance_dashboard
  sbom_cbom
  reporting_alerting
  ai_llm
  pqc_migration
  crypto_discovery
  mpc_engine
  data_protection
  clustering
)

declare -A ENABLED=()
hsm_mode="software"
in_features=0

while IFS= read -r raw; do
  line="${raw%%#*}"
  [[ -z "${line//[[:space:]]/}" ]] && continue

  if [[ "${line}" =~ ^[[:space:]]*hsm_mode:[[:space:]]*([a-zA-Z_]+) ]]; then
    hsm_mode="${BASH_REMATCH[1],,}"
  fi

  if [[ "${line}" =~ ^[[:space:]]*features:[[:space:]]*$ ]]; then
    in_features=1
    continue
  fi

  if [[ "${in_features}" -eq 1 ]]; then
    if [[ "${line}" =~ ^[[:space:]]{4,}([a-z0-9_]+):[[:space:]]*(true|false) ]]; then
      key="${BASH_REMATCH[1]}"
      val="${BASH_REMATCH[2]}"
      if [[ "${val}" == "true" ]]; then
        ENABLED["${key}"]=1
      else
        unset 'ENABLED[$key]' || true
      fi
      continue
    fi
    if [[ ! "${line}" =~ ^[[:space:]]{4,} ]]; then
      in_features=0
    fi
  fi
done < "${FILE}"

profiles=()
for feature in "${FEATURE_ORDER[@]}"; do
  if [[ -n "${ENABLED[${feature}]:-}" ]]; then
    profiles+=("${feature}")
  fi
done

case "${hsm_mode}" in
  hardware)
    profiles+=("hsm_hardware")
    ;;
  software)
    profiles+=("hsm_software")
    ;;
  auto)
    profiles+=("hsm_hardware" "hsm_software")
    ;;
  *)
    echo "invalid hsm_mode in ${FILE}: ${hsm_mode}" >&2
    exit 1
    ;;
esac

declare -A SEEN=()
ordered=()
for p in "${profiles[@]}"; do
  if [[ -z "${SEEN[${p}]:-}" ]]; then
    SEEN["${p}"]=1
    ordered+=("${p}")
  fi
done

(IFS=,; echo "${ordered[*]}")
