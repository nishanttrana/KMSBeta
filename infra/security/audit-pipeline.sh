#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=infra/security/common.sh
source "${SCRIPT_DIR}/common.sh"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${SECURITY_DIR}/reports/${RUN_ID}"
mkdir -p "${RUN_DIR}"
export REPORT_ROOT="${RUN_DIR}"

declare -a CHECKS=("license" "cve" "side-channel" "sbom")
declare -A SCRIPT_BY_CHECK=(
  ["license"]="${SCRIPT_DIR}/license-audit.sh"
  ["cve"]="${SCRIPT_DIR}/cve-scan.sh"
  ["side-channel"]="${SCRIPT_DIR}/side-channel-suite.sh"
  ["sbom"]="${SCRIPT_DIR}/sbom-embed.sh"
)

overall="PASS"

for check in "${CHECKS[@]}"; do
  script_path="${SCRIPT_BY_CHECK[${check}]}"
  if bash "${script_path}"; then
    :
  else
    overall="FAIL"
  fi
done

report_md="${RUN_DIR}/audit-report.md"
report_json="${RUN_DIR}/audit-report.json"
report_txt="${RUN_DIR}/audit-report.txt"

{
  echo "Vecta KMS Supply Chain Security Audit"
  echo "generated_at=$(timestamp_utc)"
  echo "run_id=${RUN_ID}"
  echo "overall=${overall}"
  for check in "${CHECKS[@]}"; do
    status_file="${RUN_DIR}/${check}/status.txt"
    summary_file="${RUN_DIR}/${check}/summary.txt"
    status="FAIL"
    summary="no summary generated"
    [[ -f "${status_file}" ]] && status="$(cat "${status_file}")"
    [[ -f "${summary_file}" ]] && summary="$(cat "${summary_file}")"
    echo "${check}.status=${status}"
    echo "${check}.summary=${summary}"
  done
} > "${report_txt}"

{
  echo "# Vecta KMS Supply Chain Security Audit"
  echo
  echo "- Generated (UTC): $(timestamp_utc)"
  echo "- Run ID: \`${RUN_ID}\`"
  echo "- Overall: **${overall}**"
  echo
  echo "| Check | Status | Summary |"
  echo "|---|---|---|"
  for check in "${CHECKS[@]}"; do
    status_file="${RUN_DIR}/${check}/status.txt"
    summary_file="${RUN_DIR}/${check}/summary.txt"
    status="FAIL"
    summary="no summary generated"
    [[ -f "${status_file}" ]] && status="$(cat "${status_file}")"
    [[ -f "${summary_file}" ]] && summary="$(cat "${summary_file}")"
    summary="${summary//|/-}"
    echo "| ${check} | ${status} | ${summary} |"
  done
} > "${report_md}"

{
  echo "{"
  echo "  \"generated_at\": \"$(timestamp_utc)\","
  echo "  \"run_id\": \"${RUN_ID}\","
  echo "  \"overall\": \"${overall}\","
  echo "  \"checks\": ["
  for idx in "${!CHECKS[@]}"; do
    check="${CHECKS[${idx}]}"
    status_file="${RUN_DIR}/${check}/status.txt"
    summary_file="${RUN_DIR}/${check}/summary.txt"
    status="FAIL"
    summary="no summary generated"
    [[ -f "${status_file}" ]] && status="$(cat "${status_file}")"
    [[ -f "${summary_file}" ]] && summary="$(cat "${summary_file}")"
    comma=","
    if (( idx == ${#CHECKS[@]} - 1 )); then
      comma=""
    fi
    echo "    {\"name\": \"$(json_escape "${check}")\", \"status\": \"$(json_escape "${status}")\", \"summary\": \"$(json_escape "${summary}")\"}${comma}"
  done
  echo "  ]"
  echo "}"
} > "${report_json}"

latest_dir="${SECURITY_DIR}/reports/latest"
rm -rf "${latest_dir}"
mkdir -p "${latest_dir}"
cp -R "${RUN_DIR}/." "${latest_dir}/"

echo "Supply chain audit complete."
echo "Report directory: ${RUN_DIR}"
echo "Latest report: ${latest_dir}/audit-report.md"

if [[ "${overall}" != "PASS" ]]; then
  exit 1
fi
