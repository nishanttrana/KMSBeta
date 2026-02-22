#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STOP_SCRIPT="${ROOT_DIR}/infra/scripts/stop-kms.sh"
START_SCRIPT="${ROOT_DIR}/infra/scripts/start-kms.sh"

DEPLOYMENT_FILE="${1:-/etc/vecta/deployment.yaml}"

echo "running forced KMS recovery"
bash "${STOP_SCRIPT}" "${DEPLOYMENT_FILE}" --force || true
bash "${START_SCRIPT}" "${DEPLOYMENT_FILE}"
echo "KMS recovery completed"
