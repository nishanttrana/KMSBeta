#!/usr/bin/env bash
# Regenerates the Helm chart's stack description from docker-compose.yml
# (scripts/generate_helm_chart.py, docs/KUBERNETES.md).
#   scripts/helm-chart.sh           write deploy/helm/vecta-kms/files
#   scripts/helm-chart.sh --check   fail if the chart is out of date
# Compose is resolved with placeholder secrets in a clean environment, so no
# real value (.env is not read) can reach the chart.
set -euo pipefail
cd "$(dirname "$0")/.."
CHART=deploy/helm/vecta-kms
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

placeholders=()
for v in AUTH_BOOTSTRAP_CLI_PASSWORD INTERNAL_API_TOKEN INTERNAL_SERVICE_BOOTSTRAP_SECRET NATS_AUTH_TOKEN \
  POSTGRES_PASSWORD VALKEY_PASSWORD WORKLOAD_IDENTITY_SHARED_SECRET JWT_PUBLIC_KEY_B64; do
  placeholders+=("${v}=__VECTA_SECRET_${v}__")
done
env -i PATH="${PATH}" HOME="${HOME}" ${DOCKER_HOST:+DOCKER_HOST="${DOCKER_HOST}"} "${placeholders[@]}" VECTA_VERSION=__VECTA_VERSION__ \
  docker compose --env-file /dev/null --profile '*' config --format json > "${work}/compose.json"

if [[ "${1:-}" == "--check" ]]; then
  cp -R "${CHART}" "${work}/chart"
  python3 scripts/generate_helm_chart.py "${work}/compose.json" "$(pwd)" "${work}/chart"
  if ! diff -r "${CHART}/files" "${work}/chart/files" >/dev/null; then
    diff -r "${CHART}/files" "${work}/chart/files" | head -40 >&2
    echo "FAIL: ${CHART}/files is out of date with docker-compose.yml; run scripts/helm-chart.sh" >&2
    exit 1
  fi
  echo "PASS: Helm chart matches docker-compose.yml"
  exit 0
fi
python3 scripts/generate_helm_chart.py "${work}/compose.json" "$(pwd)" "${CHART}"
echo "wrote ${CHART}/files"
