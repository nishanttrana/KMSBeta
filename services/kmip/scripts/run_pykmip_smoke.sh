#!/usr/bin/env bash
set -euo pipefail

NETWORK="${NETWORK:-vecta-kms_kms_net}"
HOST="${KMIP_HOST:-envoy}"
PORT="${KMIP_PORT:-5696}"
VERSION="${KMIP_VERSION:-1.4}"

docker run --rm --network "${NETWORK}" \
  -v "$(pwd)/infra/certs/out/kmip-client:/certs/client:ro" \
  -v "$(pwd)/infra/certs/out/ca:/certs/ca:ro" \
  -v "$(pwd)/services/kmip/scripts:/scripts:ro" \
  python:3.11-slim sh -lc \
  "pip install -q pykmip && python /scripts/pykmip_smoke.py --host ${HOST} --port ${PORT} --cert /certs/client/tls.crt --key /certs/client/tls.key --ca /certs/ca/ca.crt --version ${VERSION}"
