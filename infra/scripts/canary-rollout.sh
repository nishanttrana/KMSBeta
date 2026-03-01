#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <compose-service> <health-url> [max_error_percent] [sample_count]"
  echo "Example: $0 dashboard http://127.0.0.1:5173 5 30"
  exit 1
fi

SERVICE="$1"
HEALTH_URL="$2"
MAX_ERROR_PERCENT="${3:-5}"
SAMPLE_COUNT="${4:-30}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl not found"
  exit 1
fi

echo "[canary] target service: ${SERVICE}"
echo "[canary] health url: ${HEALTH_URL}"
echo "[canary] max error %: ${MAX_ERROR_PERCENT}"
echo "[canary] sample count: ${SAMPLE_COUNT}"

CURRENT_CID="$(docker compose ps -q "${SERVICE}" || true)"
if [[ -z "${CURRENT_CID}" ]]; then
  echo "[canary] service container not found: ${SERVICE}"
  exit 1
fi

CURRENT_IMAGE_TAG="$(docker inspect -f '{{.Config.Image}}' "${CURRENT_CID}")"
CURRENT_IMAGE_ID="$(docker inspect -f '{{.Image}}' "${CURRENT_CID}")"
if [[ -z "${CURRENT_IMAGE_TAG}" || -z "${CURRENT_IMAGE_ID}" ]]; then
  echo "[canary] failed to resolve current image"
  exit 1
fi

echo "[canary] preserving rollback image id ${CURRENT_IMAGE_ID} as ${CURRENT_IMAGE_TAG}"
docker image tag "${CURRENT_IMAGE_ID}" "${CURRENT_IMAGE_TAG}"

echo "[canary] deploying candidate..."
docker compose up -d --build --no-deps "${SERVICE}"

NEW_CID="$(docker compose ps -q "${SERVICE}")"
if [[ -z "${NEW_CID}" ]]; then
  echo "[canary] failed to start candidate container"
  exit 1
fi

echo "[canary] waiting for healthy state..."
HEALTHY=0
for _ in $(seq 1 60); do
  STATUS="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${NEW_CID}" || true)"
  if [[ "${STATUS}" == "healthy" || "${STATUS}" == "running" ]]; then
    HEALTHY=1
    break
  fi
  sleep 2
done

if [[ "${HEALTHY}" -ne 1 ]]; then
  echo "[canary] candidate did not become healthy. rolling back..."
  docker image tag "${CURRENT_IMAGE_ID}" "${CURRENT_IMAGE_TAG}"
  docker compose up -d --no-deps "${SERVICE}"
  exit 1
fi

echo "[canary] running probe traffic..."
FAILURES=0
for _ in $(seq 1 "${SAMPLE_COUNT}"); do
  CODE="$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 3 "${HEALTH_URL}" || true)"
  if [[ ! "${CODE}" =~ ^2 ]]; then
    FAILURES=$((FAILURES + 1))
  fi
  sleep 1
done

ERROR_PERCENT=$((FAILURES * 100 / SAMPLE_COUNT))
echo "[canary] failures=${FAILURES}/${SAMPLE_COUNT} (${ERROR_PERCENT}%)"

if [[ "${ERROR_PERCENT}" -gt "${MAX_ERROR_PERCENT}" ]]; then
  echo "[canary] error budget exceeded. rolling back..."
  docker image tag "${CURRENT_IMAGE_ID}" "${CURRENT_IMAGE_TAG}"
  docker compose up -d --no-deps "${SERVICE}"
  exit 1
fi

echo "[canary] rollout accepted."
