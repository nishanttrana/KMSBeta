#!/usr/bin/env bash
# Runs the two-node integration tests (replication engine and secure join)
# against two
# throwaway Postgres 17 servers with wal_level=logical. Cleans up afterwards.
# Usage: ./scripts/test-cluster-replication.sh
set -euo pipefail
cd "$(dirname "$0")/.."

NET="vecta-repl-test-$$"
PW="$(openssl rand -hex 16)"
IMAGE="${PG_IMAGE:-postgres:17.11-alpine}"
cleanup() {
  if [ "${TEST_RC:-0}" != "0" ]; then
    for role in primary member; do
      echo "--- ${role} postgres log (last 40 lines)"; docker logs "${NET}-${role}" 2>&1 | tail -40
    done
  fi
  docker rm -f "${NET}-primary" "${NET}-member" >/dev/null 2>&1 || true
  docker network rm "${NET}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "${NET}" >/dev/null
for role in primary member; do
  docker run -d --name "${NET}-${role}" --network "${NET}" --network-alias "${role}" \
    -e POSTGRES_PASSWORD="${PW}" -p 127.0.0.1::5432 "${IMAGE}" \
    postgres -c wal_level=logical -c max_replication_slots=64 -c max_wal_senders=64 \
      -c max_worker_processes=96 -c max_logical_replication_workers=64 -c max_sync_workers_per_subscription=4 >/dev/null
done
for role in primary member; do
  for _ in $(seq 1 60); do
    docker exec "${NET}-${role}" pg_isready -U postgres >/dev/null 2>&1 && break
    sleep 1
  done
done
port() { docker port "${NET}-$1" 5432/tcp | head -1 | awk -F: '{print $NF}'; }

VECTA_REPL_PRIMARY_DSN="postgres://postgres:${PW}@127.0.0.1:$(port primary)/postgres?sslmode=disable" \
VECTA_REPL_MEMBER_DSN="postgres://postgres:${PW}@127.0.0.1:$(port member)/postgres?sslmode=disable" \
VECTA_REPL_PRIMARY_HOST="primary:5432" \
  go test -count=1 -p 1 -v -run 'TestSelectiveReplicationBetweenTwoNodes|TestSecureJoinEndToEnd' ./pkg/clusterrepl ./services/cluster-manager || TEST_RC=$?
exit "${TEST_RC:-0}"
