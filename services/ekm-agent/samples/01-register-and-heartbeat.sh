#!/usr/bin/env bash
# Sample: Register an EKM agent and send a heartbeat using Bearer token auth.
# Usage: ./01-register-and-heartbeat.sh

BASE_URL="${EKM_API_BASE_URL:-https://localhost/svc/ekm}"
TOKEN="${EKM_AUTH_TOKEN:-your-bearer-token}"
TENANT="${TENANT_ID:-tenant-001}"
AGENT="${AGENT_ID:-agent-mssql-01}"

echo "==> Registering agent..."
curl -sk -X POST "${BASE_URL}/ekm/agents/register" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Tenant-ID: ${TENANT}" \
  -d '{
    "tenant_id": "'"${TENANT}"'",
    "agent_id": "'"${AGENT}"'",
    "name": "Sample TDE Agent",
    "role": "ekm-agent",
    "db_engine": "mssql",
    "host": "db-server-01.corp.local",
    "version": "1.0.0",
    "heartbeat_interval_sec": 30
  }'

echo ""
echo "==> Sending heartbeat..."
curl -sk -X POST "${BASE_URL}/ekm/agents/${AGENT}/heartbeat" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Tenant-ID: ${TENANT}" \
  -d '{
    "tenant_id": "'"${TENANT}"'",
    "status": "connected",
    "tde_state": "enabled",
    "active_key_id": "tde-key-001",
    "active_key_version": "v1",
    "metadata_json": "{\"hostname\":\"db-server-01\"}"
  }'

echo ""
echo "Done."
