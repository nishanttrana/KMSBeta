#!/usr/bin/env bash
# Sample: Trigger TDE key rotation via the agent rotation endpoint.
# Usage: ./04-rotate-key.sh

BASE_URL="${EKM_API_BASE_URL:-https://localhost/svc/ekm}"
TOKEN="${EKM_AUTH_TOKEN:-your-bearer-token}"
TENANT="${TENANT_ID:-tenant-001}"
AGENT="${AGENT_ID:-agent-mssql-01}"

echo "==> Rotating TDE key for agent ${AGENT}..."
curl -sk -X POST "${BASE_URL}/ekm/agents/${AGENT}/rotate" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Tenant-ID: ${TENANT}" \
  -d '{
    "tenant_id": "'"${TENANT}"'",
    "reason": "scheduled_rotation",
    "force": false
  }'

echo ""
echo "Done."
