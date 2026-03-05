#!/usr/bin/env bash
# Sample: Check agent status and list all registered agents.
# Usage: ./03-check-agent-status.sh

BASE_URL="${EKM_API_BASE_URL:-https://localhost/svc/ekm}"
TOKEN="${EKM_AUTH_TOKEN:-your-bearer-token}"
TENANT="${TENANT_ID:-tenant-001}"
AGENT="${AGENT_ID:-agent-mssql-01}"

echo "==> List all agents..."
curl -sk "${BASE_URL}/ekm/agents" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Tenant-ID: ${TENANT}"

echo ""
echo "==> Get specific agent status..."
curl -sk "${BASE_URL}/ekm/agents/${AGENT}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Tenant-ID: ${TENANT}"

echo ""
echo "==> Get agent health..."
curl -sk "${BASE_URL}/ekm/agents/${AGENT}/health" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Tenant-ID: ${TENANT}"

echo ""
echo "Done."
