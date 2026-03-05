#!/usr/bin/env bash
# Sample: Register an EKM agent using mutual TLS authentication.
# Usage: ./02-register-mtls.sh

BASE_URL="${EKM_API_BASE_URL:-https://localhost/svc/ekm}"
TENANT="${TENANT_ID:-tenant-001}"
AGENT="${AGENT_ID:-agent-mssql-01}"

CERT="${MTLS_CERT_PATH:-/etc/vecta-ekm/certs/agent.crt}"
KEY="${MTLS_KEY_PATH:-/etc/vecta-ekm/certs/agent.key}"
CA="${MTLS_CA_PATH:-/etc/vecta-ekm/certs/ca.crt}"

echo "==> Registering agent with mTLS..."
curl -s -X POST "${BASE_URL}/ekm/agents/register" \
  --cert "${CERT}" \
  --key "${KEY}" \
  --cacert "${CA}" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${TENANT}" \
  -d '{
    "tenant_id": "'"${TENANT}"'",
    "agent_id": "'"${AGENT}"'",
    "name": "mTLS TDE Agent",
    "role": "ekm-agent",
    "db_engine": "mssql",
    "host": "db-server-02.corp.local",
    "version": "1.0.0"
  }'

echo ""
echo "Done."
