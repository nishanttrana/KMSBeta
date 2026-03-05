/* Auto-extracted from VectaDashboardV3 for modularization. */

export const REST_API_CATALOG = [
  {
    id: "keys-list",
    group: "Key Management",
    title: "List Keys",
    service: "keycore",
    method: "GET",
    pathTemplate: "/keys?tenant_id={{tenant_id}}&limit=100&offset=0",
    bodyTemplate: "",
    description: "Returns key inventory metadata for a tenant. This does not return plaintext key material.",
    requestExample: "GET /svc/keycore/keys?tenant_id=root&limit=100&offset=0",
    responseExample: {
      items: [{ id: "key_01", name: "prod-db-master", algorithm: "AES-256-GCM", status: "active", version: 2 }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid query parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller does not have list-keys permission" }
    ]
  },
  {
    id: "keys-create",
    group: "Key Management",
    title: "Create Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "name": "customer-key-name",\n  "algorithm": "AES-256-GCM",\n  "purpose": "encrypt-decrypt",\n  "status": "active",\n  "export_allowed": false\n}',
    description: "Creates a new cryptographic key object with policy attributes.",
    requestExample: "POST /svc/keycore/keys",
    responseExample: { key: { id: "key_123", name: "customer-key-name", algorithm: "AES-256-GCM", status: "active" } },
    errorCodes: [
      { code: 400, meaning: "Invalid algorithm/payload" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 409, meaning: "Key name already exists for tenant" }
    ]
  },
  {
    id: "key-encrypt",
    group: "Crypto",
    title: "Encrypt",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/encrypt",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "plaintext": "hello-vecta",\n  "encoding": "utf-8",\n  "aad": "context",\n  "aad_encoding": "utf-8",\n  "iv_mode": "internal",\n  "reference_id": "txn-001"\n}',
    description: "Encrypts plaintext with selected key. For AEAD ciphers, AAD integrity is enforced.",
    requestExample: "POST /svc/keycore/keys/{key_id}/encrypt",
    responseExample: {
      ciphertext: "BASE64...",
      iv: "BASE64...",
      key_id: "key_123",
      version: 2,
      reference_id: "txn-001"
    },
    errorCodes: [
      { code: 400, meaning: "Payload invalid (encoding/AAD/IV mismatch)" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Key state/policy blocks encryption (disabled/deactivated/limit)" }
    ]
  },
  {
    id: "key-decrypt",
    group: "Crypto",
    title: "Decrypt",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/decrypt",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "ciphertext": "BASE64...",\n  "binary_encoding": "base64",\n  "aad": "context",\n  "aad_encoding": "utf-8",\n  "iv": "BASE64...",\n  "output_encoding": "utf-8"\n}',
    description: "Decrypts ciphertext and verifies AEAD tag when applicable.",
    requestExample: "POST /svc/keycore/keys/{key_id}/decrypt",
    responseExample: { plaintext: "hello-vecta", output_encoding: "utf-8", key_id: "key_123", version: 2 },
    errorCodes: [
      { code: 400, meaning: "Ciphertext or IV format invalid" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Authentication/tag verification failed or wrong key/version" }
    ]
  },
  {
    id: "key-sign",
    group: "Crypto",
    title: "Sign",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/sign",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "message": "payload-to-sign",\n  "encoding": "utf-8",\n  "algorithm": "ecdsa-sha384"\n}',
    description: "Generates digital signature or MAC depending on key type/purpose.",
    requestExample: "POST /svc/keycore/keys/{key_id}/sign",
    responseExample: { signature: "BASE64...", algorithm: "ecdsa-sha384", key_id: "key_123", version: 2 },
    errorCodes: [
      { code: 400, meaning: "Algorithm/message invalid for selected key" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Key policy/state blocks signing" }
    ]
  },
  {
    id: "key-verify",
    group: "Crypto",
    title: "Verify",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/verify",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "message": "payload-to-sign",\n  "signature": "BASE64...",\n  "encoding": "utf-8",\n  "algorithm": "ecdsa-sha384"\n}',
    description: "Verifies signature validity for the supplied payload and key.",
    requestExample: "POST /svc/keycore/keys/{key_id}/verify",
    responseExample: { valid: true, algorithm: "ecdsa-sha384", key_id: "key_123" },
    errorCodes: [
      { code: 400, meaning: "Signature/message format invalid" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Verification failed" }
    ]
  },
  {
    id: "crypto-hash",
    group: "Crypto",
    title: "Hash",
    service: "keycore",
    method: "POST",
    pathTemplate: "/crypto/hash",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "algorithm": "sha-512",\n  "input": "data-to-hash",\n  "encoding": "utf-8",\n  "binary_output_encoding": "base64"\n}',
    description: "Runs backend hash function and returns digest.",
    requestExample: "POST /svc/keycore/crypto/hash",
    responseExample: { algorithm: "sha-512", digest: "BASE64...", digest_encoding: "base64" },
    errorCodes: [
      { code: 400, meaning: "Unsupported hash algorithm or malformed input" },
      { code: 401, meaning: "JWT missing/invalid/expired" }
    ]
  },
  {
    id: "crypto-random",
    group: "Crypto",
    title: "Random Bytes",
    service: "keycore",
    method: "POST",
    pathTemplate: "/crypto/random",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "length": 32,\n  "source": "kms-csprng",\n  "binary_output_encoding": "base64"\n}',
    description: "Generates cryptographically secure random bytes from backend entropy source.",
    requestExample: "POST /svc/keycore/crypto/random",
    responseExample: { length: 32, random: "BASE64...", encoding: "base64", source: "kms-csprng" },
    errorCodes: [
      { code: 400, meaning: "Length invalid or source unsupported" },
      { code: 401, meaning: "JWT missing/invalid/expired" }
    ]
  },
  {
    id: "secrets-list",
    group: "Management",
    title: "List Secrets",
    service: "secrets",
    method: "GET",
    pathTemplate: "/secrets?tenant_id={{tenant_id}}&limit=100&offset=0",
    bodyTemplate: "",
    description: "Returns secret metadata inventory. Secret values are not returned here.",
    requestExample: "GET /svc/secrets/secrets?tenant_id=root&limit=100&offset=0",
    responseExample: { items: [{ id: "sec_01", name: "db-password", secret_type: "password", status: "active" }] },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid query" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks secret-list privilege" }
    ]
  },
  {
    id: "certs-list",
    group: "Management",
    title: "List Certificates",
    service: "certs",
    method: "GET",
    pathTemplate: "/certs?tenant_id={{tenant_id}}&limit=100&offset=0",
    bodyTemplate: "",
    description: "Returns certificate inventory for tenant CA/certificate lifecycle tracking.",
    requestExample: "GET /svc/certs/certs?tenant_id=root&limit=100&offset=0",
    responseExample: { items: [{ id: "crt_01", subject_cn: "api.bank.com", status: "active", algorithm: "ECDSA-P384" }] },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid query" },
      { code: 401, meaning: "JWT missing/invalid/expired" }
    ]
  },
  {
    id: "cert-issue",
    group: "Management",
    title: "Issue Certificate",
    service: "certs",
    method: "POST",
    pathTemplate: "/certs",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "ca_id": "ca_runtime",\n  "subject_cn": "service.tenant.local",\n  "sans": ["service.tenant.local"],\n  "cert_type": "tls-server",\n  "algorithm": "ECDSA-P384",\n  "server_keygen": true,\n  "validity_days": 365,\n  "protocol": "REST"\n}',
    description: "Issues a certificate from selected CA/profile. Supports server-side keygen.",
    requestExample: "POST /svc/certs/certs",
    responseExample: { certificate: { id: "crt_99", status: "active", subject_cn: "service.tenant.local" } },
    errorCodes: [
      { code: 400, meaning: "CA/profile/subject invalid" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Issuance policy violation" }
    ]
  },
  {
    id: "gov-requests",
    group: "Management",
    title: "List Governance Requests",
    service: "governance",
    method: "GET",
    pathTemplate: "/governance/requests?tenant_id={{tenant_id}}&status=pending",
    bodyTemplate: "",
    description: "Returns active/pending governance approvals and quorum state.",
    requestExample: "GET /svc/governance/governance/requests?tenant_id=root&status=pending",
    responseExample: { items: [{ id: "req_01", action: "key.export", status: "pending", required_approvals: 2, current_approvals: 1 }] },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid filter" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks governance read privilege" }
    ]
  },
  {
    id: "byok-accounts-list",
    group: "BYOK",
    title: "List Cloud Accounts",
    service: "cloud",
    method: "GET",
    pathTemplate: "/cloud/accounts",
    bodyTemplate: "",
    description: "Returns registered cloud BYOK connectors (AWS, Azure, GCP, OCI, Salesforce) for current tenant.",
    requestExample: "GET /svc/cloud/cloud/accounts",
    responseExample: { items: [{ id: "acct_aws_01", provider: "aws", name: "aws-prod", default_region: "us-east-1", status: "active" }] },
    errorCodes: [
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks BYOK connector read privilege" }
    ]
  },
  {
    id: "byok-import-key",
    group: "BYOK",
    title: "Import/Sync Key To CSP",
    service: "cloud",
    method: "POST",
    pathTemplate: "/cloud/import",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "key_id": "{{key_id}}",\n  "provider": "aws",\n  "account_id": "acct_aws_01",\n  "vecta_region": "primary",\n  "cloud_region": "us-east-1",\n  "metadata_json": "{\\"source\\":\\"rest-api\\"}"\n}',
    description: "Imports or binds a KMS key to cloud KMS/HSM target using configured account credentials.",
    requestExample: "POST /svc/cloud/cloud/import",
    responseExample: { binding: { id: "bind_01", key_id: "key_123", provider: "aws", cloud_key_ref: "arn:aws:kms:..." } },
    errorCodes: [
      { code: 400, meaning: "Provider/account/key payload invalid" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Cloud import refused by CSP or policy" }
    ]
  },
  {
    id: "hyok-endpoints-list",
    group: "HYOK",
    title: "List HYOK Endpoints",
    service: "hyok",
    method: "GET",
    pathTemplate: "/hyok/v1/endpoints?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists HYOK endpoint protocols and policy bindings (DKE/Salesforce/Google/Generic).",
    requestExample: "GET /svc/hyok/hyok/v1/endpoints?tenant_id=root",
    responseExample: { items: [{ protocol: "dke", enabled: true, auth_mode: "mtls_or_jwt", governance_required: true }] },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks HYOK read privilege" }
    ]
  },
  {
    id: "hyok-dke-publickey",
    group: "HYOK",
    title: "Get DKE Public Key",
    service: "hyok",
    method: "GET",
    pathTemplate: "/hyok/dke/v1/keys/{{key_id}}/publickey?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns DKE-compatible public key material for Microsoft-style HYOK/DKE integration.",
    requestExample: "GET /svc/hyok/hyok/dke/v1/keys/{key_id}/publickey?tenant_id=root",
    responseExample: { key: { key_id: "key_123", algorithm: "RSA-OAEP-2048", format: "pem", public_key: "-----BEGIN PUBLIC KEY-----..." } },
    errorCodes: [
      { code: 400, meaning: "key_id missing or invalid for DKE" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Key algorithm/profile incompatible with DKE export" }
    ]
  },
  {
    id: "kmip-profiles-list",
    group: "KMIP",
    title: "List KMIP Client Profiles",
    service: "kmip",
    method: "GET",
    pathTemplate: "/kmip/profiles?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists KMIP onboarding profiles used to issue/internalize KMIP client credentials.",
    requestExample: "GET /svc/kmip/kmip/profiles?tenant_id=root",
    responseExample: { items: [{ id: "prof_01", name: "default-kmip", role: "kmip-client", certificate_duration_days: 365 }] },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" }
    ]
  },
  {
    id: "kmip-client-create",
    group: "KMIP",
    title: "Create KMIP Client",
    service: "kmip",
    method: "POST",
    pathTemplate: "/kmip/clients",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "name": "app-kmip-client-01",\n  "profile_id": "prof_01",\n  "role": "kmip-client",\n  "enrollment_mode": "internal",\n  "common_name": "app-kmip-client-01"\n}',
    description: "Registers a KMIP client and issues internal credentials when enrollment_mode is internal.",
    requestExample: "POST /svc/kmip/kmip/clients",
    responseExample: { client: { id: "kmip_client_01", name: "app-kmip-client-01", status: "active", enrollment_mode: "internal" } },
    errorCodes: [
      { code: 400, meaning: "Profile/enrollment payload invalid" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Certificate issuance or external cert validation failed" }
    ]
  },
  {
    id: "kmip-clients-list",
    group: "KMIP",
    title: "List KMIP Clients",
    service: "kmip",
    method: "GET",
    pathTemplate: "/kmip/clients?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists registered KMIP clients, enrollment mode, certificate fingerprint and status.",
    requestExample: "GET /svc/kmip/kmip/clients?tenant_id=root",
    responseExample: { items: [{ id: "kmipc_01", name: "app-kmip-client-01", status: "active", enrollment_mode: "internal", role: "kmip-client" }] },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" }
    ]
  },
  {
    id: "kmip-client-delete",
    group: "KMIP",
    title: "Delete KMIP Client",
    service: "kmip",
    method: "DELETE",
    pathTemplate: "/kmip/clients/{{id}}?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Deletes a KMIP client registration and removes certificate-linked access from KMIP service.",
    requestExample: "DELETE /svc/kmip/kmip/clients/kmipc_01?tenant_id=root",
    responseExample: { status: "deleted" },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or client id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "KMIP client not found" }
    ]
  },
  {
    id: "kmip-profile-delete",
    group: "KMIP",
    title: "Delete KMIP Client Profile",
    service: "kmip",
    method: "DELETE",
    pathTemplate: "/kmip/profiles/{{id}}?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Deletes a KMIP client profile. Profile deletion is blocked while any KMIP client is still attached.",
    requestExample: "DELETE /svc/kmip/kmip/profiles/kpf_01?tenant_id=root",
    responseExample: { status: "deleted" },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or profile id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "Profile not found" },
      { code: 409, meaning: "Profile is still assigned to one or more KMIP clients" }
    ]
  },
  {
    id: "ekm-agents-list",
    group: "EKM",
    title: "List EKM Agents",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/agents?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists deployed EKM/TDE agents and their registration metadata.",
    requestExample: "GET /svc/ekm/ekm/agents?tenant_id=root",
    responseExample: { items: [{ id: "agent_01", name: "mssql-prod-01", db_engine: "mssql", status: "active", host: "10.0.0.5" }] },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" }
    ]
  },
  {
    id: "ekm-agent-register",
    group: "EKM",
    title: "Register EKM Agent",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/agents/register",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "name": "mssql-prod-03",\n  "role": "ekm-agent",\n  "db_engine": "mssql",\n  "host": "10.0.0.15",\n  "version": "SQL Server 2022",\n  "heartbeat_interval_sec": 30,\n  "auto_provision_tde": true\n}',
    description: "Registers an EKM agent endpoint and provisions initial TDE key mapping policy.",
    requestExample: "POST /svc/ekm/ekm/agents/register",
    responseExample: { agent: { id: "agent_03", name: "mssql-prod-03", status: "active", assigned_key_id: "key_tde_01" } },
    errorCodes: [
      { code: 400, meaning: "Agent payload invalid (host/engine/version)" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Key provisioning/policy assignment failed" }
    ]
  },
  {
    id: "qkd-overview",
    group: "QKD",
    title: "QKD Overview",
    service: "qkd",
    method: "GET",
    pathTemplate: "/qkd/v1/overview?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns ETSI QKD interface status, pool metrics, and link telemetry for tenant.",
    requestExample: "GET /svc/qkd/qkd/v1/overview?tenant_id=root",
    responseExample: { overview: { status: { active: true, link_status: "up", key_rate: 1200 }, pool: { available_keys: 847293, pool_fill_pct: 68 } } },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 503, meaning: "QKD interface disabled/unavailable" }
    ]
  },
  {
    id: "qkd-test-generate",
    group: "QKD",
    title: "Generate Test QKD Keys",
    service: "qkd",
    method: "POST",
    pathTemplate: "/qkd/v1/test/generate",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "slave_sae_id": "sae-node-b",\n  "device_id": "qkd-node-b",\n  "count": 8,\n  "key_size_bits": 256,\n  "qber_min": 1.2,\n  "qber_max": 2.8\n}',
    description: "Generates QKD test keys through the QKD service flow for validation and pool testing.",
    requestExample: "POST /svc/qkd/qkd/v1/test/generate",
    responseExample: { result: { accepted_count: 8, discarded_count: 0, accepted_key_ids: ["qkd_01", "qkd_02"] } },
    errorCodes: [
      { code: 400, meaning: "Invalid QKD test generation parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "QBER/pool policy rejected generated keys" }
    ]
  },
  {
    id: "mpc-dkg-initiate",
    group: "MPC",
    title: "Initiate MPC DKG Ceremony",
    service: "mpc",
    method: "POST",
    pathTemplate: "/mpc/dkg/initiate",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "key_name": "custody-btc-hot",\n  "algorithm": "ECDSA-P256-GG20",\n  "threshold": 3,\n  "participants": ["alice@bank.com", "bob@bank.com", "hsm-partition"]\n}',
    description: "Starts distributed key generation with threshold policy. Produces no single full private key holder.",
    requestExample: "POST /svc/mpc/mpc/dkg/initiate",
    responseExample: { ceremony: { id: "cer_01", type: "dkg", status: "pending", required_contributors: 3 } },
    errorCodes: [
      { code: 400, meaning: "Threshold/participant/algorithm combination invalid" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Governance/quorum policy blocked ceremony" }
    ]
  },
  {
    id: "mpc-sign-initiate",
    group: "MPC",
    title: "Initiate MPC Signing",
    service: "mpc",
    method: "POST",
    pathTemplate: "/mpc/sign/initiate",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "key_id": "{{key_id}}",\n  "message_hash": "BASE64_OR_HEX_HASH",\n  "participants": ["alice@bank.com", "bob@bank.com"]\n}',
    description: "Starts threshold signing ceremony for existing MPC key.",
    requestExample: "POST /svc/mpc/mpc/sign/initiate",
    responseExample: { ceremony: { id: "cer_sign_01", type: "sign", status: "pending" } },
    errorCodes: [
      { code: 400, meaning: "Message hash/key payload invalid" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "MPC key not ready or insufficient eligible participants" }
    ]
  },
  {
    id: "approval-vote",
    group: "Approvals",
    title: "Vote Approval Request",
    service: "governance",
    method: "POST",
    pathTemplate: "/governance/approve/REQ_ID_HERE",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "request_id": "REQ_ID_HERE",\n  "vote": "approved",\n  "approver_email": "approver@bank.com",\n  "comment": "Approved after review",\n  "vote_method": "dashboard",\n  "challenge_code": ""\n}',
    description: "Submits governance vote for pending request; supports challenge-response when enabled.",
    requestExample: "POST /svc/governance/governance/approve/{request_id}",
    responseExample: { request: { id: "req_01", status: "approved", current_approvals: 2, required_approvals: 2 } },
    errorCodes: [
      { code: 400, meaning: "Vote payload invalid or request_id missing" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Request expired/challenge invalid/already resolved" }
    ]
  },
  {
    id: "reporting-alerts-list",
    group: "Reporting",
    title: "List Alerts",
    service: "reporting",
    method: "GET",
    pathTemplate: "/alerts?tenant_id={{tenant_id}}&status=open&limit=100&offset=0",
    bodyTemplate: "",
    description: "Lists alert center events with severity/status filters and pagination.",
    requestExample: "GET /svc/reporting/alerts?tenant_id=root&status=open&limit=100&offset=0",
    responseExample: { items: [{ id: "alert_01", severity: "critical", title: "FDE Integrity Check Failed", status: "open" }] },
    errorCodes: [
      { code: 400, meaning: "Invalid query filters" },
      { code: 401, meaning: "JWT missing/invalid/expired" }
    ]
  },
  {
    id: "reporting-ack-alert",
    group: "Reporting",
    title: "Acknowledge Alert",
    service: "reporting",
    method: "PUT",
    pathTemplate: "/alerts/ALERT_ID_HERE/acknowledge?tenant_id={{tenant_id}}",
    bodyTemplate:
      '{\n  "actor": "admin@bank.com"\n}',
    description: "Acknowledges an active alert and updates alert center counters/channels state.",
    requestExample: "PUT /svc/reporting/alerts/{alert_id}/acknowledge?tenant_id=root",
    responseExample: { status: "ok" },
    errorCodes: [
      { code: 400, meaning: "alert_id missing or invalid" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Alert already resolved or immutable" }
    ]
  },
  {
    id: "reporting-generate-report",
    group: "Reporting",
    title: "Generate Report Job",
    service: "reporting",
    method: "POST",
    pathTemplate: "/reports/generate",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "template_id": "key-rotation-summary",\n  "format": "pdf",\n  "requested_by": "admin@bank.com",\n  "filters": {\n    "date_from": "2026-01-01",\n    "date_to": "2026-12-31"\n  }\n}',
    description: "Creates an asynchronous reporting job (PDF/JSON/CSV depending on template/format support).",
    requestExample: "POST /svc/reporting/reports/generate",
    responseExample: { job: { id: "rep_job_01", template_id: "key-rotation-summary", status: "queued", format: "pdf" } },
    errorCodes: [
      { code: 400, meaning: "Template/format/filter payload invalid" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Template disabled or policy restricts generation" }
    ]
  },

  /* ── Auth & Identity ─────────────────────────────────────────────── */
  {
    id: "auth-login",
    group: "Auth & Identity",
    title: "Login",
    service: "auth",
    method: "POST",
    pathTemplate: "/auth/login",
    bodyTemplate:
      '{\n  "username": "admin",\n  "password": "changeme",\n  "tenant_id": "{{tenant_id}}"\n}',
    description: "Authenticates user and returns JWT access/refresh tokens.",
    requestExample: "POST /svc/auth/auth/login",
    responseExample: {
      access_token: "eyJhbGciOi...",
      refresh_token: "dGhpcyBpcyBh...",
      token_type: "Bearer",
      expires_in: 3600
    },
    errorCodes: [
      { code: 400, meaning: "Missing or malformed credentials" },
      { code: 401, meaning: "Invalid username or password" },
      { code: 403, meaning: "Account locked or tenant disabled" }
    ]
  },
  {
    id: "auth-refresh",
    group: "Auth & Identity",
    title: "Refresh Token",
    service: "auth",
    method: "POST",
    pathTemplate: "/auth/refresh",
    bodyTemplate:
      '{\n  "refresh_token": "REFRESH_TOKEN_HERE",\n  "tenant_id": "{{tenant_id}}"\n}',
    description: "Exchanges refresh token for a new access token.",
    requestExample: "POST /svc/auth/auth/refresh",
    responseExample: {
      access_token: "eyJhbGciOi...",
      token_type: "Bearer",
      expires_in: 3600
    },
    errorCodes: [
      { code: 400, meaning: "Missing or malformed refresh token" },
      { code: 401, meaning: "Refresh token expired or revoked" }
    ]
  },
  {
    id: "auth-logout",
    group: "Auth & Identity",
    title: "Logout",
    service: "auth",
    method: "POST",
    pathTemplate: "/auth/logout",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}"\n}',
    description: "Invalidates current session and revokes tokens.",
    requestExample: "POST /svc/auth/auth/logout",
    responseExample: { status: "ok", message: "Session invalidated" },
    errorCodes: [
      { code: 401, meaning: "JWT missing/invalid/expired" }
    ]
  },
  {
    id: "auth-change-password",
    group: "Auth & Identity",
    title: "Change Password",
    service: "auth",
    method: "POST",
    pathTemplate: "/auth/change-password",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "current_password": "old",\n  "new_password": "new"\n}',
    description: "Changes the authenticated user's password.",
    requestExample: "POST /svc/auth/auth/change-password",
    responseExample: { status: "ok", message: "Password changed successfully" },
    errorCodes: [
      { code: 400, meaning: "New password does not meet policy requirements" },
      { code: 401, meaning: "Current password incorrect or JWT invalid" },
      { code: 403, meaning: "Password change not permitted by policy" }
    ]
  },
  {
    id: "auth-users-list",
    group: "Auth & Identity",
    title: "List Users",
    service: "auth",
    method: "GET",
    pathTemplate: "/auth/users?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists all user accounts in the tenant.",
    requestExample: "GET /svc/auth/auth/users?tenant_id=root",
    responseExample: {
      items: [{ id: "usr_01", username: "admin", role: "admin", email: "admin@example.com", status: "active" }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks user-list privilege" }
    ]
  },
  {
    id: "auth-users-create",
    group: "Auth & Identity",
    title: "Create User",
    service: "auth",
    method: "POST",
    pathTemplate: "/auth/users",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "username": "newuser",\n  "password": "securepass",\n  "role": "operator",\n  "email": "user@example.com"\n}',
    description: "Creates a new user account.",
    requestExample: "POST /svc/auth/auth/users",
    responseExample: { user: { id: "usr_02", username: "newuser", role: "operator", email: "user@example.com", status: "active" } },
    errorCodes: [
      { code: 400, meaning: "Invalid payload or password policy violation" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 409, meaning: "Username already exists in tenant" }
    ]
  },
  {
    id: "auth-tenants-list",
    group: "Auth & Identity",
    title: "List Tenants",
    service: "auth",
    method: "GET",
    pathTemplate: "/tenants?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists all configured tenants.",
    requestExample: "GET /svc/auth/tenants?tenant_id=root",
    responseExample: {
      items: [{ id: "tenant_01", name: "prod-tenant", admin_email: "admin@example.com", status: "active" }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks tenant-list privilege" }
    ]
  },
  {
    id: "auth-tenants-create",
    group: "Auth & Identity",
    title: "Create Tenant",
    service: "auth",
    method: "POST",
    pathTemplate: "/tenants",
    bodyTemplate:
      '{\n  "name": "prod-tenant",\n  "admin_email": "admin@example.com"\n}',
    description: "Creates a new tenant with isolated key namespace.",
    requestExample: "POST /svc/auth/tenants",
    responseExample: { tenant: { id: "tenant_02", name: "prod-tenant", admin_email: "admin@example.com", status: "active" } },
    errorCodes: [
      { code: 400, meaning: "Invalid tenant name or admin email" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 409, meaning: "Tenant name already exists" }
    ]
  },
  {
    id: "auth-password-policy-get",
    group: "Auth & Identity",
    title: "Get Password Policy",
    service: "auth",
    method: "GET",
    pathTemplate: "/auth/password-policy?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns current password policy configuration.",
    requestExample: "GET /svc/auth/auth/password-policy?tenant_id=root",
    responseExample: {
      min_length: 12,
      require_uppercase: true,
      require_number: true,
      require_special: true,
      max_age_days: 90
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks policy-read privilege" }
    ]
  },
  {
    id: "auth-password-policy-update",
    group: "Auth & Identity",
    title: "Update Password Policy",
    service: "auth",
    method: "PUT",
    pathTemplate: "/auth/password-policy",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "min_length": 12,\n  "require_uppercase": true,\n  "require_number": true,\n  "require_special": true,\n  "max_age_days": 90\n}',
    description: "Updates password policy enforcement rules.",
    requestExample: "PUT /svc/auth/auth/password-policy",
    responseExample: { status: "ok", message: "Password policy updated" },
    errorCodes: [
      { code: 400, meaning: "Invalid policy parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks policy-update privilege" }
    ]
  },
  {
    id: "auth-security-policy-get",
    group: "Auth & Identity",
    title: "Get Security Policy",
    service: "auth",
    method: "GET",
    pathTemplate: "/auth/security-policy?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns login security settings (lockout, MFA, session timeout).",
    requestExample: "GET /svc/auth/auth/security-policy?tenant_id=root",
    responseExample: {
      max_failed_attempts: 5,
      lockout_duration_minutes: 15,
      session_timeout_minutes: 30,
      mfa_required: false
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks policy-read privilege" }
    ]
  },
  {
    id: "auth-security-policy-update",
    group: "Auth & Identity",
    title: "Update Security Policy",
    service: "auth",
    method: "PUT",
    pathTemplate: "/auth/security-policy",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "max_failed_attempts": 5,\n  "lockout_duration_minutes": 15,\n  "session_timeout_minutes": 30,\n  "mfa_required": false\n}',
    description: "Updates login security and session timeout settings.",
    requestExample: "PUT /svc/auth/auth/security-policy",
    responseExample: { status: "ok", message: "Security policy updated" },
    errorCodes: [
      { code: 400, meaning: "Invalid security policy parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks policy-update privilege" }
    ]
  },
  {
    id: "auth-sso-providers",
    group: "Auth & Identity",
    title: "List SSO Providers",
    service: "auth",
    method: "GET",
    pathTemplate: "/auth/sso/providers?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists configured SSO identity providers (SAML/OIDC).",
    requestExample: "GET /svc/auth/auth/sso/providers?tenant_id=root",
    responseExample: {
      items: [{ id: "sso_01", name: "corporate-okta", protocol: "OIDC", status: "active", issuer: "https://corp.okta.com" }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks SSO configuration read privilege" }
    ]
  },
  {
    id: "auth-identity-providers",
    group: "Auth & Identity",
    title: "List Identity Providers",
    service: "auth",
    method: "GET",
    pathTemplate: "/auth/identity/providers?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists external identity providers (LDAP/AD/OIDC/SAML) for user sync.",
    requestExample: "GET /svc/auth/auth/identity/providers?tenant_id=root",
    responseExample: {
      items: [{ id: "idp_01", name: "corp-ldap", type: "LDAP", status: "active", host: "ldap.corp.local" }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks identity provider read privilege" }
    ]
  },
  {
    id: "auth-clients-list",
    group: "Auth & Identity",
    title: "List API Clients",
    service: "auth",
    method: "GET",
    pathTemplate: "/auth/clients?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists registered API/service clients.",
    requestExample: "GET /svc/auth/auth/clients?tenant_id=root",
    responseExample: {
      items: [{ id: "client_01", name: "billing-svc", client_id: "svc_billing_abc", status: "active", created_at: "2026-01-15T10:00:00Z" }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks client-list privilege" }
    ]
  },

  /* ── Key Lifecycle ───────────────────────────────────────────────── */
  {
    id: "keys-import",
    group: "Key Management",
    title: "Import Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/import",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "name": "imported-key",\n  "algorithm": "AES-256-GCM",\n  "key_material": "BASE64_KEY_MATERIAL",\n  "encoding": "base64"\n}',
    description: "Imports external key material into the KMS.",
    requestExample: "POST /svc/keycore/keys/import",
    responseExample: { key: { id: "key_imp_01", name: "imported-key", algorithm: "AES-256-GCM", status: "active", origin: "imported" } },
    errorCodes: [
      { code: 400, meaning: "Invalid key material or algorithm mismatch" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks key-import privilege" },
      { code: 404, meaning: "Tenant not found" }
    ]
  },
  {
    id: "keys-rotate",
    group: "Key Management",
    title: "Rotate Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/rotate",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}"\n}',
    description: "Rotates key to a new version. Previous versions remain for decryption.",
    requestExample: "POST /svc/keycore/keys/{key_id}/rotate",
    responseExample: { key: { id: "key_123", version: 3, status: "active", rotated_at: "2026-03-04T12:00:00Z" } },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or key_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks key-rotate privilege" },
      { code: 404, meaning: "Key not found" }
    ]
  },
  {
    id: "keys-export",
    group: "Key Management",
    title: "Export Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/export",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "format": "raw",\n  "encoding": "base64"\n}',
    description: "Exports key material (requires export_allowed policy).",
    requestExample: "POST /svc/keycore/keys/{key_id}/export",
    responseExample: { key_material: "BASE64...", format: "raw", encoding: "base64", key_id: "key_123", version: 2 },
    errorCodes: [
      { code: 400, meaning: "Invalid format or encoding parameter" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Key export not allowed by policy" },
      { code: 404, meaning: "Key not found" }
    ]
  },
  {
    id: "keys-destroy",
    group: "Key Management",
    title: "Destroy Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/destroy",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}"\n}',
    description: "Permanently destroys key material. Irreversible.",
    requestExample: "POST /svc/keycore/keys/{key_id}/destroy",
    responseExample: { status: "destroyed", key_id: "key_123", destroyed_at: "2026-03-04T12:00:00Z" },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or key_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks key-destroy privilege or governance approval required" },
      { code: 404, meaning: "Key not found" }
    ]
  },
  {
    id: "keys-activate",
    group: "Key Management",
    title: "Activate Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/activate",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}"\n}',
    description: "Transitions key to active state for cryptographic operations.",
    requestExample: "POST /svc/keycore/keys/{key_id}/activate",
    responseExample: { key: { id: "key_123", status: "active", activated_at: "2026-03-04T12:00:00Z" } },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or key_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "Key not found" },
      { code: 422, meaning: "Key state does not allow activation" }
    ]
  },
  {
    id: "keys-deactivate",
    group: "Key Management",
    title: "Deactivate Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/deactivate",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}"\n}',
    description: "Deactivates key. Existing ciphertext can still be decrypted.",
    requestExample: "POST /svc/keycore/keys/{key_id}/deactivate",
    responseExample: { key: { id: "key_123", status: "deactivated", deactivated_at: "2026-03-04T12:00:00Z" } },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or key_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "Key not found" },
      { code: 422, meaning: "Key state does not allow deactivation" }
    ]
  },
  {
    id: "keys-versions",
    group: "Key Management",
    title: "List Key Versions",
    service: "keycore",
    method: "GET",
    pathTemplate: "/keys/{{key_id}}/versions?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists all versions of a key with activation timestamps.",
    requestExample: "GET /svc/keycore/keys/{key_id}/versions?tenant_id=root",
    responseExample: {
      items: [
        { version: 1, status: "deactivated", created_at: "2025-01-01T00:00:00Z" },
        { version: 2, status: "active", created_at: "2026-01-15T00:00:00Z" }
      ]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or key_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "Key not found" }
    ]
  },
  {
    id: "keys-usage",
    group: "Key Management",
    title: "Get Key Usage",
    service: "keycore",
    method: "GET",
    pathTemplate: "/keys/{{key_id}}/usage?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns key usage counters and limit configuration.",
    requestExample: "GET /svc/keycore/keys/{key_id}/usage?tenant_id=root",
    responseExample: {
      key_id: "key_123",
      total_operations: 45230,
      total_bytes: 1048576,
      max_operations: 1000000,
      max_bytes: 0
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or key_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "Key not found" }
    ]
  },
  {
    id: "keys-usage-limit",
    group: "Key Management",
    title: "Set Key Usage Limit",
    service: "keycore",
    method: "PUT",
    pathTemplate: "/keys/{{key_id}}/usage/limit",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "max_operations": 1000000,\n  "max_bytes": 0\n}',
    description: "Sets operational usage limits on a key.",
    requestExample: "PUT /svc/keycore/keys/{key_id}/usage/limit",
    responseExample: { status: "ok", key_id: "key_123", max_operations: 1000000, max_bytes: 0 },
    errorCodes: [
      { code: 400, meaning: "Invalid limit parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks key-policy-update privilege" },
      { code: 404, meaning: "Key not found" }
    ]
  },
  {
    id: "keys-wrap",
    group: "Key Management",
    title: "Wrap Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/wrap",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "plaintext_key": "BASE64...",\n  "encoding": "base64"\n}',
    description: "Wraps (encrypts) a key using the selected wrapping key.",
    requestExample: "POST /svc/keycore/keys/{key_id}/wrap",
    responseExample: { wrapped_key: "BASE64...", wrapping_key_id: "key_123", wrapping_key_version: 2 },
    errorCodes: [
      { code: 400, meaning: "Invalid plaintext key or encoding" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Key policy does not allow wrapping" },
      { code: 404, meaning: "Wrapping key not found" }
    ]
  },
  {
    id: "keys-unwrap",
    group: "Key Management",
    title: "Unwrap Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/unwrap",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "wrapped_key": "BASE64...",\n  "encoding": "base64"\n}',
    description: "Unwraps (decrypts) a previously wrapped key.",
    requestExample: "POST /svc/keycore/keys/{key_id}/unwrap",
    responseExample: { plaintext_key: "BASE64...", wrapping_key_id: "key_123", wrapping_key_version: 2 },
    errorCodes: [
      { code: 400, meaning: "Invalid wrapped key or encoding" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Key policy does not allow unwrapping" },
      { code: 404, meaning: "Wrapping key not found" }
    ]
  },
  {
    id: "keys-mac",
    group: "Key Management",
    title: "Compute MAC",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/mac",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "message": "data-to-mac",\n  "encoding": "utf-8",\n  "algorithm": "hmac-sha256"\n}',
    description: "Computes HMAC/CMAC over the provided message.",
    requestExample: "POST /svc/keycore/keys/{key_id}/mac",
    responseExample: { mac: "BASE64...", algorithm: "hmac-sha256", key_id: "key_123", version: 2 },
    errorCodes: [
      { code: 400, meaning: "Invalid message, encoding, or algorithm" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "Key not found" },
      { code: 422, meaning: "Key type/state incompatible with MAC operation" }
    ]
  },
  {
    id: "keys-derive",
    group: "Key Management",
    title: "Derive Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/derive",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "algorithm": "hkdf-sha256",\n  "context": "app-context",\n  "length": 32\n}',
    description: "Derives a new key from the master key using KDF.",
    requestExample: "POST /svc/keycore/keys/{key_id}/derive",
    responseExample: { derived_key: "BASE64...", algorithm: "hkdf-sha256", length: 32, source_key_id: "key_123" },
    errorCodes: [
      { code: 400, meaning: "Invalid KDF algorithm, context, or length" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "Key not found" },
      { code: 422, meaning: "Key type/state incompatible with derivation" }
    ]
  },

  /* ── Secret Vault ────────────────────────────────────────────────── */
  {
    id: "secrets-create",
    group: "Secret Vault",
    title: "Create Secret",
    service: "secrets",
    method: "POST",
    pathTemplate: "/secrets",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "name": "db-password",\n  "secret_type": "password",\n  "value": "s3cret!",\n  "description": "Production database password"\n}',
    description: "Creates a new secret in the vault.",
    requestExample: "POST /svc/secrets/secrets",
    responseExample: { secret: { id: "sec_02", name: "db-password", secret_type: "password", status: "active", version: 1 } },
    errorCodes: [
      { code: 400, meaning: "Invalid payload or secret_type" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks secret-create privilege" },
      { code: 409, meaning: "Secret name already exists for tenant" }
    ]
  },
  {
    id: "secrets-get",
    group: "Secret Vault",
    title: "Get Secret Metadata",
    service: "secrets",
    method: "GET",
    pathTemplate: "/secrets/{{secret_id}}?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns secret metadata (not the value).",
    requestExample: "GET /svc/secrets/secrets/{secret_id}?tenant_id=root",
    responseExample: { secret: { id: "sec_01", name: "db-password", secret_type: "password", status: "active", version: 3, created_at: "2026-01-01T00:00:00Z" } },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or secret_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks secret-read privilege" },
      { code: 404, meaning: "Secret not found" }
    ]
  },
  {
    id: "secrets-get-value",
    group: "Secret Vault",
    title: "Get Secret Value",
    service: "secrets",
    method: "GET",
    pathTemplate: "/secrets/{{secret_id}}/value?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns the decrypted secret value.",
    requestExample: "GET /svc/secrets/secrets/{secret_id}/value?tenant_id=root",
    responseExample: { secret_id: "sec_01", value: "s3cret!", version: 3 },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or secret_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks secret-value-read privilege" },
      { code: 404, meaning: "Secret not found" }
    ]
  },
  {
    id: "secrets-update",
    group: "Secret Vault",
    title: "Update Secret",
    service: "secrets",
    method: "PUT",
    pathTemplate: "/secrets/{{secret_id}}",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "value": "new-s3cret!",\n  "description": "Updated password"\n}',
    description: "Updates secret value, creating a new version.",
    requestExample: "PUT /svc/secrets/secrets/{secret_id}",
    responseExample: { secret: { id: "sec_01", name: "db-password", version: 4, status: "active", updated_at: "2026-03-04T12:00:00Z" } },
    errorCodes: [
      { code: 400, meaning: "Invalid payload" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks secret-update privilege" },
      { code: 404, meaning: "Secret not found" }
    ]
  },
  {
    id: "secrets-delete",
    group: "Secret Vault",
    title: "Delete Secret",
    service: "secrets",
    method: "DELETE",
    pathTemplate: "/secrets/{{secret_id}}?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Soft-deletes a secret from the vault.",
    requestExample: "DELETE /svc/secrets/secrets/{secret_id}?tenant_id=root",
    responseExample: { status: "deleted", secret_id: "sec_01", deleted_at: "2026-03-04T12:00:00Z" },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or secret_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks secret-delete privilege" },
      { code: 404, meaning: "Secret not found" }
    ]
  },
  {
    id: "secrets-rotate",
    group: "Secret Vault",
    title: "Rotate Secret",
    service: "secrets",
    method: "POST",
    pathTemplate: "/secrets/{{secret_id}}/rotate",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}"\n}',
    description: "Rotates secret to a new version.",
    requestExample: "POST /svc/secrets/secrets/{secret_id}/rotate",
    responseExample: { secret: { id: "sec_01", version: 5, status: "active", rotated_at: "2026-03-04T12:00:00Z" } },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or secret_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks secret-rotate privilege" },
      { code: 404, meaning: "Secret not found" }
    ]
  },
  {
    id: "secrets-versions",
    group: "Secret Vault",
    title: "List Secret Versions",
    service: "secrets",
    method: "GET",
    pathTemplate: "/secrets/{{secret_id}}/versions?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists all versions of a secret with timestamps.",
    requestExample: "GET /svc/secrets/secrets/{secret_id}/versions?tenant_id=root",
    responseExample: {
      items: [
        { version: 1, created_at: "2026-01-01T00:00:00Z", status: "superseded" },
        { version: 2, created_at: "2026-02-15T00:00:00Z", status: "active" }
      ]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or secret_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "Secret not found" }
    ]
  },
  {
    id: "secrets-stats",
    group: "Secret Vault",
    title: "Vault Statistics",
    service: "secrets",
    method: "GET",
    pathTemplate: "/secrets/stats?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns vault statistics (total secrets, types, rotation status).",
    requestExample: "GET /svc/secrets/secrets/stats?tenant_id=root",
    responseExample: {
      total_secrets: 142,
      by_type: { password: 80, api_key: 35, certificate: 15, generic: 12 },
      rotation_overdue: 8,
      last_rotation: "2026-03-01T00:00:00Z"
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks secret-stats privilege" }
    ]
  },

  /* ── Certificates / PKI ────────────────────────────────────────────── */
  {
    id: "certs-ca-create",
    group: "Certificates / PKI",
    title: "Create Certificate Authority",
    service: "certs",
    method: "POST",
    pathTemplate: "/certs/ca",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "name": "root-ca",\n  "algorithm": "ECDSA-P384",\n  "validity_years": 10,\n  "subject_cn": "Vecta Root CA",\n  "key_type": "internal"\n}',
    description: "Creates a new Certificate Authority.",
    requestExample: "POST /svc/certs/certs/ca",
    responseExample: {
      ca: { id: "ca_01", name: "root-ca", algorithm: "ECDSA-P384", subject_cn: "Vecta Root CA", status: "active", validity_years: 10 }
    },
    errorCodes: [
      { code: 400, meaning: "Invalid algorithm, subject, or validity parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 409, meaning: "CA with same name already exists for tenant" },
      { code: 422, meaning: "CA creation blocked by policy or HSM unavailable" }
    ]
  },
  {
    id: "certs-ca-list",
    group: "Certificates / PKI",
    title: "List Certificate Authorities",
    service: "certs",
    method: "GET",
    pathTemplate: "/certs/ca?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists all Certificate Authorities for tenant.",
    requestExample: "GET /svc/certs/certs/ca?tenant_id=root",
    responseExample: {
      items: [{ id: "ca_01", name: "root-ca", algorithm: "ECDSA-P384", subject_cn: "Vecta Root CA", status: "active" }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks CA list privilege" }
    ]
  },
  {
    id: "certs-revoke",
    group: "Certificates / PKI",
    title: "Revoke Certificate",
    service: "certs",
    method: "POST",
    pathTemplate: "/certs/{{cert_id}}/revoke",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "reason": "key_compromise"\n}',
    description: "Revokes a certificate with specified reason code.",
    requestExample: "POST /svc/certs/certs/{cert_id}/revoke",
    responseExample: {
      certificate: { id: "crt_01", status: "revoked", revocation_reason: "key_compromise", revoked_at: "2026-03-04T12:00:00Z" }
    },
    errorCodes: [
      { code: 400, meaning: "Invalid reason code or missing cert_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "Certificate not found" },
      { code: 422, meaning: "Certificate already revoked or expired" }
    ]
  },
  {
    id: "certs-renew",
    group: "Certificates / PKI",
    title: "Renew Certificate",
    service: "certs",
    method: "POST",
    pathTemplate: "/certs/{{cert_id}}/renew",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "validity_days": 365\n}',
    description: "Renews a certificate with new validity period.",
    requestExample: "POST /svc/certs/certs/{cert_id}/renew",
    responseExample: {
      certificate: { id: "crt_01_v2", status: "active", not_before: "2026-03-04T00:00:00Z", not_after: "2027-03-04T00:00:00Z", renewed_from: "crt_01" }
    },
    errorCodes: [
      { code: 400, meaning: "Invalid validity_days or missing cert_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "Certificate not found" },
      { code: 422, meaning: "Certificate revoked or CA signing policy violation" }
    ]
  },
  {
    id: "certs-download",
    group: "Certificates / PKI",
    title: "Download Certificate",
    service: "certs",
    method: "GET",
    pathTemplate: "/certs/download/{{cert_id}}?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Downloads certificate in PEM/DER format.",
    requestExample: "GET /svc/certs/certs/download/{cert_id}?tenant_id=root",
    responseExample: {
      cert_id: "crt_01",
      format: "pem",
      data: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
    },
    errorCodes: [
      { code: 400, meaning: "Missing cert_id or tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "Certificate not found" }
    ]
  },
  {
    id: "certs-profiles-list",
    group: "Certificates / PKI",
    title: "List Certificate Profiles",
    service: "certs",
    method: "GET",
    pathTemplate: "/certs/profiles?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists certificate issuance profiles (TLS server, client auth, code signing, etc.).",
    requestExample: "GET /svc/certs/certs/profiles?tenant_id=root",
    responseExample: {
      items: [
        { id: "prof_tls", name: "TLS Server", cert_type: "tls-server", default_validity_days: 365 },
        { id: "prof_client", name: "Client Auth", cert_type: "client-auth", default_validity_days: 180 },
        { id: "prof_codesign", name: "Code Signing", cert_type: "code-signing", default_validity_days: 730 }
      ]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" }
    ]
  },
  {
    id: "certs-inventory",
    group: "Certificates / PKI",
    title: "Certificate Inventory",
    service: "certs",
    method: "GET",
    pathTemplate: "/certs/inventory?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns certificate inventory summary with expiry statistics.",
    requestExample: "GET /svc/certs/certs/inventory?tenant_id=root",
    responseExample: {
      total: 256,
      by_status: { active: 210, expired: 30, revoked: 16 },
      expiring_30d: 12,
      expiring_90d: 35,
      by_algorithm: { "ECDSA-P384": 180, "RSA-2048": 50, "RSA-4096": 26 }
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks cert inventory privilege" }
    ]
  },
  {
    id: "certs-security-status",
    group: "Certificates / PKI",
    title: "PKI Security Status",
    service: "certs",
    method: "GET",
    pathTemplate: "/certs/security/status?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns PKI security posture including weak algorithms and expiring certs.",
    requestExample: "GET /svc/certs/certs/security/status?tenant_id=root",
    responseExample: {
      posture_score: 87,
      weak_algorithms: [{ algorithm: "RSA-1024", count: 3, recommendation: "Upgrade to RSA-2048 or ECDSA-P384" }],
      expiring_critical: 4,
      revocation_pending: 1,
      ca_health: { root_ca_valid: true, intermediate_ca_valid: true }
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks PKI security read privilege" }
    ]
  },

  /* ── Audit ─────────────────────────────────────────────────────────── */
  {
    id: "audit-events-list",
    group: "Audit",
    title: "List Audit Events",
    service: "audit",
    method: "GET",
    pathTemplate: "/audit/events?tenant_id={{tenant_id}}&limit=100&offset=0",
    bodyTemplate: "",
    description: "Lists audit trail events with pagination.",
    requestExample: "GET /svc/audit/audit/events?tenant_id=root&limit=100&offset=0",
    responseExample: {
      items: [
        { id: "evt_001", action: "key.created", actor: "admin@bank.com", target: "key_123", timestamp: "2026-03-04T10:30:00Z", service: "keycore" }
      ],
      total: 4520,
      limit: 100,
      offset: 0
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid pagination parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks audit read privilege" }
    ]
  },
  {
    id: "audit-event-get",
    group: "Audit",
    title: "Get Audit Event",
    service: "audit",
    method: "GET",
    pathTemplate: "/audit/events/{{id}}?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns full details for a specific audit event.",
    requestExample: "GET /svc/audit/audit/events/{id}?tenant_id=root",
    responseExample: {
      id: "evt_001",
      action: "key.created",
      actor: "admin@bank.com",
      actor_ip: "10.0.0.5",
      target: "key_123",
      target_type: "key",
      service: "keycore",
      timestamp: "2026-03-04T10:30:00Z",
      metadata: { algorithm: "AES-256-GCM", key_name: "prod-db-master" },
      chain_hash: "sha256:abc123..."
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or event id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "Audit event not found" }
    ]
  },
  {
    id: "audit-search",
    group: "Audit",
    title: "Search Audit Events",
    service: "audit",
    method: "POST",
    pathTemplate: "/audit/search",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "query": "key.exported",\n  "from": "2026-01-01T00:00:00Z",\n  "to": "2026-12-31T23:59:59Z",\n  "limit": 50\n}',
    description: "Searches audit events by action, actor, target, or time range.",
    requestExample: "POST /svc/audit/audit/search",
    responseExample: {
      items: [
        { id: "evt_042", action: "key.exported", actor: "ops@bank.com", target: "key_456", timestamp: "2026-02-15T14:22:00Z" }
      ],
      total: 7,
      limit: 50
    },
    errorCodes: [
      { code: 400, meaning: "Invalid query, date range, or limit" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks audit search privilege" }
    ]
  },
  {
    id: "audit-stats",
    group: "Audit",
    title: "Audit Statistics",
    service: "audit",
    method: "GET",
    pathTemplate: "/audit/stats?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns audit statistics (event counts by type, actor, service).",
    requestExample: "GET /svc/audit/audit/stats?tenant_id=root",
    responseExample: {
      total_events: 45200,
      by_action: { "key.created": 1200, "key.rotated": 800, "key.exported": 45, "secret.accessed": 3500 },
      by_service: { keycore: 22000, secrets: 12000, certs: 5000, governance: 6200 },
      by_actor_top5: [
        { actor: "admin@bank.com", count: 15000 },
        { actor: "ops@bank.com", count: 10000 }
      ]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks audit stats privilege" }
    ]
  },
  {
    id: "audit-chain-verify",
    group: "Audit",
    title: "Verify Audit Chain",
    service: "audit",
    method: "GET",
    pathTemplate: "/audit/chain/verify?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Verifies tamper-proof audit chain integrity.",
    requestExample: "GET /svc/audit/audit/chain/verify?tenant_id=root",
    responseExample: {
      chain_valid: true,
      total_blocks: 45200,
      last_verified_block: 45200,
      last_hash: "sha256:def456...",
      verified_at: "2026-03-04T12:00:00Z"
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 422, meaning: "Chain integrity verification failed — potential tampering detected" }
    ]
  },
  {
    id: "audit-timeline",
    group: "Audit",
    title: "Target Event Timeline",
    service: "audit",
    method: "GET",
    pathTemplate: "/audit/timeline/{{target_id}}?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns timeline of all events related to a specific target (key, cert, secret).",
    requestExample: "GET /svc/audit/audit/timeline/{target_id}?tenant_id=root",
    responseExample: {
      target_id: "key_123",
      target_type: "key",
      events: [
        { id: "evt_001", action: "key.created", actor: "admin@bank.com", timestamp: "2026-01-10T08:00:00Z" },
        { id: "evt_015", action: "key.rotated", actor: "admin@bank.com", timestamp: "2026-02-10T08:00:00Z" },
        { id: "evt_042", action: "key.exported", actor: "ops@bank.com", timestamp: "2026-02-15T14:22:00Z" }
      ]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or target_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "No audit events found for target" }
    ]
  },

  /* ── Compliance ────────────────────────────────────────────────────── */
  {
    id: "compliance-posture",
    group: "Compliance",
    title: "Compliance Posture",
    service: "compliance",
    method: "GET",
    pathTemplate: "/compliance/posture?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns overall compliance posture score and breakdown.",
    requestExample: "GET /svc/compliance/compliance/posture?tenant_id=root",
    responseExample: {
      overall_score: 92,
      by_framework: [
        { framework: "NIST SP 800-57", score: 95, controls_passed: 38, controls_total: 40 },
        { framework: "PCI-DSS", score: 88, controls_passed: 22, controls_total: 25 }
      ],
      last_assessed: "2026-03-03T06:00:00Z"
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks compliance read privilege" }
    ]
  },
  {
    id: "compliance-posture-history",
    group: "Compliance",
    title: "Compliance Posture History",
    service: "compliance",
    method: "GET",
    pathTemplate: "/compliance/posture/history?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns compliance score trend over time.",
    requestExample: "GET /svc/compliance/compliance/posture/history?tenant_id=root",
    responseExample: {
      trend: [
        { date: "2026-01-01", score: 85 },
        { date: "2026-02-01", score: 89 },
        { date: "2026-03-01", score: 92 }
      ]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks compliance read privilege" }
    ]
  },
  {
    id: "compliance-assessment-run",
    group: "Compliance",
    title: "Run Compliance Assessment",
    service: "compliance",
    method: "POST",
    pathTemplate: "/compliance/assessment/run",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "framework_id": "nist-sp800-57"\n}',
    description: "Triggers a compliance assessment against selected framework.",
    requestExample: "POST /svc/compliance/compliance/assessment/run",
    responseExample: {
      assessment: { id: "assess_01", framework_id: "nist-sp800-57", status: "running", started_at: "2026-03-04T12:00:00Z" }
    },
    errorCodes: [
      { code: 400, meaning: "Invalid or unsupported framework_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 409, meaning: "Assessment already in progress for this framework" },
      { code: 422, meaning: "Assessment blocked by policy or insufficient data" }
    ]
  },
  {
    id: "compliance-frameworks",
    group: "Compliance",
    title: "List Compliance Frameworks",
    service: "compliance",
    method: "GET",
    pathTemplate: "/compliance/frameworks?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists available compliance frameworks (NIST, PCI-DSS, FIPS, etc.).",
    requestExample: "GET /svc/compliance/compliance/frameworks?tenant_id=root",
    responseExample: {
      items: [
        { id: "nist-sp800-57", name: "NIST SP 800-57", version: "Rev. 5", controls_count: 40 },
        { id: "pci-dss-4.0", name: "PCI-DSS", version: "4.0", controls_count: 25 },
        { id: "fips-140-3", name: "FIPS 140-3", version: "2019", controls_count: 18 }
      ]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" }
    ]
  },
  {
    id: "compliance-key-hygiene",
    group: "Compliance",
    title: "Key Hygiene Report",
    service: "compliance",
    method: "GET",
    pathTemplate: "/compliance/keys/hygiene?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns key hygiene report (rotation overdue, weak algorithms, policy violations).",
    requestExample: "GET /svc/compliance/compliance/keys/hygiene?tenant_id=root",
    responseExample: {
      rotation_overdue: [{ key_id: "key_42", name: "legacy-db-key", last_rotated: "2025-01-15T00:00:00Z", policy_max_days: 90 }],
      weak_algorithms: [{ key_id: "key_03", algorithm: "DES", recommendation: "Migrate to AES-256-GCM" }],
      policy_violations: 5,
      total_keys_assessed: 320
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks compliance key hygiene privilege" }
    ]
  },
  {
    id: "compliance-orphaned-keys",
    group: "Compliance",
    title: "Orphaned Keys Report",
    service: "compliance",
    method: "GET",
    pathTemplate: "/compliance/keys/orphaned?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists keys with no recent usage that may be orphaned.",
    requestExample: "GET /svc/compliance/compliance/keys/orphaned?tenant_id=root",
    responseExample: {
      items: [
        { key_id: "key_07", name: "decom-app-key", last_used: "2025-06-10T00:00:00Z", days_inactive: 267, status: "active" },
        { key_id: "key_11", name: "test-key-old", last_used: "2025-03-01T00:00:00Z", days_inactive: 368, status: "active" }
      ],
      total_orphaned: 2
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks compliance orphaned-keys privilege" }
    ]
  },
  {
    id: "compliance-sbom",
    group: "Compliance",
    title: "Software Bill of Materials",
    service: "compliance",
    method: "GET",
    pathTemplate: "/compliance/sbom?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns software bill of materials for KMS components.",
    requestExample: "GET /svc/compliance/compliance/sbom?tenant_id=root",
    responseExample: {
      components: [
        { name: "vecta-keycore", version: "3.2.1", license: "Commercial", vulnerabilities: 0 },
        { name: "openssl", version: "3.1.4", license: "Apache-2.0", vulnerabilities: 0 },
        { name: "golang", version: "1.22.1", license: "BSD-3-Clause", vulnerabilities: 0 }
      ],
      generated_at: "2026-03-04T12:00:00Z",
      format: "CycloneDX"
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks SBOM read privilege" }
    ]
  },
  {
    id: "compliance-cbom-summary",
    group: "Compliance",
    title: "Cryptographic Bill of Materials",
    service: "compliance",
    method: "GET",
    pathTemplate: "/compliance/cbom/summary?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns cryptographic bill of materials summary with PQC readiness.",
    requestExample: "GET /svc/compliance/compliance/cbom/summary?tenant_id=root",
    responseExample: {
      algorithms_in_use: [
        { algorithm: "AES-256-GCM", usage_count: 245, pqc_safe: true },
        { algorithm: "RSA-2048", usage_count: 50, pqc_safe: false, migration_recommendation: "ML-KEM-768" },
        { algorithm: "ECDSA-P384", usage_count: 180, pqc_safe: false, migration_recommendation: "ML-DSA-65" }
      ],
      pqc_readiness_pct: 51,
      total_crypto_assets: 475,
      generated_at: "2026-03-04T12:00:00Z"
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks CBOM read privilege" }
    ]
  },

  /* ── Governance ────────────────────────────────────────────────────── */
  {
    id: "governance-settings-get",
    group: "Governance",
    title: "Get Governance Settings",
    service: "governance",
    method: "GET",
    pathTemplate: "/governance/settings?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns governance delivery configuration (approval modes, notification channels).",
    requestExample: "GET /svc/governance/governance/settings?tenant_id=root",
    responseExample: {
      approval_expiry_minutes: 60,
      notify_email: true,
      notify_slack: false,
      smtp_host: "smtp.example.com",
      smtp_port: "587",
      default_approval_mode: "quorum",
      challenge_response_enabled: false
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks governance settings read privilege" }
    ]
  },
  {
    id: "governance-settings-update",
    group: "Governance",
    title: "Update Governance Settings",
    service: "governance",
    method: "PUT",
    pathTemplate: "/governance/settings",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "approval_expiry_minutes": 60,\n  "notify_email": true,\n  "notify_slack": false,\n  "smtp_host": "smtp.example.com",\n  "smtp_port": "587"\n}',
    description: "Updates governance notification and delivery settings.",
    requestExample: "PUT /svc/governance/governance/settings",
    responseExample: {
      status: "updated",
      approval_expiry_minutes: 60,
      notify_email: true,
      notify_slack: false,
      smtp_host: "smtp.example.com",
      smtp_port: "587"
    },
    errorCodes: [
      { code: 400, meaning: "Invalid settings payload" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks governance settings write privilege" },
      { code: 422, meaning: "SMTP validation failed or invalid configuration" }
    ]
  },
  {
    id: "governance-system-state-get",
    group: "Governance",
    title: "Get System State",
    service: "governance",
    method: "GET",
    pathTemplate: "/governance/system/state?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns system state (FIPS mode, network config, backup policy).",
    requestExample: "GET /svc/governance/governance/system/state?tenant_id=root",
    responseExample: {
      fips_mode: "enabled",
      backup_schedule: "daily@02:00",
      backup_retention_days: 30,
      network_mode: "private",
      last_backup: "2026-03-04T02:00:00Z",
      hsm_status: "connected"
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks system state read privilege" }
    ]
  },
  {
    id: "governance-system-state-update",
    group: "Governance",
    title: "Update System State",
    service: "governance",
    method: "PUT",
    pathTemplate: "/governance/system/state",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "fips_mode": "enabled",\n  "backup_schedule": "daily@02:00",\n  "backup_retention_days": 30\n}',
    description: "Updates system-level security and operational state.",
    requestExample: "PUT /svc/governance/governance/system/state",
    responseExample: {
      status: "updated",
      fips_mode: "enabled",
      backup_schedule: "daily@02:00",
      backup_retention_days: 30
    },
    errorCodes: [
      { code: 400, meaning: "Invalid system state payload" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks system state write privilege" },
      { code: 422, meaning: "FIPS mode transition blocked or backup schedule invalid" }
    ]
  },
  {
    id: "governance-backups-list",
    group: "Governance",
    title: "List Backups",
    service: "governance",
    method: "GET",
    pathTemplate: "/governance/backups?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists encrypted backup jobs with status and timestamps.",
    requestExample: "GET /svc/governance/governance/backups?tenant_id=root",
    responseExample: {
      items: [
        { id: "bkp_01", scope: "system", status: "completed", created_at: "2026-03-04T02:00:00Z", size_mb: 128, bind_to_hsm: false },
        { id: "bkp_02", scope: "system", status: "completed", created_at: "2026-03-03T02:00:00Z", size_mb: 125, bind_to_hsm: false }
      ]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks backup list privilege" }
    ]
  },
  {
    id: "governance-backups-create",
    group: "Governance",
    title: "Create Backup",
    service: "governance",
    method: "POST",
    pathTemplate: "/governance/backups",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "scope": "system",\n  "bind_to_hsm": false,\n  "created_by": "admin"\n}',
    description: "Creates an encrypted backup of KMS data.",
    requestExample: "POST /svc/governance/governance/backups",
    responseExample: {
      backup: { id: "bkp_03", scope: "system", status: "in_progress", created_at: "2026-03-04T12:00:00Z", created_by: "admin", bind_to_hsm: false }
    },
    errorCodes: [
      { code: 400, meaning: "Invalid scope or missing required fields" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks backup create privilege" },
      { code: 409, meaning: "Backup already in progress" },
      { code: 422, meaning: "HSM binding requested but HSM unavailable" }
    ]
  },
  {
    id: "governance-policies-list",
    group: "Governance",
    title: "List Governance Policies",
    service: "governance",
    method: "GET",
    pathTemplate: "/governance/policies?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists governance policies (approval rules, quorum requirements).",
    requestExample: "GET /svc/governance/governance/policies?tenant_id=root",
    responseExample: {
      items: [
        { id: "pol_01", name: "key-export-approval", action: "key.export", required_approvals: 2, approver_roles: ["admin", "security-officer"], status: "active" },
        { id: "pol_02", name: "key-destroy-approval", action: "key.destroy", required_approvals: 3, approver_roles: ["admin", "security-officer", "compliance-officer"], status: "active" }
      ]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks governance policies read privilege" }
    ]
  },
  {
    id: "governance-policies-create",
    group: "Governance",
    title: "Create Governance Policy",
    service: "governance",
    method: "POST",
    pathTemplate: "/governance/policies",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "name": "key-export-approval",\n  "action": "key.export",\n  "required_approvals": 2,\n  "approver_roles": ["admin", "security-officer"]\n}',
    description: "Creates a governance approval policy.",
    requestExample: "POST /svc/governance/governance/policies",
    responseExample: {
      policy: { id: "pol_03", name: "key-export-approval", action: "key.export", required_approvals: 2, approver_roles: ["admin", "security-officer"], status: "active", created_at: "2026-03-04T12:00:00Z" }
    },
    errorCodes: [
      { code: 400, meaning: "Invalid policy payload or missing required fields" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks governance policy create privilege" },
      { code: 409, meaning: "Policy with same name or action already exists" },
      { code: 422, meaning: "Invalid approver roles or action not recognized" }
    ]
  },

  /* ── Data Protection ─────────────────────────────────────────── */

  {
    id: "dataprotect-tokenize",
    group: "Data Protection",
    title: "Tokenize",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/tokenize",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "plaintext": "4111-1111-1111-1111",\n  "format": "credit_card",\n  "ttl": "24h"\n}',
    description: "Tokenizes sensitive data and returns a surrogate token with optional TTL.",
    requestExample: "POST /svc/dataprotect/tokenize",
    responseExample: {
      token: "tok_abc123",
      format: "credit_card",
      expires_at: "2026-03-05T12:00:00Z"
    },
    errorCodes: [
      { code: 400, meaning: "Invalid payload or unsupported format" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks tokenize permission" },
      { code: 422, meaning: "Plaintext does not match declared format" }
    ]
  },
  {
    id: "dataprotect-detokenize",
    group: "Data Protection",
    title: "Detokenize",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/detokenize",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "token": "tok_abc123"\n}',
    description: "Resolves a token back to its original plaintext value.",
    requestExample: "POST /svc/dataprotect/detokenize",
    responseExample: {
      plaintext: "4111-1111-1111-1111",
      format: "credit_card"
    },
    errorCodes: [
      { code: 400, meaning: "Invalid payload or malformed token" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks detokenize permission" },
      { code: 404, meaning: "Token not found or expired" }
    ]
  },
  {
    id: "dataprotect-tokenize-batch",
    group: "Data Protection",
    title: "Batch Tokenize",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/tokenize/batch",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "items": [\n    { "plaintext": "4111-1111-1111-1111", "format": "credit_card" },\n    { "plaintext": "550000001234", "format": "credit_card" }\n  ]\n}',
    description: "Tokenizes multiple values in a single request.",
    requestExample: "POST /svc/dataprotect/tokenize/batch",
    responseExample: {
      tokens: [
        { token: "tok_abc123", format: "credit_card" },
        { token: "tok_def456", format: "credit_card" }
      ]
    },
    errorCodes: [
      { code: 400, meaning: "Invalid payload or unsupported format in one or more items" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks tokenize permission" },
      { code: 422, meaning: "One or more items failed format validation" }
    ]
  },
  {
    id: "dataprotect-fpe-encrypt",
    group: "Data Protection",
    title: "FPE Encrypt",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/fpe/encrypt",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "key_id": "{{key_id}}",\n  "plaintext": "4111111111111111",\n  "alphabet": "numeric",\n  "tweak": "0000000000"\n}',
    description: "Encrypts data using Format-Preserving Encryption (FF1/FF3-1), keeping output in the same format and length.",
    requestExample: "POST /svc/dataprotect/fpe/encrypt",
    responseExample: {
      ciphertext: "7293840185629374",
      alphabet: "numeric"
    },
    errorCodes: [
      { code: 400, meaning: "Invalid payload, alphabet, or tweak length" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks FPE encrypt permission" },
      { code: 404, meaning: "Key not found" },
      { code: 422, meaning: "Plaintext contains characters outside declared alphabet" }
    ]
  },
  {
    id: "dataprotect-fpe-decrypt",
    group: "Data Protection",
    title: "FPE Decrypt",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/fpe/decrypt",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "key_id": "{{key_id}}",\n  "ciphertext": "7293840185629374",\n  "alphabet": "numeric",\n  "tweak": "0000000000"\n}',
    description: "Decrypts FPE-encrypted data back to the original plaintext.",
    requestExample: "POST /svc/dataprotect/fpe/decrypt",
    responseExample: {
      plaintext: "4111111111111111",
      alphabet: "numeric"
    },
    errorCodes: [
      { code: 400, meaning: "Invalid payload, alphabet, or tweak length" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks FPE decrypt permission" },
      { code: 404, meaning: "Key not found" },
      { code: 422, meaning: "Ciphertext contains characters outside declared alphabet" }
    ]
  },
  {
    id: "dataprotect-mask",
    group: "Data Protection",
    title: "Mask Data",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/mask",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "value": "4111-1111-1111-1111",\n  "policy_id": "mask_cc"\n}',
    description: "Applies a masking policy to partially obscure sensitive data.",
    requestExample: "POST /svc/dataprotect/mask",
    responseExample: {
      masked: "****-****-****-1111",
      policy_id: "mask_cc"
    },
    errorCodes: [
      { code: 400, meaning: "Invalid payload or missing required fields" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks mask permission" },
      { code: 404, meaning: "Masking policy not found" }
    ]
  },
  {
    id: "dataprotect-redact",
    group: "Data Protection",
    title: "Redact Data",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/redact",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "text": "My SSN is 123-45-6789 and email is user@example.com",\n  "rules": ["ssn", "email"]\n}',
    description: "Scans text for sensitive patterns and replaces matches with [REDACTED].",
    requestExample: "POST /svc/dataprotect/redact",
    responseExample: {
      redacted: "My SSN is [REDACTED] and email is [REDACTED]",
      detections: [
        { type: "ssn", count: 1 },
        { type: "email", count: 1 }
      ]
    },
    errorCodes: [
      { code: 400, meaning: "Invalid payload or unrecognized rule names" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks redact permission" },
      { code: 422, meaning: "Text exceeds maximum allowed length" }
    ]
  },
  {
    id: "dataprotect-envelope-encrypt",
    group: "Data Protection",
    title: "Envelope Encrypt",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/app/envelope-encrypt",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "key_id": "{{key_id}}",\n  "plaintext_base64": "SGVsbG8gV29ybGQ=",\n  "aad": "context-string"\n}',
    description: "Generates a DEK, encrypts plaintext locally, and wraps the DEK with the specified KEK.",
    requestExample: "POST /svc/dataprotect/app/envelope-encrypt",
    responseExample: {
      encrypted_dek: "base64...",
      ciphertext_base64: "base64...",
      iv: "base64...",
      tag: "base64...",
      aad: "context-string"
    },
    errorCodes: [
      { code: 400, meaning: "Invalid payload or base64 encoding" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks envelope encrypt permission" },
      { code: 404, meaning: "Key not found" },
      { code: 422, meaning: "Key state/policy blocks encryption" }
    ]
  },
  {
    id: "dataprotect-envelope-decrypt",
    group: "Data Protection",
    title: "Envelope Decrypt",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/app/envelope-decrypt",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "key_id": "{{key_id}}",\n  "encrypted_dek": "base64...",\n  "ciphertext_base64": "base64...",\n  "iv": "base64...",\n  "tag": "base64...",\n  "aad": "context-string"\n}',
    description: "Unwraps the DEK with the KEK and decrypts the ciphertext.",
    requestExample: "POST /svc/dataprotect/app/envelope-decrypt",
    responseExample: {
      plaintext_base64: "SGVsbG8gV29ybGQ="
    },
    errorCodes: [
      { code: 400, meaning: "Invalid payload or base64 encoding" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks envelope decrypt permission" },
      { code: 404, meaning: "Key not found" },
      { code: 422, meaning: "Authentication/tag verification failed or wrong key" }
    ]
  },
  {
    id: "dataprotect-masking-policies-list",
    group: "Data Protection",
    title: "List Masking Policies",
    service: "dataprotect",
    method: "GET",
    pathTemplate: "/masking-policies?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists all configured masking policies for a tenant.",
    requestExample: "GET /svc/dataprotect/masking-policies?tenant_id=root",
    responseExample: {
      items: [
        { id: "mask_cc", name: "Credit Card Mask", pattern: "credit_card", mask_char: "*", visible_last: 4, status: "active" }
      ]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks masking policy read privilege" }
    ]
  },

  /* ── Payment Crypto ──────────────────────────────────────────── */

  {
    id: "payment-keys-list",
    group: "Payment Crypto",
    title: "List Payment Keys",
    service: "payment",
    method: "GET",
    pathTemplate: "/payment/keys?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists payment-related cryptographic keys (BDK, KEK, ZMK, etc.).",
    requestExample: "GET /svc/payment/payment/keys?tenant_id=root",
    responseExample: {
      items: [
        { id: "pkey_01", label: "BDK-Production", type: "BDK", algorithm: "TDES", status: "active", created_at: "2026-01-15T10:00:00Z" }
      ]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks payment key list privilege" }
    ]
  },
  {
    id: "payment-keys-register",
    group: "Payment Crypto",
    title: "Register Payment Key",
    service: "payment",
    method: "POST",
    pathTemplate: "/payment/keys",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "label": "BDK-Production",\n  "type": "BDK",\n  "algorithm": "TDES",\n  "key_block": "S0128..."\n}',
    description: "Registers an externally-sourced payment key into the KMS.",
    requestExample: "POST /svc/payment/payment/keys",
    responseExample: {
      key: { id: "pkey_02", label: "BDK-Production", type: "BDK", algorithm: "TDES", status: "active", kcv: "A1B2C3" }
    },
    errorCodes: [
      { code: 400, meaning: "Invalid key block or missing required fields" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks payment key register privilege" },
      { code: 409, meaning: "Key with same label already exists" },
      { code: 422, meaning: "Key block validation failed (KCV mismatch)" }
    ]
  },
  {
    id: "payment-tr31-create",
    group: "Payment Crypto",
    title: "TR-31 Create Key Block",
    service: "payment",
    method: "POST",
    pathTemplate: "/payment/tr31/create",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "wrapping_key_id": "pkey_01",\n  "key_data_hex": "0123456789ABCDEF...",\n  "key_usage": "B0",\n  "algorithm": "T",\n  "mode_of_use": "E"\n}',
    description: "Creates an ANSI TR-31 key block by wrapping key material under a specified wrapping key.",
    requestExample: "POST /svc/payment/payment/tr31/create",
    responseExample: {
      key_block: "D0128B0TE00N0000...",
      format: "D",
      length: 128
    },
    errorCodes: [
      { code: 400, meaning: "Invalid hex data or TR-31 attributes" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks TR-31 create privilege" },
      { code: 404, meaning: "Wrapping key not found" },
      { code: 422, meaning: "Key usage/algorithm combination not valid per TR-31 spec" }
    ]
  },
  {
    id: "payment-tr31-parse",
    group: "Payment Crypto",
    title: "TR-31 Parse Key Block",
    service: "payment",
    method: "POST",
    pathTemplate: "/payment/tr31/parse",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "wrapping_key_id": "pkey_01",\n  "key_block": "D0128B0TE00N0000..."\n}',
    description: "Parses and unwraps a TR-31 key block, returning its header attributes.",
    requestExample: "POST /svc/payment/payment/tr31/parse",
    responseExample: {
      key_usage: "B0",
      algorithm: "T",
      mode_of_use: "E",
      format: "D",
      key_version: "00",
      exportability: "N"
    },
    errorCodes: [
      { code: 400, meaning: "Malformed key block" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks TR-31 parse privilege" },
      { code: 404, meaning: "Wrapping key not found" },
      { code: 422, meaning: "Key block MAC verification failed" }
    ]
  },
  {
    id: "payment-pin-translate",
    group: "Payment Crypto",
    title: "PIN Translate",
    service: "payment",
    method: "POST",
    pathTemplate: "/payment/pin/translate",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "source_key_id": "pkey_01",\n  "dest_key_id": "pkey_02",\n  "pin_block": "0412AC...",\n  "source_format": "ISO0",\n  "dest_format": "ISO3",\n  "pan": "4111111111111111"\n}',
    description: "Translates a PIN block from one encryption key and format to another.",
    requestExample: "POST /svc/payment/payment/pin/translate",
    responseExample: {
      pin_block: "3412BD...",
      dest_format: "ISO3"
    },
    errorCodes: [
      { code: 400, meaning: "Invalid PIN block or format specification" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks PIN translate privilege" },
      { code: 404, meaning: "Source or destination key not found" },
      { code: 422, meaning: "PIN block decryption failed or PAN mismatch" }
    ]
  },
  {
    id: "payment-pvv-generate",
    group: "Payment Crypto",
    title: "PVV Generate",
    service: "payment",
    method: "POST",
    pathTemplate: "/payment/pin/pvv/generate",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "pvk_id": "pkey_01",\n  "pin_block": "0412AC...",\n  "pan": "4111111111111111",\n  "pin_block_format": "ISO0"\n}',
    description: "Generates a PIN Verification Value (PVV) from a PIN block using the Visa PVV algorithm.",
    requestExample: "POST /svc/payment/payment/pin/pvv/generate",
    responseExample: {
      pvv: "1234"
    },
    errorCodes: [
      { code: 400, meaning: "Invalid PIN block, PAN, or format" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks PVV generate privilege" },
      { code: 404, meaning: "PVK key not found" },
      { code: 422, meaning: "PIN block decryption failed" }
    ]
  },
  {
    id: "payment-cvv-compute",
    group: "Payment Crypto",
    title: "CVV Compute",
    service: "payment",
    method: "POST",
    pathTemplate: "/payment/pin/cvv/compute",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "cvk_id": "pkey_01",\n  "pan": "4111111111111111",\n  "expiry": "2612",\n  "service_code": "101"\n}',
    description: "Computes a Card Verification Value (CVV/CVV2) using the specified CVK.",
    requestExample: "POST /svc/payment/payment/pin/cvv/compute",
    responseExample: {
      cvv: "789"
    },
    errorCodes: [
      { code: 400, meaning: "Invalid PAN, expiry, or service code format" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks CVV compute privilege" },
      { code: 404, meaning: "CVK key not found" },
      { code: 422, meaning: "PAN fails Luhn check" }
    ]
  },
  {
    id: "payment-iso20022-sign",
    group: "Payment Crypto",
    title: "ISO 20022 Sign",
    service: "payment",
    method: "POST",
    pathTemplate: "/payment/iso20022/sign",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "key_id": "{{key_id}}",\n  "message_type": "pacs.008",\n  "payload_base64": "PERvY3VtZW50Pg=="\n}',
    description: "Signs an ISO 20022 payment message with the specified signing key.",
    requestExample: "POST /svc/payment/payment/iso20022/sign",
    responseExample: {
      signature_base64: "MEUCIQD...",
      algorithm: "RSA-SHA256",
      message_type: "pacs.008"
    },
    errorCodes: [
      { code: 400, meaning: "Invalid payload or unsupported message type" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks ISO 20022 signing privilege" },
      { code: 404, meaning: "Signing key not found" },
      { code: 422, meaning: "Key type incompatible with signing operation" }
    ]
  },
  // ── Reporting expansion ──────────────────────────────────────────────
  {
    id: "reporting-alert-stats",
    group: "Reporting",
    title: "Alert Stats",
    service: "reporting",
    method: "GET",
    pathTemplate: "/alerts/stats?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns aggregate alert statistics including counts by severity and open/acknowledged breakdown.",
    requestExample: "GET /svc/reporting/alerts/stats?tenant_id=root",
    responseExample: {
      total: 847,
      by_severity: { critical: 12, high: 89, warning: 234, info: 512 },
      open: 156,
      acknowledged: 691
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid query parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },
  {
    id: "reporting-alert-mttr",
    group: "Reporting",
    title: "Alert MTTR Stats",
    service: "reporting",
    method: "GET",
    pathTemplate: "/alerts/stats/mttr?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns mean-time-to-resolve statistics for alerts, broken down by severity over a rolling period.",
    requestExample: "GET /svc/reporting/alerts/stats/mttr?tenant_id=root",
    responseExample: {
      mean_time_to_resolve_hours: 4.2,
      by_severity: { critical: 0.5, high: 2.1, warning: 6.8, info: 12.4 },
      period: "30d"
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid query parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },
  {
    id: "reporting-alert-top-sources",
    group: "Reporting",
    title: "Alert Top Sources",
    service: "reporting",
    method: "GET",
    pathTemplate: "/alerts/stats/top-sources?tenant_id={{tenant_id}}&limit=5",
    bodyTemplate: "",
    description: "Returns the top alert-generating sources ranked by count.",
    requestExample: "GET /svc/reporting/alerts/stats/top-sources?tenant_id=root&limit=5",
    responseExample: {
      sources: [{ source: "auth-service", count: 245 }, { source: "key-rotation", count: 189 }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid limit" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },
  {
    id: "reporting-alert-rules-list",
    group: "Reporting",
    title: "List Alert Rules",
    service: "reporting",
    method: "GET",
    pathTemplate: "/alerts/rules?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists configured alert rules including conditions, thresholds, and enabled state.",
    requestExample: "GET /svc/reporting/alerts/rules?tenant_id=root",
    responseExample: {
      items: [{ id: "rule_01", name: "High Failure Rate", condition: "threshold", pattern: "auth.login.failed", threshold: 10, window_seconds: 300, severity: "high", enabled: true }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid query parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },
  {
    id: "reporting-alert-rules-create",
    group: "Reporting",
    title: "Create Alert Rule",
    service: "reporting",
    method: "POST",
    pathTemplate: "/alerts/rules",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "name": "High Failure Rate",\n  "condition": "threshold",\n  "pattern": "auth.login.failed",\n  "threshold": 10,\n  "window_seconds": 300,\n  "severity": "high",\n  "channels": ["email", "webhook"]\n}',
    description: "Creates a new alert rule with condition, threshold, and notification channels.",
    requestExample: "POST /svc/reporting/alerts/rules",
    responseExample: {
      rule: { id: "rule_02", name: "High Failure Rate", condition: "threshold", enabled: true, created_at: "2026-03-04T12:00:00Z" }
    },
    errorCodes: [
      { code: 400, meaning: "Invalid rule payload or missing required fields" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" },
      { code: 409, meaning: "Rule with same name already exists" }
    ]
  },
  {
    id: "reporting-alerts-bulk-ack",
    group: "Reporting",
    title: "Bulk Acknowledge Alerts",
    service: "reporting",
    method: "POST",
    pathTemplate: "/alerts/bulk/acknowledge",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "alert_ids": ["alert_01", "alert_02", "alert_03"],\n  "note": "Investigated — false positive"\n}',
    description: "Acknowledges multiple alerts in a single request with an optional investigation note.",
    requestExample: "POST /svc/reporting/alerts/bulk/acknowledge",
    responseExample: {
      acknowledged: 3,
      failed: 0
    },
    errorCodes: [
      { code: 400, meaning: "Invalid payload or empty alert_ids array" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" },
      { code: 422, meaning: "One or more alert IDs not found" }
    ]
  },
  {
    id: "reporting-report-jobs-list",
    group: "Reporting",
    title: "List Report Jobs",
    service: "reporting",
    method: "GET",
    pathTemplate: "/reports/jobs?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists report generation jobs with status and download links for completed reports.",
    requestExample: "GET /svc/reporting/reports/jobs?tenant_id=root",
    responseExample: {
      items: [{ id: "rpt_01", type: "compliance-summary", status: "completed", created_at: "2026-03-04T02:00:00Z", download_url: "/reports/download/rpt_01" }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid query parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },
  {
    id: "reporting-scheduled-list",
    group: "Reporting",
    title: "List Scheduled Reports",
    service: "reporting",
    method: "GET",
    pathTemplate: "/reports/scheduled?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists scheduled report definitions with cron expressions and last/next run timestamps.",
    requestExample: "GET /svc/reporting/reports/scheduled?tenant_id=root",
    responseExample: {
      items: [{ id: "sched_01", name: "Weekly Compliance", type: "compliance-summary", cron: "0 2 * * MON", last_run: "2026-03-03T02:00:00Z", next_run: "2026-03-10T02:00:00Z", enabled: true }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid query parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },
  // ── Security Posture ───────────────────────────────────────────────
  {
    id: "posture-findings-list",
    group: "Security Posture",
    title: "List Findings",
    service: "posture",
    method: "GET",
    pathTemplate: "/posture/findings?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists security posture findings such as weak algorithms, expired keys, and policy violations.",
    requestExample: "GET /svc/posture/posture/findings?tenant_id=root",
    responseExample: {
      items: [{ id: "find_01", title: "Weak Key Algorithm", severity: "high", resource: "key_abc", category: "key-hygiene", status: "open", first_seen: "2026-03-01T10:00:00Z" }],
      total: 42
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid query parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },
  {
    id: "posture-risk-score",
    group: "Security Posture",
    title: "Get Risk Score",
    service: "posture",
    method: "GET",
    pathTemplate: "/posture/risk?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns the composite risk score with grade, category breakdown, and trend direction.",
    requestExample: "GET /svc/posture/posture/risk?tenant_id=root",
    responseExample: {
      score: 72,
      grade: "B",
      breakdown: { key_hygiene: 85, access_control: 70, compliance: 65, crypto_agility: 68 },
      trend: "improving"
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },
  {
    id: "posture-risk-history",
    group: "Security Posture",
    title: "Risk History",
    service: "posture",
    method: "GET",
    pathTemplate: "/posture/risk/history?tenant_id={{tenant_id}}&days=30",
    bodyTemplate: "",
    description: "Returns historical risk score data points over the requested number of days.",
    requestExample: "GET /svc/posture/posture/risk/history?tenant_id=root&days=30",
    responseExample: {
      points: [{ date: "2026-03-04", score: 72 }, { date: "2026-03-03", score: 70 }, { date: "2026-03-02", score: 68 }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid days parameter" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },
  {
    id: "posture-dashboard",
    group: "Security Posture",
    title: "Get Posture Dashboard",
    service: "posture",
    method: "GET",
    pathTemplate: "/posture/dashboard?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns a consolidated posture dashboard with risk score, finding counts, and top recommendations.",
    requestExample: "GET /svc/posture/posture/dashboard?tenant_id=root",
    responseExample: {
      risk_score: 72,
      findings: { critical: 2, high: 8, warning: 15, info: 17 },
      top_recommendations: [{ title: "Rotate expired keys", impact: "high", effort: "low" }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },
  {
    id: "posture-actions-list",
    group: "Security Posture",
    title: "List Remediation Actions",
    service: "posture",
    method: "GET",
    pathTemplate: "/posture/actions?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists recommended remediation actions linked to findings with priority and status.",
    requestExample: "GET /svc/posture/posture/actions?tenant_id=root",
    responseExample: {
      items: [{ id: "act_01", finding_id: "find_01", action: "rotate_key", status: "pending", priority: "high" }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid query parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },
  // ── Discovery ──────────────────────────────────────────────────────
  {
    id: "discovery-scan-start",
    group: "Discovery",
    title: "Start Scan",
    service: "discovery",
    method: "POST",
    pathTemplate: "/discovery/scan",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "scope": "full",\n  "targets": ["aws", "azure", "gcp"],\n  "depth": "deep"\n}',
    description: "Initiates a cryptographic asset discovery scan across specified cloud providers.",
    requestExample: "POST /svc/discovery/discovery/scan",
    responseExample: {
      scan: { id: "scan_01", status: "running", scope: "full", started_at: "2026-03-04T12:00:00Z", targets: ["aws", "azure", "gcp"] }
    },
    errorCodes: [
      { code: 400, meaning: "Invalid scope, targets, or missing required fields" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" },
      { code: 409, meaning: "Scan already in progress" }
    ]
  },
  {
    id: "discovery-scans-list",
    group: "Discovery",
    title: "List Scans",
    service: "discovery",
    method: "GET",
    pathTemplate: "/discovery/scans?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists discovery scan history with status, timing, and asset counts.",
    requestExample: "GET /svc/discovery/discovery/scans?tenant_id=root",
    responseExample: {
      items: [{ id: "scan_01", status: "completed", scope: "full", started_at: "2026-03-04T12:00:00Z", completed_at: "2026-03-04T12:15:00Z", assets_found: 1247 }]
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid query parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },
  {
    id: "discovery-assets-list",
    group: "Discovery",
    title: "List Assets",
    service: "discovery",
    method: "GET",
    pathTemplate: "/discovery/assets?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists discovered cryptographic assets with provider, type, algorithm, and status details.",
    requestExample: "GET /svc/discovery/discovery/assets?tenant_id=root",
    responseExample: {
      items: [{ id: "asset_01", type: "kms_key", provider: "aws", region: "us-east-1", name: "prod-master-key", algorithm: "AES-256", status: "active", discovered_at: "2026-03-04T12:05:00Z" }],
      total: 1247
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id or invalid query parameters" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },
  {
    id: "discovery-summary",
    group: "Discovery",
    title: "Get Summary",
    service: "discovery",
    method: "GET",
    pathTemplate: "/discovery/summary?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns an aggregate summary of discovered assets grouped by provider and type.",
    requestExample: "GET /svc/discovery/discovery/summary?tenant_id=root",
    responseExample: {
      total_assets: 1247,
      by_provider: { aws: 523, azure: 412, gcp: 312 },
      by_type: { kms_key: 890, certificate: 234, secret: 123 },
      last_scan: "2026-03-04T12:15:00Z"
    },
    errorCodes: [
      { code: 400, meaning: "Missing tenant_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Caller lacks required privilege" }
    ]
  },

  // ── Disk Encryption ──
  {
    id: "fde-status",
    group: "Disk Encryption",
    title: "Get FDE Status",
    service: "governance",
    method: "GET",
    pathTemplate: "/governance/system/fde/status?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns full-disk encryption status including algorithm, LUKS version, key slots, and storage usage.",
    requestExample: "GET /svc/governance/governance/system/fde/status?tenant_id=root",
    responseExample: {
      enabled: true,
      algorithm: "aes-xts-plain64",
      luks_version: "2",
      key_derivation: "argon2id",
      device: "/dev/sda2",
      unlock_method: "passphrase",
      recovery_shares: 5,
      recovery_threshold: 3,
      key_slots: [{ slot: 0, status: "active", type: "passphrase" }],
      volume_size_gb: 500,
      used_gb: 120
    },
    errorCodes: [
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Not a system admin" }
    ]
  },
  {
    id: "fde-integrity-check",
    group: "Disk Encryption",
    title: "Run Integrity Check",
    service: "governance",
    method: "POST",
    pathTemplate: "/governance/system/fde/integrity-check",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}"\n}',
    description: "Triggers a LUKS integrity verification on the encrypted volume.",
    requestExample: "POST /svc/governance/governance/system/fde/integrity-check",
    responseExample: { passed: true, mode: "dm-integrity", checked_at: "2026-03-05T10:30:00Z", errors: [] },
    errorCodes: [
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Not a system admin" },
      { code: 500, meaning: "Integrity check failed with internal error" }
    ]
  },
  {
    id: "fde-rotate-key",
    group: "Disk Encryption",
    title: "Rotate Volume Key",
    service: "governance",
    method: "POST",
    pathTemplate: "/governance/system/fde/rotate-key",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "confirm": true,\n  "reason": "scheduled-rotation"\n}',
    description: "Initiates an online LUKS volume key rotation. This is a long-running operation.",
    requestExample: "POST /svc/governance/governance/system/fde/rotate-key",
    responseExample: { status: "rotating", job_id: "fde-rot-001", started_at: "2026-03-05T10:35:00Z", estimated_duration_minutes: 15 },
    errorCodes: [
      { code: 400, meaning: "Missing confirmation flag" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Not a system admin" }
    ]
  },
  {
    id: "fde-test-recovery",
    group: "Disk Encryption",
    title: "Test Recovery Shares",
    service: "governance",
    method: "POST",
    pathTemplate: "/governance/system/fde/test-recovery",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "shares": ["share-1-hex...", "share-2-hex...", "share-3-hex..."]\n}',
    description: "Validates Shamir recovery shares without actually unlocking the volume.",
    requestExample: "POST /svc/governance/governance/system/fde/test-recovery",
    responseExample: { valid: true, shares_provided: 3, threshold_required: 3, tested_at: "2026-03-05T10:40:00Z" },
    errorCodes: [
      { code: 400, meaning: "Insufficient shares provided" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Not a system admin" }
    ]
  },
  {
    id: "fde-recovery-shares",
    group: "Disk Encryption",
    title: "Get Recovery Share Status",
    service: "governance",
    method: "GET",
    pathTemplate: "/governance/system/fde/recovery-shares?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns the current recovery share distribution status and verification timestamps.",
    requestExample: "GET /svc/governance/governance/system/fde/recovery-shares?tenant_id=root",
    responseExample: { total: 5, threshold: 3, shares: [{ index: 1, label: "CTO", verified: true, last_verified: "2026-03-01T08:00:00Z" }] },
    errorCodes: [
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Not a system admin" }
    ]
  },

  // ── AI / LLM ──
  {
    id: "ai-query",
    group: "AI / LLM",
    title: "Query AI Assistant",
    service: "ai",
    method: "POST",
    pathTemplate: "/ai/query",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "query": "What keys are expiring this month?",\n  "include_context": ["keys", "policies", "audit"]\n}',
    description: "Sends a natural-language query to the AI assistant with optional KMS context sources.",
    requestExample: "POST /svc/ai/ai/query",
    responseExample: { response: "There are 3 keys expiring this month...", model: "claude-sonnet-4-6", tokens_used: 420, context_sources_used: ["keys", "policies"], redactions_applied: 0, warnings: [] },
    errorCodes: [
      { code: 400, meaning: "Empty query or invalid context source" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 503, meaning: "AI backend unavailable" }
    ]
  },
  {
    id: "ai-analyze-incident",
    group: "AI / LLM",
    title: "Analyze Incident",
    service: "ai",
    method: "POST",
    pathTemplate: "/ai/analyze/incident",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "incident_id": "inc-001",\n  "description": "Unauthorized key export attempt detected"\n}',
    description: "AI-powered incident analysis with root cause suggestions and remediation steps.",
    requestExample: "POST /svc/ai/ai/analyze/incident",
    responseExample: { analysis: "The unauthorized export attempt was...", severity: "high", recommendations: ["Revoke key export permission", "Enable quorum approval"], confidence: 0.87 },
    errorCodes: [
      { code: 400, meaning: "Missing incident details" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 503, meaning: "AI backend unavailable" }
    ]
  },
  {
    id: "ai-recommend-posture",
    group: "AI / LLM",
    title: "Recommend Posture",
    service: "ai",
    method: "POST",
    pathTemplate: "/ai/recommend/posture",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "focus": "key-rotation"\n}',
    description: "Generates security posture improvement recommendations based on current KMS state.",
    requestExample: "POST /svc/ai/ai/recommend/posture",
    responseExample: { recommendations: [{ area: "Key Rotation", priority: "high", suggestion: "Enable automatic rotation for 12 keys older than 90 days" }], overall_score: 78 },
    errorCodes: [
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 503, meaning: "AI backend unavailable" }
    ]
  },
  {
    id: "ai-explain-policy",
    group: "AI / LLM",
    title: "Explain Policy",
    service: "ai",
    method: "POST",
    pathTemplate: "/ai/explain/policy",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "policy_id": "pol-001"\n}',
    description: "Returns a natural-language explanation of a KMS policy including its effective permissions and scope.",
    requestExample: "POST /svc/ai/ai/explain/policy",
    responseExample: { explanation: "This policy allows encrypt and decrypt operations...", effective_scope: "tenant=root, key_group=production", warnings: [] },
    errorCodes: [
      { code: 400, meaning: "Missing or invalid policy_id" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 404, meaning: "Policy not found" }
    ]
  },
  {
    id: "ai-config-get",
    group: "AI / LLM",
    title: "Get AI Config",
    service: "ai",
    method: "GET",
    pathTemplate: "/ai/config?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns the current AI service configuration including provider, model, and context settings.",
    requestExample: "GET /svc/ai/ai/config?tenant_id=root",
    responseExample: { provider: "claude", model: "claude-sonnet-4-6", endpoint: "", temperature: 0.3, max_context_tokens: 8000, context_sources: { keys: true, policies: true, audit: true, posture: true, alerts: false }, redaction_fields: ["passphrase", "secret"] },
    errorCodes: [
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Not a system admin" }
    ]
  },
  {
    id: "ai-config-update",
    group: "AI / LLM",
    title: "Update AI Config",
    service: "ai",
    method: "PUT",
    pathTemplate: "/ai/config",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "provider": "claude",\n  "model": "claude-sonnet-4-6",\n  "temperature": 0.3\n}',
    description: "Updates the AI service configuration. Partial updates are supported.",
    requestExample: "PUT /svc/ai/ai/config",
    responseExample: { status: "updated", updated_at: "2026-03-05T12:00:00Z" },
    errorCodes: [
      { code: 400, meaning: "Invalid configuration values" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Not a system admin" }
    ]
  },

  // ── Network ──
  {
    id: "network-apply",
    group: "Network",
    title: "Apply Network Config",
    service: "governance",
    method: "POST",
    pathTemplate: "/governance/system/network/apply",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}"\n}',
    description: "Applies pending network configuration changes including IP and interface updates. May cause brief connectivity disruption.",
    requestExample: "POST /svc/governance/governance/system/network/apply",
    responseExample: { status: "applied", applied_at: "2026-03-05T12:05:00Z" },
    errorCodes: [
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Not a system admin" },
      { code: 500, meaning: "Network configuration apply failed" }
    ]
  }
];
