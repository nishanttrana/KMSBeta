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
  }
];
