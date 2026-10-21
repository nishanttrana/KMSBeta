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
    description: "Lists the tenant's keys the caller may see. Key material is never returned.",
    requestExample: "GET /svc/keycore/keys?tenant_id=root&limit=100&offset=0",
    responseExample: {"items": [{"id": "key_123", "tenant_id": "root", "name": "prod-db-master", "description": "", "algorithm": "AES-256", "key_type": "symmetric", "purpose": "encrypt-decrypt", "status": "active", "current_version": 2, "kcv": "63EF1D", "export_allowed": false, "tags": [], "labels": {}, "created_at": "2026-01-15T00:00:00Z", "updated_at": "2026-01-15T00:00:00Z"}], "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode: keycore refuses a field it does not read) or the operation failed" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "permission_denied, access_denied or policy_denied" },
      { code: 404, meaning: "Key not found, or not visible to the caller" }
    ],
  },
  {
    id: "keys-create",
    group: "Key Management",
    title: "Create Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"name\": \"customer-key-name\",\n  \"description\": \"What this key protects\",\n  \"algorithm\": \"AES-256\",\n  \"key_type\": \"symmetric\",\n  \"purpose\": \"encrypt-decrypt\",\n  \"export_allowed\": false\n}",
    description: "Creates a key and responds with its id and KCV. Read the key with GET /keys/{id}.",
    requestExample: "POST /svc/keycore/keys",
    responseExample: {"key_id": "key_123", "tenant_id": "root", "kcv": "63EF1D", "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode: keycore refuses a field it does not read) or the operation failed" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "permission_denied, access_denied or policy_denied" },
      { code: 404, meaning: "Key not found, or not visible to the caller" }
    ],
  },
  {
    id: "key-encrypt",
    group: "Crypto",
    title: "Encrypt",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/encrypt",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"plaintext\": \"aGVsbG8tdmVjdGE=\",\n  \"iv_mode\": \"internal\",\n  \"reference_id\": \"txn-001\"\n}",
    description: "Encrypts base64 plaintext under the key's current version. keycore generates the IV and returns it with the ciphertext and the version.",
    requestExample: "POST /svc/keycore/keys/{key_id}/encrypt",
    responseExample: {"ciphertext": "9BEzxmi6v7I7BAMQAi/IfnvETLvoLQDr0+BL", "iv": "AaWJlSbQQ50GHHnX", "kcv": "", "key_id": "key_123", "version": 1, "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode) or the operation failed for this key" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "access_denied, policy_denied or fips_mode_violation" },
      { code: 429, meaning: "The key's operation limit is reached" }
    ],
  },
  {
    id: "key-decrypt",
    group: "Crypto",
    title: "Decrypt",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/decrypt",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"ciphertext\": \"<ciphertext from encrypt>\",\n  \"iv\": \"<iv from encrypt>\"\n}",
    description: "Decrypts a ciphertext with the IV that encrypt returned. The plaintext is base64.",
    requestExample: "POST /svc/keycore/keys/{key_id}/decrypt",
    responseExample: {"plaintext": "aGVsbG8tdmVjdGE=", "key_id": "key_123", "version": 1, "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode) or the operation failed for this key" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "access_denied, policy_denied or fips_mode_violation" },
      { code: 429, meaning: "The key's operation limit is reached" }
    ],
  },
  {
    id: "key-sign",
    group: "Crypto",
    title: "Sign",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/sign",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"data\": \"aGVsbG8tdmVjdGE=\"\n}",
    description: "Signs base64 data with the key's current version.",
    requestExample: "POST /svc/keycore/keys/{key_id}/sign",
    responseExample: {"signature": "MEQCICYCcLP6ajSG1S/mmleq6qo3/kC1Xm7JQUyJhCJY1fFhAiBK0XtgJeOAvpwVrjhOFgTcYNWeWWKdjGtJA1mcGIubEw==", "key_id": "key_123", "version": 1, "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode) or the operation failed for this key" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "access_denied, policy_denied or fips_mode_violation" },
      { code: 429, meaning: "The key's operation limit is reached" }
    ],
  },
  {
    id: "key-verify",
    group: "Crypto",
    title: "Verify",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/verify",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"data\": \"aGVsbG8tdmVjdGE=\",\n  \"signature\": \"<signature from sign>\"\n}",
    description: "Verifies a signature over base64 data. verified says whether it holds.",
    requestExample: "POST /svc/keycore/keys/{key_id}/verify",
    responseExample: {"verified": true, "key_id": "key_123", "version": 1, "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode) or the operation failed for this key" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "access_denied, policy_denied or fips_mode_violation" },
      { code: 429, meaning: "The key's operation limit is reached" }
    ],
  },
  {
    id: "crypto-hash",
    group: "Crypto",
    title: "Hash",
    service: "keycore",
    method: "POST",
    pathTemplate: "/crypto/hash",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"algorithm\": \"sha-512\",\n  \"input\": \"aGVsbG8tdmVjdGE=\"\n}",
    description: "Hashes base64 input and returns the digest in base64.",
    requestExample: "POST /svc/keycore/crypto/hash",
    responseExample: {"algorithm": "sha-512", "digest": "Z/2JXRtNr411VTCGlqE4sqwpwb9CbD/5b8z0X1W2qS3ypRM1WRgDwrRcK2NMrQP6/418GcPymwsv7G4gE+I21Q==", "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode) or an unsupported algorithm or source" },
      { code: 401, meaning: "Token missing, invalid or expired" }
    ],
  },
  {
    id: "crypto-random",
    group: "Crypto",
    title: "Random Bytes",
    service: "keycore",
    method: "POST",
    pathTemplate: "/crypto/random",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"length\": 32\n}",
    description: "Returns random bytes in base64 and the source that produced them.",
    requestExample: "POST /svc/keycore/crypto/random",
    responseExample: {"bytes": "+GaAWutvirlRBVaGNAwM6+xp0CCms5GGL0mtad8O+Co=", "length": 32, "source": "kms-csprng", "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode) or an unsupported algorithm or source" },
      { code: 401, meaning: "Token missing, invalid or expired" }
    ],
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
    responseExample: {"items": [{"id": "sec_7cf336e0c472c6ce", "tenant_id": "t1", "name": "db-password", "secret_type": "password", "description": "Updated password", "labels": {}, "metadata": {}, "status": "active", "lease_ttl_seconds": 0, "current_version": 3, "created_by": "tester", "created_at": "2026-10-12T10:48:10Z", "updated_at": "2026-10-12T10:48:10Z", "path": "/db-password", "restricted": false}], "request_id": "req_e030d0c1f774e24d"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [{"id": "crt_64ba2899fb6c95fa", "tenant_id": "t1", "ca_id": "ca_dfed5bd39eee614b", "serial_number": "a90dfab78a89c7146535c897f9ad7f", "subject_cn": "service.tenant.local", "sans": ["service.tenant.local"], "cert_type": "tls-server", "algorithm": "ECDSA-P384", "profile_id": "", "protocol": "renew", "cert_class": "classical", "cert_pem": "<certificate>", "status": "revoked", "not_before": "2026-10-12T10:43:06.803576Z", "not_after": "2027-10-12T10:48:06.803576Z", "revoked_at": "2026-10-12T10:48:06.804617Z", "revocation_reason": "key_compromise", "created_at": "2026-10-12T10:48:06Z", "updated_at": "2026-10-12T10:48:06Z", "key_ref": ""}], "request_id": "req_f71632d705e47451"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "cert-issue",
    group: "Management",
    title: "Issue Certificate",
    service: "certs",
    method: "POST",
    pathTemplate: "/certs",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"ca_id\": \"{{ca_id}}\",\n  \"subject_cn\": \"service.tenant.local\",\n  \"sans\": [\n    \"service.tenant.local\"\n  ],\n  \"cert_type\": \"tls-server\",\n  \"algorithm\": \"ECDSA-P384\",\n  \"server_keygen\": true,\n  \"validity_days\": 365,\n  \"protocol\": \"REST\"\n}",
    description: "Issues a certificate from selected CA/profile. Supports server-side keygen.",
    requestExample: "POST /svc/certs/certs",
    responseExample: {"certificate": {"id": "crt_3167cf35fa15485d", "tenant_id": "t1", "ca_id": "ca_dfed5bd39eee614b", "serial_number": "cbf02d8d6fc0b525958c467dc0bd2e", "subject_cn": "service.tenant.local", "sans": ["service.tenant.local"], "cert_type": "tls-server", "algorithm": "ECDSA-P384", "profile_id": "", "protocol": "REST", "cert_class": "classical", "cert_pem": "<certificate>", "status": "active", "not_before": "2026-10-12T10:43:06.797519Z", "not_after": "2027-10-12T10:48:06.797519Z", "revoked_at": "0001-01-01T00:00:00Z", "revocation_reason": "", "created_at": "2026-10-12T10:48:06Z", "updated_at": "2026-10-12T10:48:06Z", "key_ref": ""}, "private_key_pem": "<private key, PEM>", "request_id": "req_9388d99edbcc4ecb"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "cert-star-summary",
    group: "Management",
    title: "Get ACME STAR Summary",
    service: "certs",
    method: "GET",
    pathTemplate: "/certs/star/summary?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns tenant ACME STAR posture including subscription counts, due-soon subscriptions, delegated coverage, and rollout-group risk.",
    requestExample: "GET /svc/certs/certs/star/summary?tenant_id=root",
    responseExample: {"request_id": "req_7fb1e27e0d160bde", "summary": {"tenant_id": "t1", "enabled": true, "delegation_enabled": true, "subscription_count": 1, "delegated_count": 1, "auto_renew_count": 1, "due_soon_count": 1, "error_count": 0, "mass_rollout_risk_count": 0, "subscriptions": [{"id": "star_18194c17aa23752c", "tenant_id": "t1", "name": "mesh-edge", "account_id": "", "ca_id": "ca_dfed5bd39eee614b", "subject_cn": "edge.root.example", "sans": [], "cert_type": "tls-server", "cert_class": "star", "algorithm": "ECDSA-P256", "validity_hours": 24, "renew_before_minutes": 120, "auto_renew": true, "allow_delegation": true, "delegated_subscriber": "spiffe://prod/ns/edge/sa/gateway", "latest_cert_id": "crt_c8c5d116025fff54", "issuance_count": 2, "status": "active", "rollout_group": "mesh-us-east-1", "last_issued_at": "2026-10-12T10:48:06.802299Z", "next_renewal_at": "2026-10-13T08:48:06Z", "created_by": "system", "metadata_json": "null", "created_at": "2026-10-12T10:48:06.798884Z"}], "mass_rollout_risks": null, "recommended_window_hint": "Use short-lived STAR certs for gateways, ephemeral agents, a..."}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "cert-star-list",
    group: "Management",
    title: "List ACME STAR Subscriptions",
    service: "certs",
    method: "GET",
    pathTemplate: "/certs/star/subscriptions?tenant_id={{tenant_id}}&limit=100",
    bodyTemplate: "",
    description: "Lists STAR subscriptions with delegated subscriber metadata, issuance counters, and next renewal timing.",
    requestExample: "GET /svc/certs/certs/star/subscriptions?tenant_id=root&limit=100",
    responseExample: {"items": [{"id": "star_18194c17aa23752c", "tenant_id": "t1", "name": "mesh-edge", "account_id": "", "ca_id": "ca_dfed5bd39eee614b", "subject_cn": "edge.root.example", "sans": ["edge.root.example"], "cert_type": "tls-server", "cert_class": "star", "algorithm": "ECDSA-P256", "validity_hours": 24, "renew_before_minutes": 120, "auto_renew": true, "allow_delegation": true, "delegated_subscriber": "spiffe://prod/ns/edge/sa/gateway", "latest_cert_id": "crt_c8c5d116025fff54", "issuance_count": 2, "status": "active", "rollout_group": "mesh-us-east-1", "last_issued_at": "2026-10-12T10:48:06.802299Z", "next_renewal_at": "2026-10-13T08:48:06Z", "created_by": "system", "metadata_json": "null", "created_at": "2026-10-12T10:48:06.798884Z"}], "request_id": "req_19364f0bae4cf1fc"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "cert-star-create",
    group: "Management",
    title: "Create ACME STAR Subscription",
    service: "certs",
    method: "POST",
    pathTemplate: "/certs/star/subscriptions",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "name": "mesh-edge",\n  "ca_id": "{{ca_id}}",\n  "subject_cn": "edge.root.example",\n  "sans": ["edge.root.example"],\n  "validity_hours": 24,\n  "renew_before_minutes": 120,\n  "auto_renew": true,\n  "allow_delegation": true,\n  "delegated_subscriber": "spiffe://prod/ns/edge/sa/gateway",\n  "rollout_group": "mesh-us-east-1"\n}',
    description: "Creates a short-lived automatically renewed certificate subscription under the tenant ACME STAR policy.",
    requestExample: "POST /svc/certs/certs/star/subscriptions",
    responseExample: {"request_id": "req_5af18fa75ea81303", "subscription": {"id": "star_18194c17aa23752c", "tenant_id": "t1", "name": "mesh-edge", "account_id": "", "ca_id": "ca_dfed5bd39eee614b", "subject_cn": "edge.root.example", "sans": ["edge.root.example"], "cert_type": "tls-server", "cert_class": "star", "algorithm": "ECDSA-P256", "validity_hours": 24, "renew_before_minutes": 120, "auto_renew": true, "allow_delegation": true, "delegated_subscriber": "spiffe://prod/ns/edge/sa/gateway", "latest_cert_id": "crt_985af93d6ad2b94b", "issuance_count": 1, "status": "active", "rollout_group": "mesh-us-east-1", "last_issued_at": "2026-10-12T10:48:06.800441Z", "next_renewal_at": "2026-10-13T08:48:06Z", "created_by": "system", "metadata_json": "null", "created_at": "2026-10-12T10:48:06.798884Z"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "cert-star-refresh",
    group: "Management",
    title: "Refresh ACME STAR Subscription",
    service: "certs",
    method: "POST",
    pathTemplate: "/certs/star/subscriptions/{{subscription_id}}/refresh",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "force": true,\n  "requested_by": "platform-ops"\n}',
    description: "Forces immediate re-issuance for one ACME STAR subscription.",
    requestExample: "POST /svc/certs/certs/star/subscriptions/{{subscription_id}}/refresh",
    responseExample: {"request_id": "req_e5762f8d5d0c422f", "subscription": {"id": "star_18194c17aa23752c", "tenant_id": "t1", "name": "mesh-edge", "account_id": "", "ca_id": "ca_dfed5bd39eee614b", "subject_cn": "edge.root.example", "sans": ["edge.root.example"], "cert_type": "tls-server", "cert_class": "star", "algorithm": "ECDSA-P256", "validity_hours": 24, "renew_before_minutes": 120, "auto_renew": true, "allow_delegation": true, "delegated_subscriber": "spiffe://prod/ns/edge/sa/gateway", "latest_cert_id": "crt_c8c5d116025fff54", "issuance_count": 2, "status": "active", "rollout_group": "mesh-us-east-1", "last_issued_at": "2026-10-12T10:48:06.802299Z", "next_renewal_at": "2026-10-13T08:48:06Z", "created_by": "system", "metadata_json": "null", "created_at": "2026-10-12T10:48:06.798884Z"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "cert-star-delete",
    group: "Management",
    title: "Delete ACME STAR Subscription",
    service: "certs",
    method: "DELETE",
    pathTemplate: "/certs/star/subscriptions/{{subscription_id}}?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Deletes a STAR subscription and stops future automated renewals for it.",
    requestExample: "DELETE /svc/certs/certs/star/subscriptions/{{subscription_id}}?tenant_id={{tenant_id}}",
    responseExample: {"request_id": "req_b2e27c6c8335fc42", "status": "deleted"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
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
    responseExample: {"items": null, "request_id": "req_FA86Rq_hy2o"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [], "request_id": "req_795dadb105582588"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "byok-create",
    group: "BYOK",
    title: "Bring Your Own Key To A Cloud",
    service: "cloud",
    method: "POST",
    pathTemplate: "/cloud/byok/keys",
    bodyTemplate:
      '{\n  "account_id": "acct_aws_01",\n  "key_id": "{{key_id}}",\n  "alias": "orders-db",\n  "validity_days": 365\n}',
    description: "Creates the cloud key and imports the KMS key's current version: the cloud's wrapping key, wrapped in keycore (KMS keys) or inside the PKCS#11 HSM (HSM keys made with cloud import allowed), imported, verified. Returns the key and the run's steps.",
    requestExample: "POST /svc/cloud/cloud/byok/keys",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "byok-rotate",
    group: "BYOK",
    title: "Rotate A BYOK Key",
    service: "cloud",
    method: "POST",
    pathTemplate: "/cloud/byok/keys/{{byok_id}}/rotate",
    bodyTemplate: '{\n  "validity_days": 365\n}',
    description: "Rotates the KMS key, imports the new version as new material and makes it current in the cloud. Reimport, revoke, restore, verify and sync are the sibling operations.",
    requestExample: "POST /svc/cloud/cloud/byok/keys/byok_01/rotate",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
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
    responseExample: {"items": [{"tenant_id": "t1", "protocol": "dke", "enabled": true, "auth_mode": "jwt", "policy_id": "", "governance_required": false, "metadata_json": "{}", "created_at": "0001-01-01T00:00:00Z", "updated_at": "0001-01-01T00:00:00Z"}], "request_id": "req_ae2eba7c52f14cc4"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
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
    responseExample: {"items": [], "request_id": "req_3a329da668805426"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "kmip-client-create",
    group: "KMIP",
    title: "Create KMIP Client",
    service: "kmip",
    method: "POST",
    pathTemplate: "/kmip/clients",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"name\": \"app-kmip-client-01\",\n  \"profile_id\": \"{{profile_id}}\",\n  \"role\": \"kmip-client\",\n  \"enrollment_mode\": \"internal\",\n  \"common_name\": \"app-kmip-client-01\"\n}",
    description: "Registers a KMIP client and issues internal credentials when enrollment_mode is internal.",
    requestExample: "POST /svc/kmip/kmip/clients",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [], "request_id": "req_1e4bf78320934796"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "kmip-client-delete",
    group: "KMIP",
    title: "Delete KMIP Client",
    service: "kmip",
    method: "DELETE",
    pathTemplate: "/kmip/clients/{{client_id}}?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Deletes a KMIP client registration and removes certificate-linked access from KMIP service.",
    requestExample: "DELETE /svc/kmip/kmip/clients/{{client_id}}?tenant_id={{tenant_id}}",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "kmip-profile-delete",
    group: "KMIP",
    title: "Delete KMIP Client Profile",
    service: "kmip",
    method: "DELETE",
    pathTemplate: "/kmip/profiles/{{profile_id}}?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Deletes a KMIP client profile. Profile deletion is blocked while any KMIP client is still attached.",
    requestExample: "DELETE /svc/kmip/kmip/profiles/{{profile_id}}?tenant_id={{tenant_id}}",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
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
    responseExample: {"items": [{"id": "agent_ae2691882c162b91", "tenant_id": "t1", "name": "mssql-prod-03", "role": "ekm-agent", "db_engine": "mssql", "host": "10.0.0.15", "version": "SQL Server 2022", "status": "connected", "tde_state": "enabled", "heartbeat_interval_sec": 30, "last_heartbeat_at": "2026-10-12T10:52:42.154775Z", "assigned_key_id": "tde-key-001", "assigned_key_version": "v1", "config_version": 3, "config_version_ack": 0, "metadata_json": "{}", "tls_client_cn": "tester", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z"}], "request_id": "req_fb5cc5093af9b0a1"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"agent": {"id": "agent_ae2691882c162b91", "tenant_id": "t1", "name": "mssql-prod-03", "role": "ekm-agent", "db_engine": "mssql", "host": "10.0.0.15", "version": "SQL Server 2022", "status": "connected", "tde_state": "unknown", "heartbeat_interval_sec": 30, "last_heartbeat_at": "2026-10-12T10:52:42.149023Z", "assigned_key_id": "tde_key_1", "assigned_key_version": "v1", "config_version": 1, "config_version_ack": 0, "metadata_json": "{}", "tls_client_cn": "tester", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z"}, "auto_provisioned_key": {"id": "tde_key_1", "tenant_id": "t1", "keycore_key_id": "tde_key_1", "name": "tde-agent-agent_ae2691882c162b91", "algorithm": "RSA-3072", "status": "active", "current_version": "v1", "public_key": "<public key>", "public_key_format": "pem", "created_by": "ekm-auto-agent", "auto_provisioned": true, "metadata_json": "{}", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z", "rotated_at": "0001-01-01T00:00:00Z", "last_accessed_at": "0001-01-01T00:00:00Z"}, "request_id": "req_319be47636ad0b17"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "approval-vote",
    group: "Approvals",
    title: "Vote Approval Request",
    service: "governance",
    method: "POST",
    pathTemplate: "/governance/approve/{{request_id}}",
    bodyTemplate: 
      "{\n  \"vote\": \"approved\",\n  \"comment\": \"Approved after review\"\n}",
    description: "Submits governance vote for pending request; supports challenge-response when enabled.",
    requestExample: "POST /svc/governance/governance/approve/{request_id}",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
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
    responseExample: {"items": [], "request_id": "req_73f62fc31b178c6d"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "reporting-ack-alert",
    group: "Reporting",
    title: "Acknowledge Alert",
    service: "reporting",
    method: "PUT",
    pathTemplate: "/alerts/{{alert_id}}/acknowledge?tenant_id={{tenant_id}}",
    bodyTemplate: 
      "{}",
    description: "Acknowledges an active alert and updates alert center counters/channels state.",
    requestExample: "PUT /svc/reporting/alerts/{alert_id}/acknowledge?tenant_id=root",
    responseExample: {"request_id": "req_354e8c23ead8d6fe", "status": "ok"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "reporting-generate-report",
    group: "Reporting",
    title: "Generate Report Job",
    service: "reporting",
    method: "POST",
    pathTemplate: "/reports/generate?tenant_id={{tenant_id}}",
    bodyTemplate:
      '{\n  "template_id": "key-rotation-summary",\n  "format": "pdf",\n  "filters": {\n    "date_from": "2026-01-01",\n    "date_to": "2026-12-31"\n  }\n}',
    description: "Creates an asynchronous reporting job (PDF/JSON/CSV depending on template/format support).",
    requestExample: "POST /svc/reporting/reports/generate",
    responseExample: {"job": {"id": "rjob_79cbc86ee76a1e9c", "tenant_id": "t1", "template_id": "key-rotation-summary", "format": "pdf", "status": "queued", "filters": {"date_from": "2026-01-01", "date_to": "2026-12-31"}, "result_content": "", "result_content_type": "", "requested_by": "tester", "error": "", "created_at": "0001-01-01T00:00:00Z", "updated_at": "0001-01-01T00:00:00Z", "completed_at": "0001-01-01T00:00:00Z"}, "request_id": "req_2a020a7aae27b39c"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"username\": \"newuser\",\n  \"password\": \"Example-Passw0rd-2026\"\n}",
    description: "Authenticates user and returns JWT access/refresh tokens.",
    requestExample: "POST /svc/auth/auth/login",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "auth-refresh",
    group: "Auth & Identity",
    title: "Refresh Token",
    service: "auth",
    method: "POST",
    pathTemplate: "/auth/refresh",
    bodyTemplate: 
      "",
    description: "Issues a new token for the caller of the bearer token presented. There is no body.",
    requestExample: "POST /svc/auth/auth/refresh",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "auth-logout",
    group: "Auth & Identity",
    title: "Logout",
    service: "auth",
    method: "POST",
    pathTemplate: "/auth/logout",
    bodyTemplate: 
      "{}",
    description: "Invalidates current session and revokes tokens.",
    requestExample: "POST /svc/auth/auth/logout",
    responseExample: {"request_id": "req_c91ae9e7a5f4cdfa", "status": "ok"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "auth-change-password",
    group: "Auth & Identity",
    title: "Change Password",
    service: "auth",
    method: "POST",
    pathTemplate: "/auth/change-password",
    bodyTemplate: 
      "{\n  \"current_password\": \"Example-Passw0rd-2026\",\n  \"new_password\": \"Another-Passw0rd-2026\"\n}",
    description: "Changes the authenticated user's password.",
    requestExample: "POST /svc/auth/auth/change-password",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [{"id": "usr_b97e75f0b50d23f8", "tenant_id": "t1", "username": "alice.scim", "email": "alice@example.com", "role": "readonly", "status": "active", "must_change_password": false, "created_at": "2026-10-12T10:55:29Z"}], "request_id": "req_b79829f86dafa6a6"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "auth-users-create",
    group: "Auth & Identity",
    title: "Create User",
    service: "auth",
    method: "POST",
    pathTemplate: "/auth/users",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"username\": \"newuser\",\n  \"password\": \"Example-Passw0rd-2026\",\n  \"role\": \"readonly\",\n  \"email\": \"user@example.com\"\n}",
    description: "Creates a new user account.",
    requestExample: "POST /svc/auth/auth/users",
    responseExample: {"request_id": "req_615e52f0f3ac364f", "user_id": "usr_176b4c99438de96d"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "auth-scim-settings-get",
    group: "Auth & Identity",
    title: "Get SCIM Settings",
    service: "auth",
    method: "GET",
    pathTemplate: "/auth/scim/settings?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns tenant SCIM provisioning settings such as enablement, default role/status, deprovision behavior, and token prefix state.",
    requestExample: "GET /svc/auth/auth/scim/settings?tenant_id=root",
    responseExample: {"request_id": "req_2a5bd0a01e77f5b0", "settings": {"tenant_id": "t1", "enabled": true, "default_role": "readonly", "default_status": "active", "default_must_change_password": false, "deprovision_mode": "disable", "group_role_mappings_enabled": true, "updated_by": "admin-1", "created_at": "2026-10-12T10:55:29Z", "updated_at": "2026-10-12T10:55:29Z"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "auth-scim-settings-update",
    group: "Auth & Identity",
    title: "Update SCIM Settings",
    service: "auth",
    method: "PUT",
    pathTemplate: "/auth/scim/settings",
    bodyTemplate:
      '{\n  "tenant_id": "{{tenant_id}}",\n  "enabled": true,\n  "default_role": "readonly",\n  "default_status": "active",\n  "default_must_change_password": false,\n  "deprovision_mode": "disable",\n  "group_role_mappings_enabled": true\n}',
    description: "Creates or updates tenant SCIM provisioning controls for inbound user and group lifecycle.",
    requestExample: "PUT /svc/auth/auth/scim/settings",
    responseExample: {"request_id": "req_ba9bf9575c5c4706", "settings": {"tenant_id": "t1", "enabled": true, "default_role": "readonly", "default_status": "active", "default_must_change_password": false, "deprovision_mode": "disable", "group_role_mappings_enabled": true, "updated_by": "admin-1", "created_at": "2026-10-12T10:55:29Z", "updated_at": "2026-10-12T10:55:29Z"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "auth-scim-users-list",
    group: "Auth & Identity",
    title: "List SCIM Users",
    service: "auth",
    method: "GET",
    pathTemplate: "/auth/scim/users?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists tenant users created or managed through SCIM provisioning, including external IDs and sync state.",
    requestExample: "GET /svc/auth/auth/scim/users?tenant_id=root",
    responseExample: {"items": [{"id": "usr_b97e75f0b50d23f8", "tenant_id": "t1", "username": "alice.scim", "email": "alice@example.com", "role": "readonly", "status": "active", "must_change_password": false, "created_at": "2026-10-12T10:55:29Z", "external_id": "okta-user-01", "display_name": "Alice SCIM", "scim_managed": true, "last_synced_at": "2026-10-12T10:55:29Z"}], "request_id": "req_2986c917203dfe3d"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "scim-users-create",
    group: "Auth & Identity",
    title: "SCIM Create User",
    service: "auth",
    method: "POST",
    pathTemplate: "/scim/v2/Users",
    bodyTemplate:
      '{\n  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],\n  "externalId": "okta-user-01",\n  "userName": "alice.scim",\n  "displayName": "Alice SCIM",\n  "active": true,\n  "emails": [{"value": "alice@example.com", "primary": true}],\n  "roles": [{"value": "readonly"}]\n}',
    description: "RFC 7644 SCIM user provisioning endpoint for IdPs such as Okta or Entra ID. Uses the tenant SCIM bearer token rather than a JWT admin session.",
    requestExample: "POST /svc/auth/scim/v2/Users",
    responseExample: {"active": true, "displayName": "Alice SCIM", "emails": [{"primary": true, "type": "work", "value": "alice@example.com"}], "externalId": "okta-user-01", "id": "usr_b97e75f0b50d23f8", "meta": {"created": "2026-10-12T10:55:29Z", "lastModified": "2026-10-12T10:55:29Z", "resourceType": "User"}, "name": {"familyName": "", "givenName": ""}, "roles": [{"value": "readonly"}], "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "alice.scim"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "scim-groups-create",
    group: "Auth & Identity",
    title: "SCIM Create Group",
    service: "auth",
    method: "POST",
    pathTemplate: "/scim/v2/Groups",
    bodyTemplate: 
      "{\n  \"schemas\": [\n    \"urn:ietf:params:scim:schemas:core:2.0:Group\"\n  ],\n  \"externalId\": \"okta-group-ops\",\n  \"displayName\": \"Operations\"\n}",
    description: "RFC 7644 SCIM group provisioning endpoint used to mirror directory groups and later map them to tenant roles inside KMS.",
    requestExample: "POST /svc/auth/scim/v2/Groups",
    responseExample: {"displayName": "Operations", "externalId": "okta-group-ops", "id": "grp_12092717dc7b43bc", "members": [], "meta": {"created": "2026-10-12T10:55:29Z", "lastModified": "2026-10-12T10:55:29Z", "resourceType": "Group"}, "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [{"id": "prod-tenant", "name": "Production", "status": "active", "created_at": "2026-10-12T10:55:29Z"}], "request_id": "req_c5a8959449aaf7d6"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "auth-tenants-create",
    group: "Auth & Identity",
    title: "Create Tenant",
    service: "auth",
    method: "POST",
    pathTemplate: "/tenants",
    bodyTemplate: 
      "{\n  \"id\": \"prod-tenant\",\n  \"name\": \"Production\",\n  \"admin_email\": \"admin@example.com\"\n}",
    description: "Creates a new tenant with isolated key namespace.",
    requestExample: "POST /svc/auth/tenants",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"policy": {"tenant_id": "t1", "min_length": 12, "max_length": 128, "require_upper": true, "require_lower": true, "require_digit": true, "require_special": true, "require_no_whitespace": true, "deny_username": true, "deny_email_local_part": true, "min_unique_chars": 6, "updated_by": "admin-1", "updated_at": "2026-10-12T10:55:29Z"}, "request_id": "req_7ba6ea8b7a8c9acf"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "auth-password-policy-update",
    group: "Auth & Identity",
    title: "Update Password Policy",
    service: "auth",
    method: "PUT",
    pathTemplate: "/auth/password-policy",
    bodyTemplate: 
      "{\n  \"min_length\": 12,\n  \"require_special\": true\n}",
    description: "Updates password policy enforcement rules.",
    requestExample: "PUT /svc/auth/auth/password-policy",
    responseExample: {"policy": {"tenant_id": "t1", "min_length": 12, "max_length": 128, "require_upper": true, "require_lower": true, "require_digit": true, "require_special": true, "require_no_whitespace": true, "deny_username": true, "deny_email_local_part": true, "min_unique_chars": 6, "updated_by": "admin-1", "updated_at": "2026-10-12T10:55:29Z"}, "request_id": "req_37238e060dcfe547"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"policy": {"tenant_id": "t1", "max_failed_attempts": 5, "lockout_minutes": 15, "idle_timeout_minutes": 15, "updated_by": "admin-1", "updated_at": "2026-10-12T10:55:29Z"}, "request_id": "req_83b14d49ad7637c8"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "auth-security-policy-update",
    group: "Auth & Identity",
    title: "Update Security Policy",
    service: "auth",
    method: "PUT",
    pathTemplate: "/auth/security-policy",
    bodyTemplate: 
      "{\n  \"max_failed_attempts\": 5\n}",
    description: "Updates login security and session timeout settings.",
    requestExample: "PUT /svc/auth/auth/security-policy",
    responseExample: {"policy": {"tenant_id": "t1", "max_failed_attempts": 5, "lockout_minutes": 15, "idle_timeout_minutes": 15, "updated_by": "admin-1", "updated_at": "2026-10-12T10:55:29Z"}, "request_id": "req_2378b06046ae6a00"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"providers": [], "request_id": "req_7953bfe09046803f"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [{"tenant_id": "t1", "provider": "ad", "enabled": false, "config": {"base_dn": "", "bind_dn": "", "group_name_attr": "cn", "group_object_filter": "(objectClass=group)", "insecure_skip_verify": false, "ldap_url": "ldaps://dc01.example.local:636", "timeout_sec": 10, "use_start_tls": false, "user_display_attr": "displayName", "user_email_attr": "mail", "user_login_attr": "sAMAccountName", "user_object_filter": "(objectClass=user)"}, "secret_presence": {"bind_password_set": false}, "updated_by": "system", "created_at": "0001-01-01T00:00:00Z", "updated_at": "0001-01-01T00:00:00Z"}], "request_id": "req_2f6344d2118e4628"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": null, "request_id": "req_32c5c88d3407e0cb"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"name\": \"imported-key\",\n  \"algorithm\": \"AES-256\",\n  \"key_type\": \"symmetric\",\n  \"purpose\": \"encrypt-decrypt\",\n  \"import_method\": \"raw\",\n  \"material\": \"MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY=\"\n}",
    description: "Imports key material (base64; raw unless import_method says otherwise). Responds as create does.",
    requestExample: "POST /svc/keycore/keys/import",
    responseExample: {"key_id": "key_imp_01", "tenant_id": "root", "kcv": "AB0B21", "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode: keycore refuses a field it does not read) or the operation failed" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "permission_denied, access_denied or policy_denied" },
      { code: 404, meaning: "Key not found, or not visible to the caller" }
    ],
  },
  {
    id: "keys-rotate",
    group: "Key Management",
    title: "Rotate Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/rotate",
    bodyTemplate: 
      "{\n  \"reason\": \"scheduled\",\n  \"old_version_action\": \"deactivate\"\n}",
    description: "Gives the key a new version; older versions keep their own material. A key pair's public key follows its private key.",
    requestExample: "POST /svc/keycore/keys/{key_id}/rotate",
    responseExample: {"status": "ok", "version": 2, "version_id": "kv_7f2f231eaddf36b2", "algorithm": "", "kcv": "CDE147", "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode: keycore refuses a field it does not read) or the operation failed" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "permission_denied, access_denied or policy_denied" },
      { code: 404, meaning: "Key not found, or not visible to the caller" }
    ],
  },
  {
    id: "keys-export",
    group: "Key Management",
    title: "Export Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/export",
    bodyTemplate:
      '{\n  "wrapping_key_id": "{{wrapping_key_id}}",\n  "export_mode": "wrapped",\n  "reason": "why this key is leaving"\n}',
    description: "Exports the key's material wrapped under another key. Needs export_allowed and a reason, which is recorded in the audit event. export_mode public-plaintext returns a public component instead and needs no reason. HSM keys do not leave through this route.",
    requestExample: 'POST /svc/keycore/keys/{key_id}/export\n{"wrapping_key_id":"key_kek","export_mode":"wrapped","reason":"why this key is leaving"}',
    responseExample: { key_id: "key_123", kcv: "A1B2C3", wrapped_material: "BASE64...", material_iv: "BASE64...", wrapping_key_id: "key_kek", export_format: "aes-gcm-wrapped-by-kek" },
    errorCodes: [
      { code: 400, meaning: "export_reason_required, export_reason_invalid, or the export failed (export disabled, wrapping key not usable)" },
      { code: 401, meaning: "JWT missing/invalid/expired" },
      { code: 403, meaning: "Access or policy denied" }
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
      "{\n  \"mode\": \"scheduled\",\n  \"destroy_after_days\": 30,\n  \"confirm_name\": \"<the key's name>\",\n  \"justification\": \"decommissioned\",\n  \"checks\": {\n    \"no_active_workloads\": true,\n    \"backup_completed\": true,\n    \"irreversible_ack\": true\n  }\n}",
    description: "Schedules the key for destruction. confirm_name must be the key's name and every check true.",
    requestExample: "POST /svc/keycore/keys/{key_id}/destroy",
    responseExample: {"status": "destroy-pending", "mode": "scheduled", "destroy_at": "2026-11-11T05:38:09Z", "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode: keycore refuses a field it does not read) or the operation failed" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "permission_denied, access_denied or policy_denied" },
      { code: 404, meaning: "Key not found, or not visible to the caller" }
    ],
  },
  {
    id: "keys-activate",
    group: "Key Management",
    title: "Activate Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/activate",
    bodyTemplate: 
      "{\n  \"mode\": \"immediate\"\n}",
    description: "Activates the key now, or at activation_date with mode scheduled.",
    requestExample: "POST /svc/keycore/keys/{key_id}/activate",
    responseExample: {"status": "active", "activation_date": null, "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode: keycore refuses a field it does not read) or the operation failed" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "permission_denied, access_denied or policy_denied" },
      { code: 404, meaning: "Key not found, or not visible to the caller" }
    ],
  },
  {
    id: "keys-deactivate",
    group: "Key Management",
    title: "Deactivate Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/deactivate",
    bodyTemplate: "{}",
    description: "Deactivates the key. What it protected can still be decrypted and verified.",
    requestExample: "POST /svc/keycore/keys/{key_id}/deactivate",
    responseExample: {"status": "deactivated", "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode: keycore refuses a field it does not read) or the operation failed" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "permission_denied, access_denied or policy_denied" },
      { code: 404, meaning: "Key not found, or not visible to the caller" }
    ],
  },
  {
    id: "keys-versions",
    group: "Key Management",
    title: "List Key Versions",
    service: "keycore",
    method: "GET",
    pathTemplate: "/keys/{{key_id}}/versions?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists the key's versions with their status and KCV.",
    requestExample: "GET /svc/keycore/keys/{key_id}/versions?tenant_id=root",
    responseExample: {"items": [{"id": "kv_7f2f231eaddf36b2", "version": 2, "status": "active", "kcv": "CDE147", "created_at": "2026-01-15T00:00:00Z"}, {"id": "kv_672f0bedd79a4d2e", "version": 1, "status": "deactivated", "kcv": "9B708B", "created_at": "2025-01-01T00:00:00Z"}], "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode: keycore refuses a field it does not read) or the operation failed" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "permission_denied, access_denied or policy_denied" },
      { code: 404, meaning: "Key not found, or not visible to the caller" }
    ],
  },
  {
    id: "keys-usage",
    group: "Key Management",
    title: "Get Key Usage",
    service: "keycore",
    method: "GET",
    pathTemplate: "/keys/{{key_id}}/usage?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Returns the key's operation counters, its limit and what remains of it.",
    requestExample: "GET /svc/keycore/keys/{key_id}/usage?tenant_id=root",
    responseExample: {"usage": {"ops_total": 2, "ops_encrypt": 1, "ops_decrypt": 1, "ops_sign": 0, "ops_limit": 0, "ops_limit_window": ""}, "remaining": 0, "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode: keycore refuses a field it does not read) or the operation failed" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "permission_denied, access_denied or policy_denied" },
      { code: 404, meaning: "Key not found, or not visible to the caller" }
    ],
  },
  {
    id: "keys-usage-limit",
    group: "Key Management",
    title: "Set Key Usage Limit",
    service: "keycore",
    method: "PUT",
    pathTemplate: "/keys/{{key_id}}/usage/limit",
    bodyTemplate: 
      "{\n  \"ops_limit\": 1000000,\n  \"window\": \"total\"\n}",
    description: "Sets the key's operation limit (0 is unlimited) and its window: total, daily or monthly.",
    requestExample: "PUT /svc/keycore/keys/{key_id}/usage/limit",
    responseExample: {"status": "ok", "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode: keycore refuses a field it does not read) or the operation failed" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "permission_denied, access_denied or policy_denied" },
      { code: 404, meaning: "Key not found, or not visible to the caller" }
    ],
  },
  {
    id: "keys-wrap",
    group: "Key Management",
    title: "Wrap Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/wrap",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"plaintext\": \"aGVsbG8tdmVjdGE=\"\n}",
    description: "Wraps base64 key material under this key. Responds with the ciphertext and the IV to unwrap it with.",
    requestExample: "POST /svc/keycore/keys/{key_id}/wrap",
    responseExample: {"ciphertext": "t5EzPH/zuHJZ5K9XfRnabpJPDypkmSZkGrTg", "iv": "O3ZfttdsCKbU589c", "kcv": "", "key_id": "key_123", "version": 1, "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode) or the operation failed for this key" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "access_denied, policy_denied or fips_mode_violation" },
      { code: 429, meaning: "The key's operation limit is reached" }
    ],
  },
  {
    id: "keys-unwrap",
    group: "Key Management",
    title: "Unwrap Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/unwrap",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"ciphertext\": \"<ciphertext from wrap>\",\n  \"iv\": \"<iv from wrap>\"\n}",
    description: "Unwraps what wrap returned. The plaintext is base64.",
    requestExample: "POST /svc/keycore/keys/{key_id}/unwrap",
    responseExample: {"plaintext": "aGVsbG8tdmVjdGE=", "key_id": "key_123", "version": 1, "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode) or the operation failed for this key" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "access_denied, policy_denied or fips_mode_violation" },
      { code: 429, meaning: "The key's operation limit is reached" }
    ],
  },
  {
    id: "keys-mac",
    group: "Key Management",
    title: "Compute MAC",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/mac",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"data\": \"aGVsbG8tdmVjdGE=\"\n}",
    description: "Computes a MAC over base64 data. The MAC is returned as signature.",
    requestExample: "POST /svc/keycore/keys/{key_id}/mac",
    responseExample: {"signature": "J5NLTrg2CBpq5ax5BQuDuH/ZhlAJLc1td9TQat+5uzY=", "key_id": "key_123", "version": 1, "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode) or the operation failed for this key" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "access_denied, policy_denied or fips_mode_violation" },
      { code: 429, meaning: "The key's operation limit is reached" }
    ],
  },
  {
    id: "keys-derive",
    group: "Key Management",
    title: "Derive Key",
    service: "keycore",
    method: "POST",
    pathTemplate: "/keys/{{key_id}}/derive",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"algorithm\": \"hkdf-sha256\",\n  \"length_bits\": 256,\n  \"info\": \"aGVsbG8tdmVjdGE=\"\n}",
    description: "Derives key material from this key (HKDF). length_bits and base64 info select the output.",
    requestExample: "POST /svc/keycore/keys/{key_id}/derive",
    responseExample: {"key_id": "key_123", "version": 1, "algorithm": "hkdf-sha256", "length_bits": 256, "derived_key": "BASE64...", "request_id": "req_3c8cb9866229e7f2"},
    errorCodes: [
      { code: 400, meaning: "bad_request (the body does not decode) or the operation failed for this key" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "access_denied, policy_denied or fips_mode_violation" },
      { code: 429, meaning: "The key's operation limit is reached" }
    ],
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
    responseExample: {"request_id": "req_5bd804cd5e9ba412", "secret": {"id": "sec_7cf336e0c472c6ce", "tenant_id": "t1", "name": "db-password", "secret_type": "password", "description": "Production database password", "labels": {}, "metadata": {}, "status": "active", "lease_ttl_seconds": 0, "current_version": 1, "created_by": "tester", "created_at": "2026-10-12T10:48:10Z", "updated_at": "2026-10-12T10:48:10Z", "path": "/db-password", "restricted": false}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"request_id": "req_82b43ff68ba2fd7d", "secret": {"id": "sec_7cf336e0c472c6ce", "tenant_id": "t1", "name": "db-password", "secret_type": "password", "description": "Updated password", "labels": {}, "metadata": {}, "status": "active", "lease_ttl_seconds": 0, "current_version": 3, "created_by": "tester", "created_at": "2026-10-12T10:48:10Z", "updated_at": "2026-10-12T10:48:10Z", "path": "/db-password", "restricted": false}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
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
    responseExample: {"content_type": "text/plain", "format": "raw", "request_id": "req_86bb095a66147377", "value": "new-s3cret!", "version": 3},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "secrets-update",
    group: "Secret Vault",
    title: "Update Secret",
    service: "secrets",
    method: "PUT",
    pathTemplate: "/secrets/{{secret_id}}",
    bodyTemplate: 
      "{\n  \"value\": \"new-s3cret!\",\n  \"description\": \"Updated password\"\n}",
    description: "Updates secret value, creating a new version.",
    requestExample: "PUT /svc/secrets/secrets/{secret_id}",
    responseExample: {"request_id": "req_4a0f765bc5a7746e", "secret": {"id": "sec_7cf336e0c472c6ce", "tenant_id": "t1", "name": "db-password", "secret_type": "password", "description": "Updated password", "labels": {}, "metadata": {}, "status": "active", "lease_ttl_seconds": 0, "current_version": 3, "created_by": "tester", "created_at": "2026-10-12T10:48:10Z", "updated_at": "2026-10-12T10:48:10Z", "path": "/db-password", "restricted": false}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
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
    responseExample: {"recoverable": true, "request_id": "req_07fcd2ce6718adb5", "status": "deleted"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "secrets-rotate",
    group: "Secret Vault",
    title: "Rotate Secret",
    service: "secrets",
    method: "POST",
    pathTemplate: "/secrets/{{secret_id}}/rotate",
    bodyTemplate: 
      "{\n  \"value\": \"n3w-s3cret!\"\n}",
    description: "Rotates secret to a new version.",
    requestExample: "POST /svc/secrets/secrets/{secret_id}/rotate",
    responseExample: {"request_id": "req_ccbf5781afec746c", "secret": {"id": "sec_7cf336e0c472c6ce", "tenant_id": "t1", "name": "db-password", "secret_type": "password", "description": "Production database password", "labels": {}, "metadata": {}, "status": "active", "lease_ttl_seconds": 0, "current_version": 2, "created_by": "tester", "created_at": "2026-10-12T10:48:10Z", "updated_at": "2026-10-12T10:48:10Z", "path": "/db-password", "restricted": false}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
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
    responseExample: {"request_id": "req_ddfbeb4efc5eb18e", "versions": [{"version": 3, "created_at": "2026-10-12T10:48:10Z"}]},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
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
    responseExample: {"request_id": "req_0e4cf639b9941453", "stats": {"total_secrets": 1, "by_type": {"password": 1}, "total_versions": 3, "expiring_within_30d": 0, "expired": 0}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"name\": \"root-ca\",\n  \"ca_level\": \"root\",\n  \"algorithm\": \"ECDSA-P384\",\n  \"subject\": \"CN=Example Root CA\",\n  \"validity_days\": 3650\n}",
    description: "Creates a new Certificate Authority.",
    requestExample: "POST /svc/certs/certs/ca",
    responseExample: {"ca": {"id": "ca_dfed5bd39eee614b", "tenant_id": "t1", "name": "root-ca", "parent_ca_id": "", "ca_level": "root", "algorithm": "ECDSA-P384", "ca_type": "classical", "key_backend": "software", "key_ref": "", "cert_pem": "<certificate>", "subject": "CN=Example Root CA", "status": "active", "ots_current": 0, "ots_max": 0, "ots_alert_threshold": 0, "created_at": "2026-10-12T10:48:06Z", "updated_at": "2026-10-12T10:48:06Z"}, "request_id": "req_71cca19f16b45ef6"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [{"id": "ca_dfed5bd39eee614b", "tenant_id": "t1", "name": "root-ca", "parent_ca_id": "", "ca_level": "root", "algorithm": "ECDSA-P384", "ca_type": "classical", "key_backend": "software", "key_ref": "", "cert_pem": "<certificate>", "subject": "CN=Example Root CA", "status": "active", "ots_current": 0, "ots_max": 0, "ots_alert_threshold": 0, "created_at": "2026-10-12T10:48:06Z", "updated_at": "2026-10-12T10:48:06Z"}], "request_id": "req_39c5d72807511b54"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "certs-revoke",
    group: "Certificates / PKI",
    title: "Revoke Certificate",
    service: "certs",
    method: "POST",
    pathTemplate: "/certs/{{cert_id}}/revoke",
    bodyTemplate: 
      "{\n  \"reason\": \"key_compromise\"\n}",
    description: "Revokes a certificate with specified reason code.",
    requestExample: "POST /svc/certs/certs/{cert_id}/revoke",
    responseExample: {"request_id": "req_cb6a5af4e094e4d5", "status": "revoked"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "certs-renew",
    group: "Certificates / PKI",
    title: "Renew Certificate",
    service: "certs",
    method: "POST",
    pathTemplate: "/certs/{{cert_id}}/renew",
    bodyTemplate: 
      "{\n  \"validity_days\": 365\n}",
    description: "Renews a certificate with new validity period.",
    requestExample: "POST /svc/certs/certs/{cert_id}/renew",
    responseExample: {"certificate": {"id": "crt_64ba2899fb6c95fa", "tenant_id": "t1", "ca_id": "ca_dfed5bd39eee614b", "serial_number": "a90dfab78a89c7146535c897f9ad7f", "subject_cn": "service.tenant.local", "sans": ["service.tenant.local"], "cert_type": "tls-server", "algorithm": "ECDSA-P384", "profile_id": "", "protocol": "renew", "cert_class": "classical", "cert_pem": "<certificate>", "status": "active", "not_before": "2026-10-12T10:43:06.803576Z", "not_after": "2027-10-12T10:48:06.803576Z", "revoked_at": "0001-01-01T00:00:00Z", "revocation_reason": "", "created_at": "2026-10-12T10:48:06Z", "updated_at": "2026-10-12T10:48:06Z", "key_ref": ""}, "request_id": "req_1d0e07a58f8bdb94"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
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
    responseExample: {"content": "<certificate>", "content_type": "application/x-pem-file", "request_id": "req_02aa4cc3acd3305e"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
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
    responseExample: {"items": [{"id": "cpf_ecc8f4d3e51b5bc9", "tenant_id": "t1", "name": "internal-mtls-service", "cert_type": "tls-client", "algorithm": "ECDSA-P384", "cert_class": "classical", "profile_json": "{\"mtls\":\"internal\"}", "is_default": true, "created_at": "2026-10-12T10:48:06Z"}], "request_id": "req_a98b8885ffdb412b"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [{"cert_id": "crt_985af93d6ad2b94b", "ca_id": "ca_dfed5bd39eee614b", "cert_type": "tls-server", "cert_class": "classical", "status": "active", "not_after": "2026-10-13T10:48:06Z", "profile_id": ""}], "request_id": "req_54f5ef1886faa503"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"request_id": "req_12cc7f2080d5a756", "status": {"storage_mode": "legacy", "root_key_mode": "legacy", "ready": false, "state": "legacy", "key_version": "", "sealed_path": "", "mlock_status": ""}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": null, "request_id": "req_0736d3ac390de1fe"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "audit-search",
    group: "Audit",
    title: "Search Audit Events",
    service: "audit",
    method: "POST",
    pathTemplate: "/audit/search?tenant_id={{tenant_id}}&action=audit.key.export&limit=50",
    bodyTemplate: 
      "",
    description: "Searches audit events. The filters are query parameters, as for GET /audit/events; the body is not read.",
    requestExample: "POST /svc/audit/audit/search?tenant_id={{tenant_id}}&action=audit.key.export&limit=50",
    responseExample: {"items": null, "request_id": "req_ceb47c7ea201c7d5"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "audit-chain-verify",
    group: "Audit",
    title: "Verify Audit Chain",
    service: "audit",
    method: "GET",
    pathTemplate: "/audit/chain/verify?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Verifies the tenant's audit chains from each chain's newest signed checkpoint (add full=true to walk every row), and reports when the hourly full walk last passed.",
    requestExample: "GET /svc/audit/audit/chain/verify?tenant_id=root",
    responseExample: {"breaks": null, "from_sequence": {}, "last_full_verification": null, "ok": true, "request_id": "req_c3b2e0276164f02f", "rows_checked": 0, "scope": "since_checkpoint"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "audit-investigate",
    group: "Audit",
    title: "Investigate Audit Activity",
    service: "audit",
    method: "GET",
    pathTemplate: "/audit/investigate?tenant_id={{tenant_id}}&actor_id={{actor_id}}",
    bodyTemplate: "",
    description: "For the events the pivots select (actor_id, action, target_id, source_ip, user_agent, service, result, session_id, correlation_id, from, to), the top values of each, counted over the whole window. GET /audit/events with the same filters plus one value lists exactly the events it counts.",
    requestExample: "GET /svc/audit/audit/investigate?tenant_id=root&actor_id=admin",
    responseExample: {"investigation": {"bucket_seconds": 3600, "distinct": {"action": 0, "actor_id": 0, "correlation_id": 0, "result": 0, "service": 0, "session_id": 0, "source_ip": 0, "target_id": 0, "user_agent": 0}, "facets": {"action": [], "actor_id": [], "correlation_id": [], "result": [], "service": [], "session_id": [], "source_ip": [], "target_id": [], "user_agent": []}, "first_seen": null, "from": "2026-10-21T19:47:55.956134Z", "last_seen": null, "series": [{"count": 0, "start": "2026-10-21T19:00:00Z"}], "to": "2026-10-21T19:47:55.956134Z", "total": 0}, "request_id": "req_d7213693e729b873"},
    errorCodes: [
      { code: 400, meaning: "from or to is not an RFC 3339 time" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"posture": {"id": "posture_72d5e55357c2ce2f", "tenant_id": "t1", "overall_score": 99, "key_hygiene": 98, "policy_compliance": 100, "access_security": 100, "crypto_posture": 98, "pqc_readiness": 100, "framework_scores": {"eidas": 99, "fips-140-3": 99, "nist-800-57": 99, "pci-dss-4.0": 99}, "metrics": {"approved_algorithm_pct": 0, "cert_active": 0, "cert_ari_enabled": 0, "cert_due_soon_windows": 0, "cert_emergency_rotations": 0, "cert_expired": 0, "cert_expiring_30d": 0, "cert_mass_renewal_risks": 0, "cert_missed_windows": 0, "cert_pqc_class_pct": 0, "cert_revoked": 0, "cert_score": 100, "cert_star_delegated": 0, "cert_star_due_soon": 0, "cert_star_rollout_risks": 0, "cert_star_subscriptions": 0, "cert_total": 0, "cert_weak_algorithms": 0, "deprecated_count": 0, "failed_auth_rate_pct": 0, "mfa_adoption_pct": 0, "orphaned_count": 0, "policy_coverage_pct": 0, "policy_violation_count": 0}, "gap_count": 0, "created_at": "2026-10-12T10:44:21Z"}, "request_id": "req_bd427b273eeafe9e"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [{"id": "posture_72d5e55357c2ce2f", "tenant_id": "t1", "overall_score": 99, "key_hygiene": 98, "policy_compliance": 100, "access_security": 100, "crypto_posture": 98, "pqc_readiness": 100, "framework_scores": {"eidas": 99, "fips-140-3": 99, "nist-800-57": 99, "pci-dss-4.0": 99}, "metrics": {"approved_algorithm_pct": 0, "cert_active": 0, "cert_ari_enabled": 0, "cert_due_soon_windows": 0, "cert_emergency_rotations": 0, "cert_expired": 0, "cert_expiring_30d": 0, "cert_mass_renewal_risks": 0, "cert_missed_windows": 0, "cert_pqc_class_pct": 0, "cert_revoked": 0, "cert_score": 100, "cert_star_delegated": 0, "cert_star_due_soon": 0, "cert_star_rollout_risks": 0, "cert_star_subscriptions": 0, "cert_total": 0, "cert_weak_algorithms": 0, "deprecated_count": 0, "failed_auth_rate_pct": 0, "mfa_adoption_pct": 0, "orphaned_count": 0, "policy_coverage_pct": 0, "policy_violation_count": 0}, "gap_count": 0, "created_at": "2026-10-12T10:44:21Z"}], "request_id": "req_82bf1d3fadd69e67"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "compliance-assessment-run",
    group: "Compliance",
    title: "Run Compliance Assessment",
    service: "compliance",
    method: "POST",
    pathTemplate: "/compliance/assessment/run",
    bodyTemplate: 
      "{}",
    description: "Triggers a compliance assessment against selected framework.",
    requestExample: "POST /svc/compliance/compliance/assessment/run",
    responseExample: {"assessment": {"id": "assess_09f7a63e06cddea4", "tenant_id": "t1", "trigger": "manual", "template_id": "default", "template_name": "Built-in Baseline", "overall_score": 99, "framework_scores": {"eidas": 99, "fips-140-3": 99, "nist-800-57": 99, "pci-dss-4.0": 99}, "findings": [], "pqc": {"ready_percent": 0, "ml_kem_migrated": 0, "ml_dsa_migrated": 0, "pending": 0, "total_evaluated": 0}, "cert_metrics": {"cert_score": 100}, "posture": {"id": "posture_72d5e55357c2ce2f", "tenant_id": "t1", "overall_score": 99, "key_hygiene": 98, "policy_compliance": 100, "access_security": 100, "crypto_posture": 98, "pqc_readiness": 100, "framework_scores": {"eidas": 99, "fips-140-3": 99, "nist-800-57": 99, "pci-dss-4.0": 99}, "metrics": {"approved_algorithm_pct": 0, "cert_active": 0, "cert_ari_enabled": 0, "cert_due_soon_windows": 0, "cert_emergency_rotations": 0, "cert_expired": 0, "cert_expiring_30d": 0, "cert_mass_renewal_risks": 0, "cert_missed_windows": 0, "cert_pqc_class_pct": 0, "cert_revoked": 0, "cert_score": 100, "cert_star_delegated": 0, "cert_star_due_soon": 0, "cert_star_rollout_risks": 0, "cert_star_subscriptions": 0, "cert_total": 0, "cert_weak_algorithms": 0, "deprecated_count": 0, "failed_auth_rate_pct": 0, "mfa_adoption_pct": 0, "orphaned_count": 0, "policy_coverage_pct": 0, "policy_violation_count": 0}, "gap_count": 0, "created_at": "2026-10-12T10:44:21Z"}, "created_at": "2026-10-12T10:44:21Z"}, "request_id": "req_d91b06815a0d8ec8"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [{"id": "pci-dss-4.0", "name": "PCI DSS", "version": "4.0", "description": "Payment card data security controls", "controls": [{}]}], "request_id": "req_6ef5baf9d34664a9"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"report": {"tenant_id": "t1", "total_keys": 0, "approved_algorithm_pct": 0, "rotation_coverage_pct": 0, "policy_coverage_pct": 0, "orphaned_count": 0, "expiring_count": 0, "deprecated_count": 0, "unused_90_days_count": 0, "pqc_ready_pct": 0, "algorithm_distribution": {}, "orphaned_keys": [], "expiring_keys": []}, "request_id": "req_b63b63c70fc8c418"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [], "request_id": "req_db50130ac1eb0fec"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"request_id": "req_026ee83429143c33", "summary": {"algorithm_distribution": {}, "deprecated_count": 0, "pqc_readiness_percent": 0, "pqc_ready_count": 0, "strength_histogram": {"128-255": 0, "256-3071": 0, "<128": 0, ">=3072": 0}, "total_assets": 0}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"request_id": "req_mRYpGuYv3lI", "settings": {"tenant_id": "root", "approval_expiry_minutes": 60, "expiry_check_interval_seconds": 5, "approval_delivery_mode": "notify", "smtp_connection_id": "", "smtp_host": "", "smtp_port": "", "smtp_username": "", "smtp_from": "", "smtp_starttls": false, "notify_dashboard": true, "notify_email": true, "notify_slack": false, "notify_teams": false, "slack_connection_id": "", "teams_connection_id": "", "delivery_webhook_timeout_seconds": 5, "challenge_response_enabled": false, "updated_by": "system", "updated_at": "2026-10-12T10:50:27Z"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "governance-settings-update",
    group: "Governance",
    title: "Update Governance Settings",
    service: "governance",
    method: "PUT",
    pathTemplate: "/governance/settings",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"approval_expiry_minutes\": 60,\n  \"notify_email\": true\n}",
    description: "Updates governance notification and delivery settings.",
    requestExample: "PUT /svc/governance/governance/settings",
    responseExample: {"request_id": "req_iZ3mq-EfAIE", "settings": {"tenant_id": "root", "approval_expiry_minutes": 60, "expiry_check_interval_seconds": 5, "approval_delivery_mode": "notify", "smtp_connection_id": "", "smtp_host": "", "smtp_port": "", "smtp_username": "", "smtp_from": "", "smtp_starttls": false, "notify_dashboard": true, "notify_email": true, "notify_slack": false, "notify_teams": false, "slack_connection_id": "", "teams_connection_id": "", "delivery_webhook_timeout_seconds": 5, "challenge_response_enabled": false, "updated_by": "system", "updated_at": "2026-10-12T10:50:27Z"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"request_id": "req_RvStLfLMUFI", "state": {"tenant_id": "root", "fips_mode": "enabled", "fips_mode_policy": "strict", "fips_crypto_library": "Go Cryptographic Module (go1.27.1, GOEXPERIMENT=none, CGO=1,...", "fips_library_validated": false, "fips_runtime_enabled": false, "fips_runtime_enforced": false, "fips_module_version": "latest", "fips_tls_profile": "tls13_minimum", "fips_rng_mode": "os_csprng", "fips_entropy_source": "os-csprng", "fips_entropy_health": "ok", "fips_entropy_sample_bytes": 4096, "fips_entropy_read_micros": 2, "fips_entropy_measured_at": "2026-10-12T10:50:27.864472Z", "snmp_target": "", "go_runtime_version": "go1.27.1", "flight_recorder_ready": true, "runtime_secret_ready": false, "posture_force_quorum_destructive_ops": false, "posture_require_step_up_auth": false, "posture_pause_connector_sync": false, "posture_guardrail_policy_required": false, "updated_by": "system"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "governance-system-state-update",
    group: "Governance",
    title: "Update System State",
    service: "governance",
    method: "PUT",
    pathTemplate: "/governance/system/state",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"fips_mode\": \"enabled\"\n}",
    description: "Updates system-level security and operational state.",
    requestExample: "PUT /svc/governance/governance/system/state",
    responseExample: {"request_id": "req_mo6RBjQiCTM", "state": {"tenant_id": "root", "fips_mode": "enabled", "fips_mode_policy": "strict", "fips_crypto_library": "Go Cryptographic Module (go1.27.1, GOEXPERIMENT=none, CGO=1,...", "fips_library_validated": false, "fips_runtime_enabled": false, "fips_runtime_enforced": false, "fips_module_version": "latest", "fips_tls_profile": "tls13_minimum", "fips_rng_mode": "os_csprng", "fips_entropy_source": "os-csprng", "fips_entropy_health": "ok", "fips_entropy_sample_bytes": 4096, "fips_entropy_read_micros": 3, "fips_entropy_measured_at": "2026-10-12T10:50:27.86388Z", "snmp_target": "", "go_runtime_version": "go1.27.1", "flight_recorder_ready": true, "runtime_secret_ready": false, "posture_force_quorum_destructive_ops": false, "posture_require_step_up_auth": false, "posture_pause_connector_sync": false, "posture_guardrail_policy_required": false, "updated_by": "system"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [{"id": "apol_jsaGd7mi3Dw", "tenant_id": "root", "name": "key-destroy-approval", "description": "", "scope": "key_operation", "trigger_actions": ["key.destroy"], "quorum_mode": "threshold", "required_approvals": 2, "total_approvers": 3, "approver_roles": ["admin"], "approver_users": null, "timeout_hours": 48, "escalation_hours": 0, "escalation_to": null, "retention_days": 90, "notification_channels": ["email"], "status": "active", "created_at": "2026-10-12T10:50:27Z"}], "request_id": "req_lmIfapWoQNg"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "governance-policies-create",
    group: "Governance",
    title: "Create Governance Policy",
    service: "governance",
    method: "POST",
    pathTemplate: "/governance/policies",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"name\": \"key-destroy-approval\",\n  \"scope\": \"key_operation\",\n  \"trigger_actions\": [\n    \"key.destroy\"\n  ],\n  \"required_approvals\": 2,\n  \"total_approvers\": 3,\n  \"approver_roles\": [\n    \"admin\",\n    \"security-officer\"\n  ]\n}",
    description: "Creates a governance approval policy.",
    requestExample: "POST /svc/governance/governance/policies",
    responseExample: {"policy": {"id": "apol_jsaGd7mi3Dw", "tenant_id": "root", "name": "key-destroy-approval", "description": "", "scope": "key_operation", "trigger_actions": ["key.destroy"], "quorum_mode": "threshold", "required_approvals": 2, "total_approvers": 3, "approver_roles": ["admin"], "approver_users": null, "timeout_hours": 48, "escalation_hours": 0, "escalation_to": null, "retention_days": 90, "notification_channels": ["email"], "status": "active", "created_at": "2026-10-12T10:50:27Z"}, "request_id": "req_EN_XAvWR-zw"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"vault_id\": \"{{vault_id}}\",\n  \"values\": [\n    \"4111111111111111\"\n  ]\n}",
    description: "Tokenizes sensitive data and returns a surrogate token with optional TTL.",
    requestExample: "POST /svc/dataprotect/tokenize",
    responseExample: {"items": [{"expires_at": "2027-10-12T10:48:02.674116Z", "input": "4111111111111111", "reused": false, "token": "<token>", "vault_id": "vault_454d00340849ca86"}], "request_id": "req_6180c7d9346b5901"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "dataprotect-detokenize",
    group: "Data Protection",
    title: "Detokenize",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/detokenize",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"tokens\": [\n    \"<token from tokenize>\"\n  ]\n}",
    description: "Resolves a token back to its original plaintext value.",
    requestExample: "POST /svc/dataprotect/detokenize",
    responseExample: {"items": [{"created_at": "2026-10-12T10:48:02Z", "expires_at": "2027-10-12T10:48:02.674116Z", "renew_count": 0, "token": "<token>", "use_count": 0, "use_limit": 0, "value": "4111111111111111", "vault_id": "vault_454d00340849ca86"}], "request_id": "req_2cd62cbf220abd52"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "dataprotect-tokenize-batch",
    group: "Data Protection",
    title: "Batch Tokenize",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/tokenize/batch",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"vault_id\": \"{{vault_id}}\",\n  \"values\": [\n    \"4111111111111111\",\n    \"5500005555555559\"\n  ]\n}",
    description: "Tokenizes multiple values in a single request.",
    requestExample: "POST /svc/dataprotect/tokenize/batch",
    responseExample: {"items": [{"input": "4111111111111111", "reused": true, "token": "<token>", "vault_id": "vault_454d00340849ca86"}], "request_id": "req_ca33208abc45b0b0"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "dataprotect-fpe-encrypt",
    group: "Data Protection",
    title: "FPE Encrypt",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/fpe/encrypt",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"key_id\": \"{{key_id}}\",\n  \"plaintext\": \"4111111111111111\",\n  \"tweak\": \"0000000000\"\n}",
    description: "Encrypts data using Format-Preserving Encryption (FF1/FF3-1), keeping output in the same format and length.",
    requestExample: "POST /svc/dataprotect/fpe/encrypt",
    responseExample: {"request_id": "req_487d4b3c697676bc", "result": {"ciphertext": "8584984204257152"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "dataprotect-fpe-decrypt",
    group: "Data Protection",
    title: "FPE Decrypt",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/fpe/decrypt",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"key_id\": \"{{key_id}}\",\n  \"ciphertext\": \"7293840185629374\",\n  \"tweak\": \"0000000000\"\n}",
    description: "Decrypts FPE-encrypted data back to the original plaintext.",
    requestExample: "POST /svc/dataprotect/fpe/decrypt",
    responseExample: {"request_id": "req_03b493daa8314483", "result": {"plaintext": "2972197281620566"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "dataprotect-mask",
    group: "Data Protection",
    title: "Mask Data",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/mask",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"policy_id\": \"{{policy_id}}\",\n  \"data\": {\n    \"card_number\": \"4111111111111111\"\n  },\n  \"role\": \"support\"\n}",
    description: "Applies a masking policy to partially obscure sensitive data.",
    requestExample: "POST /svc/dataprotect/mask",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "dataprotect-redact",
    group: "Data Protection",
    title: "Redact Data",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/redact",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"content\": \"Card 4111 1111 1111 1111, contact jane@example.com\",\n  \"content_type\": \"text/plain\"\n}",
    description: "Scans text for sensitive patterns and replaces matches with [REDACTED].",
    requestExample: "POST /svc/dataprotect/redact",
    responseExample: {"request_id": "req_cc833b9932168c29", "result": {"content": "Card 4111 1111 1111 1111, contact [REDACTED]", "matches": [{"end": 50, "label": "EMAIL", "match": "jane@example.com", "start": 34}]}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "dataprotect-envelope-encrypt",
    group: "Data Protection",
    title: "Envelope Encrypt",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/app/envelope-encrypt",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"key_id\": \"{{key_id}}\",\n  \"plaintext\": \"aGVsbG8tdmVjdGE=\"\n}",
    description: "Generates a DEK, encrypts plaintext locally, and wraps the DEK with the specified KEK.",
    requestExample: "POST /svc/dataprotect/app/envelope-encrypt",
    responseExample: {"request_id": "req_d67cc069e238e532", "result": {"algorithm": "AES-GCM", "ciphertext": "doKLVKxKvt9PCKf/nGrF3GgPNMxB/tu3KYpo66Gn0XE=", "dek_created_at": "2026-10-12T10:48:02Z", "iv": "H15exaH5RamALIBq", "wrapped_dek": "x/uEWNdtfJ6l63i9z3DE/4R5EvLv/EOeVvTZjYvquxTzJE9ped125WoCDUbffk1D", "wrapped_dek_iv": "HxNV/UhDPdnita9T"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "dataprotect-envelope-decrypt",
    group: "Data Protection",
    title: "Envelope Decrypt",
    service: "dataprotect",
    method: "POST",
    pathTemplate: "/app/envelope-decrypt",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"key_id\": \"{{key_id}}\",\n  \"ciphertext\": \"<ciphertext from envelope-encrypt>\",\n  \"iv\": \"<iv from envelope-encrypt>\",\n  \"wrapped_dek\": \"<wrapped_dek from envelope-encrypt>\",\n  \"wrapped_dek_iv\": \"<wrapped_dek_iv from envelope-encrypt>\"\n}",
    description: "Unwraps the DEK with the KEK and decrypts the ciphertext.",
    requestExample: "POST /svc/dataprotect/app/envelope-decrypt",
    responseExample: {"request_id": "req_7a81fea2649e5ce5", "result": {"plaintext": "aGVsbG8tdmVjdGE="}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [], "request_id": "req_0600da044e316809"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"request_id": "req_bc8ec112f4b329b2", "stats": {"bucket_seconds": 3600, "by_severity": {"critical": 0, "high": 0, "info": 0, "warning": 0}, "by_status": {}, "daily_trend": {}, "from": "2026-10-12T10:43:56.498128Z", "generated_at": "2026-10-12T10:43:56.498131Z", "series": [{"count": 0, "start": "2026-10-12T10:00:00Z"}], "to": "2026-10-12T10:43:56.498128Z", "top_actions": [], "total": 0}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"mttr_minutes": {}, "request_id": "req_5eb1e27eaacc003f"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"request_id": "req_4454b866fd703ab3", "sources": {"actors": [], "ips": [], "services": []}, "top_actors": [], "top_ips": [], "top_services": []},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [{"id": "rule_a88171850fa9affc", "tenant_id": "t1", "name": "High Failure Rate", "condition": "threshold", "severity": "high", "event_pattern": "", "threshold": 10, "window_seconds": 300, "channels": ["screen"], "enabled": true, "expression": "", "created_at": "2026-10-12T10:43:56Z", "updated_at": "2026-10-12T10:43:56Z"}], "request_id": "req_95fe85b12d3b6e5c"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "reporting-alert-rules-create",
    group: "Reporting",
    title: "Create Alert Rule",
    service: "reporting",
    method: "POST",
    pathTemplate: "/alerts/rules",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"name\": \"High Failure Rate\",\n  \"condition\": \"threshold\",\n  \"threshold\": 10,\n  \"window_seconds\": 300,\n  \"severity\": \"high\",\n  \"channels\": [\n    \"email\",\n    \"webhook\"\n  ]\n}",
    description: "Creates a new alert rule with condition, threshold, and notification channels.",
    requestExample: "POST /svc/reporting/alerts/rules",
    responseExample: {"item": {"id": "rule_a88171850fa9affc", "tenant_id": "t1", "name": "High Failure Rate", "condition": "threshold", "severity": "high", "event_pattern": "", "threshold": 10, "window_seconds": 300, "channels": ["screen"], "enabled": true, "expression": "", "created_at": "0001-01-01T00:00:00Z", "updated_at": "0001-01-01T00:00:00Z"}, "request_id": "req_1646b3ec21f392c2"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "reporting-alerts-bulk-ack",
    group: "Reporting",
    title: "Bulk Acknowledge Alerts",
    service: "reporting",
    method: "POST",
    pathTemplate: "/alerts/bulk/acknowledge",
    bodyTemplate: 
      "{\n  \"note\": \"Investigated \\u2014 false positive\"\n}",
    description: "Acknowledges multiple alerts in a single request with an optional investigation note.",
    requestExample: "POST /svc/reporting/alerts/bulk/acknowledge",
    responseExample: {"request_id": "req_a5121a9b9ffd4be3", "updated": 0},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [{"id": "rjob_79cbc86ee76a1e9c", "tenant_id": "t1", "template_id": "key-rotation-summary", "format": "pdf", "status": "completed", "filters": {"date_from": "2026-01-01", "date_to": "2026-12-31"}, "result_content": "JVBERi0xLjQKJeLjz9MKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFn...", "result_content_type": "application/pdf", "requested_by": "tester", "error": "", "created_at": "2026-10-12T10:43:56Z", "updated_at": "2026-10-12T10:43:56Z", "completed_at": "2026-10-12T10:43:56.498071Z"}], "request_id": "req_fcc8d1de1d9fe6f0"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [], "request_id": "req_9ff249f07633102a"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [], "request_id": "req_2e1ab88fdf227651"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"request_id": "req_dc2e533c7f2cb9b9", "risk": {"id": "", "tenant_id": "t1", "risk_24h": 0, "risk_7d": 0, "predictive_score": 0, "preventive_score": 0, "corrective_score": 0, "top_signals": null, "captured_at": "0001-01-01T00:00:00Z", "assessed": false, "baseline_days": 0}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [], "request_id": "req_b0b27dc4b93b3312"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"blast_radius": [], "critical_findings": 0, "open_findings": 0, "pending_actions": [], "recent_findings": [], "remediation_cockpit": [{"id": "approval-required", "label": "Approval Required", "description": "Actions that run only after a governance approval opened by the executor.", "count": 0, "actions": null}], "request_id": "req_d8f963c3d1b75d1c", "risk": {"id": "", "tenant_id": "t1", "risk_24h": 0, "risk_7d": 0, "predictive_score": 0, "preventive_score": 0, "corrective_score": 0, "top_signals": null, "captured_at": "0001-01-01T00:00:00Z", "assessed": false, "baseline_days": 0}, "risk_drivers": {"current_risk_24h": 0, "previous_risk_24h": 0, "net_delta": 0, "summary": "Risk is stable relative to the previous scan.", "drivers": []}, "scenario_simulator": [], "sla_overview": {"open_count": 0, "overdue_count": 0, "due_soon_count": 0, "average_age_hours": 0}, "validation_badges": [{"domain": "byok", "kind": "auth_freshness", "label": "BYOK auth freshness", "status": "unknown", "detail": "No successful connector auth seen recently.", "last_checked_at": "2026-10-12T10:43:37.478648Z", "last_success_at": "0001-01-01T00:00:00Z"}]},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [], "request_id": "req_782c6f77570abac2"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
      "{\n  \"tenant_id\": \"{{tenant_id}}\"\n}",
    description: "Initiates a cryptographic asset discovery scan across specified cloud providers.",
    requestExample: "POST /svc/discovery/discovery/scan",
    responseExample: {"request_id": "req_0195606aa31200c4", "scan": {"id": "scan_28690cc6009d95ef", "tenant_id": "t1", "scan_type": "network,cloud,certs,code,git,storage", "status": "running", "trigger": "manual", "stats": {"sources_done": []}, "started_at": "2026-10-12T10:43:50.902489Z", "completed_at": "0001-01-01T00:00:00Z", "created_at": "0001-01-01T00:00:00Z"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [{"id": "scan_28690cc6009d95ef", "tenant_id": "t1", "scan_type": "network,cloud,certs,code,git,storage", "status": "running", "trigger": "manual", "stats": {"sources_done": []}, "started_at": "2026-10-12T10:43:50.902489Z", "completed_at": "0001-01-01T00:00:00Z", "created_at": "2026-10-12T10:43:50Z"}], "request_id": "req_8c225bcc9d4f1016"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"items": [], "request_id": "req_6609c245ba708cf2", "total": 0},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
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
    responseExample: {"request_id": "req_f04e54ddc236e540", "summary": {"tenant_id": "t1", "total_assets": 1, "source_distribution": {"certs": 1}, "algorithm_distribution": {"RSA-3072": 1}, "classification_counts": {"exposed": 0, "quantum_vulnerable": 1, "strong": 0, "unknown": 0, "weak": 0}, "pqc_ready_count": 0, "pqc_readiness_percent": 0, "algorithm_classes": {"RSA-3072": {"quantum_vulnerable": 1}}, "source_classification": {"certs": {"quantum_vulnerable": 1}}, "expiring_30d": 0}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },

  // ── Disk Encryption ──

  // ── Network ──

  // ── EKM Agent ──
  {
    id: "ekm-agent-status",
    group: "EKM Agent",
    title: "Get Agent Status",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/agents/{{agent_id}}/status",
    bodyTemplate: "",
    description: "Returns full status, configuration, and last heartbeat data for a specific EKM agent.",
    requestExample: "GET /svc/ekm/ekm/agents/agent-mssql-01",
    responseExample: {"request_id": "req_f1bf07017842d616", "status": {"agent": {"id": "agent_ae2691882c162b91", "tenant_id": "t1", "name": "mssql-prod-03", "role": "ekm-agent", "db_engine": "mssql", "host": "10.0.0.15", "version": "SQL Server 2022", "status": "connected", "tde_state": "enabled", "heartbeat_interval_sec": 30, "last_heartbeat_at": "2026-10-12T10:52:42.154775Z", "assigned_key_id": "tde-key-001", "assigned_key_version": "v1", "config_version": 3, "config_version_ack": 0, "metadata_json": "{}", "tls_client_cn": "tester", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z"}, "managed_databases": 1, "tde_enabled_databases": 0, "last_heartbeat_age_sec": 0}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-agent-health",
    group: "EKM Agent",
    title: "Agent Health Check",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/agents/{{agent_id}}/health",
    bodyTemplate: "",
    description: "Returns real-time agent health: connectivity, TDE state, PKCS#11 readiness, OS metrics.",
    requestExample: "GET /svc/ekm/ekm/agents/agent-mssql-01/health",
    responseExample: {"health": {"agent": {"id": "agent_ae2691882c162b91", "tenant_id": "t1", "name": "mssql-prod-03", "role": "ekm-agent", "db_engine": "mssql", "host": "10.0.0.15", "version": "SQL Server 2022", "status": "connected", "tde_state": "enabled", "heartbeat_interval_sec": 30, "last_heartbeat_at": "2026-10-12T10:52:42.154775Z", "assigned_key_id": "tde-key-001", "assigned_key_version": "v1", "config_version": 3, "config_version_ack": 0, "metadata_json": "{}", "tls_client_cn": "tester", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z"}, "health": "unknown", "last_heartbeat_age_sec": 0, "metrics": {"hostname": "10.0.0.15", "os_name": "", "os_version": "", "kernel": "", "arch": "", "cpu_usage_pct": 0, "memory_usage_pct": 0, "disk_usage_pct": 0, "load_1": 0, "uptime_sec": 0, "agent_runtime_sec": 0}, "warnings": ["agent has not reported OS metrics"]}, "request_id": "req_e2e3133fb5695326"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-agent-logs",
    group: "EKM Agent",
    title: "Get Agent Logs",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/agents/{{agent_id}}/logs?limit={{limit}}",
    bodyTemplate: "",
    description: "Returns recent operation logs for an EKM agent, including heartbeats, rotations, and errors.",
    requestExample: "GET /svc/ekm/ekm/agents/agent-mssql-01/logs?limit=50",
    responseExample: {"items": [], "request_id": "req_2c7ea6888e11d098"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-agent-deploy",
    group: "EKM Agent",
    title: "Download Agent Package",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/agents/{{agent_id}}/deploy?tenant_id={{tenant_id}}&os=linux",
    bodyTemplate: "",
    description: "Downloads the agent deployment package (ZIP) pre-configured for this agent's settings.",
    requestExample: "GET /svc/ekm/ekm/agents/{{agent_id}}/deploy?tenant_id={{tenant_id}}&os=linux",
    responseExample: {"package": {"agent_id": "agent_ae2691882c162b91", "name": "mssql-prod-03", "db_engine": "mssql", "target_os": "linux", "created_at": "2026-10-12T10:52:42.155832Z", "heartbeat_path": "/ekm/agents/agent_ae2691882c162b91/heartbeat", "register_path": "/ekm/agents/register", "rotate_path": "/ekm/agents/agent_ae2691882c162b91/rotate", "supported_databases": ["mssql"], "recommended_profiles": [], "files": [{"path": "agent.env", "content": "TENANT_ID=t1\nAGENT_ID=agent_ae2691882c162b91\nAGENT_NAME=mssq...", "mode": "0600"}]}, "request_id": "req_42c8b5b2c08dfd4a"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-agent-rotate",
    group: "EKM Agent",
    title: "Rotate Agent TDE Key",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/agents/{{agent_id}}/rotate",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"reason\": \"scheduled_rotation\"\n}",
    description: "Triggers TDE key rotation for the agent's database. Creates a new key version and re-wraps the DEK.",
    requestExample: "POST /svc/ekm/ekm/agents/agent-mssql-01/rotate",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-agent-delete",
    group: "EKM Agent",
    title: "Delete Agent",
    service: "ekm",
    method: "DELETE",
    pathTemplate: "/ekm/agents/{{agent_id}}",
    bodyTemplate: "",
    description: "Removes an EKM agent registration. Database must have local key backup before removal.",
    requestExample: "DELETE /svc/ekm/ekm/agents/agent-mssql-01",
    responseExample: {"deleted": {"agent_id": "agent_ae2691882c162b91", "deleted_databases": 1, "deleted_keys": 1, "deleted_logs": 0, "deleted_key_ids": ["tde_key_3"]}, "request_id": "req_eebfa4adec265ac8"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-agent-heartbeat",
    group: "EKM Agent",
    title: "Agent Heartbeat",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/agents/{{agent_id}}/heartbeat",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "status": "connected",\n  "tde_state": "enabled",\n  "active_key_id": "tde-key-001",\n  "active_key_version": "v1",\n  "metadata_json": "{}"\n}',
    description: "Sends agent heartbeat with status, TDE state, OS metrics, and PKCS#11 health.",
    requestExample: "POST /svc/ekm/ekm/agents/agent-mssql-01/heartbeat",
    responseExample: {"agent": {"id": "agent_ae2691882c162b91", "tenant_id": "t1", "name": "mssql-prod-03", "role": "ekm-agent", "db_engine": "mssql", "host": "10.0.0.15", "version": "SQL Server 2022", "status": "connected", "tde_state": "enabled", "heartbeat_interval_sec": 30, "last_heartbeat_at": "2026-10-12T10:52:42.154775Z", "assigned_key_id": "tde-key-001", "assigned_key_version": "v1", "config_version": 3, "config_version_ack": 0, "metadata_json": "{}", "tls_client_cn": "tester", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z"}, "request_id": "req_4ca61bbcb5426d98"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },

  // ── BitLocker ──
  {
    id: "ekm-bitlocker-register",
    group: "BitLocker",
    title: "Register BitLocker Client",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/bitlocker/clients/register",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"name\": \"Desktop-Finance-01\",\n  \"host\": \"10.0.1.50\"\n}",
    description: "Registers a Windows machine for centralized BitLocker management.",
    requestExample: "POST /svc/ekm/ekm/bitlocker/clients/register",
    responseExample: {"client": {"id": "blc_6b6283d344090663", "tenant_id": "t1", "name": "Desktop-Finance-01", "host": "10.0.1.50", "os_version": "windows", "status": "connected", "health": "unknown", "protection_status": "unknown", "encryption_percentage": 0, "mount_point": "C:", "heartbeat_interval_sec": 30, "last_heartbeat_at": "2026-10-12T10:52:42.153512Z", "tpm_present": false, "tpm_ready": false, "jwt_subject": "tester", "tls_client_cn": "", "metadata_json": "{}", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z"}, "request_id": "req_60db85a8329abddc"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "ekm-bitlocker-list",
    group: "BitLocker",
    title: "List BitLocker Clients",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/bitlocker/clients?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists all registered BitLocker clients with encryption status and last heartbeat.",
    requestExample: "GET /svc/ekm/ekm/bitlocker/clients?tenant_id=root",
    responseExample: {"items": [{"id": "blc_6b6283d344090663", "tenant_id": "t1", "name": "Desktop-Finance-01", "host": "10.0.1.50", "os_version": "windows", "status": "connected", "health": "unknown", "protection_status": "unknown", "encryption_percentage": 0, "mount_point": "C:", "heartbeat_interval_sec": 30, "last_heartbeat_at": "2026-10-12T10:52:42.153512Z", "tpm_present": false, "tpm_ready": false, "jwt_subject": "tester", "tls_client_cn": "", "metadata_json": "{}", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z"}], "request_id": "req_f4388edb71c8631c"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "ekm-bitlocker-get",
    group: "BitLocker",
    title: "Get BitLocker Client",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/bitlocker/clients/{{client_id}}",
    bodyTemplate: "",
    description: "Returns detailed BitLocker client info: encryption status, protector, mount point, TPM state.",
    requestExample: "GET /svc/ekm/ekm/bitlocker/clients/bl-win-01",
    responseExample: {"client": {"id": "blc_6b6283d344090663", "tenant_id": "t1", "name": "Desktop-Finance-01", "host": "10.0.1.50", "os_version": "windows", "status": "connected", "health": "unknown", "protection_status": "unknown", "encryption_percentage": 0, "mount_point": "C:", "heartbeat_interval_sec": 30, "last_heartbeat_at": "2026-10-12T10:52:42.153512Z", "tpm_present": false, "tpm_ready": false, "jwt_subject": "tester", "tls_client_cn": "", "metadata_json": "{}", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z"}, "request_id": "req_8f833ea813c9fb95"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-bitlocker-delete-preview",
    group: "BitLocker",
    title: "Preview BitLocker Client Deletion",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/bitlocker/clients/{{client_id}}/delete-preview",
    bodyTemplate: "",
    description: "Shows impact of deleting a BitLocker client, including escrowed recovery keys that will be orphaned.",
    requestExample: "GET /svc/ekm/ekm/bitlocker/clients/bl-win-01/delete-preview",
    responseExample: {"preview": {"client_id": "blc_6b6283d344090663", "client_name": "Desktop-Finance-01", "host": "10.0.1.50", "latest_recovery_key": "", "latest_recovery_key_masked": "", "latest_recovery_at": "0001-01-01T00:00:00Z", "recovery_keys_available": 0}, "request_id": "req_6e1dec10eda80e89"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-bitlocker-delete",
    group: "BitLocker",
    title: "Delete BitLocker Client",
    service: "ekm",
    method: "DELETE",
    pathTemplate: "/ekm/bitlocker/clients/{{client_id}}",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"reason\": \"decommissioned\",\n  \"confirm_backup\": true\n}",
    description: "Removes a BitLocker client registration and optionally purges escrowed recovery keys.",
    requestExample: "DELETE /svc/ekm/ekm/bitlocker/clients/bl-win-01",
    responseExample: {"deleted": {"client_id": "blc_6b6283d344090663", "deleted_clients": 1, "deleted_jobs": 1, "deleted_recovery_keys": 0}, "request_id": "req_dca208e04dfcdc26"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-bitlocker-heartbeat",
    group: "BitLocker",
    title: "BitLocker Client Heartbeat",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/bitlocker/clients/{{client_id}}/heartbeat",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "status": "connected",\n  "protection_status": "On",\n  "encryption_percentage": 100\n}',
    description: "Sends heartbeat from BitLocker agent with current encryption status and OS metrics.",
    requestExample: "POST /svc/ekm/ekm/bitlocker/clients/bl-win-01/heartbeat",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-bitlocker-operations",
    group: "BitLocker",
    title: "Execute BitLocker Operation",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/bitlocker/clients/{{client_id}}/operations",
    bodyTemplate: 
      "{\n  \"operation\": \"enable\"\n}",
    description: "Queues a BitLocker operation (enable, disable, suspend, resume, rotate_recovery, status, tpm_status).",
    requestExample: "POST /svc/ekm/ekm/bitlocker/clients/bl-win-01/operations",
    responseExample: {"job": {"id": "bljob_806fb88aeb05dacc", "tenant_id": "t1", "client_id": "blc_6b6283d344090663", "operation": "enable", "params_json": "{}", "status": "pending", "requested_by": "dashboard", "request_id": "blop_51982c9a6a72e28d", "requested_at": "2026-10-12T10:52:42.155374Z", "dispatched_at": "0001-01-01T00:00:00Z", "completed_at": "0001-01-01T00:00:00Z", "result_json": "{}", "error_message": "", "recovery_key_ref": ""}, "request_id": "req_a3c0ef96393818ca"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-bitlocker-jobs-next",
    group: "BitLocker",
    title: "Poll Next BitLocker Job",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/bitlocker/clients/{{client_id}}/jobs/next",
    bodyTemplate: "",
    description: "Agent polls for the next pending job. Returns empty if no jobs are queued.",
    requestExample: "POST /svc/ekm/ekm/bitlocker/clients/bl-win-01/jobs/next",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-bitlocker-job-result",
    group: "BitLocker",
    title: "Submit Job Result",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/bitlocker/clients/{{client_id}}/jobs/{{job_id}}/result",
    bodyTemplate: 
      "{\n  \"status\": \"completed\",\n  \"result\": {\n    \"message\": \"BitLocker enabled\"\n  }\n}",
    description: "Agent submits the result of a completed BitLocker job.",
    requestExample: "POST /svc/ekm/ekm/bitlocker/clients/bl-win-01/jobs/job-abc123/result",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-bitlocker-recovery",
    group: "BitLocker",
    title: "Get Recovery Keys",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/bitlocker/recovery?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists escrowed BitLocker recovery keys. Supports filtering by client ID.",
    requestExample: "GET /svc/ekm/ekm/bitlocker/recovery?tenant_id=root",
    responseExample: {"items": [], "request_id": "req_1167f642c375e598"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "ekm-bitlocker-network-scan",
    group: "BitLocker",
    title: "Network Scan for BitLocker",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/bitlocker/network/scan",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"ip_range\": \"10.0.1.0/28\"\n}",
    description: "Scans a subnet for Windows endpoints that support BitLocker, returning discovered devices.",
    requestExample: "POST /svc/ekm/ekm/bitlocker/network/scan",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "ekm-bitlocker-deploy",
    group: "BitLocker",
    title: "Download BitLocker Agent",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/bitlocker/clients/{{client_id}}/deploy?tenant_id={{tenant_id}}&os=windows",
    bodyTemplate: "",
    description: "Downloads the BitLocker agent installer package pre-configured for this client.",
    requestExample: "GET /svc/ekm/ekm/bitlocker/clients/{{client_id}}/deploy?tenant_id={{tenant_id}}&os=windows",
    responseExample: {"package": {"agent_id": "blc_6b6283d344090663", "name": "Desktop-Finance-01", "db_engine": "bitlocker", "target_os": "windows", "created_at": "2026-10-12T10:52:42.15659Z", "heartbeat_path": "/ekm/bitlocker/clients/blc_6b6283d344090663/heartbeat", "register_path": "/ekm/bitlocker/clients/register", "rotate_path": "/ekm/bitlocker/clients/blc_6b6283d344090663/operations", "supported_databases": ["bitlocker"], "recommended_profiles": ["windows-bitlocker-agent"], "files": [{"path": "agent-config.json", "content": "{\n  \"agent_id\": \"blc_6b6283d344090663\",\n  \"agent_mode\": \"bit...", "mode": "0600"}]}, "request_id": "req_532ee2da4168ad75"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },

  // ── TDE Keys ──
  {
    id: "ekm-tde-create",
    group: "TDE Keys",
    title: "Create TDE Key",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/tde/keys",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "name": "mssql-prod-tde",\n  "algorithm": "RSA-3072"\n}',
    description: "Creates a new TDE encryption key for database transparent data encryption.",
    requestExample: "POST /svc/ekm/ekm/tde/keys",
    responseExample: {"key": {"id": "tde_key_2", "tenant_id": "t1", "keycore_key_id": "tde_key_2", "name": "mssql-prod-tde", "algorithm": "RSA-3072", "status": "active", "current_version": "v1", "public_key": "<public key>", "public_key_format": "pem", "created_by": "ekm", "auto_provisioned": false, "metadata_json": "{}", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z", "rotated_at": "0001-01-01T00:00:00Z", "last_accessed_at": "0001-01-01T00:00:00Z"}, "request_id": "req_e6ac1e8be8a4939a"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "ekm-tde-wrap",
    group: "TDE Keys",
    title: "Wrap (Encrypt) with TDE Key",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/tde/keys/{{key_id}}/wrap",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"plaintext\": \"aGVsbG8tdmVjdGE=\"\n}",
    description: "Wraps (encrypts) data using a TDE key. Used by agents to encrypt DEKs.",
    requestExample: "POST /svc/ekm/ekm/tde/keys/tde-key-001/wrap",
    responseExample: {"request_id": "req_6372b7a1fe1b3d74", "result": {"key_id": "tde_key_2", "version": 1, "ciphertext": "d3JhcDphR1ZzYkc4dGRtVmpkR0U9", "iv": "ZmFrZS1la20taXYtMDE="}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-tde-unwrap",
    group: "TDE Keys",
    title: "Unwrap (Decrypt) with TDE Key",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/tde/keys/{{key_id}}/unwrap",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"ciphertext\": \"<ciphertext from wrap>\",\n  \"iv\": \"<iv from wrap>\"\n}",
    description: "Unwraps (decrypts) data using a TDE key. Used by agents to decrypt DEKs.",
    requestExample: "POST /svc/ekm/ekm/tde/keys/tde-key-001/unwrap",
    responseExample: {"request_id": "req_f1614f9a40053510", "result": {"key_id": "tde_key_2", "version": 2, "plaintext": "aGVsbG8tdmVjdGE="}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-tde-rotate",
    group: "TDE Keys",
    title: "Rotate TDE Key",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/tde/keys/{{key_id}}/rotate",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "reason": "compliance_rotation"\n}',
    description: "Rotates a TDE key to a new version. Old versions remain available for unwrap/decrypt.",
    requestExample: "POST /svc/ekm/ekm/tde/keys/tde-key-001/rotate",
    responseExample: {"request_id": "req_7b541ac956b384d7", "rotation": {"key_id": "tde_key_2", "version_id": "v2", "affected_agent_ids": []}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "ekm-tde-public",
    group: "TDE Keys",
    title: "Get TDE Key Public Info",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/tde/keys/{{key_id}}/public",
    bodyTemplate: "",
    description: "Returns the public key keycore holds for a TDE key (pem or opaque). TDE key material never leaves the KMS; 424 public_key_unavailable when keycore holds none.",
    requestExample: "GET /svc/ekm/ekm/tde/keys/tde-key-001/public",
    responseExample: {"public_key": {"key_id": "tde_key_2", "algorithm": "RSA-3072", "public_key": "<public key>", "format": "pem", "key_version": "v2"}, "request_id": "req_1e604b816c990c60"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },

  // ── EKM Database ──
  {
    id: "ekm-db-register",
    group: "EKM Database",
    title: "Register EKM Database",
    service: "ekm",
    method: "POST",
    pathTemplate: "/ekm/databases",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"agent_id\": \"{{agent_id}}\",\n  \"name\": \"MSSQL-Prod\",\n  \"engine\": \"mssql\",\n  \"host\": \"10.0.0.15\",\n  \"port\": 1433,\n  \"database_name\": \"orders\"\n}",
    description: "Registers a database instance for EKM key management and TDE monitoring.",
    requestExample: "POST /svc/ekm/ekm/databases",
    responseExample: {"auto_provisioned_key": {"id": "tde_key_3", "tenant_id": "t1", "keycore_key_id": "tde_key_3", "name": "tde-db-db_396b95fa1bf44d10", "algorithm": "RSA-3072", "status": "active", "current_version": "v1", "public_key": "<public key>", "public_key_format": "pem", "created_by": "ekm-auto-database", "auto_provisioned": true, "metadata_json": "{}", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z", "rotated_at": "0001-01-01T00:00:00Z", "last_accessed_at": "0001-01-01T00:00:00Z"}, "database": {"id": "db_396b95fa1bf44d10", "tenant_id": "t1", "agent_id": "agent_ae2691882c162b91", "name": "MSSQL-Prod", "engine": "mssql", "host": "10.0.0.15", "port": 1433, "database_name": "orders", "status": "", "tde_enabled": false, "tde_state": "disabled", "key_id": "tde_key_3", "auto_provisioned": true, "metadata_json": "{}", "last_seen_at": "2026-10-12T10:52:42.15436Z", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z"}, "request_id": "req_0282a2032da8805a"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "ekm-db-list",
    group: "EKM Database",
    title: "List EKM Databases",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/databases?tenant_id={{tenant_id}}",
    bodyTemplate: "",
    description: "Lists all registered databases with their TDE encryption status.",
    requestExample: "GET /svc/ekm/ekm/databases?tenant_id=root",
    responseExample: {"items": [{"id": "db_396b95fa1bf44d10", "tenant_id": "t1", "agent_id": "agent_ae2691882c162b91", "name": "MSSQL-Prod", "engine": "mssql", "host": "10.0.0.15", "port": 1433, "database_name": "orders", "status": "", "tde_enabled": false, "tde_state": "disabled", "key_id": "tde_key_3", "auto_provisioned": true, "metadata_json": "{}", "last_seen_at": "2026-10-12T10:52:42.15436Z", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z"}], "request_id": "req_e834f2aae8fe9b8e"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "ekm-db-get",
    group: "EKM Database",
    title: "Get EKM Database",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/databases/{{database_id}}",
    bodyTemplate: "",
    description: "Returns detailed info for a registered database: TDE state, assigned agent, key mapping.",
    requestExample: "GET /svc/ekm/ekm/databases/db-001",
    responseExample: {"database": {"id": "db_396b95fa1bf44d10", "tenant_id": "t1", "agent_id": "agent_ae2691882c162b91", "name": "MSSQL-Prod", "engine": "mssql", "host": "10.0.0.15", "port": 1433, "database_name": "orders", "status": "", "tde_enabled": false, "tde_state": "disabled", "key_id": "tde_key_3", "auto_provisioned": true, "metadata_json": "{}", "last_seen_at": "2026-10-12T10:52:42.15436Z", "created_at": "2026-10-12T10:52:42Z", "updated_at": "2026-10-12T10:52:42Z"}, "request_id": "req_1180e89658f3e773"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },

  // ── EKM SDK ──
  {
    id: "ekm-sdk-overview",
    group: "EKM SDK",
    title: "SDK Overview",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/sdk/overview",
    bodyTemplate: "",
    description: "Lists the client SDK Vecta ships: the Java JCA provider (source), with the services it registers. No PKCS#11 module is shipped and no usage telemetry is reported.",
    requestExample: "GET /svc/ekm/ekm/sdk/overview?tenant_id={{tenant_id}}",
    responseExample: {"overview": {"refreshed_at": "2026-10-12T10:52:42.157955Z", "providers": [{"id": "jca", "name": "Java JCA/JCE Provider", "artifact_name": "vecta-jca-sdk-all.zip", "version": "source", "status": "available", "size_label": "13 KB", "transport": "HTTPS (TLS 1.3), bearer token", "sessions_active": 0, "ops_24h": 0, "clients_connected": 0, "top_mechanism": "", "platforms": [], "capabilities": []}], "mechanisms": [], "clients": []}, "request_id": "req_c298e83258ee56d6"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "ekm-sdk-download",
    group: "EKM SDK",
    title: "Download SDK Package",
    service: "ekm",
    method: "GET",
    pathTemplate: "/ekm/sdk/download?tenant_id={{tenant_id}}&provider=jca&os=all",
    bodyTemplate: "",
    description: "Downloads the Java JCA provider source as a zip (base64 in the JSON response). provider=pkcs11 is refused: no PKCS#11 module exists.",
    requestExample: "GET /svc/ekm/ekm/sdk/download?tenant_id={{tenant_id}}&provider=jca&os=all",
    responseExample: {"artifact": {"provider": "jca", "target_os": "all", "filename": "vecta-jca-sdk-all.zip", "content_type": "application/zip", "encoding": "base64", "content": "UEsDBBQACAAIAAAAAAAAAAAAAAAAAAAAAAAuAAAAdmVjdGEtamNhLXByb3Zp...", "size_bytes": 13116, "sha256": "981b7653467fd4707d0984b97c6675376bdb2695334273f1d46a3086cb931c3d"}, "request_id": "req_01e4d7476654d146"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },

  /* ── Vault Hierarchy (OpenBao-compatible) ── */

  /* ── HSM Certificate Operations ── */
  {
    id: "hsm-create-ca",
    group: "HSM Certificates",
    title: "Create HSM-Backed CA",
    service: "certs",
    method: "POST",
    pathTemplate: "/certs/ca",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"name\": \"hsm-root-ca\",\n  \"ca_level\": \"root\",\n  \"algorithm\": \"ECDSA-P384\",\n  \"key_backend\": \"hsm\",\n  \"subject\": \"CN=Example HSM Root CA\"\n}",
    description: "Creates a certificate authority with its signing key stored in the HSM. All signing operations are delegated to the HSM via PKCS#11.",
    requestExample: 'POST /svc/certs/ca\n{"name":"Prod Root CA","algorithm":"ECDSA-P384","key_backend":"hsm","key_ref":"hsm-key-001","subject":"CN=Prod Root CA,O=Acme"}',
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },

  /* ── Examples that were kept in the catalogue generator until 13.1.0-beta ── */
  {
    id: "auth-post-auth-client-token",
    group: "Identity & Access (auth)",
    title: "Issue REST Client Token",
    service: "auth",
    method: "POST",
    pathTemplate: "/auth/client-token?tenant_id={{tenant_id}}",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"client_id\": \"reg_123\"\n}",
    description: "Issues a tenant-scoped client access token. Depending on the registered client auth mode, the request must also carry a validated mTLS binding, DPoP proof, or HTTP Message Signature.",
    requestExample: "POST /svc/auth/auth/client-token?tenant_id={{tenant_id}}",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "auth-get-auth-clients",
    group: "Identity & Access (auth)",
    title: "List Client Registrations",
    service: "auth",
    method: "GET",
    pathTemplate: "/auth/clients?tenant_id={{tenant_id}}",
    bodyTemplate:
      "",
    description: "Lists registered clients with sender-constrained auth mode, replay protection state, and verification counters.",
    requestExample: "GET /svc/auth/auth/clients?tenant_id={{tenant_id}}",
    responseExample: {"items": null, "request_id": "req_f9757a8af9565986"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "auth-put-auth-clients-id",
    group: "Identity & Access (auth)",
    title: "Update Client Registration Security",
    service: "auth",
    method: "PUT",
    pathTemplate: "/auth/clients/{{id}}?tenant_id={{tenant_id}}",
    bodyTemplate:
      "{\n  \"ip_whitelist\": [\"10.10.10.0/24\"],\n  \"rate_limit\": 1500,\n  \"auth_mode\": \"http_message_signature\",\n  \"replay_protection_enabled\": true,\n  \"http_signature_key_id\": \"sdk-signing-key-01\",\n  \"http_signature_public_key_pem\": \"-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\",\n  \"http_signature_algorithm\": \"ed25519\"\n}",
    description: "Updates the client allowlist, rate limit, auth mode, and sender-constrained request binding. This is where operators move REST clients from legacy bearer mode to OAuth mTLS, DPoP, or HTTP Message Signatures.",
    requestExample: "PUT /svc/auth/auth/clients/{{id}}?tenant_id={{tenant_id}}",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "auth-get-auth-rest-client-security-summary",
    group: "Identity & Access (auth)",
    title: "Get REST Client Security Summary",
    service: "auth",
    method: "GET",
    pathTemplate: "/auth/rest-client-security/summary?tenant_id={{tenant_id}}",
    bodyTemplate:
      "",
    description: "Returns sender-constrained auth posture for tenant REST clients, including replay protection coverage, signature failures, unsigned request blocks, and non-compliant legacy clients.",
    requestExample: "GET /svc/auth/auth/rest-client-security/summary?tenant_id={{tenant_id}}",
    responseExample: {"request_id": "req_f84752c4fbf77370", "summary": {"tenant_id": "t1", "total_clients": 0, "sender_constrained_clients": 0, "oauth_mtls_clients": 0, "dpop_clients": 0, "http_message_signature_clients": 0, "replay_protected_clients": 0, "verified_requests": 0, "replay_violations": 0, "signature_failures": 0, "unsigned_rejects": 0, "non_compliant_clients": 0, "last_violation_at": "0001-01-01T00:00:00Z"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "sbom-post-sbom-generate",
    group: "SBOM / CBOM (sbom)",
    title: "Generate SBOM Snapshot",
    service: "sbom",
    method: "POST",
    pathTemplate: "/sbom/generate?tenant_id={{tenant_id}}",
    bodyTemplate:
      "{\n  \"trigger\": \"manual\"\n}",
    description: "Builds a fresh software BOM snapshot from the local workspace. The snapshot is used by the history, diff and export endpoints.",
    requestExample: "POST /svc/sbom/sbom/generate?tenant_id={{tenant_id}}",
    responseExample: {"request_id": "req_c728d40c38a76fcd", "snapshot": {"id": "sbom_608d8c409c528649", "source_hash": "928da6df71c794dcfbda176c2ebee103beee9db17471eb95c72491cde286f291", "created_at": "2026-10-12T10:49:32Z", "document": {"format": "cyclonedx", "spec_version": "1.6", "generated_at": "2026-10-12T10:49:32.631386Z", "appliance": "vecta-kms", "components": [{}]}, "summary": {"appliance": "vecta-kms", "component_count": 4, "format": "cyclonedx", "generated_at": "2026-10-12T10:49:32.631386Z", "spec_version": "1.6", "type_count": {"infrastructure": 3, "runtime": 1}}}, "status": "accepted"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "confidential-get-confidential-policy",
    group: "Confidential Compute (confidential)",
    title: "Get Attestation Policy",
    service: "confidential",
    method: "GET",
    pathTemplate: "/confidential/policy?tenant_id={{tenant_id}}",
    bodyTemplate:
      "",
    description: "Returns the tenant-scoped attested key release policy used by the Confidential Compute service.",
    requestExample: "GET /svc/confidential/confidential/policy?tenant_id={{tenant_id}}",
    responseExample: {"policy": {"tenant_id": "t1", "enabled": true, "provider": "aws_nitro_enclaves", "mode": "enforce", "key_scopes": ["payments-prod"], "approved_images": ["123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/authorizer:v1.4.2"], "approved_subjects": ["spiffe://root/workloads/payments-authorizer"], "allowed_attesters": ["aws.nitro-enclaves"], "required_measurements": {"pcr0": "baseline-image-hash", "pcr8": "secure-boot-chain-hash"}, "required_claims": {"environment": "prod", "team": "payments"}, "require_secure_boot": true, "require_debug_disabled": true, "max_evidence_age_sec": 300, "cluster_scope": "node_allowlist", "allowed_cluster_nodes": ["vecta-kms-01"], "fallback_action": "deny", "updated_by": "tester", "updated_at": "0001-01-01T00:00:00Z"}, "request_id": "req_bfbb17966a21f5f7"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "confidential-put-confidential-policy",
    group: "Confidential Compute (confidential)",
    title: "Update Attestation Policy",
    service: "confidential",
    method: "PUT",
    pathTemplate: "/confidential/policy?tenant_id={{tenant_id}}",
    bodyTemplate:
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"enabled\": true,\n  \"provider\": \"aws_nitro_enclaves\",\n  \"mode\": \"enforce\",\n  \"key_scopes\": [\"payments-prod\"],\n  \"approved_images\": [\"123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/authorizer:v1.4.2\"],\n  \"approved_subjects\": [\"spiffe://root/workloads/payments-authorizer\"],\n  \"allowed_attesters\": [\"aws.nitro-enclaves\"],\n  \"required_measurements\": { \"pcr0\": \"baseline-image-hash\", \"pcr8\": \"secure-boot-chain-hash\" },\n  \"required_claims\": { \"environment\": \"prod\", \"team\": \"payments\" },\n  \"require_secure_boot\": true,\n  \"require_debug_disabled\": true,\n  \"max_evidence_age_sec\": 300,\n  \"cluster_scope\": \"node_allowlist\",\n  \"allowed_cluster_nodes\": [\"vecta-kms-01\"],\n  \"fallback_action\": \"deny\"\n}",
    description: "Creates or updates the tenant attestation policy for attested key release.",
    requestExample: "PUT /svc/confidential/confidential/policy?tenant_id={{tenant_id}}",
    responseExample: {"policy": {"tenant_id": "t1", "enabled": true, "provider": "aws_nitro_enclaves", "mode": "enforce", "key_scopes": ["payments-prod"], "approved_images": ["123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/authorizer:v1.4.2"], "approved_subjects": ["spiffe://root/workloads/payments-authorizer"], "allowed_attesters": ["aws.nitro-enclaves"], "required_measurements": {"pcr0": "baseline-image-hash", "pcr8": "secure-boot-chain-hash"}, "required_claims": {"environment": "prod", "team": "payments"}, "require_secure_boot": true, "require_debug_disabled": true, "max_evidence_age_sec": 300, "cluster_scope": "node_allowlist", "allowed_cluster_nodes": ["vecta-kms-01"], "fallback_action": "deny", "updated_by": "tester", "updated_at": "0001-01-01T00:00:00Z"}, "request_id": "req_7e140e04e1de31ba"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "confidential-get-confidential-summary",
    group: "Confidential Compute (confidential)",
    title: "Get Confidential Compute Summary",
    service: "confidential",
    method: "GET",
    pathTemplate: "/confidential/summary?tenant_id={{tenant_id}}",
    bodyTemplate:
      "",
    description: "Returns summary metrics for the tenant attested release program, including recent release decisions and cluster node spread.",
    requestExample: "GET /svc/confidential/confidential/summary?tenant_id={{tenant_id}}",
    responseExample: {"request_id": "req_c42d5a1067b40916", "summary": {"tenant_id": "t1", "policy_enabled": true, "provider": "aws_nitro_enclaves", "approved_image_count": 1, "key_scope_count": 1, "release_count_24h": 0, "deny_count_24h": 0, "review_count_24h": 0, "cryptographically_verified_count_24h": 0, "unique_cluster_nodes": 0, "last_decision_at": "0001-01-01T00:00:00Z"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "confidential-post-confidential-evaluate",
    group: "Confidential Compute (confidential)",
    title: "Evaluate Attested Key Release",
    service: "confidential",
    method: "POST",
    pathTemplate: "/confidential/evaluate?tenant_id={{tenant_id}}",
    bodyTemplate:
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"key_id\": \"key-prod-root\",\n  \"key_scope\": \"payments-prod\",\n  \"provider\": \"aws_nitro_enclaves\",\n  \"attestation_format\": \"cose_sign1\",\n  \"attestation_document\": \"{{base64_cose_sign1_attestation_document}}\",\n  \"audience\": \"kms-key-release\",\n  \"nonce\": \"nonce-demo-001\",\n  \"cluster_node_id\": \"vecta-kms-01\",\n  \"requester\": \"platform-ops\",\n  \"release_reason\": \"authorize payment enclave\",\n  \"dry_run\": true\n}",
    description: "Cryptographically verifies an AWS, Azure, or GCP attestation document, derives signed claims and measurements, and then evaluates the result against the tenant attested-release policy.",
    requestExample: "POST /svc/confidential/confidential/evaluate?tenant_id={{tenant_id}}",
    responseExample: {"request_id": "req_0604041aace4cc29", "result": {"release_id": "rel_0120b68ef5f3808f", "decision": "deny", "allowed": false, "reasons": ["failed to parse AWS attestation document"], "matched_claims": [], "matched_measurements": [], "missing_claims": [], "missing_measurements": [], "missing_attributes": ["cryptographic_verification"], "measurement_hash": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "claims_hash": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "policy_version": "63dc51d0a99a9d84e97bad1b80cf6b47c39027a07feb3f2859dca505c73e8791", "provider": "aws_nitro_enclaves", "cluster_node_id": "vecta-kms-01", "cryptographically_verified": false, "verification_mode": "aws_cose_sign1_x509", "verification_issuer": "", "verification_key_id": "", "attestation_document_hash": "724d093b5c0d0793334d76b82ce8d9af6c0dd0f174c7752237b59b88a446eddf", "attestation_document_format": "cose_sign1", "expires_at": "0001-01-01T00:00:00Z", "evaluated_at": "2026-10-12T10:43:40.339103Z", "policy": {"tenant_id": "t1", "enabled": false, "provider": "aws_nitro_enclaves", "mode": "enforce", "key_scopes": [], "approved_images": [], "approved_subjects": [], "allowed_attesters": [], "required_measurements": {}, "required_claims": {}, "require_secure_boot": true, "require_debug_disabled": true, "max_evidence_age_sec": 300, "cluster_scope": "cluster_wide", "allowed_cluster_nodes": [], "fallback_action": "deny", "updated_at": "0001-01-01T00:00:00Z"}, "released": false}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "confidential-get-confidential-releases",
    group: "Confidential Compute (confidential)",
    title: "List Attested Release History",
    service: "confidential",
    method: "GET",
    pathTemplate: "/confidential/releases?tenant_id={{tenant_id}}",
    bodyTemplate:
      "",
    description: "Lists stored attested release decisions for the tenant.",
    requestExample: "GET /svc/confidential/confidential/releases?tenant_id={{tenant_id}}",
    responseExample: {"items": null, "request_id": "req_bd35b508d8aa6892"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "confidential-get-confidential-releases-id",
    group: "Confidential Compute (confidential)",
    title: "Get Attested Release Record",
    service: "confidential",
    method: "GET",
    pathTemplate: "/confidential/releases/{{id}}?tenant_id={{tenant_id}}",
    bodyTemplate:
      "",
    description: "Returns a single stored attested release record for the tenant.",
    requestExample: "GET /svc/confidential/confidential/releases/{{id}}?tenant_id={{tenant_id}}",
    responseExample: {"item": {"id": "", "tenant_id": "", "key_id": "", "key_scope": "", "provider": "", "workload_identity": "", "attester": "", "image_ref": "", "image_digest": "", "audience": "", "evidence_issued_at": "0001-01-01T00:00:00Z", "secure_boot": false, "debug_disabled": false, "cluster_node_id": "", "requester": "", "release_reason": "", "decision": "", "allowed": false, "reasons": null, "matched_claims": null, "matched_measurements": null, "missing_claims": null, "missing_measurements": null, "missing_attributes": null}, "request_id": "req_de305c2adc75a800"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" },
      { code: 404, meaning: "Not found, or not visible to the caller" }
    ],
  },
  {
    id: "workload-get-workload-identity-settings",
    group: "Workload Identity (workload)",
    title: "Get Workload Identity Settings",
    service: "workload",
    method: "GET",
    pathTemplate: "/workload-identity/settings?tenant_id={{tenant_id}}",
    bodyTemplate:
      "",
    description: "Returns the tenant SPIFFE trust-domain settings, issuance defaults, federation mode, and token-exchange controls.",
    requestExample: "GET /svc/workload/workload-identity/settings?tenant_id={{tenant_id}}",
    responseExample: {"request_id": "req_8813f421cd5387d4", "settings": {"tenant_id": "root", "enabled": true, "trust_domain": "root", "federation_enabled": true, "token_exchange_enabled": true, "default_x509_ttl_seconds": 43200, "default_jwt_ttl_seconds": 1800, "rotation_window_seconds": 900, "allowed_audiences": ["kms"], "local_bundle_jwks": "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"5fa586363e126afc\",...", "local_ca_certificate_pem": "<certificate>", "jwt_signer_key_id": "<jwt signer key id>", "updated_by": "tester", "updated_at": "0001-01-01T00:00:00Z"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "workload-put-workload-identity-settings",
    group: "Workload Identity (workload)",
    title: "Update Workload Identity Settings",
    service: "workload",
    method: "PUT",
    pathTemplate: "/workload-identity/settings?tenant_id={{tenant_id}}",
    bodyTemplate:
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"enabled\": true,\n  \"trust_domain\": \"root\",\n  \"federation_enabled\": true,\n  \"token_exchange_enabled\": true,\n  \"default_x509_ttl_seconds\": 43200,\n  \"default_jwt_ttl_seconds\": 1800,\n  \"rotation_window_seconds\": 1800,\n  \"allowed_audiences\": [\"kms\", \"kms-workload\", \"kms-rest\"]\n}",
    description: "Creates or updates the tenant workload-identity policy: the SPIFFE trust domain, whether federated trust domains and token exchange are accepted, SVID lifetimes and the JWT-SVID audiences accepted for exchange. Needs workload.write.",
    requestExample: "PUT /svc/workload/workload-identity/settings?tenant_id={{tenant_id}}",
    responseExample: {"request_id": "req_74c85d06f0423bd8", "settings": {"tenant_id": "root", "enabled": true, "trust_domain": "root", "federation_enabled": true, "token_exchange_enabled": true, "default_x509_ttl_seconds": 43200, "default_jwt_ttl_seconds": 1800, "rotation_window_seconds": 900, "allowed_audiences": ["kms"], "local_bundle_jwks": "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"5fa586363e126afc\",...", "local_ca_certificate_pem": "<certificate>", "jwt_signer_key_id": "<jwt signer key id>", "updated_by": "tester", "updated_at": "0001-01-01T00:00:00Z"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "workload-get-workload-identity-summary",
    group: "Workload Identity (workload)",
    title: "Get Workload Identity Summary",
    service: "workload",
    method: "GET",
    pathTemplate: "/workload-identity/summary?tenant_id={{tenant_id}}",
    bodyTemplate:
      "",
    description: "Returns health and drift counters for workload identity, including expiring or expired SVIDs, over-privileged registrations, token exchange activity, and key usage.",
    requestExample: "GET /svc/workload/workload-identity/summary?tenant_id={{tenant_id}}",
    responseExample: {"request_id": "req_1208a142baa4a5e6", "summary": {"tenant_id": "root", "enabled": true, "trust_domain": "root", "federation_enabled": true, "token_exchange_enabled": true, "registration_count": 1, "enabled_registration_count": 1, "federated_trust_domain_count": 0, "issuance_count_24h": 3, "token_exchange_count_24h": 0, "key_usage_count_24h": 0, "unique_workloads_using_keys_24h": 0, "unique_keys_used_24h": 0, "expiring_svid_count": 0, "expired_svid_count": 0, "over_privileged_count": 0, "last_exchange_at": "0001-01-01T00:00:00Z", "last_key_use_at": "0001-01-01T00:00:00Z", "rotation_healthy": true, "key_usage_unavailable": "audit log client is not configured"}},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "workload-post-workload-identity-registrations",
    group: "Workload Identity (workload)",
    title: "Create Workload Registration",
    service: "workload",
    method: "POST",
    pathTemplate: "/workload-identity/registrations?tenant_id={{tenant_id}}",
    bodyTemplate:
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"name\": \"payments-api\",\n  \"spiffe_id\": \"spiffe://root/workloads/payments-api\",\n  \"selectors\": [\"docker:image:payments-api\", \"env:prod\"],\n  \"allowed_interfaces\": [\"rest\", \"payment-tcp\"],\n  \"allowed_key_ids\": [\"key_payments_prod\"],\n  \"permissions\": [\"key.encrypt\", \"key.decrypt\", \"key.sign\"],\n  \"issue_jwt_svid\": true,\n  \"issue_x509_svid\": true,\n  \"enabled\": true\n}",
    description: "Registers a workload identity and binds it to allowed interfaces, permissions, and keys.",
    requestExample: "POST /svc/workload/workload-identity/registrations?tenant_id={{tenant_id}}",
    responseExample: {"registration": {"id": "wid_a2dd16109494795c", "tenant_id": "root", "name": "payments-api", "spiffe_id": "spiffe://root/workloads/payments-api", "selectors": ["docker:image:payments-api"], "allowed_interfaces": ["payment-tcp"], "allowed_key_ids": ["key_payments_prod"], "permissions": ["key.decrypt"], "issue_x509_svid": true, "issue_jwt_svid": true, "default_ttl_seconds": 1800, "enabled": true, "last_issued_at": "0001-01-01T00:00:00Z", "last_used_at": "0001-01-01T00:00:00Z", "created_at": "0001-01-01T00:00:00Z", "updated_at": "0001-01-01T00:00:00Z"}, "request_id": "req_3b770f16aad81bf1"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "workload-post-workload-identity-issue",
    group: "Workload Identity (workload)",
    title: "Issue SVID",
    service: "workload",
    method: "POST",
    pathTemplate: "/workload-identity/issue?tenant_id={{tenant_id}}",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"registration_id\": \"{{registration_id}}\",\n  \"svid_type\": \"jwt\",\n  \"audiences\": [\n    \"kms\"\n  ],\n  \"ttl_seconds\": 1800\n}",
    description: "Issues a JWT-SVID or X.509-SVID for a registered workload using the tenant trust domain signer material. Needs workload.issue: an X.509-SVID response carries the workload's private key.",
    requestExample: "POST /svc/workload/workload-identity/issue?tenant_id={{tenant_id}}",
    responseExample: {"issued": {"issuance_id": "iss_4ad9d122ad10b8d7", "registration_id": "wid_a2dd16109494795c", "spiffe_id": "spiffe://root/workloads/payments-api", "svid_type": "jwt", "jwt_svid": "<jwt>", "jwks_json": "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"5fa586363e126afc\",...", "serial_or_key_id": "5fa586363e126afc", "expires_at": "2026-10-12T11:23:01.645279Z", "rotation_due_at": "2026-10-12T11:08:01.645279Z", "cryptographically_signed": true}, "request_id": "req_6d4d1ba5b83e0617"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "workload-post-workload-identity-token-exchange",
    group: "Workload Identity (workload)",
    title: "Exchange SVID For KMS Token",
    service: "workload",
    method: "POST",
    pathTemplate: "/workload-identity/token/exchange?tenant_id={{tenant_id}}",
    bodyTemplate: 
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"registration_id\": \"{{registration_id}}\",\n  \"interface_name\": \"rest\",\n  \"audience\": \"kms\",\n  \"requested_permissions\": [\n    \"key.encrypt\",\n    \"key.decrypt\"\n  ],\n  \"requested_key_ids\": [\n    \"key_payments_prod\"\n  ],\n  \"jwt_svid\": \"<jwt_svid from issue>\"\n}",
    description: "Needs no bearer token: the SVID is the credential. Verifies it against the tenant's trust anchors (federated bundles only when federation is on), requires the audience to be one the tenant allows and the registration to be the SVID's own, applies interface and key scoping, and returns a short-lived KMS bearer token. An X.509-SVID also needs x509_svid_proof: a signature by its private key over the tenant, the leaf certificate's SHA-256 and signed_at, accepted once within two minutes.",
    requestExample: "POST /svc/workload/workload-identity/token/exchange?tenant_id={{tenant_id}}",
    responseExample: {"exchange": {"tenant_id": "root", "registration_id": "wid_a2dd16109494795c", "spiffe_id": "spiffe://root/workloads/payments-api", "trust_domain": "root", "svid_type": "jwt", "interface_name": "rest", "allowed_permissions": ["key.decrypt"], "allowed_key_ids": ["key_payments_prod"], "kms_access_token": "<kms access token>", "kms_access_token_expiry": "<kms access token expiry>", "svid_expires_at": "<svid expires at>", "rotation_due_at": "2026-10-12T11:08:01Z"}, "request_id": "req_bc1ad1d705528442"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "workload-get-workload-identity-graph",
    group: "Workload Identity (workload)",
    title: "Get Workload Authorization Graph",
    service: "workload",
    method: "GET",
    pathTemplate: "/workload-identity/graph?tenant_id={{tenant_id}}",
    bodyTemplate:
      "",
    description: "Returns the workload-to-key authorization graph built from registrations plus observed workload-backed key usage in audit events.",
    requestExample: "GET /svc/workload/workload-identity/graph?tenant_id={{tenant_id}}",
    responseExample: {"graph": {"tenant_id": "root", "generated_at": "2026-10-12T10:53:01.646415Z", "nodes": [{"id": "key:key_payments_prod", "label": "key_payments_prod", "kind": "key", "status": "bound"}], "edges": [{"source": "workload:spiffe://root/workloads/payments-api", "target": "key:key_payments_prod", "label": "authorized", "kind": "policy"}], "key_usage_unavailable": "audit log client is not configured"}, "request_id": "req_2cb2e9518a9ae003"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "workload-get-workload-identity-usage",
    group: "Workload Identity (workload)",
    title: "List Workload Key Usage",
    service: "workload",
    method: "GET",
    pathTemplate: "/workload-identity/usage?tenant_id={{tenant_id}}",
    bodyTemplate:
      "",
    description: "Returns recent audit-backed key operations that were authenticated through workload identity instead of a static API credential.",
    requestExample: "GET /svc/workload/workload-identity/usage?tenant_id={{tenant_id}}",
    responseExample: {"note": "Execute endpoint to inspect the live response payload."},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "sbom-post-cbom-generate",
    group: "SBOM / CBOM (sbom)",
    title: "Generate CBOM Snapshot",
    service: "sbom",
    method: "POST",
    pathTemplate: "/cbom/generate?tenant_id={{tenant_id}}",
    bodyTemplate:
      "{\n  \"tenant_id\": \"{{tenant_id}}\",\n  \"trigger\": \"manual\"\n}",
    description: "Builds a fresh cryptographic BOM snapshot for the tenant, including algorithm distribution, PQC readiness, deprecated assets, and source inventory.",
    requestExample: "POST /svc/sbom/cbom/generate?tenant_id={{tenant_id}}",
    responseExample: {"request_id": "req_514f4a69f50c83cd", "snapshot": {"id": "cbom_187031851b8a55c1", "tenant_id": "root", "source_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "created_at": "2026-10-12T10:49:32Z", "document": {"format": "cyclonedx-crypto", "spec_version": "1.6", "tenant_id": "root", "generated_at": "2026-10-12T10:49:32.628182Z", "assets": [], "algorithm_distribution": {}, "strength_histogram": {"128-255": 0, "256-3071": 0, "<128": 0, ">=3072": 0}, "deprecated_count": 0, "pqc_ready_count": 0, "total_asset_count": 0, "pqc_readiness_percent": 0, "source_count": {"certs": 0, "discovery": 0, "keycore": 0}, "metadata": {}}, "summary": {"algorithm_distribution": {}, "deprecated_count": 0, "pqc_readiness_percent": 0, "pqc_ready_count": 0, "source_count": {"certs": 0, "discovery": 0, "keycore": 0}, "strength_histogram": {"128-255": 0, "256-3071": 0, "<128": 0, ">=3072": 0}, "tenant_id": "root", "total_assets": 0}}, "status": "accepted"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  },
  {
    id: "sbom-get-cbom-pqc-readiness",
    group: "SBOM / CBOM (sbom)",
    title: "Get CBOM PQC Readiness",
    service: "sbom",
    method: "GET",
    pathTemplate: "/cbom/pqc-readiness?tenant_id={{tenant_id}}",
    bodyTemplate:
      "",
    description: "Returns post-quantum readiness metrics derived from the latest tenant CBOM, including total assets, PQC-ready counts, deprecated counts, algorithm distribution, and strength histogram.",
    requestExample: "GET /svc/sbom/cbom/pqc-readiness?tenant_id={{tenant_id}}",
    responseExample: {"pqc_readiness": {"pqc_readiness_percent": 0, "pqc_ready_count": 0, "status": "not_ready", "tenant_id": "root", "total_assets": 0}, "request_id": "req_0833bebb6225a254"},
    errorCodes: [
      { code: 400, meaning: "The body does not decode, or the request is not valid for this route" },
      { code: 401, meaning: "Token missing, invalid or expired" },
      { code: 403, meaning: "The caller lacks the permission this route needs" }
    ],
  }
];
