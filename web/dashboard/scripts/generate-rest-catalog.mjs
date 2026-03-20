#!/usr/bin/env node

import { promises as fs } from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const repoRoot = path.resolve(__dirname, "../../..");
const servicesRoot = path.join(repoRoot, "services");
const outputPath = path.join(repoRoot, "web", "dashboard", "src", "generated", "restApiCatalog.generated.ts");

const WITH_BODY = new Set(["POST", "PUT", "PATCH"]);

const SERVICE_GROUP = {
  ai: "AI Security",
  audit: "Audit & Alerts",
  auth: "Identity & Access",
  certs: "Certificates / PKI",
  cloud: "Cloud Key Control",
  compliance: "Compliance",
  confidential: "Confidential Compute",
  autokey: "Autokey",
  dataprotect: "Data Protection",
  discovery: "Discovery",
  ekm: "Enterprise Key Management",
  governance: "Governance",
  hyok: "HYOK",
  keycore: "Key Management",
  kmip: "KMIP",
  mpc: "MPC",
  payment: "Payment Crypto",
  policy: "Policy",
  pqc: "PQC",
  qkd: "QKD",
  reporting: "Reporting",
  sbom: "SBOM / CBOM",
  secrets: "Secret Vault",
  posture: "Security Posture",
  qrng: "QRNG",
  workload: "Workload Identity",
  "cluster-manager": "Cluster Management"
};

const SERVICE_LABEL = {
  ai: "AI",
  audit: "Audit",
  auth: "Auth",
  certs: "Certs",
  cloud: "Cloud",
  compliance: "Compliance",
  confidential: "Confidential",
  autokey: "Autokey",
  dataprotect: "Data Protect",
  discovery: "Discovery",
  ekm: "EKM",
  governance: "Governance",
  hyok: "HYOK",
  keycore: "KeyCore",
  kmip: "KMIP",
  mpc: "MPC",
  payment: "Payment",
  policy: "Policy",
  pqc: "PQC",
  qkd: "QKD",
  reporting: "Reporting",
  sbom: "SBOM",
  secrets: "Secrets",
  posture: "Posture",
  qrng: "QRNG",
  workload: "Workload",
  "cluster-manager": "Cluster"
};

const ALLOWED_SERVICES = new Set(Object.keys(SERVICE_GROUP));

const ENDPOINT_OVERRIDES = {
  "ai|GET|/ai/config": {
    title: "Get AI Configuration",
    description: "Returns the tenant AI provider configuration, including backend selection, provider authentication mode, MCP compatibility, context collection settings, and redaction fields.",
    responseExample: {
      config: {
        tenant_id: "root",
        backend: "claude",
        endpoint: "https://api.anthropic.com/v1/messages",
        model: "claude-sonnet-4-6",
        api_key_secret: "ai-provider-token",
        provider_auth: { required: true, type: "bearer" },
        mcp: { enabled: false, endpoint: "" },
        max_context_tokens: 8000,
        temperature: 0.3,
        context_sources: {
          keys: { enabled: true, limit: 25, fields: ["id", "name", "algorithm", "status"] },
          policies: { enabled: true, all: false, limit: 20 },
          audit: { enabled: true, last_hours: 24, limit: 100 },
          posture: { enabled: true, current: true },
          alerts: { enabled: true, unresolved: true, limit: 50 }
        },
        redaction_fields: ["encrypted_material", "wrapped_dek", "pwd_hash", "api_key", "passphrase"],
        updated_at: "2026-03-11T09:30:00Z"
      }
    },
    errorCodes: [
      { code: 400, meaning: "tenant_id is missing from query or X-Tenant-ID" },
      { code: 401, meaning: "Authentication required or token invalid" },
      { code: 403, meaning: "Caller lacks permission to read AI configuration" }
    ]
  },
  "ai|PUT|/ai/config": {
    title: "Update AI Configuration",
    bodyTemplate: '{\n  "backend": "copilot",\n  "endpoint": "https://api.githubcopilot.com/chat/completions",\n  "model": "gpt-4o",\n  "api_key_secret": "copilot-token",\n  "provider_auth": {\n    "required": true,\n    "type": "bearer"\n  },\n  "mcp": {\n    "enabled": true,\n    "endpoint": "mcp://kms-ai"\n  },\n  "max_context_tokens": 12000,\n  "temperature": 0.2,\n  "context_sources": {\n    "keys": { "enabled": true, "limit": 25, "fields": ["id", "name", "algorithm", "status"] },\n    "policies": { "enabled": true, "all": false, "limit": 20 },\n    "audit": { "enabled": true, "last_hours": 24, "limit": 100 },\n    "posture": { "enabled": true, "current": true },\n    "alerts": { "enabled": true, "unresolved": true, "limit": 50 }\n  },\n  "redaction_fields": ["encrypted_material", "wrapped_dek", "pwd_hash", "api_key", "passphrase"]\n}',
    description: "Updates the tenant AI provider configuration. Managed providers require provider_auth.required=true with api_key or bearer auth. MCP-enabled configurations must also provide an MCP endpoint.",
    responseExample: {
      config: {
        tenant_id: "root",
        backend: "copilot",
        endpoint: "https://api.githubcopilot.com/chat/completions",
        model: "gpt-4o",
        provider_auth: { required: true, type: "bearer" },
        mcp: { enabled: true, endpoint: "mcp://kms-ai" },
        updated_at: "2026-03-11T09:35:00Z"
      }
    },
    errorCodes: [
      { code: 400, meaning: "Backend, endpoint, auth mode, or MCP settings are invalid" },
      { code: 401, meaning: "Authentication required or token invalid" },
      { code: 403, meaning: "Caller lacks permission to update AI configuration" }
    ]
  },
  "ai|POST|/ai/query": {
    title: "Query AI Assistant",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "query": "Analyze recent unresolved alerts and recommend actions",\n  "include_context": true\n}',
    description: "Submits a natural-language AI assistant request. When include_context=true, the service may attach redacted keys, policy, audit, posture, and alert context according to the saved tenant AI configuration.",
    responseExample: {
      result: {
        action: "query",
        tenant_id: "root",
        answer: "There are 3 unresolved high severity alerts. Start with the posture risk spike and the stale approval backlog.",
        backend: "claude",
        model: "claude-sonnet-4-6",
        redactions_applied: 4,
        context_summary: { keys: 12, policies: 6, audit_events: 45, alerts: 3 },
        warnings: [],
        generated_at: "2026-03-11T09:40:00Z"
      }
    },
    errorCodes: [
      { code: 400, meaning: "Query is empty or request JSON is invalid" },
      { code: 401, meaning: "Authentication required or token invalid" },
      { code: 503, meaning: "Provider unavailable and no fallback response could be generated" }
    ]
  },
  "ai|POST|/ai/analyze/incident": {
    title: "Analyze Incident",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "incident_id": "inc-001",\n  "title": "Unauthorized key export attempt",\n  "description": "A privileged user attempted an export against a production key.",\n  "details": {\n    "key_id": "key_123",\n    "actor": "ops-admin",\n    "approval_status": "missing"\n  }\n}',
    description: "Generates an AI-assisted incident analysis for a specific security or governance event and returns a narrative response with context-aware warnings.",
    responseExample: {
      result: {
        action: "incident_analysis",
        tenant_id: "root",
        answer: "The export attempt appears blocked by governance controls. Review the actor's role bindings and pending approvals.",
        backend: "claude",
        model: "claude-sonnet-4-6",
        redactions_applied: 1,
        context_summary: { incident_id: "inc-001" },
        warnings: [],
        generated_at: "2026-03-11T09:41:00Z"
      }
    }
  },
  "ai|POST|/ai/recommend/posture": {
    title: "Recommend Posture Improvements",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "focus": "key-rotation"\n}',
    description: "Uses current posture, audit, and policy context to generate prioritized remediation guidance for the requested focus area or for the overall KMS posture.",
    responseExample: {
      result: {
        action: "posture_recommendation",
        tenant_id: "root",
        answer: "Enable automatic rotation for stale AES keys and resolve open posture findings tied to weak legacy algorithms.",
        backend: "fallback",
        model: "deterministic-rules",
        redactions_applied: 0,
        context_summary: { focus: "key-rotation" },
        warnings: ["LLM provider unavailable; returned fallback guidance."],
        generated_at: "2026-03-11T09:42:00Z"
      }
    }
  },
  "ai|POST|/ai/explain/policy": {
    title: "Explain Policy",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "policy_id": "policy-rotate-90d",\n  "policy": {\n    "id": "policy-rotate-90d",\n    "name": "Rotate every 90 days",\n    "status": "active"\n  }\n}',
    description: "Produces a natural-language explanation of a policy by ID or from an inline policy document, including likely enforcement intent and plain-English warnings.",
    responseExample: {
      result: {
        action: "policy_explanation",
        tenant_id: "root",
        answer: "This policy requires 90-day rotation and blocks long-lived production keys from remaining active without renewal.",
        backend: "claude",
        model: "claude-sonnet-4-6",
        redactions_applied: 0,
        context_summary: { policy_id: "policy-rotate-90d" },
        warnings: [],
        generated_at: "2026-03-11T09:43:00Z"
      }
    },
    errorCodes: [
      { code: 400, meaning: "policy_id is missing and no inline policy document was provided" },
      { code: 401, meaning: "Authentication required or token invalid" },
      { code: 404, meaning: "Referenced policy could not be found" }
    ]
  },
  "auth|POST|/auth/client-token": {
    title: "Issue REST Client Token",
    description: "Issues a tenant-scoped client access token. Depending on the registered client auth mode, the request must also carry a validated mTLS binding, DPoP proof, or HTTP Message Signature.",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "client_id": "reg_123",\n  "api_key": "vk_live_xxx"\n}',
    responseExample: {
      access_token: "<jwt>",
      expires_in: 3600,
      token_type: "Bearer",
      sender_constrained: true,
      auth_mode: "dpop",
      replay_protection: true,
      request_id: "req_123"
    },
    errorCodes: [
      { code: 400, meaning: "Client proof is malformed or the request body is invalid" },
      { code: 401, meaning: "Client proof, certificate binding, or API credential did not verify" },
      { code: 409, meaning: "Replay nonce was already used inside the protected window" }
    ]
  },
  "auth|GET|/auth/clients": {
    title: "List Client Registrations",
    description: "Lists registered clients with sender-constrained auth mode, replay protection state, and verification counters.",
    responseExample: {
      items: [
        {
          id: "reg_123",
          client_name: "payments-sdk",
          status: "approved",
          auth_mode: "oauth_mtls",
          replay_protection_enabled: true,
          verified_request_count: 1487,
          replay_violation_count: 0,
          signature_failure_count: 0,
          unsigned_reject_count: 0
        }
      ]
    }
  },
  "auth|PUT|/auth/clients/{id}": {
    title: "Update Client Registration Security",
    description: "Updates the client allowlist, rate limit, auth mode, and sender-constrained request binding. This is where operators move REST clients from legacy bearer mode to OAuth mTLS, DPoP, or HTTP Message Signatures.",
    bodyTemplate: '{\n  "ip_whitelist": ["10.10.10.0/24"],\n  "rate_limit": 1500,\n  "auth_mode": "http_message_signature",\n  "replay_protection_enabled": true,\n  "http_signature_key_id": "sdk-signing-key-01",\n  "http_signature_public_key_pem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----",\n  "http_signature_algorithm": "ed25519"\n}',
    responseExample: {
      status: "ok",
      request_id: "req_123"
    }
  },
  "auth|GET|/auth/rest-client-security/summary": {
    title: "Get REST Client Security Summary",
    description: "Returns sender-constrained auth posture for tenant REST clients, including replay protection coverage, signature failures, unsigned request blocks, and non-compliant legacy clients.",
    responseExample: {
      summary: {
        tenant_id: "root",
        total_clients: 7,
        sender_constrained_clients: 5,
        oauth_mtls_clients: 2,
        dpop_clients: 2,
        http_message_signature_clients: 1,
        replay_protected_clients: 5,
        non_compliant_clients: 2,
        verified_requests: 2157,
        replay_violations: 1,
        signature_failures: 3,
        unsigned_rejects: 4,
        last_violation_at: "2026-03-20T10:15:00Z"
      }
    }
  },
  "sbom|POST|/sbom/generate": {
    title: "Generate SBOM Snapshot",
    bodyTemplate: '{\n  "trigger": "manual"\n}',
    description: "Builds a fresh software BOM snapshot from the local workspace. The snapshot is used by history, diff, export, and vulnerability correlation endpoints.",
    responseExample: {
      status: "accepted",
      snapshot: { id: "sbom_20260311_001", created_at: "2026-03-11T09:45:00Z" }
    }
  },
  "confidential|GET|/confidential/policy": {
    title: "Get Attestation Policy",
    description: "Returns the tenant-scoped attested key release policy used by the Confidential Compute service.",
    responseExample: {
      policy: {
        tenant_id: "root",
        enabled: true,
        provider: "aws_nitro_enclaves",
        mode: "enforce",
        key_scopes: ["payments-prod"],
        approved_images: ["123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/authorizer:v1.4.2"],
        approved_subjects: ["spiffe://root/workloads/payments-authorizer"],
        allowed_attesters: ["aws.nitro-enclaves"],
        required_measurements: { pcr0: "baseline-image-hash", pcr8: "secure-boot-chain-hash" },
        required_claims: { environment: "prod", team: "payments" },
        require_secure_boot: true,
        require_debug_disabled: true,
        max_evidence_age_sec: 300,
        cluster_scope: "node_allowlist",
        allowed_cluster_nodes: ["vecta-kms-01", "vecta-kms-02"],
        fallback_action: "deny",
        updated_at: "2026-03-18T11:00:00Z"
      }
    }
  },
  "confidential|PUT|/confidential/policy": {
    title: "Update Attestation Policy",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "enabled": true,\n  "provider": "aws_nitro_enclaves",\n  "mode": "enforce",\n  "key_scopes": ["payments-prod"],\n  "approved_images": ["123456789012.dkr.ecr.us-east-1.amazonaws.com/payments/authorizer:v1.4.2"],\n  "approved_subjects": ["spiffe://root/workloads/payments-authorizer"],\n  "allowed_attesters": ["aws.nitro-enclaves"],\n  "required_measurements": { "pcr0": "baseline-image-hash", "pcr8": "secure-boot-chain-hash" },\n  "required_claims": { "environment": "prod", "team": "payments" },\n  "require_secure_boot": true,\n  "require_debug_disabled": true,\n  "max_evidence_age_sec": 300,\n  "cluster_scope": "node_allowlist",\n  "allowed_cluster_nodes": ["vecta-kms-01"],\n  "fallback_action": "deny"\n}',
    description: "Creates or updates the tenant attestation policy for attested key release.",
    responseExample: {
      policy: {
        tenant_id: "root",
        enabled: true,
        provider: "aws_nitro_enclaves",
        mode: "enforce",
        updated_at: "2026-03-18T11:02:00Z"
      }
    }
  },
  "confidential|GET|/confidential/summary": {
    title: "Get Confidential Compute Summary",
    description: "Returns summary metrics for the tenant attested release program, including recent release decisions and cluster node spread.",
    responseExample: {
      summary: {
        tenant_id: "root",
        policy_enabled: true,
        provider: "aws_nitro_enclaves",
        approved_image_count: 2,
        key_scope_count: 1,
        release_count_24h: 14,
        deny_count_24h: 2,
        review_count_24h: 1,
        cryptographically_verified_count_24h: 13,
        unique_cluster_nodes: 2,
        latest_decision: "release",
        last_decision_at: "2026-03-18T11:15:00Z"
      }
    }
  },
  "confidential|POST|/confidential/evaluate": {
    title: "Evaluate Attested Key Release",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "key_id": "key-prod-root",\n  "key_scope": "payments-prod",\n  "provider": "aws_nitro_enclaves",\n  "attestation_format": "cose_sign1",\n  "attestation_document": "{{base64_cose_sign1_attestation_document}}",\n  "audience": "kms-key-release",\n  "nonce": "nonce-demo-001",\n  "cluster_node_id": "vecta-kms-01",\n  "requester": "platform-ops",\n  "release_reason": "authorize payment enclave",\n  "dry_run": true\n}',
    description: "Cryptographically verifies an AWS, Azure, or GCP attestation document, derives signed claims and measurements, and then evaluates the result against the tenant attested-release policy.",
    responseExample: {
      result: {
        release_id: "rel_01J123EXAMPLE",
        decision: "release",
        allowed: true,
        reasons: [],
        matched_claims: ["environment", "team"],
        matched_measurements: ["pcr0", "pcr8"],
        missing_claims: [],
        missing_measurements: [],
        measurement_hash: "sha256:measurement-hash",
        claims_hash: "sha256:claims-hash",
        policy_version: "sha256:policy-version",
        provider: "aws_nitro_enclaves",
        cluster_node_id: "vecta-kms-01",
        cryptographically_verified: true,
        verification_mode: "aws_cose_sign1_x509",
        verification_issuer: "aws.nitro-enclaves",
        verification_key_id: "02",
        attestation_document_hash: "sha256:document-hash",
        attestation_document_format: "cose_sign1",
        evaluated_at: "2026-03-18T11:16:00Z"
      }
    }
  },
  "confidential|GET|/confidential/releases": {
    title: "List Attested Release History",
    description: "Lists stored attested release decisions for the tenant.",
    responseExample: {
      items: [
        {
          id: "rel_01J123EXAMPLE",
          tenant_id: "root",
          key_id: "key-prod-root",
          key_scope: "payments-prod",
          provider: "aws_nitro_enclaves",
          workload_identity: "spiffe://root/workloads/payments-authorizer",
          cluster_node_id: "vecta-kms-01",
          decision: "release",
          allowed: true,
          cryptographically_verified: true,
          verification_issuer: "aws.nitro-enclaves",
          attestation_document_hash: "sha256:document-hash",
          measurement_hash: "sha256:measurement-hash",
          policy_version: "sha256:policy-version",
          created_at: "2026-03-18T11:16:00Z"
        }
      ]
    }
  },
  "confidential|GET|/confidential/releases/{id}": {
    title: "Get Attested Release Record",
    description: "Returns a single stored attested release record for the tenant.",
    responseExample: {
      item: {
        id: "rel_01J123EXAMPLE",
        tenant_id: "root",
        key_id: "key-prod-root",
        key_scope: "payments-prod",
        provider: "aws_nitro_enclaves",
        decision: "release",
        allowed: true,
        cryptographically_verified: true,
        verification_issuer: "aws.nitro-enclaves",
        verification_mode: "aws_cose_sign1_x509",
        attestation_document_hash: "sha256:document-hash",
        measurement_hash: "sha256:measurement-hash",
        claims_hash: "sha256:claims-hash",
        policy_version: "sha256:policy-version",
        created_at: "2026-03-18T11:16:00Z"
      }
    }
  },
  "workload|GET|/workload-identity/settings": {
    title: "Get Workload Identity Settings",
    description: "Returns the tenant SPIFFE trust-domain settings, issuance defaults, federation mode, and token-exchange controls.",
    responseExample: {
      settings: {
        tenant_id: "root",
        enabled: true,
        trust_domain: "root",
        federation_enabled: true,
        token_exchange_enabled: true,
        disable_static_api_keys: true,
        default_x509_ttl_seconds: 43200,
        default_jwt_ttl_seconds: 1800,
        rotation_window_seconds: 1800,
        allowed_audiences: ["kms", "kms-workload", "kms-rest"],
        jwt_signer_key_id: "wid-root-1",
        updated_at: "2026-03-19T09:00:00Z"
      }
    }
  },
  "workload|PUT|/workload-identity/settings": {
    title: "Update Workload Identity Settings",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "enabled": true,\n  "trust_domain": "root",\n  "federation_enabled": true,\n  "token_exchange_enabled": true,\n  "disable_static_api_keys": true,\n  "default_x509_ttl_seconds": 43200,\n  "default_jwt_ttl_seconds": 1800,\n  "rotation_window_seconds": 1800,\n  "allowed_audiences": ["kms", "kms-workload", "kms-rest"]\n}',
    description: "Creates or updates the tenant workload-identity policy, including the SPIFFE trust domain and whether static API keys should be phased out for workloads.",
    responseExample: {
      settings: {
        tenant_id: "root",
        enabled: true,
        trust_domain: "root",
        disable_static_api_keys: true,
        updated_at: "2026-03-19T09:02:00Z"
      }
    }
  },
  "workload|GET|/workload-identity/summary": {
    title: "Get Workload Identity Summary",
    description: "Returns health and drift counters for workload identity, including expiring or expired SVIDs, over-privileged registrations, token exchange activity, and key usage.",
    responseExample: {
      summary: {
        tenant_id: "root",
        enabled: true,
        trust_domain: "root",
        registration_count: 4,
        enabled_registration_count: 4,
        federated_trust_domain_count: 1,
        issuance_count_24h: 8,
        token_exchange_count_24h: 21,
        key_usage_count_24h: 57,
        unique_workloads_using_keys_24h: 3,
        unique_keys_used_24h: 4,
        expiring_svid_count: 1,
        expired_svid_count: 0,
        over_privileged_count: 1,
        rotation_healthy: true
      }
    }
  },
  "workload|POST|/workload-identity/registrations": {
    title: "Create Workload Registration",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "name": "payments-api",\n  "spiffe_id": "spiffe://root/workloads/payments-api",\n  "selectors": ["docker:image:payments-api", "env:prod"],\n  "allowed_interfaces": ["rest", "payment-tcp"],\n  "allowed_key_ids": ["key_payments_prod"],\n  "permissions": ["key.encrypt", "key.decrypt", "key.sign"],\n  "issue_jwt_svid": true,\n  "issue_x509_svid": true,\n  "enabled": true\n}',
    description: "Registers a workload identity and binds it to allowed interfaces, permissions, and keys.",
    responseExample: {
      registration: {
        id: "wid_01J123EXAMPLE",
        tenant_id: "root",
        name: "payments-api",
        spiffe_id: "spiffe://root/workloads/payments-api",
        allowed_interfaces: ["rest", "payment-tcp"],
        allowed_key_ids: ["key_payments_prod"],
        permissions: ["key.encrypt", "key.decrypt", "key.sign"],
        enabled: true,
        created_at: "2026-03-19T09:05:00Z"
      }
    }
  },
  "workload|POST|/workload-identity/issue": {
    title: "Issue SVID",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "registration_id": "wid_01J123EXAMPLE",\n  "svid_type": "jwt",\n  "audiences": ["kms"],\n  "ttl_seconds": 1800,\n  "requested_by": "platform-ops"\n}',
    description: "Issues a JWT-SVID or X.509-SVID for a registered workload using the tenant trust domain signer material.",
    responseExample: {
      issued: {
        issuance_id: "iss_01J123EXAMPLE",
        registration_id: "wid_01J123EXAMPLE",
        spiffe_id: "spiffe://root/workloads/payments-api",
        svid_type: "jwt",
        serial_or_key_id: "wid-root-1",
        expires_at: "2026-03-19T09:35:00Z",
        rotation_due_at: "2026-03-19T09:05:00Z",
        cryptographically_signed: true
      }
    }
  },
  "workload|POST|/workload-identity/token/exchange": {
    title: "Exchange SVID For KMS Token",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "registration_id": "wid_01J123EXAMPLE",\n  "interface_name": "rest",\n  "audience": "kms",\n  "requested_permissions": ["key.encrypt", "key.decrypt"],\n  "requested_key_ids": ["key_payments_prod"],\n  "jwt_svid": "eyJhbGciOiJFZERTQSIsImtpZCI6IndpZC1yb290In0..."\n}',
    description: "Validates a presented SVID against the tenant or federated trust bundle, applies interface and key scoping, and returns a short-lived KMS bearer token.",
    responseExample: {
      exchange: {
        tenant_id: "root",
        registration_id: "wid_01J123EXAMPLE",
        spiffe_id: "spiffe://root/workloads/payments-api",
        trust_domain: "root",
        svid_type: "jwt",
        interface_name: "rest",
        allowed_permissions: ["key.encrypt", "key.decrypt"],
        allowed_key_ids: ["key_payments_prod"],
        kms_access_token_expiry: "2026-03-19T09:20:00Z"
      }
    }
  },
  "workload|GET|/workload-identity/graph": {
    title: "Get Workload Authorization Graph",
    description: "Returns the workload-to-key authorization graph built from registrations plus observed workload-backed key usage in audit events.",
    responseExample: {
      graph: {
        tenant_id: "root",
        generated_at: "2026-03-19T09:10:00Z",
        nodes: [
          { id: "workload:spiffe://root/workloads/payments-api", label: "spiffe://root/workloads/payments-api", kind: "workload", status: "enabled" },
          { id: "key:key_payments_prod", label: "key_payments_prod", kind: "key", status: "bound" }
        ],
        edges: [
          { source: "workload:spiffe://root/workloads/payments-api", target: "key:key_payments_prod", label: "authorized", kind: "policy" }
        ]
      }
    }
  },
  "workload|GET|/workload-identity/usage": {
    title: "List Workload Key Usage",
    description: "Returns recent audit-backed key operations that were authenticated through workload identity instead of a static API credential.",
    responseExample: {
      items: [
        {
          event_id: "evt_01J123EXAMPLE",
          tenant_id: "root",
          workload_identity: "spiffe://root/workloads/payments-api",
          trust_domain: "root",
          key_id: "key_payments_prod",
          operation: "encrypt",
          interface_name: "rest",
          client_id: "wid_01J123EXAMPLE",
          result: "success",
          created_at: "2026-03-19T09:15:00Z"
        }
      ]
    }
  },
  "sbom|GET|/sbom/vulnerabilities": {
    title: "List SBOM Vulnerabilities",
    description: "Returns merged vulnerability findings for the latest SBOM snapshot. Results can include Manual OSV advisories for air-gapped use, live OSV package matches, and Trivy repository scan results.",
    responseExample: {
      items: [
        {
          id: "CVE-2026-1000",
          source: "OSV",
          severity: "high",
          component: "golang.org/x/net",
          installed_version: "v0.20.0",
          fixed_version: "v0.35.0",
          summary: "HTTP issue in golang.org/x/net.",
          reference: "https://osv.dev/vulnerability/GO-2026-0001"
        },
        {
          id: "CVE-2025-29923",
          source: "Trivy",
          severity: "low",
          component: "github.com/redis/go-redis/v9",
          installed_version: "v9.7.0",
          fixed_version: "9.7.3",
          summary: "go-redis vulnerability",
          reference: "https://avd.aquasec.com/nvd/cve-2025-29923"
        }
      ]
    },
    errorCodes: [
      { code: 401, meaning: "Authentication required or token invalid" },
      { code: 403, meaning: "Caller lacks SBOM read privilege" },
      { code: 500, meaning: "Snapshot load or vulnerability provider processing failed" }
    ]
  },
  "sbom|GET|/sbom/advisories": {
    title: "List Offline Advisories",
    description: "Lists manually managed offline advisories that are merged into the SBOM vulnerability view before online providers. This supports air-gapped KMS deployments.",
    responseExample: {
      items: [
        {
          id: "CVE-2026-5000",
          component: "example/module",
          ecosystem: "go",
          introduced_version: "v1.0.0",
          fixed_version: "v1.3.0",
          severity: "critical",
          summary: "Offline advisory",
          reference: "https://example.test/CVE-2026-5000",
          created_at: "2026-03-11T09:46:00Z",
          updated_at: "2026-03-11T09:46:00Z"
        }
      ]
    }
  },
  "sbom|POST|/sbom/advisories": {
    title: "Create or Update Offline Advisory",
    bodyTemplate: '{\n  "id": "CVE-2026-5000",\n  "component": "example/module",\n  "ecosystem": "go",\n  "introduced_version": "v1.0.0",\n  "fixed_version": "v1.3.0",\n  "severity": "critical",\n  "summary": "Offline advisory for an air-gapped deployment",\n  "reference": "https://example.test/CVE-2026-5000"\n}',
    description: "Creates or updates a manual advisory record for offline or disconnected environments. These advisories are treated as an internal OSV-style source during vulnerability matching.",
    responseExample: {
      item: {
        id: "CVE-2026-5000",
        component: "example/module",
        ecosystem: "go",
        fixed_version: "v1.3.0",
        severity: "critical",
        summary: "Offline advisory for an air-gapped deployment"
      }
    },
    errorCodes: [
      { code: 400, meaning: "Advisory payload is invalid or required fields are missing" },
      { code: 401, meaning: "Authentication required or token invalid" },
      { code: 409, meaning: "Conflicting advisory data prevented save" }
    ]
  },
  "sbom|DELETE|/sbom/advisories/{id}": {
    title: "Delete Offline Advisory",
    description: "Deletes a manually managed offline advisory by advisory ID.",
    requestExample: "DELETE /svc/sbom/sbom/advisories/CVE-2026-5000?tenant_id={{tenant_id}}",
    responseExample: {
      status: "deleted"
    },
    errorCodes: [
      { code: 401, meaning: "Authentication required or token invalid" },
      { code: 404, meaning: "Advisory ID was not found" }
    ]
  },
  "sbom|POST|/cbom/generate": {
    title: "Generate CBOM Snapshot",
    bodyTemplate: '{\n  "tenant_id": "{{tenant_id}}",\n  "trigger": "manual"\n}',
    description: "Builds a fresh cryptographic BOM snapshot for the tenant, including algorithm distribution, PQC readiness, deprecated assets, and source inventory.",
    responseExample: {
      status: "accepted",
      snapshot: { id: "cbom_20260311_001", tenant_id: "{{tenant_id}}", created_at: "2026-03-11T09:47:00Z" }
    }
  },
  "sbom|GET|/cbom/pqc-readiness": {
    title: "Get CBOM PQC Readiness",
    description: "Returns post-quantum readiness metrics derived from the latest tenant CBOM, including total assets, PQC-ready counts, deprecated counts, algorithm distribution, and strength histogram.",
    responseExample: {
      pqc_readiness: {
        total_assets: 42,
        pqc_ready_count: 8,
        pqc_readiness_percent: 19,
        deprecated_count: 4,
        algorithm_distribution: { AES: 16, RSA: 9, ECDSA: 9, "ML-DSA": 8 },
        strength_histogram: { "128": 8, "256": 34 }
      }
    }
  }
};

async function walk(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walk(full)));
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    if (!entry.name.endsWith(".go")) {
      continue;
    }
    if (entry.name !== "handler.go" && entry.name !== "http_api.go") {
      continue;
    }
    files.push(full);
  }
  return files;
}

function slug(text) {
  return String(text || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function toCatalogItem(service, method, routePath) {
  const normalizedPath = String(routePath || "").trim() || "/";
  const pathTemplate = normalizedPath.includes("?")
    ? normalizedPath
    : `${normalizedPath}?tenant_id={{tenant_id}}`;
  const group = `${SERVICE_GROUP[service] || "Other"} (${service})`;
  const serviceLabel = SERVICE_LABEL[service] || service;
  const id = `${service}-${slug(method)}-${slug(normalizedPath)}`;
  const base = {
    id,
    group,
    title: `${method} ${normalizedPath}`,
    service,
    method,
    pathTemplate,
    bodyTemplate: WITH_BODY.has(method) ? '{\n  "tenant_id": "{{tenant_id}}"\n}' : "",
    description: `Auto-discovered route from ${serviceLabel} service.`,
    requestExample: `${method} /svc/${service}${pathTemplate}`,
    responseExample: {
      note: "Execute endpoint to inspect the live response payload."
    },
    errorCodes: [
      { code: 401, meaning: "Authentication required or token invalid" },
      { code: 403, meaning: "Caller lacks permission for this operation" },
      { code: 400, meaning: "Request payload, path, or query parameters invalid" }
    ]
  };
  const override = ENDPOINT_OVERRIDES[`${service}|${method}|${normalizedPath}`];
  return override ? { ...base, ...override } : base;
}

async function main() {
  try {
    await fs.access(servicesRoot);
  } catch {
    process.stdout.write(`Skipped route discovery: services root not found at ${servicesRoot}\n`);
    return;
  }

  const files = await walk(servicesRoot);
  const routeRegex = /mux\.HandleFunc\("([A-Z]+)\s+([^"]+)"\s*,/g;
  const unique = new Map();

  for (const filePath of files) {
    const rel = path.relative(servicesRoot, filePath).replace(/\\/g, "/");
    const [service] = rel.split("/");
    if (!ALLOWED_SERVICES.has(service)) {
      continue;
    }
    const source = await fs.readFile(filePath, "utf8");
    let match;
    while ((match = routeRegex.exec(source)) !== null) {
      const method = String(match[1] || "").trim().toUpperCase();
      const routePath = String(match[2] || "").trim();
      if (!method || !routePath) {
        continue;
      }
      const key = `${service}|${method}|${routePath}`;
      if (unique.has(key)) {
        continue;
      }
      unique.set(key, toCatalogItem(service, method, routePath));
    }
  }

  const items = [...unique.values()].sort((a, b) => {
    if (a.group !== b.group) {
      return a.group.localeCompare(b.group);
    }
    if (a.service !== b.service) {
      return a.service.localeCompare(b.service);
    }
    if (a.method !== b.method) {
      return a.method.localeCompare(b.method);
    }
    return a.pathTemplate.localeCompare(b.pathTemplate);
  });

  const banner =
    "// Auto-generated by web/dashboard/scripts/generate-rest-catalog.mjs.\n" +
    "// Do not edit this file manually.\n\n";
  const body = `export const DISCOVERED_REST_API_CATALOG = ${JSON.stringify(items, null, 2)};\n`;

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, banner + body, "utf8");
  process.stdout.write(`Generated ${items.length} routes -> ${outputPath}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error?.stack || error}\n`);
  process.exit(1);
});
