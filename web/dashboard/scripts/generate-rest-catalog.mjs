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
  "cluster-manager": "Cluster Management"
};

const SERVICE_LABEL = {
  ai: "AI",
  audit: "Audit",
  auth: "Auth",
  certs: "Certs",
  cloud: "Cloud",
  compliance: "Compliance",
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
  "sbom|POST|/sbom/generate": {
    title: "Generate SBOM Snapshot",
    bodyTemplate: '{\n  "trigger": "manual"\n}',
    description: "Builds a fresh software BOM snapshot from the local workspace. The snapshot is used by history, diff, export, and vulnerability correlation endpoints.",
    responseExample: {
      status: "accepted",
      snapshot: { id: "sbom_20260311_001", created_at: "2026-03-11T09:45:00Z" }
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
