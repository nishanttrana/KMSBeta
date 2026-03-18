import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import YAML from "yaml";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..", "..", "..");
const dashboardRoot = path.resolve(__dirname, "..");
const docsOutDir = path.join(repoRoot, "docs", "openapi");
const publicOutDir = path.join(dashboardRoot, "public", "openapi");
const swaggerUiDistDir = path.join(dashboardRoot, "node_modules", "swagger-ui-dist");

const isoDateTime = { type: "string", format: "date-time" };
const objectAny = { type: "object", additionalProperties: true };
const stringMap = { type: "object", additionalProperties: { type: "string" } };
const intMap = { type: "object", additionalProperties: { type: "integer" } };

const headerRequestId = {
  name: "X-Request-ID",
  in: "header",
  required: false,
  description: "Optional client correlation id. The service generates one when omitted.",
  schema: { type: "string" },
};

const headerTenant = {
  name: "X-Tenant-ID",
  in: "header",
  required: false,
  description: "Alternative tenant scope header accepted by tenant-aware handlers.",
  schema: { type: "string", example: "root" },
};

const queryTenant = {
  name: "tenant_id",
  in: "query",
  required: false,
  description: "Tenant scope. Required for tenant-aware operations unless supplied in the request body or `X-Tenant-ID`.",
  schema: { type: "string", example: "root" },
};

const queryLimit = {
  name: "limit",
  in: "query",
  required: false,
  schema: { type: "integer", minimum: 1, example: 20 },
};

const pathId = {
  name: "id",
  in: "path",
  required: true,
  schema: { type: "string" },
};

const queryFrom = {
  name: "from",
  in: "query",
  required: true,
  schema: { type: "string", example: "sbom_20260311_a1b2c3" },
};

const queryTo = {
  name: "to",
  in: "query",
  required: true,
  schema: { type: "string", example: "sbom_20260311_d4e5f6" },
};

const querySbomFormat = {
  name: "format",
  in: "query",
  required: false,
  schema: { type: "string", enum: ["cyclonedx", "spdx", "pdf"], default: "cyclonedx" },
};

const querySbomEncoding = {
  name: "encoding",
  in: "query",
  required: false,
  schema: { type: "string", enum: ["json", "xml"], default: "json" },
};

const queryCbomFormat = {
  name: "format",
  in: "query",
  required: false,
  schema: { type: "string", enum: ["cyclonedx", "pdf"], default: "cyclonedx" },
};

const media = (schema) => ({ "application/json": { schema } });
const err = (description) => ({ description, content: media({ $ref: "#/components/schemas/ErrorEnvelope" }) });

function buildAIComponents() {
  return {
    parameters: {
      RequestIdHeader: headerRequestId,
      TenantHeader: headerTenant,
      TenantQuery: queryTenant,
    },
    schemas: {
      ErrorEnvelope: {
        type: "object",
        required: ["error"],
        properties: {
          error: {
            type: "object",
            required: ["code", "message", "request_id", "tenant_id"],
            properties: {
              code: { type: "string", example: "bad_request" },
              message: { type: "string", example: "tenant_id is required" },
              request_id: { type: "string", example: "req_1a2b3c4d5e6f7a8b" },
              tenant_id: { type: "string", example: "root" },
            },
          },
        },
      },
      StringList: { type: "array", items: { type: "string" } },
      ContextKeysConfig: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          limit: { type: "integer", minimum: 0 },
          fields: { $ref: "#/components/schemas/StringList" },
        },
      },
      ContextPoliciesConfig: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          all: { type: "boolean" },
          limit: { type: "integer", minimum: 0 },
        },
      },
      ContextAuditConfig: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          last_hours: { type: "integer", minimum: 0 },
          limit: { type: "integer", minimum: 0 },
        },
      },
      ContextPostureConfig: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          current: { type: "boolean" },
        },
      },
      ContextAlertsConfig: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          unresolved: { type: "boolean" },
          limit: { type: "integer", minimum: 0 },
        },
      },
      ContextSources: {
        type: "object",
        properties: {
          keys: { $ref: "#/components/schemas/ContextKeysConfig" },
          policies: { $ref: "#/components/schemas/ContextPoliciesConfig" },
          audit: { $ref: "#/components/schemas/ContextAuditConfig" },
          posture: { $ref: "#/components/schemas/ContextPostureConfig" },
          alerts: { $ref: "#/components/schemas/ContextAlertsConfig" },
        },
      },
      ProviderAuthConfig: {
        type: "object",
        required: ["required", "type"],
        properties: {
          required: { type: "boolean" },
          type: { type: "string", enum: ["api_key", "bearer", "none"] },
        },
      },
      MCPConfig: {
        type: "object",
        required: ["enabled", "endpoint"],
        properties: {
          enabled: { type: "boolean" },
          endpoint: { type: "string", example: "mcp://kms-ai" },
        },
      },
      AIConfig: {
        type: "object",
        required: ["tenant_id", "backend", "endpoint", "model", "api_key_secret", "provider_auth", "mcp", "max_context_tokens", "temperature", "context_sources", "redaction_fields", "updated_at"],
        properties: {
          tenant_id: { type: "string", example: "root" },
          backend: { type: "string", enum: ["claude", "openai", "azure-openai", "copilot", "self-hosted", "ollama", "vllm", "llamacpp"] },
          endpoint: { type: "string", example: "https://api.anthropic.com/v1/messages" },
          model: { type: "string", example: "claude-sonnet-4-20250514" },
          api_key_secret: { type: "string", example: "ai-provider-token" },
          provider_auth: { $ref: "#/components/schemas/ProviderAuthConfig" },
          mcp: { $ref: "#/components/schemas/MCPConfig" },
          max_context_tokens: { type: "integer", minimum: 256 },
          temperature: { type: "number", minimum: 0, maximum: 2 },
          context_sources: { $ref: "#/components/schemas/ContextSources" },
          redaction_fields: { $ref: "#/components/schemas/StringList" },
          updated_at: isoDateTime,
        },
      },
      AIConfigUpdate: {
        type: "object",
        properties: {
          backend: { type: "string", enum: ["claude", "openai", "azure-openai", "copilot", "self-hosted", "ollama", "vllm", "llamacpp"] },
          endpoint: { type: "string" },
          model: { type: "string" },
          api_key_secret: { type: "string" },
          provider_auth: { $ref: "#/components/schemas/ProviderAuthConfig" },
          mcp: { $ref: "#/components/schemas/MCPConfig" },
          max_context_tokens: { type: "integer", minimum: 256 },
          temperature: { type: "number", minimum: 0, maximum: 2 },
          context_sources: { $ref: "#/components/schemas/ContextSources" },
          redaction_fields: { $ref: "#/components/schemas/StringList" },
        },
      },
      QueryRequest: {
        type: "object",
        required: ["query"],
        properties: {
          tenant_id: { type: "string" },
          query: { type: "string", minLength: 1 },
          include_context: { type: "boolean" },
        },
      },
      IncidentAnalysisRequest: {
        type: "object",
        properties: {
          tenant_id: { type: "string" },
          incident_id: { type: "string" },
          title: { type: "string" },
          description: { type: "string" },
          details: objectAny,
        },
      },
      PostureRecommendationRequest: {
        type: "object",
        properties: {
          tenant_id: { type: "string" },
          focus: { type: "string" },
        },
      },
      PolicyExplainRequest: {
        type: "object",
        properties: {
          tenant_id: { type: "string" },
          policy_id: { type: "string" },
          policy: objectAny,
        },
      },
      AIResponse: {
        type: "object",
        required: ["action", "tenant_id", "answer", "backend", "model", "redactions_applied", "context_summary", "generated_at"],
        properties: {
          action: { type: "string", enum: ["query", "incident_analysis", "posture_recommendation", "policy_explanation"] },
          tenant_id: { type: "string" },
          answer: { type: "string" },
          backend: { type: "string" },
          model: { type: "string" },
          redactions_applied: { type: "integer", minimum: 0 },
          context_summary: objectAny,
          context: objectAny,
          warnings: { $ref: "#/components/schemas/StringList" },
          generated_at: isoDateTime,
        },
      },
      AIConfigEnvelope: {
        type: "object",
        required: ["config", "request_id"],
        properties: {
          config: { $ref: "#/components/schemas/AIConfig" },
          request_id: { type: "string" },
        },
      },
      AIResultEnvelope: {
        type: "object",
        required: ["result", "request_id"],
        properties: {
          result: { $ref: "#/components/schemas/AIResponse" },
          request_id: { type: "string" },
        },
      },
    },
  };
}

function buildAISpec() {
  const params = [
    { $ref: "#/components/parameters/RequestIdHeader" },
    { $ref: "#/components/parameters/TenantQuery" },
    { $ref: "#/components/parameters/TenantHeader" },
  ];
  return {
    openapi: "3.0.3",
    info: {
      title: "Vecta KMS AI Service API",
      version: "1.0.0",
      description: "OpenAPI contract for AI configuration and assistant workflows. Use `/svc/ai` through the dashboard proxy or `http://localhost:8090` directly.",
    },
    servers: [
      { url: "/svc/ai", description: "Dashboard reverse proxy" },
      { url: "http://localhost:8090", description: "Direct AI service" },
    ],
    tags: [
      { name: "AI Config" },
      { name: "AI Assistant" },
    ],
    paths: {
      "/ai/config": {
        get: {
          tags: ["AI Config"],
          operationId: "getAIConfig",
          parameters: params,
          responses: {
            200: { description: "Tenant AI configuration.", content: media({ $ref: "#/components/schemas/AIConfigEnvelope" }) },
            400: err("Missing tenant scope."),
            500: err("Unhandled AI service failure."),
          },
        },
        put: {
          tags: ["AI Config"],
          operationId: "updateAIConfig",
          parameters: params,
          requestBody: { required: true, content: media({ $ref: "#/components/schemas/AIConfigUpdate" }) },
          responses: {
            200: { description: "Merged AI configuration.", content: media({ $ref: "#/components/schemas/AIConfigEnvelope" }) },
            400: err("Configuration validation failed."),
            500: err("Unhandled AI service failure."),
          },
        },
      },
      "/ai/query": {
        post: {
          tags: ["AI Assistant"],
          operationId: "queryAI",
          parameters: params,
          requestBody: { required: true, content: media({ $ref: "#/components/schemas/QueryRequest" }) },
          responses: {
            200: { description: "AI query result.", content: media({ $ref: "#/components/schemas/AIResultEnvelope" }) },
            400: err("Missing tenant or query."),
            500: err("Unhandled AI service failure."),
          },
        },
      },
      "/ai/analyze/incident": {
        post: {
          tags: ["AI Assistant"],
          operationId: "analyzeIncident",
          parameters: params,
          requestBody: { required: true, content: media({ $ref: "#/components/schemas/IncidentAnalysisRequest" }) },
          responses: {
            200: { description: "Incident analysis result.", content: media({ $ref: "#/components/schemas/AIResultEnvelope" }) },
            400: err("Missing tenant or malformed payload."),
            500: err("Unhandled AI service failure."),
          },
        },
      },
      "/ai/recommend/posture": {
        post: {
          tags: ["AI Assistant"],
          operationId: "recommendPosture",
          parameters: params,
          requestBody: { required: true, content: media({ $ref: "#/components/schemas/PostureRecommendationRequest" }) },
          responses: {
            200: { description: "Posture recommendation result.", content: media({ $ref: "#/components/schemas/AIResultEnvelope" }) },
            400: err("Missing tenant or malformed payload."),
            500: err("Unhandled AI service failure."),
          },
        },
      },
      "/ai/explain/policy": {
        post: {
          tags: ["AI Assistant"],
          operationId: "explainPolicy",
          parameters: params,
          requestBody: { required: true, content: media({ $ref: "#/components/schemas/PolicyExplainRequest" }) },
          responses: {
            200: { description: "Policy explanation result.", content: media({ $ref: "#/components/schemas/AIResultEnvelope" }) },
            400: err("Missing tenant or malformed payload."),
            500: err("Unhandled AI service failure."),
          },
        },
      },
    },
    components: buildAIComponents(),
  };
}

function buildSBOMComponents() {
  return {
    parameters: {
      RequestIdHeader: headerRequestId,
      TenantHeader: headerTenant,
      TenantQuery: queryTenant,
      LimitQuery: queryLimit,
      IdPath: pathId,
      SnapshotFrom: queryFrom,
      SnapshotTo: queryTo,
      SBOMExportFormat: querySbomFormat,
      SBOMExportEncoding: querySbomEncoding,
      CBOMExportFormat: queryCbomFormat,
    },
    schemas: {
      ErrorEnvelope: {
        type: "object",
        required: ["error"],
        properties: {
          error: {
            type: "object",
            required: ["code", "message", "request_id", "tenant_id"],
            properties: {
              code: { type: "string" },
              message: { type: "string" },
              request_id: { type: "string" },
              tenant_id: { type: "string" },
            },
          },
        },
      },
      JsonObject: objectAny,
      JsonObjectList: { type: "array", items: objectAny },
      BOMComponent: {
        type: "object",
        required: ["name", "version", "type", "purl", "supplier", "licenses", "hashes", "metadata", "ecosystem"],
        properties: {
          name: { type: "string" },
          version: { type: "string" },
          type: { type: "string" },
          purl: { type: "string" },
          supplier: { type: "string" },
          licenses: { type: "array", items: { type: "string" } },
          hashes: stringMap,
          metadata: stringMap,
          ecosystem: { type: "string" },
        },
      },
      SBOMSummary: {
        type: "object",
        required: ["appliance", "format", "spec_version", "component_count", "type_count", "generated_at"],
        properties: {
          appliance: { type: "string" },
          format: { type: "string" },
          spec_version: { type: "string" },
          component_count: { type: "integer", minimum: 0 },
          type_count: intMap,
          generated_at: isoDateTime,
        },
      },
      SBOMDocument: {
        type: "object",
        required: ["format", "spec_version", "generated_at", "appliance", "components"],
        properties: {
          format: { type: "string" },
          spec_version: { type: "string" },
          generated_at: isoDateTime,
          appliance: { type: "string" },
          components: { type: "array", items: { $ref: "#/components/schemas/BOMComponent" } },
        },
      },
      SBOMSnapshot: {
        type: "object",
        required: ["id", "source_hash", "created_at", "document", "summary"],
        properties: {
          id: { type: "string" },
          source_hash: { type: "string" },
          created_at: isoDateTime,
          document: { $ref: "#/components/schemas/SBOMDocument" },
          summary: { $ref: "#/components/schemas/SBOMSummary" },
        },
      },
      VulnerabilityMatch: {
        type: "object",
        required: ["id", "source", "severity", "component", "installed_version", "fixed_version", "summary", "reference"],
        properties: {
          id: { type: "string" },
          source: { type: "string", description: "Source label or merged source list, for example `OSV, Trivy`." },
          severity: { type: "string", enum: ["critical", "high", "medium", "low", "unknown"] },
          component: { type: "string" },
          installed_version: { type: "string" },
          fixed_version: { type: "string" },
          summary: { type: "string" },
          reference: { type: "string" },
        },
      },
      ManualAdvisory: {
        type: "object",
        required: ["id", "component", "ecosystem", "introduced_version", "fixed_version", "severity", "summary", "reference", "created_at", "updated_at"],
        properties: {
          id: { type: "string" },
          component: { type: "string" },
          ecosystem: { type: "string" },
          introduced_version: { type: "string" },
          fixed_version: { type: "string" },
          severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
          summary: { type: "string" },
          reference: { type: "string" },
          created_at: isoDateTime,
          updated_at: isoDateTime,
        },
      },
      ManualAdvisoryUpsert: {
        type: "object",
        required: ["component", "severity", "summary"],
        properties: {
          id: { type: "string" },
          component: { type: "string" },
          ecosystem: { type: "string" },
          introduced_version: { type: "string" },
          fixed_version: { type: "string" },
          severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
          summary: { type: "string" },
          reference: { type: "string" },
        },
      },
      CryptoAsset: {
        type: "object",
        required: ["id", "tenant_id", "source", "asset_type", "name", "algorithm", "strength_bits", "status", "pqc_ready", "deprecated", "metadata"],
        properties: {
          id: { type: "string" },
          tenant_id: { type: "string" },
          source: { type: "string" },
          asset_type: { type: "string" },
          name: { type: "string" },
          algorithm: { type: "string" },
          strength_bits: { type: "integer", minimum: 0 },
          status: { type: "string" },
          pqc_ready: { type: "boolean" },
          deprecated: { type: "boolean" },
          metadata: objectAny,
        },
      },
      CBOMSummary: {
        type: "object",
        required: ["tenant_id", "algorithm_distribution", "strength_histogram", "deprecated_count", "pqc_ready_count", "total_assets", "pqc_readiness_percent", "source_count"],
        properties: {
          tenant_id: { type: "string" },
          algorithm_distribution: intMap,
          strength_histogram: intMap,
          deprecated_count: { type: "integer", minimum: 0 },
          pqc_ready_count: { type: "integer", minimum: 0 },
          total_assets: { type: "integer", minimum: 0 },
          pqc_readiness_percent: { type: "number", minimum: 0, maximum: 100 },
          source_count: intMap,
        },
      },
      CBOMDocument: {
        type: "object",
        required: ["format", "spec_version", "tenant_id", "generated_at", "assets", "algorithm_distribution", "strength_histogram", "deprecated_count", "pqc_ready_count", "total_asset_count", "pqc_readiness_percent", "source_count", "metadata"],
        properties: {
          format: { type: "string" },
          spec_version: { type: "string" },
          tenant_id: { type: "string" },
          generated_at: isoDateTime,
          assets: { type: "array", items: { $ref: "#/components/schemas/CryptoAsset" } },
          algorithm_distribution: intMap,
          strength_histogram: intMap,
          deprecated_count: { type: "integer", minimum: 0 },
          pqc_ready_count: { type: "integer", minimum: 0 },
          total_asset_count: { type: "integer", minimum: 0 },
          pqc_readiness_percent: { type: "number", minimum: 0, maximum: 100 },
          source_count: intMap,
          metadata: stringMap,
        },
      },
      CBOMSnapshot: {
        type: "object",
        required: ["id", "tenant_id", "source_hash", "created_at", "document", "summary"],
        properties: {
          id: { type: "string" },
          tenant_id: { type: "string" },
          source_hash: { type: "string" },
          created_at: isoDateTime,
          document: { $ref: "#/components/schemas/CBOMDocument" },
          summary: { $ref: "#/components/schemas/CBOMSummary" },
        },
      },
      PQCReadiness: {
        type: "object",
        required: ["tenant_id", "pqc_ready_count", "total_assets", "pqc_readiness_percent", "status"],
        properties: {
          tenant_id: { type: "string" },
          pqc_ready_count: { type: "integer", minimum: 0 },
          total_assets: { type: "integer", minimum: 0 },
          pqc_readiness_percent: { type: "number", minimum: 0, maximum: 100 },
          status: { type: "string", enum: ["ready", "in_progress", "not_ready"] },
        },
      },
      BOMDiff: {
        type: "object",
        required: ["from_id", "to_id", "added", "removed", "changed", "metrics", "compared_at"],
        properties: {
          from_id: { type: "string" },
          to_id: { type: "string" },
          added: { $ref: "#/components/schemas/JsonObjectList" },
          removed: { $ref: "#/components/schemas/JsonObjectList" },
          changed: { $ref: "#/components/schemas/JsonObjectList" },
          metrics: objectAny,
          compared_at: isoDateTime,
        },
      },
      ExportArtifact: {
        type: "object",
        required: ["format", "content_type", "encoding", "content"],
        properties: {
          format: { type: "string" },
          content_type: { type: "string" },
          encoding: { type: "string" },
          content: { type: "string" },
        },
      },
      GenerateSBOMRequest: { type: "object", properties: { trigger: { type: "string" } } },
      GenerateCBOMRequest: { type: "object", properties: { tenant_id: { type: "string" }, trigger: { type: "string" } } },
      SBOMSnapshotEnvelope: { type: "object", required: ["item", "request_id"], properties: { item: { $ref: "#/components/schemas/SBOMSnapshot" }, request_id: { type: "string" } } },
      SBOMSnapshotListEnvelope: { type: "object", required: ["items", "request_id"], properties: { items: { type: "array", items: { $ref: "#/components/schemas/SBOMSnapshot" } }, request_id: { type: "string" } } },
      VulnerabilityListEnvelope: { type: "object", required: ["items", "request_id"], properties: { items: { type: "array", items: { $ref: "#/components/schemas/VulnerabilityMatch" } }, request_id: { type: "string" } } },
      ManualAdvisoryEnvelope: { type: "object", required: ["item", "request_id"], properties: { item: { $ref: "#/components/schemas/ManualAdvisory" }, request_id: { type: "string" } } },
      ManualAdvisoryListEnvelope: { type: "object", required: ["items", "request_id"], properties: { items: { type: "array", items: { $ref: "#/components/schemas/ManualAdvisory" } }, request_id: { type: "string" } } },
      DeleteEnvelope: { type: "object", required: ["status", "request_id"], properties: { status: { type: "string", enum: ["deleted"] }, request_id: { type: "string" } } },
      DiffEnvelope: { type: "object", required: ["diff", "request_id"], properties: { diff: { $ref: "#/components/schemas/BOMDiff" }, request_id: { type: "string" } } },
      ExportEnvelope: { type: "object", required: ["export", "request_id"], properties: { export: { $ref: "#/components/schemas/ExportArtifact" }, request_id: { type: "string" } } },
      CBOMSnapshotEnvelope: { type: "object", required: ["item", "request_id"], properties: { item: { $ref: "#/components/schemas/CBOMSnapshot" }, request_id: { type: "string" } } },
      CBOMSnapshotListEnvelope: { type: "object", required: ["items", "request_id"], properties: { items: { type: "array", items: { $ref: "#/components/schemas/CBOMSnapshot" } }, request_id: { type: "string" } } },
      CBOMSummaryEnvelope: { type: "object", required: ["summary", "request_id"], properties: { summary: { $ref: "#/components/schemas/CBOMSummary" }, request_id: { type: "string" } } },
      PQCReadinessEnvelope: { type: "object", required: ["pqc_readiness", "request_id"], properties: { pqc_readiness: { $ref: "#/components/schemas/PQCReadiness" }, request_id: { type: "string" } } },
    },
  };
}

function buildSBOMSpec() {
  const tenantParams = [
    { $ref: "#/components/parameters/RequestIdHeader" },
    { $ref: "#/components/parameters/TenantQuery" },
    { $ref: "#/components/parameters/TenantHeader" },
  ];

  return {
    openapi: "3.0.3",
    info: {
      title: "Vecta KMS SBOM and CBOM Service API",
      version: "1.0.0",
      description: "OpenAPI contract for SBOM generation, vulnerability correlation, offline advisories, and CBOM/PQC readiness. Use `/svc/sbom` through the dashboard proxy or `http://localhost:8180` directly.",
    },
    servers: [
      { url: "/svc/sbom", description: "Dashboard reverse proxy" },
      { url: "http://localhost:8180", description: "Direct SBOM service" },
    ],
    tags: [
      { name: "SBOM" },
      { name: "SBOM Advisories" },
      { name: "CBOM" },
    ],
    paths: {
      "/sbom/generate": {
        post: {
          tags: ["SBOM"],
          operationId: "generateSBOM",
          parameters: [{ $ref: "#/components/parameters/RequestIdHeader" }],
          requestBody: { required: false, content: media({ $ref: "#/components/schemas/GenerateSBOMRequest" }) },
          responses: {
            202: { description: "SBOM generation accepted.", content: media({ type: "object", required: ["status", "snapshot", "request_id"], properties: { status: { type: "string", enum: ["accepted"] }, snapshot: { $ref: "#/components/schemas/SBOMSnapshot" }, request_id: { type: "string" } } }) },
            500: err("Unhandled SBOM generation failure."),
          },
        },
      },
      "/sbom/latest": {
        get: {
          tags: ["SBOM"],
          operationId: "getLatestSBOM",
          parameters: [{ $ref: "#/components/parameters/RequestIdHeader" }],
          responses: {
            200: { description: "Latest SBOM snapshot.", content: media({ $ref: "#/components/schemas/SBOMSnapshotEnvelope" }) },
            404: err("No SBOM snapshot found."),
            500: err("Unhandled SBOM retrieval failure."),
          },
        },
      },
      "/sbom/history": {
        get: {
          tags: ["SBOM"],
          operationId: "listSBOMHistory",
          parameters: [{ $ref: "#/components/parameters/RequestIdHeader" }, { $ref: "#/components/parameters/LimitQuery" }],
          responses: {
            200: { description: "Historical SBOM snapshots.", content: media({ $ref: "#/components/schemas/SBOMSnapshotListEnvelope" }) },
            500: err("Unhandled SBOM history failure."),
          },
        },
      },
      "/sbom/vulnerabilities": {
        get: {
          tags: ["SBOM"],
          operationId: "listSBOMVulnerabilities",
          responses: {
            200: { description: "Merged Manual OSV, OSV, and Trivy findings.", content: media({ $ref: "#/components/schemas/VulnerabilityListEnvelope" }) },
            404: err("No SBOM snapshot found."),
            500: err("Unhandled vulnerability correlation failure."),
          },
        },
      },
      "/sbom/advisories": {
        get: {
          tags: ["SBOM Advisories"],
          operationId: "listManualAdvisories",
          responses: {
            200: { description: "Manual offline advisories.", content: media({ $ref: "#/components/schemas/ManualAdvisoryListEnvelope" }) },
            500: err("Unhandled advisory retrieval failure."),
          },
        },
        post: {
          tags: ["SBOM Advisories"],
          operationId: "saveManualAdvisory",
          requestBody: { required: true, content: media({ $ref: "#/components/schemas/ManualAdvisoryUpsert" }) },
          responses: {
            202: { description: "Manual advisory stored.", content: media({ $ref: "#/components/schemas/ManualAdvisoryEnvelope" }) },
            400: err("Advisory validation failed."),
            500: err("Unhandled advisory persistence failure."),
          },
        },
      },
      "/sbom/advisories/{id}": {
        delete: {
          tags: ["SBOM Advisories"],
          operationId: "deleteManualAdvisory",
          parameters: [{ $ref: "#/components/parameters/RequestIdHeader" }, { $ref: "#/components/parameters/IdPath" }],
          responses: {
            200: { description: "Manual advisory deleted.", content: media({ $ref: "#/components/schemas/DeleteEnvelope" }) },
            404: err("Manual advisory not found."),
            500: err("Unhandled advisory deletion failure."),
          },
        },
      },
      "/sbom/diff": {
        get: {
          tags: ["SBOM"],
          operationId: "diffSBOM",
          parameters: [{ $ref: "#/components/parameters/RequestIdHeader" }, { $ref: "#/components/parameters/SnapshotFrom" }, { $ref: "#/components/parameters/SnapshotTo" }],
          responses: {
            200: { description: "SBOM diff result.", content: media({ $ref: "#/components/schemas/DiffEnvelope" }) },
            400: err("Missing snapshot ids."),
            404: err("One or both SBOM snapshots were not found."),
            500: err("Unhandled SBOM diff failure."),
          },
        },
      },
      "/sbom/{id}/export": {
        get: {
          tags: ["SBOM"],
          operationId: "exportSBOM",
          parameters: [{ $ref: "#/components/parameters/RequestIdHeader" }, { $ref: "#/components/parameters/IdPath" }, { $ref: "#/components/parameters/SBOMExportFormat" }, { $ref: "#/components/parameters/SBOMExportEncoding" }],
          responses: {
            200: { description: "SBOM export payload.", content: media({ $ref: "#/components/schemas/ExportEnvelope" }) },
            400: err("Unsupported export format."),
            404: err("SBOM snapshot not found."),
            500: err("Unhandled SBOM export failure."),
          },
        },
      },
      "/sbom/{id}": {
        get: {
          tags: ["SBOM"],
          operationId: "getSBOMById",
          parameters: [{ $ref: "#/components/parameters/RequestIdHeader" }, { $ref: "#/components/parameters/IdPath" }],
          responses: {
            200: { description: "SBOM snapshot.", content: media({ $ref: "#/components/schemas/SBOMSnapshotEnvelope" }) },
            404: err("SBOM snapshot not found."),
            500: err("Unhandled SBOM retrieval failure."),
          },
        },
      },
      "/cbom/generate": {
        post: {
          tags: ["CBOM"],
          operationId: "generateCBOM",
          parameters: tenantParams,
          requestBody: { required: false, content: media({ $ref: "#/components/schemas/GenerateCBOMRequest" }) },
          responses: {
            202: { description: "CBOM generation accepted.", content: media({ type: "object", required: ["status", "snapshot", "request_id"], properties: { status: { type: "string", enum: ["accepted"] }, snapshot: { $ref: "#/components/schemas/CBOMSnapshot" }, request_id: { type: "string" } } }) },
            400: err("Missing tenant scope."),
            500: err("Unhandled CBOM generation failure."),
          },
        },
      },
      "/cbom/latest": {
        get: {
          tags: ["CBOM"],
          operationId: "getLatestCBOM",
          parameters: tenantParams,
          responses: {
            200: { description: "Latest CBOM snapshot.", content: media({ $ref: "#/components/schemas/CBOMSnapshotEnvelope" }) },
            400: err("Missing tenant scope."),
            404: err("No CBOM snapshot found."),
            500: err("Unhandled CBOM retrieval failure."),
          },
        },
      },
      "/cbom/history": {
        get: {
          tags: ["CBOM"],
          operationId: "listCBOMHistory",
          parameters: [...tenantParams, { $ref: "#/components/parameters/LimitQuery" }],
          responses: {
            200: { description: "Historical CBOM snapshots.", content: media({ $ref: "#/components/schemas/CBOMSnapshotListEnvelope" }) },
            400: err("Missing tenant scope."),
            500: err("Unhandled CBOM history failure."),
          },
        },
      },
      "/cbom/summary": {
        get: {
          tags: ["CBOM"],
          operationId: "getCBOMSummary",
          parameters: tenantParams,
          responses: {
            200: { description: "CBOM summary.", content: media({ $ref: "#/components/schemas/CBOMSummaryEnvelope" }) },
            400: err("Missing tenant scope."),
            404: err("No CBOM snapshot found."),
            500: err("Unhandled CBOM summary failure."),
          },
        },
      },
      "/cbom/pqc-readiness": {
        get: {
          tags: ["CBOM"],
          operationId: "getCBOMPQCReadiness",
          parameters: tenantParams,
          responses: {
            200: { description: "PQC readiness view.", content: media({ $ref: "#/components/schemas/PQCReadinessEnvelope" }) },
            400: err("Missing tenant scope."),
            404: err("No CBOM snapshot found."),
            500: err("Unhandled PQC readiness failure."),
          },
        },
      },
      "/cbom/diff": {
        get: {
          tags: ["CBOM"],
          operationId: "diffCBOM",
          parameters: [...tenantParams, { $ref: "#/components/parameters/SnapshotFrom" }, { $ref: "#/components/parameters/SnapshotTo" }],
          responses: {
            200: { description: "CBOM diff result.", content: media({ $ref: "#/components/schemas/DiffEnvelope" }) },
            400: err("Missing tenant scope or snapshot ids."),
            404: err("One or both CBOM snapshots were not found."),
            500: err("Unhandled CBOM diff failure."),
          },
        },
      },
      "/cbom/{id}/export": {
        get: {
          tags: ["CBOM"],
          operationId: "exportCBOM",
          parameters: [...tenantParams, { $ref: "#/components/parameters/IdPath" }, { $ref: "#/components/parameters/CBOMExportFormat" }],
          responses: {
            200: { description: "CBOM export payload.", content: media({ $ref: "#/components/schemas/ExportEnvelope" }) },
            400: err("Missing tenant scope or unsupported export format."),
            404: err("CBOM snapshot not found."),
            500: err("Unhandled CBOM export failure."),
          },
        },
      },
      "/cbom/{id}": {
        get: {
          tags: ["CBOM"],
          operationId: "getCBOMById",
          parameters: [...tenantParams, { $ref: "#/components/parameters/IdPath" }],
          responses: {
            200: { description: "CBOM snapshot.", content: media({ $ref: "#/components/schemas/CBOMSnapshotEnvelope" }) },
            400: err("Missing tenant scope."),
            404: err("CBOM snapshot not found."),
            500: err("Unhandled CBOM retrieval failure."),
          },
        },
      },
    },
    components: buildSBOMComponents(),
  };
}

function buildPostureComponents() {
  return {
    parameters: {
      RequestIdHeader: headerRequestId,
      TenantHeader: headerTenant,
      TenantQuery: queryTenant,
      LimitQuery: queryLimit,
      IdPath: pathId,
    },
    schemas: {
      ErrorEnvelope: {
        type: "object",
        required: ["error"],
        properties: {
          error: {
            type: "object",
            required: ["code", "message", "request_id", "tenant_id"],
            properties: {
              code: { type: "string" },
              message: { type: "string" },
              request_id: { type: "string" },
              tenant_id: { type: "string" },
            },
          },
        },
      },
      RiskSnapshot: {
        type: "object",
        properties: {
          id: { type: "string" },
          tenant_id: { type: "string" },
          risk_24h: { type: "integer" },
          risk_7d: { type: "integer" },
          predictive_score: { type: "integer" },
          preventive_score: { type: "integer" },
          corrective_score: { type: "integer" },
          top_signals: objectAny,
          captured_at: isoDateTime,
        },
      },
      RiskDriverContribution: {
        type: "object",
        properties: {
          id: { type: "string" },
          label: { type: "string" },
          domain: { type: "string" },
          delta_points: { type: "integer" },
          severity: { type: "string" },
          explanation: { type: "string" },
          evidence: objectAny,
        },
      },
      RiskDriverExplainer: {
        type: "object",
        properties: {
          current_risk_24h: { type: "integer" },
          previous_risk_24h: { type: "integer" },
          net_delta: { type: "integer" },
          summary: { type: "string" },
          drivers: { type: "array", items: { $ref: "#/components/schemas/RiskDriverContribution" } },
        },
      },
      BlastRadius: {
        type: "object",
        properties: {
          tenants: { type: "array", items: { type: "string" } },
          apps: { type: "array", items: { type: "string" } },
          services: { type: "array", items: { type: "string" } },
          resources: { type: "array", items: { type: "string" } },
          actors: { type: "array", items: { type: "string" } },
          event_count: { type: "integer" },
          last_seen_at: isoDateTime,
          summary: { type: "string" },
        },
      },
      RemediationImpact: {
        type: "object",
        properties: {
          risk_reduction: { type: "integer" },
          operational_cost: { type: "string" },
          time_to_apply: { type: "string" },
        },
      },
      Finding: {
        type: "object",
        properties: {
          id: { type: "string" },
          tenant_id: { type: "string" },
          engine: { type: "string" },
          finding_type: { type: "string" },
          title: { type: "string" },
          description: { type: "string" },
          severity: { type: "string" },
          risk_score: { type: "integer" },
          recommended_action: { type: "string" },
          auto_action_allowed: { type: "boolean" },
          status: { type: "string" },
          fingerprint: { type: "string" },
          evidence: objectAny,
          detected_at: isoDateTime,
          updated_at: isoDateTime,
          resolved_at: isoDateTime,
          sla_due_at: isoDateTime,
          reopen_count: { type: "integer" },
          risk_drivers: { type: "array", items: { $ref: "#/components/schemas/RiskDriverContribution" } },
          blast_radius: { $ref: "#/components/schemas/BlastRadius" },
        },
      },
      RemediationAction: {
        type: "object",
        properties: {
          id: { type: "string" },
          tenant_id: { type: "string" },
          finding_id: { type: "string" },
          action_type: { type: "string" },
          recommended_action: { type: "string" },
          safety_gate: { type: "string" },
          approval_required: { type: "boolean" },
          approval_request_id: { type: "string" },
          status: { type: "string" },
          executed_by: { type: "string" },
          executed_at: isoDateTime,
          evidence: objectAny,
          result_message: { type: "string" },
          created_at: isoDateTime,
          updated_at: isoDateTime,
          impact_estimate: { $ref: "#/components/schemas/RemediationImpact" },
          rollback_hint: { type: "string" },
          blast_radius: { $ref: "#/components/schemas/BlastRadius" },
          priority: { type: "string" },
        },
      },
      RemediationCockpitGroup: {
        type: "object",
        properties: {
          id: { type: "string" },
          label: { type: "string" },
          description: { type: "string" },
          count: { type: "integer" },
          actions: { type: "array", items: { $ref: "#/components/schemas/RemediationAction" } },
        },
      },
      ValidationBadge: {
        type: "object",
        properties: {
          domain: { type: "string" },
          kind: { type: "string" },
          label: { type: "string" },
          status: { type: "string" },
          detail: { type: "string" },
          last_checked_at: isoDateTime,
          last_success_at: isoDateTime,
          metric: { type: "number" },
        },
      },
      ScenarioSimulation: {
        type: "object",
        properties: {
          id: { type: "string" },
          label: { type: "string" },
          category: { type: "string" },
          action_type: { type: "string" },
          current_risk_24h: { type: "integer" },
          projected_risk_24h: { type: "integer" },
          risk_delta: { type: "integer" },
          summary: { type: "string" },
          impact_estimate: { type: "string" },
          rollback_hint: { type: "string" },
          approval_required: { type: "boolean" },
          based_on: { type: "array", items: { type: "string" } },
        },
      },
      SLAOverview: {
        type: "object",
        properties: {
          open_count: { type: "integer" },
          overdue_count: { type: "integer" },
          due_soon_count: { type: "integer" },
          average_age_hours: { type: "number" },
          breached_ids: { type: "array", items: { type: "string" } },
        },
      },
      PostureDashboard: {
        type: "object",
        properties: {
          risk: { $ref: "#/components/schemas/RiskSnapshot" },
          recent_findings: { type: "array", items: { $ref: "#/components/schemas/Finding" } },
          pending_actions: { type: "array", items: { $ref: "#/components/schemas/RemediationAction" } },
          open_findings: { type: "integer" },
          critical_findings: { type: "integer" },
          risk_drivers: { $ref: "#/components/schemas/RiskDriverExplainer" },
          remediation_cockpit: { type: "array", items: { $ref: "#/components/schemas/RemediationCockpitGroup" } },
          blast_radius: { type: "array", items: { $ref: "#/components/schemas/BlastRadius" } },
          scenario_simulator: { type: "array", items: { $ref: "#/components/schemas/ScenarioSimulation" } },
          validation_badges: { type: "array", items: { $ref: "#/components/schemas/ValidationBadge" } },
          sla_overview: { $ref: "#/components/schemas/SLAOverview" },
        },
      },
      PostureDashboardEnvelope: {
        type: "object",
        required: ["risk", "recent_findings", "pending_actions", "open_findings", "critical_findings", "risk_drivers", "remediation_cockpit", "blast_radius", "scenario_simulator", "validation_badges", "sla_overview", "request_id"],
        properties: {
          risk: { $ref: "#/components/schemas/RiskSnapshot" },
          recent_findings: { type: "array", items: { $ref: "#/components/schemas/Finding" } },
          pending_actions: { type: "array", items: { $ref: "#/components/schemas/RemediationAction" } },
          open_findings: { type: "integer" },
          critical_findings: { type: "integer" },
          risk_drivers: { $ref: "#/components/schemas/RiskDriverExplainer" },
          remediation_cockpit: { type: "array", items: { $ref: "#/components/schemas/RemediationCockpitGroup" } },
          blast_radius: { type: "array", items: { $ref: "#/components/schemas/BlastRadius" } },
          scenario_simulator: { type: "array", items: { $ref: "#/components/schemas/ScenarioSimulation" } },
          validation_badges: { type: "array", items: { $ref: "#/components/schemas/ValidationBadge" } },
          sla_overview: { $ref: "#/components/schemas/SLAOverview" },
          request_id: { type: "string" },
        },
      },
      FindingListEnvelope: {
        type: "object",
        required: ["items", "request_id"],
        properties: {
          items: { type: "array", items: { $ref: "#/components/schemas/Finding" } },
          request_id: { type: "string" },
        },
      },
      ActionListEnvelope: {
        type: "object",
        required: ["items", "request_id"],
        properties: {
          items: { type: "array", items: { $ref: "#/components/schemas/RemediationAction" } },
          request_id: { type: "string" },
        },
      },
      RiskEnvelope: {
        type: "object",
        required: ["risk", "request_id"],
        properties: {
          risk: { $ref: "#/components/schemas/RiskSnapshot" },
          request_id: { type: "string" },
        },
      },
      RiskHistoryEnvelope: {
        type: "object",
        required: ["items", "request_id"],
        properties: {
          items: { type: "array", items: { $ref: "#/components/schemas/RiskSnapshot" } },
          request_id: { type: "string" },
        },
      },
    },
  };
}

function buildPostureSpec() {
  const tenantParams = [
    { $ref: "#/components/parameters/RequestIdHeader" },
    { $ref: "#/components/parameters/TenantQuery" },
    { $ref: "#/components/parameters/TenantHeader" },
  ];

  return {
    openapi: "3.0.3",
    info: {
      title: "Vecta KMS Security Posture API",
      version: "1.0.0",
      description: "OpenAPI contract for posture dashboards, risk drivers, remediation cockpit, blast radius views, and scenario simulation. Use `/svc/posture` through the dashboard proxy or `http://localhost:8220` directly.",
    },
    servers: [
      { url: "/svc/posture", description: "Dashboard reverse proxy" },
      { url: "http://localhost:8220", description: "Direct posture service" },
    ],
    tags: [
      { name: "Posture Dashboard" },
      { name: "Posture Findings" },
      { name: "Posture Actions" },
    ],
    paths: {
      "/posture/dashboard": {
        get: {
          tags: ["Posture Dashboard"],
          operationId: "getPostureDashboard",
          parameters: tenantParams,
          responses: {
            200: { description: "Posture dashboard with risk drivers, remediation cockpit, blast radius, validation badges, and SLA overview.", content: media({ $ref: "#/components/schemas/PostureDashboardEnvelope" }) },
            500: err("Unhandled posture dashboard failure."),
          },
        },
      },
      "/posture/findings": {
        get: {
          tags: ["Posture Findings"],
          operationId: "listPostureFindings",
          parameters: [
            ...tenantParams,
            { name: "engine", in: "query", required: false, schema: { type: "string" } },
            { name: "status", in: "query", required: false, schema: { type: "string" } },
            { name: "severity", in: "query", required: false, schema: { type: "string" } },
            { $ref: "#/components/parameters/LimitQuery" },
          ],
          responses: {
            200: { description: "Filtered posture findings.", content: media({ $ref: "#/components/schemas/FindingListEnvelope" }) },
            400: err("Missing tenant scope."),
            500: err("Unhandled posture findings failure."),
          },
        },
      },
      "/posture/actions": {
        get: {
          tags: ["Posture Actions"],
          operationId: "listPostureActions",
          parameters: [
            ...tenantParams,
            { name: "status", in: "query", required: false, schema: { type: "string" } },
            { name: "action_type", in: "query", required: false, schema: { type: "string" } },
            { $ref: "#/components/parameters/LimitQuery" },
          ],
          responses: {
            200: { description: "Remediation actions, including approval-required and manual actions.", content: media({ $ref: "#/components/schemas/ActionListEnvelope" }) },
            400: err("Missing tenant scope."),
            500: err("Unhandled posture action failure."),
          },
        },
      },
      "/posture/risk": {
        get: {
          tags: ["Posture Dashboard"],
          operationId: "getLatestPostureRisk",
          parameters: tenantParams,
          responses: {
            200: { description: "Latest risk snapshot.", content: media({ $ref: "#/components/schemas/RiskEnvelope" }) },
            500: err("Unhandled posture risk failure."),
          },
        },
      },
      "/posture/risk/history": {
        get: {
          tags: ["Posture Dashboard"],
          operationId: "listPostureRiskHistory",
          parameters: [...tenantParams, { $ref: "#/components/parameters/LimitQuery" }],
          responses: {
            200: { description: "Historical risk snapshots.", content: media({ $ref: "#/components/schemas/RiskHistoryEnvelope" }) },
            500: err("Unhandled posture history failure."),
          },
        },
      },
      "/posture/scan": {
        post: {
          tags: ["Posture Dashboard"],
          operationId: "runPostureScan",
          parameters: [
            ...tenantParams,
            { name: "sync_audit", in: "query", required: false, schema: { type: "boolean", default: false } },
          ],
          responses: {
            200: { description: "Manual posture scan result.", content: media({ type: "object", required: ["risk", "tenant_id", "request_id"], properties: { risk: { $ref: "#/components/schemas/RiskSnapshot" }, tenant_id: { type: "string" }, request_id: { type: "string" } } }) },
            400: err("Missing tenant scope."),
            500: err("Unhandled posture scan failure."),
          },
        },
      },
      "/posture/actions/{id}/execute": {
        post: {
          tags: ["Posture Actions"],
          operationId: "executePostureAction",
          parameters: [...tenantParams, { $ref: "#/components/parameters/IdPath" }],
          requestBody: {
            required: false,
            content: media({
              type: "object",
              properties: {
                actor: { type: "string" },
                approval_request_id: { type: "string" },
              },
            }),
          },
          responses: {
            200: { description: "Action execution accepted.", content: media({ type: "object", required: ["ok", "request_id"], properties: { ok: { type: "boolean" }, request_id: { type: "string" } } }) },
            400: err("Missing tenant scope or malformed payload."),
            500: err("Unhandled posture action execution failure."),
          },
        },
      },
    },
    components: buildPostureComponents(),
  };
}

function buildComplianceComponents() {
  return {
    parameters: {
      RequestIdHeader: headerRequestId,
      TenantHeader: headerTenant,
      TenantQuery: queryTenant,
      LimitQuery: queryLimit,
      IdPath: pathId,
    },
    schemas: {
      ErrorEnvelope: {
        type: "object",
        required: ["error"],
        properties: {
          error: {
            type: "object",
            required: ["code", "message", "request_id", "tenant_id"],
            properties: {
              code: { type: "string" },
              message: { type: "string" },
              request_id: { type: "string" },
              tenant_id: { type: "string" },
            },
          },
        },
      },
      AssessmentResult: {
        type: "object",
        properties: {
          id: { type: "string" },
          tenant_id: { type: "string" },
          trigger: { type: "string" },
          template_id: { type: "string" },
          template_name: { type: "string" },
          overall_score: { type: "integer" },
          framework_scores: intMap,
          findings: { type: "array", items: objectAny },
          pqc: objectAny,
          cert_metrics: { type: "object", additionalProperties: { type: "number" } },
          posture: objectAny,
          created_at: isoDateTime,
        },
      },
      AssessmentFindingDelta: {
        type: "object",
        properties: {
          title: { type: "string" },
          severity: { type: "string" },
          current_count: { type: "integer" },
          previous_count: { type: "integer" },
          delta: { type: "integer" },
        },
      },
      AssessmentDomainDelta: {
        type: "object",
        properties: {
          domain: { type: "string" },
          label: { type: "string" },
          current_score: { type: "integer" },
          previous_score: { type: "integer" },
          delta: { type: "integer" },
          status: { type: "string" },
        },
      },
      AssessmentConnectorDelta: {
        type: "object",
        properties: {
          connector: { type: "string" },
          label: { type: "string" },
          current_fails: { type: "integer" },
          previous_fails: { type: "integer" },
          delta: { type: "integer" },
          last_failure_at: isoDateTime,
          status: { type: "string" },
        },
      },
      AssessmentDelta: {
        type: "object",
        properties: {
          latest_assessment_id: { type: "string" },
          previous_assessment_id: { type: "string" },
          latest_score: { type: "integer" },
          previous_score: { type: "integer" },
          score_delta: { type: "integer" },
          summary: { type: "string" },
          added_findings: { type: "array", items: { $ref: "#/components/schemas/AssessmentFindingDelta" } },
          resolved_findings: { type: "array", items: { $ref: "#/components/schemas/AssessmentFindingDelta" } },
          recovered_domains: { type: "array", items: { $ref: "#/components/schemas/AssessmentDomainDelta" } },
          regressed_domains: { type: "array", items: { $ref: "#/components/schemas/AssessmentDomainDelta" } },
          new_failing_connectors: { type: "array", items: { $ref: "#/components/schemas/AssessmentConnectorDelta" } },
          compared_at: isoDateTime,
        },
      },
      ComplianceTemplate: {
        type: "object",
        properties: {
          id: { type: "string" },
          tenant_id: { type: "string" },
          name: { type: "string" },
          description: { type: "string" },
          enabled: { type: "boolean" },
          frameworks: { type: "array", items: objectAny },
          created_at: isoDateTime,
          updated_at: isoDateTime,
        },
      },
      AssessmentEnvelope: {
        type: "object",
        required: ["assessment", "request_id"],
        properties: {
          assessment: { $ref: "#/components/schemas/AssessmentResult" },
          request_id: { type: "string" },
        },
      },
      AssessmentHistoryEnvelope: {
        type: "object",
        required: ["items", "request_id"],
        properties: {
          items: { type: "array", items: { $ref: "#/components/schemas/AssessmentResult" } },
          request_id: { type: "string" },
        },
      },
      AssessmentDeltaEnvelope: {
        type: "object",
        required: ["delta", "request_id"],
        properties: {
          delta: { $ref: "#/components/schemas/AssessmentDelta" },
          request_id: { type: "string" },
        },
      },
      ComplianceTemplateListEnvelope: {
        type: "object",
        required: ["items", "request_id"],
        properties: {
          items: { type: "array", items: { $ref: "#/components/schemas/ComplianceTemplate" } },
          request_id: { type: "string" },
        },
      },
    },
  };
}

function buildComplianceSpec() {
  const tenantParams = [
    { $ref: "#/components/parameters/RequestIdHeader" },
    { $ref: "#/components/parameters/TenantQuery" },
    { $ref: "#/components/parameters/TenantHeader" },
  ];

  return {
    openapi: "3.0.3",
    info: {
      title: "Vecta KMS Compliance API",
      version: "1.0.0",
      description: "OpenAPI contract for compliance posture, assessment runs, delta views, and template-driven framework scoring. Use `/svc/compliance` through the dashboard proxy or `http://localhost:8110` directly.",
    },
    servers: [
      { url: "/svc/compliance", description: "Dashboard reverse proxy" },
      { url: "http://localhost:8110", description: "Direct compliance service" },
    ],
    tags: [
      { name: "Compliance Posture" },
      { name: "Compliance Assessments" },
      { name: "Compliance Templates" },
    ],
    paths: {
      "/compliance/posture": {
        get: {
          tags: ["Compliance Posture"],
          operationId: "getCompliancePosture",
          parameters: [
            ...tenantParams,
            { name: "refresh", in: "query", required: false, schema: { type: "boolean", default: false } },
          ],
          responses: {
            200: { description: "Current compliance posture snapshot.", content: media({ type: "object", required: ["posture", "request_id"], properties: { posture: objectAny, request_id: { type: "string" } } }) },
            400: err("Missing tenant scope."),
            500: err("Unhandled compliance posture failure."),
          },
        },
      },
      "/compliance/assessment": {
        get: {
          tags: ["Compliance Assessments"],
          operationId: "getLatestComplianceAssessment",
          parameters: [
            ...tenantParams,
            { name: "template_id", in: "query", required: false, schema: { type: "string" } },
          ],
          responses: {
            200: { description: "Latest non-auto assessment.", content: media({ $ref: "#/components/schemas/AssessmentEnvelope" }) },
            400: err("Missing tenant scope."),
            404: err("No compliance assessment exists yet."),
            500: err("Unhandled assessment retrieval failure."),
          },
        },
      },
      "/compliance/assessment/delta": {
        get: {
          tags: ["Compliance Assessments"],
          operationId: "getComplianceAssessmentDelta",
          parameters: [
            ...tenantParams,
            { name: "template_id", in: "query", required: false, schema: { type: "string" } },
          ],
          responses: {
            200: { description: "Delta between the latest and previous real assessments.", content: media({ $ref: "#/components/schemas/AssessmentDeltaEnvelope" }) },
            400: err("Missing tenant scope."),
            404: err("No compliance assessment exists yet."),
            500: err("Unhandled assessment delta failure."),
          },
        },
      },
      "/compliance/assessment/run": {
        post: {
          tags: ["Compliance Assessments"],
          operationId: "runComplianceAssessment",
          parameters: tenantParams,
          requestBody: {
            required: false,
            content: media({
              type: "object",
              properties: {
                template_id: { type: "string" },
                recompute: { type: "boolean", default: true },
              },
            }),
          },
          responses: {
            200: { description: "Manual compliance assessment result.", content: media({ $ref: "#/components/schemas/AssessmentEnvelope" }) },
            400: err("Missing tenant scope or malformed payload."),
            500: err("Unhandled assessment run failure."),
          },
        },
      },
      "/compliance/assessment/history": {
        get: {
          tags: ["Compliance Assessments"],
          operationId: "listComplianceAssessmentHistory",
          parameters: [
            ...tenantParams,
            { name: "template_id", in: "query", required: false, schema: { type: "string" } },
            { $ref: "#/components/parameters/LimitQuery" },
          ],
          responses: {
            200: { description: "Assessment history for the selected template scope.", content: media({ $ref: "#/components/schemas/AssessmentHistoryEnvelope" }) },
            400: err("Missing tenant scope."),
            500: err("Unhandled assessment history failure."),
          },
        },
      },
      "/compliance/templates": {
        get: {
          tags: ["Compliance Templates"],
          operationId: "listComplianceTemplates",
          parameters: tenantParams,
          responses: {
            200: { description: "Saved compliance templates.", content: media({ $ref: "#/components/schemas/ComplianceTemplateListEnvelope" }) },
            400: err("Missing tenant scope."),
            500: err("Unhandled template retrieval failure."),
          },
        },
      },
    },
    components: buildComplianceComponents(),
  };
}

function buildReportingComponents() {
  return {
    parameters: {
      RequestIdHeader: headerRequestId,
      TenantHeader: headerTenant,
      TenantQuery: queryTenant,
      LimitQuery: queryLimit,
      IdPath: pathId,
    },
    schemas: {
      ErrorEnvelope: {
        type: "object",
        required: ["error"],
        properties: {
          error: {
            type: "object",
            required: ["code", "message", "request_id", "tenant_id"],
            properties: {
              code: { type: "string" },
              message: { type: "string" },
              request_id: { type: "string" },
              tenant_id: { type: "string" },
            },
          },
        },
      },
      ReportTemplate: {
        type: "object",
        properties: {
          id: { type: "string" },
          name: { type: "string" },
          description: { type: "string" },
          formats: { type: "array", items: { type: "string" } },
        },
      },
      ReportJob: {
        type: "object",
        properties: {
          id: { type: "string" },
          tenant_id: { type: "string" },
          template_id: { type: "string" },
          format: { type: "string" },
          status: { type: "string" },
          filters: objectAny,
          result_content: { type: "string" },
          result_content_type: { type: "string" },
          requested_by: { type: "string" },
          error: { type: "string" },
          created_at: isoDateTime,
          updated_at: isoDateTime,
          completed_at: isoDateTime,
        },
      },
      ReportTemplateListEnvelope: {
        type: "object",
        required: ["items", "request_id"],
        properties: {
          items: { type: "array", items: { $ref: "#/components/schemas/ReportTemplate" } },
          request_id: { type: "string" },
        },
      },
      ReportJobEnvelope: {
        type: "object",
        required: ["job", "request_id"],
        properties: {
          job: { $ref: "#/components/schemas/ReportJob" },
          request_id: { type: "string" },
        },
      },
      ReportJobListEnvelope: {
        type: "object",
        required: ["items", "request_id"],
        properties: {
          items: { type: "array", items: { $ref: "#/components/schemas/ReportJob" } },
          request_id: { type: "string" },
        },
      },
      MTTDEnvelope: {
        type: "object",
        required: ["mttd_minutes", "request_id"],
        properties: {
          mttd_minutes: { type: "object", additionalProperties: { type: "number" } },
          request_id: { type: "string" },
        },
      },
      MTTREnvelope: {
        type: "object",
        required: ["mttr_minutes", "request_id"],
        properties: {
          mttr_minutes: { type: "object", additionalProperties: { type: "number" } },
          request_id: { type: "string" },
        },
      },
      TopSourcesEnvelope: {
        type: "object",
        required: ["sources", "request_id"],
        properties: {
          top_actors: { type: "array", items: objectAny },
          top_ips: { type: "array", items: objectAny },
          top_services: { type: "array", items: objectAny },
          sources: objectAny,
          request_id: { type: "string" },
        },
      },
    },
  };
}

function buildReportingSpec() {
  const tenantParams = [
    { $ref: "#/components/parameters/RequestIdHeader" },
    { $ref: "#/components/parameters/TenantQuery" },
    { $ref: "#/components/parameters/TenantHeader" },
  ];

  return {
    openapi: "3.0.3",
    info: {
      title: "Vecta KMS Reporting and Alerting API",
      version: "1.0.0",
      description: "OpenAPI contract for report templates, evidence-pack generation, report jobs, and alert timing analytics including MTTD. Use `/svc/reporting` through the dashboard proxy or `http://localhost:8140` directly.",
    },
    servers: [
      { url: "/svc/reporting", description: "Dashboard reverse proxy" },
      { url: "http://localhost:8140", description: "Direct reporting service" },
    ],
    tags: [
      { name: "Reporting" },
      { name: "Reporting Stats" },
    ],
    paths: {
      "/reports/templates": {
        get: {
          tags: ["Reporting"],
          operationId: "listReportTemplates",
          parameters: [{ $ref: "#/components/parameters/RequestIdHeader" }],
          responses: {
            200: { description: "Available report templates, including Evidence Pack.", content: media({ $ref: "#/components/schemas/ReportTemplateListEnvelope" }) },
            500: err("Unhandled template retrieval failure."),
          },
        },
      },
      "/reports/generate": {
        post: {
          tags: ["Reporting"],
          operationId: "generateReport",
          parameters: tenantParams,
          requestBody: {
            required: true,
            content: media({
              type: "object",
              required: ["tenant_id", "template_id"],
              properties: {
                tenant_id: { type: "string", example: "root" },
                template_id: { type: "string", enum: ["key_generation", "key_rotation", "kms_operations", "hyok_activity", "byok_activity", "certificate_lifecycle", "compliance_audit", "posture_summary", "evidence_pack", "alert_summary", "custom"] },
                format: { type: "string", enum: ["pdf", "csv", "json"], default: "pdf" },
                requested_by: { type: "string" },
                filters: objectAny,
              },
            }),
          },
          responses: {
            202: { description: "Report generation queued.", content: media({ $ref: "#/components/schemas/ReportJobEnvelope" }) },
            400: err("Missing tenant scope or malformed payload."),
            500: err("Unhandled report generation failure."),
          },
        },
      },
      "/reports/jobs": {
        get: {
          tags: ["Reporting"],
          operationId: "listReportJobs",
          parameters: [...tenantParams, { $ref: "#/components/parameters/LimitQuery" }],
          responses: {
            200: { description: "Report jobs for the current tenant.", content: media({ $ref: "#/components/schemas/ReportJobListEnvelope" }) },
            400: err("Missing tenant scope."),
            500: err("Unhandled report job listing failure."),
          },
        },
      },
      "/reports/jobs/{id}": {
        get: {
          tags: ["Reporting"],
          operationId: "getReportJob",
          parameters: [...tenantParams, { $ref: "#/components/parameters/IdPath" }],
          responses: {
            200: { description: "Single report job state.", content: media({ $ref: "#/components/schemas/ReportJobEnvelope" }) },
            400: err("Missing tenant scope."),
            404: err("Report job not found."),
            500: err("Unhandled report job retrieval failure."),
          },
        },
      },
      "/reports/jobs/{id}/download": {
        get: {
          tags: ["Reporting"],
          operationId: "downloadReportJob",
          parameters: [...tenantParams, { $ref: "#/components/parameters/IdPath" }],
          responses: {
            200: { description: "Completed report content.", content: media({ type: "object", required: ["content", "content_type", "template_id", "generated_at", "report_job_id", "request_id"], properties: { content: { type: "string" }, content_type: { type: "string" }, template_id: { type: "string" }, generated_at: isoDateTime, report_job_id: { type: "string" }, request_id: { type: "string" } } }) },
            400: err("Missing tenant scope."),
            404: err("Report job not found."),
            409: err("Report job is not completed yet."),
            500: err("Unhandled report download failure."),
          },
        },
      },
      "/alerts/stats/mttd": {
        get: {
          tags: ["Reporting Stats"],
          operationId: "getMTTDStats",
          parameters: tenantParams,
          responses: {
            200: { description: "Mean time to detect by severity.", content: media({ $ref: "#/components/schemas/MTTDEnvelope" }) },
            400: err("Missing tenant scope."),
            500: err("Unhandled MTTD retrieval failure."),
          },
        },
      },
      "/alerts/stats/mttr": {
        get: {
          tags: ["Reporting Stats"],
          operationId: "getMTTRStats",
          parameters: tenantParams,
          responses: {
            200: { description: "Mean time to resolve by severity.", content: media({ $ref: "#/components/schemas/MTTREnvelope" }) },
            400: err("Missing tenant scope."),
            500: err("Unhandled MTTR retrieval failure."),
          },
        },
      },
      "/alerts/stats/top-sources": {
        get: {
          tags: ["Reporting Stats"],
          operationId: "getTopAlertSources",
          parameters: tenantParams,
          responses: {
            200: { description: "Top alert-producing actors, IPs, and services.", content: media({ $ref: "#/components/schemas/TopSourcesEnvelope" }) },
            400: err("Missing tenant scope."),
            500: err("Unhandled top-source retrieval failure."),
          },
        },
      },
    },
    components: buildReportingComponents(),
  };
}

async function writeSpec(name, spec) {
  const yaml = YAML.stringify(spec);
  const json = `${JSON.stringify(spec, null, 2)}\n`;
  await fs.mkdir(docsOutDir, { recursive: true });
  await fs.mkdir(publicOutDir, { recursive: true });
  await fs.writeFile(path.join(docsOutDir, `${name}.openapi.yaml`), yaml, "utf8");
  await fs.writeFile(path.join(docsOutDir, `${name}.openapi.json`), json, "utf8");
  await fs.writeFile(path.join(publicOutDir, `${name}.openapi.yaml`), yaml, "utf8");
  await fs.writeFile(path.join(publicOutDir, `${name}.openapi.json`), json, "utf8");
}

async function copySwaggerUIAssets() {
  const targetDir = path.join(publicOutDir, "swagger-ui");
  await fs.mkdir(targetDir, { recursive: true });
  const files = [
    "swagger-ui.css",
    "swagger-ui-bundle.js",
    "swagger-ui-standalone-preset.js",
  ];
  for (const file of files) {
    await fs.copyFile(path.join(swaggerUiDistDir, file), path.join(targetDir, file));
  }
}

function viewerHTML(title, specFile) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <link rel="stylesheet" href="./swagger-ui/swagger-ui.css" />
  <style>
    body { margin: 0; background: #060a11; color: #e2e8f0; font-family: system-ui, sans-serif; }
    .topbar { display: flex; align-items: center; justify-content: space-between; padding: 12px 18px; border-bottom: 1px solid #1a2944; background: linear-gradient(90deg, rgba(6,214,224,.12), rgba(15,21,33,.95)); }
    .title { font-size: 14px; font-weight: 700; color: #06d6e0; }
    .links a { color: #94a3b8; text-decoration: none; margin-left: 12px; font-size: 12px; }
    .links a:hover { color: #06d6e0; }
    #swagger-ui { min-height: calc(100vh - 54px); }
  </style>
</head>
<body>
  <div class="topbar">
    <div class="title">${title}</div>
    <div class="links">
      <a href="./${specFile.replace(".json", ".yaml")}" target="_blank" rel="noreferrer">YAML</a>
      <a href="./${specFile}" target="_blank" rel="noreferrer">JSON</a>
    </div>
  </div>
  <div id="swagger-ui"></div>
  <script src="./swagger-ui/swagger-ui-bundle.js"></script>
  <script src="./swagger-ui/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function () {
      window.ui = SwaggerUIBundle({
        url: "./${specFile}",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
        layout: "StandaloneLayout",
        docExpansion: "list",
        defaultModelsExpandDepth: 1,
        displayRequestDuration: true
      });
    };
  </script>
</body>
</html>
`;
}

async function writeViewerPages() {
  await fs.mkdir(publicOutDir, { recursive: true });
  await fs.writeFile(path.join(publicOutDir, "ai.html"), viewerHTML("Vecta KMS AI Service OpenAPI", "ai.openapi.json"), "utf8");
  await fs.writeFile(path.join(publicOutDir, "sbom.html"), viewerHTML("Vecta KMS SBOM / CBOM OpenAPI", "sbom.openapi.json"), "utf8");
  await fs.writeFile(path.join(publicOutDir, "posture.html"), viewerHTML("Vecta KMS Security Posture OpenAPI", "posture.openapi.json"), "utf8");
  await fs.writeFile(path.join(publicOutDir, "compliance.html"), viewerHTML("Vecta KMS Compliance OpenAPI", "compliance.openapi.json"), "utf8");
  await fs.writeFile(path.join(publicOutDir, "reporting.html"), viewerHTML("Vecta KMS Reporting OpenAPI", "reporting.openapi.json"), "utf8");
}

async function main() {
  await writeSpec("ai", buildAISpec());
  await writeSpec("sbom", buildSBOMSpec());
  await writeSpec("posture", buildPostureSpec());
  await writeSpec("compliance", buildComplianceSpec());
  await writeSpec("reporting", buildReportingSpec());
  await copySwaggerUIAssets();
  await writeViewerPages();
  console.log(`Generated OpenAPI specs -> ${docsOutDir} and ${publicOutDir}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
