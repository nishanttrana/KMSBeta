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

// kernelRoutes documents routes served by the pkg/route kernel: a verified
// bearer token is required, the tenant is the token's (a named tenant must
// match it; kms-* service principals act for the tenant they name), and each
// request is audited as audit.<service>.<action>, refusals included. Every
// listed route must be in the spec, so the two can't drift apart silently.
function kernelRoutes(spec, service, routes) {
  spec.security = [{ bearerAuth: [] }];
  spec.components.securitySchemes = { bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" } };
  for (const [key, [perm, action, note]] of Object.entries(routes)) {
    const [method, route] = key.split(" ");
    const op = spec.paths[route]?.[method.toLowerCase()];
    if (!op) throw new Error(`${service}: ${key} is not in the spec`);
    op.description = [op.description, `Permission \`${perm}\`. Audited as \`audit.${service}.${action}\`, refusals included (\`reason\` = \`unauthenticated\`, \`permission_denied\`, \`tenant_mismatch\`, \`tenant_conflict\`).`, note]
      .filter(Boolean)
      .join(" ");
    op.responses[401] ??= err("No valid bearer token (reason `unauthenticated`).");
    op.responses[403] ??= err("Missing permission, or a tenant other than the token's.");
  }
  return spec;
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
      GenerateSBOMRequest: { type: "object", properties: { trigger: { type: "string" } } },
      GenerateCBOMRequest: { type: "object", properties: { trigger: { type: "string" } } },
      SBOMSnapshotEnvelope: { type: "object", required: ["item", "request_id"], properties: { item: { $ref: "#/components/schemas/SBOMSnapshot" }, request_id: { type: "string" } } },
      SBOMSnapshotListEnvelope: { type: "object", required: ["items", "request_id"], properties: { items: { type: "array", items: { $ref: "#/components/schemas/SBOMSnapshot" } }, request_id: { type: "string" } } },
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
  const platformWrite = "The platform SBOM is shared by every tenant: only the platform tenant (or a tenant-less root token or kms-* service principal) may change it; anyone else is refused with reason `platform_tenant_required`.";
  return kernelRoutes(sbomPaths(), "sbom", {
    "POST /sbom/generate": ["sbom.write", "sbom_generate_requested", platformWrite],
    "GET /sbom/latest": ["sbom.read", "sbom_latest_read"],
    "GET /sbom/history": ["sbom.read", "sbom_history_listed"],
    "GET /sbom/diff": ["sbom.read", "sbom_diff_read"],
    "GET /sbom/{id}/export": ["sbom.read", "sbom_exported"],
    "GET /sbom/{id}": ["sbom.read", "sbom_read"],
    "POST /cbom/generate": ["sbom.write", "cbom_generate_requested", "The CBOM is built for the token's tenant; `tenant_id` is no longer read from the body."],
    "GET /cbom/latest": ["sbom.read", "cbom_latest_read"],
    "GET /cbom/history": ["sbom.read", "cbom_history_listed"],
    "GET /cbom/summary": ["sbom.read", "cbom_summary_read"],
    "GET /cbom/pqc-readiness": ["sbom.read", "cbom_pqc_readiness_read"],
    "GET /cbom/diff": ["sbom.read", "cbom_diff_read"],
    "GET /cbom/{id}/export": ["sbom.read", "cbom_exported"],
    "GET /cbom/{id}": ["sbom.read", "cbom_read"],
  });
}

function sbomPaths() {
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
      description: "OpenAPI contract for SBOM generation, history, diff and export, and CBOM/PQC readiness. Served at `/svc/sbom` through the Envoy edge.",
    },
    servers: [
      { url: "/svc/sbom", description: "Envoy edge" },
    ],
    tags: [
      { name: "SBOM" },
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
      PostureEvent: {
        type: "object",
        required: ["service", "action"],
        additionalProperties: false,
        properties: {
          id: { type: "string" },
          timestamp: isoDateTime,
          tenant_id: { type: "string", description: "Optional; must equal the request tenant (the token's)." },
          service: { type: "string" },
          action: { type: "string" },
          result: { type: "string" },
          severity: { type: "string" },
          actor: { type: "string", description: "The actor the event describes (data), not the caller's identity." },
          ip: { type: "string" },
          request_id: { type: "string" },
          resource_id: { type: "string" },
          error_code: { type: "string" },
          latency_ms: { type: "number" },
          node_id: { type: "string" },
          details: objectAny,
          created_at: isoDateTime,
        },
      },
      IngestEnvelope: {
        type: "object",
        required: ["inserted", "request_id"],
        properties: {
          inserted: { type: "integer" },
          tenant_id: { type: "string" },
          request_id: { type: "string" },
        },
      },
    },
    securitySchemes: {
      bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
    },
  };
}

function buildPostureSpec() {
  const tenantParams = [
    { $ref: "#/components/parameters/RequestIdHeader" },
    { $ref: "#/components/parameters/TenantQuery" },
    { $ref: "#/components/parameters/TenantHeader" },
  ];
  // Every route is on the pkg/route kernel: a verified JWT is required, the
  // tenant is the token's (a named tenant must match it), and each request is
  // audited as audit.posture.<action>, refusals included.
  const kernel = (perm, action) =>
    `Permission \`${perm}\`. Audited as \`audit.posture.${action}\`, refusals included (\`reason\` = \`unauthenticated\`, \`permission_denied\`, \`tenant_mismatch\`, \`tenant_conflict\`, \`tenant_wildcard\`).`;
  const refusals = {
    400: err("tenant_id missing (service principals must name one) or malformed request."),
    401: err("No valid bearer token (reason unauthenticated)."),
    403: err("Missing permission, a tenant other than the token's, or the wildcard tenant `*`/`all`."),
    500: err("Internal failure (no detail is returned)."),
  };
  const ok = (description, schema) => ({ 200: { description, content: media(schema) } });

  return {
    openapi: "3.0.3",
    info: {
      title: "Vecta KMS Security Posture API",
      version: "2.0.0",
      description: "OpenAPI contract for posture dashboards, risk drivers, remediation cockpit, blast radius views, and what-if risk projections for pending remediation actions. Served at `/svc/posture` through the Envoy edge. Every route requires a verified bearer token; the tenant is bound from it. Internal callers use their kms-* service identity.",
    },
    servers: [
      { url: "/svc/posture", description: "Envoy edge" },
    ],
    security: [{ bearerAuth: [] }],
    tags: [
      { name: "Posture Dashboard" },
      { name: "Posture Events" },
      { name: "Posture Findings" },
      { name: "Posture Actions" },
    ],
    paths: {
      "/posture/health": {
        get: {
          tags: ["Posture Dashboard"],
          operationId: "getPostureHealth",
          description: "Any verified identity. Audited as `audit.posture.health_read`.",
          parameters: [{ $ref: "#/components/parameters/RequestIdHeader" }],
          responses: {
            ...ok("Service is up.", { type: "object", properties: { status: { type: "string" }, service: { type: "string" }, request_id: { type: "string" } } }),
            401: refusals[401],
          },
        },
      },
      "/posture/dashboard": {
        get: {
          tags: ["Posture Dashboard"],
          operationId: "getPostureDashboard",
          description: kernel("posture.read", "dashboard_viewed"),
          parameters: tenantParams,
          responses: {
            ...ok("Posture dashboard with risk drivers, remediation cockpit, blast radius, validation badges, and SLA overview.", { $ref: "#/components/schemas/PostureDashboardEnvelope" }),
            ...refusals,
          },
        },
      },
      "/posture/risk": {
        get: {
          tags: ["Posture Dashboard"],
          operationId: "getLatestPostureRisk",
          description: kernel("posture.read", "risk_read") + " A tenant never scanned returns an empty snapshot for that tenant.",
          parameters: tenantParams,
          responses: {
            ...ok("Latest risk snapshot of the tenant.", { $ref: "#/components/schemas/RiskEnvelope" }),
            ...refusals,
          },
        },
      },
      "/posture/risk/history": {
        get: {
          tags: ["Posture Dashboard"],
          operationId: "listPostureRiskHistory",
          description: kernel("posture.read", "risk_history_read"),
          parameters: [...tenantParams, { $ref: "#/components/parameters/LimitQuery" }, { name: "offset", in: "query", required: false, schema: { type: "integer", minimum: 0 } }],
          responses: {
            ...ok("Historical risk snapshots of the tenant.", { $ref: "#/components/schemas/RiskHistoryEnvelope" }),
            ...refusals,
          },
        },
      },
      "/posture/scan": {
        post: {
          tags: ["Posture Dashboard"],
          operationId: "runPostureScan",
          description: kernel("posture.write", "scan_run") + " Scans the request tenant only; the scheduler scans every tenant in-process.",
          parameters: [
            ...tenantParams,
            { name: "sync_audit", in: "query", required: false, schema: { type: "boolean", default: false } },
          ],
          responses: {
            ...ok("Scan result for the tenant.", { type: "object", required: ["risk", "tenant_id", "request_id"], properties: { risk: { $ref: "#/components/schemas/RiskSnapshot" }, tenant_id: { type: "string" }, request_id: { type: "string" } } }),
            ...refusals,
          },
        },
      },
      "/posture/events": {
        post: {
          tags: ["Posture Events"],
          operationId: "ingestPostureEvent",
          description: kernel("posture.write", "events_ingested"),
          parameters: tenantParams,
          requestBody: { required: true, content: media({ $ref: "#/components/schemas/PostureEvent" }) },
          responses: {
            ...ok("Events stored.", { $ref: "#/components/schemas/IngestEnvelope" }),
            ...refusals,
          },
        },
      },
      "/posture/events/batch": {
        post: {
          tags: ["Posture Events"],
          operationId: "ingestPostureEventsBatch",
          description: kernel("posture.write", "events_ingested") + " An item naming another tenant refuses the whole batch (`tenant_mismatch`); nothing is stored.",
          parameters: tenantParams,
          requestBody: {
            required: true,
            content: media({ type: "object", required: ["items"], additionalProperties: false, properties: { items: { type: "array", items: { $ref: "#/components/schemas/PostureEvent" } } } }),
          },
          responses: {
            ...ok("Events stored.", { $ref: "#/components/schemas/IngestEnvelope" }),
            ...refusals,
          },
        },
      },
      "/posture/ingest/audit": {
        post: {
          tags: ["Posture Events"],
          operationId: "syncPostureFromAudit",
          description: kernel("posture.write", "audit_synced") + " Pulls the tenant's recent audit events into the posture engine.",
          parameters: [...tenantParams, { name: "limit", in: "query", required: false, schema: { type: "integer", minimum: 1, maximum: 5000, default: 500 } }],
          responses: {
            ...ok("Events stored.", { $ref: "#/components/schemas/IngestEnvelope" }),
            ...refusals,
          },
        },
      },
      "/posture/findings": {
        get: {
          tags: ["Posture Findings"],
          operationId: "listPostureFindings",
          description: kernel("posture.read", "findings_listed"),
          parameters: [
            ...tenantParams,
            { name: "engine", in: "query", required: false, schema: { type: "string" } },
            { name: "status", in: "query", required: false, schema: { type: "string" } },
            { name: "severity", in: "query", required: false, schema: { type: "string" } },
            { name: "finding_type", in: "query", required: false, schema: { type: "string" } },
            { name: "from", in: "query", required: false, schema: isoDateTime },
            { name: "to", in: "query", required: false, schema: isoDateTime },
            { $ref: "#/components/parameters/LimitQuery" },
            { name: "offset", in: "query", required: false, schema: { type: "integer", minimum: 0 } },
          ],
          responses: {
            ...ok("Filtered posture findings.", { $ref: "#/components/schemas/FindingListEnvelope" }),
            ...refusals,
          },
        },
      },
      "/posture/findings/{id}/status": {
        put: {
          tags: ["Posture Findings"],
          operationId: "updatePostureFindingStatus",
          description: kernel("posture.write", "finding_status_updated"),
          parameters: [...tenantParams, { $ref: "#/components/parameters/IdPath" }],
          requestBody: {
            required: true,
            content: media({ type: "object", required: ["status"], additionalProperties: false, properties: { status: { type: "string", enum: ["open", "acknowledged", "resolved", "reopened"] } } }),
          },
          responses: {
            ...ok("Status updated.", { type: "object", required: ["ok", "request_id"], properties: { ok: { type: "boolean" }, request_id: { type: "string" } } }),
            ...refusals,
            404: err("Finding not found in the tenant."),
          },
        },
      },
      "/posture/actions": {
        get: {
          tags: ["Posture Actions"],
          operationId: "listPostureActions",
          description: kernel("posture.read", "actions_listed"),
          parameters: [
            ...tenantParams,
            { name: "status", in: "query", required: false, schema: { type: "string" } },
            { name: "action_type", in: "query", required: false, schema: { type: "string" } },
            { $ref: "#/components/parameters/LimitQuery" },
            { name: "offset", in: "query", required: false, schema: { type: "integer", minimum: 0 } },
          ],
          responses: {
            ...ok("Remediation actions, including approval-required and manual actions.", { $ref: "#/components/schemas/ActionListEnvelope" }),
            ...refusals,
          },
        },
      },
      "/posture/actions/{id}/execute": {
        post: {
          tags: ["Posture Actions"],
          operationId: "executePostureAction",
          description: kernel("posture.action.execute", "action_executed") + " Runs the action's executor as the verified caller (an `actor` body field is rejected, `X-Actor-ID` is ignored). Only `escalate_remediation` is executable: it raises the overdue finding one severity level, restarts its SLA and resolves the SLA-breach finding. An approval-required action runs only on an approved governance request bound to this action and opened by the caller: the first call opens one and is refused `approval_pending`. Refusal reasons also include `approval_invalid`, `approval_unavailable` and `not_executable`.",
          parameters: [...tenantParams, { $ref: "#/components/parameters/IdPath" }],
          requestBody: {
            required: false,
            content: media({
              type: "object",
              additionalProperties: false,
              properties: {
                approval_request_id: { type: "string", description: "Optional; must be an approved governance request bound to this action and opened by the caller." },
              },
            }),
          },
          responses: {
            ...ok("The executor ran; `result` says what changed.", { type: "object", required: ["ok", "request_id"], properties: { ok: { type: "boolean" }, result: objectAny, request_id: { type: "string" } } }),
            ...refusals,
            403: err("Missing permission, another tenant, the wildcard tenant, or approval_invalid (the given approval_request_id is not an approved request bound to this action and caller)."),
            404: err("Action not found in the tenant."),
            409: err("approval_pending (an approval request was opened or is still pending; its ID is in the message), not_executable (no executor for this action type, or the action was withdrawn), already_executed, or finding_not_open."),
            503: err("approval_unavailable: governance approvals are not configured or can't be reached (fail closed)."),
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
      description: "OpenAPI contract for compliance posture, assessment runs, delta views, and template-driven framework scoring. Served at `/svc/compliance` through the Envoy edge.",
    },
    servers: [
      { url: "/svc/compliance", description: "Envoy edge" },
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
  return kernelRoutes(reportingPaths(), "reporting", {
    "GET /reports/templates": ["reporting.read", "report_templates_listed"],
    "POST /reports/generate": ["reporting.write", "report_requested", "The job is queued for the token's tenant and `requested_by` is the verified caller; `tenant_id` and `requested_by` are no longer read from the body (a `requested_by` field is rejected)."],
    "GET /reports/jobs": ["reporting.read", "report_jobs_listed"],
    "GET /reports/jobs/{id}": ["reporting.read", "report_job_read"],
    "DELETE /reports/jobs/{id}": ["reporting.delete", "report_deleted", "The deleting actor is the verified caller; the `actor` query parameter and `X-Actor-ID` header are ignored."],
    "GET /reports/jobs/{id}/download": ["reporting.read", "report_downloaded"],
    "GET /alerts/stats/mttd": ["reporting.read", "mttd_stats_viewed"],
    "GET /alerts/stats/mttr": ["reporting.read", "mttr_stats_read"],
    "GET /alerts/stats/top-sources": ["reporting.read", "top_sources_read"],
  });
}

function reportingPaths() {
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
      description: "OpenAPI contract for report templates, evidence-pack generation, report jobs, and alert timing analytics including MTTD. Served at `/svc/reporting` through the Envoy edge.",
    },
    servers: [
      { url: "/svc/reporting", description: "Envoy edge" },
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
              required: ["template_id"],
              properties: {
                template_id: { type: "string", enum: ["key_generation", "key_rotation", "kms_operations", "hyok_activity", "byok_activity", "certificate_lifecycle", "compliance_audit", "posture_summary", "evidence_pack", "alert_summary", "custom"] },
                format: { type: "string", enum: ["pdf", "csv", "json"], default: "pdf" },
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
        delete: {
          tags: ["Reporting"],
          operationId: "deleteReportJob",
          parameters: [...tenantParams, { $ref: "#/components/parameters/IdPath" }],
          responses: {
            200: { description: "Report job deleted.", content: media({ type: "object", required: ["deleted", "request_id"], properties: { deleted: { type: "boolean" }, request_id: { type: "string" } } }) },
            404: err("Report job not found in the token's tenant."),
            500: err("Unhandled report job deletion failure."),
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
  await fs.writeFile(path.join(publicOutDir, "sbom.html"), viewerHTML("Vecta KMS SBOM / CBOM OpenAPI", "sbom.openapi.json"), "utf8");
  await fs.writeFile(path.join(publicOutDir, "posture.html"), viewerHTML("Vecta KMS Security Posture OpenAPI", "posture.openapi.json"), "utf8");
  await fs.writeFile(path.join(publicOutDir, "compliance.html"), viewerHTML("Vecta KMS Compliance OpenAPI", "compliance.openapi.json"), "utf8");
  await fs.writeFile(path.join(publicOutDir, "reporting.html"), viewerHTML("Vecta KMS Reporting OpenAPI", "reporting.openapi.json"), "utf8");
}

async function main() {
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
