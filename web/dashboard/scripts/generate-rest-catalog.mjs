#!/usr/bin/env node

import { promises as fs } from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const repoRoot = path.resolve(__dirname, "../../..");
const servicesRoot = path.join(repoRoot, "services");
const outputPath = path.join(repoRoot, "web", "dashboard", "src", "generated", "restApiCatalog.generated.ts");
// Every hand-written example (src/components/v3/restApiCatalog.ts) as data a
// Go test can read: a
// service's rest_examples_test.go sends its examples to the real handlers.
const examplesPath = path.join(repoRoot, "web", "dashboard", "src", "generated", "restApiExamples.generated.json");
const handWrittenPath = path.join(repoRoot, "web", "dashboard", "src", "components", "v3", "restApiCatalog.ts");

// A service directory whose edge prefix (/svc/<name>/) is another name.
const EDGE_NAME = { "cluster-manager": "cluster" };

const WITH_BODY = new Set(["POST", "PUT", "PATCH"]);

const SERVICE_GROUP = {
  audit: "Audit & Alerts",
  auth: "Identity & Access",
  certs: "Certificates / PKI",
  cloud: "Cloud Key Control",
  compliance: "Compliance",
  confidential: "Confidential Compute",
  autokey: "Autokey",
  keyaccess: "Key Access Justifications",
  signing: "Artifact Signing",
  dataprotect: "Data Protection",
  discovery: "Discovery",
  ekm: "Enterprise Key Management",
  governance: "Governance",
  hyok: "HYOK",
  keycore: "Key Management",
  kmip: "KMIP",
  mpc: "MPC",
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
  keyaccess: "Key Access",
  signing: "Signing",
  dataprotect: "Data Protect",
  discovery: "Discovery",
  ekm: "EKM",
  governance: "Governance",
  hyok: "HYOK",
  keycore: "KeyCore",
  kmip: "KMIP",
  mpc: "MPC",
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

async function loadHandWritten() {
  const { default: ts } = await import("typescript");
  const source = await fs.readFile(handWrittenPath, "utf8");
  const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
  const mod = await import(`data:text/javascript;base64,${Buffer.from(js).toString("base64")}`);
  return mod.REST_API_CATALOG;
}


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
    // Routes live in any file of a service (handler_agility.go, ...), not
    // only handler.go; test files register fake servers, not routes.
    if (entry.name.endsWith("_test.go")) {
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
  const edge = EDGE_NAME[service] || service;
  const group = `${SERVICE_GROUP[service] || "Other"} (${edge})`;
  const serviceLabel = SERVICE_LABEL[service] || service;
  const id = `${edge}-${slug(method)}-${slug(normalizedPath)}`;
  const base = {
    id,
    group,
    title: `${method} ${normalizedPath}`,
    service: edge,
    method,
    pathTemplate,
    bodyTemplate: WITH_BODY.has(method) ? '{\n  "tenant_id": "{{tenant_id}}"\n}' : "",
    description: `Auto-discovered route from ${serviceLabel} service.`,
    requestExample: `${method} /svc/${edge}${pathTemplate}`,
    responseExample: {
      note: "Execute endpoint to inspect the live response payload."
    },
    errorCodes: [
      { code: 401, meaning: "Authentication required or token invalid" },
      { code: 403, meaning: "Caller lacks permission for this operation" },
      { code: 400, meaning: "Request payload, path, or query parameters invalid" }
    ]
  };
  return base;
}

async function main() {
  try {
    await fs.access(servicesRoot);
  } catch {
    process.stdout.write(`Skipped route discovery: services root not found at ${servicesRoot}\n`);
    return;
  }

  const files = await walk(servicesRoot);
  // mux.HandleFunc("GET /x", h) and the pkg/route kernel's
  // r.Handle("GET /x", route.Spec{...}, h) (CLAUDE.md rule 2), literal patterns.
  const routeRegex = /\b(?:mux\.HandleFunc|\w+\.Handle)\("(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\/[^"]*)"\s*,/g;
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

  const example = (item) => ({ id: item.id, service: item.service, method: item.method, pathTemplate: item.pathTemplate, bodyTemplate: item.bodyTemplate || "", responseExample: item.responseExample || {} });
  const examples = (await loadHandWritten())
    .map(example)
    .sort((a, b) => a.service.localeCompare(b.service) || a.id.localeCompare(b.id));
  await fs.writeFile(examplesPath, `${JSON.stringify(examples, null, 2)}\n`, "utf8");
  process.stdout.write(`Wrote ${examples.length} hand-written examples -> ${examplesPath}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error?.stack || error}\n`);
  process.exit(1);
});
