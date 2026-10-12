import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { REST_API_CATALOG } from "../../src/components/v3/restApiCatalog";
import { DISCOVERED_REST_API_CATALOG } from "../../src/generated/restApiCatalog.generated";
import { DISCOVERED_SERVICES, REST_API_CATALOG_FULL, VERIFIED_EXAMPLE_SERVICES } from "../../src/lib/restCatalog";

// The REST API tab's hand-written examples drifted from the services: 18
// named routes nothing registers (two services that do not exist among them)
// and 18 of keycore's 21 showed bodies it refuses or answers it never gives
// (12.3.0-beta). These tie the catalogue to the source.

const ROOT = join(__dirname, "..", "..");
const REPO = join(ROOT, "..", "..");
const segments = (path: string) => String(path).split("?")[0]!.split("/").filter(Boolean);
const isParam = (segment: string) => /^\{\{?[^}]+\}?\}$/.test(segment);

describe("REST catalogue", () => {
  it("names only routes a service registers", () => {
    const routes = DISCOVERED_REST_API_CATALOG.map((route) => ({ service: route.service, method: route.method, path: segments(route.pathTemplate) }));
    const missing = REST_API_CATALOG.filter((entry) => {
      const path = segments(entry.pathTemplate);
      return !routes.some((route) => route.service === entry.service && route.method === entry.method && route.path.length === path.length &&
        route.path.every((segment, i) => isParam(segment) || segment === path[i]));
    }).map((entry) => `${entry.id}: ${entry.method} /svc/${entry.service}${entry.pathTemplate.split("?")[0]}`);
    expect(missing).toEqual([]);
  });

  // A Go test reads this copy (services/<name>/rest_examples_test.go). It is
  // written by `npm run generate:rest-catalog`, which the build runs.
  it("exports every hand-written example as it stands", () => {
    const exported: Array<Record<string, unknown>> = JSON.parse(readFileSync(join(ROOT, "src/generated/restApiExamples.generated.json"), "utf8"));
    const byID = new Map(exported.map((item) => [item.id, item]));
    const overrides = DISCOVERED_REST_API_CATALOG.filter((item) => (item as { handWritten?: boolean }).handWritten);
    expect(exported.length).toBe(REST_API_CATALOG.length + overrides.length);
    for (const entry of [...REST_API_CATALOG, ...overrides]) {
      expect(byID.get(entry.id), entry.id).toEqual({ id: entry.id, service: entry.service, method: entry.method, pathTemplate: entry.pathTemplate, bodyTemplate: entry.bodyTemplate || "", responseExample: entry.responseExample || {} });
    }
  });

  it("calls a service verified only where a test sends its examples to the handlers", () => {
    const withTest = readdirSync(join(REPO, "services")).filter((name) => existsSync(join(REPO, "services", name, "rest_examples_test.go")));
    expect([...VERIFIED_EXAMPLE_SERVICES].sort()).toEqual(withTest.sort());
  });

  // The services whose examples nobody has checked. This list only shrinks:
  // add services/<name>/rest_examples_test.go, fix what it finds, and move
  // the name to VERIFIED_EXAMPLE_SERVICES.
  it("shows every other service's examples as not checked", () => {
    const unverified = new Set(REST_API_CATALOG_FULL.filter((entry) => entry.unverified).map((entry) => entry.service));
    expect([...unverified].sort()).toEqual(["audit", "auth", "certs", "cloud", "compliance", "confidential", "dataprotect", "discovery", "ekm", "governance", "hyok", "kmip", "posture", "reporting", "sbom", "secrets", "workload"]);
    expect(REST_API_CATALOG_FULL.some((entry) => entry.service === "keycore" && entry.unverified)).toBe(false);
    // A discovered route with no hand-written example claims nothing to check.
    expect(REST_API_CATALOG_FULL.find((entry) => entry.id === "keycore-put-keys-id-description")?.unverified).toBe(false);
  });

  it("lets the playground call the services that register routes, by their edge name", () => {
    expect(DISCOVERED_SERVICES.has("cluster")).toBe(true);
    for (const gone of ["cluster-manager", "ai", "qkd", "qrng", "mpc"]) expect(DISCOVERED_SERVICES.has(gone), gone).toBe(false);
  });
});
