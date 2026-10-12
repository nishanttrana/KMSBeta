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

  // Every service's examples are checked (13.1.0-beta). A service that gains
  // hand-written examples brings its rest_examples_test.go, or its examples
  // are shown as not checked and this fails.
  it("has no service whose examples are unchecked", () => {
    expect([...new Set(REST_API_CATALOG_FULL.filter((entry) => entry.unverified).map((entry) => entry.service))]).toEqual([]);
    expect(new Set(REST_API_CATALOG.map((entry) => entry.service))).toEqual(new Set(VERIFIED_EXAMPLE_SERVICES));
  });

  // A body field the service's decoder silently ignores would pass the Go
  // test. Each top-level field of an example body is one the service names
  // in a json tag.
  it("shows no request field the service does not have", () => {
    const tags = new Map<string, Set<string>>();
    const tagsOf = (service: string) => {
      if (!tags.has(service)) {
        const dir = join(REPO, "services", service);
        const found = new Set<string>();
        for (const name of readdirSync(dir)) {
          if (!name.endsWith(".go") || name.endsWith("_test.go")) continue;
          for (const m of readFileSync(join(dir, name), "utf8").matchAll(/json:"([A-Za-z0-9_]+)/g)) found.add(m[1]!);
        }
        tags.set(service, found);
      }
      return tags.get(service)!;
    };
    const unknown: string[] = [];
    for (const entry of REST_API_CATALOG) {
      let body: unknown;
      try { body = JSON.parse(entry.bodyTemplate || "{}"); } catch { unknown.push(`${entry.id}: the body is not JSON`); continue; }
      for (const field of Object.keys((body as Record<string, unknown>) || {})) {
        if (!tagsOf(entry.service).has(field)) unknown.push(`${entry.id}: ${field}`);
      }
    }
    expect(unknown).toEqual([]);
  });

  it("lets the playground call the services that register routes, by their edge name", () => {
    expect(DISCOVERED_SERVICES.has("cluster")).toBe(true);
    for (const gone of ["cluster-manager", "ai", "qkd", "qrng", "mpc"]) expect(DISCOVERED_SERVICES.has(gone), gone).toBe(false);
  });
});
