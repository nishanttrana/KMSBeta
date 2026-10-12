import { REST_API_CATALOG } from "../components/v3/restApiCatalog";
import { DISCOVERED_REST_API_CATALOG } from "../generated/restApiCatalog.generated";

// The REST API tab's catalogue: every route the services register (discovered
// from the source by scripts/generate-rest-catalog.mjs), with the hand-written
// entries, which add a title, a description and example bodies, laid over it.
//
// A hand-written example is only as good as the last time someone compared it
// with the service. A service is listed here once a Go test sends each of its
// examples to the real handlers (services/<name>/rest_examples_test.go,
// pkg/route/routetest.Examples): the route exists, the body decodes, and the
// response shown is one the service gave, or the note that no response was
// obtained. The examples of a service that is not listed are shown as not
// checked. Every service with examples is listed since 13.1.0-beta; a new
// one joins with its test (tests/unit/restCatalog.test.ts).
export const VERIFIED_EXAMPLE_SERVICES: readonly string[] = [
  "audit", "auth", "certs", "cloud", "compliance", "confidential", "dataprotect", "discovery", "ekm",
  "governance", "hyok", "keycore", "kmip", "posture", "reporting", "sbom", "secrets", "workload"
];

// A route's {param} becomes the playground's {{param}} placeholder.
export const normalizeRestPathTemplate = (raw: string) =>
  String(raw || "").replace(/\{([a-zA-Z0-9_]+)\}/g, (match, param) => (String(param || "").trim() ? `{{${String(param).trim()}}}` : match));

// A discovered entry carries no example of its own; a hand-written one is
// unverified until its service is in VERIFIED_EXAMPLE_SERVICES.
export type RestCatalogEntry = Record<string, any> & { service: string; method: string; pathTemplate: string; unverified: boolean };

export const DISCOVERED_SERVICES: ReadonlySet<string> = new Set(DISCOVERED_REST_API_CATALOG.map((item) => String(item.service)));

export const REST_API_CATALOG_FULL: RestCatalogEntry[] = (() => {
  const rows: RestCatalogEntry[] = [];
  const seen = new Set<string>();
  const add = (item: Record<string, any>, handWritten: boolean) => {
    const service = String(item?.service || "").trim();
    const method = String(item?.method || "GET").trim().toUpperCase();
    const pathTemplate = normalizeRestPathTemplate(String(item?.pathTemplate || "/"));
    const key = `${service}|${method}|${pathTemplate}`;
    if (!service || seen.has(key)) {
      return;
    }
    seen.add(key);
    rows.push({ ...item, service, method, pathTemplate, unverified: handWritten && !VERIFIED_EXAMPLE_SERVICES.includes(service) });
  };
  REST_API_CATALOG.forEach((item) => add(item, true));
  DISCOVERED_REST_API_CATALOG.forEach((item) => add(item, false));
  return rows;
})();
