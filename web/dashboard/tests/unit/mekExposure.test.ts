import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { EXPOSURE_SERVICES, reportFrom, summarize } from "../../src/lib/mekExposure";

describe("exposure register", () => {
  // The backend's list of services with an exposure register is
  // pkg/mek.Catalog; the dashboard must query every one of them (compliance
  // and audit were once missing, so their exposures showed nowhere).
  it("covers every service in the pkg/mek catalogue", () => {
    const catalog = readFileSync(resolve(__dirname, "../../../../pkg/mek/catalog.go"), "utf8");
    const services = [...catalog.matchAll(/^\t"([a-z-]+)": \{/gm)].map((m) => m[1]).sort();
    expect(services.length).toBeGreaterThan(4);
    expect(EXPOSURE_SERVICES.map((s) => s.service).sort()).toEqual(services);
  });

  it("separates no access and undeployed services from real results", () => {
    expect(reportFrom("secrets", "Secrets", 403, null).status).toBe("no_access");
    expect(reportFrom("ekm", "BitLocker", 502, null).status).toBe("unavailable");
    const ok = reportFrom("secrets", "Secrets", 200, { items: [{ item_id: "s1", item_type: "secret", exposed_since: "2026-09-26T00:00:00Z" }] });
    expect(ok.status).toBe("ok");
    expect(ok.items).toHaveLength(1);
  });

  it("counts only what was actually checked", () => {
    const sum = summarize([
      reportFrom("secrets", "Secrets", 200, { items: [
        { item_id: "a", item_type: "secret", exposed_since: "x" },
        { item_id: "b", item_type: "secret", exposed_since: "x", remediated_at: "y", remediation: "rotated" }
      ] }),
      reportFrom("certs", "CA", 403, null),
      reportFrom("ekm", "BL", 404, null)
    ]);
    expect(sum).toEqual({ open: 1, remediated: 1, servicesChecked: 1, servicesUnknown: 2 });
  });
});
