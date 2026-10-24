import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/lib/auth", () => ({ clearSession: vi.fn() }));

import type { AuthSession } from "../../src/lib/auth";
import { getCBOMPQCReadiness, getCBOMSummary, getLatestCBOM, getLatestSBOM } from "../../src/lib/sbom";
import { serviceRequestOrNone } from "../../src/lib/serviceApi";

// Before the first SBOM/CBOM snapshot the service answers 404 not_found. The
// page once loaded everything in one Promise.all, so that 404 showed "not
// found" and nothing else (13.64.0-beta). "None yet" is null; every other
// failure still throws, including the router's own 404 for a missing route.
const session = { token: "t", tenantId: "root" } as AuthSession;

function respond(status: number, body: string, type = "application/json") {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(body, { status, headers: { "content-type": type } })));
}

const notFound = JSON.stringify({ error: { code: "not_found", message: "snapshot not found" } });

describe("a read of something not generated yet", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("is null on the service's 404 not_found", async () => {
    respond(404, notFound);
    expect(await serviceRequestOrNone(session, "sbom", "/sbom/latest")).toBeNull();
  });

  it("throws on the router's plain 404", async () => {
    respond(404, "404 page not found", "text/plain");
    await expect(serviceRequestOrNone(session, "sbom", "/sbom/latest")).rejects.toThrow();
  });

  it("throws on a 404 with another code", async () => {
    respond(404, JSON.stringify({ error: { code: "feature_preview", message: "off" } }));
    await expect(serviceRequestOrNone(session, "sbom", "/sbom/latest")).rejects.toThrow("off");
  });

  it("throws on a refusal", async () => {
    respond(403, JSON.stringify({ error: { code: "permission_denied", message: "missing permission sbom.read" } }));
    await expect(serviceRequestOrNone(session, "sbom", "/sbom/latest")).rejects.toThrow("sbom.read");
  });

  it("returns the body when there is one", async () => {
    respond(200, JSON.stringify({ item: { id: "sbom_1" } }));
    expect(await serviceRequestOrNone(session, "sbom", "/sbom/latest")).toEqual({ item: { id: "sbom_1" } });
  });

  it("makes every SBOM/CBOM latest read null before the first snapshot", async () => {
    respond(404, notFound);
    expect(await getLatestSBOM(session)).toBeNull();
    expect(await getLatestCBOM(session)).toBeNull();
    expect(await getCBOMSummary(session)).toBeNull();
    expect(await getCBOMPQCReadiness(session)).toBeNull();
  });
});
