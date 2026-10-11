import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/lib/auth", () => ({ clearSession: vi.fn() }));

import type { AuthSession } from "../../src/lib/auth";
import { scanOnRecord } from "../../src/lib/platformSnapshot";
import { getPostureRisk } from "../../src/lib/posture";
import { evaluate } from "../../src/lib/recommendations";
import { parseServiceJSON } from "../../src/lib/wire";

// What the posture service really sends for a tenant it has never scanned
// (services/posture/handler.go handleLatestRisk): a zero time, not no field.
const NEVER_SCANNED = JSON.stringify({ risk: { tenant_id: "root", risk_24h: 0, captured_at: "0001-01-01T00:00:00Z", assessed: false } });
const session = { token: "t", tenantId: "root" } as AuthSession;
const SRC = join(__dirname, "..", "..", "src");

describe("Go zero times", () => {
  afterEach(() => vi.unstubAllGlobals());

  // A body read with response.json() skips the rule. These may: the API
  // playground shows a response as sent; sign-in and SSO read no times.
  it("are handled wherever a response body is read", () => {
    const allowed = ["components/v3/tabs/RestAPITab.tsx", "lib/auth.ts", "lib/authAdmin.ts"];
    const errorPayload = /error\?\.message|as APIError|as \{ error\?/;
    const hits: string[] = [];
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) { if (name !== "generated") walk(path); continue; }
        if (!/\.tsx?$/.test(name) || allowed.some((a) => path.endsWith(a))) continue;
        readFileSync(path, "utf8").split("\n").forEach((line, i) => { if (/\.json\(\)/.test(line) && !errorPayload.test(line)) hits.push(`${path.slice(SRC.length + 1)}:${i + 1}`); });
      }
    };
    walk(SRC);
    expect(hits).toEqual([]);
  });

  it("are no time at all once a response is parsed", () => {
    expect(parseServiceJSON<{ risk: { captured_at: string } }>(NEVER_SCANNED).risk.captured_at).toBe("");
    expect(parseServiceJSON<{ at: string }>('{"at":"2026-10-11T10:00:00Z"}').at).toBe("2026-10-11T10:00:00Z");
  });

  it("never count as a posture scan on record", async () => {
    expect(scanOnRecord("0001-01-01T00:00:00Z")).toBe(false);
    expect(scanOnRecord("")).toBe(false);
    expect(scanOnRecord(undefined)).toBe(false);
    expect(scanOnRecord("2026-10-11T10:00:00Z")).toBe(true);

    vi.stubGlobal("fetch", vi.fn(async () => new Response(NEVER_SCANNED, { status: 200, headers: { "content-type": "application/json" } })));
    const risk = await getPostureRisk(session);
    const { checks } = evaluate({ now: new Date(), postureFindings: [], postureEvaluated: scanOnRecord(risk.captured_at) });
    expect(checks.find((c) => c.id === "posture")?.status).toBe("unknown");
  });
});
