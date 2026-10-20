import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/lib/auth", () => ({ clearSession: vi.fn() }));

import type { AuthSession } from "../../src/lib/auth";
import { listKeys } from "../../src/lib/keycore";

const session = { token: "t", tenantId: "t1" } as AuthSession;

// listKeys pages through every key at keycore's 1000-row maximum until it
// says no more follow; one request for 2000 got the newest 100 (13.24.0-beta).
describe("listKeys", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("reads every page and stops when keycore says no more follow", async () => {
    const total = 1500;
    const urls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input), "https://kms.test");
      urls.push(url.search);
      const limit = Number(url.searchParams.get("limit"));
      const offset = Number(url.searchParams.get("offset"));
      const items = Array.from({ length: Math.max(0, Math.min(limit, total - offset)) }, (_, i) => ({ id: `k${offset + i}` }));
      return new Response(JSON.stringify({ items, has_more: offset + limit < total }), { status: 200, headers: { "content-type": "application/json" } });
    }));
    const keys = await listKeys(session);
    expect(keys).toHaveLength(total);
    expect(urls).toHaveLength(2);
    for (const u of urls) expect(new URLSearchParams(u).get("limit")).toBe("1000");
    expect(new URLSearchParams(urls[1]!).get("offset")).toBe("1000");
  });
});
