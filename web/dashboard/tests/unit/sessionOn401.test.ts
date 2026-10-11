import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/lib/auth", () => ({ clearSession: vi.fn() }));

import { clearSession } from "../../src/lib/auth";
import type { AuthSession } from "../../src/lib/auth";
import { serviceRequest, setOnUnauthorizedHandler } from "../../src/lib/serviceApi";

// Only a 401 on a call authenticated by the session token ends the session.
// A 403, or a 401 that refuses a credential carried in the body, must not:
// HYOK once answered every call 401 and signed the user out.
const session = { token: "t", tenantId: "root" } as AuthSession;

function respond(status: number) {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: { message: "refused" } }), { status })));
}

async function call(status: number, keepSessionOn401 = false) {
  const ended = vi.fn();
  setOnUnauthorizedHandler(ended);
  respond(status);
  await expect(serviceRequest(session, "workload", "/x", { method: "POST", keepSessionOn401 })).rejects.toThrow("refused");
  return ended;
}

describe("session handling on refusals", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.mocked(clearSession).mockClear();
  });

  it("ends the session on 401", async () => {
    expect(await call(401)).toHaveBeenCalledTimes(1);
    expect(clearSession).toHaveBeenCalledTimes(1);
  });

  it("keeps the session on 403", async () => {
    expect(await call(403)).not.toHaveBeenCalled();
    expect(clearSession).not.toHaveBeenCalled();
  });

  it("keeps the session when the 401 refuses a credential in the body", async () => {
    expect(await call(401, true)).not.toHaveBeenCalled();
    expect(clearSession).not.toHaveBeenCalled();
  });

  it("does not send the option to fetch", async () => {
    await call(401, true);
    const init = vi.mocked(fetch).mock.calls[0][1] as Record<string, unknown>;
    expect("keepSessionOn401" in init).toBe(false);
  });
});
