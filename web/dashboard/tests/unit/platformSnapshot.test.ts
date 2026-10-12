import { beforeEach, describe, expect, it, vi } from "vitest";

// The Command Center asked the cluster service for an overview on every load,
// including where clustering is not deployed: a 503 each time (12.3.0-beta).

const { getClusterOverview } = vi.hoisted(() => ({ getClusterOverview: vi.fn(async () => ({ summary: { total_nodes: 3 } })) }));
vi.mock("../../src/lib/cluster", () => ({ getClusterOverview }));

import { loadPlatformSnapshot } from "../../src/lib/platformSnapshot";

const session = { tenantId: "root", username: "tester", token: "t", mode: "local" } as never;

describe("platform snapshot", () => {
  beforeEach(() => {
    getClusterOverview.mockClear();
    // Every other source fails here; the snapshot records each as unavailable.
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("no network in a unit test"); }));
  });

  it("does not ask the cluster service where clustering is not deployed", async () => {
    const snapshot = await loadPlatformSnapshot(session, undefined, false);
    expect(getClusterOverview).not.toHaveBeenCalled();
    expect(snapshot.cluster).toBeUndefined();
  });

  it("asks it where clustering is deployed", async () => {
    const snapshot = await loadPlatformSnapshot(session, undefined, true);
    expect(getClusterOverview).toHaveBeenCalledTimes(1);
    expect(snapshot.cluster).toEqual({ total_nodes: 3 });
  });
});
