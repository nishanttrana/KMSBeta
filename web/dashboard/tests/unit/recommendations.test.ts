import { describe, expect, it } from "vitest";
import { algoStrength, evaluate, isQuantumVulnerable, postureScore } from "../../src/lib/recommendations";

const now = new Date("2026-09-25T00:00:00Z");

describe("algorithm classification", () => {
  it("flags disallowed algorithms", () => {
    expect(algoStrength("3DES")).toBe("broken");
    expect(algoStrength("RSA-1024")).toBe("broken");
    expect(algoStrength("SHA1-RSA")).toBe("broken");
    expect(algoStrength("RSA_2048")).toBe("legacy");
    expect(algoStrength("RSA-4096")).toBe("ok");
    expect(algoStrength("AES-128-GCM")).toBe("sub-cnsa");
    expect(algoStrength("AES-256-GCM")).toBe("ok");
  });
  it("detects quantum-vulnerable asymmetric keys", () => {
    expect(isQuantumVulnerable("ECDSA-P384")).toBe(true);
    expect(isQuantumVulnerable("RSA-3072")).toBe(true);
    expect(isQuantumVulnerable("ML-DSA-65")).toBe(false);
    expect(isQuantumVulnerable("ML-KEM-768")).toBe(false);
    expect(isQuantumVulnerable("AES-256-GCM")).toBe(false);
  });
});

describe("evaluate", () => {
  it("never fails or scores checks whose data is missing", () => {
    const { recommendations, checks } = evaluate({ now });
    expect(recommendations).toHaveLength(0);
    expect(checks.every((c) => c.status === "unknown")).toBe(true);
    expect(postureScore(recommendations, checks).assessed).toBe(0);
  });

  it("produces prioritised findings from live state", () => {
    const { recommendations, checks } = evaluate({
      now,
      keys: [
        { id: "1", name: "legacy-3des", algorithm: "3DES", status: "active", labels: { owner: "pay" } },
        { id: "2", name: "tls-signer", algorithm: "ECDSA-P256", status: "active", expires_at: "2032-01-01T00:00:00Z", labels: { owner: "web" } },
        { id: "3", name: "dek", algorithm: "AES-256-GCM", status: "active", expires_at: "2027-01-01T00:00:00Z", labels: { owner: "db" } },
      ],
      backupPolicies: [],
      keyAccess: { deny_by_default: true, require_approval_for_policy_change: true, grant_max_ttl_minutes: 60, enforce_signed_requests: true },
      certs: [{ id: "c", subject_cn: "api.example.com", algorithm: "ECDSA-P256", status: "active", not_after: "2026-09-28T00:00:00Z" }],
    });
    const ids = recommendations.map((r) => r.id);
    expect(ids[0]).toBe("algo-broken"); // critical first
    expect(ids).toContain("no-backup");
    expect(ids).toContain("pqc-migrate");
    expect(ids).toContain("cert-expiring");
    expect(ids).not.toContain("deny-default");
    expect(recommendations.find((r) => r.id === "cert-expiring")?.severity).toBe("high");
    expect(checks.find((c) => c.id === "deny-default")?.status).toBe("pass");
    const { score } = postureScore(recommendations, checks);
    expect(score).toBeLessThan(70);
  });

  it("flags the untouched bootstrap admin as critical", () => {
    const { recommendations } = evaluate({ now, users: [{ username: "admin", role: "admin", status: "active", must_change_password: true }] });
    expect(recommendations[0]).toMatchObject({ id: "default-admin", severity: "critical" });
  });
});
