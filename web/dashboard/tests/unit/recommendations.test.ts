import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { evaluate, exposure, postureScore, type KeyAlgorithmFacts } from "../../src/lib/recommendations";

const now = new Date("2026-09-25T00:00:00Z");

// The catalogue's facts as keycore's agility posture returns them.
const fact = (algorithm: string, f: Partial<KeyAlgorithmFacts>): KeyAlgorithmFacts =>
  ({ algorithm, assessed: true, weak: false, quantum_vulnerable: false, post_quantum: false, policy_status: "allowed", ...f });
const keyAlgorithms = [
  fact("3DES", { weak: true }),
  fact("ECDSA-P256", { quantum_vulnerable: true }),
  fact("AES-256-GCM", {}),
];

describe("algorithm facts", () => {
  it("come from the catalogue, never from the name", () => {
    expect(exposure(fact("X", { weak: true, quantum_vulnerable: true }))).toBe("weak");
    expect(exposure(fact("X", { quantum_vulnerable: true }))).toBe("quantum_vulnerable");
    expect(exposure(fact("X", {}))).toBe("neither");
    expect(exposure(undefined)).toBe("not_assessed");
    expect(exposure({ ...fact("RSA", {}), assessed: false })).toBe("not_assessed");
  });

  it("are not assessed when keycore's agility posture could not be read", () => {
    const { recommendations, checks } = evaluate({ now, keys: [{ id: "1", name: "legacy-3des", algorithm: "3DES", status: "active" }] });
    for (const id of ["algo-weak", "algo-policy", "pqc-keys"]) expect(checks.find((c) => c.id === id)?.status, id).toBe("unknown");
    expect(recommendations.map((r) => r.id)).not.toContain("algo-weak");
  });

  it("take deprecated and disallowed only from the tenant's own rules", () => {
    const keys = [{ id: "1", name: "signer", algorithm: "RSA-2048", status: "active", expires_at: "2027-01-01T00:00:00Z", labels: { owner: "x" } }];
    const allowed = evaluate({ now, keys, keyAlgorithms: [fact("RSA-2048", { quantum_vulnerable: true })] }).recommendations.map((r) => r.id);
    expect(allowed).not.toContain("algo-policy-stopped");
    expect(allowed).not.toContain("algo-policy-deprecated");
    const ruled = evaluate({ now, keys, keyAlgorithms: [fact("RSA-2048", { quantum_vulnerable: true, policy_status: "disallowed", policy_rule: "r1", target_algorithm: "ML-DSA-65" })] });
    const rec = ruled.recommendations.find((r) => r.id === "algo-policy-stopped");
    expect(rec?.severity).toBe("high");
    expect(rec?.fix).toContain("ML-DSA-65");
    expect(ruled.checks.find((c) => c.id === "algo-policy")?.status).toBe("fail");
  });
});

// The customer decides what to migrate and when (CLAUDE.md): no standard is
// cited, no deadline year is set, and no algorithm list is kept here.
describe("recommendations cite nothing and classify nothing themselves", () => {
  const src = (f: string) => readFileSync(join(__dirname, "..", "..", "src", f), "utf8");
  for (const f of ["lib/recommendations.ts", "components/v3/tabs/CommandCenterTab.tsx"]) {
    it(f, () => {
      const text = src(f);
      expect(text).not.toMatch(/\b(NIST|PCI|DORA|CNSA|FedRAMP|OMB|ISO 2\d{4}|ISO 22301|CIS Controls|CA\/B|RFC \d{4}|SP 800|IR 8547|frameworks)\b/);
      expect(text).not.toMatch(/\b20[3-9]\d\b/);
      expect(text).not.toMatch(/RSA-\?\(|AES-\?128|DES\|3DES|P-\?192/);
    });
  }
});

describe("evaluate", () => {
  it("never fails or scores checks whose data is missing", () => {
    const { recommendations, checks } = evaluate({ now });
    expect(recommendations).toHaveLength(0);
    expect(checks.every((c) => c.status === "unknown")).toBe(true);
    expect(postureScore(recommendations, checks).assessed).toBe(0);
  });

  it("does not pass key or certificate rules on a tenant that has none", () => {
    const { checks } = evaluate({ now, keys: [], certs: [], backups: [] });
    const status = (id: string) => checks.find((c) => c.id === id)?.status;
    for (const id of ["algo-weak", "algo-policy", "pqc-keys", "cryptoperiod", "non-exportable", "inventory", "cert-expiry"]) expect(status(id), id).toBe("unknown");
    expect(status("backup")).toBe("fail");
    // No findings and no scan on record is "never evaluated"; after a scan it is a pass.
    expect(evaluate({ now, postureFindings: [] }).checks.find((c) => c.id === "posture")?.status).toBe("unknown");
    expect(evaluate({ now, postureFindings: [], postureEvaluated: true }).checks.find((c) => c.id === "posture")?.status).toBe("pass");
    expect(evaluate({ now, postureFindings: [{ severity: "high", status: "open" }] }).checks.find((c) => c.id === "posture")?.status).toBe("fail");
    const symmetricOnly = evaluate({ now, keyAlgorithms, keys: [{ id: "1", name: "dek", algorithm: "AES-256-GCM", status: "active", expires_at: "2027-01-01T00:00:00Z", labels: { owner: "db" } }] }).checks;
    expect(symmetricOnly.find((c) => c.id === "pqc-keys")?.status).toBe("unknown");
    expect(symmetricOnly.find((c) => c.id === "algo-weak")?.status).toBe("pass");
  });

  it("produces prioritised findings from live state", () => {
    const { recommendations, checks } = evaluate({
      now,
      keyAlgorithms,
      keys: [
        { id: "1", name: "legacy-3des", algorithm: "3DES", status: "active", labels: { owner: "pay" } },
        { id: "2", name: "tls-signer", algorithm: "ECDSA-P256", status: "active", expires_at: "2032-01-01T00:00:00Z", labels: { owner: "web" } },
        { id: "3", name: "dek", algorithm: "AES-256-GCM", status: "active", expires_at: "2027-01-01T00:00:00Z", labels: { owner: "db" } },
      ],
      backups: [],
      keyAccess: { deny_by_default: true, require_approval_for_policy_change: true, grant_max_ttl_minutes: 60, enforce_signed_requests: true },
      certs: [
        { id: "c", subject_cn: "api.example.com", algorithm: "ECDSA-P256", status: "active", not_after: "2026-09-28T00:00:00Z", algorithm_facts: { assessed: true, weak: false, quantum_vulnerable: true, post_quantum: false } },
        { id: "w", subject_cn: "old.example.com", algorithm: "RSA-1024", status: "active", not_after: "2027-09-28T00:00:00Z", algorithm_facts: { assessed: true, weak: true, quantum_vulnerable: true, post_quantum: false } },
      ],
    });
    const ids = recommendations.map((r) => r.id);
    expect(ids[0]).toBe("algo-weak"); // critical first
    expect(ids).toContain("cert-weak");
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
