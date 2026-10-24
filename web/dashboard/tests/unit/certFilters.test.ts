import { describe, expect, it } from "vitest";
import { RENEWAL_FILTERS, expiryDaysLeft, isSetTime, matchesCertFilter } from "../../src/components/v3/tabs/certs/certFilters";

// The certificate tiles filter the table with these predicates, so each must
// select exactly what the certs service counted (services/certs/summary.go
// CertSummary, service_renewal.go buildCertRenewalSummary; 13.61.0-beta).
const DAY = 86_400_000;
const now = Date.parse("2026-10-24T12:00:00Z");
const at = (days: number) => new Date(now + days * DAY).toISOString();
const policy = { alertDays: 30, includeExternal: true };
const cert = (over: Record<string, unknown>) => ({ status: "active", ca_id: "ca_1", not_after: at(100), ...over });

describe("certificate tile filters mirror CertSummary", () => {
  it("counts an active certificate past its end as expired, not active or expiring", () => {
    const c = cert({ not_after: at(-1) });
    expect(matchesCertFilter(c, "active", policy, now)).toBe(false);
    expect(matchesCertFilter(c, "expiring", policy, now)).toBe(false);
  });

  it("truncates days left as Go's int() does", () => {
    expect(expiryDaysLeft(cert({ not_after: at(30.9) }), policy, now)).toBe(30);
    expect(matchesCertFilter(cert({ not_after: at(30.9) }), "expiring", policy, now)).toBe(true);
    expect(matchesCertFilter(cert({ not_after: at(31.1) }), "expiring", policy, now)).toBe(false);
  });

  it("leaves revoked and, when the policy says so, external certificates out of expiring", () => {
    expect(matchesCertFilter(cert({ status: "revoked", not_after: at(3) }), "expiring", policy, now)).toBe(false);
    expect(matchesCertFilter(cert({ status: "revoked" }), "revoked", policy, now)).toBe(true);
    const external = cert({ ca_id: "External-CA", not_after: at(3) });
    expect(matchesCertFilter(external, "expiring", policy, now)).toBe(true);
    expect(matchesCertFilter(external, "expiring", { ...policy, includeExternal: false }, now)).toBe(false);
  });
});

describe("renewal tile filters mirror buildCertRenewalSummary", () => {
  const zero = "0001-01-01T00:00:00Z";
  it("reads Go's zero time as unset", () => {
    expect(isSetTime(zero)).toBe(false);
    expect(isSetTime("")).toBe(false);
    expect(isSetTime(at(0))).toBe(true);
    expect(RENEWAL_FILTERS.missed({ missed_window_at: zero }, now)).toBe(false);
    expect(RENEWAL_FILTERS.emergency({ emergency_rotation_at: at(0) }, now)).toBe(true);
  });

  it("counts due within 72 hours and risk from medium up", () => {
    expect(RENEWAL_FILTERS.due({ scheduled_renewal_at: at(2.9) }, now)).toBe(true);
    expect(RENEWAL_FILTERS.due({ scheduled_renewal_at: at(3.1) }, now)).toBe(false);
    expect(RENEWAL_FILTERS.due({ scheduled_renewal_at: zero }, now)).toBe(false);
    expect(["low", "medium", "high", "critical"].map((r) => RENEWAL_FILTERS.risk({ risk_level: r }, now))).toEqual([false, true, true, true]);
  });
});
