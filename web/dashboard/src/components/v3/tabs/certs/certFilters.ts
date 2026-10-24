// The predicates behind each certificate count, written as the certs service
// counts them, so a tile's list is exactly the number on it (docs/DECISIONS.md,
// "Every chart drills into its entries"). Certificate tiles mirror
// CertSummary (services/certs/summary.go); renewal tiles mirror
// buildCertRenewalSummary (services/certs/service_renewal.go).

const DAY = 86_400_000;
const lower = (v: unknown) => String(v ?? "").trim().toLowerCase();
const time = (v: unknown) => Date.parse(String(v ?? ""));

export type CertFilter = "" | "active" | "expiring" | "revoked";
export type ExpiryPolicy = { alertDays: number; includeExternal: boolean };

// Whole days left for a certificate the expiry policy watches, else null:
// revoked, deleted, expired and (unless included) external ones are not.
export function expiryDaysLeft(cert: any, policy: ExpiryPolicy, now: number): number | null {
  if (lower(cert?.status) !== "active") return null;
  if (!policy.includeExternal && lower(cert?.ca_id) === "external-ca") return null;
  const end = time(cert?.not_after);
  if (Number.isNaN(end) || now > end) return null;
  return Math.trunc((end - now) / DAY);
}

export function matchesCertFilter(cert: any, filter: CertFilter, policy: ExpiryPolicy, now: number): boolean {
  switch (filter) {
    case "active": {
      const end = time(cert?.not_after);
      return lower(cert?.status) === "active" && !(now > end);
    }
    case "revoked":
      return lower(cert?.status) === "revoked";
    case "expiring": {
      const days = expiryDaysLeft(cert, policy, now);
      return days !== null && days <= policy.alertDays;
    }
    default:
      return true;
  }
}

// Go writes an unset time.Time as year 1.
export const isSetTime = (v: unknown) => {
  const t = time(v);
  return !Number.isNaN(t) && t > 0;
};

export function riskWeight(level: unknown): number {
  switch (lower(level)) {
    case "critical": return 4;
    case "high": return 3;
    case "medium": case "amber": return 2;
    case "low": case "info": return 1;
    default: return 0;
  }
}

export type RenewalFilter = "due" | "missed" | "emergency" | "risk";

export const RENEWAL_FILTERS: Record<RenewalFilter, (w: any, now: number) => boolean> = {
  due: (w, now) => isSetTime(w?.scheduled_renewal_at) && time(w.scheduled_renewal_at) < now + 72 * 3600 * 1000,
  missed: (w) => isSetTime(w?.missed_window_at),
  emergency: (w) => isSetTime(w?.emergency_rotation_at),
  risk: (w) => riskWeight(w?.risk_level) >= riskWeight("medium"),
};

// Chart fill for a risk level: the validated three-step check-in fills.
export function riskFill(level: unknown): string {
  const w = riskWeight(level);
  return w >= 4 ? "var(--cls-missed)" : w >= 2 ? "var(--cls-late)" : "var(--cls-ontime)";
}
