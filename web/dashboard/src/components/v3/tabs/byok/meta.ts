import type { BYOKKey } from "../../../../lib/byok";

export const MONO = "'JetBrains Mono',ui-monospace,monospace";

export const CLOUD_LABELS: Record<string, string> = {
  aws: "AWS KMS", azure: "Azure Key Vault", gcp: "Google Cloud KMS", oci: "OCI Vault", alibaba: "Alibaba Cloud KMS", salesforce: "Salesforce Shield",
};
export const CLOUD_ORDER = ["aws", "azure", "gcp", "oci", "alibaba", "salesforce"];
export const cloudLabel = (p: string) => CLOUD_LABELS[p] || p;

// Material states, filled with the validated class tokens (index.css).
export const STATES = [
  { id: "current", label: "Current material", short: "Current", color: "var(--cls-strong)" },
  { id: "pending", label: "Waiting for material", short: "Waiting", color: "var(--cls-qv)" },
  { id: "revoked", label: "Revoked in the cloud", short: "Revoked", color: "var(--cls-weak)" },
  { id: "cloud", label: "Cloud-generated (read-only)", short: "Cloud-generated", color: "var(--cls-unknown)" },
] as const;
export type StateId = (typeof STATES)[number]["id"];

export function stateOf(k: BYOKKey): StateId {
  if (k.origin === "cloud-generated") return "cloud";
  if (k.material_state === "current") return "current";
  if (k.material_state === "revoked") return "revoked";
  return "pending";
}

export const SOURCE_LABEL: Record<string, string> = { kms: "KMS", hsm: "HSM" };

export type BYOKDrill = { key: string; label: string; match: (k: BYOKKey) => boolean };

export const allDrill = (): BYOKDrill => ({ key: "all", label: "All cloud keys", match: () => true });
export const cloudDrill = (p: string): BYOKDrill => ({ key: `cloud:${p}`, label: cloudLabel(p), match: (k) => k.provider === p });
export const stateDrill = (s: StateId): BYOKDrill => ({
  key: `state:${s}`, label: STATES.find((x) => x.id === s)?.label ?? s, match: (k) => stateOf(k) === s,
});
export const sourceDrill = (s: string): BYOKDrill => ({
  key: `source:${s}`, label: `Material from ${SOURCE_LABEL[s] ?? s}`, match: (k) => k.origin === "byok" && k.source === s,
});
export const expiringDrill = (now: number): BYOKDrill => ({
  key: "expiring", label: "Material expiring in 30 days",
  match: (k) => !!k.expires_at && stateOf(k) === "current" && Date.parse(k.expires_at) - now < 30 * 86400_000,
});

export function fmtDate(v?: string): string {
  if (!v) return "-";
  const t = new Date(v);
  return Number.isNaN(t.getTime()) ? v : t.toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function fmtAgo(v?: string): string {
  if (!v) return "-";
  const ms = Date.now() - Date.parse(v);
  if (!Number.isFinite(ms)) return v;
  if (ms < 60_000) return "now";
  const m = Math.floor(ms / 60_000);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`;
}

export const OPERATION_LABEL: Record<string, string> = {
  create: "Bring your own key", rotate: "Rotate", reimport: "Reimport", revoke: "Revoke", restore: "Restore", verify: "Verify", sync: "Sync",
};
