import type { LucideIcon } from "lucide-react";
import { Cloud, Code2, FileBadge, Globe, Upload } from "lucide-react";
import type { AssetQuery, CryptoAsset, DiscoverySource, DiscoverySummary } from "../../../../lib/discovery";
import type { ServerDrill } from "../../chartDrill";

export const MONO = "'JetBrains Mono',monospace";

// Classes from pkg/cryptocatalog, plus "exposed" for a secret found in code
// or an upload. Risk first; each is shown with its label, never color alone.
export const CLASS_ORDER = ["exposed", "weak", "quantum_vulnerable", "strong", "unknown"] as const;
// Fills are theme tokens (index.css --cls-*), validated per theme.
const UNKNOWN = { label: "Not assessed", color: "var(--cls-unknown)" };
export const CLASS_META: Record<string, { label: string; color: string }> = {
  exposed: { label: "Exposed secret", color: "var(--cls-exposed)" },
  weak: { label: "Weak", color: "var(--cls-weak)" },
  quantum_vulnerable: { label: "Quantum-vulnerable", color: "var(--cls-qv)" },
  strong: { label: "Strong", color: "var(--cls-strong)" },
  unknown: UNKNOWN,
};
export const classMeta = (c: string) => CLASS_META[c] ?? UNKNOWN;

export const SOURCE_META: Record<string, { label: string; icon: LucideIcon }> = {
  network: { label: "Network", icon: Globe },
  cloud: { label: "Cloud KMS", icon: Cloud },
  certs: { label: "KMS certificates", icon: FileBadge },
  code: { label: "Source code", icon: Code2 },
  upload: { label: "File upload", icon: Upload },
};
export const sourceMeta = (s: string) => SOURCE_META[s] ?? { label: s, icon: Globe };

// Sources a scan reads; uploads are scanned as they arrive.
export const SCANNABLE = ["network", "cloud", "certs", "code"];

export const TYPE_LABEL: Record<string, string> = {
  tls_endpoint: "TLS endpoint",
  tls_certificate: "TLS certificate",
  ssh_endpoint: "SSH endpoint",
  ssh_host_key: "SSH host key",
  kms_key: "Cloud KMS key",
  certificate: "Certificate",
  certificate_request: "Certificate request",
  public_key: "Public key",
  ssh_public_key: "SSH public key",
  private_key_material: "Private key",
  cloud_access_key: "Cloud access key",
  hex_secret: "Hex secret",
  keystore: "Keystore",
};
export const typeLabel = (t: string) => TYPE_LABEL[t] ?? t.replace(/_/g, " ");

export const REVIEW_STATUSES = ["active", "reviewed", "accepted_risk", "remediated"];
export const REVIEW_LABEL: Record<string, string> = { active: "Not reviewed", reviewed: "Reviewed", accepted_risk: "Accepted risk", remediated: "Remediated" };
export const reviewOf = (a: CryptoAsset) => String(a.metadata?.review_status || "active");

function parse(v?: string) {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) || d.getFullYear() < 2000 ? null : d;
}

export function absTime(v?: string) {
  return parse(v)?.toLocaleString() ?? "-";
}

export function relTime(v?: string) {
  const d = parse(v);
  if (!d) return "-";
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function daysUntil(v?: string): number | null {
  const d = parse(v);
  return d ? Math.floor((d.getTime() - Date.now()) / 86400000) : null;
}

export function duration(from?: string, to?: string) {
  const a = parse(from);
  const b = parse(to);
  if (!a || !b) return "";
  const s = Math.max(0, Math.round((b.getTime() - a.getTime()) / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

// staleness: an asset of a scanned source that the source's last scan didn't
// observe (the endpoint, account key or file is gone or failed to answer).
export function isStale(a: CryptoAsset, sources: DiscoverySource[]) {
  if (!SCANNABLE.includes(a.source)) return false;
  const last = sources.find((s) => s.id === a.source)?.last_scan;
  const started = parse(last?.started_at);
  const seen = parse(a.last_seen);
  return !!started && !!seen && seen.getTime() < started.getTime() - 5000;
}

export const pct = (n: number, d: number) => (d > 0 ? Math.round((n / d) * 100) : 0);

// Drill-downs (components/v3/chartDrill.tsx): each count comes from the
// service's summary, and its list pages GET /discovery/assets with the
// filter the summary counted with, so the two always agree.
export type AssetDrill = ServerDrill<AssetQuery> & { key: string };

const sum = (m?: Record<string, number>) => Object.values(m || {}).reduce((a, b) => a + b, 0);
const algLabel = (alg: string) => alg || "no algorithm";

export const classDrill = (s: DiscoverySummary, c: string): AssetDrill => ({
  key: `class:${c}`, label: classMeta(c).label, count: s.classification_counts?.[c] || 0, query: { classification: c },
});
export const algDrill = (s: DiscoverySummary, alg: string, c?: string): AssetDrill => ({
  key: `alg:${alg}:${c ?? ""}`,
  label: c ? `${algLabel(alg)} · ${classMeta(c).label}` : algLabel(alg),
  count: c ? s.algorithm_classes?.[alg]?.[c] || 0 : sum(s.algorithm_classes?.[alg]),
  query: c ? { algorithm: alg, classification: c } : { algorithm: alg },
});
export const sourceDrill = (s: DiscoverySummary, src: string, c?: string): AssetDrill => ({
  key: `source:${src}:${c ?? ""}`,
  label: c ? `${sourceMeta(src).label} · ${classMeta(c).label}` : sourceMeta(src).label,
  count: c ? s.source_classification?.[src]?.[c] || 0 : sum(s.source_classification?.[src]),
  query: c ? { source: src, classification: c } : { source: src },
});
export const pqcDrill = (s: DiscoverySummary): AssetDrill => ({ key: "pqc", label: "Post-quantum", count: s.pqc_ready_count, query: { pqc_ready: true } });
export const riskyDrill = (s: DiscoverySummary): AssetDrill => ({
  key: "risky", label: "Weak or exposed", count: (s.classification_counts?.weak || 0) + (s.classification_counts?.exposed || 0), query: { classification: "weak,exposed" },
});
export const expiringDrill = (s: DiscoverySummary): AssetDrill => ({
  key: "expiring", label: "Expired or expiring within 30 days", count: s.expiring_30d || 0, query: { expiring_days: 30 },
});
