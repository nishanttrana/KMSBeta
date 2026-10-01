import type { LucideIcon } from "lucide-react";
import { FileText, KeyRound, Lock, Shield } from "lucide-react";
import type { SecretItem } from "../../../../lib/secrets";
import type { Drill } from "../../chartDrill";
import { C } from "../../theme";

// Charts and their drill-downs are computed from the same rows (every secret
// of the tenant, paged in full) with the same bucket functions and the same
// "now", so a bar's number is the length of the list it opens.
export type VaultDrill = Drill<SecretItem> & { key: string };

const DAY = 86400000;

export function fmtDate(v?: string): string {
  if (!v) return "-";
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return "-";
  return `${d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })} ${d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}`;
}

export function fmtAgo(v?: string): string {
  if (!v) return "";
  const ms = Date.now() - new Date(v).getTime();
  if (Number.isNaN(ms)) return "";
  if (ms < 60000) return "just now";
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ago`;
  if (ms < DAY) return `${Math.floor(ms / 3600000)}h ago`;
  return `${Math.floor(ms / DAY)}d ago`;
}

export const safeFileName = (input: string, fallback = "secret") =>
  String(input || "").trim().replace(/[^a-zA-Z0-9._-]/g, "_").replace(/^_+|_+$/g, "") || fallback;

export const CATEGORIES = [
  { id: "all", label: "All" },
  { id: "credentials", label: "Credentials" },
  { id: "ssh", label: "SSH" },
  { id: "pgp", label: "PGP" },
  { id: "x509", label: "X.509 / TLS" },
  { id: "tokens", label: "Tokens / API" },
  { id: "keys", label: "Key Material" },
  { id: "other", label: "Other" },
];

// Key pairs the secrets service generates (services/secrets GenerateKeyPair).
export const GENERATE_TYPE_OPTIONS = [
  { value: "ed25519", label: "Ed25519 (SSH)" },
  { value: "rsa-4096", label: "RSA-4096 (SSH)" },
  { value: "ecdsa-p384", label: "ECDSA-P384 (SSH)" },
  { value: "pgp-rsa-4096", label: "PGP / GPG (RSA-4096)" },
  { value: "age-x25519", label: "age (X25519)" },
  { value: "wireguard-curve25519", label: "WireGuard (Curve25519)" },
];

type Badge = { t: string; bg: string; fg: string; icon: LucideIcon };

// The secret types the service accepts (services/secrets/types.go).
const TYPE_BADGE_MAP: Record<string, Badge> = {
  api_key: { t: "API Key", bg: C.blueDim, fg: C.blueFg, icon: KeyRound },
  password: { t: "Password", bg: C.pinkDim, fg: C.pinkFg, icon: Lock },
  database_credentials: { t: "DB Credentials", bg: C.redDim, fg: C.redFg, icon: Lock },
  token: { t: "Token", bg: C.yellowDim, fg: C.yellowFg, icon: Shield },
  oauth_client_secret: { t: "OAuth", bg: C.orangeDim, fg: C.orangeFg, icon: Shield },
  ssh_private_key: { t: "SSH Key", bg: C.tealDim, fg: C.tealFg, icon: KeyRound },
  ssh_public_key: { t: "SSH Public", bg: C.tealDim, fg: C.tealFg, icon: KeyRound },
  pgp_private_key: { t: "PGP Key", bg: C.purpleDim, fg: C.purpleFg, icon: KeyRound },
  pgp_public_key: { t: "PGP Public", bg: C.purpleDim, fg: C.purpleFg, icon: KeyRound },
  ppk: { t: "PPK", bg: C.purpleDim, fg: C.purpleFg, icon: KeyRound },
  x509_certificate: { t: "X.509 Cert", bg: C.blueDim, fg: C.blueFg, icon: FileText },
  tls_certificate: { t: "TLS Cert", bg: C.blueDim, fg: C.blueFg, icon: FileText },
  tls_private_key: { t: "TLS Key", bg: C.blueDim, fg: C.blueFg, icon: KeyRound },
  pkcs12: { t: "PKCS#12", bg: C.yellowDim, fg: C.yellowFg, icon: FileText },
  jwk: { t: "JWK", bg: C.greenDim, fg: C.greenFg, icon: KeyRound },
  kerberos_keytab: { t: "Kerberos", bg: C.cyanDim, fg: C.cyanFg, icon: Shield },
  wireguard_private_key: { t: "WireGuard", bg: C.blueDim, fg: C.blueFg, icon: KeyRound },
  wireguard_public_key: { t: "WireGuard Pub", bg: C.blueDim, fg: C.blueFg, icon: KeyRound },
  age_key: { t: "age Key", bg: C.blueDim, fg: C.blueFg, icon: KeyRound },
  bitlocker_keys: { t: "BitLocker", bg: C.yellowDim, fg: C.yellowFg, icon: Lock },
  binary_blob: { t: "Binary", bg: C.blueDim, fg: C.blueFg, icon: FileText },
};
export const SUPPORTED_TYPES = Object.keys(TYPE_BADGE_MAP);

export const getBadge = (type?: string): Badge =>
  TYPE_BADGE_MAP[String(type || "").toLowerCase()] || { t: type || "secret", bg: C.blueDim, fg: C.blueFg, icon: Shield };

export function matchesCategory(secret: SecretItem, cat: string): boolean {
  const t = String(secret?.secret_type || "").toLowerCase();
  switch (cat) {
    case "credentials": return ["password", "database_credentials", "oauth_client_secret"].includes(t);
    case "ssh": return t.includes("ssh_") || t === "ppk";
    case "pgp": return t.includes("pgp_");
    case "x509": return ["x509_certificate", "tls_certificate", "tls_private_key", "pkcs12"].includes(t);
    case "tokens": return ["api_key", "token", "oauth_client_secret"].includes(t);
    case "keys": return ["jwk", "wireguard_private_key", "wireguard_public_key", "age_key", "kerberos_keytab", "bitlocker_keys"].includes(t);
    case "other": return t === "binary_blob";
    default: return true;
  }
}

export function ttlLabel(s: SecretItem): string {
  const ttl = Number(s?.lease_ttl_seconds || 0);
  if (ttl <= 0) return "No expiry";
  if (ttl >= 86400) return `${Math.round(ttl / 86400)}d`;
  if (ttl >= 3600) return `${Math.round(ttl / 3600)}h`;
  if (ttl >= 60) return `${Math.round(ttl / 60)}m`;
  return `${ttl}s`;
}

export function defaultFormatForType(secret: SecretItem): string {
  const t = String(secret?.secret_type || "");
  if (t === "ssh_private_key") return "pem";
  if (t.includes("pgp_")) return "armored";
  if (t === "jwk") return "jwk";
  if (t === "pkcs12") return "extract";
  return "raw";
}

const TTL_SECONDS: Record<string, number> = { none: 0, "1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000, "90d": 7776000, "365d": 31536000 };
export const ttlToSeconds = (mode: string, custom: string) =>
  mode === "custom" ? Math.max(0, Math.trunc(Number(custom || 0))) : TTL_SECONDS[mode] ?? 0;

// The folder a secret sits in: the directory part of its path (its "path"
// label, then its name; a Vault KV path such as app/prod/db is already one).
export function secretPath(s: SecretItem): string {
  const full = s?.path || `${String(s?.labels?.path || "")}/${String(s?.name || "")}`;
  const parts = full.split("/").filter(Boolean);
  return parts.length >= 2 ? `/${parts.slice(0, -1).join("/")}` : "/";
}

// Fills are the validated chart tokens of index.css (--cls-*), reused by
// meaning: red is past due, amber is due soon, teal is healthy, grey is none.
const FILL = { bad: "var(--cls-weak)", soon: "var(--cls-qv)", ok: "var(--cls-strong)", none: "var(--cls-unknown)" };
export const SERIES_FILL = FILL.ok;

export const EXPIRY_BUCKETS = [
  { id: "expired", label: "Expired", color: FILL.bad },
  { id: "7d", label: "Within 7 days", color: FILL.soon },
  { id: "30d", label: "8 to 30 days", color: FILL.soon },
  { id: "90d", label: "31 to 90 days", color: FILL.ok },
  { id: "later", label: "After 90 days", color: FILL.ok },
  { id: "none", label: "No expiry", color: FILL.none },
] as const;

export function expiryBucket(s: SecretItem, now: number): string {
  if (!s.expires_at) return "none";
  const ms = new Date(s.expires_at).getTime() - now;
  if (ms <= 0) return "expired";
  if (ms <= 7 * DAY) return "7d";
  if (ms <= 30 * DAY) return "30d";
  if (ms <= 90 * DAY) return "90d";
  return "later";
}

// Time since the secret last changed (updated_at: a new value or an edit).
export const AGE_BUCKETS = [
  { id: "7d", label: "Last 7 days" },
  { id: "30d", label: "8 to 30 days" },
  { id: "90d", label: "31 to 90 days" },
  { id: "365d", label: "91 to 365 days" },
  { id: "older", label: "Over a year" },
] as const;

export function ageBucket(s: SecretItem, now: number): string {
  const ms = now - new Date(s.updated_at || s.created_at || 0).getTime();
  if (ms <= 7 * DAY) return "7d";
  if (ms <= 30 * DAY) return "30d";
  if (ms <= 90 * DAY) return "90d";
  if (ms <= 365 * DAY) return "365d";
  return "older";
}

const labelOf = (list: readonly { id: string; label: string }[], id: string) => list.find((b) => b.id === id)?.label ?? id;

export const typeDrill = (type: string): VaultDrill =>
  ({ key: `type:${type}`, label: `Type: ${getBadge(type).t}`, match: (s) => String(s.secret_type || "").toLowerCase() === type });
export const expiryDrill = (id: string, now: number): VaultDrill =>
  ({ key: `expiry:${id}`, label: `Expiry: ${labelOf(EXPIRY_BUCKETS, id)}`, match: (s) => expiryBucket(s, now) === id });
export const ageDrill = (id: string, now: number): VaultDrill =>
  ({ key: `age:${id}`, label: `Last changed: ${labelOf(AGE_BUCKETS, id)}`, match: (s) => ageBucket(s, now) === id });
export const expiringDrill = (now: number): VaultDrill =>
  ({ key: "expiring", label: "Expiring within 30 days", match: (s) => ["7d", "30d"].includes(expiryBucket(s, now)) });
export const neverRotatedDrill = (): VaultDrill =>
  ({ key: "v1", label: "Never rotated (still version 1)", match: (s) => Number(s.current_version) === 1 });
export const restrictedDrill = (): VaultDrill =>
  ({ key: "restricted", label: "Value limited by an access rule", match: (s) => s.restricted === true });
export const allDrill = (): VaultDrill => ({ key: "all", label: "All secrets", match: () => true });

// The Vault / OpenBao KV routes the secrets service registers
// (services/secrets/handler.go). X-Vault-Namespace carries the tenant.
export const VAULT_ROUTES = [
  { method: "GET", path: "/v1/{mount}/data/{path}", what: "KV v2 read" },
  { method: "GET", path: "/v1/{mount}/data/{path}?version=N", what: "KV v2 read of a version" },
  { method: "POST", path: "/v1/{mount}/data/{path}", what: "KV v2 write (new version)" },
  { method: "DELETE", path: "/v1/{mount}/data/{path}", what: "Delete (recoverable)" },
  { method: "GET", path: "/v1/{mount}/metadata/{path}", what: "KV v2 metadata" },
  { method: "GET", path: "/v1/{mount}/{path}", what: "KV v1 read" },
  { method: "POST", path: "/v1/{mount}/{path}", what: "KV v1 write" },
  { method: "GET", path: "/v1/sys/health", what: "Health" },
  { method: "POST", path: "/v1/auth/token/lookup-self", what: "Token lookup" },
];
