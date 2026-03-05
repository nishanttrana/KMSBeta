// @ts-nocheck
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Clock, Copy, Download, Eye, EyeOff, FileText, Folder, History, KeyRound,
  Lock, Plus, RefreshCcw, RotateCcw, ScrollText, Search, Shield,
  ShieldAlert, Trash2, Upload
} from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import {
  createSecret,
  deleteSecret as deleteVaultSecret,
  generateKeyPairSecret,
  getSecretAuditLog,
  getSecretValue,
  getVaultStats,
  listSecrets,
  listSecretVersions,
  rotateSecret,
  updateSecret,
  type SecretAuditEntry,
  type SecretItem,
  type SecretVersionInfo,
  type VaultStats
} from "../../../lib/secrets";
import { B, Bar, Btn, Card, Chk, FG, Inp, Modal, Row2, Row3, Section, Sel, Stat, Tabs, Txt, usePromptDialog } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";

/* ── helpers ── */
function safeFileName(input, fallback = "secret") {
  return String(input || "").trim().replace(/[^a-zA-Z0-9._-]/g, "_").replace(/^_+|_+$/g, "") || fallback;
}
function fmtDate(v) {
  if (!v) return "—";
  try { const d = new Date(v); return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }) + " " + d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }); } catch { return "—"; }
}
function fmtDateShort(v) {
  if (!v) return "—";
  try { return new Date(v).toLocaleDateString("en-US", { month: "short", day: "numeric" }); } catch { return "—"; }
}
function fmtAgo(v) {
  if (!v) return "";
  try {
    const ms = Date.now() - new Date(v).getTime();
    if (ms < 60000) return "just now";
    if (ms < 3600000) return `${Math.floor(ms / 60000)}m ago`;
    if (ms < 86400000) return `${Math.floor(ms / 3600000)}h ago`;
    return `${Math.floor(ms / 86400000)}d ago`;
  } catch { return ""; }
}
function copyToClipboard(text, onToast) {
  navigator.clipboard.writeText(text).then(() => onToast?.("Copied to clipboard.")).catch(() => onToast?.("Copy failed."));
}

/* ── constants ── */
const CATEGORIES = [
  { id: "all", label: "All" },
  { id: "credentials", label: "Credentials" },
  { id: "ssh", label: "SSH" },
  { id: "pgp", label: "PGP" },
  { id: "x509", label: "X.509 / TLS" },
  { id: "tokens", label: "Tokens / API" },
  { id: "keys", label: "Key Material" },
  { id: "other", label: "Other" }
];

const GENERATE_TYPE_OPTIONS = [
  { value: "ed25519", label: "Ed25519 (SSH - recommended)" },
  { value: "rsa-4096", label: "RSA-4096 (SSH)" },
  { value: "ecdsa-p384", label: "ECDSA-P384 (SSH)" },
  { value: "pgp-rsa-4096", label: "PGP / GPG (RSA-4096)" },
  { value: "age-x25519", label: "age (X25519)" },
  { value: "wireguard-curve25519", label: "WireGuard (Curve25519)" }
];

const SUPPORTED_TYPES = [
  "api_key", "password", "database_credentials", "token", "oauth_client_secret",
  "ssh_private_key", "ssh_public_key", "pgp_private_key", "pgp_public_key", "ppk",
  "x509_certificate", "pkcs12", "jwk", "kerberos_keytab", "wireguard_private_key",
  "wireguard_public_key", "age_key", "tls_private_key", "tls_certificate", "binary_blob",
  "bitlocker_keys"
];

const TYPE_BADGE_MAP = {
  api_key: { t: "API Key", bg: C.blueDim, fg: C.blue, icon: KeyRound },
  password: { t: "Password", bg: C.pinkDim, fg: C.pink, icon: Lock },
  database_credentials: { t: "DB Credentials", bg: C.redDim, fg: C.red, icon: Lock },
  token: { t: "Token", bg: C.yellowDim, fg: C.yellow, icon: Shield },
  oauth_client_secret: { t: "OAuth", bg: C.orangeDim, fg: C.orange, icon: Shield },
  ssh_private_key: { t: "SSH Key", bg: C.tealDim, fg: C.teal, icon: KeyRound },
  ssh_public_key: { t: "SSH Public", bg: C.tealDim, fg: C.teal, icon: KeyRound },
  pgp_private_key: { t: "PGP Key", bg: C.purpleDim, fg: C.purple, icon: KeyRound },
  pgp_public_key: { t: "PGP Public", bg: C.purpleDim, fg: C.purple, icon: KeyRound },
  ppk: { t: "PPK", bg: C.purpleDim, fg: C.purple, icon: KeyRound },
  x509_certificate: { t: "X.509 Cert", bg: C.blueDim, fg: C.blue, icon: FileText },
  tls_certificate: { t: "TLS Cert", bg: C.blueDim, fg: C.blue, icon: FileText },
  tls_private_key: { t: "TLS Key", bg: C.blueDim, fg: C.blue, icon: KeyRound },
  pkcs12: { t: "PKCS#12", bg: C.yellowDim, fg: C.yellow, icon: FileText },
  jwk: { t: "JWK", bg: C.greenDim, fg: C.green, icon: KeyRound },
  kerberos_keytab: { t: "Kerberos", bg: C.cyanDim, fg: C.cyan, icon: Shield },
  wireguard_private_key: { t: "WireGuard", bg: C.blueDim, fg: C.blue, icon: KeyRound },
  wireguard_public_key: { t: "WireGuard Pub", bg: C.blueDim, fg: C.blue, icon: KeyRound },
  age_key: { t: "age Key", bg: C.blueDim, fg: C.blue, icon: KeyRound },
  bitlocker_keys: { t: "BitLocker", bg: C.yellowDim, fg: C.yellow, icon: Lock },
  binary_blob: { t: "Binary", bg: C.blueDim, fg: C.blue, icon: FileText }
};

function getBadge(type) {
  return TYPE_BADGE_MAP[String(type || "").toLowerCase()] || { t: type || "secret", bg: C.blueDim, fg: C.blue, icon: Shield };
}

function matchesCategory(secret, cat) {
  if (cat === "all") return true;
  const t = String(secret?.secret_type || "").toLowerCase();
  if (cat === "credentials") return ["password", "database_credentials", "oauth_client_secret"].includes(t);
  if (cat === "ssh") return t.includes("ssh_") || t === "ppk";
  if (cat === "pgp") return t.includes("pgp_");
  if (cat === "x509") return ["x509_certificate", "tls_certificate", "tls_private_key", "pkcs12"].includes(t);
  if (cat === "tokens") return ["api_key", "token", "oauth_client_secret"].includes(t);
  if (cat === "keys") return ["jwk", "wireguard_private_key", "wireguard_public_key", "age_key", "kerberos_keytab", "bitlocker_keys"].includes(t);
  if (cat === "other") return t === "binary_blob";
  return true;
}

function ttlLabel(s) {
  const ttl = Number(s?.lease_ttl_seconds || 0);
  if (ttl <= 0) return "No expiry";
  if (ttl >= 86400) return `${Math.round(ttl / 86400)}d`;
  if (ttl >= 3600) return `${Math.round(ttl / 3600)}h`;
  if (ttl >= 60) return `${Math.round(ttl / 60)}m`;
  return `${ttl}s`;
}

function expiryStatus(s) {
  if (!s?.expires_at) return null;
  const ms = new Date(s.expires_at).getTime() - Date.now();
  if (ms <= 0) return { label: "Expired", color: C.red };
  if (ms < 7 * 86400000) return { label: "Expiring soon", color: C.amber };
  return null;
}

function defaultFormatForType(secret) {
  const t = String(secret?.secret_type || "");
  if (t === "ssh_private_key") return "pem";
  if (t.includes("pgp_")) return "armored";
  if (t === "ppk") return "ppk";
  if (t === "jwk") return "jwk";
  if (t === "pkcs12") return "extract";
  return "raw";
}

function ttlToSeconds(mode, custom) {
  if (mode === "none") return 0;
  if (mode === "1h") return 3600;
  if (mode === "24h") return 86400;
  if (mode === "7d") return 604800;
  if (mode === "30d") return 2592000;
  if (mode === "90d") return 7776000;
  if (mode === "365d") return 31536000;
  if (mode === "custom") return Math.max(0, Math.trunc(Number(custom || 0)));
  return 0;
}

/* ── MAIN COMPONENT ── */
export const VaultTab = ({ session, onToast }: { session: AuthSession | null; onToast?: (m: string) => void }) => {
  const [modal, setModal] = useState(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [secrets, setSecrets] = useState([]);
  const [stats, setStats] = useState(null);
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("all");
  const [sortBy, setSortBy] = useState("updated");

  // Folder hierarchy (OpenBao-compatible path structure)
  const [currentPath, setCurrentPath] = useState("/");
  const [folderModalOpen, setFolderModalOpen] = useState(false);
  const [newFolderName, setNewFolderName] = useState("");

  // Create form
  const [createName, setCreateName] = useState("");
  const [createType, setCreateType] = useState("api_key");
  const [createValue, setCreateValue] = useState("");
  const [createDesc, setCreateDesc] = useState("");
  const [createTTLMode, setCreateTTLMode] = useState("none");
  const [createTTLCustom, setCreateTTLCustom] = useState("");
  const [createLeaseBased, setCreateLeaseBased] = useState(false);
  const [createDeliveryFormat, setCreateDeliveryFormat] = useState("raw");
  const [envelopeEncryption, setEnvelopeEncryption] = useState(true);

  // Generate form
  const [generateType, setGenerateType] = useState("ed25519");
  const [generateName, setGenerateName] = useState("");
  const [generatedPublicKey, setGeneratedPublicKey] = useState("");

  // Retrieve/detail
  const [selectedSecret, setSelectedSecret] = useState(null);
  const [valueFormat, setValueFormat] = useState("raw");
  const [retrievedValue, setRetrievedValue] = useState("");
  const [retrievedType, setRetrievedType] = useState("");
  const [showValue, setShowValue] = useState(false);

  // Version history
  const [versions, setVersions] = useState([]);

  // Audit log
  const [auditEntries, setAuditEntries] = useState([]);

  // Rotate
  const [rotateValue, setRotateValue] = useState("");

  const promptDialog = usePromptDialog();

  /* ── data loading ── */
  const loadAll = useCallback(async (force = false) => {
    if (!session) return;
    setLoading(true);
    try {
      const [items, vaultStats] = await Promise.all([
        listSecrets(session, { limit: 500, offset: 0, noCache: force }),
        getVaultStats(session).catch(() => null)
      ]);
      setSecrets(Array.isArray(items) ? items : []);
      if (vaultStats) setStats(vaultStats);
    } catch (e) {
      onToast?.(`Secrets load failed: ${errMsg(e)}`);
    } finally {
      setLoading(false);
    }
  }, [session, onToast]);

  useEffect(() => { void loadAll(false); }, [loadAll]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try { await loadAll(true); onToast?.("Vault refreshed."); } finally { setRefreshing(false); }
  };

  /* ── filtering & sorting ── */
  const filtered = useMemo(() => {
    const q = String(search || "").trim().toLowerCase();
    let items = secrets.filter((s) => {
      if (!matchesCategory(s, category)) return false;
      if (!q) return true;
      return [s.name, s.id, s.secret_type, s.description, s.created_by].some((v) => String(v || "").toLowerCase().includes(q));
    });
    if (sortBy === "name") items.sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
    else if (sortBy === "type") items.sort((a, b) => String(a.secret_type || "").localeCompare(String(b.secret_type || "")));
    else if (sortBy === "created") items.sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime());
    else items.sort((a, b) => new Date(b.updated_at || 0).getTime() - new Date(a.updated_at || 0).getTime());
    return items;
  }, [secrets, search, category, sortBy]);

  /* ── folder hierarchy (OpenBao-compatible path structure) ── */
  const getSecretPath = (s: any): string => {
    const labels = s?.labels || s?.metadata || {};
    const path = String(labels?.path || labels?.folder || "").trim();
    if (path && path !== "/") return path.startsWith("/") ? path : `/${path}`;
    // Derive path from secret name convention: "dept/project/name" or "dept.project.name"
    const name = String(s?.name || "");
    const parts = name.includes("/") ? name.split("/") : name.includes(".") && name.split(".").length > 2 ? name.split(".") : null;
    if (parts && parts.length >= 2) return `/${parts.slice(0, -1).join("/")}`;
    return "/";
  };

  const folderTree = useMemo(() => {
    const folders = new Map<string, { secrets: any[], subfolders: Set<string> }>();
    // Always ensure root exists
    folders.set("/", { secrets: [], subfolders: new Set() });

    filtered.forEach((s) => {
      const path = getSecretPath(s);
      if (!folders.has(path)) folders.set(path, { secrets: [], subfolders: new Set() });
      folders.get(path)!.secrets.push(s);

      // Register parent folders
      const parts = path.split("/").filter(Boolean);
      for (let i = 0; i < parts.length; i++) {
        const parentPath = i === 0 ? "/" : `/${parts.slice(0, i).join("/")}`;
        const childPath = `/${parts.slice(0, i + 1).join("/")}`;
        if (!folders.has(parentPath)) folders.set(parentPath, { secrets: [], subfolders: new Set() });
        folders.get(parentPath)!.subfolders.add(childPath);
      }
    });
    return folders;
  }, [filtered]);

  const currentFolderData = useMemo(() => {
    const data = folderTree.get(currentPath);
    if (!data) return { secrets: filtered, subfolders: [] };
    return { secrets: data.secrets, subfolders: Array.from(data.subfolders).sort() };
  }, [folderTree, currentPath, filtered]);

  const breadcrumbs = useMemo(() => {
    const parts = currentPath.split("/").filter(Boolean);
    const crumbs = [{ label: "root", path: "/" }];
    parts.forEach((part, i) => {
      crumbs.push({ label: part, path: `/${parts.slice(0, i + 1).join("/")}` });
    });
    return crumbs;
  }, [currentPath]);

  const countSecretsInPath = (path: string): number => {
    let count = 0;
    folderTree.forEach((data, key) => {
      if (key === path || key.startsWith(path === "/" ? "/" : `${path}/`)) {
        count += data.secrets.length;
      }
    });
    return path === "/" ? filtered.length : count;
  };

  /* ── actions ── */
  const submitCreate = async () => {
    if (!session) return;
    if (!createName.trim() || !createType.trim() || !createValue) {
      onToast?.("Secret name, type, and value are required."); return;
    }
    setBusy(true);
    try {
      await createSecret(session, {
        name: createName.trim(),
        secret_type: createType.trim().toLowerCase().replace(/\s+/g, "_"),
        value: createValue,
        description: createDesc.trim(),
        labels: { delivery_format: createDeliveryFormat, path: currentPath === "/" ? "/" : currentPath },
        lease_ttl_seconds: ttlToSeconds(createTTLMode, createTTLCustom),
        metadata: { source: "dashboard", lease_based: createLeaseBased, envelope_encryption: envelopeEncryption, path: currentPath }
      });
      onToast?.("Secret stored securely.");
      setModal(null); setCreateName(""); setCreateValue(""); setCreateDesc(""); setCreateType("api_key"); setCreateTTLMode("none"); setCreateTTLCustom(""); setCreateLeaseBased(false); setCreateDeliveryFormat("raw");
      await loadAll(true);
    } catch (e) { onToast?.(`Store failed: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const submitGenerate = async () => {
    if (!session || !generateName.trim()) { onToast?.("Key name is required."); return; }
    setBusy(true);
    try {
      const out = await generateKeyPairSecret(session, { name: generateName.trim(), key_type: generateType, labels: { source: "dashboard", key_type: generateType }, lease_ttl_seconds: 0 });
      setGeneratedPublicKey(String(out.public_key || ""));
      onToast?.(`${String(out.key_type || generateType)} key pair generated. Private key stored in vault.`);
      await loadAll(true);
    } catch (e) { onToast?.(`Generate failed: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const openDetail = async (secret) => {
    if (!session) return;
    setSelectedSecret(secret);
    const format = defaultFormatForType(secret);
    setValueFormat(format); setRetrievedValue(""); setRetrievedType(""); setShowValue(false);
    setVersions([]); setAuditEntries([]);
    setModal("detail");
    setBusy(true);
    try {
      const [val, vers, audit] = await Promise.all([
        getSecretValue(session, secret.id, format).catch(() => ({ value: "", content_type: "" })),
        listSecretVersions(session, secret.id).catch(() => []),
        getSecretAuditLog(session, secret.id).catch(() => [])
      ]);
      setRetrievedValue(String(val.value || "")); setRetrievedType(String(val.content_type || ""));
      setVersions(vers); setAuditEntries(audit);
    } catch (e) { onToast?.(`Read failed: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const fetchFormat = async () => {
    if (!session || !selectedSecret) return;
    setBusy(true);
    try {
      const out = await getSecretValue(session, selectedSecret.id, valueFormat);
      setRetrievedValue(String(out.value || "")); setRetrievedType(String(out.content_type || ""));
      onToast?.(`Fetched in ${valueFormat} format.`);
    } catch (e) { onToast?.(`Format fetch failed: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const downloadSecret = async (secret) => {
    if (!session) return;
    setBusy(true);
    try {
      const format = defaultFormatForType(secret);
      const out = await getSecretValue(session, secret.id, format);
      const base = safeFileName(String(secret?.name || secret?.id || "secret"));
      const extMap = { pem: "pem", openssh: "pub", ppk: "ppk", armored: "asc", jwk: "json", extract: "json", raw: "txt" };
      const fn = `${base}.${extMap[format] || "txt"}`;
      const blob = new Blob([String(out.value || "")], { type: String(out.content_type || "text/plain") });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = fn; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
      onToast?.(`Downloaded ${secret.name}.`);
    } catch (e) { onToast?.(`Download failed: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const removeSecret = async (secret) => {
    if (!session) return;
    const ok = await promptDialog.confirm({ title: "Delete Secret", message: `Permanently delete "${secret.name}"? This cannot be undone.`, confirmLabel: "Delete", danger: true });
    if (!ok) return;
    setBusy(true);
    try {
      await deleteVaultSecret(session, secret.id);
      onToast?.("Secret deleted."); setModal(null);
      await loadAll(true);
    } catch (e) { onToast?.(`Delete failed: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const submitRotate = async () => {
    if (!session || !selectedSecret || !rotateValue) { onToast?.("New value is required for rotation."); return; }
    setBusy(true);
    try {
      const updated = await rotateSecret(session, selectedSecret.id, rotateValue);
      onToast?.(`Secret rotated to version ${updated.current_version}.`);
      setModal(null); setRotateValue("");
      await loadAll(true);
    } catch (e) { onToast?.(`Rotation failed: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  /* ── stats ── */
  const totalSecrets = stats?.total_secrets ?? secrets.length;
  const totalVersions = stats?.total_versions ?? 0;
  const expiringSoon = stats?.expiring_within_30d ?? 0;
  const expired = stats?.expired ?? 0;
  const typeBreakdown = stats?.by_type || {};

  return <div>
    {/* ── KPI Stats ── */}
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(160px,1fr))", gap: 10, marginBottom: 18 }}>
      <Stat l="Total Secrets" v={totalSecrets} s={`${Object.keys(typeBreakdown).length} types`} c="accent" i={Lock} />
      <Stat l="Versions" v={totalVersions} s="Total stored" c="blue" i={History} />
      <Stat l="Expiring (30d)" v={expiringSoon} s={expired > 0 ? `${expired} already expired` : "None expired"} c={expiringSoon > 0 ? "amber" : "green"} i={Clock} />
      <div style={{ flex: 1, background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, padding: "12px 14px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>Envelope Encryption</span>
          <Shield size={14} strokeWidth={2} color={C.dim} />
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 6 }}>
          <div
            onClick={() => setEnvelopeEncryption(!envelopeEncryption)}
            style={{ width: 40, height: 22, borderRadius: 11, background: envelopeEncryption ? C.green : C.border, cursor: "pointer", position: "relative", transition: "background .2s", flexShrink: 0 }}
          >
            <div style={{ width: 16, height: 16, borderRadius: 8, background: C.white, position: "absolute", top: 3, left: envelopeEncryption ? 21 : 3, transition: "left .2s", boxShadow: "0 1px 3px rgba(0,0,0,.3)" }} />
          </div>
          <span style={{ fontSize: 15, fontWeight: 700, color: envelopeEncryption ? C.green : C.muted, letterSpacing: -0.5 }}>
            {envelopeEncryption ? "AES-256-GCM" : "Off"}
          </span>
        </div>
        <div style={{ fontSize: 9, color: C.dim, marginTop: 4 }}>{envelopeEncryption ? "MEK-wrapped DEK per secret — all values encrypted at rest" : "Secrets stored without envelope encryption"}</div>
      </div>
    </div>

    {/* ── Toolbar ── */}
    <Section title="Secret Vault" actions={<>
      <Btn small onClick={handleRefresh} disabled={refreshing || busy}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}><RefreshCcw size={11} />{refreshing ? "Refreshing..." : "Refresh"}</span>
      </Btn>
    </>}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, marginBottom: 14, flexWrap: "wrap" }}>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {CATEGORIES.map((cat) => <button key={cat.id} onClick={() => setCategory(cat.id)} style={{
            height: 32, padding: "0 12px", borderRadius: 8,
            border: `1px solid ${category === cat.id ? C.accent : C.border}`,
            background: category === cat.id ? C.accentDim : "transparent",
            color: category === cat.id ? C.accent : C.muted, fontSize: 10, cursor: "pointer", fontWeight: 600
          }}>{cat.label}</button>)}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn primary onClick={() => setModal("create")} style={{ height: 34, padding: "0 18px", borderRadius: 8, fontWeight: 700 }}>
            <Plus size={12} /> Store Secret
          </Btn>
          <Btn onClick={() => { setGeneratedPublicKey(""); setGenerateName(""); setModal("generate"); }} style={{ height: 34, padding: "0 14px", borderRadius: 8 }}>
            <KeyRound size={12} /> Generate
          </Btn>
        </div>
      </div>

      {/* ── Search + Sort ── */}
      <div style={{ display: "flex", gap: 10, marginBottom: 14, alignItems: "center", flexWrap: "wrap" }}>
        <div style={{ position: "relative", flex: 1, minWidth: 200, maxWidth: 400 }}>
          <Search size={13} style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: C.muted }} />
          <Inp placeholder="Search secrets..." value={search} onChange={(e) => setSearch(e.target.value)} style={{ paddingLeft: 30, height: 34 }} />
        </div>
        <Sel value={sortBy} onChange={(e) => setSortBy(e.target.value)} w={150} style={{ height: 34 }}>
          <option value="updated">Recently Updated</option>
          <option value="created">Recently Created</option>
          <option value="name">Name A-Z</option>
          <option value="type">By Type</option>
        </Sel>
        <div style={{ fontSize: 10, color: C.muted }}>{filtered.length} secret{filtered.length !== 1 ? "s" : ""}</div>
      </div>

      {/* ── Type Distribution Bar ── */}
      {Object.keys(typeBreakdown).length > 0 && totalSecrets > 0 && <div style={{ marginBottom: 14 }}>
        <div style={{ display: "flex", height: 6, borderRadius: 3, overflow: "hidden", background: C.border }}>
          {Object.entries(typeBreakdown).map(([t, c]) => {
            const badge = getBadge(t);
            return <div key={t} style={{ width: `${(c / totalSecrets) * 100}%`, background: badge.fg, minWidth: 2 }} title={`${badge.t}: ${c}`} />;
          })}
        </div>
        <div style={{ display: "flex", gap: 10, marginTop: 6, flexWrap: "wrap" }}>
          {Object.entries(typeBreakdown).map(([t, c]) => {
            const badge = getBadge(t);
            return <span key={t} style={{ fontSize: 9, color: C.muted, display: "inline-flex", alignItems: "center", gap: 4 }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, background: badge.fg, display: "inline-block" }} />
              {badge.t} ({c})
            </span>;
          })}
        </div>
      </div>}

      {/* ── Folder Hierarchy (OpenBao-compatible) ── */}
      <div style={{ marginBottom: 14 }}>
        {/* Breadcrumb Navigation */}
        <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 8, flexWrap: "wrap" }}>
          <span style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginRight: 4 }}>Path:</span>
          {breadcrumbs.map((crumb, i) => (
            <span key={crumb.path} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
              {i > 0 && <span style={{ color: C.muted, fontSize: 10 }}>/</span>}
              <span
                onClick={() => setCurrentPath(crumb.path)}
                style={{ fontSize: 10, color: crumb.path === currentPath ? C.accent : C.text, cursor: "pointer", fontWeight: crumb.path === currentPath ? 700 : 400, padding: "2px 4px", borderRadius: 4, background: crumb.path === currentPath ? C.accentDim : "transparent" }}
              >{crumb.label}</span>
            </span>
          ))}
          <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
            <Btn small onClick={() => { setNewFolderName(""); setFolderModalOpen(true); }} style={{ height: 24, fontSize: 9 }}>+ Folder</Btn>
          </span>
        </div>

        {/* Subfolder Cards */}
        {currentFolderData.subfolders.length > 0 && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(180px,1fr))", gap: 8, marginBottom: 10 }}>
            {currentFolderData.subfolders.map((folderPath) => {
              const folderName = folderPath.split("/").filter(Boolean).pop() || folderPath;
              const secretCount = countSecretsInPath(folderPath);
              return (
                <div
                  key={folderPath}
                  onClick={() => setCurrentPath(folderPath)}
                  style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, cursor: "pointer", transition: "border-color .15s" }}
                  onMouseEnter={(e) => { e.currentTarget.style.borderColor = C.accent; }}
                  onMouseLeave={(e) => { e.currentTarget.style.borderColor = C.border; }}
                >
                  <div style={{ width: 28, height: 28, borderRadius: 6, background: C.accentDim, display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <Folder size={14} color={C.accent} />
                  </div>
                  <div>
                    <div style={{ fontSize: 11, fontWeight: 600, color: C.text }}>{folderName}</div>
                    <div style={{ fontSize: 9, color: C.dim }}>{secretCount} secret{secretCount !== 1 ? "s" : ""}</div>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Path info */}
        <div style={{ fontSize: 9, color: C.dim, marginBottom: 4 }}>
          {currentPath === "/" ? `${filtered.length} secrets total across all paths` : `${currentFolderData.secrets.length} secrets in ${currentPath}`}
          {currentPath !== "/" && <span onClick={() => setCurrentPath("/")} style={{ color: C.accent, cursor: "pointer", marginLeft: 8 }}>Show all</span>}
        </div>
      </div>

      {/* Create Folder Modal */}
      {folderModalOpen && <Modal open={folderModalOpen} title="Create Folder" onClose={() => setFolderModalOpen(false)}>
        <div style={{ fontSize: 10, color: C.dim, marginBottom: 10 }}>
          Create a folder path for organizing secrets by department, project, or environment. Compatible with OpenBao/Vault path-based access policies.
        </div>
        <FG label="Folder Name" hint="e.g. engineering, production, finance/accounts">
          <Inp value={newFolderName} onChange={(e) => setNewFolderName(e.target.value)} placeholder="department-name" />
        </FG>
        <div style={{ fontSize: 9, color: C.muted, marginTop: 4 }}>
          Full path: <code style={{ color: C.accent }}>{currentPath === "/" ? "/" : currentPath + "/"}{newFolderName || "<name>"}</code>
        </div>
        <div style={{ marginTop: 10, padding: "8px 12px", borderRadius: 6, background: `${C.blue}12`, border: `1px solid ${C.blue}33`, fontSize: 10, color: C.dim }}>
          <b style={{ color: C.blue }}>OpenBao compatible:</b> Folder paths map to Vault/OpenBao secret engine paths. Use <code style={{ color: C.accent }}>secret/data/{"{path}"}</code> for KV v2 access. Hooks and policies apply at each path level.
        </div>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
          <Btn onClick={() => setFolderModalOpen(false)}>Cancel</Btn>
          <Btn primary onClick={() => {
            const folderName = newFolderName.trim().replace(/[^a-zA-Z0-9._/-]/g, "-").replace(/\/+/g, "/").replace(/^\/|\/$/g, "");
            if (!folderName) { onToast?.("Folder name is required."); return; }
            const newPath = currentPath === "/" ? `/${folderName}` : `${currentPath}/${folderName}`;
            setCurrentPath(newPath);
            setFolderModalOpen(false);
            onToast?.(`Navigated to ${newPath}. Store secrets here to populate the folder.`);
          }} disabled={!newFolderName.trim()}>Create & Navigate</Btn>
        </div>
      </Modal>}

      {/* ── Secret Cards Grid ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(320px,1fr))", gap: 10 }}>
        {(currentPath === "/" ? filtered : currentFolderData.secrets).map((s) => {
          const badge = getBadge(s.secret_type);
          const BadgeIcon = badge.icon;
          const exp = expiryStatus(s);
          return <div key={s.id} onClick={() => void openDetail(s)} style={{
            background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: "14px 16px",
            cursor: "pointer", transition: "border-color .15s, box-shadow .15s",
            borderLeft: `3px solid ${badge.fg}`,
          }}
            onMouseEnter={(e) => { e.currentTarget.style.borderColor = badge.fg; e.currentTarget.style.boxShadow = `0 0 0 1px ${badge.fg}22`; }}
            onMouseLeave={(e) => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.borderLeftColor = badge.fg; e.currentTarget.style.boxShadow = "none"; }}
          >
            <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: C.text, lineHeight: 1.3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.name}</div>
                {s.description && <div style={{ fontSize: 10, color: C.muted, marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.description}</div>}
              </div>
              <span style={{ background: badge.bg, color: badge.fg, borderRadius: 6, padding: "3px 8px", fontSize: 9, fontWeight: 700, whiteSpace: "nowrap", display: "inline-flex", alignItems: "center", gap: 4 }}>
                <BadgeIcon size={10} /> {badge.t}
              </span>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 10, color: C.muted }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 3 }}><Clock size={9} /> {ttlLabel(s)}</span>
                <span style={{ color: C.dim }}>v{s.current_version}</span>
                {exp && <span style={{ color: exp.color, fontWeight: 600, display: "inline-flex", alignItems: "center", gap: 3 }}>
                  <ShieldAlert size={9} /> {exp.label}
                </span>}
              </div>
              <span>{fmtAgo(s.updated_at)}</span>
            </div>

            <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
              <Btn small onClick={(e) => { e.stopPropagation(); void downloadSecret(s); }} disabled={busy}><Download size={10} /> Download</Btn>
              <Btn small danger onClick={(e) => { e.stopPropagation(); void removeSecret(s); }} disabled={busy}><Trash2 size={10} /> Delete</Btn>
            </div>
          </div>;
        })}
      </div>

      {/* ── Empty State ── */}
      {!filtered.length && <div style={{ textAlign: "center", padding: "40px 20px" }}>
        {loading ? <div style={{ fontSize: 12, color: C.muted }}>Loading secrets...</div> : <>
          <Lock size={40} strokeWidth={1} color={C.muted} style={{ marginBottom: 12 }} />
          <div style={{ fontSize: 13, fontWeight: 600, color: C.dim, marginBottom: 6 }}>
            {secrets.length === 0 ? "No secrets stored yet" : "No secrets match your filter"}
          </div>
          <div style={{ fontSize: 10, color: C.muted, maxWidth: 360, margin: "0 auto", lineHeight: 1.6 }}>
            {secrets.length === 0
              ? `Store API keys, database credentials, SSH keys, certificates, tokens, and other sensitive material.${envelopeEncryption ? " All values are envelope-encrypted at rest with AES-256-GCM." : ""}`
              : "Try adjusting your search or category filter."}
          </div>
          {secrets.length === 0 && <div style={{ marginTop: 16, display: "flex", gap: 8, justifyContent: "center" }}>
            <Btn primary onClick={() => setModal("create")}><Plus size={12} /> Store Your First Secret</Btn>
            <Btn onClick={() => { setGeneratedPublicKey(""); setGenerateName(""); setModal("generate"); }}><KeyRound size={12} /> Generate Key Pair</Btn>
          </div>}
        </>}
      </div>}
    </Section>

    {/* ── OpenBao Compatibility & Hooks ── */}
    <Section title="OpenBao Compatibility">
      <Card style={{ padding: 14 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 8 }}>API Compatibility</div>
            <div style={{ display: "grid", gap: 4, fontSize: 10, color: C.dim }}>
              {[
                { api: "secret/data/{path}", desc: "KV v2 read/write — maps to vault paths" },
                { api: "secret/metadata/{path}", desc: "KV v2 metadata — version history" },
                { api: "secret/delete/{path}", desc: "Soft delete secret versions" },
                { api: "secret/undelete/{path}", desc: "Restore soft-deleted versions" },
                { api: "sys/mounts/secret", desc: "Mount configuration" },
                { api: "sys/policies/acl/{name}", desc: "Path-based ACL policies" },
              ].map((item) => (
                <div key={item.api} style={{ display: "flex", gap: 8, padding: "4px 0", borderBottom: `1px solid ${C.border}` }}>
                  <code style={{ color: C.accent, fontSize: 9, fontFamily: "'JetBrains Mono',monospace", minWidth: 200 }}>{item.api}</code>
                  <span>{item.desc}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 8 }}>Event Hooks</div>
            <div style={{ display: "grid", gap: 4, fontSize: 10, color: C.dim }}>
              {[
                { hook: "secret.created", desc: "Fires when a new secret is stored at any path" },
                { hook: "secret.updated", desc: "Fires when secret value is modified" },
                { hook: "secret.rotated", desc: "Fires on version rotation — triggers downstream sync" },
                { hook: "secret.deleted", desc: "Fires on soft or hard delete" },
                { hook: "secret.accessed", desc: "Fires on read — for audit and access tracking" },
                { hook: "secret.expired", desc: "Fires when TTL/lease expires — auto-cleanup trigger" },
                { hook: "folder.policy_changed", desc: "Fires when path ACL policy is modified" },
              ].map((item) => (
                <div key={item.hook} style={{ display: "flex", gap: 8, padding: "4px 0", borderBottom: `1px solid ${C.border}` }}>
                  <code style={{ color: C.green, fontSize: 9, fontFamily: "'JetBrains Mono',monospace", minWidth: 180 }}>{item.hook}</code>
                  <span>{item.desc}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div style={{ marginTop: 12, padding: "8px 12px", borderRadius: 6, background: `${C.purple}12`, border: `1px solid ${C.purple}33`, fontSize: 10, color: C.dim }}>
          <b style={{ color: C.purple }}>OpenBao extensions:</b> Custom plugin backends, transit engine for encryption-as-a-service, and identity/entity aliases are supported through the hooks system. Configure webhooks in Administration → Event Hooks.
        </div>
      </Card>
    </Section>

    {/* ══════════════ STORE SECRET MODAL ══════════════ */}
    <Modal open={modal === "create"} onClose={() => setModal(null)} title="Store New Secret" wide>
      <Row2>
        <FG label="Name" required hint="Unique identifier for this secret"><Inp placeholder="prod-api-key-stripe" value={createName} onChange={(e) => setCreateName(e.target.value)} /></FG>
        <FG label="Type" required>
          <Sel value={createType} onChange={(e) => setCreateType(e.target.value)}>
            {SUPPORTED_TYPES.map((t) => <option key={t} value={t}>{getBadge(t).t}</option>)}
          </Sel>
        </FG>
      </Row2>
      <FG label="Description" hint="Optional context for this secret"><Inp placeholder="Stripe production API key for billing service" value={createDesc} onChange={(e) => setCreateDesc(e.target.value)} /></FG>
      <FG label="Secret Value" required hint={envelopeEncryption ? "Envelope-encrypted at rest with AES-256-GCM. Never stored plaintext." : "Encryption disabled — secret will be stored as-is."}>
        <Txt placeholder="Paste API key, PEM block, JSON, password..." rows={6} value={createValue} onChange={(e) => setCreateValue(e.target.value)} />
      </FG>
      <Row2>
        <FG label="TTL / Expiration">
          <Sel value={createTTLMode} onChange={(e) => setCreateTTLMode(e.target.value)}>
            <option value="none">No expiry</option>
            <option value="1h">1 hour</option>
            <option value="24h">24 hours</option>
            <option value="7d">7 days</option>
            <option value="30d">30 days</option>
            <option value="90d">90 days</option>
            <option value="365d">365 days</option>
            <option value="custom">Custom (seconds)</option>
          </Sel>
        </FG>
        <FG label="Delivery Format">
          <Sel value={createDeliveryFormat} onChange={(e) => setCreateDeliveryFormat(e.target.value)}>
            <option value="raw">As stored (raw)</option>
            <option value="pem">PEM</option>
            <option value="jwk">JWK</option>
            <option value="armored">Armored</option>
            <option value="ppk">PPK</option>
          </Sel>
        </FG>
      </Row2>
      {createTTLMode === "custom" && <FG label="Custom TTL (seconds)"><Inp type="number" min="0" value={createTTLCustom} onChange={(e) => setCreateTTLCustom(e.target.value)} /></FG>}
      <Chk label="Lease-based access (must renew TTL before expiry)" checked={createLeaseBased} onChange={() => setCreateLeaseBased((v) => !v)} />
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
        <Btn onClick={() => setModal(null)} disabled={busy}>Cancel</Btn>
        <Btn primary onClick={() => void submitCreate()} disabled={busy}>{busy ? "Encrypting..." : "Store Secret"}</Btn>
      </div>
    </Modal>

    {/* ══════════════ GENERATE KEY PAIR MODAL ══════════════ */}
    <Modal open={modal === "generate"} onClose={() => setModal(null)} title="Generate Key Pair">
      <FG label="Key Type" required>
        <Sel value={generateType} onChange={(e) => setGenerateType(e.target.value)}>
          {GENERATE_TYPE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </Sel>
      </FG>
      <FG label="Name" required hint="Private key stored in vault, public key displayed for copy"><Inp placeholder="deploy-key-production" value={generateName} onChange={(e) => setGenerateName(e.target.value)} /></FG>
      {generatedPublicKey && <FG label="Generated Public Key">
        <Txt rows={4} value={generatedPublicKey} readOnly />
        <div style={{ marginTop: 6 }}><Btn small onClick={() => copyToClipboard(generatedPublicKey, onToast)}><Copy size={10} /> Copy Public Key</Btn></div>
      </FG>}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
        <Btn onClick={() => setModal(null)} disabled={busy}>Cancel</Btn>
        <Btn primary onClick={() => void submitGenerate()} disabled={busy}>{busy ? "Generating..." : "Generate Key Pair"}</Btn>
      </div>
    </Modal>

    {/* ══════════════ SECRET DETAIL MODAL ══════════════ */}
    <Modal open={modal === "detail"} onClose={() => setModal(null)} title={selectedSecret ? `Secret: ${selectedSecret.name}` : "Secret Detail"} wide>
      {selectedSecret && <>
        {/* ── Metadata ── */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 16 }}>
          <div style={{ background: C.card, borderRadius: 8, padding: "10px 12px" }}>
            <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", marginBottom: 4 }}>Type</div>
            <div style={{ fontSize: 12, color: getBadge(selectedSecret.secret_type).fg, fontWeight: 600 }}>{getBadge(selectedSecret.secret_type).t}</div>
          </div>
          <div style={{ background: C.card, borderRadius: 8, padding: "10px 12px" }}>
            <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", marginBottom: 4 }}>Version</div>
            <div style={{ fontSize: 12, color: C.accent, fontWeight: 600 }}>v{selectedSecret.current_version}</div>
          </div>
          <div style={{ background: C.card, borderRadius: 8, padding: "10px 12px" }}>
            <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", marginBottom: 4 }}>TTL</div>
            <div style={{ fontSize: 12, color: C.text, fontWeight: 600 }}>{ttlLabel(selectedSecret)}</div>
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 16, fontSize: 10, color: C.dim }}>
          <div><span style={{ color: C.muted }}>Created: </span>{fmtDate(selectedSecret.created_at)}</div>
          <div><span style={{ color: C.muted }}>Updated: </span>{fmtDate(selectedSecret.updated_at)}</div>
          <div><span style={{ color: C.muted }}>Created by: </span>{selectedSecret.created_by || "—"}</div>
          <div><span style={{ color: C.muted }}>ID: </span><span style={{ fontFamily: "'IBM Plex Mono',monospace", fontSize: 9 }}>{selectedSecret.id}</span></div>
          {selectedSecret.expires_at && <div><span style={{ color: C.muted }}>Expires: </span><span style={{ color: expiryStatus(selectedSecret)?.color || C.text }}>{fmtDate(selectedSecret.expires_at)}</span></div>}
          {selectedSecret.description && <div style={{ gridColumn: "1/3" }}><span style={{ color: C.muted }}>Description: </span>{selectedSecret.description}</div>}
        </div>

        {/* ── Retrieve Value ── */}
        <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 14, marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}><Eye size={13} /> Secret Value</div>
          <Row2>
            <FG label="Output Format">
              <Sel value={valueFormat} onChange={(e) => setValueFormat(e.target.value)}>
                <option value="raw">raw</option><option value="pem">pem</option><option value="openssh">openssh</option>
                <option value="ppk">ppk</option><option value="extract">extract</option><option value="jwk">jwk</option>
                <option value="armored">armored</option>
              </Sel>
            </FG>
            <FG label="Content Type"><Inp value={retrievedType} readOnly /></FG>
          </Row2>
          <FG label="Value">
            <div style={{ position: "relative" }}>
              <Txt rows={6} value={showValue ? retrievedValue : (retrievedValue ? "••••••••••••••••••••••••••••" : "(loading...)")} readOnly />
              <div style={{ position: "absolute", top: 6, right: 8, display: "flex", gap: 4 }}>
                <button onClick={() => setShowValue(!showValue)} style={{ background: "rgba(0,0,0,.3)", border: "none", color: C.muted, cursor: "pointer", padding: "3px 6px", borderRadius: 4, fontSize: 9, display: "inline-flex", alignItems: "center", gap: 3 }}>
                  {showValue ? <><EyeOff size={10} /> Hide</> : <><Eye size={10} /> Reveal</>}
                </button>
                {showValue && <button onClick={() => copyToClipboard(retrievedValue, onToast)} style={{ background: "rgba(0,0,0,.3)", border: "none", color: C.muted, cursor: "pointer", padding: "3px 6px", borderRadius: 4, fontSize: 9, display: "inline-flex", alignItems: "center", gap: 3 }}>
                  <Copy size={10} /> Copy
                </button>}
              </div>
            </div>
          </FG>
          <div style={{ display: "flex", gap: 6 }}>
            <Btn small primary onClick={() => void fetchFormat()} disabled={busy}>{busy ? "Fetching..." : "Fetch Format"}</Btn>
            <Btn small onClick={() => void downloadSecret(selectedSecret)} disabled={busy}><Download size={10} /> Download</Btn>
          </div>
        </div>

        {/* ── Version History ── */}
        {versions.length > 0 && <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 14, marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}><History size={13} /> Version History</div>
          <div style={{ maxHeight: 160, overflow: "auto" }}>
            {versions.map((v) => <div key={v.version} style={{
              display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 10px", fontSize: 10,
              borderRadius: 6, marginBottom: 4,
              background: v.version === selectedSecret.current_version ? C.accentDim : "transparent",
              border: `1px solid ${v.version === selectedSecret.current_version ? C.accent : C.border}`
            }}>
              <span style={{ fontWeight: 600, color: v.version === selectedSecret.current_version ? C.accent : C.text }}>
                v{v.version} {v.version === selectedSecret.current_version && <B c="accent">current</B>}
              </span>
              <span style={{ color: C.muted, fontFamily: "'IBM Plex Mono',monospace", fontSize: 9 }}>
                SHA256: {String(v.value_hash || "").substring(0, 16)}...
              </span>
              <span style={{ color: C.muted }}>{fmtDate(v.created_at)}</span>
            </div>)}
          </div>
        </div>}

        {/* ── Audit Log ── */}
        {auditEntries.length > 0 && <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 14, marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}><ScrollText size={13} /> Audit Log</div>
          <div style={{ maxHeight: 180, overflow: "auto" }}>
            {auditEntries.map((e) => <div key={e.id} style={{ display: "flex", gap: 10, padding: "6px 10px", fontSize: 10, borderRadius: 6, marginBottom: 3, background: C.card, border: `1px solid ${C.border}` }}>
              <span style={{ color: actionColor(e.action), fontWeight: 600, minWidth: 60 }}>{e.action}</span>
              <span style={{ color: C.dim, flex: 1 }}>{e.detail}</span>
              <span style={{ color: C.muted, whiteSpace: "nowrap" }}>{e.actor}</span>
              <span style={{ color: C.muted, whiteSpace: "nowrap" }}>{fmtDate(e.created_at)}</span>
            </div>)}
          </div>
        </div>}

        {/* ── Actions ── */}
        <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 14, display: "flex", gap: 8, justifyContent: "space-between" }}>
          <div style={{ display: "flex", gap: 8 }}>
            <Btn onClick={() => { setRotateValue(""); setModal("rotate"); }}><RotateCcw size={12} /> Rotate Value</Btn>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <Btn danger onClick={() => void removeSecret(selectedSecret)} disabled={busy}><Trash2 size={12} /> Delete</Btn>
            <Btn onClick={() => setModal(null)}>Close</Btn>
          </div>
        </div>
      </>}
    </Modal>

    {/* ══════════════ ROTATE SECRET MODAL ══════════════ */}
    <Modal open={modal === "rotate"} onClose={() => setModal(null)} title={`Rotate Secret: ${selectedSecret?.name || ""}`}>
      <div style={{ fontSize: 10, color: C.dim, marginBottom: 12, lineHeight: 1.5 }}>
        Rotating a secret creates a new encrypted version while preserving all previous versions. Current version: <strong style={{ color: C.accent }}>v{selectedSecret?.current_version}</strong>
      </div>
      <FG label="New Secret Value" required hint="Will be encrypted and stored as the next version">
        <Txt placeholder="Paste new value..." rows={6} value={rotateValue} onChange={(e) => setRotateValue(e.target.value)} />
      </FG>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
        <Btn onClick={() => setModal(null)} disabled={busy}>Cancel</Btn>
        <Btn primary onClick={() => void submitRotate()} disabled={busy}>{busy ? "Rotating..." : "Rotate Secret"}</Btn>
      </div>
    </Modal>

    {promptDialog.ui}
  </div>;
};

function actionColor(action) {
  if (action === "created") return C.green;
  if (action === "rotated") return C.amber;
  if (action === "deleted") return C.red;
  if (action === "updated") return C.blue;
  return C.accent;
}
