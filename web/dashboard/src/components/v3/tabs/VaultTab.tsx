// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useCallback, useEffect, useMemo, useState } from "react";
import { Clock, Copy, Download, Folder, KeyRound, Lock, Plus, RefreshCcw, Search, ShieldAlert, Trash2, UserCheck } from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import { listKeyAccessGroups } from "../../../lib/keycore";
import {
  createSecret,
  deleteSecret as deleteVaultSecret,
  generateKeyPairSecret,
  getSecretValue,
  getVaultSettings,
  getVaultStats,
  listAccessRules,
  listAllSecrets,
  listVersionCaps,
  rotateSecret
} from "../../../lib/secrets";
import { DrillHint, DrillPanel, clickable } from "../chartDrill";
import { Btn, FG, Inp, Modal, Row2, Section, Sel, Tabs, Txt, usePromptDialog } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { AccessRules, VaultSettingsCard, VersionCaps } from "./vault/Access";
import { SecretRow, TypeBadge, VaultApiCard, VaultCharts, VaultTiles } from "./vault/Charts";
import { SecretDetail } from "./vault/Detail";
import {
  CATEGORIES, GENERATE_TYPE_OPTIONS, SUPPORTED_TYPES, defaultFormatForType, expiryBucket, fmtAgo,
  getBadge, matchesCategory, safeFileName, secretPath, ttlLabel, ttlToSeconds
} from "./vault/meta";

const PAGE = 60;

function copyToClipboard(text, onToast) {
  navigator.clipboard.writeText(text).then(() => onToast?.("Copied to clipboard.")).catch(() => onToast?.("Copy failed."));
}

function expiryStatus(s, now) {
  const b = expiryBucket(s, now);
  if (b === "expired") return { label: "Expired", color: C.redFg };
  if (b === "7d") return { label: "Expiring soon", color: C.amberFg };
  return null;
}

/* ── MAIN COMPONENT ── */
export const VaultTab = ({ session, onToast, onNavigate }: { session: AuthSession | null; onToast?: (m: string) => void; onNavigate?: (tab: string) => void }) => {
  const [modal, setModal] = useState(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [secrets, setSecrets] = useState([]);
  const [loadError, setLoadError] = useState("");
  // Deleted secrets (kept until destroyed) and access rules: null with an
  // error when their call failed, never an empty list.
  const [deleted, setDeleted] = useState(null);
  const [rules, setRules] = useState(null);
  const [settings, setSettings] = useState(null);
  const [groups, setGroups] = useState(null); // access group names by ID
  const [caps, setCaps] = useState(null); // version caps by path
  const [sideError, setSideError] = useState({ deleted: "", rules: "", settings: "", caps: "" });
  const [view, setView] = useState("Secrets");
  const [stats, setStats] = useState(null);
  const [statsError, setStatsError] = useState("");
  // One "now" for the charts, the tiles and their drill-downs.
  const [asOf, setAsOf] = useState(() => Date.now());
  const [drill, setDrill] = useState(null);
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("all");
  const [sortBy, setSortBy] = useState("updated");
  const [currentPath, setCurrentPath] = useState("/");
  const [shown, setShown] = useState(PAGE);

  // Create form
  const [createName, setCreateName] = useState("");
  const [createType, setCreateType] = useState("api_key");
  const [createValue, setCreateValue] = useState("");
  const [createDesc, setCreateDesc] = useState("");
  const [createFolder, setCreateFolder] = useState("");
  const [createTTLMode, setCreateTTLMode] = useState("none");
  const [createTTLCustom, setCreateTTLCustom] = useState("");

  // Generate form
  const [generateType, setGenerateType] = useState("ed25519");
  const [generateName, setGenerateName] = useState("");
  const [generatedPublicKey, setGeneratedPublicKey] = useState("");

  const [selectedSecret, setSelectedSecret] = useState(null);
  const [rotateValue, setRotateValue] = useState("");

  const promptDialog = usePromptDialog();

  /* ── data loading ── */
  const loadAll = useCallback(async () => {
    if (!session) return;
    setLoading(true);
    const [items, vaultStats, gone, ruleList, vaultSettings, groupList, capList] = await Promise.allSettled([
      listAllSecrets(session), getVaultStats(session), listAllSecrets(session, true), listAccessRules(session), getVaultSettings(session), listKeyAccessGroups(session), listVersionCaps(session)]);
    setCaps(capList.status === "fulfilled" ? capList.value : null);
    setSettings(vaultSettings.status === "fulfilled" ? vaultSettings.value : null);
    setGroups(groupList.status === "fulfilled" ? Object.fromEntries(groupList.value.map((g) => [g.id, g.name])) : null);
    setDeleted(gone.status === "fulfilled" ? gone.value : null);
    setRules(ruleList.status === "fulfilled" ? ruleList.value : null);
    const why = (r) => r.status === "rejected" ? errMsg(r.reason) : "";
    setSideError({ deleted: why(gone), rules: why(ruleList), settings: why(vaultSettings), caps: why(capList) });
    setAsOf(Date.now());
    if (items.status === "fulfilled") { setSecrets(items.value); setLoadError(""); }
    else { setSecrets([]); setLoadError(errMsg(items.reason)); }
    if (vaultStats.status === "fulfilled") { setStats(vaultStats.value); setStatsError(""); }
    else { setStats(null); setStatsError(errMsg(vaultStats.reason)); }
    setLoading(false);
  }, [session]);

  useEffect(() => { void loadAll(); }, [loadAll]);

  /* ── filtering & sorting ── */
  const filtered = useMemo(() => {
    const q = String(search || "").trim().toLowerCase();
    const items = secrets.filter((s) => {
      if (!matchesCategory(s, category)) return false;
      if (!q) return true;
      return [s.name, s.id, s.secret_type, s.description, s.created_by].some((v) => String(v || "").toLowerCase().includes(q));
    });
    const time = (v) => new Date(v || 0).getTime();
    if (sortBy === "name") items.sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
    else if (sortBy === "type") items.sort((a, b) => String(a.secret_type || "").localeCompare(String(b.secret_type || "")));
    else if (sortBy === "created") items.sort((a, b) => time(b.created_at) - time(a.created_at));
    else items.sort((a, b) => time(b.updated_at) - time(a.updated_at));
    return items;
  }, [secrets, search, category, sortBy]);

  /* ── folders: the secrets' own path labels and path-style names ── */
  const folders = useMemo(() => {
    const direct = new Map(); // path -> secrets directly in it
    const children = new Map(); // path -> child paths
    filtered.forEach((s) => {
      const path = secretPath(s);
      direct.set(path, [...(direct.get(path) || []), s]);
      const parts = path.split("/").filter(Boolean);
      parts.forEach((_, i) => {
        const parent = i === 0 ? "/" : `/${parts.slice(0, i).join("/")}`;
        children.set(parent, (children.get(parent) || new Set()).add(`/${parts.slice(0, i + 1).join("/")}`));
      });
    });
    return { direct, children };
  }, [filtered]);

  const inPath = (path) => path === "/" ? filtered : filtered.filter((s) => { const p = secretPath(s); return p === path || p.startsWith(`${path}/`); });
  const subfolders = Array.from(folders.children.get(currentPath) || []).sort();
  const listed = currentPath === "/" ? filtered : (folders.direct.get(currentPath) || []);
  const crumbs = currentPath.split("/").filter(Boolean);
  const drilled = useMemo(() => drill ? secrets.filter(drill.match) : [], [drill, secrets]);

  useEffect(() => { setShown(PAGE); }, [search, category, sortBy, currentPath]);

  /* ── actions ── */
  const openCreate = () => { setCreateFolder(currentPath === "/" ? "" : currentPath.slice(1)); setModal("create"); };
  const openGenerate = () => { setGeneratedPublicKey(""); setGenerateName(""); setModal("generate"); };

  const submitCreate = async () => {
    if (!session) return;
    if (!createName.trim() || !createValue) { onToast?.("Secret name and value are required."); return; }
    const folder = createFolder.trim().replace(/[^a-zA-Z0-9._/-]/g, "-").replace(/\/+/g, "/").replace(/^\/|\/$/g, "");
    setBusy(true);
    try {
      await createSecret(session, {
        name: createName.trim(),
        secret_type: createType,
        value: createValue,
        description: createDesc.trim(),
        labels: folder ? { path: `/${folder}` } : {},
        lease_ttl_seconds: ttlToSeconds(createTTLMode, createTTLCustom),
        metadata: { source: "dashboard" }
      });
      onToast?.("Secret stored.");
      setModal(null); setCreateName(""); setCreateValue(""); setCreateDesc(""); setCreateType("api_key"); setCreateTTLMode("none"); setCreateTTLCustom("");
      await loadAll();
    } catch (e) { onToast?.(`Store failed: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const submitGenerate = async () => {
    if (!session || !generateName.trim()) { onToast?.("Key name is required."); return; }
    setBusy(true);
    try {
      const out = await generateKeyPairSecret(session, { name: generateName.trim(), key_type: generateType, labels: { source: "dashboard", key_type: generateType }, lease_ttl_seconds: 0 });
      setGeneratedPublicKey(String(out.public_key || ""));
      onToast?.(`${String(out.key_type || generateType)} key pair generated. Private key stored in vault.`);
      await loadAll();
    } catch (e) { onToast?.(`Generate failed: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const openDetail = (secret) => { setSelectedSecret(secret); setModal("detail"); };

  const downloadSecret = async (secret) => {
    if (!session) return;
    setBusy(true);
    try {
      const format = defaultFormatForType(secret);
      const out = await getSecretValue(session, secret.id, format);
      const ext = { pem: "pem", armored: "asc", jwk: "json", extract: "json" }[format] || "txt";
      const url = URL.createObjectURL(new Blob([String(out.value || "")], { type: String(out.content_type || "text/plain") }));
      const a = document.createElement("a"); a.href = url; a.download = `${safeFileName(secret.name || secret.id)}.${ext}`;
      document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
      onToast?.(`Downloaded ${secret.name}.`);
    } catch (e) { onToast?.(`Download failed: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const removeSecret = async (secret) => {
    if (!session) return;
    const ok = await promptDialog.confirm({ title: "Delete Secret", message: `Delete "${secret.name}"? It moves to Deleted, where it can be restored or destroyed. Its value cannot be read meanwhile.`, confirmLabel: "Delete", danger: true });
    if (!ok) return;
    setBusy(true);
    try {
      await deleteVaultSecret(session, secret.id);
      onToast?.("Secret deleted. It can be restored from Deleted."); setModal(null);
      await loadAll();
    } catch (e) { onToast?.(`Delete failed: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const submitRotate = async () => {
    if (!session || !selectedSecret || !rotateValue) { onToast?.("New value is required for rotation."); return; }
    setBusy(true);
    try {
      const updated = await rotateSecret(session, selectedSecret.id, rotateValue, selectedSecret.current_version);
      onToast?.(`Secret rotated to version ${updated.current_version}.`);
      setModal(null); setRotateValue("");
      await loadAll();
    } catch (e) { onToast?.(`Rotation failed: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const pickDrill = (d) => setDrill((cur) => cur?.key === d.key ? null : d);
  const chip = (on) => ({ height: 30, padding: "0 12px", borderRadius: 8, border: `1px solid ${on ? C.accentFg : C.border}`, background: on ? C.accentDim : "transparent", color: on ? C.accentFg : C.muted, fontSize: 11, cursor: "pointer", fontWeight: 600 });

  return <div>
    <Section title={<><Lock size={16} color={C.accentFg} />Secret Vault</>} actions={<>
      <Btn small onClick={() => void loadAll()} disabled={loading || busy}><RefreshCcw size={12} />{loading ? "Refreshing" : "Refresh"}</Btn>
      <Btn small onClick={openGenerate}><KeyRound size={12} />Generate key pair</Btn>
      <Btn small primary onClick={openCreate}><Plus size={12} />Store secret</Btn>
    </>} />

    {loadError
      ? <div style={{ marginBottom: 14, padding: "10px 14px", border: `1px solid ${C.redFg}`, borderRadius: "var(--radius-md)", fontSize: 12, color: C.redFg }}>Secret vault unavailable: {loadError}</div>
      : <VaultTiles secrets={secrets} now={asOf} active={drill?.key || ""} onDrill={pickDrill} stats={stats} statsError={statsError} />}

    {secrets.length > 0 && <>
      <DrillHint />
      <VaultCharts secrets={secrets} now={asOf} active={drill?.key || ""} onDrill={pickDrill} />
    </>}
    {drill && <DrillPanel label={drill.label} count={drilled.length} onClear={() => setDrill(null)}>
      {drilled.map((s) => <SecretRow key={s.id} secret={s} onOpen={() => openDetail(s)} />)}
    </DrillPanel>}
    <div style={{ height: 16 }} />

    {!loadError && <Tabs tabs={["Secrets", "Deleted", "Access rules"]} active={view} onChange={setView} />}

    {!loadError && view === "Deleted" && (deleted === null
      ? <div style={{ fontSize: 11.5, color: C.redFg }}>Deleted secrets unavailable: {sideError.deleted}</div>
      : <>
        <div style={{ fontSize: 11, color: C.muted, marginBottom: 8 }}>{settings?.deleted_retention_days > 0 ? `Destroyed ${settings.deleted_retention_days} days after the delete, unless restored.` : "Kept until restored or destroyed."}</div>
        {deleted.length === 0 ? <div style={{ fontSize: 12, color: C.muted, textAlign: "center", padding: "28px 0" }}>Nothing deleted.</div>
          : deleted.map((s) => <SecretRow key={s.id} secret={s} onOpen={() => openDetail(s)} />)}
      </>)}

    {!loadError && view === "Access rules" && <VaultSettingsCard session={session} settings={settings} error={sideError.settings} uncovered={settings?.default_deny ? null : secrets.filter((s) => !s.restricted).length}
      confirm={promptDialog.confirm} onChanged={() => void loadAll()} onToast={onToast} />}
    {!loadError && view === "Access rules" && <VersionCaps session={session} caps={caps} error={sideError.caps} confirm={promptDialog.confirm} onChanged={() => void loadAll()} onToast={onToast} />}
    {!loadError && view === "Access rules" && <AccessRules session={session} rules={rules} groups={groups} error={sideError.rules} restricted={secrets.filter((s) => s.restricted).length} total={secrets.length}
      confirm={promptDialog.confirm} onChanged={() => void loadAll()} onToast={onToast} />}

    {/* ── Inventory ── */}
    {!loadError && view === "Secrets" && <>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
        {CATEGORIES.map((cat) => <button key={cat.id} type="button" onClick={() => setCategory(cat.id)} style={chip(category === cat.id)}>{cat.label}</button>)}
      </div>
      <div style={{ display: "flex", gap: 10, marginBottom: 12, alignItems: "center", flexWrap: "wrap" }}>
        <div style={{ position: "relative", flex: 1, minWidth: 200, maxWidth: 400 }}>
          <Search size={13} style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: C.muted }} />
          <Inp placeholder="Search name, type, owner" value={search} onChange={(e) => setSearch(e.target.value)} style={{ paddingLeft: 30, height: 34 }} />
        </div>
        <Sel value={sortBy} onChange={(e) => setSortBy(e.target.value)} w={160} style={{ height: 34 }}>
          <option value="updated">Recently changed</option>
          <option value="created">Recently created</option>
          <option value="name">Name A-Z</option>
          <option value="type">By type</option>
        </Sel>
        <span style={{ fontSize: 11, color: C.muted }}>{filtered.length} of {secrets.length}</span>
      </div>

      {/* Folders */}
      <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 8, flexWrap: "wrap", fontSize: 11 }}>
        <Folder size={12} color={C.muted} />
        <span onClick={() => setCurrentPath("/")} style={{ ...clickable, color: currentPath === "/" ? C.accentFg : C.text, fontWeight: currentPath === "/" ? 700 : 400 }}>all</span>
        {crumbs.map((part, i) => {
          const path = `/${crumbs.slice(0, i + 1).join("/")}`;
          return <span key={path} style={{ display: "inline-flex", gap: 4 }}>
            <span style={{ color: C.muted }}>/</span>
            <span onClick={() => setCurrentPath(path)} style={{ ...clickable, color: path === currentPath ? C.accentFg : C.text, fontWeight: path === currentPath ? 700 : 400 }}>{part}</span>
          </span>;
        })}
      </div>
      {subfolders.length > 0 && <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
        {subfolders.map((path) => (
          <button key={path} type="button" onClick={() => setCurrentPath(path)} title={path}
            style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "7px 12px", background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, cursor: "pointer", color: C.text, fontSize: 11, fontWeight: 600 }}>
            <Folder size={13} color={C.accentFg} />{path.split("/").pop()}
            <span style={{ color: C.muted, fontWeight: 400 }}>{inPath(path).length}</span>
          </button>
        ))}
      </div>}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(320px,1fr))", gap: 10 }}>
        {listed.slice(0, shown).map((s) => {
          const badge = getBadge(s.secret_type);
          const exp = expiryStatus(s, asOf);
          return <div key={s.id} onClick={() => openDetail(s)} className="vecta-stat-card" style={{
            background: C.card, border: `1px solid ${C.border}`, borderLeft: `3px solid ${badge.fg}`, borderRadius: "var(--radius-md)", padding: "12px 14px", cursor: "pointer", boxShadow: "var(--shadow-sm)", minWidth: 0
          }}>
            <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 650, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.name}</div>
                {s.description && <div style={{ fontSize: 11, color: C.muted, marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.description}</div>}
              </div>
              <TypeBadge type={s.secret_type} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 11, color: C.muted }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 3 }}><Clock size={10} /> {ttlLabel(s)}</span>
                <span>v{s.current_version}</span>
                {exp && <span style={{ color: exp.color, fontWeight: 600, display: "inline-flex", alignItems: "center", gap: 3 }}><ShieldAlert size={10} /> {exp.label}</span>}
                {s.restricted && <span title="An access rule limits who may read this value" style={{ color: C.purpleFg, display: "inline-flex", alignItems: "center", gap: 3 }}><UserCheck size={10} /> restricted</span>}
              </div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span>{fmtAgo(s.updated_at)}</span>
                <button type="button" title="Download (audited value read)" disabled={busy} onClick={(e) => { e.stopPropagation(); void downloadSecret(s); }} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", padding: 2 }}><Download size={13} /></button>
                <button type="button" title="Delete" disabled={busy} onClick={(e) => { e.stopPropagation(); void removeSecret(s); }} style={{ background: "none", border: "none", color: C.redFg, cursor: "pointer", padding: 2 }}><Trash2 size={13} /></button>
              </div>
            </div>
          </div>;
        })}
      </div>
      {listed.length > shown && <div style={{ textAlign: "center", marginTop: 12 }}>
        <Btn small onClick={() => setShown((n) => n + PAGE)}>Show more ({listed.length - shown} left)</Btn>
      </div>}

      {!listed.length && <div style={{ textAlign: "center", padding: "36px 20px" }}>
        {loading ? <div style={{ fontSize: 12, color: C.muted }}>Loading secrets...</div> : <>
          <Lock size={36} strokeWidth={1} color={C.muted} style={{ marginBottom: 10 }} />
          <div style={{ fontSize: 13, fontWeight: 600, color: C.dim, marginBottom: 12 }}>{secrets.length === 0 ? "No secrets stored yet" : "No secrets match"}</div>
          {secrets.length === 0 && <div style={{ display: "flex", gap: 8, justifyContent: "center" }}>
            <Btn primary onClick={openCreate}><Plus size={12} /> Store a secret</Btn>
            <Btn onClick={openGenerate}><KeyRound size={12} /> Generate key pair</Btn>
          </div>}
        </>}
      </div>}
    </>}

    <VaultApiCard onNavigate={onNavigate} />

    {/* ══════════════ STORE SECRET MODAL ══════════════ */}
    <Modal open={modal === "create"} onClose={() => setModal(null)} title="Store New Secret" wide>
      <Row2>
        <FG label="Name" required hint="Unique in this tenant"><Inp placeholder="prod-api-key-stripe" value={createName} onChange={(e) => setCreateName(e.target.value)} /></FG>
        <FG label="Type" required>
          <Sel value={createType} onChange={(e) => setCreateType(e.target.value)}>
            {SUPPORTED_TYPES.map((t) => <option key={t} value={t}>{getBadge(t).t}</option>)}
          </Sel>
        </FG>
      </Row2>
      <Row2>
        <FG label="Folder" hint="Optional, for example engineering/prod"><Inp placeholder="(none)" value={createFolder} onChange={(e) => setCreateFolder(e.target.value)} /></FG>
        <FG label="Description"><Inp placeholder="What this secret is for" value={createDesc} onChange={(e) => setCreateDesc(e.target.value)} /></FG>
      </Row2>
      <FG label="Secret Value" required hint="Encrypted with AES-256-GCM under its own data key before it is stored">
        <Txt placeholder="Paste API key, PEM block, JSON, password..." rows={6} value={createValue} onChange={(e) => setCreateValue(e.target.value)} />
      </FG>
      <Row2>
        <FG label="Expires after" hint="Value reads are refused once expired">
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
        {createTTLMode === "custom" ? <FG label="Seconds"><Inp type="number" min="0" value={createTTLCustom} onChange={(e) => setCreateTTLCustom(e.target.value)} /></FG> : <div />}
      </Row2>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
        <Btn onClick={() => setModal(null)} disabled={busy}>Cancel</Btn>
        <Btn primary onClick={() => void submitCreate()} disabled={busy}>{busy ? "Storing..." : "Store Secret"}</Btn>
      </div>
    </Modal>

    {/* ══════════════ GENERATE KEY PAIR MODAL ══════════════ */}
    <Modal open={modal === "generate"} onClose={() => setModal(null)} title="Generate Key Pair">
      <FG label="Key Type" required>
        <Sel value={generateType} onChange={(e) => setGenerateType(e.target.value)}>
          {GENERATE_TYPE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </Sel>
      </FG>
      <FG label="Name" required hint="The private key is stored in the vault; the public key is shown here"><Inp placeholder="deploy-key-production" value={generateName} onChange={(e) => setGenerateName(e.target.value)} /></FG>
      {generatedPublicKey && <FG label="Generated Public Key">
        <Txt rows={4} value={generatedPublicKey} readOnly />
        <div style={{ marginTop: 6 }}><Btn small onClick={() => copyToClipboard(generatedPublicKey, onToast)}><Copy size={10} /> Copy Public Key</Btn></div>
      </FG>}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
        <Btn onClick={() => setModal(null)} disabled={busy}>Cancel</Btn>
        <Btn primary onClick={() => void submitGenerate()} disabled={busy}>{busy ? "Generating..." : "Generate Key Pair"}</Btn>
      </div>
    </Modal>

    {modal === "detail" && session && <SecretDetail key={selectedSecret?.id} session={session} secret={selectedSecret} groups={groups || undefined} now={asOf} confirm={promptDialog.confirm}
      onClose={() => setModal(null)} onChanged={() => void loadAll()} onToast={onToast}
      onRotate={() => { setRotateValue(""); setModal("rotate"); }} onDelete={() => void removeSecret(selectedSecret)} onDownload={() => void downloadSecret(selectedSecret)} />}

    {/* ══════════════ ROTATE SECRET MODAL ══════════════ */}
    <Modal open={modal === "rotate"} onClose={() => setModal(null)} title={`Rotate Secret: ${selectedSecret?.name || ""}`}>
      <FG label="New Secret Value" required hint={`Stored as v${Number(selectedSecret?.current_version || 0) + 1}. Earlier versions are kept.`}>
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
