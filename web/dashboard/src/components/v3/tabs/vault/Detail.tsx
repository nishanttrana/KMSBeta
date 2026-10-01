import { Copy, Download, Eye, EyeOff, History, RotateCcw, ScrollText, Trash2, Undo2, UserCheck } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../../lib/auth";
import {
  ACCESS_CAPABILITIES, destroySecret, destroySecretVersion, getSecretAccess, getSecretAuditLog, getSecretValue, listSecretVersions,
  restoreSecret, rollbackSecret, type SecretAccess, type SecretAuditEntry, type SecretItem, type SecretValueResponse, type SecretVersionInfo,
} from "../../../../lib/secrets";
import { B, Btn, Modal, Sel, Txt } from "../../legacyPrimitives";
import { errMsg } from "../../runtimeUtils";
import { C } from "../../theme";
import { RuleRow, type GroupNames } from "./Access";
import { TypeBadge } from "./Charts";
import { defaultFormatForType, expiryBucket, fmtDate, ttlLabel } from "./meta";

const MONO = "'JetBrains Mono',ui-monospace,monospace";
const FORMATS = ["raw", "pem", "openssh", "armored", "jwk", "extract"];
const changeColor = (action: string) =>
  action === "created" || action === "restored" ? C.greenFg : action === "rotated" || action === "rolled_back" ? C.amberFg : action.includes("destroyed") || action === "deleted" ? C.redFg : C.blueFg;

type Props = {
  session: AuthSession;
  secret: SecretItem | null;
  groups?: GroupNames | undefined;
  now: number;
  confirm: (opts: Record<string, unknown>) => Promise<boolean>;
  onClose: () => void;
  onChanged: () => void; // the list is stale: reload it
  onRotate: () => void;
  onDelete: () => void;
  onDownload: () => void;
  onToast?: ((m: string) => void) | undefined;
};

// The secret's detail view, mounted per secret (key = its ID). Metadata,
// access, versions and history load on open; a value is read only when asked
// for, since every read is audited.
export function SecretDetail({ session, secret, groups, now, confirm, onClose, onChanged, onRotate, onDelete, onDownload, onToast }: Props) {
  const [format, setFormat] = useState(() => (secret ? defaultFormatForType(secret) : "raw"));
  const [shown, setShown] = useState<SecretValueResponse | null>(null);
  const [visible, setVisible] = useState(false);
  const [valueError, setValueError] = useState("");
  const [versions, setVersions] = useState<SecretVersionInfo[] | null>(null);
  const [changes, setChanges] = useState<SecretAuditEntry[] | null>(null);
  const [access, setAccess] = useState<SecretAccess | null>(null);
  const [loadError, setLoadError] = useState("");
  const [busy, setBusy] = useState(false);

  const id = secret?.id || "";
  const load = useCallback(async () => {
    if (!id) return;
    const [v, c, a] = await Promise.allSettled([listSecretVersions(session, id), getSecretAuditLog(session, id), getSecretAccess(session, id)]);
    setVersions(v.status === "fulfilled" ? v.value : null);
    setChanges(c.status === "fulfilled" ? c.value : null);
    setAccess(a.status === "fulfilled" ? a.value : null);
    setLoadError([v, c, a].filter((r) => r.status === "rejected").map((r) => errMsg((r as PromiseRejectedResult).reason)).join("; "));
  }, [session, id]);

  useEffect(() => { void load(); }, [load]);

  if (!secret) return null;
  const deleted = secret.status === "deleted";
  const can = (capability: string) => access?.caller?.[capability] !== false;
  const expired = expiryBucket(secret, now) === "expired";

  const run = async (what: string, fn: () => Promise<unknown>, after: "reload" | "close") => {
    setBusy(true);
    try {
      await fn();
      onToast?.(what);
      onChanged();
      if (after === "close") onClose(); else await load();
    } catch (e) { onToast?.(`Refused: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const reveal = async (version = 0) => {
    setBusy(true); setValueError("");
    try { setShown(await getSecretValue(session, secret.id, version ? "raw" : format, version)); setVisible(true); }
    catch (e) { setShown(null); setValueError(errMsg(e)); } finally { setBusy(false); }
  };

  const rollback = async (version: number) => {
    if (!(await confirm({ title: "Roll back", message: `Make the value of v${version} current again? It is stored as v${secret.current_version + 1}; nothing is removed.`, confirmLabel: "Roll back" }))) return;
    await run(`Rolled back to the value of v${version}.`, () => rollbackSecret(session, secret.id, version, secret.current_version), "close");
  };
  const destroyVersion = async (version: number) => {
    if (!(await confirm({ title: "Destroy version", message: `Permanently destroy v${version} of "${secret.name}"? Its value cannot be recovered.`, confirmLabel: "Destroy", danger: true }))) return;
    await run(`Version ${version} destroyed.`, () => destroySecretVersion(session, secret.id, version), "reload");
  };
  const destroy = async () => {
    if (!(await confirm({ title: "Destroy secret", message: `Permanently destroy "${secret.name}" and all ${secret.current_version} version(s)? This cannot be undone.`, confirmLabel: "Destroy", danger: true }))) return;
    await run("Secret destroyed.", () => destroySecret(session, secret.id), "close");
  };

  const facts: [string, React.ReactNode][] = [
    ["Type", <TypeBadge key="t" type={secret.secret_type} />],
    ["Version", `v${secret.current_version}`],
    ["Lease", ttlLabel(secret)],
    deleted ? ["Deleted", <span key="d" style={{ color: C.redFg }}>{fmtDate(secret.deleted_at)}</span>]
      : ["Expires", secret.expires_at ? <span key="e" style={{ color: expired ? C.redFg : C.text }}>{fmtDate(secret.expires_at)}</span> : "Never"],
  ];
  const head = { fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 8, display: "flex", alignItems: "center", gap: 6 } as const;
  const section = { borderTop: `1px solid ${C.border}`, paddingTop: 14, marginBottom: 14 } as const;
  const iconBtn = { background: "none", border: "none", cursor: "pointer", padding: 2 } as const;

  return (
    <Modal open onClose={onClose} title={`Secret: ${secret.name}`} wide>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 10, marginBottom: 14 }}>
        {facts.map(([label, value]) => (
          <div key={label} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: "10px 12px" }}>
            <div style={{ fontSize: 10, color: C.muted, marginBottom: 4 }}>{label}</div>
            <div style={{ fontSize: 12, color: C.text, fontWeight: 600 }}>{value}</div>
          </div>
        ))}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 14, fontSize: 11, color: C.dim }}>
        <div><span style={{ color: C.muted }}>Created: </span>{fmtDate(secret.created_at)} by {secret.created_by || "-"}</div>
        <div><span style={{ color: C.muted }}>{deleted ? "Deleted by: " : "Changed: "}</span>{deleted ? secret.deleted_by || "-" : fmtDate(secret.updated_at)}</div>
        <div><span style={{ color: C.muted }}>Path: </span><span style={{ fontFamily: MONO, fontSize: 10 }}>{secret.path || "-"}</span></div>
        <div><span style={{ color: C.muted }}>ID: </span><span style={{ fontFamily: MONO, fontSize: 10 }}>{secret.id}</span></div>
        {secret.description && <div style={{ gridColumn: "1/3" }}><span style={{ color: C.muted }}>Description: </span>{secret.description}</div>}
      </div>
      {loadError && <div style={{ fontSize: 11, color: C.redFg, marginBottom: 14 }}>Details unavailable: {loadError}</div>}

      {/* ── Access: the rules on this path, and what this caller may do ── */}
      {access && <div style={section}>
        <div style={{ ...head, flexWrap: "wrap" }}>
          <UserCheck size={13} /> Access
          <span style={{ fontWeight: 400, color: C.muted, marginRight: "auto" }}>{access.rules.length ? `${access.rules.length} rule${access.rules.length === 1 ? "" : "s"} on this path` : access.default_deny ? "no rule: denied by default" : "no rule: open to the secrets permission"}</span>
          {ACCESS_CAPABILITIES.map((c) => <B key={c} c={can(c) ? "green" : "red"}>{can(c) ? c : `no ${c}`}</B>)}
        </div>
        {access.rules.map((r) => <RuleRow key={r.id} rule={r} groups={groups} />)}
      </div>}

      {/* ── Value: read on request ── */}
      {!deleted && <div style={section}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10, flexWrap: "wrap" }}>
          <span style={{ ...head, marginBottom: 0, marginRight: "auto" }}><Eye size={13} /> Value{shown ? ` (v${shown.version})` : ""}</span>
          <Sel w={120} value={format} onChange={(e) => { setFormat(e.target.value); setShown(null); setVisible(false); setValueError(""); }}>
            {FORMATS.map((f) => <option key={f} value={f}>{f}</option>)}
          </Sel>
          {shown
            ? <Btn small onClick={() => setVisible((v) => !v)}>{visible ? <><EyeOff size={11} /> Hide</> : <><Eye size={11} /> Show</>}</Btn>
            : <Btn small primary onClick={() => void reveal()} disabled={busy || !can("value")} title={can("value") ? "Reads the value; the read is audited" : "An access rule does not allow you to read this value"}>{busy ? "Reading..." : <><Eye size={11} /> Reveal</>}</Btn>}
          {shown && visible && <Btn small onClick={() => void navigator.clipboard.writeText(shown.value).then(() => onToast?.("Copied to clipboard."), () => onToast?.("Copy failed."))}><Copy size={11} /> Copy</Btn>}
          <Btn small onClick={onDownload} disabled={busy || !can("value")}><Download size={11} /> Download</Btn>
        </div>
        {valueError
          ? <div style={{ fontSize: 11, color: C.redFg }}>Value unavailable: {valueError}</div>
          : <Txt rows={shown && visible ? 6 : 2} readOnly value={shown ? (visible ? shown.value : "••••••••••••••••") : ""} placeholder="Not read. Reveal reads the value and records it in the audit log." />}
        {shown && <div style={{ fontSize: 10, color: C.muted, marginTop: 4 }}>{shown.format} · {shown.content_type}</div>}
      </div>}

      <div style={{ ...section, display: "grid", gridTemplateColumns: "1.2fr 1.4fr", gap: 14 }}>
        <div>
          <div style={head}><History size={13} /> Versions{versions ? ` (${versions.length})` : ""}</div>
          <div style={{ maxHeight: 190, overflow: "auto" }}>
            {(versions || []).map((v) => {
              const current = v.version === secret.current_version;
              return <div key={v.version} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 6, padding: "5px 8px", fontSize: 11, borderRadius: 6, marginBottom: 4, border: `1px solid ${current ? C.accentFg : C.border}` }}>
                <span style={{ fontWeight: 600, color: C.text }}>v{v.version} {current && <B c="accent">current</B>}</span>
                <span style={{ color: C.muted, marginLeft: "auto" }}>{fmtDate(v.created_at)}</span>
                {!current && !deleted && <>
                  <button type="button" aria-label={`Read v${v.version}`} title="Read this version (audited)" disabled={busy || !can("value")} onClick={() => void reveal(v.version)} style={{ ...iconBtn, color: C.muted }}><Eye size={13} /></button>
                  <button type="button" aria-label={`Roll back to v${v.version}`} title="Roll back to this value" disabled={busy || !can("write")} onClick={() => void rollback(v.version)} style={{ ...iconBtn, color: C.accentFg }}><Undo2 size={13} /></button>
                  <button type="button" aria-label={`Destroy v${v.version}`} title="Destroy this version" disabled={busy || !can("delete")} onClick={() => void destroyVersion(v.version)} style={{ ...iconBtn, color: C.redFg }}><Trash2 size={13} /></button>
                </>}
              </div>;
            })}
          </div>
        </div>
        <div>
          <div style={head}><ScrollText size={13} /> Changes{changes ? ` (${changes.length})` : ""}</div>
          <div style={{ maxHeight: 190, overflow: "auto" }}>
            {(changes || []).map((e) => <div key={e.id} title={e.detail} style={{ display: "grid", gridTemplateColumns: "104px 1fr auto", gap: 8, padding: "5px 8px", fontSize: 11, borderBottom: `1px solid ${C.border}` }}>
              <span style={{ color: changeColor(e.action), fontWeight: 600 }}>{e.action.replace(/_/g, " ")}</span>
              <span style={{ color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.actor}</span>
              <span style={{ color: C.muted, whiteSpace: "nowrap" }}>{fmtDate(e.created_at)}</span>
            </div>)}
          </div>
        </div>
      </div>

      <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 14, display: "flex", gap: 8, justifyContent: "space-between" }}>
        {deleted
          ? <Btn primary disabled={busy || !can("write")} onClick={() => void run("Secret restored.", () => restoreSecret(session, secret.id), "close")}><Undo2 size={12} /> Restore</Btn>
          : <Btn disabled={busy || !can("write")} onClick={onRotate}><RotateCcw size={12} /> Rotate value</Btn>}
        <div style={{ display: "flex", gap: 8 }}>
          {deleted
            ? <Btn danger disabled={busy || !can("delete")} onClick={() => void destroy()}><Trash2 size={12} /> Destroy</Btn>
            : <Btn danger disabled={busy || !can("delete")} onClick={onDelete}><Trash2 size={12} /> Delete</Btn>}
          <Btn onClick={onClose}>Close</Btn>
        </div>
      </div>
    </Modal>
  );
}
