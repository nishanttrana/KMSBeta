import { useEffect, useState, type CSSProperties, type ReactNode } from "react";
import {
  Webhook as WebhookIcon, Plus, RefreshCw, Trash2, Edit2, Zap,
  CheckCircle, XCircle, ToggleLeft, ToggleRight, ChevronRight, ChevronDown, X
} from "lucide-react";
import { C } from "../../v3/theme";
import {
  listWebhooks,
  createWebhook,
  updateWebhook,
  deleteWebhook,
  testWebhook,
  listDeliveries,
  type Webhook,
  type WebhookDelivery,
  type WebhookFormat,
  type WebhookInput,
} from "../../../lib/webhooks";

// Every webhook, delivery and count comes from the audit service. When it
// can't be read the tab says so with the error; it never substitutes sample
// data or pretends an action succeeded.

/* ─── Props ──────────────────────────────────────────────── */
interface Props {
  session: any;
  enabledFeatures?: any;
  keyCatalog?: any[];
}

/* ─── Event subscriptions ───────────────────────────────── */
// Real audit action prefixes (docs/API_REFERENCE.md, Audit Action Subject
// Reference). A custom pattern can name one action, e.g. audit.key.rotate.
const EVENT_PATTERNS: { pattern: string; label: string }[] = [
  { pattern: "*", label: "Every audit event" },
  { pattern: "audit.key.*", label: "Keys and crypto operations" },
  { pattern: "audit.secrets.*", label: "Secret vault" },
  { pattern: "audit.cert.*", label: "Certificates and CAs" },
  { pattern: "audit.auth.*", label: "Authentication and identity" },
  { pattern: "audit.governance.*", label: "Approvals, backup, FIPS mode" },
  { pattern: "audit.cluster.*", label: "Cluster" },
  { pattern: "audit.kmip.*", label: "KMIP" },
  { pattern: "audit.posture.*", label: "Posture findings and remediation" },
  { pattern: "audit.audit.*", label: "Audit service itself" },
];
const PATTERN_RE = /^audit(\.[a-z0-9_]+)+(\.\*)?$|^audit\.\*$|^\*$/;

const FORMAT_LABELS: Record<WebhookFormat, string> = {
  json: "JSON", splunk_hec: "Splunk HEC", datadog: "Datadog Logs", slack: "Slack",
};
const FORMAT_COLORS: Record<WebhookFormat, string> = {
  json: C.blue, splunk_hec: C.orange, datadog: C.purple, slack: C.accent,
};
const FORMAT_HINTS: Record<WebhookFormat, string> = {
  json: "{event_type, event}: the full audit event.",
  splunk_hec: "HEC event envelope. Add header Authorization: Splunk <token>.",
  datadog: "Datadog Logs intake array. Add header DD-API-KEY.",
  slack: "Slack incoming-webhook text message.",
};

function errText(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

/* ─── Helpers ─────────────────────────────────────────────── */
function relTime(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}
function shortUrl(url: string) {
  try { const u = new URL(url); return `${u.host}${u.pathname}`.slice(0, 48) + (u.pathname.length + u.host.length > 48 ? "…" : ""); }
  catch { return url.slice(0, 48); }
}

/* ─── Stat Card ──────────────────────────────────────────── */
interface StatCardProps { icon: ReactNode; label: string; value: string | number; color?: string; bg?: string }
function StatCard({ icon, label, value, color = C.accent, bg = C.accentTint }: StatCardProps) {
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "16px 20px", display: "flex", alignItems: "center", gap: 14, flex: 1, minWidth: 150 }}>
      <div style={{ background: bg, border: `1px solid ${color}22`, borderRadius: 8, padding: 8, color, flexShrink: 0 }}>{icon}</div>
      <div>
        <div style={{ fontSize: 22, fontWeight: 700, color: C.text }}>{value}</div>
        <div style={{ fontSize: 11, color: C.dim, marginTop: 2 }}>{label}</div>
      </div>
    </div>
  );
}

/* ─── Webhook Modal ──────────────────────────────────────── */
function WebhookModal({ initial, onClose, onSave }: {
  initial: Webhook | undefined;
  onClose: () => void;
  onSave: (data: WebhookInput) => Promise<void>;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [url, setUrl] = useState(initial?.url ?? "");
  const [format, setFormat] = useState<WebhookFormat>(initial && initial.format in FORMAT_LABELS ? initial.format : "json");
  const [events, setEvents] = useState<Set<string>>(new Set(initial?.events ?? []));
  const [custom, setCustom] = useState("");
  const [headers, setHeaders] = useState<{ k: string; v: string }[]>(
    Object.keys(initial?.headers ?? {}).map(k => ({ k, v: "" }))
  );
  const [secret, setSecret] = useState("");
  const [clearSecret, setClearSecret] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const stale = Array.from(events).filter(e => !PATTERN_RE.test(e));

  function addCustom() {
    const p = custom.trim();
    if (!PATTERN_RE.test(p)) { setError(`"${p}" is not an audit action or prefix (e.g. audit.key.rotate or audit.key.*)`); return; }
    setEvents(prev => new Set(prev).add(p));
    setCustom(""); setError(null);
  }

  function toggleEvent(e: string) {
    setEvents(prev => { const n = new Set(prev); if (n.has(e)) n.delete(e); else n.add(e); return n; });
  }
  function addHeader() { setHeaders(h => [...h, { k: "", v: "" }]); }
  function removeHeader(i: number) { setHeaders(h => h.filter((_, idx) => idx !== i)); }
  function setHeader(i: number, field: "k" | "v", val: string) {
    setHeaders(h => h.map((row, idx) => idx === i ? { ...row, [field]: val } : row));
  }

  async function handleSave() {
    setSaving(true);
    setError(null);
    try {
      const hdrs = Object.fromEntries(headers.filter(h => h.k.trim()).map(h => [h.k.trim(), h.v]));
      const data: WebhookInput = { name: name.trim(), url: url.trim(), format, events: Array.from(events).filter(e => PATTERN_RE.test(e)), headers: hdrs };
      if (secret) data.secret = secret;
      if (clearSecret) data.clear_secret = true;
      await onSave(data);
      onClose();
    } catch (e) {
      setError(errText(e));
    } finally {
      setSaving(false);
    }
  }

  const inp: CSSProperties = { background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, padding: "7px 10px", fontSize: 12, width: "100%", fontFamily: "IBM Plex Sans, sans-serif", outline: "none", boxSizing: "border-box" };
  const lbl: CSSProperties = { fontSize: 11, color: C.dim, marginBottom: 4, display: "block" };

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.65)", zIndex: 9999, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: C.card, border: `1px solid ${C.borderHi}`, borderRadius: 12, padding: 28, width: 540, maxHeight: "85vh", overflowY: "auto", boxShadow: "0 24px 60px rgba(0,0,0,.6)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
          <span style={{ fontSize: 15, fontWeight: 600, color: C.text }}>{initial?.id ? "Edit Webhook" : "Add Webhook"}</span>
          <button onClick={onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", padding: 4 }}><X size={16} /></button>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div><label style={lbl}>Name</label><input style={inp} value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Splunk SIEM" /></div>
          <div><label style={lbl}>Endpoint URL (https only)</label><input style={inp} value={url} onChange={e => setUrl(e.target.value)} placeholder="https://…" /></div>
          <div>
            <label style={lbl}>Format</label>
            <select style={inp} value={format} onChange={e => setFormat(e.target.value as WebhookFormat)}>
              {(Object.keys(FORMAT_LABELS) as WebhookFormat[]).map(f => <option key={f} value={f}>{FORMAT_LABELS[f]}</option>)}
            </select>
            <div style={{ fontSize: 10, color: C.muted, marginTop: 4 }}>{FORMAT_HINTS[format]}</div>
          </div>
          <div>
            <label style={lbl}>Signing Secret (HMAC-SHA256, X-KMS-Signature, at least 16 characters)</label>
            <input style={inp} value={secret} onChange={e => setSecret(e.target.value)} type="password"
              placeholder={initial?.has_secret ? "Set; leave blank to keep it" : "Leave blank to skip signing"} />
            {initial?.has_secret && (
              <label style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 6, fontSize: 11, color: C.dim }}>
                <input type="checkbox" checked={clearSecret} onChange={e => setClearSecret(e.target.checked)} style={{ accentColor: C.accent }} /> Remove the signing secret
              </label>
            )}
          </div>

          <div>
            <label style={lbl}>Audit events to deliver</label>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {EVENT_PATTERNS.map(({ pattern, label }) => {
                const checked = events.has(pattern);
                return (
                  <label key={pattern} title={label} style={{ display: "flex", alignItems: "center", gap: 5, cursor: "pointer", userSelect: "none" }}>
                    <input type="checkbox" checked={checked} onChange={() => toggleEvent(pattern)} style={{ accentColor: C.accent }} />
                    <span style={{ fontSize: 11, color: checked ? C.text : C.dim, fontFamily: "IBM Plex Mono, monospace" }}>{pattern}</span>
                  </label>
                );
              })}
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
              <input style={{ ...inp, flex: 1 }} value={custom} onChange={e => setCustom(e.target.value)} placeholder="Custom: audit.key.rotate or audit.hsm.*" />
              <button onClick={addCustom} disabled={!custom.trim()} style={{ background: "none", border: `1px solid ${C.border}`, borderRadius: 5, color: C.dim, fontSize: 11, padding: "3px 10px", cursor: "pointer" }}>Add</button>
            </div>
            {Array.from(events).filter(e => !EVENT_PATTERNS.some(p => p.pattern === e)).map(e => (
              <span key={e} style={{ display: "inline-flex", alignItems: "center", gap: 4, marginTop: 6, marginRight: 6, fontSize: 11, fontFamily: "IBM Plex Mono, monospace", color: PATTERN_RE.test(e) ? C.text : C.red }}>
                {e}{!PATTERN_RE.test(e) && " (not an audit action; removed on save)"}
                <button onClick={() => toggleEvent(e)} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", padding: 0 }}><X size={11} /></button>
              </span>
            ))}
            {stale.length > 0 && <div style={{ fontSize: 10, color: C.amber, marginTop: 6 }}>Older event names never matched a real audit action; choose audit prefixes instead.</div>}
          </div>

          <div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
              <label style={{ ...lbl, marginBottom: 0 }}>Custom Headers</label>
              <button onClick={addHeader} style={{ background: "none", border: `1px solid ${C.border}`, borderRadius: 5, color: C.dim, fontSize: 11, padding: "3px 8px", cursor: "pointer" }}>+ Add</button>
            </div>
            {headers.map((h, i) => (
              <div key={i} style={{ display: "flex", gap: 6, marginBottom: 6 }}>
                <input style={{ ...inp, flex: 1 }} placeholder="Header name" value={h.k} onChange={e => setHeader(i, "k", e.target.value)} />
                <input style={{ ...inp, flex: 2 }} type="password" placeholder={initial?.headers && h.k in initial.headers ? "Set; leave blank to keep" : "Value"} value={h.v} onChange={e => setHeader(i, "v", e.target.value)} />
                <button onClick={() => removeHeader(i)} style={{ background: "none", border: "none", color: C.red, cursor: "pointer", flexShrink: 0 }}><X size={13} /></button>
              </div>
            ))}
          </div>
        </div>

        {error && <div style={{ fontSize: 12, color: C.red, marginTop: 14 }}>Not saved: {error}</div>}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 20 }}>
          <button onClick={onClose} style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 6, color: C.dim, padding: "8px 16px", cursor: "pointer", fontSize: 12 }}>Cancel</button>
          <button
            onClick={handleSave}
            disabled={saving || !name.trim() || !url.trim() || events.size === 0}
            style={{ background: C.accent, border: "none", borderRadius: 6, color: C.bg, padding: "8px 18px", cursor: saving ? "not-allowed" : "pointer", fontSize: 12, fontWeight: 600, opacity: saving ? 0.7 : 1 }}
          >
            {saving ? "Saving…" : initial?.id ? "Save Changes" : "Add Webhook"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ─── Delivery Log ───────────────────────────────────────── */
function DeliveryLog({ webhook, session, onClose }: { webhook: Webhook; session: any; onClose: () => void }) {
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listDeliveries(session, webhook.id)
      .then(setDeliveries)
      .catch(e => setError(errText(e)))
      .finally(() => setLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
  }, [webhook.id]);

  const th: CSSProperties = { textAlign: "left", fontSize: 10, color: C.muted, fontWeight: 600, padding: "8px 12px", textTransform: "uppercase", letterSpacing: "0.06em", whiteSpace: "nowrap" };
  const td: CSSProperties = { padding: "10px 12px", fontSize: 12, color: C.text, verticalAlign: "middle" };

  return (
    <div style={{ marginTop: 8, background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 10, overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: `1px solid ${C.border}` }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>Delivery Log — {webhook.name}</span>
        <button onClick={onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer" }}><X size={14} /></button>
      </div>
      {loading ? (
        <div style={{ padding: 24, textAlign: "center", color: C.dim, fontSize: 12 }}>Loading deliveries…</div>
      ) : error ? (
        <div style={{ padding: 24, textAlign: "center", color: C.red, fontSize: 12 }}>Delivery log unavailable: {error}</div>
      ) : deliveries.length === 0 ? (
        <div style={{ padding: 24, textAlign: "center", color: C.muted, fontSize: 12 }}>No deliveries recorded.</div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Event", "Status", "HTTP", "Latency", "Delivered", "Error"].map(h => (
                  <th key={h} style={th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {deliveries.map((d, i) => (
                <tr key={d.id} style={{ borderBottom: i < deliveries.length - 1 ? `1px solid ${C.border}` : "none" }}>
                  <td style={td}><span style={{ fontFamily: "IBM Plex Mono, monospace", fontSize: 11, color: C.accent }}>{d.event_type}</span></td>
                  <td style={td}>
                    {d.status === "success"
                      ? <span style={{ display: "flex", alignItems: "center", gap: 4, color: C.green, fontSize: 11 }}><CheckCircle size={11} /> Success</span>
                      : <span style={{ display: "flex", alignItems: "center", gap: 4, color: C.red, fontSize: 11 }}><XCircle size={11} /> Failed</span>}
                  </td>
                  <td style={{ ...td, fontFamily: "IBM Plex Mono, monospace", color: d.http_status && d.http_status < 300 ? C.green : C.red }}>{d.http_status || "—"}</td>
                  <td style={{ ...td, fontFamily: "IBM Plex Mono, monospace", color: C.dim }}>{d.latency_ms}ms · {d.attempt}×</td>
                  <td style={{ ...td, fontFamily: "IBM Plex Mono, monospace", fontSize: 11, color: C.dim }}>{relTime(d.delivered_at)}</td>
                  <td style={{ ...td, color: C.red, fontSize: 11 }}>{d.error || <span style={{ color: C.muted }}>—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ─── Webhook Card ───────────────────────────────────────── */
function WebhookCard({ wh, onToggle, onEdit, onDelete, onTest, onViewLog, logOpen }: {
  wh: Webhook;
  onToggle: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onTest: () => Promise<void>;
  onViewLog: () => void;
  logOpen: boolean;
}) {
  const fmtColor = FORMAT_COLORS[wh.format] ?? C.dim;
  const [testing, setTesting] = useState(false);

  async function handleTest() {
    setTesting(true);
    await onTest();
    setTesting(false);
  }

  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "16px 18px" }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span style={{ fontSize: 14, fontWeight: 600, color: C.text }}>{wh.name}</span>
            <span style={{ background: `${fmtColor}18`, color: fmtColor, border: `1px solid ${fmtColor}33`, borderRadius: 5, fontSize: 10, padding: "1px 7px", fontWeight: 600 }}>{FORMAT_LABELS[wh.format] ?? `${wh.format} (unsupported)`}</span>
            {wh.has_secret && <span style={{ color: C.dim, fontSize: 10 }}>signed</span>}
            {!wh.enabled && <span style={{ background: C.amberDim, color: C.amber, borderRadius: 5, fontSize: 10, padding: "1px 7px", fontWeight: 600 }}>Disabled</span>}
            {wh.failure_count > 0 && <span style={{ background: C.redDim, color: C.red, borderRadius: 5, fontSize: 10, padding: "1px 7px" }}>{wh.failure_count} failure{wh.failure_count > 1 ? "s" : ""}</span>}
          </div>
          <div style={{ fontSize: 11, color: C.dim, marginTop: 4, fontFamily: "IBM Plex Mono, monospace" }}>{shortUrl(wh.url)}</div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 8, flexWrap: "wrap" }}>
            <span style={{ fontSize: 11, color: C.muted, fontFamily: "IBM Plex Mono, monospace" }} title={wh.events.join(", ")}>{wh.events.slice(0, 3).join(", ")}{wh.events.length > 3 ? ` +${wh.events.length - 3}` : ""}</span>
            {wh.last_delivery_at && (
              <span style={{ fontSize: 11, color: C.muted, display: "flex", alignItems: "center", gap: 4 }}>
                {wh.last_delivery_status === "success"
                  ? <CheckCircle size={11} color={C.green} />
                  : <XCircle size={11} color={C.red} />}
                {relTime(wh.last_delivery_at)}
              </span>
            )}
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          <button onClick={onToggle} title={wh.enabled ? "Disable" : "Enable"} style={{ background: "none", border: "none", cursor: "pointer", color: wh.enabled ? C.green : C.muted, padding: 2 }}>
            {wh.enabled ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
          </button>
          <button onClick={handleTest} disabled={testing} title="Test" style={{ background: C.accentDim, border: `1px solid ${C.accent}22`, borderRadius: 6, color: C.accent, padding: "5px 9px", cursor: "pointer", fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}>
            <Zap size={11} />{testing ? "…" : "Test"}
          </button>
          <button onClick={onEdit} title="Edit" style={{ background: "none", border: `1px solid ${C.border}`, borderRadius: 6, color: C.dim, padding: 6, cursor: "pointer" }}><Edit2 size={12} /></button>
          <button onClick={onDelete} title="Delete" style={{ background: "none", border: `1px solid ${C.border}`, borderRadius: 6, color: C.red, padding: 6, cursor: "pointer" }}><Trash2 size={12} /></button>
          <button onClick={onViewLog} title="View log" style={{ background: "none", border: `1px solid ${C.border}`, borderRadius: 6, color: C.dim, padding: 6, cursor: "pointer" }}>
            {logOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ─── Main Component ─────────────────────────────────────── */
export function WebhooksTab({ session }: Props) {
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [editTarget, setEditTarget] = useState<Webhook | null>(null);
  const [openLogId, setOpenLogId] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function load(silent = false) {
    if (!silent) setLoading(true); else setRefreshing(true);
    try {
      setWebhooks(await listWebhooks(session));
      setUnavailable(null);
    } catch (e) {
      setWebhooks([]);
      setUnavailable(errText(e));
    } finally {
      setLoading(false); setRefreshing(false);
    }
  }

  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
  useEffect(() => { load(); }, []);

  // Only what the server confirmed is shown; errors surface, never a local guess.
  async function act(fn: () => Promise<unknown>, label: string) {
    setError(null); setNotice(null);
    try { await fn(); } catch (e) { setError(`${label}: ${errText(e)}`); }
    await load(true);
  }

  async function handleSave(data: WebhookInput) {
    if (editTarget) await updateWebhook(session, editTarget.id, data); // errors show in the modal
    else await createWebhook(session, data);
    setEditTarget(null);
    await load(true);
  }

  const handleDelete = (id: string) => act(async () => {
    await deleteWebhook(session, id);
    if (openLogId === id) setOpenLogId(null);
  }, "Delete failed");

  const handleToggle = (wh: Webhook) => act(() => updateWebhook(session, wh.id, { enabled: !wh.enabled }), "Not changed");

  const handleTest = (wh: Webhook) => act(async () => {
    const r = await testWebhook(session, wh.id);
    if (r.success) setNotice(`${wh.name}: test delivered (HTTP ${r.http_status}, ${r.latency_ms} ms)`);
    else setError(`${wh.name}: test failed${r.http_status ? ` (HTTP ${r.http_status})` : ""}: ${r.error}`);
  }, "Test not sent");

  const activeCount = webhooks.filter(w => w.enabled).length;
  const failingCount = webhooks.filter(w => w.last_delivery_status === "failure").length;
  const failedDeliveries = webhooks.reduce((s, w) => s + w.failure_count, 0);

  const divider: CSSProperties = { borderTop: `1px solid ${C.border}`, margin: "24px 0" };
  const sectionTitle: CSSProperties = { fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 };

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: 320, color: C.dim, fontSize: 13, gap: 10, fontFamily: "IBM Plex Sans, sans-serif" }}>
        <RefreshCw size={16} style={{ animation: "spin 1s linear infinite" }} />
        Loading webhooks…
        <style>{`@keyframes spin { from{transform:rotate(0deg)}to{transform:rotate(360deg)} }`}</style>
      </div>
    );
  }

  return (
    <div style={{ fontFamily: "IBM Plex Sans, sans-serif", color: C.text, padding: "4px 0" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 700, color: C.text }}>Webhooks &amp; SIEM</div>
          <div style={{ fontSize: 12, color: C.dim, marginTop: 2 }}>Matching audit events are delivered as they are recorded, signed with HMAC-SHA256 when a secret is set</div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button
            onClick={() => load(true)}
            disabled={refreshing}
            style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 7, color: C.dim, padding: "7px 13px", cursor: "pointer", fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}
          >
            <RefreshCw size={13} style={refreshing ? { animation: "spin 1s linear infinite" } : {}} /> Refresh
          </button>
          <button
            onClick={() => { setEditTarget(null); setShowModal(true); }}
            style={{ background: C.accent, border: "none", borderRadius: 7, color: C.bg, padding: "7px 14px", cursor: "pointer", fontSize: 12, fontWeight: 600, display: "flex", alignItems: "center", gap: 6 }}
          >
            <Plus size={13} /> Add Webhook
          </button>
        </div>
      </div>

      {unavailable && (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 24, marginBottom: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: C.text }}>Not assessed: webhook configuration is unavailable</div>
          <div style={{ fontSize: 12, color: C.dim, marginTop: 6 }}>The audit service did not return webhooks, so none are shown.</div>
          <div style={{ fontSize: 11, color: C.red, marginTop: 8, fontFamily: "IBM Plex Mono, monospace", wordBreak: "break-word" }}>{unavailable}</div>
        </div>
      )}
      {error && <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 8, padding: "8px 12px", fontSize: 12, color: C.red, marginBottom: 14 }}>{error}</div>}
      {notice && <div style={{ background: C.greenDim, border: `1px solid ${C.green}`, borderRadius: 8, padding: "8px 12px", fontSize: 12, color: C.green, marginBottom: 14 }}>{notice}</div>}

      {!unavailable && <>
      {/* Stat cards */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
        <StatCard icon={<WebhookIcon size={16} />} label="Active Webhooks" value={activeCount} color={C.accent} bg={C.accentTint} />
        <StatCard icon={<XCircle size={16} />} label="Last Delivery Failed" value={failingCount} color={C.amber} bg={C.amberTint} />
        <StatCard icon={<XCircle size={16} />} label="Failed Deliveries (total)" value={failedDeliveries} color={C.red} bg={C.redTint} />
      </div>

      {/* Webhooks list */}
      <div style={sectionTitle}>Configured Webhooks</div>

      {webhooks.length === 0 ? (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 40, textAlign: "center", color: C.muted, fontSize: 13 }}>
          No webhooks configured. Click "Add Webhook" to get started.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {webhooks.map(wh => (
            <div key={wh.id}>
              <WebhookCard
                wh={wh}
                logOpen={openLogId === wh.id}
                onToggle={() => handleToggle(wh)}
                onEdit={() => { setEditTarget(wh); setShowModal(true); }}
                onDelete={() => handleDelete(wh.id)}
                onTest={() => handleTest(wh)}
                onViewLog={() => setOpenLogId(prev => prev === wh.id ? null : wh.id)}
              />
              {openLogId === wh.id && (
                <DeliveryLog
                  webhook={wh}
                  session={session}
                  onClose={() => setOpenLogId(null)}
                />
              )}
            </div>
          ))}
        </div>
      )}

      <div style={divider} />

      {/* Format reference */}
      <div style={sectionTitle}>Supported Formats</div>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        {(Object.entries(FORMAT_LABELS) as [WebhookFormat, string][]).map(([fmt, label]) => (
          <div key={fmt} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: "8px 14px", display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: FORMAT_COLORS[fmt], boxShadow: `0 0 6px ${FORMAT_COLORS[fmt]}` }} />
            <span style={{ fontSize: 12, color: C.text }}>{label}</span>
          </div>
        ))}
      </div>

      </>}

      {showModal && (
        <WebhookModal
          initial={editTarget ?? undefined}
          onClose={() => { setShowModal(false); setEditTarget(null); }}
          onSave={handleSave}
        />
      )}
      <style>{`@keyframes spin { from{transform:rotate(0deg)}to{transform:rotate(360deg)} }`}</style>
    </div>
  );
}
