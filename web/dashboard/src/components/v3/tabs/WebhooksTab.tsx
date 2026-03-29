// @ts-nocheck
import { useEffect, useState } from "react";
import {
  Webhook as WebhookIcon, Plus, RefreshCw, Trash2, Edit2, Zap,
  CheckCircle, XCircle, Clock, ToggleLeft, ToggleRight, ChevronRight, ChevronDown, X
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
  type WebhookEventType,
} from "../../../lib/webhooks";

/* ─── Props ──────────────────────────────────────────────── */
interface Props {
  session: any;
  enabledFeatures?: any;
  keyCatalog?: any[];
}

/* ─── Mock data ──────────────────────────────────────────── */
const MOCK_WEBHOOKS: Webhook[] = [
  {
    id: "wh-1", tenant_id: "t1", name: "Splunk SIEM", url: "https://splunk.internal.corp/services/collector/event",
    format: "splunk_hec", events: ["key.created", "key.rotated", "key.deleted", "access.denied", "audit.high_severity"],
    secret: "sp_hmac_s3cr3t", enabled: true, created_at: "2025-11-01T00:00:00Z",
    last_delivery_at: new Date(Date.now() - 120_000).toISOString(), last_delivery_status: "success",
    failure_count: 0, headers: { "X-Splunk-Token": "abc123" },
  },
  {
    id: "wh-2", tenant_id: "t1", name: "Datadog Monitoring", url: "https://http-intake.logs.datadoghq.com/api/v2/logs",
    format: "datadog", events: ["key.expiring", "key.expired", "cert.expiring", "cert.revoked", "posture.risk_change"],
    secret: "dd_hmac_s3cr3t", enabled: true, created_at: "2025-12-01T00:00:00Z",
    last_delivery_at: new Date(Date.now() - 3_600_000).toISOString(), last_delivery_status: "success",
    failure_count: 1, headers: { "DD-API-KEY": "ddkey123" },
  },
  {
    id: "wh-3", tenant_id: "t1", name: "Slack Security Alerts", url: "https://hooks.slack.com/services/T00000/B00000/XXXXXXXX",
    format: "slack", events: ["access.denied", "access.anomaly", "ceremony.started", "ceremony.aborted"],
    secret: "", enabled: true, created_at: "2026-01-15T00:00:00Z",
    last_delivery_at: new Date(Date.now() - 86_400_000).toISOString(), last_delivery_status: "failed",
    failure_count: 3, headers: {},
  },
  {
    id: "wh-4", tenant_id: "t1", name: "PagerDuty On-Call", url: "https://events.pagerduty.com/v2/enqueue",
    format: "pagerduty", events: ["cluster.node_down", "cluster.leader_change", "access.anomaly"],
    secret: "pd_integration_key", enabled: false, created_at: "2026-02-10T00:00:00Z",
    last_delivery_at: undefined, last_delivery_status: undefined, failure_count: 0, headers: {},
  },
];

const MOCK_DELIVERIES: WebhookDelivery[] = [
  { id: "d-1", webhook_id: "wh-1", event_type: "key.rotated", payload_preview: '{"event":"key.rotated","key_id":"k-abc"}', status: "success", http_status: 200, delivered_at: new Date(Date.now() - 120_000).toISOString(), latency_ms: 43, attempt: 1 },
  { id: "d-2", webhook_id: "wh-1", event_type: "access.denied", payload_preview: '{"event":"access.denied","user":"ops@corp"}', status: "success", http_status: 200, delivered_at: new Date(Date.now() - 3_600_000).toISOString(), latency_ms: 61, attempt: 1 },
  { id: "d-3", webhook_id: "wh-1", event_type: "audit.high_severity", payload_preview: '{"event":"audit.high_severity"}', status: "failed", http_status: 503, delivered_at: new Date(Date.now() - 7_200_000).toISOString(), latency_ms: 5000, error: "Service Unavailable", attempt: 3 },
  { id: "d-4", webhook_id: "wh-1", event_type: "key.created", payload_preview: '{"event":"key.created","key_id":"k-xyz"}', status: "success", http_status: 200, delivered_at: new Date(Date.now() - 86_400_000).toISOString(), latency_ms: 38, attempt: 1 },
];

/* ─── Event groups ───────────────────────────────────────── */
const EVENT_GROUPS: { label: string; events: WebhookEventType[] }[] = [
  { label: "Key Events",    events: ["key.created","key.rotated","key.deleted","key.expiring","key.expired"] },
  { label: "Secret Events", events: ["secret.created","secret.rotated","secret.deleted"] },
  { label: "Cert Events",   events: ["cert.issued","cert.renewed","cert.revoked","cert.expiring"] },
  { label: "Access Events", events: ["access.denied","access.anomaly"] },
  { label: "System Events", events: ["ceremony.started","ceremony.completed","ceremony.aborted","audit.high_severity","posture.risk_change","cluster.node_down","cluster.leader_change"] },
];

const FORMAT_LABELS: Record<WebhookFormat, string> = {
  splunk_hec: "Splunk HEC", datadog: "Datadog", pagerduty: "PagerDuty",
  slack: "Slack", json: "JSON", generic_siem: "Generic SIEM",
};
const FORMAT_COLORS: Record<WebhookFormat, string> = {
  splunk_hec: C.orange, datadog: C.purple, pagerduty: C.green,
  slack: C.accent, json: C.blue, generic_siem: C.dim,
};

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
interface StatCardProps { icon: React.ReactNode; label: string; value: string | number; color?: string; bg?: string }
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
  initial?: Partial<Webhook>;
  onClose: () => void;
  onSave: (data: Partial<Webhook>) => Promise<void>;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [url, setUrl] = useState(initial?.url ?? "");
  const [format, setFormat] = useState<WebhookFormat>(initial?.format ?? "json");
  const [events, setEvents] = useState<Set<WebhookEventType>>(new Set(initial?.events ?? []));
  const [headers, setHeaders] = useState<{ k: string; v: string }[]>(
    Object.entries(initial?.headers ?? {}).map(([k, v]) => ({ k, v }))
  );
  const [secret, setSecret] = useState(initial?.secret ?? "");
  const [saving, setSaving] = useState(false);

  function toggleEvent(e: WebhookEventType) {
    setEvents(prev => { const n = new Set(prev); n.has(e) ? n.delete(e) : n.add(e); return n; });
  }
  function addHeader() { setHeaders(h => [...h, { k: "", v: "" }]); }
  function removeHeader(i: number) { setHeaders(h => h.filter((_, idx) => idx !== i)); }
  function setHeader(i: number, field: "k" | "v", val: string) {
    setHeaders(h => h.map((row, idx) => idx === i ? { ...row, [field]: val } : row));
  }

  async function handleSave() {
    setSaving(true);
    try {
      const hdrs = Object.fromEntries(headers.filter(h => h.k).map(h => [h.k, h.v]));
      await onSave({ name, url, format, events: Array.from(events), headers: hdrs, secret });
      onClose();
    } catch { /* swallow */ }
    finally { setSaving(false); }
  }

  const inp: React.CSSProperties = { background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, padding: "7px 10px", fontSize: 12, width: "100%", fontFamily: "IBM Plex Sans, sans-serif", outline: "none", boxSizing: "border-box" };
  const lbl: React.CSSProperties = { fontSize: 11, color: C.dim, marginBottom: 4, display: "block" };

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.65)", zIndex: 9999, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: C.card, border: `1px solid ${C.borderHi}`, borderRadius: 12, padding: 28, width: 540, maxHeight: "85vh", overflowY: "auto", boxShadow: "0 24px 60px rgba(0,0,0,.6)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
          <span style={{ fontSize: 15, fontWeight: 600, color: C.text }}>{initial?.id ? "Edit Webhook" : "Add Webhook"}</span>
          <button onClick={onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", padding: 4 }}><X size={16} /></button>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div><label style={lbl}>Name</label><input style={inp} value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Splunk SIEM" /></div>
          <div><label style={lbl}>Endpoint URL</label><input style={inp} value={url} onChange={e => setUrl(e.target.value)} placeholder="https://…" /></div>
          <div>
            <label style={lbl}>Format</label>
            <select style={inp} value={format} onChange={e => setFormat(e.target.value as WebhookFormat)}>
              {(Object.keys(FORMAT_LABELS) as WebhookFormat[]).map(f => <option key={f} value={f}>{FORMAT_LABELS[f]}</option>)}
            </select>
          </div>
          <div><label style={lbl}>Signing Secret (HMAC-SHA256)</label><input style={inp} value={secret} onChange={e => setSecret(e.target.value)} placeholder="Leave blank to skip signing" type="password" /></div>

          <div>
            <label style={lbl}>Events</label>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {EVENT_GROUPS.map(group => (
                <div key={group.label}>
                  <div style={{ fontSize: 11, color: C.accent, fontWeight: 600, marginBottom: 6 }}>{group.label}</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {group.events.map(ev => {
                      const checked = events.has(ev);
                      return (
                        <label key={ev} style={{ display: "flex", alignItems: "center", gap: 5, cursor: "pointer", userSelect: "none" }}>
                          <input type="checkbox" checked={checked} onChange={() => toggleEvent(ev)} style={{ accentColor: C.accent }} />
                          <span style={{ fontSize: 11, color: checked ? C.text : C.dim, fontFamily: "IBM Plex Mono, monospace" }}>{ev}</span>
                        </label>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
              <label style={{ ...lbl, marginBottom: 0 }}>Custom Headers</label>
              <button onClick={addHeader} style={{ background: "none", border: `1px solid ${C.border}`, borderRadius: 5, color: C.dim, fontSize: 11, padding: "3px 8px", cursor: "pointer" }}>+ Add</button>
            </div>
            {headers.map((h, i) => (
              <div key={i} style={{ display: "flex", gap: 6, marginBottom: 6 }}>
                <input style={{ ...inp, flex: 1 }} placeholder="Header name" value={h.k} onChange={e => setHeader(i, "k", e.target.value)} />
                <input style={{ ...inp, flex: 2 }} placeholder="Value" value={h.v} onChange={e => setHeader(i, "v", e.target.value)} />
                <button onClick={() => removeHeader(i)} style={{ background: "none", border: "none", color: C.red, cursor: "pointer", flexShrink: 0 }}><X size={13} /></button>
              </div>
            ))}
          </div>
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 20 }}>
          <button onClick={onClose} style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 6, color: C.dim, padding: "8px 16px", cursor: "pointer", fontSize: 12 }}>Cancel</button>
          <button
            onClick={handleSave}
            disabled={saving || !name || !url}
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

  useEffect(() => {
    listDeliveries(session, webhook.id)
      .then(setDeliveries)
      .catch(() => setDeliveries(MOCK_DELIVERIES.filter(d => d.webhook_id === webhook.id)))
      .finally(() => setLoading(false));
  }, [webhook.id]);

  const th: React.CSSProperties = { textAlign: "left", fontSize: 10, color: C.muted, fontWeight: 600, padding: "8px 12px", textTransform: "uppercase", letterSpacing: "0.06em", whiteSpace: "nowrap" };
  const td: React.CSSProperties = { padding: "10px 12px", fontSize: 12, color: C.text, verticalAlign: "middle" };

  return (
    <div style={{ marginTop: 8, background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 10, overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: `1px solid ${C.border}` }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>Delivery Log — {webhook.name}</span>
        <button onClick={onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer" }}><X size={14} /></button>
      </div>
      {loading ? (
        <div style={{ padding: 24, textAlign: "center", color: C.dim, fontSize: 12 }}>Loading deliveries…</div>
      ) : deliveries.length === 0 ? (
        <div style={{ padding: 24, textAlign: "center", color: C.muted, fontSize: 12 }}>No deliveries recorded.</div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Event Type", "Status", "HTTP", "Latency", "Delivered At", "Error"].map(h => (
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
                      : d.status === "retrying"
                      ? <span style={{ display: "flex", alignItems: "center", gap: 4, color: C.amber, fontSize: 11 }}><Clock size={11} /> Retrying</span>
                      : <span style={{ display: "flex", alignItems: "center", gap: 4, color: C.red, fontSize: 11 }}><XCircle size={11} /> Failed</span>}
                  </td>
                  <td style={{ ...td, fontFamily: "IBM Plex Mono, monospace", color: d.http_status && d.http_status < 300 ? C.green : C.red }}>{d.http_status ?? "—"}</td>
                  <td style={{ ...td, fontFamily: "IBM Plex Mono, monospace", color: C.dim }}>{d.latency_ms}ms</td>
                  <td style={{ ...td, fontFamily: "IBM Plex Mono, monospace", fontSize: 11, color: C.dim }}>{relTime(d.delivered_at)}</td>
                  <td style={{ ...td, color: C.red, fontSize: 11 }}>{d.error ?? <span style={{ color: C.muted }}>—</span>}</td>
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
  onTest: () => void;
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
            <span style={{ background: `${fmtColor}18`, color: fmtColor, border: `1px solid ${fmtColor}33`, borderRadius: 5, fontSize: 10, padding: "1px 7px", fontWeight: 600 }}>{FORMAT_LABELS[wh.format]}</span>
            {!wh.enabled && <span style={{ background: C.amberDim, color: C.amber, borderRadius: 5, fontSize: 10, padding: "1px 7px", fontWeight: 600 }}>Disabled</span>}
            {wh.failure_count > 0 && <span style={{ background: C.redDim, color: C.red, borderRadius: 5, fontSize: 10, padding: "1px 7px" }}>{wh.failure_count} failure{wh.failure_count > 1 ? "s" : ""}</span>}
          </div>
          <div style={{ fontSize: 11, color: C.dim, marginTop: 4, fontFamily: "IBM Plex Mono, monospace" }}>{shortUrl(wh.url)}</div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 8, flexWrap: "wrap" }}>
            <span style={{ fontSize: 11, color: C.muted }}>{wh.events.length} events subscribed</span>
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
export function WebhooksTab({ session, enabledFeatures, keyCatalog }: Props) {
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [editTarget, setEditTarget] = useState<Webhook | null>(null);
  const [openLogId, setOpenLogId] = useState<string | null>(null);

  async function load(silent = false) {
    if (!silent) setLoading(true); else setRefreshing(true);
    try {
      const data = await listWebhooks(session);
      setWebhooks(data);
    } catch {
      setWebhooks(MOCK_WEBHOOKS);
    } finally {
      setLoading(false); setRefreshing(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleSave(data: Partial<Webhook>) {
    if (editTarget) {
      const updated = await updateWebhook(session, editTarget.id, data).catch(() => ({ ...editTarget, ...data } as Webhook));
      setWebhooks(prev => prev.map(w => w.id === editTarget.id ? updated : w));
    } else {
      const created = await createWebhook(session, data).catch(() => ({ id: `wh-${Date.now()}`, tenant_id: "t1", failure_count: 0, enabled: true, created_at: new Date().toISOString(), ...data } as Webhook));
      setWebhooks(prev => [...prev, created]);
    }
    setEditTarget(null);
  }

  async function handleDelete(id: string) {
    await deleteWebhook(session, id).catch(() => {});
    setWebhooks(prev => prev.filter(w => w.id !== id));
    if (openLogId === id) setOpenLogId(null);
  }

  async function handleToggle(wh: Webhook) {
    const updated = await updateWebhook(session, wh.id, { enabled: !wh.enabled }).catch(() => ({ ...wh, enabled: !wh.enabled } as Webhook));
    setWebhooks(prev => prev.map(w => w.id === wh.id ? updated : w));
  }

  async function handleTest(id: string) {
    await testWebhook(session, id).catch(() => {});
    await load(true);
  }

  const activeCount = webhooks.filter(w => w.enabled).length;
  const successDeliveries = webhooks.filter(w => w.last_delivery_status === "success").length;
  const failedDeliveries = webhooks.reduce((s, w) => s + w.failure_count, 0);

  const divider: React.CSSProperties = { borderTop: `1px solid ${C.border}`, margin: "24px 0" };
  const sectionTitle: React.CSSProperties = { fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 };

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
          <div style={{ fontSize: 12, color: C.dim, marginTop: 2 }}>Outbound event delivery to external systems</div>
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

      {/* Stat cards */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
        <StatCard icon={<WebhookIcon size={16} />} label="Active Webhooks" value={activeCount} color={C.accent} bg={C.accentTint} />
        <StatCard icon={<CheckCircle size={16} />} label="Deliveries (24h)" value={successDeliveries} color={C.green} bg={C.greenTint} />
        <StatCard icon={<XCircle size={16} />} label="Failed Deliveries (24h)" value={failedDeliveries} color={C.red} bg={C.redTint} />
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
                onTest={() => handleTest(wh.id)}
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
