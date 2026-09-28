// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import {
  Play, Plus, RefreshCcw, Trash2, Edit2, CheckCircle2, XCircle,
  Zap, Shield, Clock, Activity, ChevronDown, ChevronRight,
  ToggleLeft, ToggleRight, ListChecks, Link2, AlertTriangle, FlaskConical, Ban, RotateCcw
} from "lucide-react";
import { C } from "../../v3/theme";

// ── helpers ──────────────────────────────────────────────────────────────────

function fmtDate(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function fmtAgo(iso?: string): string {
  if (!iso) return "—";
  const diff = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function fmtDuration(started?: string, completed?: string): string {
  if (!started || !completed) return "—";
  const diff = Math.max(0, Math.floor((new Date(completed).getTime() - new Date(started).getTime()) / 1000));
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
  return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
}


// Every call reports { ok, status, data, error } so failures are shown, never
// replaced by placeholder data.
async function call(session: any, service: string, method: string, path: string, body?: any) {
  const headers: any = { "X-Tenant-ID": session?.tenantId || "", "Authorization": `Bearer ${session?.token || ""}` };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  try {
    // eslint-disable-next-line no-restricted-globals -- intentional: legacy direct call, refactor to typed client tracked separately
    const r = await fetch(`/svc/${service}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const json = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, data: json, error: json?.error?.message || json?.message || (r.ok ? "" : `HTTP ${r.status}`) };
  } catch (e: any) {
    return { ok: false, status: 0, data: {}, error: String(e?.message || e) };
  }
}

// ── shared primitives ─────────────────────────────────────────────────────────

const TH = ({ children }: any) => (
  <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}`, whiteSpace: "nowrap" }}>{children}</th>
);
const TD = ({ children, mono }: any) => (
  <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{children}</td>
);
const Badge = ({ color, children }: any) => (
  <span style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600, textTransform: "capitalize", letterSpacing: 0.3 }}>{children}</span>
);
const Btn = ({ onClick, children, variant = "default", disabled = false, small = false }: any) => {
  const base: any = { display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: small ? 11 : 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", transition: "opacity .15s", opacity: disabled ? 0.5 : 1 };
  const styles: any = {
    default: { background: C.accent, color: C.bg },
    ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` },
    danger: { background: C.redDim, color: C.red, border: `1px solid ${C.red}33` },
    green: { background: C.greenDim, color: C.green, border: `1px solid ${C.green}33` },
  };
  return <button onClick={disabled ? undefined : onClick} style={{ ...base, ...styles[variant] }}>{children}</button>;
};
const Inp = ({ label, ...props }: any) => (
  <div style={{ marginBottom: 12 }}>
    {label && <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div>}
    <input {...props} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box", ...props.style }} />
  </div>
);
const Sel = ({ label, children, ...props }: any) => (
  <div style={{ marginBottom: 12 }}>
    {label && <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div>}
    <select {...props} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box", ...props.style }}>{children}</select>
  </div>
);
const Txt = ({ label, ...props }: any) => (
  <div style={{ marginBottom: 12 }}>
    {label && <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div>}
    <textarea {...props} rows={props.rows || 3} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", resize: "vertical", boxSizing: "border-box", fontFamily: "inherit", ...props.style }} />
  </div>
);
const Chk = ({ label, checked, onChange }: any) => (
  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12, cursor: "pointer" }} onClick={() => onChange(!checked)}>
    <div style={{ width: 16, height: 16, borderRadius: 4, border: `1px solid ${checked ? C.accent : C.border}`, background: checked ? C.accent : "transparent", display: "flex", alignItems: "center", justifyContent: "center" }}>
      {checked && <CheckCircle2 size={10} color={C.bg} />}
    </div>
    <span style={{ fontSize: 12, color: C.text }}>{label}</span>
  </div>
);
const StatCard = ({ icon, label, value, color = C.accent, tint, sublabel }: any) => (
  <div style={{ flex: 1, minWidth: 150, background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "14px 16px", display: "flex", flexDirection: "column", gap: 6, backgroundImage: tint ? `linear-gradient(135deg, ${tint}, transparent)` : undefined }}>
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <span style={{ color }}>{icon}</span>
      <span style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, fontWeight: 600 }}>{label}</span>
    </div>
    <div style={{ fontSize: 22, fontWeight: 700, color, letterSpacing: -0.5 }}>{value}</div>
    {sublabel && <div style={{ fontSize: 10, color: C.muted }}>{sublabel}</div>}
  </div>
);

// The trigger/action catalogue comes from the backend

// The trigger/action/connection catalogue comes from the backend
// (GET /compliance/playbooks/catalog): the dashboard offers exactly what the
// executor performs and what services really emit.

const prettify = (s: string) => (s || "").replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());

const groupColor = (group: string) => ({
  "Incident response": C.red, "Key lifecycle": C.blue, "Certificates": C.cyan || C.blue, "Access": C.purple,
  "Compliance": C.amber, "Platform": C.orange, "Custom": C.accent,
} as Record<string, string>)[group] || C.muted;

const statusColor = (s: string) => {
  if (s === "completed" || s === "done") return C.green;
  if (["failed", "cancelled", "approval_denied", "approval_expired", "refused"].includes(s)) return C.red;
  if (s === "partial_failure") return C.orange;
  if (["running", "pending_approval", "awaiting_approval"].includes(s)) return C.amber;
  return C.muted;
};

const groupBy = (items: any[]) => {
  const out: { group: string; items: any[] }[] = [];
  for (const it of items || []) {
    let g = out.find(x => x.group === it.group);
    if (!g) { g = { group: it.group, items: [] }; out.push(g); }
    g.items.push(it);
  }
  return out;
};

// Parameters: one key=value per line (values may contain commas, JSON, URLs).
const paramsToText = (p: Record<string, string>) => Object.entries(p || {}).filter(([k]) => k !== "connection_id").map(([k, v]) => `${k}=${v}`).join("\n");
const textToParams = (text: string) => {
  const out: Record<string, string> = {};
  for (const line of (text || "").split("\n")) {
    const i = line.indexOf("=");
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
};

const Card = ({ title, icon, right, children }: any) => (
  <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden", marginBottom: 20 }}>
    {title && (
      <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 8 }}>
        {icon}<span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{title}</span>
        <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>{right}</div>
      </div>
    )}
    {children}
  </div>
);

const Err = ({ children }: any) => children ? <div style={{ fontSize: 12, color: C.red, margin: "0 0 12px" }}>{children}</div> : null;

// FiltersEditor edits [{field, op, value}]: triggers and action conditions.
function FiltersEditor({ filters, onChange, catalog, label }: any) {
  const fields = [...(catalog?.event_fields || []), "details."];
  const set = (i: number, k: string, v: string) => onChange(filters.map((f: any, idx: number) => idx === i ? { ...f, [k]: v } : f));
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div>
      {filters.map((f: any, i: number) => (
        <div key={i} style={{ display: "flex", gap: 6, marginBottom: 6 }}>
          <input list="pb-event-fields" value={f.field} placeholder="field (e.g. severity, details.key_id)" onChange={(e: any) => set(i, "field", e.target.value)}
            style={{ flex: 2, background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "6px 8px", color: C.text, fontSize: 11 }} />
          <select value={f.op} onChange={(e: any) => set(i, "op", e.target.value)} style={{ flex: 1, background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontSize: 11 }}>
            {(catalog?.filter_ops || []).map((o: string) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input value={f.value} placeholder="value (comma list for in)" onChange={(e: any) => set(i, "value", e.target.value)}
            style={{ flex: 2, background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "6px 8px", color: C.text, fontSize: 11 }} />
          <button onClick={() => onChange(filters.filter((_: any, idx: number) => idx !== i))} style={{ background: "none", border: "none", color: C.red, cursor: "pointer" }}><Trash2 size={12} /></button>
        </div>
      ))}
      <datalist id="pb-event-fields">{fields.map((f: string) => <option key={f} value={f} />)}</datalist>
      <Btn variant="ghost" small onClick={() => onChange([...filters, { field: "severity", op: "eq", value: "" }])}><Plus size={10} /> Add filter</Btn>
    </div>
  );
}

// ── main component ────────────────────────────────────────────────────────────

export function PlaybooksTab({ session }: { session: any }) {
  const api = useCallback((service: string, method: string, path: string, body?: any) => call(session, service, method, path, body), [session]);
  const cp = useCallback((method: string, path: string, body?: any) => api("compliance", method, `/compliance${path}`, body), [api]);
  const [view, setView] = useState("overview");
  const [catalog, setCatalog] = useState<any>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [playbooks, setPlaybooks] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [runs, setRuns] = useState<any[]>([]);
  const [runFilter, setRunFilter] = useState({ status: "", incident_id: "" });
  const [openRun, setOpenRun] = useState<string>("");
  const [connections, setConnections] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [incidentRuns, setIncidentRuns] = useState<Record<string, any[]>>({});
  const [toast, setToast] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [dryRun, setDryRun] = useState<any>(null);
  const [connForm, setConnForm] = useState<any>(null);

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(""), 5000); };
  const fail = (key: string, msg: string) => setErrors(p => ({ ...p, [key]: msg }));

  const triggerSpec = (t: string) => catalog?.triggers?.find((x: any) => x.type === t);
  const actionSpec = (a: string) => catalog?.actions?.find((x: any) => x.type === a);
  const connType = (t: string) => catalog?.connection_types?.find((x: any) => x.type === t);

  const emptyForm = () => ({
    name: "", description: "", category: "incident_response", enabled: true,
    trigger: { type: "canary_tripped", subject: "", filters: [], threshold: 0, window_seconds: 0, group_by: "" },
    actions: [{ type: "create_audit_event", delay_seconds: "0", params: "message=", connection_id: "", condition: [], require_approval: false }],
  });
  const [form, setForm] = useState<any>(emptyForm());
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    const next: Record<string, string> = {};
    const [cat, pbs, sum, conns] = await Promise.all([cp("GET", "/playbooks/catalog"), cp("GET", "/playbooks"), cp("GET", "/playbooks/summary"), cp("GET", "/playbooks/connections")]);
    if (cat.ok) setCatalog(cat.data.data); else next.catalog = cat.error;
    if (pbs.ok) setPlaybooks(pbs.data.data || []); else next.playbooks = pbs.error;
    if (sum.ok) setSummary(sum.data.data); else next.summary = sum.error;
    if (conns.ok) setConnections(conns.data.data || []); else next.connections = conns.error;
    setErrors(next);
  }, [cp]);

  const loadRuns = useCallback(async () => {
    const q = new URLSearchParams();
    if (runFilter.status) q.set("status", runFilter.status);
    if (runFilter.incident_id) q.set("incident_id", runFilter.incident_id);
    q.set("limit", "100");
    const r = await cp("GET", `/playbook-runs?${q.toString()}`);
    if (r.ok) { setRuns(r.data.data || []); fail("runs", ""); } else fail("runs", r.error);
  }, [runFilter, cp]);

  const loadIncidents = useCallback(async () => {
    const r = await api("reporting", "GET", `/incidents?limit=50`);
    if (!r.ok) { fail("incidents", r.error); return; }
    const items = r.data.items || r.data.incidents || r.data.data || [];
    setIncidents(items);
    fail("incidents", "");
    const linked: Record<string, any[]> = {};
    await Promise.all(items.slice(0, 50).map(async (inc: any) => {
      const rr = await cp("GET", `/playbook-runs?incident_id=${encodeURIComponent(inc.id)}&limit=20`);
      linked[inc.id] = rr.ok ? (rr.data.data || []) : [];
    }));
    setIncidentRuns(linked);
  }, [api, cp]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (view === "runs" || view === "overview") loadRuns(); }, [view, loadRuns]);
  useEffect(() => { if (view === "incidents") loadIncidents(); }, [view, loadIncidents]);

  // ── playbook actions ──
  const payloadOf = (pb: any, enabled: boolean) => ({
    name: pb.name, description: pb.description, category: pb.category, enabled,
    trigger: pb.trigger,
    actions: (pb.actions || []).map((a: any) => ({ type: a.type, delay_seconds: a.delay_seconds || 0, parameters: a.parameters || {}, condition: a.condition || [], require_approval: !!a.require_approval })),
  });

  const handleToggle = async (pb: any) => {
    const r = await cp("PUT", `/playbooks/${pb.id}`, payloadOf(pb, !pb.enabled));
    if (!r.ok) showToast("Update refused: " + r.error);
    load();
  };
  const handleDelete = async (pb: any) => {
    if (!window.confirm(`Delete playbook "${pb.name}"?`)) return;
    const r = await cp("DELETE", `/playbooks/${pb.id}`);
    showToast(r.ok ? "Playbook deleted." : "Delete refused: " + r.error);
    load();
  };
  const handleRun = async (pb: any) => {
    const raw = window.prompt("Event context for this run as JSON (optional), e.g. {\"target_id\":\"key_123\",\"severity\":\"high\"}", "");
    let event: any = undefined;
    if (raw) { try { event = JSON.parse(raw); } catch { showToast("Event context is not valid JSON."); return; } }
    const r = await cp("POST", `/playbooks/${pb.id}/run`, event ? { event } : {});
    if (r.ok) { showToast(`Run ${r.data.data.run_id} started; see Runs.`); setTimeout(() => { load(); loadRuns(); }, 1200); }
    else showToast("Run refused: " + r.error);
  };
  const handleDryRun = async (pb: any) => {
    const raw = window.prompt("Event to test against as JSON (optional)", "");
    let event: any = undefined;
    if (raw) { try { event = JSON.parse(raw); } catch { showToast("Event is not valid JSON."); return; } }
    const r = await cp("POST", `/playbooks/${pb.id}/dry-run`, event ? { event } : {});
    if (r.ok) setDryRun({ pb, ...r.data.data }); else showToast("Dry run failed: " + r.error);
  };
  const handleCancel = async (run: any) => {
    const r = await cp("POST", `/playbook-runs/${run.id}/cancel`, {});
    showToast(r.ok ? "Run cancelled." : "Cancel refused: " + r.error);
    setTimeout(loadRuns, 500);
  };
  const handleRetry = async (run: any) => {
    const r = await cp("POST", `/playbook-runs/${run.id}/retry`, {});
    showToast(r.ok ? `Retry ${r.data.data.run_id} started.` : "Retry refused: " + r.error);
    setTimeout(loadRuns, 1000);
  };

  // ── editor ──
  const openEditor = (pb?: any) => {
    if (!pb) { setForm(emptyForm()); setEditingId(null); setView("editor"); return; }
    setForm({
      name: pb.name, description: pb.description, category: pb.category || "incident_response", enabled: pb.enabled,
      trigger: { type: pb.trigger?.type || "", subject: pb.trigger?.subject || "", filters: pb.trigger?.filters || [], threshold: pb.trigger?.threshold || 0, window_seconds: pb.trigger?.window_seconds || 0, group_by: pb.trigger?.group_by || "" },
      actions: (pb.actions || []).map((a: any) => ({
        type: a.type, delay_seconds: String(a.delay_seconds || 0), params: paramsToText(a.parameters), connection_id: a.parameters?.connection_id || "",
        condition: a.condition || [], require_approval: !!a.require_approval,
      })),
    });
    setEditingId(pb.id);
    setView("editor");
  };
  const setTrigger = (k: string, v: any) => setForm((p: any) => ({ ...p, trigger: { ...p.trigger, [k]: v } }));
  const setAction = (i: number, k: string, v: any) => setForm((p: any) => ({ ...p, actions: p.actions.map((a: any, idx: number) => idx === i ? { ...a, [k]: v } : a) }));

  const handleSave = async () => {
    setSaving(true);
    try {
      const t = form.trigger;
      const threshold = parseInt(t.threshold) || 0;
      const body = {
        name: form.name, description: form.description, category: form.category, enabled: form.enabled,
        trigger: {
          type: t.type, ...(t.type === "custom_event" ? { subject: t.subject } : {}),
          filters: t.filters.filter((f: any) => f.field),
          ...(threshold > 1 ? { threshold, window_seconds: parseInt(t.window_seconds) || 0, group_by: t.group_by || undefined } : {}),
        },
        actions: form.actions.map((a: any) => {
          const parameters = textToParams(a.params);
          if (actionSpec(a.type)?.connection) parameters.connection_id = a.connection_id;
          return { type: a.type, delay_seconds: parseInt(a.delay_seconds) || 0, parameters, condition: a.condition.filter((f: any) => f.field), require_approval: !!a.require_approval };
        }),
      };
      const r = editingId ? await cp("PUT", `/playbooks/${editingId}`, body) : await cp("POST", "/playbooks", body);
      if (r.ok) { showToast(editingId ? "Playbook saved." : `Playbook "${form.name}" created.`); setEditingId(null); setView("playbooks"); load(); }
      else showToast("Save refused: " + r.error);
    } finally { setSaving(false); }
  };

  // ── connections ──
  const saveConnection = async () => {
    const f = connForm;
    const body = { name: f.name, type: f.type, fields: Object.fromEntries(Object.entries(f.fields).filter(([, v]) => v !== "")) };
    const r = f.id ? await cp("PUT", `/playbooks/connections/${f.id}`, body) : await cp("POST", "/playbooks/connections", body);
    if (r.ok) { showToast("Connection saved (credentials sealed)."); setConnForm(null); load(); } else showToast("Save refused: " + r.error);
  };
  const testConnection = async (c: any) => {
    const r = await cp("POST", `/playbooks/connections/${c.id}/test`, {});
    showToast(r.ok ? `Test reached ${c.endpoint}.` : "Test failed: " + r.error);
  };
  const deleteConnection = async (c: any) => {
    if (!window.confirm(`Delete connection "${c.name}"?`)) return;
    const r = await cp("DELETE", `/playbooks/connections/${c.id}`);
    showToast(r.ok ? "Connection deleted." : "Delete refused: " + r.error);
    load();
  };

  const triggerGroups = groupBy(catalog?.triggers);
  const actionGroups = groupBy(catalog?.actions);
  const covered = new Set(playbooks.filter((p: any) => p.enabled && p.authorized_by).map((p: any) => p.trigger?.type));
  const neededPerms = Array.from(new Set(form.actions.map((a: any) => actionSpec(a.type)?.permission).filter(Boolean)));
  const awaiting = runs.filter((r: any) => r.status === "awaiting_approval");

  const authBadge = (pb: any) => {
    const unsupported = !triggerSpec(pb.trigger?.type) || (pb.actions || []).some((a: any) => !actionSpec(a.type));
    if (catalog && unsupported) return <Badge color={C.red}>Unsupported step, edit</Badge>;
    if (!pb.authorized_by) return <Badge color={C.amber}>Not authorized</Badge>;
    return <span style={{ fontSize: 10, color: C.muted }}>{pb.authorized_by}</span>;
  };

  const RunRow = ({ r }: any) => {
    const open = openRun === r.id;
    return (
      <>
        <tr>
          <TD><button onClick={() => setOpenRun(open ? "" : r.id)} style={{ background: "none", border: "none", cursor: "pointer", color: C.muted, padding: 0 }}>{open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}</button></TD>
          <TD mono>{r.id}</TD>
          <TD>{playbooks.find((p: any) => p.id === r.playbook_id)?.name || r.playbook_id}</TD>
          <TD><Badge color={groupColor(triggerSpec(r.trigger_event)?.group)}>{r.trigger_event}</Badge></TD>
          <TD>{r.actor || "—"}</TD>
          <TD><Badge color={statusColor(r.status)}>{prettify(r.status)}</Badge></TD>
          <TD>{r.incident_id || "—"}</TD>
          <TD>{fmtDate(r.started_at)}</TD>
          <TD>
            <div style={{ display: "flex", gap: 6 }}>
              {["running", "awaiting_approval"].includes(r.status) && <Btn variant="danger" small onClick={() => handleCancel(r)}><Ban size={11} /> Cancel</Btn>}
              {["failed", "partial_failure", "cancelled", "approval_denied", "approval_expired"].includes(r.status) && <Btn variant="ghost" small onClick={() => handleRetry(r)}><RotateCcw size={11} /> Retry</Btn>}
            </div>
          </TD>
        </tr>
        {open && (
          <tr><td colSpan={9} style={{ background: C.bg, padding: "12px 32px" }}>
            <div style={{ fontSize: 10, color: C.muted, marginBottom: 6 }}>
              {r.context?.supplied ? "Event supplied by the runner" : `Event ${r.context?.subject || "—"}`}
              {r.context?.target_id ? ` · target ${r.context.target_id}` : ""}{r.context?.severity ? ` · severity ${r.context.severity}` : ""}
              {r.approval_request_id ? ` · waiting on governance request ${r.approval_request_id}` : ""}{r.retry_of ? ` · retry of ${r.retry_of}` : ""}
            </div>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH>#</TH><TH>Action</TH><TH>Outcome</TH><TH>Target</TH><TH>Detail</TH><TH>At</TH><TH>ms</TH></tr></thead>
              <tbody>
                {(r.results || []).map((x: any, i: number) => (
                  <tr key={i}>
                    <TD>{x.index}</TD><TD>{actionSpec(x.type)?.label || x.type}</TD>
                    <TD><Badge color={statusColor(x.status)}>{prettify(x.status)}</Badge></TD>
                    <TD mono>{x.target || "—"}</TD><TD>{[x.reason, x.error].filter(Boolean).join(": ") || "—"}</TD>
                    <TD>{fmtDate(x.at)}</TD><TD>{x.elapsed_ms}</TD>
                  </tr>
                ))}
              </tbody>
            </table>
          </td></tr>
        )}
      </>
    );
  };

  const views = [["overview", "Overview", Activity], ["playbooks", "Playbooks", ListChecks], ["runs", "Runs", Zap], ["incidents", "Incidents", AlertTriangle], ["connections", "Connections", Link2]];

  return (
    <div style={{ padding: "24px 28px", maxWidth: 1240, margin: "0 auto" }}>
      {toast && <div style={{ position: "fixed", bottom: 24, right: 24, background: C.card, border: `1px solid ${C.borderHi}`, borderRadius: 8, padding: "10px 16px", color: C.text, fontSize: 12, zIndex: 999, maxWidth: 440 }}>{toast}</div>}

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Play size={20} color={C.accent} />
          <span style={{ fontSize: 18, fontWeight: 700, color: C.text }}>Playbooks</span>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {views.map(([v, label, Icon]: any) => <Btn key={v} small variant={view === v ? "default" : "ghost"} onClick={() => setView(v)}><Icon size={12} /> {label}</Btn>)}
          <Btn small disabled={!catalog} onClick={() => openEditor()}><Plus size={12} /> New</Btn>
          <Btn variant="ghost" small onClick={() => { load(); loadRuns(); }}><RefreshCcw size={12} /></Btn>
        </div>
      </div>
      <div style={{ fontSize: 11, color: C.dim, marginBottom: 16, lineHeight: 1.5 }}>
        A playbook responds to an audited event (or runs by hand): it can notify through sealed connections, act on keys, certificates, users, alerts and incidents, and pause for a governance approval.
        Actions run as the compliance service on the authority of the person who last saved the playbook, re-checked with auth before every automatic run.
      </div>
      <Err>{errors.catalog && `Playbook catalogue unavailable: ${errors.catalog}`}</Err>
      <Err>{errors.playbooks && `Playbooks unavailable: ${errors.playbooks}`}</Err>

      {view === "overview" && (
        <>
          <div style={{ display: "flex", gap: 14, marginBottom: 20, flexWrap: "wrap" }}>
            <StatCard icon={<ListChecks size={16} />} label="Playbooks" value={summary?.total_playbooks ?? "unavailable"} color={C.accent} />
            <StatCard icon={<CheckCircle2 size={16} />} label="Enabled" value={summary?.enabled_count ?? "unavailable"} color={C.green} />
            <StatCard icon={<Zap size={16} />} label="Runs today" value={summary?.runs_today ?? "unavailable"} color={C.amber} />
            <StatCard icon={<Clock size={16} />} label="Awaiting approval" value={errors.runs ? "unavailable" : awaiting.length} color={awaiting.length ? C.amber : C.muted} />
          </div>
          {awaiting.length > 0 && (
            <Card title="Runs awaiting approval (approve in Governance)" icon={<Clock size={14} color={C.amber} />}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}><tbody>{awaiting.map((r: any) => <RunRow key={r.id} r={r} />)}</tbody></table>
            </Card>
          )}
          {catalog && (
            <Card title={`Trigger coverage: ${catalog.triggers.filter((t: any) => covered.has(t.type)).length} / ${catalog.triggers.length} triggers have an enabled, authorized playbook`} icon={<Shield size={14} color={C.accent} />}>
              <div style={{ padding: 16 }}>
                {triggerGroups.map(g => (
                  <div key={g.group} style={{ marginBottom: 14 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: groupColor(g.group), marginBottom: 6 }}>{g.group}</div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                      {g.items.map((t: any) => (
                        <div key={t.type} style={{ background: covered.has(t.type) ? C.greenDim : C.card, border: `1px solid ${covered.has(t.type) ? C.green + "33" : C.border}`, borderRadius: 6, padding: "6px 10px", minWidth: 170 }}>
                          <div style={{ fontSize: 10, fontWeight: 600, color: C.text }}>{covered.has(t.type) ? <CheckCircle2 size={10} color={C.green} /> : <XCircle size={10} color={C.muted} />} {t.label}</div>
                          <div style={{ fontSize: 9, color: C.muted, fontFamily: "'JetBrains Mono', monospace" }}>{(t.subjects || []).join(", ") || "any subject you name"}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </>
      )}

      {view === "playbooks" && (
        <Card title="All playbooks" icon={<ListChecks size={14} color={C.accent} />}>
          {dryRun && (
            <div style={{ padding: 16, borderBottom: `1px solid ${C.border}`, background: C.bg }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <FlaskConical size={13} color={C.accent} /><span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Dry run: {dryRun.pb.name}</span>
                <span style={{ fontSize: 10, color: C.muted }}>nothing was changed; targets were read from their services</span>
                <button onClick={() => setDryRun(null)} style={{ marginLeft: "auto", background: "none", border: "none", color: C.muted, cursor: "pointer" }}><XCircle size={13} /></button>
              </div>
              <div style={{ fontSize: 11, color: dryRun.trigger_matches ? C.green : C.amber, marginBottom: 6 }}>Trigger filters {dryRun.trigger_matches ? "match" : "do not match"} this event.</div>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr><TH>#</TH><TH>Action</TH><TH>Would run</TH><TH>Parameters</TH><TH>Permission</TH><TH>Approval</TH><TH>Target</TH></tr></thead>
                <tbody>{dryRun.steps.map((s: any) => (
                  <tr key={s.index}>
                    <TD>{s.index}</TD><TD>{actionSpec(s.type)?.label || s.type}</TD>
                    <TD>{s.would_run ? <Badge color={C.green}>yes</Badge> : <Badge color={C.muted}>{s.reason || "no"}</Badge>}</TD>
                    <TD mono>{Object.entries(s.parameters || {}).map(([k, v]) => `${k}=${v}`).join(", ") || "—"}</TD>
                    <TD>{s.permission ? <Badge color={s.has_permission ? C.green : C.red}>{s.permission}</Badge> : "—"}</TD>
                    <TD>{s.approval_required ? "required" : "—"}</TD><TD>{s.target_check}</TD>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
          {playbooks.length === 0 ? <div style={{ padding: 28, textAlign: "center", color: C.muted, fontSize: 12 }}>No playbooks yet.</div> : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH>Name</TH><TH>Trigger</TH><TH>Actions</TH><TH>Enabled</TH><TH>Authorized by</TH><TH>Runs</TH><TH>Last run</TH><TH></TH></tr></thead>
              <tbody>{playbooks.map((pb: any) => (
                <tr key={pb.id}>
                  <TD><span style={{ fontWeight: 600 }}>{pb.name}</span><div style={{ fontSize: 10, color: C.muted }}>{prettify(pb.category)}{pb.description ? ` · ${pb.description}` : ""}</div></TD>
                  <TD>
                    <Badge color={groupColor(triggerSpec(pb.trigger?.type)?.group)}>{triggerSpec(pb.trigger?.type)?.label || pb.trigger?.type}</Badge>
                    <div style={{ fontSize: 9, color: C.muted }}>
                      {pb.trigger?.subject || ""}{(pb.trigger?.filters || []).length ? ` · ${pb.trigger.filters.length} filter(s)` : ""}
                      {pb.trigger?.threshold > 1 ? ` · ${pb.trigger.threshold} in ${pb.trigger.window_seconds}s${pb.trigger.group_by ? ` per ${pb.trigger.group_by}` : ""}` : ""}
                    </div>
                  </TD>
                  <TD><span style={{ color: C.dim }}>{(pb.actions || []).map((a: any) => actionSpec(a.type)?.label || a.type).join(" → ")}</span></TD>
                  <TD><button onClick={() => handleToggle(pb)} style={{ background: "none", border: "none", cursor: "pointer", color: pb.enabled ? C.green : C.muted }}>{pb.enabled ? <ToggleRight size={18} /> : <ToggleLeft size={18} />}</button></TD>
                  <TD>{authBadge(pb)}</TD>
                  <TD>{pb.run_count}</TD>
                  <TD>{pb.last_run_at ? fmtAgo(pb.last_run_at) : "Never"}</TD>
                  <TD>
                    <div style={{ display: "flex", gap: 6 }}>
                      <Btn variant="ghost" small onClick={() => openEditor(pb)}><Edit2 size={11} /></Btn>
                      <Btn variant="ghost" small onClick={() => handleDryRun(pb)}><FlaskConical size={11} /> Dry run</Btn>
                      <Btn variant="green" small onClick={() => handleRun(pb)}><Play size={11} /> Run</Btn>
                      <Btn variant="danger" small onClick={() => handleDelete(pb)}><Trash2 size={11} /></Btn>
                    </div>
                  </TD>
                </tr>
              ))}</tbody>
            </table>
          )}
        </Card>
      )}

      {view === "runs" && (
        <Card title="Runs" icon={<Zap size={14} color={C.accent} />} right={<>
          <select value={runFilter.status} onChange={(e: any) => setRunFilter(p => ({ ...p, status: e.target.value }))} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontSize: 11 }}>
            <option value="">all statuses</option>
            {["running", "awaiting_approval", "completed", "pending_approval", "partial_failure", "failed", "cancelled", "approval_denied", "approval_expired"].map(s => <option key={s} value={s}>{prettify(s)}</option>)}
          </select>
          <input placeholder="incident id" value={runFilter.incident_id} onChange={(e: any) => setRunFilter(p => ({ ...p, incident_id: e.target.value }))} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontSize: 11, padding: "3px 6px" }} />
        </>}>
          <Err>{errors.runs && <div style={{ padding: 12 }}>Runs unavailable: {errors.runs}</div>}</Err>
          {runs.length === 0 ? <div style={{ padding: 28, textAlign: "center", color: C.muted, fontSize: 12 }}>No runs match.</div> : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH></TH><TH>Run</TH><TH>Playbook</TH><TH>Trigger</TH><TH>On authority of</TH><TH>Status</TH><TH>Incident</TH><TH>Started</TH><TH></TH></tr></thead>
              <tbody>{runs.map((r: any) => <RunRow key={r.id} r={r} />)}</tbody>
            </table>
          )}
        </Card>
      )}

      {view === "incidents" && (
        <Card title="Incidents (Alert Center) and the playbook runs that responded" icon={<AlertTriangle size={14} color={C.red} />}>
          <Err>{errors.incidents && <div style={{ padding: 12 }}>Incidents unavailable: {errors.incidents}</div>}</Err>
          {incidents.length === 0 ? <div style={{ padding: 28, textAlign: "center", color: C.muted, fontSize: 12 }}>No incidents. Playbooks with the "Incident opened" trigger respond when one opens.</div> : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH>Incident</TH><TH>Severity</TH><TH>Status</TH><TH>Alerts</TH><TH>Assigned</TH><TH>Playbook runs</TH></tr></thead>
              <tbody>{incidents.map((inc: any) => (
                <tr key={inc.id}>
                  <TD><span style={{ fontWeight: 600 }}>{inc.title}</span><div style={{ fontSize: 9, color: C.muted, fontFamily: "'JetBrains Mono', monospace" }}>{inc.id}</div></TD>
                  <TD><Badge color={statusColor(inc.severity === "critical" ? "failed" : "running")}>{inc.severity}</Badge></TD>
                  <TD>{prettify(inc.status)}</TD><TD>{inc.alert_count}</TD><TD>{inc.assigned_to || "—"}</TD>
                  <TD>{(incidentRuns[inc.id] || []).length === 0 ? <span style={{ color: C.muted }}>none</span> :
                    (incidentRuns[inc.id] || []).map((r: any) => (
                      <div key={r.id} style={{ fontSize: 10 }}>
                        <button onClick={() => { setRunFilter({ status: "", incident_id: inc.id }); setView("runs"); }} style={{ background: "none", border: "none", color: C.accent, cursor: "pointer", padding: 0 }}>
                          {playbooks.find((p: any) => p.id === r.playbook_id)?.name || r.playbook_id}
                        </button> <Badge color={statusColor(r.status)}>{prettify(r.status)}</Badge>
                      </div>
                    ))}</TD>
                </tr>
              ))}</tbody>
            </table>
          )}
        </Card>
      )}

      {view === "connections" && (
        <Card title="Connections (credentials sealed under the compliance master key; never shown again)" icon={<Link2 size={14} color={C.accent} />}
          right={<Btn small disabled={!catalog} onClick={() => setConnForm({ name: "", type: "slack", fields: {} })}><Plus size={11} /> New connection</Btn>}>
          <Err>{errors.connections && <div style={{ padding: 12 }}>Connections unavailable: {errors.connections}</div>}</Err>
          {connForm && (
            <div style={{ padding: 16, borderBottom: `1px solid ${C.border}`, background: C.bg, maxWidth: 560 }}>
              <Inp label="Name" value={connForm.name} onChange={(e: any) => setConnForm((p: any) => ({ ...p, name: e.target.value }))} />
              <Sel label="Type" value={connForm.type} disabled={!!connForm.id} onChange={(e: any) => setConnForm((p: any) => ({ ...p, type: e.target.value, fields: {} }))}>
                {(catalog?.connection_types || []).map((t: any) => <option key={t.type} value={t.type}>{t.label}</option>)}
              </Sel>
              {[...(connType(connForm.type)?.fields || []), ...(connType(connForm.type)?.optional || [])].map((f: string) => (
                <Inp key={f} label={`${f}${(connType(connForm.type)?.fields || []).includes(f) ? " *" : ""}${connForm.id ? " (leave ******** to keep)" : ""}`}
                  type={f === "headers" ? "text" : "password"} placeholder={f === "headers" ? '{"Authorization":"Bearer ..."}' : f.endsWith("url") ? "https://..." : ""}
                  value={connForm.fields[f] ?? ""} onChange={(e: any) => setConnForm((p: any) => ({ ...p, fields: { ...p.fields, [f]: e.target.value } }))} />
              ))}
              <div style={{ fontSize: 10, color: C.muted, marginBottom: 10 }}>The endpoint must be a public https address; platform services and private addresses are refused.</div>
              <div style={{ display: "flex", gap: 8 }}>
                <Btn onClick={saveConnection}>Save</Btn><Btn variant="ghost" onClick={() => setConnForm(null)}>Cancel</Btn>
              </div>
            </div>
          )}
          {connections.length === 0 ? <div style={{ padding: 28, textAlign: "center", color: C.muted, fontSize: 12 }}>No connections.</div> : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH>Name</TH><TH>Type</TH><TH>Endpoint</TH><TH>Fields set</TH><TH>Updated</TH><TH></TH></tr></thead>
              <tbody>{connections.map((c: any) => (
                <tr key={c.id}>
                  <TD><span style={{ fontWeight: 600 }}>{c.name}</span><div style={{ fontSize: 9, color: C.muted, fontFamily: "'JetBrains Mono', monospace" }}>{c.id}</div></TD>
                  <TD>{connType(c.type)?.label || c.type}</TD><TD mono>{c.endpoint}</TD><TD>{(c.fields_set || []).join(", ")}</TD><TD>{fmtAgo(c.updated_at)}</TD>
                  <TD><div style={{ display: "flex", gap: 6 }}>
                    <Btn variant="ghost" small onClick={() => testConnection(c)}>Test</Btn>
                    <Btn variant="ghost" small onClick={() => setConnForm({ id: c.id, name: c.name, type: c.type, fields: Object.fromEntries((c.fields_set || []).map((f: string) => [f, "********"])) })}><Edit2 size={11} /></Btn>
                    <Btn variant="danger" small onClick={() => deleteConnection(c)}><Trash2 size={11} /></Btn>
                  </div></TD>
                </tr>
              ))}</tbody>
            </table>
          )}
        </Card>
      )}

      {view === "editor" && catalog && (
        <div style={{ display: "flex", gap: 20, alignItems: "flex-start", flexWrap: "wrap" }}>
          <div style={{ flex: "1 1 380px", background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "20px 24px" }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 16 }}>{editingId ? "Edit playbook" : "New playbook"}</div>
            <Inp label="Name *" value={form.name} onChange={(e: any) => setForm((p: any) => ({ ...p, name: e.target.value }))} />
            <Txt label="Description" rows={2} value={form.description} onChange={(e: any) => setForm((p: any) => ({ ...p, description: e.target.value }))} />
            <Sel label="Category" value={form.category} onChange={(e: any) => setForm((p: any) => ({ ...p, category: e.target.value }))}>
              {catalog.categories.map((c: string) => <option key={c} value={c}>{prettify(c)}</option>)}
            </Sel>
            <Sel label="Trigger" value={form.trigger.type} onChange={(e: any) => setTrigger("type", e.target.value)}>
              {!triggerSpec(form.trigger.type) && <option value={form.trigger.type}>{form.trigger.type} (no longer supported)</option>}
              {triggerGroups.map(g => <optgroup key={g.group} label={g.group}>{g.items.map((t: any) => <option key={t.type} value={t.type}>{t.label}</option>)}</optgroup>)}
            </Sel>
            {form.trigger.type === "custom_event" ? (
              <Inp label="Audit subject (exact, or ending in .*) — fires only if a service emits it" placeholder="audit.cert.*" value={form.trigger.subject} onChange={(e: any) => setTrigger("subject", e.target.value)} />
            ) : (
              <div style={{ fontSize: 10, color: C.muted, marginTop: -6, marginBottom: 12, fontFamily: "'JetBrains Mono', monospace" }}>
                fires on {(triggerSpec(form.trigger.type)?.subjects || []).join(", ")}{triggerSpec(form.trigger.type)?.success_only ? " (success only)" : ""}
              </div>
            )}
            <FiltersEditor label="Trigger filters (all must match)" catalog={catalog} filters={form.trigger.filters} onChange={(v: any) => setTrigger("filters", v)} />
            <div style={{ display: "flex", gap: 8 }}>
              <Inp label="Threshold (events)" type="number" value={form.trigger.threshold} onChange={(e: any) => setTrigger("threshold", e.target.value)} />
              <Inp label="Window (seconds)" type="number" value={form.trigger.window_seconds} onChange={(e: any) => setTrigger("window_seconds", e.target.value)} />
              <Inp label="Group by (field)" placeholder="actor_id" value={form.trigger.group_by} onChange={(e: any) => setTrigger("group_by", e.target.value)} />
            </div>
            <div style={{ fontSize: 10, color: C.muted, marginTop: -6, marginBottom: 12 }}>With a threshold above 1 the playbook fires when that many matching events arrive within the window (per group). Counts are kept on the primary and restart from zero after a failover.</div>
            <Chk label="Enabled (runs automatically when the trigger fires)" checked={form.enabled} onChange={(v: boolean) => setForm((p: any) => ({ ...p, enabled: v }))} />
            <div style={{ fontSize: 11, color: C.dim }}>{neededPerms.length ? <>Enabling it needs: <b>{neededPerms.join(", ")}</b>. It will run on your authority.</> : "These actions need no extra permission."}</div>
          </div>

          <div style={{ flex: "1 1 460px", background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "20px 24px" }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 4 }}>Actions</div>
            <div style={{ fontSize: 10, color: C.muted, marginBottom: 14 }}>Run in order. Templates: {(catalog.templates || []).join(" ")}</div>
            {form.actions.map((a: any, i: number) => {
              const spec = actionSpec(a.type);
              const conns = connections.filter((c: any) => c.type === spec?.connection);
              return (
                <div key={i} style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 14px", marginBottom: 10 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                    <span style={{ fontSize: 11, color: C.muted, fontWeight: 600 }}>Action {i + 1}</span>
                    {form.actions.length > 1 && <button onClick={() => setForm((p: any) => ({ ...p, actions: p.actions.filter((_: any, idx: number) => idx !== i) }))} style={{ background: "none", border: "none", color: C.red, cursor: "pointer" }}><Trash2 size={13} /></button>}
                  </div>
                  <Sel value={a.type} onChange={(e: any) => setAction(i, "type", e.target.value)}>
                    {!spec && <option value={a.type}>{a.type} (no longer supported)</option>}
                    {actionGroups.map(g => <optgroup key={g.group} label={g.group}>{g.items.map((t: any) => <option key={t.type} value={t.type}>{t.label}</option>)}</optgroup>)}
                  </Sel>
                  {spec?.connection && (
                    <Sel label={`${connType(spec.connection)?.label || spec.connection} connection *`} value={a.connection_id} onChange={(e: any) => setAction(i, "connection_id", e.target.value)}>
                      <option value="">{conns.length ? "choose…" : "no connection of this type: add one under Connections"}</option>
                      {conns.map((c: any) => <option key={c.id} value={c.id}>{c.name} ({c.endpoint})</option>)}
                    </Sel>
                  )}
                  <Txt label="Parameters (one key=value per line)" rows={3} value={a.params} onChange={(e: any) => setAction(i, "params", e.target.value)}
                    placeholder={(spec?.required || []).filter((k: string) => k !== "connection_id").map((k: string) => `${k}=`).join("\n")} style={{ fontFamily: "'JetBrains Mono', monospace" }} />
                  {spec && (
                    <div style={{ fontSize: 10, color: C.muted, lineHeight: 1.6, marginBottom: 8 }}>
                      {(spec.required || []).filter((k: string) => k !== "connection_id").length ? <>Required: {spec.required.filter((k: string) => k !== "connection_id").join(", ")}. </> : null}
                      Optional: {[...(spec.optional || []), "stop_on_failure"].join(", ")}. {spec.permission ? <>Needs {spec.permission}. </> : null}
                      {spec.delegated ? "Auth performs it for you, re-checking your permission. " : ""}
                      {a.type === "send_email" ? "Recipients: emails of this tenant's users or role:<name>, comma-separated. " : ""}
                      {a.type === "set_incident_status" ? `Status: ${(catalog.incident_statuses || []).join(", ")}. ` : ""}
                    </div>
                  )}
                  <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                    <Inp label="Delay (s)" type="number" value={a.delay_seconds} onChange={(e: any) => setAction(i, "delay_seconds", e.target.value)} style={{ width: 90 }} />
                    <Chk label={spec?.approval === "required" ? "Governance approval (always required)" : "Require governance approval"} checked={spec?.approval === "required" || a.require_approval}
                      onChange={(v: boolean) => spec?.approval !== "required" && setAction(i, "require_approval", v)} />
                  </div>
                  <FiltersEditor label="Run only if (condition on the event)" catalog={catalog} filters={a.condition} onChange={(v: any) => setAction(i, "condition", v)} />
                </div>
              );
            })}
            <Btn variant="ghost" small onClick={() => setForm((p: any) => ({ ...p, actions: [...p.actions, { type: "create_audit_event", delay_seconds: "0", params: "", connection_id: "", condition: [], require_approval: false }] }))}><Plus size={11} /> Add action</Btn>
            <div style={{ marginTop: 18, display: "flex", gap: 8 }}>
              <Btn onClick={handleSave} disabled={saving || !form.name}>{saving ? "Saving…" : editingId ? "Save playbook" : "Create playbook"}</Btn>
              <Btn variant="ghost" onClick={() => { setEditingId(null); setView("playbooks"); }}>Cancel</Btn>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
