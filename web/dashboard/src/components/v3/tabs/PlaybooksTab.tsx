// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import {
  Play, Plus, RefreshCcw, Trash2, Edit2, CheckCircle2, XCircle,
  Zap, Shield, Clock, Activity, ChevronDown, ChevronRight,
  ToggleLeft, ToggleRight, ListChecks
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

const base = "/svc/compliance";

async function apiGet(path: string, tenantId: string, token: string) {
  // eslint-disable-next-line no-restricted-globals -- intentional: legacy direct call, refactor to typed client tracked separately
  const r = await fetch(`${base}${path}`, { headers: { "X-Tenant-ID": tenantId, "Authorization": `Bearer ${token}` } });
  return r.json();
}

async function apiPost(path: string, tenantId: string, token: string, body: any) {
  // eslint-disable-next-line no-restricted-globals -- intentional: legacy direct call, refactor to typed client tracked separately
  const r = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Tenant-ID": tenantId, "Authorization": `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  return r.json();
}

async function apiPut(path: string, tenantId: string, token: string, body: any) {
  // eslint-disable-next-line no-restricted-globals -- intentional: legacy direct call, refactor to typed client tracked separately
  const r = await fetch(`${base}${path}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Tenant-ID": tenantId, "Authorization": `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  return r.json();
}

async function apiDelete(path: string, tenantId: string, token: string) {
  // eslint-disable-next-line no-restricted-globals -- intentional: legacy direct call, refactor to typed client tracked separately
  const r = await fetch(`${base}${path}`, { method: "DELETE", headers: { "X-Tenant-ID": tenantId, "Authorization": `Bearer ${token}` } });
  return r.json();
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
// (GET /compliance/playbooks/catalog): the dashboard offers exactly what the
// executor performs and what services really emit, nothing hardcoded here.

const errMsg = (res: any) => res?.error?.message || res?.message || "unknown error";

const prettify = (s: string) => (s || "").replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());

const groupColor = (group: string) => ({
  "Incident response": C.red,
  "Key lifecycle": C.blue,
  "Certificates": C.cyan || C.blue,
  "Access": C.purple,
  "Compliance": C.amber,
  "Platform": C.orange,
} as Record<string, string>)[group] || C.muted;

const statusColor = (s: string) => {
  if (s === "completed") return C.green;
  if (s === "failed" || s === "cancelled") return C.red;
  if (s === "partial_failure") return C.orange;
  if (s === "running" || s === "pending_approval") return C.amber;
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

// Parameters are edited one per line as key=value (values may contain
// commas, JSON, URLs).
const paramsToText = (p: Record<string, string>) => Object.entries(p || {}).map(([k, v]) => `${k}=${v}`).join("\n");
const textToParams = (text: string) => {
  const out: Record<string, string> = {};
  for (const line of (text || "").split("\n")) {
    const i = line.indexOf("=");
    if (i <= 0) continue;
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
};

// ── main component ────────────────────────────────────────────────────────────

export function PlaybooksTab({ session }: { session: any }) {
  const tenantId = session?.tenantId || "";
  const token = session?.token || "";
  const [view, setView] = useState<"overview" | "playbooks" | "create">("overview");
  const [catalog, setCatalog] = useState<any>(null);
  const [catalogError, setCatalogError] = useState("");
  const [playbooks, setPlaybooks] = useState<any[]>([]);
  const [loadError, setLoadError] = useState("");
  const [summary, setSummary] = useState<any>(null);
  const [recentRuns, setRecentRuns] = useState<any[]>([]);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [rowRuns, setRowRuns] = useState<Record<string, any[]>>({});
  const [toast, setToast] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);

  const triggerSpec = (t: string) => catalog?.triggers?.find((x: any) => x.type === t);
  const actionSpec = (a: string) => catalog?.actions?.find((x: any) => x.type === a);

  const emptyForm = () => ({
    name: "",
    description: "",
    category: "incident_response",
    trigger_type: catalog?.triggers?.[0]?.type || "",
    enabled: true,
    actions: [{ type: "create_audit_event", delay_seconds: "0", params: "" }],
  });
  const [form, setForm] = useState(emptyForm());
  const [saving, setSaving] = useState(false);

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(""), 4500);
  };

  const load = useCallback(async () => {
    try {
      const cat = await apiGet("/playbooks/catalog", tenantId, token);
      if (cat?.data) { setCatalog(cat.data); setCatalogError(""); } else setCatalogError(errMsg(cat));
    } catch (e: any) {
      setCatalogError(String(e?.message || e));
    }
    try {
      const [pbRes, summaryRes] = await Promise.all([
        apiGet("/playbooks", tenantId, token),
        apiGet("/playbooks/summary", tenantId, token),
      ]);
      if (!pbRes?.data) { setLoadError(errMsg(pbRes)); return; }
      setLoadError("");
      const pbs = pbRes.data;
      setPlaybooks(pbs);
      setSummary(summaryRes?.data || null);
      const ran = pbs.filter((p: any) => p.run_count > 0).slice(0, 3);
      const runResults = await Promise.all(ran.map((p: any) => apiGet(`/playbooks/${p.id}/runs?limit=5`, tenantId, token)));
      const allRuns = runResults.flatMap((r: any) => r?.data || []);
      allRuns.sort((a: any, b: any) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime());
      setRecentRuns(allRuns.slice(0, 10));
    } catch (e: any) {
      setLoadError(String(e?.message || e));
    }
  }, [tenantId, token]);

  useEffect(() => { load(); }, [load]);

  const loadRuns = async (id: string) => {
    const res = await apiGet(`/playbooks/${id}/runs?limit=10`, tenantId, token);
    setRowRuns(prev => ({ ...prev, [id]: res?.data || [] }));
  };

  const toggleRow = async (id: string) => {
    const next = new Set(expandedRows);
    if (next.has(id)) next.delete(id);
    else { next.add(id); if (!rowRuns[id]) await loadRuns(id); }
    setExpandedRows(next);
  };

  const handleRun = async (pb: any) => {
    const res = await apiPost(`/playbooks/${pb.id}/run`, tenantId, token, {});
    if (res?.data?.run_id) {
      showToast(`Run ${res.data.run_id} started. Each action is audited; see run history for the outcome.`);
      setTimeout(() => { loadRuns(pb.id); load(); }, 1500);
    } else {
      showToast("Run refused: " + errMsg(res));
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm("Delete this playbook?")) return;
    const res = await apiDelete(`/playbooks/${id}`, tenantId, token);
    showToast(res?.data ? "Playbook deleted." : "Delete failed: " + errMsg(res));
    load();
  };

  // Secret parameters come back as ******** and are sent back unchanged; the
  // backend keeps the stored value.
  const payloadOf = (pb: any, enabled: boolean) => ({
    name: pb.name,
    description: pb.description,
    category: pb.category,
    trigger: { type: pb.trigger?.type },
    actions: (pb.actions || []).map((a: any) => ({ type: a.type, delay_seconds: a.delay_seconds || 0, parameters: a.parameters || {} })),
    enabled,
  });

  const handleToggleEnabled = async (pb: any) => {
    const res = await apiPut(`/playbooks/${pb.id}`, tenantId, token, payloadOf(pb, !pb.enabled));
    if (!res?.data) showToast("Update refused: " + errMsg(res));
    load();
  };

  const handleSave = async () => {
    if (!form.name) { showToast("Name is required."); return; }
    setSaving(true);
    try {
      const body = {
        name: form.name,
        description: form.description,
        category: form.category,
        trigger: { type: form.trigger_type },
        actions: form.actions.map((a: any) => ({ type: a.type, delay_seconds: parseInt(a.delay_seconds) || 0, parameters: textToParams(a.params) })),
        enabled: form.enabled,
      };
      const res = editingId
        ? await apiPut(`/playbooks/${editingId}`, tenantId, token, body)
        : await apiPost("/playbooks", tenantId, token, body);
      if (res?.data?.id) {
        showToast(editingId ? "Playbook updated." : `Playbook "${form.name}" created.`);
        setForm(emptyForm());
        setEditingId(null);
        setView("playbooks");
        load();
      } else {
        showToast("Save refused: " + errMsg(res));
      }
    } finally {
      setSaving(false);
    }
  };

  const handleEdit = (pb: any) => {
    setForm({
      name: pb.name,
      description: pb.description,
      category: pb.category || "incident_response",
      trigger_type: pb.trigger?.type || "",
      enabled: pb.enabled,
      actions: (pb.actions || []).map((a: any) => ({ type: a.type, delay_seconds: String(a.delay_seconds || 0), params: paramsToText(a.parameters) })),
    });
    setEditingId(pb.id);
    setView("create");
  };

  const addAction = () => setForm(p => ({ ...p, actions: [...p.actions, { type: "create_audit_event", delay_seconds: "0", params: "" }] }));
  const removeAction = (i: number) => setForm(p => ({ ...p, actions: p.actions.filter((_: any, idx: number) => idx !== i) }));
  const updateAction = (i: number, field: string, value: string) => setForm(p => ({
    ...p,
    actions: p.actions.map((a: any, idx: number) => idx === i ? { ...a, [field]: value } : a),
  }));

  const triggerGroups = groupBy(catalog?.triggers);
  const actionGroups = groupBy(catalog?.actions);
  const coveredTriggers = new Set(playbooks.filter((p: any) => p.enabled && p.authorized_by).map((p: any) => p.trigger?.type));
  const neededPerms = Array.from(new Set(form.actions.map((a: any) => actionSpec(a.type)?.permission).filter(Boolean)));

  const authBadge = (pb: any) => {
    const unsupported = !triggerSpec(pb.trigger?.type) || (pb.actions || []).some((a: any) => !actionSpec(a.type));
    if (catalog && unsupported) return <Badge color={C.red}>Unsupported step, edit</Badge>;
    if (!pb.authorized_by) return <Badge color={C.amber}>Not authorized</Badge>;
    return <span style={{ fontSize: 10, color: C.muted }}>{pb.authorized_by}</span>;
  };

  return (
    <div style={{ padding: "24px 28px", maxWidth: 1200, margin: "0 auto" }}>
      {toast && (
        <div style={{ position: "fixed", bottom: 24, right: 24, background: C.card, border: `1px solid ${C.borderHi}`, borderRadius: 8, padding: "10px 16px", color: C.text, fontSize: 12, zIndex: 999, boxShadow: "0 8px 24px rgba(0,0,0,.4)", maxWidth: 420 }}>
          {toast}
        </div>
      )}

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Play size={20} color={C.accent} />
          <span style={{ fontSize: 18, fontWeight: 700, color: C.text, letterSpacing: -0.4 }}>Playbooks</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {(["overview", "playbooks", "create"] as const).map(v => (
            <Btn key={v} variant={view === v ? "default" : "ghost"} small disabled={v === "create" && !catalog} onClick={() => { if (v === "create") { setForm(emptyForm()); setEditingId(null); } setView(v); }}>
              {v === "create" ? <><Plus size={12} /> New</>
               : v === "playbooks" ? <><ListChecks size={12} /> Playbooks</>
               : <><Activity size={12} /> Overview</>}
            </Btn>
          ))}
          <Btn variant="ghost" small onClick={load}><RefreshCcw size={12} /></Btn>
        </div>
      </div>

      <div style={{ fontSize: 11, color: C.dim, marginBottom: 16, lineHeight: 1.5 }}>
        A playbook runs its actions when its trigger event is audited, or when someone runs it. Actions act as the compliance service, so saving an
        enabled playbook, or running one, needs every permission its actions use. Automatic runs act on the authority of whoever last saved it.
      </div>
      {catalogError && <div style={{ fontSize: 12, color: C.red, marginBottom: 12 }}>Playbook catalogue unavailable: {catalogError}</div>}
      {loadError && <div style={{ fontSize: 12, color: C.red, marginBottom: 12 }}>Playbooks unavailable: {loadError}</div>}

      {view === "overview" && (
        <>
          <div style={{ display: "flex", gap: 14, marginBottom: 24, flexWrap: "wrap" }}>
            <StatCard icon={<ListChecks size={16} />} label="Total Playbooks" value={summary?.total_playbooks ?? "unavailable"} color={C.accent} tint={C.accentTint} />
            <StatCard icon={<CheckCircle2 size={16} />} label="Enabled" value={summary?.enabled_count ?? "unavailable"} color={C.green} tint={C.greenTint} />
            <StatCard icon={<Zap size={16} />} label="Runs Today" value={summary?.runs_today ?? "unavailable"} color={C.amber} tint={C.amberTint} />
            <StatCard icon={<Clock size={16} />} label="Last Run Status" value={summary?.last_run_status || "none"} color={statusColor(summary?.last_run_status)} sublabel={summary?.last_run_at ? fmtAgo(summary.last_run_at) : undefined} />
          </div>

          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden", marginBottom: 24 }}>
            <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 8 }}>
              <Activity size={14} color={C.accent} />
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Playbook Execution History</span>
            </div>
            {recentRuns.length === 0 ? (
              <div style={{ padding: 24, textAlign: "center", color: C.muted, fontSize: 12 }}>No playbook runs yet.</div>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr><TH>Playbook ID</TH><TH>Trigger</TH><TH>On authority of</TH><TH>Status</TH><TH>Actions Run</TH><TH>Started At</TH><TH>Duration</TH></tr></thead>
                <tbody>
                  {recentRuns.map((r: any) => (
                    <tr key={r.id}>
                      <TD mono>{r.playbook_id}</TD>
                      <TD><Badge color={groupColor(triggerSpec(r.trigger_event)?.group)}>{r.trigger_event || "—"}</Badge></TD>
                      <TD>{r.actor || "—"}</TD>
                      <TD><Badge color={statusColor(r.status)}>{prettify(r.status)}</Badge></TD>
                      <TD>{r.actions_run}</TD>
                      <TD>{fmtDate(r.started_at)}</TD>
                      <TD>{fmtDuration(r.started_at, r.completed_at)}</TD>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {catalog && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
              <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 8 }}>
                <Shield size={14} color={C.accent} />
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Trigger Coverage</span>
                <span style={{ fontSize: 10, color: C.muted, marginLeft: 8 }}>
                  {catalog.triggers.filter((t: any) => coveredTriggers.has(t.type)).length} / {catalog.triggers.length} triggers have an enabled, authorized playbook
                </span>
              </div>
              <div style={{ padding: 16 }}>
                {triggerGroups.map(g => (
                  <div key={g.group} style={{ marginBottom: 16 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: groupColor(g.group), marginBottom: 8 }}>{g.group}</div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                      {g.items.map((t: any) => {
                        const covered = coveredTriggers.has(t.type);
                        return (
                          <div key={t.type} title={t.subjects.join(", ")} style={{ background: covered ? C.greenDim : C.card, border: `1px solid ${covered ? C.green + "33" : C.border}`, borderRadius: 6, padding: "6px 10px", display: "flex", alignItems: "center", gap: 6, minWidth: 160 }}>
                            {covered ? <CheckCircle2 size={12} color={C.green} /> : <XCircle size={12} color={C.muted} />}
                            <div>
                              <div style={{ fontSize: 10, fontWeight: 600, color: C.text }}>{t.label}</div>
                              <div style={{ fontSize: 9, color: C.muted, fontFamily: "'JetBrains Mono', monospace" }}>{t.subjects.join(", ")}</div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {view === "playbooks" && (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
          <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <ListChecks size={14} color={C.accent} />
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>All Playbooks</span>
            </div>
            <Btn variant="default" small disabled={!catalog} onClick={() => { setForm(emptyForm()); setEditingId(null); setView("create"); }}><Plus size={11} /> New Playbook</Btn>
          </div>
          {playbooks.length === 0 ? (
            <div style={{ padding: 32, textAlign: "center", color: C.muted, fontSize: 12 }}>No playbooks configured.</div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH></TH><TH>Name</TH><TH>Category</TH><TH>Trigger</TH><TH>Actions</TH><TH>Enabled</TH><TH>Authorized by</TH><TH>Runs</TH><TH>Last Run</TH><TH></TH></tr></thead>
              <tbody>
                {playbooks.map((pb: any) => (
                  <>
                    <tr key={pb.id}>
                      <TD>
                        <button onClick={() => toggleRow(pb.id)} style={{ background: "none", border: "none", cursor: "pointer", color: C.muted, padding: 0 }}>
                          {expandedRows.has(pb.id) ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                        </button>
                      </TD>
                      <TD><span style={{ fontWeight: 600 }}>{pb.name}</span><div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{pb.description}</div></TD>
                      <TD><Badge color={C.muted}>{prettify(pb.category)}</Badge></TD>
                      <TD><Badge color={groupColor(triggerSpec(pb.trigger?.type)?.group)}>{triggerSpec(pb.trigger?.type)?.label || pb.trigger?.type || "—"}</Badge></TD>
                      <TD><span style={{ color: C.dim }}>{(pb.actions || []).map((a: any) => actionSpec(a.type)?.label || a.type).join(", ")}</span></TD>
                      <TD>
                        <button onClick={() => handleToggleEnabled(pb)} style={{ background: "none", border: "none", cursor: "pointer", color: pb.enabled ? C.green : C.muted, padding: 0, display: "inline-flex" }}>
                          {pb.enabled ? <ToggleRight size={18} /> : <ToggleLeft size={18} />}
                        </button>
                      </TD>
                      <TD>{authBadge(pb)}</TD>
                      <TD>{pb.run_count}</TD>
                      <TD>{pb.last_run_at ? fmtAgo(pb.last_run_at) : "Never"}</TD>
                      <TD>
                        <div style={{ display: "flex", gap: 6 }}>
                          <Btn variant="ghost" small onClick={() => handleEdit(pb)}><Edit2 size={11} /> Edit</Btn>
                          <Btn variant="green" small onClick={() => handleRun(pb)}><Play size={11} /> Run</Btn>
                          <Btn variant="danger" small onClick={() => handleDelete(pb.id)}><Trash2 size={11} /></Btn>
                        </div>
                      </TD>
                    </tr>
                    {expandedRows.has(pb.id) && (
                      <tr key={pb.id + "_runs"}>
                        <td colSpan={10} style={{ padding: "0 0 0 32px", background: C.bg }}>
                          <div style={{ padding: "12px 16px" }}>
                            <div style={{ fontSize: 10, color: C.muted, fontWeight: 600, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 }}>Run History</div>
                            {(rowRuns[pb.id] || []).length === 0 ? (
                              <div style={{ fontSize: 11, color: C.muted }}>No runs recorded yet.</div>
                            ) : (
                              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                                <thead><tr><TH>Run ID</TH><TH>Trigger</TH><TH>On authority of</TH><TH>Status</TH><TH>Output</TH><TH>Started At</TH><TH>Duration</TH></tr></thead>
                                <tbody>
                                  {(rowRuns[pb.id] || []).map((r: any) => (
                                    <tr key={r.id}>
                                      <TD mono>{r.id}</TD>
                                      <TD>{r.trigger_event || "—"}</TD>
                                      <TD>{r.actor || "—"}</TD>
                                      <TD><Badge color={statusColor(r.status)}>{prettify(r.status)}</Badge></TD>
                                      <TD mono><span style={{ whiteSpace: "pre-wrap", fontSize: 10 }}>{r.output || "—"}</span></TD>
                                      <TD>{fmtDate(r.started_at)}</TD>
                                      <TD>{fmtDuration(r.started_at, r.completed_at)}</TD>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {view === "create" && catalog && (
        <div style={{ display: "flex", gap: 20, alignItems: "flex-start" }}>
          <div style={{ flex: 1, background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "20px 24px" }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 18 }}>
              {editingId ? "Edit Playbook" : "New Playbook"}
            </div>
            <Inp label="Name *" placeholder="e.g. Canary Trip Response" value={form.name} onChange={(e: any) => setForm(p => ({ ...p, name: e.target.value }))} />
            <Txt label="Description" placeholder="What this playbook does..." value={form.description} onChange={(e: any) => setForm(p => ({ ...p, description: e.target.value }))} rows={3} />
            <Sel label="Category" value={form.category} onChange={(e: any) => setForm(p => ({ ...p, category: e.target.value }))}>
              {catalog.categories.map((c: string) => <option key={c} value={c}>{prettify(c)}</option>)}
            </Sel>
            <Sel label="Trigger" value={form.trigger_type} onChange={(e: any) => setForm(p => ({ ...p, trigger_type: e.target.value }))}>
              {triggerGroups.map(g => (
                <optgroup key={g.group} label={g.group}>
                  {g.items.map((t: any) => <option key={t.type} value={t.type}>{t.label}</option>)}
                </optgroup>
              ))}
            </Sel>
            <div style={{ fontSize: 10, color: C.muted, marginTop: -6, marginBottom: 12, fontFamily: "'JetBrains Mono', monospace" }}>
              fires on {triggerSpec(form.trigger_type)?.subjects?.join(", ") || "—"}{triggerSpec(form.trigger_type)?.success_only ? " (success only)" : ""}
            </div>
            <Chk label="Enabled (runs automatically when the trigger fires)" checked={form.enabled} onChange={(v: boolean) => setForm(p => ({ ...p, enabled: v }))} />
            <div style={{ fontSize: 11, color: C.dim }}>
              {neededPerms.length ? <>Saving it enabled needs: <b>{neededPerms.join(", ")}</b></> : "These actions need no extra permission."}
            </div>
          </div>

          <div style={{ flex: 1, background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "20px 24px" }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 4 }}>Response Actions</div>
            <div style={{ fontSize: 10, color: C.muted, marginBottom: 16 }}>Run in order. Each is audited as audit.compliance.playbook_action_executed.</div>
            {form.actions.map((action: any, i: number) => {
              const spec = actionSpec(action.type);
              return (
                <div key={i} style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 14px", marginBottom: 10 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <span style={{ fontSize: 11, color: C.muted, fontWeight: 600 }}>Action {i + 1}</span>
                    {form.actions.length > 1 && (
                      <button onClick={() => removeAction(i)} style={{ background: "none", border: "none", cursor: "pointer", color: C.red, padding: 0, display: "inline-flex" }}>
                        <Trash2 size={13} />
                      </button>
                    )}
                  </div>
                  <Sel value={action.type} onChange={(e: any) => updateAction(i, "type", e.target.value)}>
                    {!spec && <option value={action.type}>{action.type} (no longer supported)</option>}
                    {actionGroups.map(g => (
                      <optgroup key={g.group} label={g.group}>
                        {g.items.map((t: any) => <option key={t.type} value={t.type}>{t.label}</option>)}
                      </optgroup>
                    ))}
                  </Sel>
                  <Inp label="Delay (seconds)" type="number" placeholder="0" value={action.delay_seconds} onChange={(e: any) => updateAction(i, "delay_seconds", e.target.value)} />
                  <Txt label="Parameters (one key=value per line)" rows={3} value={action.params} onChange={(e: any) => updateAction(i, "params", e.target.value)}
                    placeholder={(spec?.required || []).map((k: string) => `${k}=`).join("\n")} style={{ fontFamily: "'JetBrains Mono', monospace" }} />
                  {spec && (
                    <div style={{ fontSize: 10, color: C.muted, lineHeight: 1.6 }}>
                      {spec.required?.length ? <>Required: {spec.required.join(", ")}. </> : null}
                      {spec.optional?.length ? <>Optional: {spec.optional.join(", ")}, stop_on_failure. </> : <>Optional: stop_on_failure. </>}
                      {spec.secrets?.length ? <>Secret (never shown again after saving; leave ******** to keep): {spec.secrets.join(", ")}. </> : null}
                      {spec.url_param ? <>{spec.url_param} must be a public https endpoint. </> : null}
                      {spec.permission ? <>Needs {spec.permission}.</> : null}
                    </div>
                  )}
                </div>
              );
            })}
            <Btn variant="ghost" small onClick={addAction}><Plus size={11} /> Add Action</Btn>
            <div style={{ marginTop: 20, display: "flex", gap: 8 }}>
              <Btn variant="default" onClick={handleSave} disabled={saving}>
                <Play size={13} /> {saving ? "Saving..." : editingId ? "Update Playbook" : "Create Playbook"}
              </Btn>
              <Btn variant="ghost" onClick={() => { setView("playbooks"); setEditingId(null); setForm(emptyForm()); }}>Cancel</Btn>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
