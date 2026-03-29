// @ts-nocheck
import { useCallback, useEffect, useState } from "react";
import {
  Play, Plus, RefreshCcw, Trash2, Edit2, CheckCircle2, XCircle,
  Zap, AlertTriangle, Shield, Clock, Activity, ChevronDown, ChevronRight,
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

async function apiGet(path: string, tenantId: string) {
  const r = await fetch(`${base}${path}`, { headers: { "X-Tenant-ID": tenantId } });
  return r.json();
}

async function apiPost(path: string, tenantId: string, body: any) {
  const r = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Tenant-ID": tenantId },
    body: JSON.stringify(body),
  });
  return r.json();
}

async function apiPut(path: string, tenantId: string, body: any) {
  const r = await fetch(`${base}${path}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Tenant-ID": tenantId },
    body: JSON.stringify(body),
  });
  return r.json();
}

async function apiDelete(path: string, tenantId: string) {
  const r = await fetch(`${base}${path}`, { method: "DELETE", headers: { "X-Tenant-ID": tenantId } });
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

const TRIGGER_TYPES = [
  { value: "canary_tripped", label: "Canary Tripped" },
  { value: "risk_score_critical", label: "Risk Score Critical" },
  { value: "compliance_drop", label: "Compliance Score Drop" },
  { value: "auth_failure_spike", label: "Auth Failure Spike" },
  { value: "key_expiry_imminent", label: "Key Expiry Imminent" },
];

const ACTION_TYPES = [
  { value: "revoke_key", label: "Revoke Key" },
  { value: "send_alert", label: "Send Alert" },
  { value: "create_audit_event", label: "Create Audit Event" },
  { value: "disable_access", label: "Disable Access" },
  { value: "notify_soc", label: "Notify SOC" },
];

const triggerColor: Record<string, string> = {
  canary_tripped: C.red,
  risk_score_critical: C.orange,
  compliance_drop: C.amber,
  auth_failure_spike: C.purple,
  key_expiry_imminent: C.blue,
};

const statusColor = (s: string) => {
  if (s === "completed") return C.green;
  if (s === "failed") return C.red;
  if (s === "running") return C.amber;
  return C.muted;
};

const TRIGGER_COVERAGE_ITEMS = TRIGGER_TYPES.map(t => t.value);

// ── main component ────────────────────────────────────────────────────────────

export function PlaybooksTab({ session }: { session: any }) {
  const tenantId = session?.tenantId || "";
  const [view, setView] = useState<"overview" | "playbooks" | "create">("overview");
  const [playbooks, setPlaybooks] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [recentRuns, setRecentRuns] = useState<any[]>([]);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [rowRuns, setRowRuns] = useState<Record<string, any[]>>({});
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);

  // create/edit form state
  const emptyForm = () => ({
    name: "",
    description: "",
    trigger_type: "canary_tripped",
    threshold: "0",
    enabled: true,
    actions: [{ type: "send_alert", delay_seconds: "0", params: "" }],
  });
  const [form, setForm] = useState(emptyForm());
  const [creating, setCreating] = useState(false);

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(""), 3500);
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [pbRes, summaryRes] = await Promise.all([
        apiGet("/playbooks", tenantId),
        apiGet("/playbooks/summary", tenantId),
      ]);
      const pbs = pbRes.data || [];
      setPlaybooks(pbs);
      setSummary(summaryRes.data || {});

      // Collect recent runs from the playbooks that have been run.
      const ran = pbs.filter((p: any) => p.run_count > 0).slice(0, 3);
      const runResults = await Promise.all(
        ran.map((p: any) => apiGet(`/playbooks/${p.id}/runs?limit=5`, tenantId))
      );
      const allRuns = runResults.flatMap((r: any) => r.data || []);
      allRuns.sort((a: any, b: any) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime());
      setRecentRuns(allRuns.slice(0, 10));
    } catch (e) {
      // ignore
    } finally {
      setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => { load(); }, [load]);

  const toggleRow = async (id: string) => {
    const next = new Set(expandedRows);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
      if (!rowRuns[id]) {
        const res = await apiGet(`/playbooks/${id}/runs?limit=10`, tenantId);
        setRowRuns(prev => ({ ...prev, [id]: res.data || [] }));
      }
    }
    setExpandedRows(next);
  };

  const handleRun = async (id: string) => {
    const res = await apiPost(`/playbooks/${id}/run`, tenantId, {});
    if (res.data) {
      showToast(`Playbook executed: ${res.data.actions_run} action(s) run. Status: ${res.data.status}`);
      // Refresh run list for this playbook.
      const runsRes = await apiGet(`/playbooks/${id}/runs?limit=10`, tenantId);
      setRowRuns(prev => ({ ...prev, [id]: runsRes.data || [] }));
      load();
    } else {
      showToast("Run failed: " + (res.message || "unknown error"));
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm("Delete this playbook?")) return;
    await apiDelete(`/playbooks/${id}`, tenantId);
    showToast("Playbook deleted.");
    load();
  };

  const handleToggleEnabled = async (pb: any) => {
    await apiPut(`/playbooks/${pb.id}`, tenantId, { ...pb, enabled: !pb.enabled });
    load();
  };

  const formToPayload = () => {
    const actions = form.actions.map((a: any) => {
      const params: Record<string, string> = {};
      if (a.params) {
        a.params.split(",").forEach((kv: string) => {
          const [k, v] = kv.split("=").map((s: string) => s.trim());
          if (k) params[k] = v || "";
        });
      }
      return { type: a.type, delay_seconds: parseInt(a.delay_seconds) || 0, parameters: params };
    });
    return {
      tenant_id: tenantId,
      name: form.name,
      description: form.description,
      trigger: { type: form.trigger_type, threshold: parseInt(form.threshold) || 0 },
      actions,
      enabled: form.enabled,
    };
  };

  const handleCreate = async () => {
    if (!form.name) { showToast("Name is required."); return; }
    setCreating(true);
    try {
      let res;
      if (editingId) {
        res = await apiPut(`/playbooks/${editingId}`, tenantId, formToPayload());
      } else {
        res = await apiPost("/playbooks", tenantId, formToPayload());
      }
      if (res.data?.id) {
        showToast(editingId ? "Playbook updated." : `Playbook "${form.name}" created.`);
        setForm(emptyForm());
        setEditingId(null);
        setView("playbooks");
        load();
      } else {
        showToast("Save failed: " + (res.message || "unknown error"));
      }
    } finally {
      setCreating(false);
    }
  };

  const handleEdit = (pb: any) => {
    setForm({
      name: pb.name,
      description: pb.description,
      trigger_type: pb.trigger?.type || "canary_tripped",
      threshold: String(pb.trigger?.threshold || 0),
      enabled: pb.enabled,
      actions: (pb.actions || []).map((a: any) => ({
        type: a.type,
        delay_seconds: String(a.delay_seconds || 0),
        params: Object.entries(a.parameters || {}).map(([k, v]) => `${k}=${v}`).join(", "),
      })),
    });
    setEditingId(pb.id);
    setView("create");
  };

  const addAction = () => setForm(p => ({ ...p, actions: [...p.actions, { type: "send_alert", delay_seconds: "0", params: "" }] }));
  const removeAction = (i: number) => setForm(p => ({ ...p, actions: p.actions.filter((_: any, idx: number) => idx !== i) }));
  const updateAction = (i: number, field: string, value: string) => setForm(p => ({
    ...p,
    actions: p.actions.map((a: any, idx: number) => idx === i ? { ...a, [field]: value } : a),
  }));

  const coveredTriggers = new Set(playbooks.map((p: any) => p.trigger?.type));

  return (
    <div style={{ padding: "24px 28px", maxWidth: 1200, margin: "0 auto" }}>
      {/* Toast */}
      {toast && (
        <div style={{ position: "fixed", bottom: 24, right: 24, background: C.card, border: `1px solid ${C.borderHi}`, borderRadius: 8, padding: "10px 16px", color: C.text, fontSize: 12, zIndex: 999, boxShadow: "0 8px 24px rgba(0,0,0,.4)" }}>
          {toast}
        </div>
      )}

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Play size={20} color={C.accent} />
          <span style={{ fontSize: 18, fontWeight: 700, color: C.text, letterSpacing: -0.4 }}>Incident Playbooks</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {(["overview", "playbooks", "create"] as const).map(v => (
            <Btn key={v} variant={view === v ? "default" : "ghost"} small onClick={() => { if (v === "create") { setForm(emptyForm()); setEditingId(null); } setView(v); }}>
              {v === "create" ? <><Plus size={12} /> New</>
               : v === "playbooks" ? <><ListChecks size={12} /> Playbooks</>
               : <><Activity size={12} /> Overview</>}
            </Btn>
          ))}
          <Btn variant="ghost" small onClick={load}><RefreshCcw size={12} /></Btn>
        </div>
      </div>

      {/* ── OVERVIEW ── */}
      {view === "overview" && (
        <>
          {/* Stat cards */}
          <div style={{ display: "flex", gap: 14, marginBottom: 24, flexWrap: "wrap" }}>
            <StatCard icon={<ListChecks size={16} />} label="Total Playbooks" value={summary?.total_playbooks ?? "—"} color={C.accent} tint={C.accentTint} />
            <StatCard icon={<CheckCircle2 size={16} />} label="Enabled" value={summary?.enabled_count ?? "—"} color={C.green} tint={C.greenTint} />
            <StatCard icon={<Zap size={16} />} label="Runs Today" value={summary?.runs_today ?? "—"} color={C.amber} tint={C.amberTint} />
            <StatCard icon={<Clock size={16} />} label="Last Run Status" value={summary?.last_run_status || "—"} color={summary?.last_run_status === "completed" ? C.green : summary?.last_run_status === "failed" ? C.red : C.muted} sublabel={summary?.last_run_at ? fmtAgo(summary.last_run_at) : undefined} />
          </div>

          {/* Execution History Table */}
          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden", marginBottom: 24 }}>
            <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 8 }}>
              <Activity size={14} color={C.accent} />
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Playbook Execution History</span>
            </div>
            {recentRuns.length === 0 ? (
              <div style={{ padding: 24, textAlign: "center", color: C.muted, fontSize: 12 }}>No playbook runs yet. Run a playbook to see history here.</div>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr><TH>Playbook ID</TH><TH>Trigger</TH><TH>Status</TH><TH>Actions Run</TH><TH>Started At</TH><TH>Duration</TH></tr></thead>
                <tbody>
                  {recentRuns.map((r: any) => (
                    <tr key={r.id}>
                      <TD mono>{r.playbook_id}</TD>
                      <TD><Badge color={triggerColor[r.trigger_event] || C.muted}>{r.trigger_event || "—"}</Badge></TD>
                      <TD><Badge color={statusColor(r.status)}>{r.status}</Badge></TD>
                      <TD>{r.actions_run}</TD>
                      <TD>{fmtDate(r.started_at)}</TD>
                      <TD>{fmtDuration(r.started_at, r.completed_at)}</TD>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Trigger Coverage */}
          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
            <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 8 }}>
              <Shield size={14} color={C.accent} />
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Trigger Coverage</span>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 12, padding: 16 }}>
              {TRIGGER_TYPES.map(t => {
                const covered = coveredTriggers.has(t.value);
                return (
                  <div key={t.value} style={{ background: covered ? C.greenDim : C.redDim, border: `1px solid ${covered ? C.green : C.red}33`, borderRadius: 8, padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 8 }}>
                    {covered
                      ? <CheckCircle2 size={14} color={C.green} />
                      : <XCircle size={14} color={C.red} />}
                    <div>
                      <div style={{ fontSize: 11, fontWeight: 600, color: C.text }}>{t.label}</div>
                      <div style={{ fontSize: 10, color: C.muted }}>{covered ? "Covered" : "No playbook"}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}

      {/* ── PLAYBOOKS VIEW ── */}
      {view === "playbooks" && (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
          <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <ListChecks size={14} color={C.accent} />
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>All Playbooks</span>
            </div>
            <Btn variant="default" small onClick={() => { setForm(emptyForm()); setEditingId(null); setView("create"); }}><Plus size={11} /> New Playbook</Btn>
          </div>
          {playbooks.length === 0 ? (
            <div style={{ padding: 32, textAlign: "center", color: C.muted, fontSize: 12 }}>No playbooks configured. Create one to automate incident response.</div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH></TH><TH>Name</TH><TH>Trigger</TH><TH>Actions</TH><TH>Enabled</TH><TH>Runs</TH><TH>Last Run</TH><TH>Actions</TH></tr></thead>
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
                      <TD><Badge color={triggerColor[pb.trigger?.type] || C.muted}>{pb.trigger?.type || "—"}</Badge></TD>
                      <TD><span style={{ color: C.dim }}>{(pb.actions || []).length} action{(pb.actions || []).length !== 1 ? "s" : ""}</span></TD>
                      <TD>
                        <button onClick={() => handleToggleEnabled(pb)} style={{ background: "none", border: "none", cursor: "pointer", color: pb.enabled ? C.green : C.muted, padding: 0, display: "inline-flex" }}>
                          {pb.enabled ? <ToggleRight size={18} /> : <ToggleLeft size={18} />}
                        </button>
                      </TD>
                      <TD>{pb.run_count}</TD>
                      <TD>{pb.last_run_at ? fmtAgo(pb.last_run_at) : "Never"}</TD>
                      <TD>
                        <div style={{ display: "flex", gap: 6 }}>
                          <Btn variant="ghost" small onClick={() => handleEdit(pb)}><Edit2 size={11} /> Edit</Btn>
                          <Btn variant="green" small onClick={() => handleRun(pb.id)} disabled={!pb.enabled}><Play size={11} /> Run</Btn>
                          <Btn variant="danger" small onClick={() => handleDelete(pb.id)}><Trash2 size={11} /></Btn>
                        </div>
                      </TD>
                    </tr>
                    {expandedRows.has(pb.id) && (
                      <tr key={pb.id + "_runs"}>
                        <td colSpan={8} style={{ padding: "0 0 0 32px", background: C.bg }}>
                          <div style={{ padding: "12px 16px" }}>
                            <div style={{ fontSize: 10, color: C.muted, fontWeight: 600, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 }}>Run History</div>
                            {(rowRuns[pb.id] || []).length === 0 ? (
                              <div style={{ fontSize: 11, color: C.muted }}>No runs recorded yet.</div>
                            ) : (
                              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                                <thead><tr><TH>Run ID</TH><TH>Trigger</TH><TH>Status</TH><TH>Actions Run</TH><TH>Started At</TH><TH>Duration</TH></tr></thead>
                                <tbody>
                                  {(rowRuns[pb.id] || []).map((r: any) => (
                                    <tr key={r.id}>
                                      <TD mono>{r.id}</TD>
                                      <TD>{r.trigger_event || "—"}</TD>
                                      <TD><Badge color={statusColor(r.status)}>{r.status}</Badge></TD>
                                      <TD>{r.actions_run}</TD>
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

      {/* ── CREATE / EDIT VIEW ── */}
      {view === "create" && (
        <div style={{ display: "flex", gap: 20, alignItems: "flex-start" }}>
          {/* Left column */}
          <div style={{ flex: 1, background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "20px 24px" }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 18 }}>
              {editingId ? "Edit Playbook" : "New Playbook"}
            </div>
            <Inp label="Name *" placeholder="e.g. Canary Trip Response" value={form.name} onChange={(e: any) => setForm(p => ({ ...p, name: e.target.value }))} />
            <Txt label="Description" placeholder="What this playbook does..." value={form.description} onChange={(e: any) => setForm(p => ({ ...p, description: e.target.value }))} rows={3} />
            <Sel label="Trigger Type" value={form.trigger_type} onChange={(e: any) => setForm(p => ({ ...p, trigger_type: e.target.value }))}>
              {TRIGGER_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
            </Sel>
            <Inp label="Threshold (for numeric triggers)" type="number" placeholder="0" value={form.threshold} onChange={(e: any) => setForm(p => ({ ...p, threshold: e.target.value }))} />
            <Chk label="Enabled" checked={form.enabled} onChange={(v: boolean) => setForm(p => ({ ...p, enabled: v }))} />
          </div>

          {/* Right column — Actions builder */}
          <div style={{ flex: 1, background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "20px 24px" }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 4 }}>Response Actions</div>
            <div style={{ fontSize: 10, color: C.muted, marginBottom: 16 }}>Actions execute in order when the trigger fires.</div>
            {form.actions.map((action: any, i: number) => (
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
                  {ACTION_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                </Sel>
                <Inp label="Delay (seconds)" type="number" placeholder="0" value={action.delay_seconds} onChange={(e: any) => updateAction(i, "delay_seconds", e.target.value)} />
                <Inp label="Parameters (key=value, comma-separated)" placeholder="key_id=abc, email=soc@co.com" value={action.params} onChange={(e: any) => updateAction(i, "params", e.target.value)} />
              </div>
            ))}
            <Btn variant="ghost" small onClick={addAction}><Plus size={11} /> Add Action</Btn>
            <div style={{ marginTop: 20, display: "flex", gap: 8 }}>
              <Btn variant="default" onClick={handleCreate} disabled={creating}>
                <Play size={13} /> {creating ? "Saving..." : editingId ? "Update Playbook" : "Create Playbook"}
              </Btn>
              <Btn variant="ghost" onClick={() => { setView("playbooks"); setEditingId(null); setForm(emptyForm()); }}>Cancel</Btn>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
