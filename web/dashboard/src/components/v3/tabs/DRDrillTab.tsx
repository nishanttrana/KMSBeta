// @ts-nocheck
import { useCallback, useEffect, useState } from "react";
import {
  ShieldCheck, Clock, Activity, XCircle, Plus, RefreshCcw, Play, Trash2,
  CheckCircle2, Loader2, X, Minus, ExternalLink, AlertTriangle
} from "lucide-react";
import {
  listSchedules, createSchedule, deleteSchedule, triggerDrill, listRuns,
  type DrillSchedule, type DrillRun, type DrillStep
} from "../../../lib/drDrill";
import { C } from "../../v3/theme";

// ── helpers ────────────────────────────────────────────────────────────────

function fmtDate(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" });
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

function fmtRTO(seconds?: number): string {
  if (!seconds) return "—";
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

const DRILL_TYPE_LABELS: Record<string, string> = {
  key_restore: "Key Restore",
  full_failover: "Full Failover",
  partial_restore: "Partial Restore",
  backup_verify: "Backup Verify",
};

// ── mock data ──────────────────────────────────────────────────────────────

const now = new Date("2025-03-25T09:00:00Z");

const MOCK_SCHEDULES: DrillSchedule[] = [
  { id: "sched-1", name: "Nightly Key Restore", cron_expr: "0 2 * * *", drill_type: "key_restore", scope: "critical_keys", target_env: "staging", enabled: true, last_run_at: "2025-03-24T02:00:00Z", next_run_at: "2025-03-25T02:00:00Z", created_at: "2025-01-01T00:00:00Z" },
  { id: "sched-2", name: "Weekly Full Failover", cron_expr: "0 4 * * 0", drill_type: "full_failover", scope: "all_keys", target_env: "dr-region-us-west", enabled: true, last_run_at: "2025-03-23T04:00:00Z", next_run_at: "2025-03-30T04:00:00Z", created_at: "2025-01-10T00:00:00Z" },
  { id: "sched-3", name: "Backup Verification", cron_expr: "0 6 * * 1", drill_type: "backup_verify", scope: "all_keys", target_env: "staging", enabled: false, last_run_at: "2025-03-17T06:00:00Z", next_run_at: "2025-03-24T06:00:00Z", created_at: "2025-02-01T00:00:00Z" },
];

const MOCK_RUNS: DrillRun[] = [
  {
    id: "run-1", schedule_id: "sched-1", schedule_name: "Nightly Key Restore", drill_type: "key_restore",
    status: "passed", started_at: "2025-03-24T02:00:00Z", completed_at: "2025-03-24T02:04:22Z",
    rto_seconds: 262, total_keys: 42, restored_keys: 42, failed_keys: 0, triggered_by: "scheduler",
    report_url: "https://reports.internal/drill/run-1",
    steps: [
      { name: "Snapshot backup catalog", status: "passed", duration_ms: 1200 },
      { name: "Initiate key restore", status: "passed", duration_ms: 5400 },
      { name: "Verify key integrity", status: "passed", duration_ms: 8200 },
      { name: "Validate encryption ops", status: "passed", duration_ms: 3100 },
    ]
  },
  {
    id: "run-2", schedule_id: "sched-2", schedule_name: "Weekly Full Failover", drill_type: "full_failover",
    status: "passed", started_at: "2025-03-23T04:00:00Z", completed_at: "2025-03-23T04:09:44Z",
    rto_seconds: 584, total_keys: 126, restored_keys: 126, failed_keys: 0, triggered_by: "scheduler",
    report_url: "https://reports.internal/drill/run-2",
    steps: []
  },
  {
    id: "run-3", schedule_id: "sched-1", schedule_name: "Nightly Key Restore", drill_type: "key_restore",
    status: "passed", started_at: "2025-03-23T02:00:00Z", completed_at: "2025-03-23T02:05:10Z",
    rto_seconds: 310, total_keys: 42, restored_keys: 42, failed_keys: 0, triggered_by: "scheduler", steps: []
  },
  {
    id: "run-4", schedule_id: "sched-1", schedule_name: "Nightly Key Restore", drill_type: "key_restore",
    status: "failed", started_at: "2025-03-20T02:00:00Z", completed_at: "2025-03-20T02:01:55Z",
    rto_seconds: undefined, total_keys: 42, restored_keys: 18, failed_keys: 24, triggered_by: "scheduler",
    steps: []
  },
  {
    id: "run-5", schedule_id: "sched-3", schedule_name: "Backup Verification", drill_type: "backup_verify",
    status: "partial", started_at: "2025-03-17T06:00:00Z", completed_at: "2025-03-17T06:03:10Z",
    rto_seconds: 190, total_keys: 80, restored_keys: 72, failed_keys: 8, triggered_by: "scheduler", steps: []
  },
  {
    id: "run-6", schedule_id: "sched-1", schedule_name: "Nightly Key Restore", drill_type: "key_restore",
    status: "passed", started_at: "2025-03-19T02:00:00Z", completed_at: "2025-03-19T02:04:55Z",
    rto_seconds: 295, total_keys: 42, restored_keys: 42, failed_keys: 0, triggered_by: "scheduler", steps: []
  },
];

const MOCK_ACTIVE_DRILL: DrillRun = {
  id: "run-live", schedule_name: "Ad-hoc Key Restore", drill_type: "key_restore",
  status: "running", started_at: new Date(Date.now() - 75000).toISOString(),
  total_keys: 42, restored_keys: 0, failed_keys: 0, triggered_by: "admin@vecta.io",
  steps: [
    { name: "Snapshot backup catalog", status: "passed", duration_ms: 1100 },
    { name: "Initiate key restore", status: "passed", duration_ms: 4800 },
    { name: "Verify key integrity", status: "running" },
    { name: "Validate encryption ops", status: "pending" },
    { name: "Cleanup restore workspace", status: "pending" },
  ]
};

// ── sub-components ──────────────────────────────────────────────────────────

function StatCard({ label, value, icon, color }: { label: string; value: string | number; icon: React.ReactNode; color: string }) {
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "18px 22px", display: "flex", alignItems: "center", gap: 16, flex: 1, minWidth: 160 }}>
      <div style={{ background: color + "22", borderRadius: 8, padding: 10, color, display: "flex" }}>{icon}</div>
      <div>
        <div style={{ color: C.text, fontSize: 24, fontWeight: 700, lineHeight: 1 }}>{value}</div>
        <div style={{ color: C.dim, fontSize: 12, marginTop: 4 }}>{label}</div>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { color: string; label: string }> = {
    passed: { color: C.green, label: "Passed" },
    failed: { color: C.red, label: "Failed" },
    partial: { color: C.amber, label: "Partial" },
    running: { color: C.accent, label: "Running" },
    aborted: { color: C.orange, label: "Aborted" },
  };
  const cfg = map[status] ?? { color: C.blue, label: status };
  return (
    <span style={{ background: cfg.color + "22", color: cfg.color, borderRadius: 5, padding: "2px 8px", fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>
      {cfg.label}
    </span>
  );
}

function StepIcon({ status }: { status: DrillStep["status"] }) {
  if (status === "passed") return <CheckCircle2 size={16} color={C.green} />;
  if (status === "running") return <Loader2 size={16} color={C.accent} style={{ animation: "spin 1s linear infinite" }} />;
  if (status === "failed") return <XCircle size={16} color={C.red} />;
  if (status === "skipped") return <Minus size={16} color={C.muted} />;
  return <Minus size={16} color={C.border} />;
}

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 12, width: 500, maxWidth: "calc(100vw - 32px)", padding: 28 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
          <span style={{ color: C.text, fontWeight: 700, fontSize: 16 }}>{title}</span>
          <button onClick={onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", padding: 4 }}><X size={18} /></button>
        </div>
        {children}
      </div>
    </div>
  );
}

function FormField({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{ color: C.dim, fontSize: 12, fontWeight: 600, display: "block", marginBottom: 6 }}>{label}</label>
      {children}
      {hint && <div style={{ color: C.muted, fontSize: 11, marginTop: 4 }}>{hint}</div>}
    </div>
  );
}

const inputStyle: React.CSSProperties = { background: C.card, border: `1px solid ${C.border}`, borderRadius: 7, color: C.text, padding: "9px 12px", fontSize: 13, width: "100%", boxSizing: "border-box", outline: "none" };
const btnPrimary: React.CSSProperties = { background: C.accent, color: C.bg, border: "none", borderRadius: 7, padding: "9px 20px", fontWeight: 700, fontSize: 13, cursor: "pointer" };
const btnSecondary: React.CSSProperties = { background: C.card, color: C.dim, border: `1px solid ${C.border}`, borderRadius: 7, padding: "9px 20px", fontWeight: 600, fontSize: 13, cursor: "pointer" };
const btnSmall: React.CSSProperties = { background: C.card, color: C.dim, border: `1px solid ${C.border}`, borderRadius: 6, padding: "5px 10px", fontSize: 12, fontWeight: 600, cursor: "pointer" };
const btnDanger: React.CSSProperties = { ...btnSmall, color: C.red, borderColor: C.red + "44" };

// ── Main Component ──────────────────────────────────────────────────────────

export function DRDrillTab({ session }: { session: any; enabledFeatures?: any; keyCatalog?: any[] }) {
  const [schedules, setSchedules] = useState<DrillSchedule[]>([]);
  const [runs, setRuns] = useState<DrillRun[]>([]);
  const [activeDrill, setActiveDrill] = useState<DrillRun | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState<"schedules" | "history" | "active">("schedules");
  const [showCreate, setShowCreate] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState({ name: "", drill_type: "key_restore", cron_expr: "", scope: "all_keys", target_env: "" });

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [s, r] = await Promise.all([listSchedules(session), listRuns(session)]);
      setSchedules(s); setRuns(r);
      setActiveDrill(r.find(x => x.status === "running") ?? null);
    } catch {
      setSchedules(MOCK_SCHEDULES); setRuns(MOCK_RUNS); setActiveDrill(MOCK_ACTIVE_DRILL);
      setError("Live data unavailable — showing mock data.");
    } finally { setLoading(false); }
  }, [session]);

  useEffect(() => { load(); }, [load]);

  const handleRunNow = async (scheduleId: string, type: string) => {
    try {
      const run = await triggerDrill(session, scheduleId, type);
      setActiveDrill(run); setSection("active");
    } catch { setActiveDrill(MOCK_ACTIVE_DRILL); setSection("active"); }
  };

  const handleDelete = async (id: string) => {
    try { await deleteSchedule(session, id); }
    catch { /* mock */ }
    finally { await load(); }
  };

  const handleCreate = async () => {
    if (!form.name.trim() || !form.cron_expr.trim()) return;
    setSaving(true);
    try { await createSchedule(session, { ...form, drill_type: form.drill_type as DrillSchedule["drill_type"], scope: form.scope as DrillSchedule["scope"], enabled: true }); }
    catch { /* mock */ }
    finally { setSaving(false); setShowCreate(false); setForm({ name: "", drill_type: "key_restore", cron_expr: "", scope: "all_keys", target_env: "" }); await load(); }
  };

  const completedRuns = runs.filter(r => r.status !== "running");
  const passRate = completedRuns.length > 0 ? Math.round((completedRuns.filter(r => r.status === "passed").length / completedRuns.length) * 100) : 0;
  const avgRTO = completedRuns.filter(r => r.rto_seconds).reduce((acc, r) => acc + (r.rto_seconds ?? 0), 0) / Math.max(1, completedRuns.filter(r => r.rto_seconds).length);
  const lastFailure = [...runs].filter(r => r.status === "failed").sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime())[0];

  const sectionTabs: { key: "schedules" | "history" | "active"; label: string; highlight?: boolean }[] = [
    { key: "schedules", label: "Drill Schedules" },
    { key: "history", label: "Run History" },
    { key: "active", label: "Active Drill", highlight: !!activeDrill },
  ];

  const activeStepsPassed = activeDrill?.steps.filter(s => s.status === "passed").length ?? 0;
  const activeTotalSteps = activeDrill?.steps.length ?? 0;
  const activeProgress = activeTotalSteps > 0 ? Math.round((activeStepsPassed / activeTotalSteps) * 100) : 0;

  return (
    <div style={{ padding: "24px 28px", fontFamily: "system-ui, sans-serif", color: C.text, minHeight: "100vh", background: C.bg }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ background: C.greenDim, borderRadius: 8, padding: 8, color: C.green, display: "flex" }}><ShieldCheck size={22} /></div>
          <div>
            <div style={{ fontSize: 20, fontWeight: 700 }}>DR Drill Automation</div>
            <div style={{ color: C.dim, fontSize: 13 }}>Automated disaster recovery drills and key restore validation</div>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button onClick={() => setShowCreate(true)} style={{ ...btnPrimary, display: "flex", alignItems: "center", gap: 6 }}><Plus size={14} /> Create Schedule</button>
          <button onClick={load} style={{ ...btnSecondary, padding: "9px 10px" }}><RefreshCcw size={14} /></button>
        </div>
      </div>

      {error && <div style={{ background: C.amberDim, border: `1px solid ${C.amber}44`, borderRadius: 8, padding: "10px 16px", color: C.amber, fontSize: 13, marginBottom: 18 }}><AlertTriangle size={14} style={{ display: "inline", marginRight: 6 }} />{error}</div>}

      {/* Stat Cards */}
      <div style={{ display: "flex", gap: 14, marginBottom: 24, flexWrap: "wrap" }}>
        <StatCard label="Total Drills Run" value={loading ? "—" : runs.length} icon={<Activity size={18} />} color={C.blue} />
        <StatCard label="Pass Rate" value={loading ? "—" : `${passRate}%`} icon={<CheckCircle2 size={18} />} color={C.green} />
        <StatCard label="Average RTO" value={loading ? "—" : fmtRTO(Math.round(avgRTO))} icon={<Clock size={18} />} color={C.accent} />
        <StatCard label="Last Failure" value={loading ? "—" : fmtAgo(lastFailure?.started_at)} icon={<XCircle size={18} />} color={C.red} />
      </div>

      {/* Section Tabs */}
      <div style={{ display: "flex", gap: 4, borderBottom: `1px solid ${C.border}`, marginBottom: 20 }}>
        {sectionTabs.map(t => (
          <button key={t.key} onClick={() => setSection(t.key)} style={{ background: "none", border: "none", borderBottom: section === t.key ? `2px solid ${C.accent}` : "2px solid transparent", color: section === t.key ? C.accent : C.dim, padding: "10px 18px", fontSize: 13, fontWeight: 600, cursor: "pointer", marginBottom: -1, display: "flex", alignItems: "center", gap: 6 }}>
            {t.label}
            {t.highlight && <span style={{ width: 7, height: 7, borderRadius: "50%", background: C.green, display: "inline-block", animation: "pulse 1.5s ease-in-out infinite" }} />}
          </button>
        ))}
      </div>

      {loading ? (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 60, color: C.dim, gap: 10 }}><Loader2 size={20} style={{ animation: "spin 1s linear infinite" }} /> Loading...</div>
      ) : (
        <>
          {/* Schedules */}
          {section === "schedules" && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                    {["Name", "Type", "Cron", "Scope", "Target Env", "Enabled", "Last Run", "Next Run", "Actions"].map(h => (
                      <th key={h} style={{ padding: "11px 14px", textAlign: "left", color: C.dim, fontWeight: 600, fontSize: 12, whiteSpace: "nowrap" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {schedules.map(s => (
                    <tr key={s.id} style={{ borderBottom: `1px solid ${C.border}22` }}>
                      <td style={{ padding: "11px 14px", fontWeight: 600 }}>{s.name}</td>
                      <td style={{ padding: "11px 14px", color: C.dim }}>{DRILL_TYPE_LABELS[s.drill_type] ?? s.drill_type}</td>
                      <td style={{ padding: "11px 14px" }}><code style={{ background: C.surface, color: C.accent, borderRadius: 4, padding: "2px 6px", fontSize: 11 }}>{s.cron_expr}</code></td>
                      <td style={{ padding: "11px 14px", color: C.dim, textTransform: "capitalize" }}>{s.scope.replace("_", " ")}</td>
                      <td style={{ padding: "11px 14px", color: C.dim }}>{s.target_env}</td>
                      <td style={{ padding: "11px 14px" }}>
                        <span style={{ background: s.enabled ? C.greenDim : C.border + "44", color: s.enabled ? C.green : C.muted, borderRadius: 5, padding: "2px 8px", fontSize: 11, fontWeight: 600 }}>{s.enabled ? "Enabled" : "Disabled"}</span>
                      </td>
                      <td style={{ padding: "11px 14px", color: C.muted }}>{fmtAgo(s.last_run_at)}</td>
                      <td style={{ padding: "11px 14px", color: C.muted }}>{fmtDate(s.next_run_at)}</td>
                      <td style={{ padding: "11px 14px" }}>
                        <div style={{ display: "flex", gap: 6 }}>
                          <button onClick={() => handleRunNow(s.id, s.drill_type)} style={{ ...btnSmall, display: "flex", alignItems: "center", gap: 4 }}><Play size={11} /> Run Now</button>
                          <button onClick={() => handleDelete(s.id)} style={{ ...btnDanger, display: "flex", alignItems: "center", gap: 4 }}><Trash2 size={11} /></button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* History */}
          {section === "history" && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                    {["Schedule", "Type", "Started", "Duration", "Status", "Keys Restored", "RTO", "Triggered By", ""].map(h => (
                      <th key={h} style={{ padding: "11px 14px", textAlign: "left", color: C.dim, fontWeight: 600, fontSize: 12, whiteSpace: "nowrap" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {[...runs].sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime()).map(r => (
                    <tr key={r.id} style={{ borderBottom: `1px solid ${C.border}22` }}>
                      <td style={{ padding: "11px 14px", fontWeight: 600 }}>{r.schedule_name ?? "—"}</td>
                      <td style={{ padding: "11px 14px", color: C.dim }}>{DRILL_TYPE_LABELS[r.drill_type] ?? r.drill_type}</td>
                      <td style={{ padding: "11px 14px", color: C.muted }}>{fmtAgo(r.started_at)}</td>
                      <td style={{ padding: "11px 14px", color: C.dim }}>{fmtDuration(r.started_at, r.completed_at)}</td>
                      <td style={{ padding: "11px 14px" }}><StatusBadge status={r.status} /></td>
                      <td style={{ padding: "11px 14px" }}>
                        <span style={{ color: r.failed_keys > 0 ? C.red : C.green }}>{r.restored_keys}</span>
                        <span style={{ color: C.muted }}>/{r.total_keys}</span>
                      </td>
                      <td style={{ padding: "11px 14px", color: C.dim }}>{fmtRTO(r.rto_seconds)}</td>
                      <td style={{ padding: "11px 14px", color: C.muted }}>{r.triggered_by}</td>
                      <td style={{ padding: "11px 14px" }}>
                        {r.report_url && (
                          <a href={r.report_url} target="_blank" rel="noreferrer" style={{ color: C.accent, display: "flex", alignItems: "center", gap: 4, fontSize: 12, textDecoration: "none" }}><ExternalLink size={12} /> Report</a>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Active Drill */}
          {section === "active" && (
            activeDrill ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                <div style={{ background: C.card, border: `1px solid ${C.accent}44`, borderRadius: 10, padding: 20 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
                    <Loader2 size={18} color={C.accent} style={{ animation: "spin 1s linear infinite" }} />
                    <span style={{ fontWeight: 700, fontSize: 15 }}>{activeDrill.schedule_name ?? "Active Drill"}</span>
                    <StatusBadge status={activeDrill.status} />
                    <span style={{ color: C.muted, fontSize: 12, marginLeft: "auto" }}>Started {fmtAgo(activeDrill.started_at)} · Triggered by {activeDrill.triggered_by}</span>
                  </div>
                  <div style={{ marginBottom: 16 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                      <span style={{ color: C.dim, fontSize: 12 }}>Progress</span>
                      <span style={{ color: C.accent, fontSize: 12, fontWeight: 700 }}>{activeProgress}%</span>
                    </div>
                    <div style={{ background: C.border, borderRadius: 4, height: 8 }}>
                      <div style={{ width: `${activeProgress}%`, height: "100%", borderRadius: 4, background: C.accent, transition: "width 0.4s ease" }} />
                    </div>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    {activeDrill.steps.map((step, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 14px", background: C.surface, borderRadius: 8, border: `1px solid ${step.status === "running" ? C.accent + "44" : C.border + "44"}` }}>
                        <StepIcon status={step.status} />
                        <span style={{ flex: 1, fontSize: 13, color: step.status === "pending" ? C.muted : C.text }}>{step.name}</span>
                        {step.duration_ms && <span style={{ color: C.muted, fontSize: 12 }}>{step.duration_ms}ms</span>}
                        {step.message && <span style={{ color: C.dim, fontSize: 12, fontStyle: "italic" }}>{step.message}</span>}
                        <span style={{ fontSize: 11, color: step.status === "passed" ? C.green : step.status === "running" ? C.accent : step.status === "failed" ? C.red : C.muted, textTransform: "uppercase", fontWeight: 600 }}>{step.status}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 60, color: C.dim, gap: 12 }}>
                <ShieldCheck size={32} color={C.border} />
                <span style={{ fontSize: 14 }}>No drill currently running.</span>
                <button onClick={() => setSection("schedules")} style={btnSecondary}>View Schedules</button>
              </div>
            )
          )}
        </>
      )}

      {/* Create Schedule Modal */}
      {showCreate && (
        <Modal title="Create Drill Schedule" onClose={() => setShowCreate(false)}>
          <FormField label="Schedule Name">
            <input style={inputStyle} value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Nightly Critical Key Restore" />
          </FormField>
          <FormField label="Drill Type">
            <select style={inputStyle} value={form.drill_type} onChange={e => setForm(f => ({ ...f, drill_type: e.target.value }))}>
              <option value="key_restore">Key Restore</option>
              <option value="full_failover">Full Failover</option>
              <option value="partial_restore">Partial Restore</option>
              <option value="backup_verify">Backup Verify</option>
            </select>
          </FormField>
          <FormField label="Cron Expression" hint='e.g. "0 2 * * *" = daily at 2am UTC'>
            <input style={inputStyle} value={form.cron_expr} onChange={e => setForm(f => ({ ...f, cron_expr: e.target.value }))} placeholder="0 2 * * *" />
          </FormField>
          <FormField label="Scope">
            <select style={inputStyle} value={form.scope} onChange={e => setForm(f => ({ ...f, scope: e.target.value }))}>
              <option value="all_keys">All Keys</option>
              <option value="critical_keys">Critical Keys</option>
            </select>
          </FormField>
          <FormField label="Target Environment">
            <input style={inputStyle} value={form.target_env} onChange={e => setForm(f => ({ ...f, target_env: e.target.value }))} placeholder="e.g. staging, dr-us-west" />
          </FormField>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", marginTop: 8 }}>
            <button style={btnSecondary} onClick={() => setShowCreate(false)}>Cancel</button>
            <button style={btnPrimary} onClick={handleCreate} disabled={saving || !form.name.trim() || !form.cron_expr.trim()}>
              {saving ? "Creating…" : "Create Schedule"}
            </button>
          </div>
        </Modal>
      )}

      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } } @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.4; } }`}</style>
    </div>
  );
}
