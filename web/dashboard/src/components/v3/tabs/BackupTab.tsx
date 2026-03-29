// @ts-nocheck
import { useCallback, useEffect, useState } from "react";
import {
  Archive, CalendarClock, CheckCircle2, Clock, Database,
  HardDrive, Play, Plus, RefreshCw, RotateCcw, Server,
  ShieldCheck, Trash2, AlertTriangle, Download
} from "lucide-react";
import { C } from "../../v3/theme";
import {
  listPolicies, createPolicy, deletePolicy, triggerBackup,
  listRuns, listRestorePoints, restoreFromPoint, getMetrics,
  type BackupPolicy, type BackupRun, type RestorePoint, type BackupMetrics
} from "../../../lib/backup";


function fmtBytes(b: number): string {
  if (b > 1e9) return (b / 1e9).toFixed(1) + " GB";
  if (b > 1e6) return (b / 1e6).toFixed(1) + " MB";
  if (b > 1e3) return (b / 1e3).toFixed(1) + " KB";
  return b + " B";
}

function fmtDuration(start: string, end?: string): string {
  const ms = new Date(end || Date.now()).getTime() - new Date(start).getTime();
  if (ms < 60000) return `${(ms / 1000).toFixed(0)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

function fmtDate(iso?: string): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

const CELL: React.CSSProperties = { padding: "9px 12px", color: C.dim, fontSize: 12, verticalAlign: "middle" };
const TH: React.CSSProperties = { padding: "7px 12px", fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: "0.08em", textAlign: "left" };

const statusColor = (s: string) => s === "completed" ? C.green : s === "running" ? C.accent : s === "failed" ? C.red : C.amber;
const destIcon = (d: string) => d === "s3" ? "S3" : d === "gcs" ? "GCS" : d === "azure_blob" ? "AZ" : "FS";

export function BackupTab({ session }: { session: any }) {
  const [section, setSection] = useState<"policies" | "runs" | "restore">("policies");
  const [policies, setPolicies] = useState<BackupPolicy[]>([]);
  const [runs, setRuns] = useState<BackupRun[]>([]);
  const [points, setPoints] = useState<RestorePoint[]>([]);
  const [metrics, setMetrics] = useState<BackupMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [triggering, setTriggering] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", description: "", scope: "all_keys", tag_filter: "", cron_expr: "0 1 * * *", retention_days: 90, encrypt_backup: true, compress: true, destination: "local", destination_uri: "" });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [p, r, rp, m] = await Promise.all([
        listPolicies(session),
        listRuns(session),
        listRestorePoints(session),
        getMetrics(session),
      ]);
      setPolicies(p); setRuns(r); setPoints(rp); setMetrics(m);
    } catch { /* leave state as-is, loading=false will show empty tables */ }
    setLoading(false);
  }, [session]);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    setCreating(true);
    try {
      const p = await createPolicy(session, form as any);
      setPolicies(prev => [...prev, p]);
      setShowCreate(false);
      setForm({ name: "", description: "", scope: "all_keys", tag_filter: "", cron_expr: "0 1 * * *", retention_days: 90, encrypt_backup: true, compress: true, destination: "local", destination_uri: "" });
    } catch { /* show nothing — load() will refresh on next open */ }
    finally { setCreating(false); }
  };

  const handleTrigger = async (policyId: string) => {
    setTriggering(policyId);
    try {
      await triggerBackup(session, policyId);
      await load();
    } catch { await load(); }
    finally { setTriggering(null); }
  };

  const handleRestore = async (pointId: string) => {
    if (!confirm("Restore from this point? Existing keys with matching IDs will be overwritten.")) return;
    try { await restoreFromPoint(session, pointId); } catch { /* ignore */ }
    await load();
  };

  const m = metrics ?? {} as BackupMetrics;

  const statCard = (icon: React.ReactNode, label: string, value: string, sub?: string, color?: string) => (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "14px 16px", flex: 1, display: "flex", gap: 12, alignItems: "flex-start" }}>
      <div style={{ color: color || C.accent, marginTop: 2 }}>{icon}</div>
      <div>
        <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>{label}</div>
        <div style={{ fontSize: 20, fontWeight: 700, color: color || C.text }}>{value}</div>
        {sub && <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>{sub}</div>}
      </div>
    </div>
  );

  return (
    <div style={{ padding: 24, fontFamily: '"IBM Plex Sans", sans-serif', color: C.text, minHeight: "100%" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            <Archive size={18} color={C.accent} />
            <span style={{ fontSize: 16, fontWeight: 700 }}>Backup & Restore</span>
          </div>
          <div style={{ fontSize: 12, color: C.muted }}>Automated key backup policies, run history, and restore points</div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={load} style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 6, padding: "6px 12px", color: C.muted, cursor: "pointer", display: "flex", alignItems: "center", gap: 4, fontSize: 12 }}>
            <RefreshCw size={12} /> Refresh
          </button>
          {section === "policies" && (
            <button onClick={() => setShowCreate(true)} style={{ background: C.accent, border: "none", borderRadius: 6, padding: "6px 14px", color: "#000", cursor: "pointer", display: "flex", alignItems: "center", gap: 4, fontSize: 12, fontWeight: 600 }}>
              <Plus size={13} /> New Policy
            </button>
          )}
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: "flex", gap: 12, marginBottom: 20 }}>
        {statCard(<ShieldCheck size={18} />, "Success Rate (30d)", loading ? "—" : `${(m.success_rate_30d ?? 0).toFixed(1)}%`, "backup reliability", (m.success_rate_30d ?? 0) > 95 ? C.green : C.amber)}
        {statCard(<HardDrive size={18} />, "Total Backup Size", loading ? "—" : fmtBytes(m.total_backup_size_bytes ?? 0), `${m.total_restore_points ?? 0} restore points`)}
        {statCard(<Clock size={18} />, "Avg Duration", loading ? "—" : `${m.avg_backup_duration_seconds ?? 0}s`, "per backup run")}
        {statCard(<CheckCircle2 size={18} />, "Last Backup", loading ? "—" : (m.last_backup_at ? fmtDate(m.last_backup_at).split(",")[0] : "Never"), m.last_backup_status ?? "—", m.last_backup_status === "completed" ? C.green : C.red)}
      </div>

      {/* Section Tabs */}
      <div style={{ display: "flex", gap: 2, marginBottom: 16, borderBottom: `1px solid ${C.border}` }}>
        {[{ id: "policies", label: "Backup Policies" }, { id: "runs", label: "Run History" }, { id: "restore", label: "Restore Points" }].map(s => (
          <button key={s.id} onClick={() => setSection(s.id as any)} style={{
            padding: "8px 16px", border: "none", background: "transparent", cursor: "pointer",
            fontSize: 12, fontWeight: section === s.id ? 700 : 400,
            color: section === s.id ? C.accent : C.muted,
            borderBottom: section === s.id ? `2px solid ${C.accent}` : "2px solid transparent",
            marginBottom: -1,
          }}>{s.label}</button>
        ))}
      </div>

      {/* Policies */}
      {section === "policies" && (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
          {loading ? <div style={{ padding: 32, textAlign: "center", color: C.muted }}>Loading...</div> : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  {["Policy Name", "Scope", "Schedule", "Retention", "Destination", "Status", "Last Run", "Actions"].map(h => <th key={h} style={TH}>{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {policies.map(p => (
                  <tr key={p.id} style={{ borderBottom: `1px solid ${C.border}22` }}>
                    <td style={{ ...CELL, color: C.text, fontWeight: 600 }}>
                      {p.name}
                      {p.description && <div style={{ fontSize: 10, color: C.muted, marginTop: 1 }}>{p.description}</div>}
                    </td>
                    <td style={CELL}>
                      <span style={{ padding: "2px 7px", borderRadius: 4, background: C.accentDim, color: C.accent, fontSize: 10, fontWeight: 600 }}>
                        {p.scope === "tagged" ? `tag:${p.tag_filter}` : p.scope.replace("_", " ")}
                      </span>
                    </td>
                    <td style={{ ...CELL, fontFamily: "monospace", fontSize: 11 }}>{p.cron_expr}</td>
                    <td style={CELL}>{p.retention_days}d</td>
                    <td style={CELL}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <span style={{ padding: "2px 6px", borderRadius: 4, background: C.dimTint, color: C.dim, fontSize: 10, fontWeight: 700 }}>{destIcon(p.destination)}</span>
                        <span style={{ fontSize: 10, color: C.muted, maxWidth: 100, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.destination_uri || p.destination}</span>
                      </div>
                    </td>
                    <td style={CELL}>
                      <span style={{ padding: "2px 7px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: p.enabled ? C.greenDim : C.redDim, color: p.enabled ? C.green : C.red }}>
                        {p.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </td>
                    <td style={{ ...CELL, fontSize: 11 }}>{p.last_run_at ? fmtDate(p.last_run_at) : "Never"}</td>
                    <td style={CELL}>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button onClick={() => handleTrigger(p.id)} disabled={triggering === p.id} style={{ padding: "4px 8px", borderRadius: 4, border: `1px solid ${C.border}`, background: "transparent", color: C.accent, cursor: "pointer", display: "flex", alignItems: "center", gap: 3, fontSize: 11 }}>
                          <Play size={10} />{triggering === p.id ? "Running..." : "Run"}
                        </button>
                        <button onClick={() => deletePolicy(session, p.id).then(load)} style={{ padding: "4px 6px", borderRadius: 4, border: `1px solid ${C.border}`, background: "transparent", color: C.red, cursor: "pointer" }}>
                          <Trash2 size={11} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {policies.length === 0 && <tr><td colSpan={8} style={{ ...CELL, textAlign: "center", color: C.muted, padding: 32 }}>No backup policies configured. Create one to get started.</td></tr>}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Run History */}
      {section === "runs" && (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
          {loading ? <div style={{ padding: 32, textAlign: "center", color: C.muted }}>Loading...</div> : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  {["Policy", "Status", "Keys", "Size", "Destination", "Duration", "Started", "Triggered By"].map(h => <th key={h} style={TH}>{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {runs.map(r => (
                  <tr key={r.id} style={{ borderBottom: `1px solid ${C.border}22`, background: r.status === "running" ? C.accentTint : "transparent" }}>
                    <td style={{ ...CELL, color: C.text, fontWeight: 600 }}>{r.policy_name || <span style={{ color: C.muted }}>Manual</span>}</td>
                    <td style={CELL}>
                      <span style={{ padding: "2px 7px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: statusColor(r.status) + "22", color: statusColor(r.status) }}>
                        {r.status === "running" ? `Running (${Math.round(r.backed_up_keys / Math.max(r.total_keys, 1) * 100)}%)` : r.status}
                      </span>
                    </td>
                    <td style={{ ...CELL, fontFamily: "monospace" }}>{r.backed_up_keys}/{r.total_keys}</td>
                    <td style={CELL}>{fmtBytes(r.backup_size_bytes)}</td>
                    <td style={{ ...CELL, fontSize: 10, color: C.muted, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.destination_path || r.destination}</td>
                    <td style={CELL}>{r.completed_at ? fmtDuration(r.started_at, r.completed_at) : "In progress…"}</td>
                    <td style={{ ...CELL, fontSize: 11 }}>{fmtDate(r.started_at)}</td>
                    <td style={CELL}>
                      <span style={{ padding: "2px 7px", borderRadius: 4, background: C.dimTint, color: C.dim, fontSize: 10, fontWeight: 600 }}>{r.triggered_by}</span>
                    </td>
                  </tr>
                ))}
                {runs.length === 0 && <tr><td colSpan={8} style={{ ...CELL, textAlign: "center", color: C.muted, padding: 32 }}>No backup runs yet.</td></tr>}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Restore Points */}
      {section === "restore" && (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
          {loading ? <div style={{ padding: 32, textAlign: "center", color: C.muted }}>Loading...</div> : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  {["Name", "Keys", "Size", "Checksum", "Created", "Expires", "Status", "Action"].map(h => <th key={h} style={TH}>{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {points.map(p => (
                  <tr key={p.id} style={{ borderBottom: `1px solid ${C.border}22` }}>
                    <td style={{ ...CELL, color: C.text, fontWeight: 600 }}>{p.name}</td>
                    <td style={{ ...CELL, fontFamily: "monospace" }}>{p.key_count.toLocaleString()}</td>
                    <td style={CELL}>{fmtBytes(p.backup_size_bytes)}</td>
                    <td style={{ ...CELL, fontFamily: "monospace", fontSize: 10, color: C.muted, maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {p.checksum.replace("sha256:", "").slice(0, 16)}…
                    </td>
                    <td style={{ ...CELL, fontSize: 11 }}>{fmtDate(p.created_at)}</td>
                    <td style={{ ...CELL, fontSize: 11, color: p.expires_at && new Date(p.expires_at) < new Date() ? C.red : C.dim }}>
                      {p.expires_at ? fmtDate(p.expires_at) : "Never"}
                    </td>
                    <td style={CELL}>
                      <span style={{ padding: "2px 7px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: p.status === "available" ? C.greenDim : C.amberDim, color: p.status === "available" ? C.green : C.amber }}>
                        {p.status}
                      </span>
                    </td>
                    <td style={CELL}>
                      <button onClick={() => handleRestore(p.id)} disabled={p.status !== "available"} style={{ padding: "4px 10px", borderRadius: 4, border: `1px solid ${C.border}`, background: "transparent", color: p.status === "available" ? C.accent : C.muted, cursor: p.status === "available" ? "pointer" : "not-allowed", display: "flex", alignItems: "center", gap: 3, fontSize: 11 }}>
                        <RotateCcw size={10} /> Restore
                      </button>
                    </td>
                  </tr>
                ))}
                {points.length === 0 && <tr><td colSpan={8} style={{ ...CELL, textAlign: "center", color: C.muted, padding: 32 }}>No restore points available.</td></tr>}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Create Policy Modal */}
      {showCreate && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 24, width: 480, maxHeight: "80vh", overflowY: "auto" }}>
            <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 16 }}>Create Backup Policy</div>
            {[
              { label: "Name", key: "name", type: "text", placeholder: "Daily Full Backup" },
              { label: "Description", key: "description", type: "text", placeholder: "Optional description" },
              { label: "Cron Expression", key: "cron_expr", type: "text", placeholder: "0 1 * * *" },
              { label: "Retention Days", key: "retention_days", type: "number", placeholder: "90" },
              { label: "Destination URI", key: "destination_uri", type: "text", placeholder: "/var/backup/kms or s3://bucket/prefix" },
            ].map(f => (
              <div key={f.key} style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 11, color: C.muted, marginBottom: 4 }}>{f.label}</div>
                <input type={f.type} value={form[f.key]} onChange={e => setForm(p => ({ ...p, [f.key]: f.type === "number" ? +e.target.value : e.target.value }))}
                  placeholder={f.placeholder}
                  style={{ width: "100%", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, boxSizing: "border-box" }} />
              </div>
            ))}
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.muted, marginBottom: 4 }}>Scope</div>
              <select value={form.scope} onChange={e => setForm(p => ({ ...p, scope: e.target.value }))} style={{ width: "100%", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12 }}>
                <option value="all_keys">All Keys</option>
                <option value="critical_keys">Critical Keys</option>
                <option value="tagged">Tagged (specify filter)</option>
              </select>
            </div>
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.muted, marginBottom: 4 }}>Destination</div>
              <select value={form.destination} onChange={e => setForm(p => ({ ...p, destination: e.target.value }))} style={{ width: "100%", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12 }}>
                <option value="local">Local Filesystem</option>
                <option value="s3">Amazon S3</option>
                <option value="gcs">Google Cloud Storage</option>
                <option value="azure_blob">Azure Blob Storage</option>
              </select>
            </div>
            <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
              {[{ key: "encrypt_backup", label: "Encrypt" }, { key: "compress", label: "Compress" }].map(f => (
                <label key={f.key} style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", fontSize: 12, color: C.dim }}>
                  <input type="checkbox" checked={form[f.key]} onChange={e => setForm(p => ({ ...p, [f.key]: e.target.checked }))} />
                  {f.label}
                </label>
              ))}
            </div>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button onClick={() => setShowCreate(false)} style={{ padding: "7px 16px", borderRadius: 6, border: `1px solid ${C.border}`, background: "transparent", color: C.dim, cursor: "pointer", fontSize: 12 }}>Cancel</button>
              <button onClick={handleCreate} disabled={creating || !form.name} style={{ padding: "7px 16px", borderRadius: 6, border: "none", background: C.accent, color: "#000", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>
                {creating ? "Creating…" : "Create Policy"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
