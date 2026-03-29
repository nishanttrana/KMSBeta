// @ts-nocheck
import { useCallback, useEffect, useState } from "react";
import {
  Key, Layers, RefreshCcw, Plus, ChevronDown, ChevronRight,
  RotateCcw, ArrowRightLeft, CheckCircle, AlertTriangle, Archive,
  X, Loader2
} from "lucide-react";
import {
  listKEKs, createKEK, rotateKEK, listDEKs, getHierarchy,
  startRewrap, listRewrapJobs,
  type KEK, type DEK, type EnvelopeHierarchyNode, type RewrapJob
} from "../../../lib/envelopeEnc";
import { C } from "../../v3/theme";

// ── helpers ────────────────────────────────────────────────────────────────

function fmtDate(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function fmtAgo(iso?: string): string {
  if (!iso) return "—";
  const diff = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

const purposeLabel: Record<string, string> = {
  field_encryption: "Field Encryption",
  file_encryption: "File Encryption",
  db_encryption: "DB Encryption",
};

// ── mock data ──────────────────────────────────────────────────────────────

const MOCK_KEKS: KEK[] = [
  { id: "kek-1", name: "prod-master-kek", algorithm: "AES-256-GCM", version: 3, status: "active", dek_count: 14, created_at: "2024-09-01T00:00:00Z", last_rotated_at: "2025-02-10T00:00:00Z" },
  { id: "kek-2", name: "archive-kek", algorithm: "AES-256-GCM", version: 1, status: "active", dek_count: 7, created_at: "2024-06-15T00:00:00Z" },
  { id: "kek-3", name: "legacy-kek-v1", algorithm: "AES-128-GCM", version: 1, status: "retired", dek_count: 4, created_at: "2023-01-01T00:00:00Z" },
];

const MOCK_DEKS: DEK[] = [
  { id: "dek-1", kek_id: "kek-1", kek_name: "prod-master-kek", name: "users-pii-dek", wrapped_key_b64: "", algorithm: "AES-256-GCM", purpose: "field_encryption", owner_service: "user-service", created_at: "2024-09-05T00:00:00Z", last_used_at: "2025-03-20T10:00:00Z", status: "active" },
  { id: "dek-2", kek_id: "kek-1", kek_name: "prod-master-kek", name: "payments-dek", wrapped_key_b64: "", algorithm: "AES-256-GCM", purpose: "db_encryption", owner_service: "payment-service", created_at: "2024-10-01T00:00:00Z", last_used_at: "2025-03-24T08:00:00Z", status: "active" },
  { id: "dek-3", kek_id: "kek-2", kek_name: "archive-kek", name: "docs-archive-dek", wrapped_key_b64: "", algorithm: "AES-256-GCM", purpose: "file_encryption", owner_service: "storage-service", created_at: "2024-06-20T00:00:00Z", last_used_at: "2025-01-10T00:00:00Z", status: "needs_rewrap" },
  { id: "dek-4", kek_id: "kek-3", kek_name: "legacy-kek-v1", name: "old-logs-dek", wrapped_key_b64: "", algorithm: "AES-128-GCM", purpose: "file_encryption", owner_service: "log-service", created_at: "2023-02-01T00:00:00Z", last_used_at: "2024-06-01T00:00:00Z", status: "needs_rewrap" },
  { id: "dek-5", kek_id: "kek-1", kek_name: "prod-master-kek", name: "session-dek", wrapped_key_b64: "", algorithm: "AES-256-GCM", purpose: "field_encryption", owner_service: "auth-service", created_at: "2024-11-01T00:00:00Z", last_used_at: "2025-03-25T00:00:00Z", status: "active" },
];

const MOCK_HIERARCHY: EnvelopeHierarchyNode[] = MOCK_KEKS.map(k => ({
  kek_id: k.id, kek_name: k.name, kek_algorithm: k.algorithm, kek_status: k.status,
  deks: MOCK_DEKS.filter(d => d.kek_id === k.id).map(d => ({ id: d.id, name: d.name, algorithm: d.algorithm, status: d.status, owner_service: d.owner_service })),
}));

const MOCK_JOBS: RewrapJob[] = [
  { id: "job-1", old_kek_id: "kek-3", new_kek_id: "kek-1", total_deks: 4, processed_deks: 4, status: "completed", started_at: "2025-03-10T09:00:00Z", completed_at: "2025-03-10T09:05:00Z" },
  { id: "job-2", old_kek_id: "kek-2", new_kek_id: "kek-1", total_deks: 7, processed_deks: 3, status: "running", started_at: "2025-03-25T07:00:00Z" },
];

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
    active: { color: C.green, label: "Active" },
    needs_rewrap: { color: C.amber, label: "Needs Rewrap" },
    retired: { color: C.muted, label: "Retired" },
    running: { color: C.accent, label: "Running" },
    completed: { color: C.green, label: "Completed" },
    failed: { color: C.red, label: "Failed" },
    pending: { color: C.amber, label: "Pending" },
    rotating: { color: C.blue, label: "Rotating" },
  };
  const cfg = map[status] ?? { color: C.blue, label: status };
  return (
    <span style={{ background: cfg.color + "22", color: cfg.color, borderRadius: 5, padding: "2px 8px", fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>
      {cfg.label}
    </span>
  );
}

// ── Modal ──────────────────────────────────────────────────────────────────

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 12, width: 480, maxWidth: "calc(100vw - 32px)", padding: 28 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
          <span style={{ color: C.text, fontWeight: 700, fontSize: 16 }}>{title}</span>
          <button onClick={onClose} style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", padding: 4 }}><X size={18} /></button>
        </div>
        {children}
      </div>
    </div>
  );
}

function FormField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{ color: C.dim, fontSize: 12, fontWeight: 600, display: "block", marginBottom: 6 }}>{label}</label>
      {children}
    </div>
  );
}

const inputStyle: React.CSSProperties = { background: C.card, border: `1px solid ${C.border}`, borderRadius: 7, color: C.text, padding: "9px 12px", fontSize: 13, width: "100%", boxSizing: "border-box", outline: "none" };
const btnPrimary: React.CSSProperties = { background: C.accent, color: C.bg, border: "none", borderRadius: 7, padding: "9px 20px", fontWeight: 700, fontSize: 13, cursor: "pointer" };
const btnSecondary: React.CSSProperties = { background: C.card, color: C.dim, border: `1px solid ${C.border}`, borderRadius: 7, padding: "9px 20px", fontWeight: 600, fontSize: 13, cursor: "pointer" };
const btnSmall: React.CSSProperties = { background: C.card, color: C.dim, border: `1px solid ${C.border}`, borderRadius: 6, padding: "5px 12px", fontSize: 12, fontWeight: 600, cursor: "pointer" };

// ── Main Component ──────────────────────────────────────────────────────────

export function EnvelopeEncTab({ session }: { session: any; enabledFeatures?: any; keyCatalog?: any[] }) {
  const [keks, setKeks] = useState<KEK[]>([]);
  const [deks, setDeks] = useState<DEK[]>([]);
  const [hierarchy, setHierarchy] = useState<EnvelopeHierarchyNode[]>([]);
  const [jobs, setJobs] = useState<RewrapJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState<"hierarchy" | "deks" | "jobs">("hierarchy");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [showCreateKEK, setShowCreateKEK] = useState(false);
  const [showRewrap, setShowRewrap] = useState(false);
  const [newKEKName, setNewKEKName] = useState("");
  const [newKEKAlgo, setNewKEKAlgo] = useState("AES-256-GCM");
  const [rewrapOld, setRewrapOld] = useState("");
  const [rewrapNew, setRewrapNew] = useState("");
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [k, d, h, j] = await Promise.all([listKEKs(session), listDEKs(session), getHierarchy(session), listRewrapJobs(session)]);
      setKeks(k); setDeks(d); setHierarchy(h); setJobs(j);
    } catch {
      setKeks(MOCK_KEKS); setDeks(MOCK_DEKS); setHierarchy(MOCK_HIERARCHY); setJobs(MOCK_JOBS);
      setError("Live data unavailable — showing mock data.");
    } finally { setLoading(false); }
  }, [session]);

  useEffect(() => { load(); }, [load]);

  const toggleExpand = (id: string) => setExpanded(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const handleCreateKEK = async () => {
    if (!newKEKName.trim()) return;
    setSaving(true);
    try { await createKEK(session, { name: newKEKName.trim(), algorithm: newKEKAlgo }); }
    catch { /* swallow — mock */ }
    finally { setSaving(false); setShowCreateKEK(false); setNewKEKName(""); await load(); }
  };

  const handleRotateKEK = async (id: string) => {
    try { await rotateKEK(session, id); await load(); } catch { /* swallow */ }
  };

  const handleStartRewrap = async () => {
    if (!rewrapOld || !rewrapNew || rewrapOld === rewrapNew) return;
    setSaving(true);
    try { await startRewrap(session, rewrapOld, rewrapNew); }
    catch { /* mock */ }
    finally { setSaving(false); setShowRewrap(false); setRewrapOld(""); setRewrapNew(""); await load(); }
  };

  const rewrapDEKCount = deks.filter(d => d.kek_id === rewrapOld).length;

  const activeKEKs = keks.filter(k => k.status === "active").length;
  const dekNeedingRewrap = deks.filter(d => d.status === "needs_rewrap").length;
  const activeJobs = jobs.filter(j => j.status === "running").length;

  const sectionTabs: { key: "hierarchy" | "deks" | "jobs"; label: string }[] = [
    { key: "hierarchy", label: "KEK Hierarchy" },
    { key: "deks", label: "DEKs" },
    { key: "jobs", label: "Rewrap Jobs" },
  ];

  return (
    <div style={{ padding: "24px 28px", fontFamily: "system-ui, sans-serif", color: C.text, minHeight: "100vh", background: C.bg }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ background: C.accentDim, borderRadius: 8, padding: 8, color: C.accent, display: "flex" }}><Layers size={22} /></div>
          <div>
            <div style={{ fontSize: 20, fontWeight: 700 }}>Envelope Encryption</div>
            <div style={{ color: C.dim, fontSize: 13 }}>DEK / KEK hierarchy management and bulk re-wrap operations</div>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button onClick={() => setShowRewrap(true)} style={{ ...btnSecondary, display: "flex", alignItems: "center", gap: 6 }}><ArrowRightLeft size={14} /> Start Rewrap</button>
          <button onClick={() => setShowCreateKEK(true)} style={{ ...btnPrimary, display: "flex", alignItems: "center", gap: 6 }}><Plus size={14} /> Create KEK</button>
          <button onClick={load} style={{ ...btnSecondary, padding: "9px 10px" }}><RefreshCcw size={14} /></button>
        </div>
      </div>

      {error && <div style={{ background: C.amberDim, border: `1px solid ${C.amber}44`, borderRadius: 8, padding: "10px 16px", color: C.amber, fontSize: 13, marginBottom: 18 }}>{error}</div>}

      {/* Stat Cards */}
      <div style={{ display: "flex", gap: 14, marginBottom: 24, flexWrap: "wrap" }}>
        <StatCard label="Active KEKs" value={loading ? "—" : activeKEKs} icon={<Key size={18} />} color={C.accent} />
        <StatCard label="Total DEKs" value={loading ? "—" : deks.length} icon={<Layers size={18} />} color={C.blue} />
        <StatCard label="DEKs Needing Rewrap" value={loading ? "—" : dekNeedingRewrap} icon={<AlertTriangle size={18} />} color={C.amber} />
        <StatCard label="Active Rewrap Jobs" value={loading ? "—" : activeJobs} icon={<ArrowRightLeft size={18} />} color={C.green} />
      </div>

      {/* Section Tabs */}
      <div style={{ display: "flex", gap: 4, borderBottom: `1px solid ${C.border}`, marginBottom: 20 }}>
        {sectionTabs.map(t => (
          <button key={t.key} onClick={() => setSection(t.key)} style={{ background: "none", border: "none", borderBottom: section === t.key ? `2px solid ${C.accent}` : "2px solid transparent", color: section === t.key ? C.accent : C.dim, padding: "10px 18px", fontSize: 13, fontWeight: 600, cursor: "pointer", marginBottom: -1 }}>{t.label}</button>
        ))}
      </div>

      {loading ? (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 60, color: C.dim, gap: 10 }}><Loader2 size={20} style={{ animation: "spin 1s linear infinite" }} /> Loading...</div>
      ) : (
        <>
          {/* Hierarchy View */}
          {section === "hierarchy" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {hierarchy.map(node => (
                <div key={node.kek_id} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "14px 18px", cursor: "pointer" }} onClick={() => toggleExpand(node.kek_id)}>
                    <button style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", padding: 0, display: "flex" }}>
                      {expanded.has(node.kek_id) ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                    </button>
                    <Key size={16} color={C.accent} />
                    <span style={{ fontWeight: 700, fontSize: 14, flex: 1 }}>{node.kek_name}</span>
                    <span style={{ color: C.dim, fontSize: 12, marginRight: 12 }}>{node.kek_algorithm}</span>
                    <StatusBadge status={node.kek_status} />
                    <span style={{ color: C.dim, fontSize: 12, marginLeft: 16 }}>{node.deks.length} DEKs</span>
                    <button onClick={e => { e.stopPropagation(); handleRotateKEK(node.kek_id); }} style={{ ...btnSmall, marginLeft: 8, display: "flex", alignItems: "center", gap: 4 }}><RotateCcw size={12} /> Rotate KEK</button>
                    <button onClick={e => { e.stopPropagation(); setRewrapOld(node.kek_id); setShowRewrap(true); }} style={{ ...btnSmall, display: "flex", alignItems: "center", gap: 4 }}><ArrowRightLeft size={12} /> Rewrap</button>
                  </div>
                  {expanded.has(node.kek_id) && node.deks.length > 0 && (
                    <div style={{ borderTop: `1px solid ${C.border}`, background: C.surface }}>
                      {node.deks.map(dek => (
                        <div key={dek.id} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 18px 10px 52px", borderBottom: `1px solid ${C.border}22` }}>
                          <Archive size={13} color={C.blue} />
                          <span style={{ fontSize: 13, flex: 1 }}>{dek.name}</span>
                          <span style={{ color: C.dim, fontSize: 12 }}>{dek.algorithm}</span>
                          <span style={{ color: C.muted, fontSize: 12 }}>{dek.owner_service}</span>
                          <StatusBadge status={dek.status} />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* DEK Table */}
          {section === "deks" && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                    {["Name", "KEK", "Algorithm", "Purpose", "Owner Service", "Status", "Last Used", "Created"].map(h => (
                      <th key={h} style={{ padding: "11px 14px", textAlign: "left", color: C.dim, fontWeight: 600, fontSize: 12, whiteSpace: "nowrap" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {deks.map(d => (
                    <tr key={d.id} style={{ borderBottom: `1px solid ${C.border}22` }}>
                      <td style={{ padding: "11px 14px", fontWeight: 600 }}>{d.name}</td>
                      <td style={{ padding: "11px 14px", color: C.dim }}>{d.kek_name}</td>
                      <td style={{ padding: "11px 14px", color: C.dim }}>{d.algorithm}</td>
                      <td style={{ padding: "11px 14px", color: C.dim }}>{purposeLabel[d.purpose] ?? d.purpose}</td>
                      <td style={{ padding: "11px 14px", color: C.dim }}>{d.owner_service}</td>
                      <td style={{ padding: "11px 14px" }}><StatusBadge status={d.status} /></td>
                      <td style={{ padding: "11px 14px", color: C.muted }}>{fmtAgo(d.last_used_at)}</td>
                      <td style={{ padding: "11px 14px", color: C.muted }}>{fmtDate(d.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Rewrap Jobs Table */}
          {section === "jobs" && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                    {["Old KEK", "New KEK", "Total DEKs", "Progress", "Status", "Started", "Completed"].map(h => (
                      <th key={h} style={{ padding: "11px 14px", textAlign: "left", color: C.dim, fontWeight: 600, fontSize: 12 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {jobs.map(j => {
                    const pct = j.total_deks > 0 ? Math.round((j.processed_deks / j.total_deks) * 100) : 0;
                    const oldKek = keks.find(k => k.id === j.old_kek_id);
                    const newKek = keks.find(k => k.id === j.new_kek_id);
                    return (
                      <tr key={j.id} style={{ borderBottom: `1px solid ${C.border}22` }}>
                        <td style={{ padding: "11px 14px", color: C.dim }}>{oldKek?.name ?? j.old_kek_id}</td>
                        <td style={{ padding: "11px 14px", color: C.dim }}>{newKek?.name ?? j.new_kek_id}</td>
                        <td style={{ padding: "11px 14px" }}>{j.total_deks}</td>
                        <td style={{ padding: "11px 14px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <div style={{ flex: 1, background: C.border, borderRadius: 4, height: 6, minWidth: 80 }}>
                              <div style={{ width: `${pct}%`, height: "100%", borderRadius: 4, background: j.status === "failed" ? C.red : C.accent }} />
                            </div>
                            <span style={{ color: C.dim, fontSize: 11, minWidth: 32 }}>{pct}%</span>
                          </div>
                        </td>
                        <td style={{ padding: "11px 14px" }}><StatusBadge status={j.status} /></td>
                        <td style={{ padding: "11px 14px", color: C.muted }}>{fmtDate(j.started_at)}</td>
                        <td style={{ padding: "11px 14px", color: C.muted }}>{fmtDate(j.completed_at)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* Create KEK Modal */}
      {showCreateKEK && (
        <Modal title="Create Key Encryption Key (KEK)" onClose={() => setShowCreateKEK(false)}>
          <FormField label="Name">
            <input style={inputStyle} value={newKEKName} onChange={e => setNewKEKName(e.target.value)} placeholder="e.g. prod-payments-kek" />
          </FormField>
          <FormField label="Algorithm">
            <select style={inputStyle} value={newKEKAlgo} onChange={e => setNewKEKAlgo(e.target.value)}>
              <option value="AES-256-GCM">AES-256-GCM</option>
              <option value="AES-128-GCM">AES-128-GCM</option>
            </select>
          </FormField>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", marginTop: 8 }}>
            <button style={btnSecondary} onClick={() => setShowCreateKEK(false)}>Cancel</button>
            <button style={btnPrimary} onClick={handleCreateKEK} disabled={saving || !newKEKName.trim()}>
              {saving ? "Creating…" : "Create KEK"}
            </button>
          </div>
        </Modal>
      )}

      {/* Start Rewrap Modal */}
      {showRewrap && (
        <Modal title="Start Bulk DEK Rewrap" onClose={() => setShowRewrap(false)}>
          <FormField label="Old KEK (source)">
            <select style={inputStyle} value={rewrapOld} onChange={e => setRewrapOld(e.target.value)}>
              <option value="">Select old KEK…</option>
              {keks.map(k => <option key={k.id} value={k.id}>{k.name}</option>)}
            </select>
          </FormField>
          <FormField label="New KEK (target)">
            <select style={inputStyle} value={rewrapNew} onChange={e => setRewrapNew(e.target.value)}>
              <option value="">Select new KEK…</option>
              {keks.filter(k => k.status === "active" && k.id !== rewrapOld).map(k => <option key={k.id} value={k.id}>{k.name}</option>)}
            </select>
          </FormField>
          {rewrapOld && (
            <div style={{ background: C.accentDim, border: `1px solid ${C.accent}44`, borderRadius: 8, padding: "10px 14px", fontSize: 13, color: C.accent, marginBottom: 16 }}>
              <CheckCircle size={14} style={{ display: "inline", marginRight: 6 }} />
              {rewrapDEKCount} DEK{rewrapDEKCount !== 1 ? "s" : ""} will be migrated from this KEK.
            </div>
          )}
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
            <button style={btnSecondary} onClick={() => setShowRewrap(false)}>Cancel</button>
            <button style={btnPrimary} onClick={handleStartRewrap} disabled={saving || !rewrapOld || !rewrapNew || rewrapOld === rewrapNew}>
              {saving ? "Starting…" : "Start Rewrap"}
            </button>
          </div>
        </Modal>
      )}

      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
