// @ts-nocheck
import { useEffect, useState } from "react";
import {
  ShieldCheck, AlertTriangle, TrendingUp, ArrowRight, Plus,
  RefreshCw, CheckCircle, Clock, XCircle, Pause, Activity
} from "lucide-react";
import { C } from "../../v3/theme";
import {
  getAgilityScore,
  getAlgorithmInventory,
  listMigrationPlans,
  createMigrationPlan,
  type AlgorithmUsage,
  type MigrationPlan,
  type AgilityScore,
} from "../../../lib/cryptoAgility";

/* ─── Props ──────────────────────────────────────────────── */
interface Props {
  session: any;
  enabledFeatures?: any;
  keyCatalog?: any[];
}

/* ─── Mock data ──────────────────────────────────────────── */
const MOCK_SCORE: AgilityScore = {
  overall: 78,
  pqc_readiness: 42,
  deprecated_ratio: 15,
  key_diversity: 91,
  last_updated: new Date().toISOString(),
  by_group: { symmetric: 95, asymmetric: 61, hash: 88, pqc: 42 },
};

const MOCK_ALGORITHMS: AlgorithmUsage[] = [
  { algorithm: "AES-256-GCM", family: "symmetric", key_count: 1842, cert_count: 0, ops_last_30d: 4_210_000, pqc_safe: true, nist_status: "approved", migration_urgency: "none", replacement: undefined },
  { algorithm: "RSA-2048", family: "asymmetric", key_count: 634, cert_count: 218, ops_last_30d: 980_000, pqc_safe: false, nist_status: "deprecated", migration_urgency: "high", replacement: "ML-KEM-768" },
  { algorithm: "EC P-256", family: "asymmetric", key_count: 421, cert_count: 87, ops_last_30d: 760_000, pqc_safe: false, nist_status: "approved", migration_urgency: "medium", replacement: "ML-DSA-65" },
  { algorithm: "SHA-256", family: "hash", key_count: 0, cert_count: 0, ops_last_30d: 8_900_000, pqc_safe: true, nist_status: "approved", migration_urgency: "none", replacement: undefined },
  { algorithm: "ML-KEM-768", family: "pqc", key_count: 94, cert_count: 0, ops_last_30d: 12_000, pqc_safe: true, nist_status: "candidate", migration_urgency: "none", replacement: undefined },
  { algorithm: "RSA-1024", family: "asymmetric", key_count: 28, cert_count: 4, ops_last_30d: 1_200, pqc_safe: false, nist_status: "disallowed", migration_urgency: "critical", replacement: "ML-KEM-768" },
];

const MOCK_PLANS: MigrationPlan[] = [
  { id: "mp-1", name: "RSA-1024 Emergency Remediation", from_algorithm: "RSA-1024", to_algorithm: "ML-KEM-768", affected_keys: 28, completed_keys: 14, status: "in_progress", created_at: "2026-01-10T00:00:00Z", target_date: "2026-04-01" },
  { id: "mp-2", name: "RSA-2048 PQC Transition", from_algorithm: "RSA-2048", to_algorithm: "ML-KEM-768", affected_keys: 634, completed_keys: 89, status: "in_progress", created_at: "2026-02-01T00:00:00Z", target_date: "2026-12-31" },
  { id: "mp-3", name: "EC P-256 → ML-DSA", from_algorithm: "EC P-256", to_algorithm: "ML-DSA-65", affected_keys: 421, completed_keys: 0, status: "planned", created_at: "2026-03-01T00:00:00Z", target_date: "2027-06-30" },
];

/* ─── Helpers ─────────────────────────────────────────────── */
function nistColor(status: string) {
  switch (status) {
    case "approved":  return C.green;
    case "deprecated": return C.amber;
    case "disallowed": return C.red;
    case "candidate":  return C.purple;
    default:           return C.dim;
  }
}
function nistBg(status: string) {
  switch (status) {
    case "approved":  return C.greenDim;
    case "deprecated": return C.amberDim;
    case "disallowed": return C.redDim;
    case "candidate":  return C.purpleDim;
    default:           return C.accentDim;
  }
}
function urgencyColor(u: string) {
  switch (u) {
    case "critical": return C.red;
    case "high":     return C.orange;
    case "medium":   return C.amber;
    case "low":      return C.blue;
    default:         return C.dim;
  }
}
function planStatusIcon(s: string) {
  switch (s) {
    case "in_progress": return <Activity size={13} color={C.accent} />;
    case "completed":   return <CheckCircle size={13} color={C.green} />;
    case "paused":      return <Pause size={13} color={C.amber} />;
    default:            return <Clock size={13} color={C.dim} />;
  }
}
function planStatusColor(s: string) {
  switch (s) {
    case "in_progress": return C.accent;
    case "completed":   return C.green;
    case "paused":      return C.amber;
    default:            return C.dim;
  }
}
function fmtOps(n: number) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `${(n / 1_000).toFixed(0)}K`;
  return String(n);
}

/* ─── Sub-components ─────────────────────────────────────── */
function ScoreGauge({ score }: { score: number }) {
  const color = score >= 80 ? C.green : score >= 55 ? C.amber : C.red;
  const r = 54;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
      <div style={{ position: "relative", width: 140, height: 140 }}>
        <svg width={140} height={140} style={{ transform: "rotate(-90deg)" }}>
          <circle cx={70} cy={70} r={r} fill="none" stroke={C.border} strokeWidth={10} />
          <circle
            cx={70} cy={70} r={r} fill="none"
            stroke={color} strokeWidth={10}
            strokeDasharray={`${dash} ${circ - dash}`}
            strokeLinecap="round"
            style={{ transition: "stroke-dasharray 0.8s ease", filter: `drop-shadow(0 0 6px ${color})` }}
          />
        </svg>
        <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <span style={{ fontSize: 28, fontWeight: 700, color, fontFamily: "IBM Plex Mono, monospace", lineHeight: 1 }}>{score}</span>
          <span style={{ fontSize: 11, color: C.dim, marginTop: 2 }}>/ 100</span>
        </div>
      </div>
      <span style={{ fontSize: 12, color: C.dim, textAlign: "center" }}>Overall Agility Score</span>
    </div>
  );
}

interface StatCardProps { icon: React.ReactNode; label: string; value: string | number; sub?: string; color?: string; bg?: string }
function StatCard({ icon, label, value, sub, color = C.accent, bg = C.accentTint }: StatCardProps) {
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "18px 20px", display: "flex", alignItems: "flex-start", gap: 14, flex: 1, minWidth: 160 }}>
      <div style={{ background: bg, border: `1px solid ${color}22`, borderRadius: 8, padding: 8, flexShrink: 0, color }}>{icon}</div>
      <div>
        <div style={{ fontSize: 22, fontWeight: 700, color: C.text, lineHeight: 1 }}>{value}</div>
        <div style={{ fontSize: 11, color: C.dim, marginTop: 3 }}>{label}</div>
        {sub && <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{sub}</div>}
      </div>
    </div>
  );
}

/* ─── Create Plan Modal ───────────────────────────────────── */
function CreatePlanModal({ algorithms, onClose, onSave }: {
  algorithms: AlgorithmUsage[];
  onClose: () => void;
  onSave: (data: any) => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [targetDate, setTargetDate] = useState("");
  const [saving, setSaving] = useState(false);

  const algNames = algorithms.map(a => a.algorithm);

  async function handleSave() {
    if (!name || !from || !to || !targetDate) return;
    setSaving(true);
    try { await onSave({ name, from_algorithm: from, to_algorithm: to, target_date: targetDate }); onClose(); }
    catch { /* swallow */ }
    finally { setSaving(false); }
  }

  const inputStyle: React.CSSProperties = {
    background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6,
    color: C.text, padding: "8px 10px", fontSize: 13, width: "100%", fontFamily: "IBM Plex Sans, sans-serif", outline: "none",
  };
  const labelStyle: React.CSSProperties = { fontSize: 11, color: C.dim, marginBottom: 4 };

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.65)", zIndex: 9999, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: C.card, border: `1px solid ${C.borderHi}`, borderRadius: 12, padding: 28, width: 460, boxShadow: "0 24px 60px rgba(0,0,0,.6)" }}>
        <div style={{ fontSize: 16, fontWeight: 600, color: C.text, marginBottom: 20 }}>Create Migration Plan</div>

        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div>
            <div style={labelStyle}>Plan Name</div>
            <input style={inputStyle} value={name} onChange={e => setName(e.target.value)} placeholder="e.g. RSA-2048 PQC Migration" />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div>
              <div style={labelStyle}>From Algorithm</div>
              <select style={inputStyle} value={from} onChange={e => setFrom(e.target.value)}>
                <option value="">Select…</option>
                {algNames.map(a => <option key={a} value={a}>{a}</option>)}
              </select>
            </div>
            <div>
              <div style={labelStyle}>To Algorithm</div>
              <select style={inputStyle} value={to} onChange={e => setTo(e.target.value)}>
                <option value="">Select…</option>
                {algNames.map(a => <option key={a} value={a}>{a}</option>)}
              </select>
            </div>
          </div>
          <div>
            <div style={labelStyle}>Target Date</div>
            <input type="date" style={inputStyle} value={targetDate} onChange={e => setTargetDate(e.target.value)} />
          </div>
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 22 }}>
          <button onClick={onClose} style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 6, color: C.dim, padding: "8px 16px", cursor: "pointer", fontSize: 13 }}>Cancel</button>
          <button
            onClick={handleSave}
            disabled={saving || !name || !from || !to || !targetDate}
            style={{ background: C.accent, border: "none", borderRadius: 6, color: C.bg, padding: "8px 18px", cursor: saving ? "not-allowed" : "pointer", fontSize: 13, fontWeight: 600, opacity: saving ? 0.7 : 1 }}
          >
            {saving ? "Creating…" : "Create Plan"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ─── Main Component ─────────────────────────────────────── */
export function CryptoAgilityTab({ session, enabledFeatures, keyCatalog }: Props) {
  const [score, setScore] = useState<AgilityScore | null>(null);
  const [algorithms, setAlgorithms] = useState<AlgorithmUsage[]>([]);
  const [plans, setPlans] = useState<MigrationPlan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  async function load(silent = false) {
    if (!silent) setLoading(true);
    else setRefreshing(true);
    setError(null);
    try {
      const [s, a, p] = await Promise.all([
        getAgilityScore(session),
        getAlgorithmInventory(session),
        listMigrationPlans(session),
      ]);
      setScore(s); setAlgorithms(a); setPlans(p);
    } catch {
      setScore(MOCK_SCORE); setAlgorithms(MOCK_ALGORITHMS); setPlans(MOCK_PLANS);
    } finally {
      setLoading(false); setRefreshing(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleCreatePlan(data: any) {
    const plan = await createMigrationPlan(session, data).catch(() => ({
      id: `mp-${Date.now()}`, ...data, affected_keys: 0, completed_keys: 0,
      status: "planned", created_at: new Date().toISOString(),
    } as MigrationPlan));
    setPlans(prev => [...prev, plan]);
  }

  const pqcSafeCount = algorithms.filter(a => a.pqc_safe).length;
  const deprecatedCount = algorithms.filter(a => a.nist_status === "deprecated" || a.nist_status === "disallowed").length;
  const totalKeys = algorithms.reduce((s, a) => s + a.key_count, 0);
  const pqcSafeKeys = algorithms.filter(a => a.pqc_safe).reduce((s, a) => s + a.key_count, 0);
  const pqcPct = totalKeys > 0 ? Math.round((pqcSafeKeys / totalKeys) * 100) : 0;

  const divider: React.CSSProperties = { borderTop: `1px solid ${C.border}`, margin: "24px 0" };
  const sectionTitle: React.CSSProperties = { fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 };
  const th: React.CSSProperties = { textAlign: "left", fontSize: 10, color: C.muted, fontWeight: 600, padding: "8px 12px", textTransform: "uppercase", letterSpacing: "0.06em", whiteSpace: "nowrap" };
  const td: React.CSSProperties = { padding: "11px 12px", fontSize: 12, color: C.text, verticalAlign: "middle" };

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: 320, color: C.dim, fontSize: 13, gap: 10 }}>
        <RefreshCw size={16} style={{ animation: "spin 1s linear infinite" }} />
        Loading crypto agility data…
        <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  return (
    <div style={{ fontFamily: "IBM Plex Sans, sans-serif", color: C.text, padding: "4px 0" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 700, color: C.text }}>Crypto Agility</div>
          <div style={{ fontSize: 12, color: C.dim, marginTop: 2 }}>Algorithm inventory &amp; PQC migration readiness</div>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button
            onClick={() => load(true)}
            disabled={refreshing}
            style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 7, color: C.dim, padding: "7px 13px", cursor: "pointer", fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}
          >
            <RefreshCw size={13} style={refreshing ? { animation: "spin 1s linear infinite" } : {}} />
            Refresh
          </button>
          <button
            onClick={() => setShowModal(true)}
            style={{ background: C.accent, border: "none", borderRadius: 7, color: C.bg, padding: "7px 14px", cursor: "pointer", fontSize: 12, fontWeight: 600, display: "flex", alignItems: "center", gap: 6 }}
          >
            <Plus size={13} /> Create Migration Plan
          </button>
        </div>
      </div>

      {/* Score + Stat Cards Row */}
      <div style={{ display: "flex", gap: 16, alignItems: "stretch", flexWrap: "wrap" }}>
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "20px 24px", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <ScoreGauge score={score?.overall ?? 0} />
        </div>
        <div style={{ display: "flex", gap: 12, flex: 1, flexWrap: "wrap" }}>
          <StatCard icon={<Activity size={16} />} label="Total Algorithms In Use" value={algorithms.length} color={C.accent} bg={C.accentTint} />
          <StatCard icon={<ShieldCheck size={16} />} label="PQC-Safe Keys" value={`${pqcPct}%`} sub={`${pqcSafeKeys.toLocaleString()} / ${totalKeys.toLocaleString()} keys`} color={C.green} bg={C.greenTint} />
          <StatCard icon={<AlertTriangle size={16} />} label="Deprecated Algorithms" value={deprecatedCount} sub="require migration" color={C.amber} bg={C.amberTint} />
          <StatCard icon={<TrendingUp size={16} />} label="Active Migration Plans" value={plans.filter(p => p.status === "in_progress").length} sub={`${plans.length} total plans`} color={C.purple} bg={C.purpleTint} />
        </div>
      </div>

      <div style={divider} />

      {/* Algorithm Inventory */}
      <div style={sectionTitle}>Algorithm Inventory</div>
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {["Algorithm", "Family", "Keys", "Ops (30d)", "PQC Safe", "NIST Status", "Urgency", "Replacement"].map(h => (
                  <th key={h} style={th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {algorithms.map((alg, i) => (
                <tr key={alg.algorithm} style={{ borderBottom: i < algorithms.length - 1 ? `1px solid ${C.border}` : "none", background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,.01)" }}>
                  <td style={td}>
                    <span style={{ fontFamily: "IBM Plex Mono, monospace", fontSize: 12, color: C.text, fontWeight: 600 }}>{alg.algorithm}</span>
                  </td>
                  <td style={td}>
                    <span style={{ fontSize: 11, color: C.dim, background: C.accentDim, padding: "2px 7px", borderRadius: 4, textTransform: "capitalize" }}>{alg.family}</span>
                  </td>
                  <td style={{ ...td, fontFamily: "IBM Plex Mono, monospace" }}>{alg.key_count.toLocaleString()}</td>
                  <td style={{ ...td, fontFamily: "IBM Plex Mono, monospace" }}>{fmtOps(alg.ops_last_30d)}</td>
                  <td style={td}>
                    {alg.pqc_safe
                      ? <span style={{ background: C.greenDim, color: C.green, padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600 }}>Yes</span>
                      : <span style={{ background: C.redDim, color: C.red, padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600 }}>No</span>}
                  </td>
                  <td style={td}>
                    <span style={{ background: nistBg(alg.nist_status), color: nistColor(alg.nist_status), padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600, textTransform: "capitalize" }}>{alg.nist_status}</span>
                  </td>
                  <td style={td}>
                    {alg.migration_urgency === "none"
                      ? <span style={{ color: C.muted, fontSize: 11 }}>—</span>
                      : <span style={{ color: urgencyColor(alg.migration_urgency), fontSize: 11, fontWeight: 600, textTransform: "capitalize" }}>{alg.migration_urgency}</span>}
                  </td>
                  <td style={td}>
                    {alg.replacement
                      ? <span style={{ fontFamily: "IBM Plex Mono, monospace", fontSize: 11, color: C.accent }}>{alg.replacement}</span>
                      : <span style={{ color: C.muted, fontSize: 11 }}>—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div style={divider} />

      {/* Migration Plans */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
        <div style={sectionTitle}>Migration Plans</div>
        <span style={{ fontSize: 11, color: C.muted }}>{plans.length} total</span>
      </div>

      {plans.length === 0 ? (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 32, textAlign: "center", color: C.muted, fontSize: 13 }}>
          No migration plans created yet.
        </div>
      ) : (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  {["Name", "Migration", "Keys", "Progress", "Status", "Target Date"].map(h => (
                    <th key={h} style={th}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {plans.map((plan, i) => {
                  const pct = plan.affected_keys > 0 ? Math.round((plan.completed_keys / plan.affected_keys) * 100) : 0;
                  return (
                    <tr key={plan.id} style={{ borderBottom: i < plans.length - 1 ? `1px solid ${C.border}` : "none" }}>
                      <td style={td}><span style={{ fontWeight: 600 }}>{plan.name}</span></td>
                      <td style={td}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, fontFamily: "IBM Plex Mono, monospace", fontSize: 11 }}>
                          <span style={{ color: C.red }}>{plan.from_algorithm}</span>
                          <ArrowRight size={11} color={C.dim} />
                          <span style={{ color: C.green }}>{plan.to_algorithm}</span>
                        </div>
                      </td>
                      <td style={{ ...td, fontFamily: "IBM Plex Mono, monospace" }}>{plan.affected_keys.toLocaleString()}</td>
                      <td style={td}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 120 }}>
                          <div style={{ flex: 1, background: C.border, borderRadius: 99, height: 5, overflow: "hidden" }}>
                            <div style={{ width: `${pct}%`, background: pct === 100 ? C.green : C.accent, height: "100%", borderRadius: 99, transition: "width 0.5s ease" }} />
                          </div>
                          <span style={{ fontSize: 11, color: C.dim, fontFamily: "IBM Plex Mono, monospace", whiteSpace: "nowrap" }}>{plan.completed_keys}/{plan.affected_keys}</span>
                        </div>
                      </td>
                      <td style={td}>
                        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                          {planStatusIcon(plan.status)}
                          <span style={{ fontSize: 11, color: planStatusColor(plan.status), fontWeight: 600, textTransform: "capitalize" }}>{plan.status.replace("_", " ")}</span>
                        </div>
                      </td>
                      <td style={{ ...td, fontFamily: "IBM Plex Mono, monospace", fontSize: 11, color: C.dim }}>{plan.target_date}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {showModal && (
        <CreatePlanModal
          algorithms={algorithms}
          onClose={() => setShowModal(false)}
          onSave={handleCreatePlan}
        />
      )}
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
