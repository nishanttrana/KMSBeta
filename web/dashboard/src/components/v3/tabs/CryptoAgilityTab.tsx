import { useEffect, useState, type CSSProperties, type ReactNode } from "react";
import {
  ShieldCheck, AlertTriangle, TrendingUp, ArrowRight, Plus,
  RefreshCw, CheckCircle, Clock, Pause, Activity, XCircle
} from "lucide-react";
import { C } from "../../v3/theme";
import {
  getAgilityScore,
  getAlgorithmInventory,
  listMigrationPlans,
  createMigrationPlan,
  updateMigrationPlanStatus,
  type AlgorithmUsage,
  type MigrationPlan,
  type MigrationPlanStatus,
  type AgilityScore,
  type NewMigrationPlan,
} from "../../../lib/cryptoAgility";

// Every figure on this tab comes from keycore's /agility routes, computed from
// the tenant's live keys. When keycore can't answer, the tab says so and shows
// the error; it never substitutes sample data (CLAUDE.md rules 7 and 8).

/* ─── Props ──────────────────────────────────────────────── */
interface Props {
  session: any;
  enabledFeatures?: any;
  keyCatalog?: any[];
}

/* ─── Helpers ─────────────────────────────────────────────── */
const PLAN_STATUSES: MigrationPlanStatus[] = ["planned", "in_progress", "paused", "completed"];
// Suggestions for a migration target only; the inventory itself comes from keycore.
const PQC_TARGETS = ["ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

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
function errText(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

/* ─── Sub-components ─────────────────────────────────────── */
function ScoreGauge({ score }: { score: AgilityScore }) {
  if (!score.assessed) {
    return (
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8, width: 140 }}>
        <div style={{ fontSize: 15, fontWeight: 600, color: C.dim }}>Not assessed</div>
        <span style={{ fontSize: 11, color: C.muted, textAlign: "center" }}>No live keys to score yet.</span>
      </div>
    );
  }
  const value = score.score;
  const color = value >= 80 ? C.green : value >= 55 ? C.amber : C.red;
  const r = 54;
  const circ = 2 * Math.PI * r;
  const dash = (value / 100) * circ;

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
          <span style={{ fontSize: 28, fontWeight: 700, color, fontFamily: "IBM Plex Mono, monospace", lineHeight: 1 }}>{value}</span>
          <span style={{ fontSize: 11, color: C.dim, marginTop: 2 }}>/ 100 · grade {score.grade}</span>
        </div>
      </div>
      <span style={{ fontSize: 12, color: C.dim, textAlign: "center" }}>Agility Score</span>
    </div>
  );
}

interface StatCardProps { icon: ReactNode; label: string; value: string | number; sub?: string; color?: string; bg?: string }
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

function Unavailable({ error, onRetry }: { error: string; onRetry: () => void }) {
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 28, display: "flex", gap: 14, alignItems: "flex-start" }}>
      <XCircle size={18} color={C.red} style={{ flexShrink: 0, marginTop: 2 }} />
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: C.text }}>Not assessed: crypto agility data is unavailable</div>
        <div style={{ fontSize: 12, color: C.dim, marginTop: 6 }}>
          keycore did not return the algorithm inventory, so no score, inventory or migration progress is shown.
        </div>
        <div style={{ fontSize: 11, color: C.red, marginTop: 8, fontFamily: "IBM Plex Mono, monospace", wordBreak: "break-word" }}>{error}</div>
        <button onClick={onRetry} style={{ marginTop: 14, background: C.card, border: `1px solid ${C.border}`, borderRadius: 7, color: C.dim, padding: "7px 13px", cursor: "pointer", fontSize: 12, display: "inline-flex", alignItems: "center", gap: 6 }}>
          <RefreshCw size={13} /> Retry
        </button>
      </div>
    </div>
  );
}

/* ─── Create Plan Modal ───────────────────────────────────── */
function CreatePlanModal({ algorithms, onClose, onSave }: {
  algorithms: AlgorithmUsage[];
  onClose: () => void;
  onSave: (data: NewMigrationPlan) => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [targetDate, setTargetDate] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const targets = Array.from(new Set([...PQC_TARGETS, ...algorithms.map(a => a.algorithm)]));
  const valid = Boolean(name.trim() && from && to.trim() && from !== to.trim());

  async function handleSave() {
    if (!valid) return;
    setSaving(true);
    setError(null);
    try {
      const plan: NewMigrationPlan = { name: name.trim(), from_algorithm: from, to_algorithm: to.trim() };
      if (targetDate) plan.target_date = targetDate;
      await onSave(plan);
      onClose();
    } catch (e) {
      setError(errText(e));
    } finally {
      setSaving(false);
    }
  }

  const inputStyle: CSSProperties = {
    background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6,
    color: C.text, padding: "8px 10px", fontSize: 13, width: "100%", fontFamily: "IBM Plex Sans, sans-serif", outline: "none",
  };
  const labelStyle: CSSProperties = { fontSize: 11, color: C.dim, marginBottom: 4 };

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.65)", zIndex: 9999, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: C.card, border: `1px solid ${C.borderHi}`, borderRadius: 12, padding: 28, width: 460, maxWidth: "calc(100vw - 32px)", boxShadow: "0 24px 60px rgba(0,0,0,.6)" }}>
        <div style={{ fontSize: 16, fontWeight: 600, color: C.text, marginBottom: 6 }}>Create Migration Plan</div>
        <div style={{ fontSize: 11, color: C.muted, marginBottom: 18 }}>
          Affected keys are counted by keycore when the plan is created; progress is measured as keys leave the source algorithm.
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div>
            <div style={labelStyle}>Plan Name</div>
            <input style={inputStyle} value={name} onChange={e => setName(e.target.value)} placeholder="e.g. RSA-2048 PQC Migration" />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div>
              <div style={labelStyle}>From Algorithm (in use)</div>
              <select style={inputStyle} value={from} onChange={e => setFrom(e.target.value)}>
                <option value="">Select…</option>
                {algorithms.map(a => <option key={a.algorithm} value={a.algorithm}>{a.algorithm} ({a.key_count})</option>)}
              </select>
            </div>
            <div>
              <div style={labelStyle}>To Algorithm</div>
              <input style={inputStyle} list="agility-targets" value={to} onChange={e => setTo(e.target.value)} placeholder="e.g. ML-KEM-768" />
              <datalist id="agility-targets">
                {targets.map(a => <option key={a} value={a} />)}
              </datalist>
            </div>
          </div>
          <div>
            <div style={labelStyle}>Target Date (optional)</div>
            <input type="date" style={inputStyle} value={targetDate} onChange={e => setTargetDate(e.target.value)} />
          </div>
          {error && <div style={{ fontSize: 12, color: C.red }}>Plan not created: {error}</div>}
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 22 }}>
          <button onClick={onClose} style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 6, color: C.dim, padding: "8px 16px", cursor: "pointer", fontSize: 13 }}>Cancel</button>
          <button
            onClick={handleSave}
            disabled={saving || !valid}
            style={{ background: C.accent, border: "none", borderRadius: 6, color: C.bg, padding: "8px 18px", cursor: saving || !valid ? "not-allowed" : "pointer", fontSize: 13, fontWeight: 600, opacity: saving || !valid ? 0.6 : 1 }}
          >
            {saving ? "Creating…" : "Create Plan"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ─── Main Component ─────────────────────────────────────── */
export function CryptoAgilityTab({ session }: Props) {
  const [score, setScore] = useState<AgilityScore | null>(null);
  const [algorithms, setAlgorithms] = useState<AlgorithmUsage[]>([]);
  const [plans, setPlans] = useState<MigrationPlan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  async function load(silent = false) {
    if (!silent) setLoading(true);
    else setRefreshing(true);
    setError(null);
    setPlanError(null);
    try {
      const [s, a, p] = await Promise.all([
        getAgilityScore(session),
        getAlgorithmInventory(session),
        listMigrationPlans(session),
      ]);
      setScore(s); setAlgorithms(a); setPlans(p);
    } catch (e) {
      setScore(null); setAlgorithms([]); setPlans([]);
      setError(errText(e));
    } finally {
      setLoading(false); setRefreshing(false);
    }
  }

  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
  useEffect(() => { load(); }, []);

  async function handleCreatePlan(data: NewMigrationPlan) {
    const plan = await createMigrationPlan(session, data); // errors surface in the modal
    setPlans(prev => [plan, ...prev]);
  }

  async function handleStatus(plan: MigrationPlan, status: MigrationPlanStatus) {
    setPlanError(null);
    try {
      const updated = await updateMigrationPlanStatus(session, plan.id, status);
      setPlans(prev => prev.map(p => (p.id === updated.id ? updated : p)));
    } catch (e) {
      setPlanError(`${plan.name}: ${errText(e)}`);
    }
  }

  const quantumSafeKeys = algorithms.filter(a => a.is_quantum_safe).reduce((s, a) => s + a.key_count, 0);

  const divider: CSSProperties = { borderTop: `1px solid ${C.border}`, margin: "24px 0" };
  const sectionTitle: CSSProperties = { fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 };
  const th: CSSProperties = { textAlign: "left", fontSize: 10, color: C.muted, fontWeight: 600, padding: "8px 12px", textTransform: "uppercase", letterSpacing: "0.06em", whiteSpace: "nowrap" };
  const td: CSSProperties = { padding: "11px 12px", fontSize: 12, color: C.text, verticalAlign: "middle" };
  const badge = (on: boolean, yes: string, no: string, onColor = C.green, onBg = C.greenDim) => on
    ? <span style={{ background: onBg, color: onColor, padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600 }}>{yes}</span>
    : <span style={{ color: C.muted, fontSize: 11 }}>{no}</span>;

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
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20, gap: 12, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 700, color: C.text }}>Crypto Agility</div>
          <div style={{ fontSize: 12, color: C.dim, marginTop: 2 }}>Algorithm inventory &amp; PQC migration readiness, computed from your live keys</div>
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
            disabled={Boolean(error)}
            style={{ background: C.accent, border: "none", borderRadius: 7, color: C.bg, padding: "7px 14px", cursor: error ? "not-allowed" : "pointer", fontSize: 12, fontWeight: 600, display: "flex", alignItems: "center", gap: 6, opacity: error ? 0.5 : 1 }}
          >
            <Plus size={13} /> Create Migration Plan
          </button>
        </div>
      </div>

      {error || !score ? (
        <Unavailable error={error ?? "no data returned"} onRetry={() => load()} />
      ) : (
        <>
          {/* Score + Stat Cards Row */}
          <div style={{ display: "flex", gap: 16, alignItems: "stretch", flexWrap: "wrap" }}>
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "20px 24px", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <ScoreGauge score={score} />
            </div>
            <div style={{ display: "flex", gap: 12, flex: 1, flexWrap: "wrap" }}>
              <StatCard icon={<Activity size={16} />} label="Algorithms In Use" value={algorithms.length} sub={`${score.total_keys.toLocaleString()} live keys`} color={C.accent} bg={C.accentTint} />
              <StatCard icon={<ShieldCheck size={16} />} label="Quantum-Safe Keys" value={score.assessed ? `${score.quantum_readiness}%` : "—"} sub={`${quantumSafeKeys.toLocaleString()} / ${score.total_keys.toLocaleString()} keys`} color={C.green} bg={C.greenTint} />
              <StatCard icon={<AlertTriangle size={16} />} label="Legacy-Algorithm Keys" value={score.legacy_key_count.toLocaleString()} sub="require migration" color={C.amber} bg={C.amberTint} />
              <StatCard icon={<TrendingUp size={16} />} label="Active Migration Plans" value={plans.filter(p => p.status === "in_progress").length} sub={`${plans.length} total plans`} color={C.purple} bg={C.purpleTint} />
            </div>
          </div>

          {score.recommendations.length > 0 && (
            <div style={{ marginTop: 16, background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "14px 18px" }}>
              <div style={{ fontSize: 11, color: C.muted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>Recommendations</div>
              {score.recommendations.map(r => <div key={r} style={{ fontSize: 12, color: C.dim, marginTop: 4 }}>• {r}</div>)}
            </div>
          )}

          <div style={divider} />

          {/* Algorithm Inventory */}
          <div style={sectionTitle}>Algorithm Inventory</div>
          {algorithms.length === 0 ? (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 32, textAlign: "center", color: C.muted, fontSize: 13 }}>
              No live keys yet. The inventory fills in as keys are created.
            </div>
          ) : (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                      {["Algorithm", "Live Keys", "Share", "Quantum-Safe", "Legacy"].map(h => <th key={h} style={th}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {algorithms.map((alg, i) => (
                      <tr key={alg.algorithm} style={{ borderBottom: i < algorithms.length - 1 ? `1px solid ${C.border}` : "none" }}>
                        <td style={td}><span style={{ fontFamily: "IBM Plex Mono, monospace", fontSize: 12, fontWeight: 600 }}>{alg.algorithm}</span></td>
                        <td style={{ ...td, fontFamily: "IBM Plex Mono, monospace" }}>{alg.key_count.toLocaleString()}</td>
                        <td style={{ ...td, fontFamily: "IBM Plex Mono, monospace" }}>{alg.percentage.toFixed(1)}%</td>
                        <td style={td}>{badge(alg.is_quantum_safe, "Yes", "No")}</td>
                        <td style={td}>{badge(alg.is_legacy, "Legacy", "—", C.amber, C.amberDim)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div style={divider} />

          {/* Migration Plans */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
            <div style={sectionTitle}>Migration Plans</div>
            <span style={{ fontSize: 11, color: C.muted }}>{plans.length} total</span>
          </div>
          {planError && <div style={{ fontSize: 12, color: C.red, marginBottom: 10 }}>Status not changed: {planError}</div>}

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
                      {["Name", "Migration", "Progress", "Status", "Target Date"].map(h => <th key={h} style={th}>{h}</th>)}
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
                          <td style={td}>
                            <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 160 }}>
                              <div style={{ flex: 1, background: C.border, borderRadius: 99, height: 5, overflow: "hidden" }}>
                                <div style={{ width: `${pct}%`, background: pct === 100 ? C.green : C.accent, height: "100%", borderRadius: 99, transition: "width 0.5s ease" }} />
                              </div>
                              <span title={`${plan.remaining_keys} ${plan.from_algorithm} keys still live`} style={{ fontSize: 11, color: C.dim, fontFamily: "IBM Plex Mono, monospace", whiteSpace: "nowrap" }}>
                                {plan.completed_keys}/{plan.affected_keys} · {plan.remaining_keys} left
                              </span>
                            </div>
                          </td>
                          <td style={td}>
                            <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                              {planStatusIcon(plan.status)}
                              <select
                                value={plan.status}
                                onChange={e => handleStatus(plan, e.target.value as MigrationPlanStatus)}
                                style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 4, color: planStatusColor(plan.status), fontSize: 11, fontWeight: 600, padding: "2px 4px" }}
                              >
                                {PLAN_STATUSES.map(s => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
                              </select>
                            </div>
                          </td>
                          <td style={{ ...td, fontFamily: "IBM Plex Mono, monospace", fontSize: 11, color: C.dim }}>{plan.target_date ? plan.target_date.slice(0, 10) : "—"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
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
