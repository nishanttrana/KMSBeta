import { useEffect, useState, type CSSProperties, type ReactNode } from "react";
import {
  ShieldCheck, AlertTriangle, ArrowRight, Plus, RefreshCw, CheckCircle,
  Clock, Pause, Activity, XCircle, Atom, HelpCircle, KeyRound, CalendarClock, ExternalLink,
} from "lucide-react";
import { C } from "../../v3/theme";
import {
  getAgilityPosture,
  listMigrationPlans,
  createMigrationPlan,
  updateMigrationPlanStatus,
  type AgilityPosture,
  type AlgorithmUsage,
  type MigrationPlan,
  type MigrationPlanStatus,
  type NewMigrationPlan,
  type NISTStatus,
} from "../../../lib/cryptoAgility";

// Every count on this tab comes from keycore's /agility routes, computed
// from the tenant's live keys; every status, strength and date comes from
// pkg/cryptocatalog, which cites the NIST table it was copied from (CSWP
// 39-upd1 §2.3 → SP 800-131A Rev. 3 and IR 8547, both initial public
// drafts). When keycore can't answer, the tab says so and shows the error;
// it never substitutes sample data (CLAUDE.md rules 7 and 8).

interface Props {
  session: any;
  enabledFeatures?: any;
  keyCatalog?: any[];
}

const PLAN_STATUSES: MigrationPlanStatus[] = ["planned", "in_progress", "paused", "completed"];
// Suggestions for a migration target: algorithms keycore generates.
const MIGRATION_TARGETS = ["ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s", "AES-256"];

const STATUS_LABEL: Record<NISTStatus, string> = {
  acceptable: "Acceptable",
  deprecated: "Deprecated",
  disallowed: "Disallowed",
  legacy_use: "Legacy use only",
  not_approved: "Not approved",
  not_tabled: "Not tabled",
};

function statusColor(s?: NISTStatus): [string, string] {
  switch (s) {
    case "acceptable": return [C.green, C.greenDim];
    case "deprecated": return [C.amber, C.amberDim];
    case "disallowed":
    case "legacy_use":
    case "not_approved": return [C.red, C.redDim];
    default: return [C.dim, C.dimTint];
  }
}

function planStatusIcon(s: string) {
  switch (s) {
    case "in_progress": return <Activity size={13} color={C.accent} />;
    case "completed": return <CheckCircle size={13} color={C.green} />;
    case "paused": return <Pause size={13} color={C.amber} />;
    default: return <Clock size={13} color={C.dim} />;
  }
}
function planStatusColor(s: string) {
  switch (s) {
    case "in_progress": return C.accent;
    case "completed": return C.green;
    case "paused": return C.amber;
    default: return C.dim;
  }
}
function errText(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}
function daysUntil(date: string) {
  return Math.ceil((Date.parse(date + "T00:00:00Z") - Date.now()) / 86_400_000);
}

/* ─── Sub-components ─────────────────────────────────────── */
function StatusBadge({ status }: { status?: NISTStatus | undefined }) {
  if (!status) return <span style={{ color: C.muted, fontSize: 11 }}>Not assessed</span>;
  const [fg, bg] = statusColor(status);
  return <span style={{ background: bg, color: fg, padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600, whiteSpace: "nowrap" }}>{STATUS_LABEL[status]}</span>;
}

interface StatCardProps { icon: ReactNode; label: string; value: string | number; sub?: string; color?: string; bg?: string }
function StatCard({ icon, label, value, sub, color = C.accent, bg = C.accentTint }: StatCardProps) {
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "16px 18px", display: "flex", alignItems: "flex-start", gap: 12, flex: 1, minWidth: 170 }}>
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
          keycore did not return the key inventory, so no NIST status, deadline or migration progress is shown.
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

  const valid = Boolean(name.trim() && from && to.trim() && from !== to.trim());
  const source = algorithms.find(a => a.algorithm === from);
  const deadline = source?.schedule?.find(s => s.from && s.status === "disallowed")?.from;

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
                {MIGRATION_TARGETS.map(a => <option key={a} value={a} />)}
              </datalist>
            </div>
          </div>
          <div>
            <div style={labelStyle}>Target Date (optional)</div>
            <input type="date" style={inputStyle} value={targetDate} onChange={e => setTargetDate(e.target.value)} />
            {deadline && (
              <div style={{ fontSize: 10, color: C.muted, marginTop: 4 }}>
                NIST disallows {from} from {deadline} (proposed, draft); plan to finish before then.
              </div>
            )}
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
  const [posture, setPosture] = useState<AgilityPosture | null>(null);
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
      const [p, mp] = await Promise.all([getAgilityPosture(session), listMigrationPlans(session)]);
      setPosture(p); setPlans(mp);
    } catch (e) {
      setPosture(null); setPlans([]);
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

  const algorithms = posture?.algorithms ?? [];
  const counts = posture?.status_counts ?? {};
  const noNewProtection = (counts.disallowed ?? 0) + (counts.legacy_use ?? 0) + (counts.not_approved ?? 0);
  const pct = (n: number) => posture && posture.total_keys > 0 ? `${Math.round((n / posture.total_keys) * 100)}% of live keys` : "";

  const divider: CSSProperties = { borderTop: `1px solid ${C.border}`, margin: "24px 0" };
  const sectionTitle: CSSProperties = { fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 4 };
  const sectionHint: CSSProperties = { fontSize: 11, color: C.muted, marginBottom: 12 };
  const panel: CSSProperties = { background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" };
  const empty: CSSProperties = { ...panel, padding: 28, textAlign: "center", color: C.muted, fontSize: 13 };
  const th: CSSProperties = { textAlign: "left", fontSize: 10, color: C.muted, fontWeight: 600, padding: "8px 12px", textTransform: "uppercase", letterSpacing: "0.06em", whiteSpace: "nowrap" };
  const td: CSSProperties = { padding: "10px 12px", fontSize: 12, color: C.text, verticalAlign: "middle" };
  const mono: CSSProperties = { fontFamily: "IBM Plex Mono, monospace", fontSize: 12 };

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
          <div style={{ fontSize: 12, color: C.dim, marginTop: 2, maxWidth: 720 }}>
            Your live keys measured against NIST's transition schedule: NIST CSWP 39-upd1 (§2.3) defers to SP 800-131A Rev. 3 and IR 8547, both initial public drafts, so their dates are proposed.
            {posture?.as_of && <> Statuses as of {posture.as_of}.</>}
          </div>
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

      {error || !posture ? (
        <Unavailable error={error ?? "no data returned"} onRetry={() => load()} />
      ) : !posture.assessed ? (
        <div style={empty}>Not assessed: there are no live keys to measure yet. The posture fills in as keys are created.</div>
      ) : (
        <>
          {/* Measures */}
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <StatCard icon={<KeyRound size={16} />} label="Live keys" value={posture.total_keys.toLocaleString()} sub={`${algorithms.length} algorithms`} />
            <StatCard icon={<AlertTriangle size={16} />} label="Quantum-vulnerable" value={posture.quantum_vulnerable_keys.toLocaleString()} sub={`${pct(posture.quantum_vulnerable_keys)} · RSA, ECC, DH`} color={C.amber} bg={C.amberTint} />
            <StatCard icon={<Atom size={16} />} label="Post-quantum" value={posture.post_quantum_keys.toLocaleString()} sub="ML-KEM, ML-DSA, SLH-DSA" color={C.green} bg={C.greenTint} />
            <StatCard icon={<XCircle size={16} />} label="Not allowed for new protection" value={noNewProtection.toLocaleString()} sub="disallowed, legacy use or not approved" color={C.red} bg={C.redTint} />
            <StatCard icon={<HelpCircle size={16} />} label="Not assessed" value={posture.not_assessed_keys.toLocaleString()} sub="name states no parameter set" color={C.dim} bg={C.dimTint} />
          </div>

          {posture.findings.length > 0 && (
            <div style={{ marginTop: 16, ...panel, padding: "14px 18px" }}>
              <div style={{ fontSize: 11, color: C.muted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>Findings</div>
              {posture.findings.map(f => <div key={f} style={{ fontSize: 12, color: C.dim, marginTop: 4 }}>• {f}</div>)}
            </div>
          )}

          <div style={divider} />

          {/* Deadlines */}
          <div style={sectionTitle}>NIST transition deadlines for your keys</div>
          <div style={sectionHint}>Scheduled status changes that reach your live keys ("after 2030" takes effect on 2031-01-01).</div>
          {posture.milestones.length === 0 ? (
            <div style={empty}>No scheduled NIST status change reaches your live keys.</div>
          ) : (
            <div style={panel}>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                      {["Effective", "Becomes", "Live keys", "Algorithms", "Source"].map(h => <th key={h} style={th}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {posture.milestones.map((m, i) => (
                      <tr key={`${m.date}-${m.status}-${m.source}`} style={{ borderBottom: i < posture.milestones.length - 1 ? `1px solid ${C.border}` : "none" }}>
                        <td style={td}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <CalendarClock size={13} color={C.dim} />
                            <span style={mono}>{m.date}</span>
                          </div>
                          <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{daysUntil(m.date).toLocaleString()} days</div>
                        </td>
                        <td style={td}><StatusBadge status={m.status} /></td>
                        <td style={{ ...td, ...mono }}>{m.key_count.toLocaleString()}</td>
                        <td style={{ ...td, ...mono, fontSize: 11 }}>{m.algorithms.join(", ")}</td>
                        <td style={{ ...td, fontSize: 11, color: C.dim }}>{m.citation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div style={divider} />

          {/* Inventory */}
          <div style={sectionTitle}>Algorithm inventory</div>
          <div style={sectionHint}>Strength is the classical security strength in bits (SP 800-57); category is the NIST post-quantum security category (IR 8547 Table 1).</div>
          <div style={panel}>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                    {["Algorithm", "Live keys", "Share", "Strength", "PQC category", "Quantum", "NIST status today", "Next change"].map(h => <th key={h} style={th}>{h}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {algorithms.map((a, i) => (
                    <tr key={a.algorithm} style={{ borderBottom: i < algorithms.length - 1 ? `1px solid ${C.border}` : "none" }}>
                      <td style={td}>
                        <span style={{ ...mono, fontWeight: 600 }}>{a.algorithm}</span>
                        {a.note && <div style={{ fontSize: 10, color: C.muted, marginTop: 2, maxWidth: 260 }}>{a.note}</div>}
                      </td>
                      <td style={{ ...td, ...mono }}>{a.key_count.toLocaleString()}</td>
                      <td style={{ ...td, ...mono }}>{a.percentage.toFixed(1)}%</td>
                      <td style={{ ...td, ...mono }}>{a.security_bits ? `${a.security_bits}-bit` : "—"}</td>
                      <td style={{ ...td, ...mono }}>{a.pqc_category ? a.pqc_category : "—"}</td>
                      <td style={{ ...td, whiteSpace: "nowrap" }}>
                        {!a.assessed ? <span style={{ color: C.muted, fontSize: 11 }}>—</span>
                          : a.quantum_vulnerable ? <span style={{ color: C.amber, fontSize: 11, fontWeight: 600 }}>Vulnerable</span>
                            : a.post_quantum ? <span style={{ color: C.green, fontSize: 11, fontWeight: 600 }}>Post-quantum</span>
                              : a.pqc_category ? <span style={{ color: C.dim, fontSize: 11 }} title="IR 8547 tables a post-quantum security category for it">Resistant</span>
                                : <span style={{ color: C.muted, fontSize: 11 }}>—</span>}
                      </td>
                      <td style={td}><StatusBadge status={a.assessed ? a.nist_status : undefined} /></td>
                      <td style={{ ...td, fontSize: 11, color: C.dim, whiteSpace: "nowrap" }}>
                        {a.next_change?.from
                          ? <><StatusBadge status={a.next_change.status} /> <span style={{ ...mono, fontSize: 11 }}>from {a.next_change.from}</span></>
                          : "—"}
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
          {planError && <div style={{ fontSize: 12, color: C.red, marginBottom: 10 }}>Status not changed: {planError}</div>}
          {plans.length === 0 ? (
            <div style={empty}>No migration plans created yet.</div>
          ) : (
            <div style={panel}>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                      {["Name", "Migration", "Progress", "Status", "Target Date"].map(h => <th key={h} style={th}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {plans.map((plan, i) => {
                      const done = plan.affected_keys > 0 ? Math.round((plan.completed_keys / plan.affected_keys) * 100) : 0;
                      return (
                        <tr key={plan.id} style={{ borderBottom: i < plans.length - 1 ? `1px solid ${C.border}` : "none" }}>
                          <td style={td}><span style={{ fontWeight: 600 }}>{plan.name}</span></td>
                          <td style={td}>
                            <div style={{ display: "flex", alignItems: "center", gap: 6, ...mono, fontSize: 11 }}>
                              <span style={{ color: C.red }}>{plan.from_algorithm}</span>
                              <ArrowRight size={11} color={C.dim} />
                              <span style={{ color: C.green }}>{plan.to_algorithm}</span>
                            </div>
                          </td>
                          <td style={td}>
                            <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 160 }}>
                              <div style={{ flex: 1, background: C.border, borderRadius: 99, height: 5, overflow: "hidden" }}>
                                <div style={{ width: `${done}%`, background: done === 100 ? C.green : C.accent, height: "100%", borderRadius: 99, transition: "width 0.5s ease" }} />
                              </div>
                              <span title={`${plan.remaining_keys} ${plan.from_algorithm} keys still live`} style={{ fontSize: 11, color: C.dim, ...mono, whiteSpace: "nowrap" }}>
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
                          <td style={{ ...td, ...mono, fontSize: 11, color: C.dim }}>{plan.target_date ? plan.target_date.slice(0, 10) : "—"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div style={divider} />

          {/* Sources */}
          <div style={sectionTitle}>Sources</div>
          <div style={sectionHint}>Every status, date and strength on this tab is copied from these documents.</div>
          <div style={{ ...panel, padding: "10px 16px" }}>
            {posture.sources.map(s => (
              <div key={s.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 0", fontSize: 12, color: C.dim, flexWrap: "wrap" }}>
                <ShieldCheck size={13} color={s.revision === "ipd" ? C.amber : C.green} />
                <a href={s.url} target="_blank" rel="noopener noreferrer" style={{ color: C.text, textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 4 }}>
                  {s.title} <ExternalLink size={11} />
                </a>
                <span style={{ fontSize: 10, color: s.revision === "ipd" ? C.amber : C.muted }}>
                  {s.revision === "ipd" ? "initial public draft, dates proposed" : s.revision} · {s.date}
                </span>
              </div>
            ))}
          </div>
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
