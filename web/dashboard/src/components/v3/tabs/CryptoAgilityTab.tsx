import { useEffect, useState, type CSSProperties } from "react";
import {
  AlertTriangle, ArrowRight, Plus, RefreshCw, CheckCircle, Clock, Pause, Activity, XCircle,
  Atom, HelpCircle, KeyRound, CalendarClock, ShieldAlert, Pencil, Trash2, ListChecks,
} from "lucide-react";
import { C } from "../../v3/theme";
import { daysUntil, errText, inputStyle, labelStyle, Modal, StatCard } from "./agility/ui";
import { CarafPanel } from "./agility/CarafPanel";
import { PqcExecutionPanel } from "./agility/PqcExecutionPanel";
import {
  getAgilityPosture,
  listAgilityRules,
  createAgilityRule,
  updateAgilityRule,
  deleteAgilityRule,
  listMigrationPlans,
  createMigrationPlan,
  updateMigrationPlanStatus,
  ruleCovers,
  type AgilityPosture,
  type AgilityRule,
  type AlgorithmUsage,
  type MatchKind,
  type MigrationPlan,
  type MigrationPlanStatus,
  type NewAgilityRule,
  type NewMigrationPlan,
  type PolicyAction,
  type PolicyStatus,
} from "../../../lib/cryptoAgility";

// The customer decides what to migrate and when: every status and date on
// this tab comes from the tenant's own migration policy rules, which keycore
// enforces on every key operation. Counts come from the live keys, technical
// facts (strength, quantum vulnerability, weakness) from pkg/cryptocatalog.
// When keycore can't answer, the tab says so and shows the error; it never
// substitutes sample data (CLAUDE.md rules 7 and 8).

interface Props {
  session: any;
  enabledFeatures?: any;
  keyCatalog?: any[];
}

const PLAN_STATUSES: MigrationPlanStatus[] = ["planned", "in_progress", "paused", "completed"];
// Suggestions for a migration target: algorithms keycore generates.
const MIGRATION_TARGETS = ["ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s", "AES-256", "RSA-3072", "ECDSA-P384"];

const STATUS_LABEL: Record<PolicyStatus, string> = {
  allowed: "Allowed",
  deprecated: "Deprecated",
  decrypt_only: "Decrypt/verify only",
  disallowed: "Disallowed",
};
const ACTION_HELP: Record<PolicyAction, string> = {
  deprecated: "Keys keep working; they are flagged for migration.",
  decrypt_only: "New protection is refused (create, encrypt, sign, wrap, MAC, derive); decrypt, verify and unwrap keep working.",
  disallowed: "Every cryptographic operation is refused. The key can still be exported or destroyed.",
};
const MATCH_LABEL: Record<MatchKind, string> = {
  algorithm: "Specific algorithm",
  family: "Algorithm family",
  quantum_vulnerable: "Every quantum-vulnerable algorithm",
  weak: "Every weak algorithm",
  below_strength: "Everything below a strength",
};

function statusColor(s?: PolicyStatus): [string, string] {
  switch (s) {
    case "allowed": return [C.green, C.greenDim];
    case "deprecated": return [C.amber, C.amberDim];
    case "decrypt_only":
    case "disallowed": return [C.red, C.redDim];
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
function describeMatch(r: Pick<AgilityRule, "match_kind" | "match_value">) {
  switch (r.match_kind) {
    case "algorithm": return r.match_value || "";
    case "family": return `${r.match_value} family`;
    case "below_strength": return `below ${r.match_value}-bit`;
    default: return MATCH_LABEL[r.match_kind];
  }
}

/* ─── Sub-components ─────────────────────────────────────── */
function StatusBadge({ status }: { status?: PolicyStatus | undefined }) {
  if (!status) return <span style={{ color: C.muted, fontSize: 11 }}>—</span>;
  const [fg, bg] = statusColor(status);
  return <span style={{ background: bg, color: fg, padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600, whiteSpace: "nowrap" }}>{STATUS_LABEL[status]}</span>;
}

function Unavailable({ error, onRetry }: { error: string; onRetry: () => void }) {
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 28, display: "flex", gap: 14, alignItems: "flex-start" }}>
      <XCircle size={18} color={C.red} style={{ flexShrink: 0, marginTop: 2 }} />
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: C.text }}>Not assessed: crypto agility data is unavailable</div>
        <div style={{ fontSize: 12, color: C.dim, marginTop: 6 }}>
          keycore did not return the key inventory or migration policy, so no status, schedule or migration progress is shown.
        </div>
        <div style={{ fontSize: 11, color: C.red, marginTop: 8, fontFamily: "IBM Plex Mono, monospace", wordBreak: "break-word" }}>{error}</div>
        <button onClick={onRetry} style={{ marginTop: 14, background: C.card, border: `1px solid ${C.border}`, borderRadius: 7, color: C.dim, padding: "7px 13px", cursor: "pointer", fontSize: 12, display: "inline-flex", alignItems: "center", gap: 6 }}>
          <RefreshCw size={13} /> Retry
        </button>
      </div>
    </div>
  );
}

/* ─── Rule Modal ──────────────────────────────────────────── */
function RuleModal({ rule, algorithms, onClose, onSave }: {
  rule: AgilityRule | null;
  algorithms: AlgorithmUsage[];
  onClose: () => void;
  onSave: (data: NewAgilityRule) => Promise<void>;
}) {
  const [name, setName] = useState(rule?.name ?? "");
  const [kind, setKind] = useState<MatchKind>(rule?.match_kind ?? "algorithm");
  const [value, setValue] = useState(rule?.match_value ?? "");
  const [action, setAction] = useState<PolicyAction>(rule?.action ?? "decrypt_only");
  const [effective, setEffective] = useState(rule?.effective_date?.slice(0, 10) ?? "");
  const [target, setTarget] = useState(rule?.target_algorithm ?? "");
  const [note, setNote] = useState(rule?.note ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const needsValue = kind === "algorithm" || kind === "family" || kind === "below_strength";
  const valid = Boolean(name.trim() && effective && (!needsValue || value.trim()));
  const covered = algorithms.filter(a => ruleCovers({ match_kind: kind, match_value: value }, a));
  const coveredKeys = covered.reduce((n, a) => n + a.key_count, 0);
  const families = Array.from(new Set(algorithms.map(a => a.family).filter(Boolean))) as string[];
  const immediate = effective !== "" && daysUntil(effective) <= 0 && action !== "deprecated";

  async function handleSave() {
    if (!valid) return;
    setSaving(true);
    setError(null);
    try {
      const data: NewAgilityRule = { name: name.trim(), match_kind: kind, action, effective_date: effective };
      if (needsValue) data.match_value = value.trim();
      if (target.trim()) data.target_algorithm = target.trim();
      if (note.trim()) data.note = note.trim();
      await onSave(data);
      onClose();
    } catch (e) {
      setError(errText(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      title={rule ? "Edit migration rule" : "Add migration rule"}
      hint="You decide which algorithms to move off and from when. Keycore enforces the rule on every key operation from its effective date."
      onClose={onClose} onSave={handleSave} saving={saving} valid={valid} saveLabel={rule ? "Save rule" : "Add rule"}
    >
      <div>
        <div style={labelStyle}>Rule name</div>
        <input style={inputStyle} value={name} onChange={e => setName(e.target.value)} placeholder="e.g. RSA to ML-DSA" />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div>
          <div style={labelStyle}>Applies to</div>
          <select style={inputStyle} value={kind} onChange={e => { setKind(e.target.value as MatchKind); setValue(""); }}>
            {(Object.keys(MATCH_LABEL) as MatchKind[]).map(k => <option key={k} value={k}>{MATCH_LABEL[k]}</option>)}
          </select>
        </div>
        <div>
          <div style={labelStyle}>{kind === "below_strength" ? "Strength (bits)" : kind === "family" ? "Family" : kind === "algorithm" ? "Algorithm" : " "}</div>
          {kind === "algorithm" && (
            <>
              <input style={inputStyle} list="agility-algorithms" value={value} onChange={e => setValue(e.target.value)} placeholder="e.g. RSA-2048" />
              <datalist id="agility-algorithms">{algorithms.map(a => <option key={a.algorithm} value={a.algorithm} />)}</datalist>
            </>
          )}
          {kind === "family" && (
            <>
              <input style={inputStyle} list="agility-families" value={value} onChange={e => setValue(e.target.value)} placeholder="e.g. RSA" />
              <datalist id="agility-families">{families.map(f => <option key={f} value={f} />)}</datalist>
            </>
          )}
          {kind === "below_strength" && <input style={inputStyle} type="number" min={1} value={value} onChange={e => setValue(e.target.value)} placeholder="e.g. 128" />}
        </div>
      </div>
      <div style={{ fontSize: 11, color: C.muted }}>
        Covers {coveredKeys.toLocaleString()} live {coveredKeys === 1 ? "key" : "keys"} today{covered.length > 0 && <> ({covered.map(a => a.algorithm).join(", ")})</>}.
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div>
          <div style={labelStyle}>From this date</div>
          <select style={inputStyle} value={action} onChange={e => setAction(e.target.value as PolicyAction)}>
            <option value="deprecated">Deprecated</option>
            <option value="decrypt_only">Decrypt/verify only</option>
            <option value="disallowed">Disallowed</option>
          </select>
        </div>
        <div>
          <div style={labelStyle}>Effective date</div>
          <input type="date" style={inputStyle} value={effective} onChange={e => setEffective(e.target.value)} />
        </div>
      </div>
      <div style={{ fontSize: 11, color: C.muted }}>{ACTION_HELP[action]}</div>
      {immediate && (
        <div style={{ fontSize: 11, color: C.red }}>
          This takes effect immediately: operations on the {coveredKeys.toLocaleString()} covered {coveredKeys === 1 ? "key" : "keys"} will be refused as soon as the rule is saved.
        </div>
      )}
      <div>
        <div style={labelStyle}>Target algorithm (optional)</div>
        <input style={inputStyle} list="agility-rule-targets" value={target} onChange={e => setTarget(e.target.value)} placeholder="e.g. ML-DSA-65" />
        <datalist id="agility-rule-targets">{MIGRATION_TARGETS.map(a => <option key={a} value={a} />)}</datalist>
      </div>
      <div>
        <div style={labelStyle}>Note (optional)</div>
        <input style={inputStyle} value={note} onChange={e => setNote(e.target.value)} placeholder="e.g. per security board decision 2026-09" />
      </div>
      {error && <div style={{ fontSize: 12, color: C.red }}>Rule not saved: {error}</div>}
    </Modal>
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
  const policyDate = source?.next_change?.date;

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

  return (
    <Modal
      title="Create Migration Plan"
      hint="Affected keys are counted by keycore when the plan is created; progress is measured as keys leave the source algorithm."
      onClose={onClose} onSave={handleSave} saving={saving} valid={valid} saveLabel="Create Plan"
    >
      <div>
        <div style={labelStyle}>Plan Name</div>
        <input style={inputStyle} value={name} onChange={e => setName(e.target.value)} placeholder="e.g. RSA-2048 PQC Migration" />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div>
          <div style={labelStyle}>From Algorithm (in use)</div>
          <select style={inputStyle} value={from} onChange={e => { setFrom(e.target.value); const a = algorithms.find(x => x.algorithm === e.target.value); if (a?.target_algorithm && !to) setTo(a.target_algorithm); }}>
            <option value="">Select…</option>
            {algorithms.map(a => <option key={a.algorithm} value={a.algorithm}>{a.algorithm} ({a.key_count})</option>)}
          </select>
        </div>
        <div>
          <div style={labelStyle}>To Algorithm</div>
          <input style={inputStyle} list="agility-targets" value={to} onChange={e => setTo(e.target.value)} placeholder="e.g. ML-KEM-768" />
          <datalist id="agility-targets">{MIGRATION_TARGETS.map(a => <option key={a} value={a} />)}</datalist>
        </div>
      </div>
      <div>
        <div style={labelStyle}>Target Date (optional)</div>
        <input type="date" style={inputStyle} value={targetDate} onChange={e => setTargetDate(e.target.value)} />
        {policyDate && source?.next_change && (
          <div style={{ fontSize: 10, color: C.muted, marginTop: 4 }}>
            Your rule "{source.next_change.rule_name}" makes {from} {STATUS_LABEL[source.next_change.action].toLowerCase()} from {policyDate}.
          </div>
        )}
      </div>
      {error && <div style={{ fontSize: 12, color: C.red }}>Plan not created: {error}</div>}
    </Modal>
  );
}

/* ─── Main Component ─────────────────────────────────────── */
type View = "policy" | "risk" | "execution";
const VIEWS: [View, string][] = [["policy", "Migration policy"], ["risk", "Risk assessment"], ["execution", "Readiness & execution"]];

export function CryptoAgilityTab({ session, keyCatalog }: Props) {
  const [view, setView] = useState<View>("policy");
  const [posture, setPosture] = useState<AgilityPosture | null>(null);
  const [rules, setRules] = useState<AgilityRule[]>([]);
  const [plans, setPlans] = useState<MigrationPlan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [showPlanModal, setShowPlanModal] = useState(false);
  const [ruleModal, setRuleModal] = useState<{ rule: AgilityRule | null } | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  async function load(silent = false) {
    if (!silent) setLoading(true);
    else setRefreshing(true);
    setError(null);
    setActionError(null);
    try {
      const [p, r, mp] = await Promise.all([getAgilityPosture(session), listAgilityRules(session), listMigrationPlans(session)]);
      setPosture(p); setRules(r); setPlans(mp);
    } catch (e) {
      setPosture(null); setRules([]); setPlans([]);
      setError(errText(e));
    } finally {
      setLoading(false); setRefreshing(false);
    }
  }

  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
  useEffect(() => { load(); }, []);

  async function handleSaveRule(existing: AgilityRule | null, data: NewAgilityRule) {
    if (existing) await updateAgilityRule(session, existing.id, data); // errors surface in the modal
    else await createAgilityRule(session, data);
    await load(true);
  }

  async function handleDeleteRule(rule: AgilityRule) {
    if (!window.confirm(`Delete the rule "${rule.name}"? Keys it covers stop being restricted by it immediately.`)) return;
    setActionError(null);
    try {
      await deleteAgilityRule(session, rule.id);
      await load(true);
    } catch (e) {
      setActionError(`${rule.name}: ${errText(e)}`);
    }
  }

  async function handleCreatePlan(data: NewMigrationPlan) {
    const plan = await createMigrationPlan(session, data);
    setPlans(prev => [plan, ...prev]);
  }

  async function handleStatus(plan: MigrationPlan, status: MigrationPlanStatus) {
    setActionError(null);
    try {
      const updated = await updateMigrationPlanStatus(session, plan.id, status);
      setPlans(prev => prev.map(p => (p.id === updated.id ? updated : p)));
    } catch (e) {
      setActionError(`${plan.name}: ${errText(e)}`);
    }
  }

  const algorithms = posture?.algorithms ?? [];
  const counts = posture?.status_counts ?? {};
  const refusedNow = (counts.decrypt_only ?? 0) + (counts.disallowed ?? 0);
  const pct = (n: number) => posture && posture.total_keys > 0 ? `${Math.round((n / posture.total_keys) * 100)}% of live keys` : "";
  const coveredCount = (r: AgilityRule) => algorithms.filter(a => ruleCovers(r, a)).reduce((n, a) => n + a.key_count, 0);

  const divider: CSSProperties = { borderTop: `1px solid ${C.border}`, margin: "24px 0" };
  const sectionTitle: CSSProperties = { fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 4 };
  const sectionHint: CSSProperties = { fontSize: 11, color: C.muted, marginBottom: 12 };
  const panel: CSSProperties = { background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" };
  const empty: CSSProperties = { ...panel, padding: 28, textAlign: "center", color: C.muted, fontSize: 13 };
  const th: CSSProperties = { textAlign: "left", fontSize: 10, color: C.muted, fontWeight: 600, padding: "8px 12px", textTransform: "uppercase", letterSpacing: "0.06em", whiteSpace: "nowrap" };
  const td: CSSProperties = { padding: "10px 12px", fontSize: 12, color: C.text, verticalAlign: "middle" };
  const mono: CSSProperties = { fontFamily: "IBM Plex Mono, monospace", fontSize: 12 };
  const smallBtn: CSSProperties = { background: "transparent", border: `1px solid ${C.border}`, borderRadius: 5, color: C.dim, padding: "3px 7px", cursor: "pointer", display: "inline-flex", alignItems: "center" };

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
            You decide which algorithms to move off and when; keycore enforces your rules on every key operation. Assess the risk of your systems, then plan and execute the migration.
            {posture?.as_of && <> Statuses as of {posture.as_of}.</>}
          </div>
        </div>
        {view === "policy" && <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button onClick={() => load(true)} disabled={refreshing} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 7, color: C.dim, padding: "7px 13px", cursor: "pointer", fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}>
            <RefreshCw size={13} style={refreshing ? { animation: "spin 1s linear infinite" } : {}} /> Refresh
          </button>
          <button onClick={() => setRuleModal({ rule: null })} disabled={Boolean(error)} style={{ background: C.card, border: `1px solid ${C.accent}`, borderRadius: 7, color: C.accent, padding: "7px 13px", cursor: error ? "not-allowed" : "pointer", fontSize: 12, fontWeight: 600, display: "flex", alignItems: "center", gap: 6, opacity: error ? 0.5 : 1 }}>
            <ListChecks size={13} /> Add Migration Rule
          </button>
          <button onClick={() => setShowPlanModal(true)} disabled={Boolean(error)} style={{ background: C.accent, border: "none", borderRadius: 7, color: C.bg, padding: "7px 14px", cursor: error ? "not-allowed" : "pointer", fontSize: 12, fontWeight: 600, display: "flex", alignItems: "center", gap: 6, opacity: error ? 0.5 : 1 }}>
            <Plus size={13} /> Create Migration Plan
          </button>
        </div>}
      </div>

      <div role="tablist" style={{ display: "flex", gap: 4, marginBottom: 20, borderBottom: `1px solid ${C.border}` }}>
        {VIEWS.map(([id, label]) => (
          <button key={id} role="tab" aria-selected={view === id} onClick={() => setView(id)}
            style={{ background: "transparent", border: "none", borderBottom: `2px solid ${view === id ? C.accent : "transparent"}`, color: view === id ? C.text : C.dim, padding: "8px 14px", cursor: "pointer", fontSize: 13, fontWeight: view === id ? 600 : 400 }}>
            {label}
          </button>
        ))}
      </div>

      {view === "risk" ? <CarafPanel session={session} keyCatalog={Array.isArray(keyCatalog) ? keyCatalog : []} />
      : view === "execution" ? <PqcExecutionPanel session={session} />
      : error || !posture ? (
        <Unavailable error={error ?? "no data returned"} onRetry={() => load()} />
      ) : (
        <>
          {!posture.assessed ? (
            <div style={empty}>Not assessed: there are no live keys to measure yet. You can still define your migration policy below.</div>
          ) : (
            <>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                <StatCard icon={<KeyRound size={16} />} label="Live keys" value={posture.total_keys.toLocaleString()} sub={`${algorithms.length} algorithms`} />
                <StatCard icon={<AlertTriangle size={16} />} label="Quantum-vulnerable" value={posture.quantum_vulnerable_keys.toLocaleString()} sub={`${pct(posture.quantum_vulnerable_keys)} · RSA, ECC, DH`} color={C.amber} bg={C.amberTint} />
                <StatCard icon={<Atom size={16} />} label="Post-quantum" value={posture.post_quantum_keys.toLocaleString()} sub="ML-KEM, ML-DSA, SLH-DSA" color={C.green} bg={C.greenTint} />
                <StatCard icon={<ShieldAlert size={16} />} label="Not covered by a rule" value={posture.uncovered_keys.toLocaleString()} sub={`weak or quantum-vulnerable · ${posture.weak_keys.toLocaleString()} weak`} color={C.red} bg={C.redTint} />
                <StatCard icon={<XCircle size={16} />} label="Restricted by your policy" value={refusedNow.toLocaleString()} sub="decrypt/verify only or disallowed" color={C.purple} bg={C.purpleTint} />
                <StatCard icon={<HelpCircle size={16} />} label="Not assessed" value={posture.not_assessed_keys.toLocaleString()} sub="name states no parameter set" color={C.dim} bg={C.dimTint} />
              </div>

              {posture.findings.length > 0 && (
                <div style={{ marginTop: 16, ...panel, padding: "14px 18px" }}>
                  <div style={{ fontSize: 11, color: C.muted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>Findings</div>
                  {posture.findings.map(f => <div key={f} style={{ fontSize: 12, color: C.dim, marginTop: 4 }}>• {f}</div>)}
                </div>
              )}
            </>
          )}

          {actionError && <div style={{ fontSize: 12, color: C.red, marginTop: 14 }}>Not changed: {actionError}</div>}
          <div style={divider} />

          {/* Policy */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={sectionTitle}>Your migration policy</div>
            <span style={{ fontSize: 11, color: C.muted }}>{rules.length} {rules.length === 1 ? "rule" : "rules"}</span>
          </div>
          <div style={sectionHint}>
            Each rule applies from its effective date to every key operation. To require post-quantum algorithms for new protection, add a "every quantum-vulnerable algorithm → decrypt/verify only" rule.
          </div>
          {rules.length === 0 ? (
            <div style={empty}>No migration rules yet. Add one to decide when keys on an algorithm become deprecated, decrypt/verify only or disallowed.</div>
          ) : (
            <div style={panel}>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                      {["Rule", "Applies to", "Becomes", "Effective", "Target", "Covers", ""].map(h => <th key={h} style={th}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {rules.map((r, i) => {
                      const d = daysUntil(r.effective_date);
                      return (
                        <tr key={r.id} style={{ borderBottom: i < rules.length - 1 ? `1px solid ${C.border}` : "none" }}>
                          <td style={td}><span style={{ fontWeight: 600 }}>{r.name}</span>{r.note && <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{r.note}</div>}</td>
                          <td style={{ ...td, ...mono, fontSize: 11 }}>{describeMatch(r)}</td>
                          <td style={td}><StatusBadge status={r.action} /></td>
                          <td style={{ ...td, whiteSpace: "nowrap" }}>
                            <span style={mono}>{r.effective_date.slice(0, 10)}</span>
                            <div style={{ fontSize: 10, color: d <= 0 ? C.red : C.muted, marginTop: 2 }}>{d <= 0 ? "in force" : `in ${d.toLocaleString()} days`}</div>
                          </td>
                          <td style={{ ...td, ...mono, fontSize: 11 }}>{r.target_algorithm || "—"}</td>
                          <td style={{ ...td, ...mono }}>{coveredCount(r).toLocaleString()}</td>
                          <td style={{ ...td, whiteSpace: "nowrap" }}>
                            <button aria-label={`Edit ${r.name}`} onClick={() => setRuleModal({ rule: r })} style={smallBtn}><Pencil size={12} /></button>{" "}
                            <button aria-label={`Delete ${r.name}`} onClick={() => handleDeleteRule(r)} style={smallBtn}><Trash2 size={12} /></button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {posture.assessed && (
            <>
              <div style={divider} />

              {/* Schedule */}
              <div style={sectionTitle}>Your migration schedule</div>
              <div style={sectionHint}>Upcoming steps of your policy that reach your live keys.</div>
              {posture.milestones.length === 0 ? (
                <div style={empty}>No upcoming rule reaches your live keys.</div>
              ) : (
                <div style={panel}>
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                          {["Effective", "Becomes", "Live keys", "Algorithms", "Rule", "Target"].map(h => <th key={h} style={th}>{h}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {posture.milestones.map((m, i) => (
                          <tr key={m.rule_id} style={{ borderBottom: i < posture.milestones.length - 1 ? `1px solid ${C.border}` : "none" }}>
                            <td style={td}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6 }}><CalendarClock size={13} color={C.dim} /><span style={mono}>{m.date}</span></div>
                              <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>in {daysUntil(m.date).toLocaleString()} days</div>
                            </td>
                            <td style={td}><StatusBadge status={m.action} /></td>
                            <td style={{ ...td, ...mono }}>{m.key_count.toLocaleString()}</td>
                            <td style={{ ...td, ...mono, fontSize: 11 }}>{m.algorithms.join(", ")}</td>
                            <td style={{ ...td, fontSize: 11, color: C.dim }}>{m.rule_name}</td>
                            <td style={{ ...td, ...mono, fontSize: 11 }}>{m.target_algorithm || "—"}</td>
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
              <div style={sectionHint}>Strength is the classical security strength in bits; category is the post-quantum security category (1–5).</div>
              <div style={panel}>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                        {["Algorithm", "Live keys", "Share", "Strength", "PQC category", "Quantum", "Your policy today", "Next change", "Target"].map(h => <th key={h} style={th}>{h}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {algorithms.map((a, i) => (
                        <tr key={a.algorithm} style={{ borderBottom: i < algorithms.length - 1 ? `1px solid ${C.border}` : "none" }}>
                          <td style={td}>
                            <span style={{ ...mono, fontWeight: 600 }}>{a.algorithm}</span>
                            {a.weak && <span style={{ marginLeft: 6, fontSize: 10, fontWeight: 600, color: C.red }}>WEAK</span>}
                            {!a.assessed && <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>not assessed: no parameter set in the name</div>}
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
                                  : a.pqc_category ? <span style={{ color: C.dim, fontSize: 11 }}>Resistant</span>
                                    : <span style={{ color: C.muted, fontSize: 11 }}>—</span>}
                          </td>
                          <td style={td}>
                            <StatusBadge status={a.policy_status} />
                            {a.policy_rule && <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{a.policy_rule}</div>}
                          </td>
                          <td style={{ ...td, fontSize: 11, color: C.dim, whiteSpace: "nowrap" }}>
                            {a.next_change ? <><StatusBadge status={a.next_change.action} /> <span style={{ ...mono, fontSize: 11 }}>from {a.next_change.date}</span></> : "—"}
                          </td>
                          <td style={{ ...td, ...mono, fontSize: 11, whiteSpace: "nowrap" }}>{a.target_algorithm || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}

          <div style={divider} />

          {/* Migration Plans */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
            <div style={sectionTitle}>Migration Plans</div>
            <span style={{ fontSize: 11, color: C.muted }}>{plans.length} total</span>
          </div>
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
        </>
      )}

      {ruleModal && (
        <RuleModal
          rule={ruleModal.rule}
          algorithms={algorithms}
          onClose={() => setRuleModal(null)}
          onSave={data => handleSaveRule(ruleModal.rule, data)}
        />
      )}
      {showPlanModal && (
        <CreatePlanModal algorithms={algorithms} onClose={() => setShowPlanModal(false)} onSave={handleCreatePlan} />
      )}
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
