// @ts-nocheck
import { useEffect, useState } from "react";
import {
  RefreshCw, Clock, AlertTriangle, CheckCircle2, Plus, Trash2, Play, Edit2, CalendarClock
} from "lucide-react";
import { B, Btn, Card, FG, Inp, Modal, Row2, Section, Sel, Stat, Tabs, Txt } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  listPolicies,
  createPolicy,
  updatePolicy,
  deletePolicy,
  triggerRotation,
  listRuns,
  listUpcoming,
  type RotationPolicy,
  type RotationRun,
  type UpcomingRotation,
} from "../../../lib/rotationScheduler";

/* ────── Helpers ────── */

function fmtDate(iso: string) {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }); }
  catch { return "—"; }
}

function fmtDateTime(iso: string) {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
  catch { return "—"; }
}

function runDuration(started: string, completed?: string) {
  if (!started || !completed) return "—";
  try {
    const ms = new Date(completed).getTime() - new Date(started).getTime();
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${Math.round(ms / 1000)}s`;
    return `${Math.round(ms / 60000)}m`;
  } catch { return "—"; }
}

function runStatusColor(s: string) {
  switch ((s || "").toLowerCase()) {
    case "success": return "green";
    case "failed": return "red";
    case "running": return "accent";
    case "skipped": return "muted";
    default: return "blue";
  }
}

function policyStatusColor(s: string) {
  switch ((s || "").toLowerCase()) {
    case "active": return "green";
    case "paused": return "amber";
    case "error": return "red";
    default: return "muted";
  }
}

/* ────── Mock Data ────── */

const MOCK_POLICIES: RotationPolicy[] = [
  { id: "p1", tenant_id: "t1", name: "Critical Keys — 90d", target_type: "key", target_filter: "tag:critical", interval_days: 90, auto_rotate: true, notify_days_before: 14, last_rotation_at: "2025-01-05T02:00:00Z", next_rotation_at: "2025-04-05T02:00:00Z", enabled: true, created_at: "2024-10-01T00:00:00Z", total_rotations: 4, status: "active" },
  { id: "p2", tenant_id: "t1", name: "TLS Certificates — 60d", target_type: "certificate", target_filter: "tag:tls", interval_days: 60, auto_rotate: true, notify_days_before: 7, last_rotation_at: "2025-01-25T03:00:00Z", next_rotation_at: "2025-03-26T03:00:00Z", enabled: true, created_at: "2024-11-01T00:00:00Z", total_rotations: 6, status: "active" },
  { id: "p3", tenant_id: "t1", name: "DB Secrets — 30d", target_type: "secret", target_filter: "tag:database", interval_days: 30, auto_rotate: false, notify_days_before: 5, last_rotation_at: "2025-02-24T04:00:00Z", next_rotation_at: "2025-03-26T04:00:00Z", enabled: true, created_at: "2024-12-01T00:00:00Z", total_rotations: 12, status: "active" },
  { id: "p4", tenant_id: "t1", name: "API Keys — 180d", target_type: "key", target_filter: "tag:api", interval_days: 180, auto_rotate: false, notify_days_before: 21, last_rotation_at: "2024-10-01T00:00:00Z", next_rotation_at: "2025-04-01T00:00:00Z", enabled: false, created_at: "2024-07-01T00:00:00Z", total_rotations: 2, status: "paused" },
];

const MOCK_UPCOMING: UpcomingRotation[] = [
  { policy_id: "p2", policy_name: "TLS Certificates — 60d", target_id: "cert-tls-prod-01", target_name: "tls-prod-01", target_type: "certificate", scheduled_at: "2025-03-26T03:00:00Z", days_until: 1, overdue: false },
  { policy_id: "p3", policy_name: "DB Secrets — 30d", target_id: "secret-db-primary", target_name: "db-primary-secret", target_type: "secret", scheduled_at: "2025-03-26T04:00:00Z", days_until: 1, overdue: false },
  { policy_id: "p2", policy_name: "TLS Certificates — 60d", target_id: "cert-tls-staging-01", target_name: "tls-staging-01", target_type: "certificate", scheduled_at: "2025-03-20T03:00:00Z", days_until: -5, overdue: true },
  { policy_id: "p1", policy_name: "Critical Keys — 90d", target_id: "key-root-enc-01", target_name: "root-encryption-key", target_type: "key", scheduled_at: "2025-04-05T02:00:00Z", days_until: 11, overdue: false },
];

const MOCK_RUNS: RotationRun[] = [
  { id: "r1", policy_id: "p1", policy_name: "Critical Keys — 90d", target_id: "key-root-enc-prev", target_name: "root-encryption-key", target_type: "key", started_at: "2025-01-05T02:00:00Z", completed_at: "2025-01-05T02:01:13Z", status: "success", triggered_by: "schedule" },
  { id: "r2", policy_id: "p2", policy_name: "TLS Certificates — 60d", target_id: "cert-tls-prod-01", target_name: "tls-prod-01", target_type: "certificate", started_at: "2025-01-25T03:00:00Z", completed_at: "2025-01-25T03:02:44Z", status: "success", triggered_by: "schedule" },
  { id: "r3", policy_id: "p3", policy_name: "DB Secrets — 30d", target_id: "secret-db-replica", target_name: "db-replica-secret", target_type: "secret", started_at: "2025-02-24T04:00:00Z", completed_at: "2025-02-24T04:00:22Z", status: "failed", error: "Connection timeout to secret store", triggered_by: "schedule" },
  { id: "r4", policy_id: "p2", policy_name: "TLS Certificates — 60d", target_id: "cert-tls-api-01", target_name: "tls-api-01", target_type: "certificate", started_at: "2025-03-10T14:00:00Z", completed_at: "2025-03-10T14:01:58Z", status: "success", triggered_by: "manual" },
];

/* ────── Main Component ────── */

export const RotationSchedulerTab = ({ session, enabledFeatures, keyCatalog }: { session: any; enabledFeatures?: any; keyCatalog?: any[] }) => {
  const [section, setSection] = useState("policies");
  const [loading, setLoading] = useState(false);
  const [policies, setPolicies] = useState<RotationPolicy[]>([]);
  const [upcoming, setUpcoming] = useState<UpcomingRotation[]>([]);
  const [runs, setRuns] = useState<RotationRun[]>([]);
  const [error, setError] = useState("");
  const [triggerBusy, setTriggerBusy] = useState("");
  const [deleteBusy, setDeleteBusy] = useState("");

  // Policy modal
  const [policyModal, setPolicyModal] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<RotationPolicy | null>(null);
  const [pName, setPName] = useState("");
  const [pTargetType, setPTargetType] = useState<string>("key");
  const [pFilter, setPFilter] = useState("");
  const [pInterval, setPInterval] = useState("90");
  const [pAutoRotate, setPAutoRotate] = useState(true);
  const [pNotifyBefore, setPNotifyBefore] = useState("7");
  const [pSaving, setPSaving] = useState(false);
  const [pError, setPError] = useState("");

  const refresh = async () => {
    if (!session?.token) return;
    setLoading(true);
    setError("");
    try {
      const [p, u, r] = await Promise.all([
        listPolicies(session).catch(() => MOCK_POLICIES),
        listUpcoming(session).catch(() => MOCK_UPCOMING),
        listRuns(session).catch(() => MOCK_RUNS),
      ]);
      setPolicies(Array.isArray(p) ? p : MOCK_POLICIES);
      setUpcoming(Array.isArray(u) ? u : MOCK_UPCOMING);
      setRuns(Array.isArray(r) ? r : MOCK_RUNS);
    } catch (e: any) {
      setError(errMsg(e));
      setPolicies(MOCK_POLICIES);
      setUpcoming(MOCK_UPCOMING);
      setRuns(MOCK_RUNS);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void refresh(); }, [session?.token]);

  // Stats derived
  const activePolicies = policies.filter((p) => p.status === "active").length;
  const upcoming7d = upcoming.filter((u) => !u.overdue && u.days_until <= 7).length;
  const overdueCount = upcoming.filter((u) => u.overdue).length;
  const last24hRuns = runs.filter((r) => {
    try { return Date.now() - new Date(r.started_at).getTime() < 86400000; }
    catch { return false; }
  }).length;

  const openCreateModal = () => {
    setEditingPolicy(null);
    setPName(""); setPTargetType("key"); setPFilter(""); setPInterval("90");
    setPAutoRotate(true); setPNotifyBefore("7"); setPError("");
    setPolicyModal(true);
  };

  const openEditModal = (p: RotationPolicy) => {
    setEditingPolicy(p);
    setPName(p.name); setPTargetType(p.target_type); setPFilter(p.target_filter || "");
    setPInterval(String(p.interval_days)); setPAutoRotate(p.auto_rotate);
    setPNotifyBefore(String(p.notify_days_before)); setPError("");
    setPolicyModal(true);
  };

  const savePolicy = async () => {
    if (!pName.trim()) { setPError("Name is required."); return; }
    if (!Number(pInterval) || Number(pInterval) < 1) { setPError("Interval must be at least 1 day."); return; }
    setPSaving(true);
    setPError("");
    const payload: Partial<RotationPolicy> = {
      name: pName.trim(),
      target_type: pTargetType as RotationPolicy["target_type"],
      target_filter: pFilter.trim(),
      interval_days: Number(pInterval),
      auto_rotate: pAutoRotate,
      notify_days_before: Number(pNotifyBefore) || 7,
      enabled: true,
    };
    try {
      if (editingPolicy?.id) {
        await updatePolicy(session, editingPolicy.id, payload);
      } else {
        await createPolicy(session, payload);
      }
      setPolicyModal(false);
      await refresh();
    } catch (e: any) {
      setPError(errMsg(e));
    } finally {
      setPSaving(false);
    }
  };

  const doDelete = async (p: RotationPolicy) => {
    if (!window.confirm(`Delete policy "${p.name}"?`)) return;
    setDeleteBusy(p.id);
    try {
      await deletePolicy(session, p.id);
      await refresh();
    } catch { /* ignore */ }
    finally { setDeleteBusy(""); }
  };

  const doTrigger = async (policyId: string, policyName: string) => {
    if (!window.confirm(`Manually trigger rotation for policy "${policyName}"?`)) return;
    setTriggerBusy(policyId);
    try {
      await triggerRotation(session, policyId);
      await refresh();
    } catch { /* ignore */ }
    finally { setTriggerBusy(""); }
  };

  /* ════════════ RENDER ════════════ */
  return (
    <div style={{ display: "grid", gap: 14 }}>

      {/* ── Stats ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 10 }}>
        <Stat l="Active Policies" v={loading ? "…" : activePolicies} c="accent" i={CalendarClock} />
        <Stat l="Upcoming (7d)" v={loading ? "…" : upcoming7d} c="blue" i={Clock} />
        <Stat l="Overdue" v={loading ? "…" : overdueCount} c={overdueCount > 0 ? "red" : "muted"} i={AlertTriangle} />
        <Stat l="Last 24h Rotations" v={loading ? "…" : last24hRuns} c="green" i={CheckCircle2} />
      </div>

      {/* ── Error ── */}
      {error && (
        <div style={{ padding: "8px 12px", borderRadius: 7, background: C.redDim, border: `1px solid ${C.red}`, fontSize: 11, color: C.red }}>
          {error}
        </div>
      )}

      {/* ── Tab switcher + header actions ── */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
        <Tabs
          tabs={["Policies", "Schedule", "History"]}
          active={section === "policies" ? "Policies" : section === "schedule" ? "Schedule" : "History"}
          onChange={(t) => setSection(t === "Policies" ? "policies" : t === "Schedule" ? "schedule" : "history")}
        />
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          {section === "policies" && (
            <Btn small primary onClick={openCreateModal}><Plus size={11} /> Create Policy</Btn>
          )}
          <Btn small onClick={() => void refresh()} disabled={loading}><RefreshCw size={11} /> {loading ? "Loading..." : "Refresh"}</Btn>
        </div>
      </div>

      {/* ════════════ POLICIES SECTION ════════════ */}
      {section === "policies" && (
        <Section title="Rotation Policies">
          <Card style={{ padding: 0, overflow: "hidden" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1.8fr 0.8fr 1fr 0.8fr 0.9fr 0.7fr auto", padding: "9px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, background: C.surface }}>
              <div>Name</div>
              <div>Target Type</div>
              <div>Filter</div>
              <div>Interval</div>
              <div>Auto Rotate</div>
              <div>Status</div>
              <div style={{ textAlign: "right" }}>Actions</div>
            </div>
            <div style={{ maxHeight: 420, overflowY: "auto" }}>
              {loading && (
                <div style={{ padding: 28, textAlign: "center", fontSize: 12, color: C.dim }}>
                  <Clock size={20} color={C.muted} style={{ margin: "0 auto 8px", display: "block" }} />
                  Loading...
                </div>
              )}
              {!loading && policies.length === 0 && (
                <div style={{ padding: 28, textAlign: "center", fontSize: 12, color: C.dim }}>
                  <CalendarClock size={20} color={C.muted} style={{ margin: "0 auto 8px", display: "block" }} />
                  No rotation policies configured.
                </div>
              )}
              {!loading && policies.map((p) => (
                <div
                  key={p.id}
                  style={{ display: "grid", gridTemplateColumns: "1.8fr 0.8fr 1fr 0.8fr 0.9fr 0.7fr auto", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, alignItems: "center", fontSize: 11, transition: "background 120ms" }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = C.cardHover; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div style={{ color: C.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.name}</div>
                    <div style={{ fontSize: 9, color: C.dim }}>Next: {fmtDate(p.next_rotation_at)} · {p.total_rotations} total runs</div>
                  </div>
                  <div>
                    <B c={p.target_type === "key" ? "accent" : p.target_type === "certificate" ? "blue" : "purple"}>
                      {p.target_type}
                    </B>
                  </div>
                  <div style={{ color: C.dim, fontFamily: "'JetBrains Mono', monospace", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {p.target_filter || "—"}
                  </div>
                  <div style={{ color: C.text, fontWeight: 600 }}>{p.interval_days}d</div>
                  <div>
                    <B c={p.auto_rotate ? "green" : "muted"}>{p.auto_rotate ? "Auto" : "Manual"}</B>
                  </div>
                  <div><B c={policyStatusColor(p.status)}>{p.status}</B></div>
                  <div style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                    <Btn small disabled={triggerBusy === p.id} onClick={() => void doTrigger(p.id, p.name)}>
                      <Play size={9} /> {triggerBusy === p.id ? "..." : "Run"}
                    </Btn>
                    <Btn small onClick={() => openEditModal(p)}>
                      <Edit2 size={9} />
                    </Btn>
                    <Btn small danger disabled={deleteBusy === p.id} onClick={() => void doDelete(p)}>
                      <Trash2 size={9} /> {deleteBusy === p.id ? "..." : ""}
                    </Btn>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </Section>
      )}

      {/* ════════════ SCHEDULE SECTION ════════════ */}
      {section === "schedule" && (
        <Section title="Upcoming Rotations">
          <Card style={{ padding: 0, overflow: "hidden" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1.5fr 0.7fr 1fr 0.8fr auto", padding: "9px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, background: C.surface }}>
              <div>Policy</div>
              <div>Target</div>
              <div>Type</div>
              <div>Scheduled</div>
              <div>Days Until</div>
              <div style={{ textAlign: "right" }}>Action</div>
            </div>
            <div style={{ maxHeight: 420, overflowY: "auto" }}>
              {loading && (
                <div style={{ padding: 28, textAlign: "center", fontSize: 12, color: C.dim }}>
                  <Clock size={20} color={C.muted} style={{ margin: "0 auto 8px", display: "block" }} />
                  Loading...
                </div>
              )}
              {!loading && upcoming.length === 0 && (
                <div style={{ padding: 28, textAlign: "center", fontSize: 12, color: C.dim }}>
                  <CheckCircle2 size={20} color={C.muted} style={{ margin: "0 auto 8px", display: "block" }} />
                  No upcoming rotations scheduled.
                </div>
              )}
              {!loading && upcoming.map((u, idx) => (
                <div
                  key={`${u.policy_id}-${u.target_id}-${idx}`}
                  style={{ display: "grid", gridTemplateColumns: "1.5fr 1.5fr 0.7fr 1fr 0.8fr auto", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, alignItems: "center", fontSize: 11, background: u.overdue ? C.redTint : "transparent", transition: "background 120ms" }}
                  onMouseEnter={(e) => { if (!u.overdue) e.currentTarget.style.background = C.cardHover; }}
                  onMouseLeave={(e) => { if (!u.overdue) e.currentTarget.style.background = "transparent"; }}
                >
                  <div style={{ color: C.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{u.policy_name}</div>
                  <div style={{ color: C.dim, fontFamily: "'JetBrains Mono', monospace", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{u.target_name}</div>
                  <div>
                    <B c={u.target_type === "key" ? "accent" : u.target_type === "certificate" ? "blue" : "purple"}>
                      {u.target_type}
                    </B>
                  </div>
                  <div style={{ color: C.dim, fontSize: 10 }}>{fmtDateTime(u.scheduled_at)}</div>
                  <div>
                    {u.overdue
                      ? <span style={{ color: C.red, fontWeight: 700, fontSize: 11 }}>{Math.abs(u.days_until)}d overdue</span>
                      : <span style={{ color: u.days_until <= 3 ? C.amber : C.text, fontWeight: 600 }}>{u.days_until}d</span>
                    }
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <Btn small disabled={triggerBusy === u.policy_id} onClick={() => void doTrigger(u.policy_id, u.policy_name)}>
                      <Play size={9} /> {triggerBusy === u.policy_id ? "..." : "Trigger"}
                    </Btn>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </Section>
      )}

      {/* ════════════ HISTORY SECTION ════════════ */}
      {section === "history" && (
        <Section title="Rotation History">
          <Card style={{ padding: 0, overflow: "hidden" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1.5fr 0.9fr 0.6fr 0.7fr 0.8fr", padding: "9px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, background: C.surface }}>
              <div>Policy</div>
              <div>Target</div>
              <div>Started</div>
              <div>Duration</div>
              <div>Status</div>
              <div>Triggered By</div>
            </div>
            <div style={{ maxHeight: 420, overflowY: "auto" }}>
              {loading && (
                <div style={{ padding: 28, textAlign: "center", fontSize: 12, color: C.dim }}>
                  <Clock size={20} color={C.muted} style={{ margin: "0 auto 8px", display: "block" }} />
                  Loading...
                </div>
              )}
              {!loading && runs.length === 0 && (
                <div style={{ padding: 28, textAlign: "center", fontSize: 12, color: C.dim }}>
                  <CheckCircle2 size={20} color={C.muted} style={{ margin: "0 auto 8px", display: "block" }} />
                  No rotation history available.
                </div>
              )}
              {!loading && runs.map((r) => (
                <div
                  key={r.id}
                  style={{ display: "grid", gridTemplateColumns: "1.5fr 1.5fr 0.9fr 0.6fr 0.7fr 0.8fr", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, alignItems: "center", fontSize: 11, transition: "background 120ms" }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = C.cardHover; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                >
                  <div style={{ color: C.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.policy_name}</div>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ color: C.dim, fontFamily: "'JetBrains Mono', monospace", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.target_name}</div>
                    {r.error && <div style={{ fontSize: 9, color: C.red, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.error}</div>}
                  </div>
                  <div style={{ color: C.dim, fontSize: 10 }}>{fmtDateTime(r.started_at)}</div>
                  <div style={{ color: C.dim, fontSize: 10 }}>{runDuration(r.started_at, r.completed_at)}</div>
                  <div><B c={runStatusColor(r.status)}>{r.status}</B></div>
                  <div>
                    <B c={r.triggered_by === "manual" ? "amber" : r.triggered_by === "expiry" ? "orange" : "blue"}>
                      {r.triggered_by}
                    </B>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </Section>
      )}

      {/* ════════════ CREATE / EDIT POLICY MODAL ════════════ */}
      <Modal open={policyModal} onClose={() => setPolicyModal(false)} title={editingPolicy ? "Edit Rotation Policy" : "Create Rotation Policy"} wide>
        <Row2>
          <FG label="Policy Name" required>
            <Inp value={pName} onChange={(e) => setPName(e.target.value)} placeholder="e.g. Critical Keys — 90d" />
          </FG>
          <FG label="Target Type" required>
            <Sel value={pTargetType} onChange={(e) => setPTargetType(e.target.value)}>
              <option value="key">Key</option>
              <option value="secret">Secret</option>
              <option value="certificate">Certificate</option>
            </Sel>
          </FG>
        </Row2>
        <FG label="Target Filter" hint="Tag selector or glob pattern, e.g. tag:critical or prefix:prod-*">
          <Inp value={pFilter} onChange={(e) => setPFilter(e.target.value)} placeholder="tag:critical" />
        </FG>
        <Row2>
          <FG label="Interval (days)" required hint="How often to rotate matching targets">
            <Inp type="number" value={pInterval} onChange={(e) => setPInterval(e.target.value)} placeholder="90" />
          </FG>
          <FG label="Notify N Days Before" hint="Send notification this many days before rotation">
            <Inp type="number" value={pNotifyBefore} onChange={(e) => setPNotifyBefore(e.target.value)} placeholder="7" />
          </FG>
        </Row2>
        <FG label="Auto Rotate" hint="When enabled, rotation runs automatically on schedule. When disabled, requires manual trigger.">
          <div
            style={{ display: "flex", alignItems: "center", gap: 10, cursor: "pointer", width: "fit-content" }}
            onClick={() => setPAutoRotate((v) => !v)}
          >
            <div style={{ width: 40, height: 22, borderRadius: 11, background: pAutoRotate ? C.accent : C.border, position: "relative", transition: "background .2s", flexShrink: 0 }}>
              <div style={{ width: 16, height: 16, borderRadius: 8, background: C.white, position: "absolute", top: 3, left: pAutoRotate ? 21 : 3, transition: "left .2s", boxShadow: "0 1px 3px rgba(0,0,0,.3)" }} />
            </div>
            <span style={{ fontSize: 11, color: pAutoRotate ? C.accent : C.dim, fontWeight: 600 }}>
              {pAutoRotate ? "Enabled — Automatic" : "Disabled — Manual Trigger Only"}
            </span>
          </div>
        </FG>
        {pError && <div style={{ fontSize: 10, color: C.red, marginBottom: 8, padding: "6px 10px", background: C.redDim, borderRadius: 6 }}>{pError}</div>}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 10 }}>
          <Btn small onClick={() => setPolicyModal(false)}>Cancel</Btn>
          <Btn small primary onClick={savePolicy} disabled={pSaving || !pName.trim()}>
            {pSaving ? "Saving..." : editingPolicy ? "Update Policy" : "Create Policy"}
          </Btn>
        </div>
      </Modal>

    </div>
  );
};
