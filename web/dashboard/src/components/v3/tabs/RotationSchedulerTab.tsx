import { useEffect, useState } from "react";
import {
  RefreshCw, Clock, AlertTriangle, CheckCircle2, Plus, Trash2, Play, Edit2, CalendarClock
} from "lucide-react";
import { B, Btn, Card, FG, Inp, Modal, Row2, Section, Stat, Tabs } from "../legacyPrimitives";
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
  type RotationPolicyInput,
  type RotationRun,
  type UpcomingRotation,
} from "../../../lib/rotationScheduler";

// Every row comes from keycore's /rotation routes; a policy run really
// rotates the matching keys. When the routes can't be read the tab says so
// with the error; it never substitutes sample data.

/* ────── Helpers ────── */

function fmtDate(iso?: string) {
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

/* ────── Main Component ────── */

export const RotationSchedulerTab = ({ session }: { session: any; enabledFeatures?: any; keyCatalog?: any[] }) => {
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
  const [pFilter, setPFilter] = useState("");
  const [pInterval, setPInterval] = useState("90");
  const [pAutoRotate, setPAutoRotate] = useState(true);
  const [unavailable, setUnavailable] = useState("");
  const [notice, setNotice] = useState("");
  const [pSaving, setPSaving] = useState(false);
  const [pError, setPError] = useState("");

  const refresh = async () => {
    if (!session?.token) return;
    setLoading(true);
    setError("");
    try {
      const [p, u, r] = await Promise.all([listPolicies(session), listUpcoming(session), listRuns(session)]);
      setPolicies(p); setUpcoming(u); setRuns(r);
      setUnavailable("");
    } catch (e: unknown) {
      setPolicies([]); setUpcoming([]); setRuns([]);
      setUnavailable(errMsg(e));
    } finally {
      setLoading(false);
    }
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
  useEffect(() => { void refresh(); }, [session?.token]);

  // Stats derived
  const activePolicies = policies.filter((p) => p.status === "active").length;
  const upcoming7d = upcoming.filter((u) => !u.overdue && u.days_until <= 7).length;
  const overdueCount = upcoming.filter((u) => u.overdue).length;
  const last24hRuns = runs.filter((r) => r.status === "success" && Date.now() - new Date(r.started_at).getTime() < 86400000).length;
  const policyById = new Map(policies.map((p) => [p.id, p]));
  const daysOverdue = (iso: string) => Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 86400000));

  const openCreateModal = () => {
    setEditingPolicy(null);
    setPName(""); setPFilter(""); setPInterval("90");
    setPAutoRotate(true); setPError("");
    setPolicyModal(true);
  };

  const openEditModal = (p: RotationPolicy) => {
    setEditingPolicy(p);
    setPName(p.name); setPFilter(p.target_filter || "");
    setPInterval(String(p.interval_days)); setPAutoRotate(p.auto_rotate);
    setPError("");
    setPolicyModal(true);
  };

  const savePolicy = async () => {
    if (!pName.trim()) { setPError("Name is required."); return; }
    if (!Number(pInterval) || Number(pInterval) < 1) { setPError("Interval must be at least 1 day."); return; }
    setPSaving(true);
    setPError("");
    const payload: RotationPolicyInput = {
      name: pName.trim(),
      target_filter: pFilter.trim(),
      interval_days: Number(pInterval),
      auto_rotate: pAutoRotate,
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
    setError("");
    try {
      await deletePolicy(session, p.id);
    } catch (e: unknown) {
      setError(`Delete failed: ${errMsg(e)}`);
    } finally {
      setDeleteBusy("");
      await refresh();
    }
  };

  const doTrigger = async (policyId: string, policyName: string) => {
    const filter = policyById.get(policyId)?.target_filter ?? "";
    if (!window.confirm(`Rotate every active key matching "${filter}" now (policy "${policyName}")? Each key gets a new version.`)) return;
    setTriggerBusy(policyId);
    setError(""); setNotice("");
    try {
      const out = await triggerRotation(session, policyId);
      const msg = `${policyName}: rotated ${out.rotated} of ${out.matched} matching key${out.matched === 1 ? "" : "s"}`;
      if (out.failed > 0) setError(`${msg}; ${out.failed} failed (see History)`);
      else setNotice(msg);
    } catch (e: unknown) {
      setError(`Rotation not run: ${errMsg(e)}`);
    } finally {
      setTriggerBusy("");
      await refresh();
    }
  };

  /* ════════════ RENDER ════════════ */
  if (unavailable) {
    return (
      <Card style={{ padding: 20 }}>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
          <AlertTriangle size={16} color={C.red} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>Not assessed: rotation data is unavailable</div>
            <div style={{ fontSize: 11, color: C.dim, marginTop: 4 }}>keycore did not return rotation policies, schedule or history, so none are shown.</div>
            <div style={{ fontSize: 10, color: C.red, marginTop: 6, fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-word" }}>{unavailable}</div>
            <div style={{ marginTop: 10 }}><Btn small onClick={() => void refresh()}><RefreshCw size={11} /> Retry</Btn></div>
          </div>
        </div>
      </Card>
    );
  }

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
      {notice && (
        <div style={{ padding: "8px 12px", borderRadius: 7, background: C.greenDim, border: `1px solid ${C.green}`, fontSize: 11, color: C.green }}>
          {notice}
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
                    <div style={{ fontSize: 9, color: C.dim }}>Next: {fmtDate(p.next_rotation_at)} · Last: {fmtDate(p.last_rotation_at)} · {p.total_rotations} keys rotated</div>
                  </div>
                  <div>
                    <B c="accent">{p.target_type}</B>
                  </div>
                  <div style={{ color: C.dim, fontFamily: "'JetBrains Mono', monospace", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {p.target_filter || "—"}
                  </div>
                  <div style={{ color: C.text, fontWeight: 600 }}>{p.interval_days}d</div>
                  <div>
                    <B c={p.auto_rotate ? "green" : "muted"}>{p.auto_rotate ? "Auto" : "Manual"}</B>
                  </div>
                  <div title={p.last_error || undefined}><B c={policyStatusColor(p.status)}>{p.enabled ? p.status : "disabled"}</B></div>
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
              <div>Mode</div>
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
                  key={`${u.policy_id}-${idx}`}
                  style={{ display: "grid", gridTemplateColumns: "1.5fr 1.5fr 0.7fr 1fr 0.8fr auto", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, alignItems: "center", fontSize: 11, background: u.overdue ? C.redTint : "transparent", transition: "background 120ms" }}
                  onMouseEnter={(e) => { if (!u.overdue) e.currentTarget.style.background = C.cardHover; }}
                  onMouseLeave={(e) => { if (!u.overdue) e.currentTarget.style.background = "transparent"; }}
                >
                  <div style={{ color: C.text, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{u.policy_name}</div>
                  <div style={{ color: C.dim, fontFamily: "'JetBrains Mono', monospace", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>keys matching {policyById.get(u.policy_id)?.target_filter ?? "—"}</div>
                  <div>
                    <B c={policyById.get(u.policy_id)?.auto_rotate ? "green" : "muted"}>{policyById.get(u.policy_id)?.auto_rotate ? "auto" : "manual"}</B>
                  </div>
                  <div style={{ color: C.dim, fontSize: 10 }}>{fmtDateTime(u.scheduled_at)}</div>
                  <div>
                    {u.overdue
                      ? <span style={{ color: C.red, fontWeight: 700, fontSize: 11 }}>{daysOverdue(u.scheduled_at)}d overdue</span>
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
                    <B c={r.triggered_by.startsWith("manual") ? "amber" : "blue"}>
                      {r.triggered_by.startsWith("manual:") ? `manual (${r.triggered_by.slice(7)})` : r.triggered_by}
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
          <FG label="Interval (days)" required hint="How often to rotate matching keys">
            <Inp type="number" value={pInterval} onChange={(e) => setPInterval(e.target.value)} placeholder="90" />
          </FG>
        </Row2>
        <FG label="Keys to rotate" required hint="* (every active key), tag:<tag>, id:<key id>, or a key-name glob such as prod-*. Secrets and certificates are rotated by their own services.">
          <Inp value={pFilter} onChange={(e) => setPFilter(e.target.value)} placeholder="tag:critical" mono />
        </FG>
        <FG label="Auto Rotate" hint="When enabled, keycore rotates the matching keys when the policy is due. When disabled, keys rotate only when you press Run.">
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
          <Btn small primary onClick={savePolicy} disabled={pSaving || !pName.trim() || !pFilter.trim()}>
            {pSaving ? "Saving..." : editingPolicy ? "Update Policy" : "Create Policy"}
          </Btn>
        </div>
      </Modal>

    </div>
  );
};
