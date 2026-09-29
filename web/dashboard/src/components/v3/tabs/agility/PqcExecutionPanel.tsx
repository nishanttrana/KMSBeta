import { useEffect, useState } from "react";
import { Atom, Boxes, ChevronDown, ChevronRight, Play, Plus, RefreshCw, RotateCcw, ScanLine, ShieldAlert, FlaskConical } from "lucide-react";
import { C } from "../../theme";
import {
  createPQCPlan,
  executePQCPlan,
  getPQCReadiness,
  listPQCPlans,
  rollbackPQCPlan,
  runPQCScan,
  type PQCMigrationPlan,
  type PQCReadinessScan,
} from "../../../../lib/pqc";
import { Badge, errText, Field, Grid2, inputStyle, Modal, S, StatCard } from "./ui";

// Readiness and execution (the pqc service, folded in from the former
// Post-Quantum tab). The scan measures keys, certificates, discovered TLS
// endpoints and cloud keys; a plan built from it creates successor keys in
// keycore when executed, and marks certificate, TLS and code steps manual.
// Only measured facts are shown: no readiness score.

const CLASS: Record<string, [string, string]> = {
  vulnerable: [C.red, C.redDim], strong: [C.green, C.greenDim], unknown: [C.dim, C.dimTint],
};
const STEP: Record<string, [string, string]> = {
  successor_created: [C.green, C.greenDim], rotated: [C.green, C.greenDim], completed: [C.green, C.greenDim],
  manual_required: [C.amber, C.amberDim], failed: [C.red, C.redDim], rolled_back: [C.dim, C.dimTint], pending: [C.accent, C.accentTint],
};
const tone = (m: Record<string, [string, string]>, k: string): [string, string] => m[k] ?? [C.dim, C.dimTint];

function PlanModal({ onClose, onSave }: { onClose: () => void; onSave: (p: { name: string; deadline?: string; timeline_standard?: string }) => Promise<void> }) {
  const [name, setName] = useState("");
  const [deadline, setDeadline] = useState("");
  const [label, setLabel] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function save() {
    setSaving(true); setError(null);
    try {
      const p: { name: string; deadline?: string; timeline_standard?: string } = { name: name.trim() };
      if (deadline) p.deadline = deadline;
      if (label.trim()) p.timeline_standard = label.trim();
      await onSave(p); onClose();
    } catch (e) { setError(errText(e)); } finally { setSaving(false); }
  }
  return (
    <Modal title="Build execution plan" hint="The plan takes every asset from the latest scan that is weak, quantum-vulnerable or not assessed, with a target algorithm for each. Nothing changes until you execute it."
      onClose={onClose} onSave={save} saving={saving} valid={Boolean(name.trim())} saveLabel="Build plan">
      <Field label="Plan name"><input style={inputStyle} value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Signing keys to ML-DSA" /></Field>
      <Grid2>
        <Field label="Deadline (optional, yours)"><input type="date" style={inputStyle} value={deadline} onChange={e => setDeadline(e.target.value)} /></Field>
        <Field label="Label (optional)"><input style={inputStyle} value={label} onChange={e => setLabel(e.target.value)} placeholder="e.g. board policy 2026" /></Field>
      </Grid2>
      {error && <div style={{ fontSize: 12, color: C.red }}>Plan not built: {error}</div>}
    </Modal>
  );
}

export function PqcExecutionPanel({ session }: { session: any }) {
  const [scan, setScan] = useState<PQCReadinessScan | null>(null);
  const [plans, setPlans] = useState<PQCMigrationPlan[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [showPlan, setShowPlan] = useState(false);
  const [loading, setLoading] = useState(true);

  async function load() {
    setError(null);
    try {
      const [s, p] = await Promise.all([getPQCReadiness(session), listPQCPlans(session)]);
      setScan(s); setPlans(p);
    } catch (e) {
      setScan(null); setPlans([]); setError(errText(e));
    } finally { setLoading(false); }
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: run once on mount; load is a per-render closure.
  useEffect(() => { void load(); }, []);

  async function act(key: string, fn: () => Promise<string>) {
    setBusy(key); setNotice(null);
    try { setNotice(await fn()); await load(); } catch (e) { setNotice(`Failed: ${errText(e)}`); } finally { setBusy(null); }
  }

  if (loading) return <div style={{ ...S.empty, display: "flex", gap: 8, justifyContent: "center" }}><RefreshCw size={14} /> Loading readiness…</div>;
  if (error || !scan) return <div style={{ ...S.empty, color: C.red }}>Not assessed: the readiness service is unavailable. {error}</div>;
  const risks = scan.risk_items ?? [];

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap", marginBottom: 16 }}>
        <div style={{ fontSize: 12, color: C.dim, maxWidth: 720 }}>
          A scan measures keys, certificates, discovered TLS endpoints and cloud keys. Execution plans act on it: each key step creates a successor key of the target algorithm in keycore (the old key stays until you retire it); certificate, TLS and code steps are manual.
          {scan.completed_at && <> Last scan {new Date(scan.completed_at).toLocaleString()}.</>}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button style={S.button} disabled={busy !== null} onClick={() => void act("scan", async () => { const s = await runPQCScan(session); return `Scan completed: ${s.total_assets} assets.`; })}>
            <ScanLine size={13} /> {busy === "scan" ? "Scanning…" : "Run scan"}
          </button>
          <button style={S.primary} onClick={() => setShowPlan(true)}><Plus size={13} /> Build execution plan</button>
        </div>
      </div>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <StatCard icon={<Boxes size={16} />} label="Assets scanned" value={scan.total_assets} />
        <StatCard icon={<Atom size={16} />} label="Post-quantum" value={scan.pqc_ready_assets} color={C.green} bg={C.greenTint} />
        <StatCard icon={<Atom size={16} />} label="Hybrid" value={scan.hybrid_assets} color={C.accent} bg={C.accentTint} />
        <StatCard icon={<ShieldAlert size={16} />} label="To migrate" value={risks.length} sub="weak, quantum-vulnerable or not assessed" color={C.red} bg={C.redTint} />
      </div>
      {notice && <div style={{ fontSize: 12, color: notice.startsWith("Failed") ? C.red : C.green, marginTop: 12 }}>{notice}</div>}

      <div style={S.divider} />
      <div style={S.sectionTitle}>Assets to migrate</div>
      <div style={S.sectionHint}>From the latest scan, across every source.</div>
      {risks.length === 0 ? <div style={S.empty}>Nothing to migrate in the latest scan.</div> : (
        <div style={S.panel}><div style={{ overflowX: "auto", maxHeight: 420 }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr style={{ borderBottom: `1px solid ${C.border}` }}>{["Asset", "Type", "Source", "Algorithm", "Class", "Target"].map(h => <th key={h} style={S.th}>{h}</th>)}</tr></thead>
            <tbody>{risks.slice(0, 200).map((r, i) => {
              const [fg, bg] = tone(CLASS, r.classification);
              return (
                <tr key={`${r.source}-${r.asset_id}-${i}`} style={{ borderBottom: `1px solid ${C.border}` }}>
                  <td style={S.td}>{r.name}</td>
                  <td style={S.td}>{r.asset_type.replaceAll("_", " ")}</td>
                  <td style={S.td}>{r.source}</td>
                  <td style={{ ...S.td, ...S.mono, fontSize: 11 }}>{r.algorithm}</td>
                  <td style={S.td}><Badge color={fg} bg={bg}>{r.classification}</Badge></td>
                  <td style={{ ...S.td, ...S.mono, fontSize: 11 }}>{r.migration_target || "—"}</td>
                </tr>
              );
            })}</tbody>
          </table>
        </div></div>
      )}

      <div style={S.divider} />
      <div style={S.sectionTitle}>Execution plans</div>
      <div style={S.sectionHint}>Dry run shows what would change; execute changes keys in keycore; rollback deactivates the successor keys a plan created.</div>
      {plans.length === 0 ? <div style={S.empty}>No execution plans yet.</div> : (
        <div style={S.panel}>
          {plans.map((p, i) => {
            const counts: Record<string, number> = {};
            for (const st of p.steps ?? []) counts[st.status] = (counts[st.status] ?? 0) + 1;
            const expanded = open === p.id;
            return (
              <div key={p.id} style={{ borderBottom: i < plans.length - 1 ? `1px solid ${C.border}` : "none", padding: "12px 14px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                  <button aria-label={`Show steps of ${p.name}`} style={{ ...S.smallBtn, border: "none" }} onClick={() => setOpen(expanded ? null : p.id)}>
                    {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  </button>
                  <div style={{ flex: 1, minWidth: 200 }}>
                    <b style={{ fontSize: 13 }}>{p.name}</b>
                    <div style={{ fontSize: 10, color: C.muted }}>
                      {(p.steps ?? []).length} steps · {Object.entries(counts).map(([k, v]) => `${v} ${k.replaceAll("_", " ")}`).join(", ")}
                      {p.deadline && !p.deadline.startsWith("0001") && ` · deadline ${p.deadline.slice(0, 10)}`} · by {p.created_by}
                    </div>
                  </div>
                  <Badge color={C.accent} bg={C.accentTint}>{p.status.replaceAll("_", " ")}</Badge>
                  <button style={S.smallBtn} disabled={busy !== null} onClick={() => void act(`dry-${p.id}`, async () => { await executePQCPlan(session, p.id, true); return `Dry run of ${p.name}: nothing changed.`; })}>
                    <FlaskConical size={12} /> Dry run
                  </button>
                  <button style={S.smallBtn} disabled={busy !== null} onClick={() => {
                    if (!window.confirm(`Execute "${p.name}"? Each key step creates a new key of its target algorithm in keycore.`)) return;
                    void act(`run-${p.id}`, async () => { const r = await executePQCPlan(session, p.id, false); return `${p.name}: ${r.status.replaceAll("_", " ")} (${String(r.summary?.migrated_steps ?? 0)} migrated, ${String(r.summary?.manual_steps ?? 0)} manual, ${String(r.summary?.failed_steps ?? 0)} failed).`; });
                  }}>
                    <Play size={12} /> Execute
                  </button>
                  <button style={S.smallBtn} disabled={busy !== null} onClick={() => {
                    if (!window.confirm(`Roll back "${p.name}"? The successor keys it created are deactivated.`)) return;
                    void act(`rb-${p.id}`, async () => { const r = await rollbackPQCPlan(session, p.id); return `${p.name}: ${r.status.replaceAll("_", " ")}.`; });
                  }}>
                    <RotateCcw size={12} /> Roll back
                  </button>
                </div>
                {expanded && (
                  <div style={{ overflowX: "auto", marginTop: 10 }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead><tr style={{ borderBottom: `1px solid ${C.border}` }}>{["Asset", "Type", "From", "To", "Phase", "Status"].map(h => <th key={h} style={S.th}>{h}</th>)}</tr></thead>
                      <tbody>{(p.steps ?? []).map(st => {
                        const [fg, bg] = tone(STEP, st.status);
                        const reason = typeof st.metadata?.reason === "string" ? st.metadata.reason : typeof st.metadata?.error === "string" ? st.metadata.error : "";
                        return (
                          <tr key={st.id} style={{ borderBottom: `1px solid ${C.border}` }}>
                            <td style={S.td}>{st.name}</td>
                            <td style={S.td}>{st.asset_type.replaceAll("_", " ")}</td>
                            <td style={{ ...S.td, ...S.mono, fontSize: 11 }}>{st.current_algorithm}</td>
                            <td style={{ ...S.td, ...S.mono, fontSize: 11 }}>{st.target_algorithm || "—"}</td>
                            <td style={S.td}>{st.phase.replaceAll("_", " ")}</td>
                            <td style={S.td}><Badge color={fg} bg={bg}>{st.status.replaceAll("_", " ")}</Badge>{reason && <div style={{ fontSize: 10, color: C.muted, marginTop: 2, maxWidth: 280 }}>{reason}</div>}</td>
                          </tr>
                        );
                      })}</tbody>
                    </table>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
      {showPlan && <PlanModal onClose={() => setShowPlan(false)} onSave={async p => { await createPQCPlan(session, p); await load(); }} />}
    </div>
  );
}
