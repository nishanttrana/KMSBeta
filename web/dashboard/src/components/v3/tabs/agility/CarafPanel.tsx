import { useEffect, useState } from "react";
import { AlertTriangle, Boxes, Clock, HelpCircle, Pencil, Plus, ShieldCheck, Trash2, Gavel, RefreshCw } from "lucide-react";
import { C } from "../../theme";
import {
  getCarafAssessment,
  listCarafThreats,
  saveCarafThreat,
  deleteCarafThreat,
  saveCarafAsset,
  deleteCarafAsset,
  setCarafDecision,
  type CarafAssessment,
  type CarafAssetAssessment,
  type CarafDecision,
  type CarafThreat,
  type MatchKind,
  type NewCarafAsset,
  type NewCarafThreat,
} from "../../../../lib/cryptoAgility";
import { Badge, daysUntil, errText, Field, Findings, Grid2, inputStyle, Modal, S, StatCard } from "./ui";

// Crypto agility risk assessment. The customer records the threats that
// drive their migration (with the years they expect each), and profiles
// their assets (shelf life X, migration time Y, cost, keys). Keycore computes
// whether X + Y outruns the soonest threat (Z), suggests a mitigation, and
// tracks the decision the customer records. Nothing here is estimated.

const MATCH_LABEL: Record<MatchKind, string> = {
  quantum_vulnerable: "Every quantum-vulnerable algorithm",
  weak: "Every weak algorithm",
  family: "Algorithm family",
  algorithm: "Specific algorithm",
  below_strength: "Everything below a strength",
};
const TIMELINE: Record<string, [string, string, string]> = {
  exposed: ["Exposed", C.red, C.redDim],
  at_limit: ["At the limit", C.red, C.redDim],
  time_to_spare: ["Time to spare", C.green, C.greenDim],
  not_assessed: ["Not assessed", C.dim, C.dimTint],
  no_threat: ["No threat applies", C.dim, C.dimTint],
};
const DECISION_LABEL: Record<string, string> = {
  secure: "Secure", accept: "Accept risk", phase_out: "Phase out", compensating_control: "Compensating control",
};
const STATE: Record<string, [string, string, string]> = {
  undecided: ["Undecided", C.dim, C.dimTint],
  accepted: ["Accepted", C.amber, C.amberDim],
  acceptance_expired: ["Acceptance expired", C.red, C.redDim],
  open: ["Open", C.accent, C.accentTint],
  in_progress: ["In progress", C.accent, C.accentTint],
  done: ["Done", C.green, C.greenDim],
  overdue: ["Overdue", C.red, C.redDim],
};
const pick = (map: Record<string, [string, string, string]>, k: string) => map[k] ?? [k, C.dim, C.dimTint];

const SENSITIVITY = ["critical", "high", "medium", "low", "unknown"];
const TIMELINE_ORDER = ["exposed", "at_limit", "time_to_spare", "not_assessed", "no_threat"];
const PROFILE: [keyof CarafAssessment["profile"], string][] = [
  ["owner", "Owner"], ["shelf_life", "Shelf life (X)"], ["migration_time", "Migration time (Y)"],
  ["cost", "Cost"], ["sensitivity", "Sensitivity"], ["live_keys", "Linked to a live key"], ["complete", "All of the above"],
];

// Where the risk sits (sensitivity × timeline) and how much of the
// assessment rests on recorded values rather than gaps.
function RiskOverview({ data }: { data: CarafAssessment }) {
  const total = data.summary.assets;
  const rows = SENSITIVITY.filter(s => Object.values(data.heatmap?.[s] ?? {}).some(n => n > 0));
  return (
    <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginTop: 16 }}>
      <div style={{ ...S.panel, flex: 2, minWidth: 320 }} data-testid="caraf-heatmap">
        <div style={{ ...S.sectionTitle, padding: "12px 14px 0" }}>Sensitivity × exposure</div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr><th style={S.th}>Sensitivity</th>{TIMELINE_ORDER.map(t => <th key={t} style={{ ...S.th, textAlign: "center" }}>{pick(TIMELINE, t)[0]}</th>)}</tr></thead>
            <tbody>{rows.map(s => (
              <tr key={s} style={{ borderTop: `1px solid ${C.border}` }}>
                <td style={{ ...S.td, textTransform: "capitalize" }}>{s}</td>
                {TIMELINE_ORDER.map(t => {
                  const n = data.heatmap[s]?.[t] ?? 0;
                  const [, fg, bg] = pick(TIMELINE, t);
                  return <td key={t} style={{ ...S.td, textAlign: "center", fontWeight: n ? 700 : 400, color: n ? fg : C.muted, background: n ? bg : "transparent" }}>{n || "·"}</td>;
                })}
              </tr>
            ))}</tbody>
          </table>
        </div>
      </div>
      <div style={{ ...S.panel, flex: 1, minWidth: 260, padding: "12px 14px" }} data-testid="caraf-profile">
        <div style={S.sectionTitle}>Profile completeness</div>
        <div style={S.sectionHint}>Assets with each value recorded. Gaps make the assessment weaker.</div>
        {PROFILE.map(([k, label]) => {
          const n = data.profile?.[k] ?? 0;
          const pct = total ? Math.round((n / total) * 100) : 0;
          return (
            <div key={k} style={{ marginTop: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: k === "complete" ? C.text : C.dim, fontWeight: k === "complete" ? 600 : 400 }}>
                <span>{label}</span><span>{n} of {total}</span>
              </div>
              <div style={{ height: 5, background: C.border, borderRadius: 3, marginTop: 3 }}>
                <div style={{ width: `${pct}%`, height: 5, borderRadius: 3, background: pct === 100 ? C.green : C.accent }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function matchText(t: { match_kind: MatchKind; match_value?: string | undefined }) {
  switch (t.match_kind) {
    case "algorithm": return t.match_value || "";
    case "family": return `${t.match_value} family`;
    case "below_strength": return `below ${t.match_value}-bit`;
    default: return MATCH_LABEL[t.match_kind];
  }
}

function exposureText(a: CarafAssetAssessment) {
  if (a.margin_years === undefined) {
    if (a.timeline === "not_assessed") return `missing ${a.missing.join(", ").replaceAll("_", " ")}`;
    return "";
  }
  if (a.margin_years < 0) return `short by ${-a.margin_years} ${-a.margin_years === 1 ? "year" : "years"}`;
  if (a.margin_years === 0) return "no margin";
  return `${a.margin_years} ${a.margin_years === 1 ? "year" : "years"} to spare`;
}

/* ─── Threat modal ─── */
function ThreatModal({ threat, onClose, onSave }: { threat: CarafThreat | null; onClose: () => void; onSave: (t: NewCarafThreat) => Promise<void> }) {
  const [name, setName] = useState(threat?.name ?? "");
  const [category, setCategory] = useState<CarafThreat["category"]>(threat?.category ?? "quantum");
  const [kind, setKind] = useState<MatchKind>(threat?.match_kind ?? "quantum_vulnerable");
  const [value, setValue] = useState(threat?.match_value ?? "");
  const [years, setYears] = useState(threat ? String(threat.years_to_threat) : "");
  const [note, setNote] = useState(threat?.note ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const needsValue = kind === "algorithm" || kind === "family" || kind === "below_strength";
  const valid = Boolean(name.trim() && years !== "" && Number(years) >= 0 && (!needsValue || value.trim()));

  async function save() {
    setSaving(true); setError(null);
    try {
      const t: NewCarafThreat = { name: name.trim(), category, match_kind: kind, years_to_threat: Number(years) };
      if (needsValue) t.match_value = value.trim();
      if (note.trim()) t.note = note.trim();
      await onSave(t);
      onClose();
    } catch (e) { setError(errText(e)); } finally { setSaving(false); }
  }

  return (
    <Modal title={threat ? "Edit threat" : "Add threat"} hint="A threat you plan for, the algorithms it breaks, and how many years until you expect it (0 if it is here now)."
      onClose={onClose} onSave={save} saving={saving} valid={valid} saveLabel={threat ? "Save threat" : "Add threat"}>
      <Field label="Threat"><input style={inputStyle} value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Quantum computer able to break RSA and ECC" /></Field>
      <Grid2>
        <Field label="Category">
          <select style={inputStyle} value={category} onChange={e => setCategory(e.target.value as CarafThreat["category"])}>
            {["quantum", "cryptanalytic", "regulatory", "business", "other"].map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </Field>
        <Field label="Years until you expect it (Z)"><input type="number" min={0} max={100} style={inputStyle} value={years} onChange={e => setYears(e.target.value)} placeholder="e.g. 10" /></Field>
      </Grid2>
      <Grid2>
        <Field label="Breaks">
          <select style={inputStyle} value={kind} onChange={e => { setKind(e.target.value as MatchKind); setValue(""); }}>
            {(Object.keys(MATCH_LABEL) as MatchKind[]).map(k => <option key={k} value={k}>{MATCH_LABEL[k]}</option>)}
          </select>
        </Field>
        {needsValue ? <Field label={kind === "below_strength" ? "Strength (bits)" : kind === "family" ? "Family" : "Algorithm"}>
          <input style={inputStyle} value={value} onChange={e => setValue(e.target.value)} placeholder={kind === "below_strength" ? "128" : kind === "family" ? "RSA" : "RSA-2048"} />
        </Field> : <div />}
      </Grid2>
      <Field label="Note (optional)"><input style={inputStyle} value={note} onChange={e => setNote(e.target.value)} placeholder="why you expect it then" /></Field>
      {error && <div style={{ fontSize: 12, color: C.red }}>Threat not saved: {error}</div>}
    </Modal>
  );
}

/* ─── Asset modal ─── */
function AssetModal({ asset, keyCatalog, onClose, onSave }: { asset: CarafAssetAssessment["asset"] | null; keyCatalog: any[]; onClose: () => void; onSave: (a: NewCarafAsset) => Promise<void> }) {
  const [f, setF] = useState(() => ({
    name: asset?.name ?? "", description: asset?.description ?? "", owner: asset?.owner ?? "",
    ownership: asset?.ownership ?? "unknown", implementation: asset?.implementation ?? "unknown", pqc_support: asset?.pqc_support ?? "unknown",
    location: asset?.location ?? "unknown", jurisdiction: asset?.jurisdiction ?? "", sensitivity: asset?.sensitivity ?? "unknown",
    shelf: asset?.shelf_life_years !== undefined ? String(asset.shelf_life_years) : "", migrate: asset?.migration_years !== undefined ? String(asset.migration_years) : "",
    cost: asset?.cost ?? "unknown", algorithms: (asset?.algorithms ?? []).join(", "), keys: (asset?.key_ids ?? []).join(", "),
  }));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF(p => ({ ...p, [k]: e.target.value }));
  const list = (v: string) => v.split(",").map(x => x.trim()).filter(Boolean);
  const sel = (k: keyof typeof f, opts: string[]) => (
    <select style={inputStyle} value={f[k]} onChange={set(k)}>{opts.map(o => <option key={o} value={o}>{o.replaceAll("_", " ")}</option>)}</select>
  );

  async function save() {
    setSaving(true); setError(null);
    try {
      const a: NewCarafAsset = {
        name: f.name.trim(), description: f.description.trim(), owner: f.owner.trim(), ownership: f.ownership, implementation: f.implementation,
        pqc_support: f.pqc_support, location: f.location, jurisdiction: f.jurisdiction.trim(), sensitivity: f.sensitivity, cost: f.cost,
        algorithms: list(f.algorithms), key_ids: list(f.keys),
      };
      if (f.shelf !== "") a.shelf_life_years = Number(f.shelf);
      if (f.migrate !== "") a.migration_years = Number(f.migrate);
      await onSave(a);
      onClose();
    } catch (e) { setError(errText(e)); } finally { setSaving(false); }
  }

  return (
    <Modal title={asset ? "Edit asset" : "Add asset"} hint="A system that relies on cryptography: an application, a device fleet, a database. Link its keys, or list the algorithms it uses."
      onClose={onClose} onSave={save} saving={saving} valid={Boolean(f.name.trim())} saveLabel={asset ? "Save asset" : "Add asset"}>
      <Grid2>
        <Field label="Asset"><input style={inputStyle} value={f.name} onChange={set("name")} placeholder="e.g. Smart meter fleet" /></Field>
        <Field label="Owner"><input style={inputStyle} value={f.owner} onChange={set("owner")} placeholder="team or person" /></Field>
      </Grid2>
      <Field label="Description (optional)"><input style={inputStyle} value={f.description} onChange={set("description")} /></Field>
      <Grid2>
        <Field label="Must stay protected for (years, X)"><input type="number" min={0} max={100} style={inputStyle} value={f.shelf} onChange={set("shelf")} placeholder="data or device lifetime" /></Field>
        <Field label="Migration would take (years, Y)"><input type="number" min={0} max={100} style={inputStyle} value={f.migrate} onChange={set("migrate")} placeholder="to replace or upgrade" /></Field>
      </Grid2>
      <Grid2>
        <Field label="Cost to migrate">{sel("cost", ["unknown", "low", "medium", "high"])}</Field>
        <Field label="Sensitivity">{sel("sensitivity", ["unknown", "low", "medium", "high", "critical"])}</Field>
      </Grid2>
      <Grid2>
        <Field label="Ownership">{sel("ownership", ["unknown", "enterprise", "third_party"])}</Field>
        <Field label="Implementation">{sel("implementation", ["unknown", "software", "hardware", "hsm", "cloud_service", "embedded"])}</Field>
      </Grid2>
      <Grid2>
        <Field label="Post-quantum support">{sel("pqc_support", ["unknown", "supported", "planned", "none"])}</Field>
        <Field label="Location">{sel("location", ["unknown", "on_prem", "cloud", "hybrid", "edge"])}</Field>
      </Grid2>
      <Field label="Jurisdiction (optional)"><input style={inputStyle} value={f.jurisdiction} onChange={set("jurisdiction")} /></Field>
      <Field label="Linked keys (IDs, comma-separated)">
        <input style={inputStyle} list="caraf-keys" value={f.keys} onChange={set("keys")} placeholder="their algorithms are read from keycore" />
        <datalist id="caraf-keys">{keyCatalog.slice(0, 500).map((k: any) => <option key={k.id} value={k.id}>{`${k.name ?? ""} ${k.algorithm ?? ""}`}</option>)}</datalist>
      </Field>
      <Field label="Other algorithms it uses (comma-separated)"><input style={inputStyle} value={f.algorithms} onChange={set("algorithms")} placeholder="e.g. ECDSA-P256, AES-128-GCM" /></Field>
      {error && <div style={{ fontSize: 12, color: C.red }}>Asset not saved: {error}</div>}
    </Modal>
  );
}

/* ─── Decision modal ─── */
function DecisionModal({ item, onClose, onSave }: { item: CarafAssetAssessment; onClose: () => void; onSave: (d: CarafDecision) => Promise<void> }) {
  const cur = item.asset.decision;
  const [decision, setDecision] = useState<string>(cur.decision ?? item.suggestion ?? "secure");
  const [owner, setOwner] = useState(cur.owner ?? item.asset.owner ?? "");
  const [date, setDate] = useState((cur.decision === "accept" ? cur.review_by : cur.due)?.slice(0, 10) ?? "");
  const [status, setStatus] = useState<string>(cur.status ?? "open");
  const [note, setNote] = useState(cur.note ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const clearing = decision === "";
  const valid = clearing || Boolean(owner.trim() && date);

  async function save() {
    setSaving(true); setError(null);
    try {
      if (clearing) await onSave({});
      else {
        const d: CarafDecision = { decision: decision as CarafDecision["decision"] & string, owner: owner.trim(), status: status as NonNullable<CarafDecision["status"]> };
        if (decision === "accept") d.review_by = date; else d.due = date;
        if (note.trim()) d.note = note.trim();
        await onSave(d);
      }
      onClose();
    } catch (e) { setError(errText(e)); } finally { setSaving(false); }
  }

  return (
    <Modal title={`Decision for ${item.asset.name}`} hint={item.suggestion ? `Suggested from exposure and cost: ${DECISION_LABEL[item.suggestion]}. The decision is yours.` : "Record how this asset's risk will be handled."}
      onClose={onClose} onSave={save} saving={saving} valid={valid} saveLabel="Record decision">
      <Grid2>
        <Field label="Decision">
          <select style={inputStyle} value={decision} onChange={e => setDecision(e.target.value)}>
            {Object.entries(DECISION_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            <option value="">Clear decision</option>
          </select>
        </Field>
        <Field label="Owner"><input style={inputStyle} value={owner} onChange={e => setOwner(e.target.value)} disabled={clearing} /></Field>
      </Grid2>
      {!clearing && (
        <Grid2>
          <Field label={decision === "accept" ? "Review acceptance by" : "Due by"}><input type="date" style={inputStyle} value={date} onChange={e => setDate(e.target.value)} /></Field>
          {decision !== "accept" && <Field label="Status">
            <select style={inputStyle} value={status} onChange={e => setStatus(e.target.value)}>
              <option value="open">Open</option><option value="in_progress">In progress</option><option value="done">Done</option>
            </select>
          </Field>}
        </Grid2>
      )}
      {decision === "accept" && <div style={{ fontSize: 11, color: C.muted }}>An accepted risk lapses on its review date and shows as expired until reviewed.</div>}
      {!clearing && <Field label="Note (optional)"><input style={inputStyle} value={note} onChange={e => setNote(e.target.value)} placeholder="e.g. compensating control: gateway wraps the legacy TLS" /></Field>}
      {error && <div style={{ fontSize: 12, color: C.red }}>Decision not recorded: {error}</div>}
    </Modal>
  );
}

/* ─── Panel ─── */
export function CarafPanel({ session, keyCatalog }: { session: any; keyCatalog: any[] }) {
  const [data, setData] = useState<CarafAssessment | null>(null);
  const [threats, setThreats] = useState<CarafThreat[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [threatModal, setThreatModal] = useState<{ t: CarafThreat | null } | null>(null);
  const [assetModal, setAssetModal] = useState<{ a: CarafAssetAssessment["asset"] | null } | null>(null);
  const [decisionFor, setDecisionFor] = useState<CarafAssetAssessment | null>(null);

  async function load() {
    setError(null);
    try {
      const [a, t] = await Promise.all([getCarafAssessment(session), listCarafThreats(session)]);
      setData(a); setThreats(t);
    } catch (e) {
      setData(null); setThreats([]); setError(errText(e));
    } finally { setLoading(false); }
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: run once on mount; load is a per-render closure.
  useEffect(() => { void load(); }, []);

  async function remove(kind: "threat" | "asset", id: string, name: string) {
    if (!window.confirm(`Delete the ${kind} "${name}"?`)) return;
    setActionError(null);
    try {
      if (kind === "threat") await deleteCarafThreat(session, id); else await deleteCarafAsset(session, id);
      await load();
    } catch (e) { setActionError(`${name}: ${errText(e)}`); }
  }

  if (loading) return <div style={{ ...S.empty, display: "flex", gap: 8, justifyContent: "center" }}><RefreshCw size={14} /> Loading risk assessment…</div>;
  if (error || !data) {
    return <div style={{ ...S.empty, color: C.red }}>Not assessed: the risk assessment is unavailable. {error}</div>;
  }
  const s = data.summary;

  return (
    <div>
      <div style={{ fontSize: 12, color: C.dim, marginBottom: 16, maxWidth: 780 }}>
        Record the threats that drive your migration and when you expect each, then profile your assets. An asset is exposed when the years its data or device must stay protected (X) plus the years a migration would take (Y) exceed the years until the soonest threat that breaks its algorithms (Z).
      </div>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <StatCard icon={<Boxes size={16} />} label="Assets" value={s.assets} sub={`${s.threats} ${s.threats === 1 ? "threat" : "threats"} recorded`} />
        <StatCard icon={<AlertTriangle size={16} />} label="Exposed" value={s.exposed + s.at_limit} sub="X + Y ≥ Z" color={C.red} bg={C.redTint} />
        <StatCard icon={<ShieldCheck size={16} />} label="Time to spare" value={s.time_to_spare} sub="X + Y < Z" color={C.green} bg={C.greenTint} />
        <StatCard icon={<Gavel size={16} />} label="Exposed, undecided" value={s.undecided_at_risk} sub="need a decision" color={C.amber} bg={C.amberTint} />
        <StatCard icon={<Clock size={16} />} label="Overdue or lapsed" value={s.overdue + s.acceptance_expired} sub="decisions past due, acceptances past review" color={C.purple} bg={C.purpleTint} />
        <StatCard icon={<HelpCircle size={16} />} label="Not assessed" value={s.not_assessed + s.no_threat} sub="missing X or Y, or no threat applies" color={C.dim} bg={C.dimTint} />
      </div>
      {s.assets > 0 && <RiskOverview data={data} />}
      <Findings items={data.findings} />
      {actionError && <div style={{ fontSize: 12, color: C.red, marginTop: 12 }}>Not changed: {actionError}</div>}

      <div style={S.divider} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={S.sectionTitle}>Threats</div>
        <button style={S.button} onClick={() => setThreatModal({ t: null })}><Plus size={13} /> Add threat</button>
      </div>
      <div style={S.sectionHint}>The threats you plan for. Z is the years until you expect each.</div>
      {threats.length === 0 ? <div style={S.empty}>No threats recorded yet.</div> : (
        <div style={S.panel}><div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr style={{ borderBottom: `1px solid ${C.border}` }}>{["Threat", "Category", "Breaks", "Z (years)", ""].map(h => <th key={h} style={S.th}>{h}</th>)}</tr></thead>
            <tbody>{threats.map((t, i) => (
              <tr key={t.id} style={{ borderBottom: i < threats.length - 1 ? `1px solid ${C.border}` : "none" }}>
                <td style={S.td}><b>{t.name}</b>{t.note && <div style={{ fontSize: 10, color: C.muted }}>{t.note}</div>}</td>
                <td style={S.td}>{t.category}</td>
                <td style={{ ...S.td, ...S.mono, fontSize: 11 }}>{matchText(t)}</td>
                <td style={{ ...S.td, ...S.mono }}>{t.years_to_threat === 0 ? "now" : t.years_to_threat}</td>
                <td style={{ ...S.td, whiteSpace: "nowrap" }}>
                  <button aria-label={`Edit ${t.name}`} style={S.smallBtn} onClick={() => setThreatModal({ t })}><Pencil size={12} /></button>{" "}
                  <button aria-label={`Delete ${t.name}`} style={S.smallBtn} onClick={() => void remove("threat", t.id, t.name)}><Trash2 size={12} /></button>
                </td>
              </tr>))}</tbody>
          </table>
        </div></div>
      )}

      <div style={S.divider} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={S.sectionTitle}>Assets</div>
        <button style={S.button} onClick={() => setAssetModal({ a: null })}><Plus size={13} /> Add asset</button>
      </div>
      <div style={S.sectionHint}>Suggested mitigation follows exposure and your cost estimate; the decision is yours.</div>
      {data.assets.length === 0 ? <div style={S.empty}>No assets profiled yet.</div> : (
        <div style={S.panel}><div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr style={{ borderBottom: `1px solid ${C.border}` }}>{["Asset", "Algorithms", "X", "Y", "Z", "Exposure", "Cost", "Suggested", "Decision", ""].map(h => <th key={h} style={S.th}>{h}</th>)}</tr></thead>
            <tbody>{data.assets.map((x, i) => {
              const [tl, tc, tb] = pick(TIMELINE, x.timeline);
              const [sl, sc, sb] = pick(STATE, x.decision_state);
              const d = x.asset.decision;
              return (
                <tr key={x.asset.id} style={{ borderBottom: i < data.assets.length - 1 ? `1px solid ${C.border}` : "none" }}>
                  <td style={S.td}>
                    <b>{x.asset.name}</b>
                    <div style={{ fontSize: 10, color: C.muted }}>{[x.asset.owner, x.asset.ownership !== "unknown" ? x.asset.ownership.replace("_", " ") : "", x.asset.sensitivity !== "unknown" ? `${x.asset.sensitivity} sensitivity` : ""].filter(Boolean).join(" · ")}</div>
                    {x.missing_keys.length > 0 && <div style={{ fontSize: 10, color: C.red }}>{x.missing_keys.length} linked key(s) no longer live</div>}
                    {(x.consumers ?? []).length > 0 && <div title={x.consumers.join("\n")} style={{ fontSize: 10, color: C.dim }}>used by {x.consumers.length} caller(s): {x.consumers.slice(0, 2).join(", ")}{x.consumers.length > 2 ? "…" : ""}</div>}
                  </td>
                  <td style={{ ...S.td, ...S.mono, fontSize: 11 }}>{x.algorithms.join(", ") || "—"}</td>
                  <td style={{ ...S.td, ...S.mono }}>{x.x ?? "—"}</td>
                  <td style={{ ...S.td, ...S.mono }}>{x.y ?? "—"}</td>
                  <td style={{ ...S.td, ...S.mono }} title={x.threats.map(t => t.name).join(", ")}>{x.z === undefined ? "—" : x.z === 0 ? "now" : x.z}</td>
                  <td style={S.td}><Badge color={tc} bg={tb}>{tl}</Badge><div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{exposureText(x)}</div></td>
                  <td style={S.td}>{x.asset.cost}</td>
                  <td style={S.td}>{x.suggestion ? DECISION_LABEL[x.suggestion] : "—"}</td>
                  <td style={S.td}>
                    <Badge color={sc} bg={sb}>{sl}</Badge>
                    {d.decision && <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{DECISION_LABEL[d.decision]} · {d.owner}{(d.due || d.review_by) && ` · ${(d.review_by ?? d.due ?? "").slice(0, 10)}`}</div>}
                  </td>
                  <td style={{ ...S.td, whiteSpace: "nowrap" }}>
                    <button style={S.smallBtn} onClick={() => setDecisionFor(x)}><Gavel size={12} /> Decide</button>{" "}
                    <button aria-label={`Edit ${x.asset.name}`} style={S.smallBtn} onClick={() => setAssetModal({ a: x.asset })}><Pencil size={12} /></button>{" "}
                    <button aria-label={`Delete ${x.asset.name}`} style={S.smallBtn} onClick={() => void remove("asset", x.asset.id, x.asset.name)}><Trash2 size={12} /></button>
                  </td>
                </tr>
              );
            })}</tbody>
          </table>
        </div></div>
      )}

      <div style={S.divider} />
      <div style={S.sectionTitle}>Roadmap</div>
      <div style={S.sectionHint}>Your recorded decisions, by date.</div>
      {data.roadmap.length === 0 ? <div style={S.empty}>No decisions recorded yet.</div> : (
        <div style={S.panel}><div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr style={{ borderBottom: `1px solid ${C.border}` }}>{["Date", "Asset", "Decision", "Owner", "State"].map(h => <th key={h} style={S.th}>{h}</th>)}</tr></thead>
            <tbody>{data.roadmap.map((r, i) => {
              const [sl, sc, sb] = pick(STATE, r.state);
              return (
                <tr key={r.asset_id} style={{ borderBottom: i < data.roadmap.length - 1 ? `1px solid ${C.border}` : "none" }}>
                  <td style={{ ...S.td, whiteSpace: "nowrap" }}><span style={S.mono}>{r.date || "—"}</span>{r.date && <div style={{ fontSize: 10, color: C.muted }}>{daysUntil(r.date) < 0 ? `${-daysUntil(r.date)} days ago` : `in ${daysUntil(r.date)} days`}</div>}</td>
                  <td style={S.td}>{r.asset}</td>
                  <td style={S.td}>{DECISION_LABEL[r.decision]}</td>
                  <td style={S.td}>{r.owner}</td>
                  <td style={S.td}><Badge color={sc} bg={sb}>{sl}</Badge></td>
                </tr>
              );
            })}</tbody>
          </table>
        </div></div>
      )}

      {threatModal && <ThreatModal threat={threatModal.t} onClose={() => setThreatModal(null)} onSave={async t => { await saveCarafThreat(session, t, threatModal.t?.id); await load(); }} />}
      {assetModal && <AssetModal asset={assetModal.a} keyCatalog={keyCatalog} onClose={() => setAssetModal(null)} onSave={async a => { await saveCarafAsset(session, a, assetModal.a?.id); await load(); }} />}
      {decisionFor && <DecisionModal item={decisionFor} onClose={() => setDecisionFor(null)} onSave={async d => { await setCarafDecision(session, decisionFor.asset.id, d); await load(); }} />}
    </div>
  );
}
