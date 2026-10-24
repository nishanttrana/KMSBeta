import { useMemo, useState } from "react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { AlertTriangle, CalendarClock, RefreshCcw, ShieldAlert, Siren } from "lucide-react";
import { B, Btn, Card } from "../../legacyPrimitives";
import { C } from "../../theme";
import { type Drill, DrillHint, DrillPanel, clickable } from "../../chartDrill";
import { FilterTile } from "./FilterTile";
import { RENEWAL_FILTERS, type RenewalFilter, riskFill, riskWeight } from "./certFilters";

type Props = {
  summary: any;
  refreshing: boolean;
  onRefresh: () => void;
  onOpenCert: (certID: string) => void;
};

const axisTick = { fill: C.muted, fontSize: 10 };
const day = (v: unknown) => { const t = new Date(String(v || "")); return Number.isNaN(t.getTime()) || t.getTime() <= 0 ? "-" : t.toLocaleDateString(); };
const tone = (risk: unknown) => { const w = riskWeight(risk); return w >= 4 ? "red" : w >= 2 ? "amber" : "green"; };

// A day's bar names every CA renewing that day, with its share.
const DayTip = ({ active, payload }: { active?: boolean; payload?: { payload?: any }[] }) => {
  const e = active ? payload?.[0]?.payload : null;
  if (!e) return null;
  return (
    <div style={{ background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 4, padding: "6px 9px", fontSize: 11, color: C.text }}>
      <div style={{ fontWeight: 700, marginBottom: 3 }}>{`${String(e.bucket)} · ${Number(e.count || 0)}`}</div>
      {(Array.isArray(e.cas) ? e.cas : []).map((ca: any) => (
        <div key={String(ca.ca_id)} style={{ display: "flex", justifyContent: "space-between", gap: 12, color: C.dim }}>
          <span>{String(ca.ca_name || ca.ca_id || "-")}</span><span className="vk-num">{Number(ca.count || 0)}</span>
        </div>
      ))}
    </div>
  );
};

const TILES: { id: RenewalFilter; l: string; key: string; i: any; attention: string }[] = [
  { id: "due", l: "Due in 72h", key: "due_soon_count", i: CalendarClock, attention: "amber" },
  { id: "missed", l: "Missed windows", key: "missed_window_count", i: AlertTriangle, attention: "red" },
  { id: "emergency", l: "Emergency", key: "emergency_rotation_count", i: Siren, attention: "red" },
  { id: "risk", l: "At risk", key: "non_compliant_count", i: ShieldAlert, attention: "amber" },
];

// Certificates → Renewals: the certs service's renewal plan for every
// certificate, counted by the service. Each tile and bar lists the renewal
// windows it counts; a window opens its certificate.
export function CertRenewals({ summary, refreshing, onRefresh, onOpenCert }: Props) {
  const [drill, setDrill] = useState<(Drill<any> & { tile?: RenewalFilter }) | null>(null);
  const windows: any[] = useMemo(() => (Array.isArray(summary?.renewal_windows) ? summary.renewal_windows : []), [summary]);
  const schedule: any[] = Array.isArray(summary?.ca_directed_schedule) ? summary.ca_directed_schedule : [];
  // The time the summary arrived, so "due in 72h" lists what was counted.
  const now = useMemo(() => Date.now(), [summary]); // eslint-disable-line react-hooks/exhaustive-deps -- reviewed: recomputed only when a new summary arrives
  const listed = useMemo(() => (drill ? windows.filter(drill.match) : windows), [drill, windows]);

  const press = (id: RenewalFilter, label: string) => setDrill(drill?.tile === id ? null : { tile: id, label, match: (w) => RENEWAL_FILTERS[id](w, now) });
  const pickDay = (entry: any) => {
    const ids = new Set((entry?.cert_ids || []).map(String));
    setDrill({ label: `Renewing ${String(entry?.bucket || "")}`, match: (w) => ids.has(String(w.cert_id)) });
  };

  return (
    <div data-testid="cert-renewals">
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        {summary ? <B c={summary.ari_enabled === false ? "amber" : "green"}>{summary.ari_enabled === false ? "Local policy" : "CA-directed (ARI)"}</B> : null}
        {summary ? <span style={{ fontSize: 11, color: C.muted }}>{`Polled every ${Number(summary.recommended_poll_hours || 24)}h`}</span> : null}
        <span style={{ flex: 1 }} />
        <Btn small onClick={onRefresh} disabled={refreshing}><span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}><RefreshCcw size={12} />{refreshing ? "Recomputing…" : "Recompute"}</span></Btn>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 10, marginBottom: 12 }}>
        {TILES.map((t) => {
          const n = summary ? Number(summary[t.key] || 0) : null;
          return <FilterTile key={t.id} on={drill?.tile === t.id} onPress={() => press(t.id, t.l)} l={t.l} v={n === null ? "unavailable" : String(n)} c={n ? t.attention : "accent"} i={t.i} />;
        })}
      </div>
      <Card style={{ padding: 12 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Renewals per day</span>
          <span style={{ display: "flex", gap: 10, fontSize: 10, color: C.muted }}>
            {([["low", "Low"], ["medium", "Medium / high"], ["critical", "Critical"]] as const).map(([k, l]) => (
              <span key={k} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}><span style={{ width: 8, height: 8, borderRadius: 2, background: riskFill(k) }} />{l}</span>
            ))}
          </span>
        </div>
        <DrillHint />
        {schedule.length ? (
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={schedule}>
              <XAxis dataKey="bucket" tick={axisTick} axisLine={false} tickLine={false} />
              <YAxis allowDecimals={false} tick={axisTick} axisLine={false} tickLine={false} width={30} />
              <Tooltip content={<DayTip />} cursor={{ fill: C.accentDim }} />
              <Bar dataKey="count" name="Certificates" maxBarSize={56} radius={[3, 3, 0, 0]} style={clickable} onClick={(d) => pickDay(d?.payload)}>
                {schedule.map((e) => <Cell key={e.bucket} fill={riskFill(e.risk_level)} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : <div style={{ height: 120, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, color: C.muted }}>{summary ? "No renewals scheduled." : "Renewal plan unavailable."}</div>}
      </Card>
      <DrillPanel label={drill?.label ?? "All renewal windows"} count={listed.length} onClear={() => setDrill(null)}>
        {listed.map((w) => (
          <div key={w.cert_id} data-testid="renewal-row" onClick={() => onOpenCert(String(w.cert_id))} title="Open the certificate"
            style={{ display: "grid", gridTemplateColumns: "minmax(0,1.4fr) minmax(0,1fr) 150px minmax(0,1.2fr)", gap: 8, alignItems: "center", padding: "6px 4px", borderBottom: `1px solid ${C.border}`, fontSize: 11, ...clickable }}>
            <span style={{ color: C.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(w.subject_cn || w.cert_id)}</span>
            <span style={{ color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(w.ca_name || w.ca_id || "-")}</span>
            <span><B c={tone(w.risk_level)}>{String(w.renewal_state || "scheduled").replaceAll("_", " ")}</B></span>
            <span className="vk-num" style={{ color: C.muted, textAlign: "right" }}>{`${day(w.window_start)} → ${day(w.window_end)}`}</span>
          </div>
        ))}
      </DrillPanel>
    </div>
  );
}
