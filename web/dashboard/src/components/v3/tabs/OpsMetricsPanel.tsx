import { useCallback, useEffect, useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Activity, AlertTriangle, Gauge, Timer, Zap } from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import { listAuditEvents, type AuditEvent, type AuditEventQuery } from "../../../lib/audit";
import { getOpsStats, type OpsGroup, type OpsStats } from "../../../lib/opsMetrics";
import { B, Btn, Card, Stat } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import {
  bucketBounds, bucketLabel, bucketUnit, clickable, DEFAULT_WINDOW, DrillHint, DrillPanel,
  usePagedDrill, windowFrom, WindowSelect, type ServerDrill, type WindowId
} from "../chartDrill";
import { C } from "../theme";
import { AuditEventDetail } from "./AuditEventDetail";

// Operation metrics view of Operations: cryptographic operations counted by
// the audit service over the whole window (GET /ops-metrics/stats). Every
// bar lists exactly the operations it counts through the event list's
// metered_op / outcome / service / node filters over the same window; a row
// opens the event.
const OK = "var(--cls-op-ok)";
const ERR = "var(--cls-op-err)";
const axisTick = { fill: C.muted, fontSize: 10 };
const title: React.CSSProperties = { fontSize: 10.5, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "var(--font-mono)" };
const TH: React.CSSProperties = { fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, padding: "6px 8px", textAlign: "left", borderBottom: `1px solid ${C.border}` };
const TD: React.CSSProperties = { fontSize: 11, color: C.dim, padding: "6px 8px", borderBottom: `1px solid ${C.border}`, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 240 };

const compact = (n: number) => n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${(n / 1e3).toFixed(1)}K` : n.toLocaleString();
const ms = (n: number) => n < 1 ? `${n.toFixed(3)} ms` : `${n.toFixed(1)} ms`;
// A percentile is the upper bound of the histogram bucket it fell in.
const le = (n: number | null) => n == null ? "> 1000 ms" : `≤ ${n} ms`;
const pct = (part: number, whole: number) => whole ? `${((part / whole) * 100).toFixed(part && part / whole < 0.001 ? 3 : 1)}%` : "0%";
const shortService = (s: string) => String(s || "").replace(/^kms-/, "");
const SCOPE: Record<string, string> = { cluster: "Cluster-wide", node: "This node only", standalone: "Single node" };

type Seg = "ok" | "err";
const outcomeOf = (seg?: Seg): Pick<AuditEventQuery, "outcome"> => seg === "ok" ? { outcome: "success" } : seg === "err" ? { outcome: "error" } : {};

export function OpsMetricsPanel({ session }: { session: AuthSession }) {
  const [windowId, setWindowId] = useState<WindowId>(DEFAULT_WINDOW);
  const [stats, setStats] = useState<OpsStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [drill, setDrill] = useState<ServerDrill<AuditEventQuery> | null>(null);
  const [event, setEvent] = useState<AuditEvent | null>(null);

  const load = useCallback(async () => {
    if (!session?.token) return;
    setLoading(true); setErr(""); setDrill(null);
    try {
      setStats(await getOpsStats(session, { from: windowFrom(windowId) }));
    } catch (e) {
      setStats(null); setErr(errMsg(e));
    } finally { setLoading(false); }
  }, [session, windowId]);
  useEffect(() => { void load(); }, [load]);

  const fetchPage = useCallback((q: AuditEventQuery, offset: number, limit: number) => listAuditEvents(session, { ...q, offset, limit }), [session]);
  const paged = usePagedDrill(drill, fetchPage);

  const open = (label: string, count: number, query: AuditEventQuery) => {
    if (!stats || !count) return;
    setDrill({ label, count, query: { from: stats.from, to: stats.to, metered_op: "*", ...query } });
  };
  const openGroup = (dim: "metered_op" | "service" | "node", name: string, g: OpsGroup, seg?: Seg) => {
    const count = seg === "ok" ? g.ops - g.errors : seg === "err" ? g.errors : g.ops;
    const what = seg === "err" ? "Refused or failed" : seg === "ok" ? "Succeeded" : "Operations";
    open(`${what}: ${name}`, count, { [dim]: g.key, ...outcomeOf(seg) });
  };

  const series = useMemo(() => (stats?.series ?? []).map((p) => ({
    ...p, ok: p.ops - p.errors, time: bucketLabel(p.start, stats?.bucket_seconds || 3600),
  })), [stats]);
  const openBucket = (i: number, seg: Seg) => {
    const p = series[i];
    if (!p || !stats) return;
    const unit = bucketUnit(stats.bucket_seconds);
    open(`${seg === "err" ? "Refused or failed" : "Succeeded"} in the ${unit} from ${p.time} UTC`, seg === "err" ? p.errors : p.ok,
      { ...bucketBounds(p.start, stats.bucket_seconds, stats.from, stats.to), ...outcomeOf(seg) });
  };

  const t = stats?.total;
  return (
    <div style={{ display: "grid", gap: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <WindowSelect value={windowId} onChange={setWindowId} />
        <Btn small onClick={() => void load()} disabled={loading}>{loading ? "Loading…" : "Refresh"}</Btn>
        {stats && <B c={stats.scope === "node" ? "amber" : "neutral"}>{SCOPE[stats.scope] ?? stats.scope}</B>}
        {stats && <span style={{ fontSize: 10.5, color: C.muted }} title="Operations before the first recorded hour were not measured">
          {stats.recorded_since ? `Measured since ${new Date(stats.recorded_since).toLocaleString()}` : "Nothing recorded yet"}
        </span>}
      </div>

      {err ? <Card><div style={{ fontSize: 11, color: C.redFg }}>{`Operation metrics unavailable: ${err}`}</div></Card> : !stats || !t ? null : <>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 10 }}>
          <Stat l="Operations" v={compact(t.ops)} s={`${compact(stats.total_values)} values processed`} i={Zap} />
          <Stat l="Refused or failed" v={compact(t.errors)} s={`${pct(t.errors, t.ops)} of operations`} c={t.errors ? "amber" : "accent"} i={AlertTriangle} />
          <Stat l="Average latency" v={t.ops ? ms(t.avg_latency_ms) : "—"} s={t.ops ? `p50 ${le(t.p50_ms)}` : "no operations"} i={Timer} />
          <Stat l="p99 latency" v={t.ops ? le(t.p99_ms) : "—"} s={t.ops ? `p90 ${le(t.p90_ms)}` : "no operations"} i={Gauge} />
        </div>

        {t.ops === 0 ? (
          <Card>
            <div style={{ textAlign: "center", padding: 28, color: C.muted, fontSize: 12 }}>
              <Activity size={22} style={{ opacity: 0.5, marginBottom: 6 }} />
              <div>No operations in this window.</div>
            </div>
          </Card>
        ) : <>
          <DrillHint />
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={title}>{`Throughput · per ${bucketUnit(stats.bucket_seconds)} (UTC)`}</span>
              <Legend />
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={series} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke={C.border} />
                <XAxis dataKey="time" tick={axisTick} axisLine={{ stroke: C.border }} tickLine={false} interval="preserveStartEnd" minTickGap={24} />
                <YAxis tick={axisTick} axisLine={false} tickLine={false} allowDecimals={false} width={44} tickFormatter={compact} />
                <Tooltip cursor={{ fill: C.dimTint }} content={<SeriesTip />} />
                <Bar dataKey="ok" name="Succeeded" stackId="o" fill={OK} style={clickable} onClick={(_d, i) => openBucket(i, "ok")} />
                <Bar dataKey="errors" name="Refused or failed" stackId="o" fill={ERR} radius={[2, 2, 0, 0]} style={clickable} onClick={(_d, i) => openBucket(i, "err")} />
              </BarChart>
            </ResponsiveContainer>
          </Card>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(320px,1fr))", gap: 12 }}>
            <GroupBars label="By operation" rows={stats.by_op} name={(k) => k} onPick={(g, seg) => openGroup("metered_op", g.key, g, seg)} />
            <GroupBars label="By service" rows={stats.by_service} name={shortService} onPick={(g, seg) => openGroup("service", shortService(g.key), g, seg)} />
          </div>

          {stats.by_node.length > 1 && (
            <Card>
              <div style={{ ...title, marginBottom: 8 }}>By node</div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {stats.by_node.map((n) => (
                  <button key={n.key || "local"} onClick={() => openGroup("node", n.key || "(unclustered)", n)}
                    style={{ ...clickable, background: C.surface, border: `1px solid ${C.border}`, borderRadius: "var(--radius-md)", padding: "6px 10px", color: C.text, fontSize: 11, fontFamily: "var(--font-mono)" }}>
                    {`${n.key || "(unclustered)"} · ${compact(n.ops)}`}
                  </button>
                ))}
              </div>
            </Card>
          )}

          <Card style={{ padding: 0, overflow: "hidden" }}>
            <div style={{ ...title, padding: "12px 14px 8px" }}>Latency by operation</div>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>{["Operation", "Operations", "Refused or failed", "Average", "p50", "p90", "p99"].map((h) => <th key={h} style={TH}>{h}</th>)}</tr></thead>
              <tbody>
                {stats.by_op.map((g) => (
                  <tr key={g.key} onClick={() => openGroup("metered_op", g.key, g)} style={clickable}
                    onMouseEnter={(e) => { e.currentTarget.style.background = C.cardHover; }} onMouseLeave={(e) => { e.currentTarget.style.background = ""; }}>
                    <td style={{ ...TD, color: C.text, fontWeight: 600, fontFamily: "var(--font-mono)" }}>{g.key}</td>
                    <td style={TD}>{g.ops.toLocaleString()}</td>
                    <td style={{ ...TD, color: g.errors ? C.amberFg : C.muted }}>{g.errors ? `${g.errors.toLocaleString()} (${pct(g.errors, g.ops)})` : "0"}</td>
                    <td style={TD}>{ms(g.avg_latency_ms)}</td>
                    <td style={TD}>{le(g.p50_ms)}</td>
                    <td style={TD}>{le(g.p90_ms)}</td>
                    <td style={{ ...TD, color: g.p99_ms == null || g.p99_ms > 50 ? C.amberFg : C.dim }}>{le(g.p99_ms)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </>}

        {drill && (
          <DrillPanel label={drill.label} count={drill.count} onClear={() => setDrill(null)}
            loaded={paged.rows.length} loading={paged.loading} error={paged.error} onMore={paged.done ? undefined : paged.loadMore}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>{["Time", "Service", "Operation", "Actor", "Target", "Result", "Latency"].map((h) => <th key={h} style={TH}>{h}</th>)}</tr></thead>
              <tbody>
                {paged.rows.map((e) => (
                  <tr key={e.id} onClick={() => setEvent(e)} style={clickable}
                    onMouseEnter={(ev) => { ev.currentTarget.style.background = C.cardHover; }} onMouseLeave={(ev) => { ev.currentTarget.style.background = ""; }}>
                    <td style={TD}>{new Date(e.timestamp).toLocaleString()}</td>
                    <td style={TD}><B c="neutral">{shortService(e.service)}</B></td>
                    <td style={{ ...TD, color: C.text, fontFamily: "var(--font-mono)" }} title={e.action}>{String(e.details?.metered_op ?? e.action)}</td>
                    <td style={TD}>{e.actor_id || "-"}</td>
                    <td style={TD}>{e.target_id || "-"}</td>
                    <td style={TD}><B c={eventFailed(e) ? "amber" : "green"}>{eventResult(e)}</B></td>
                    <td style={TD}>{ms(eventMs(e))}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </DrillPanel>
        )}
      </>}
      <AuditEventDetail event={event} onClose={() => setEvent(null)} />
    </div>
  );
}

// The result and latency the metrics counted: a legacy publisher's details
// carry them (services/audit opSampleFromEvent).
const eventResult = (e: AuditEvent) => String((typeof e.details?.result === "string" && e.details.result) || e.result);
const eventFailed = (e: AuditEvent) => eventResult(e) !== "success";
const eventMs = (e: AuditEvent) => Number(e.duration_ms || e.details?.duration_ms || 0);

const Legend = () => (
  <span style={{ display: "inline-flex", gap: 12, fontSize: 10.5, color: C.muted }}>
    {[["Succeeded", OK], ["Refused or failed", ERR]].map(([l, c]) => (
      <span key={l} style={{ display: "inline-flex", alignItems: "center", gap: 5 }}><span style={{ width: 9, height: 9, borderRadius: 2, background: c }} />{l}</span>
    ))}
  </span>
);

type TipProps = { active?: boolean; payload?: Array<{ payload?: { time: string; ops: number; errors: number; avg_latency_ms: number } }> };
const SeriesTip = ({ active, payload }: TipProps) => {
  const p = active ? payload?.[0]?.payload : undefined;
  if (!p) return null;
  return (
    <div style={{ background: C.elevated, border: `1px solid ${C.border}`, borderRadius: "var(--radius-md)", padding: "8px 10px", fontSize: 11, color: C.text, boxShadow: "var(--shadow-md)" }}>
      <div style={{ fontWeight: 600, marginBottom: 4 }}>{`${p.time} UTC`}</div>
      <div style={{ color: C.dim }}>{`${p.ops.toLocaleString()} operations · ${p.errors.toLocaleString()} refused or failed`}</div>
      {p.ops > 0 && <div style={{ color: C.dim }}>{`Average ${ms(p.avg_latency_ms)}`}</div>}
    </div>
  );
};

// Horizontal stacked bars of a breakdown: each segment drills into its operations.
function GroupBars({ label, rows, name, onPick }: { label: string; rows: OpsGroup[]; name: (k: string) => string; onPick: (g: OpsGroup, seg: Seg) => void }) {
  const top = rows.slice(0, 10);
  const data = top.map((g) => ({ ...g, ok: g.ops - g.errors, name: name(g.key) }));
  return (
    <Card>
      <div style={{ ...title, marginBottom: 8 }}>{label}{rows.length > top.length ? ` · top ${top.length} of ${rows.length}` : ""}</div>
      <div data-testid={`bars-${label.toLowerCase().replace(/\s+/g, "-")}`}>
      <ResponsiveContainer width="100%" height={Math.max(120, data.length * 28 + 24)}>
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 12, top: 0, bottom: 0 }}>
          <XAxis type="number" tick={axisTick} axisLine={{ stroke: C.border }} tickLine={false} allowDecimals={false} tickFormatter={compact} />
          <YAxis type="category" dataKey="name" tick={{ fill: C.dim, fontSize: 10.5 }} axisLine={false} tickLine={false} width={96} />
          <Tooltip cursor={{ fill: C.dimTint }} />
          <Bar dataKey="ok" name="Succeeded" stackId="g" fill={OK} barSize={14} style={clickable} onClick={(_d, i) => { const g = top[i]; if (g) onPick(g, "ok"); }} />
          <Bar dataKey="errors" name="Refused or failed" stackId="g" fill={ERR} barSize={14} radius={[0, 2, 2, 0]} style={clickable} onClick={(_d, i) => { const g = top[i]; if (g) onPick(g, "err"); }} />
        </BarChart>
      </ResponsiveContainer>
      </div>
    </Card>
  );
}
