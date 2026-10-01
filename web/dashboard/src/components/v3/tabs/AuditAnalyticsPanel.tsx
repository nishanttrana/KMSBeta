import { useCallback, useEffect, useMemo, useState } from "react";
import { Area, AreaChart, Bar, BarChart, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { AuthSession } from "../../../lib/auth";
import { getAuditStats, listAuditEvents, type AuditEvent, type AuditEventQuery, type AuditStats } from "../../../lib/audit";
import { B, Btn, Card, Row2, Row3, Stat } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import {
  bucketBounds, bucketLabel, bucketUnit, clickable, clickedIndex, DEFAULT_WINDOW, DrillHint, DrillPanel,
  usePagedDrill, windowFrom, WindowSelect, type ServerDrill, type WindowId
} from "../chartDrill";
import { C } from "../theme";

// Activity sub-tab of the Audit Log. The audit service counts the whole
// window (GET /audit/activity/stats), from a day to a year or since uptime. Clicking a
// chart segment lists exactly the events it counts, through the event list
// with the same filters; a row opens the Audit Log's event detail.
const RESULT_COLORS: Record<string, string> = { success: C.green, failure: C.red, denied: C.amber, refused: C.amber };
const RISK_COLORS: string[] = [C.green, C.green, C.amber, C.orange, C.red];

const title: React.CSSProperties = { fontSize: 10, fontWeight: 600, color: C.dim, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 };
const axisTick = { fill: C.muted, fontSize: 9 };
const TH: React.CSSProperties = { fontSize: 9, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, padding: "5px 6px", textAlign: "left", borderBottom: `1px solid ${C.border}` };
const TD: React.CSSProperties = { fontSize: 10, color: C.dim, padding: "5px 6px", borderBottom: `1px solid ${C.border}`, whiteSpace: "nowrap", maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis" };

const shortService = (s: string) => String(s || "").replace(/^kms-/, "");
const resultTone = (r: string) => r === "success" ? "green" : r === "failure" ? "red" : "amber";

export function AuditAnalyticsPanel({ session, onOpenEvent }: { session: AuthSession; onOpenEvent: (e: AuditEvent) => void }) {
  const [windowId, setWindowId] = useState<WindowId>(DEFAULT_WINDOW);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [drill, setDrill] = useState<ServerDrill<AuditEventQuery> | null>(null);

  const load = useCallback(async () => {
    if (!session?.token) return;
    setLoading(true); setErr(""); setDrill(null);
    try {
      setStats(await getAuditStats(session, { from: windowFrom(windowId) }));
    } catch (e) {
      setStats(null); setErr(errMsg(e));
    } finally { setLoading(false); }
  }, [session, windowId]);

  useEffect(() => { void load(); }, [load]);

  const fetchPage = useCallback((q: AuditEventQuery, offset: number, limit: number) =>
    listAuditEvents(session, { ...q, exclude_http_requests: true, offset, limit }), [session]);
  const paged = usePagedDrill(drill, fetchPage);

  const win = useMemo(() => ({ from: stats?.from || "", to: stats?.to || "" }), [stats]);
  // An empty key (no actor or service recorded) has no list filter, so it
  // would list the whole window: it is not clickable.
  const open = (label: string, count: number, query: AuditEventQuery) => {
    if (Object.values(query).some((v) => v === "")) return;
    setDrill({ label, count, query: { ...win, ...query } });
  };

  const byResult = stats?.by_result ?? [];
  const series = useMemo(() => (stats?.series ?? []).map((p) => ({ ...p, time: bucketLabel(p.start, stats?.bucket_seconds || 3600) })), [stats]);
  const failures = byResult.filter((r) => r.key !== "success").reduce((s, r) => s + r.count, 0);
  const pickSeries = (state: { activeIndex?: unknown } | null) => {
    const p = series[clickedIndex(state)];
    if (!p || !stats) return;
    open(`Events in the ${bucketUnit(stats.bucket_seconds)} from ${p.time} UTC`, p.count, bucketBounds(p.start, stats.bucket_seconds, stats.from, stats.to));
  };

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
        <WindowSelect value={windowId} onChange={setWindowId} />
        <Btn small onClick={() => void load()} disabled={loading}>{loading ? "Loading…" : "Refresh"}</Btn>
        {stats && <span style={{ fontSize: 10, color: C.muted }}>{`${new Date(stats.from).toLocaleString()} to ${new Date(stats.to).toLocaleString()}`}</span>}
      </div>

      {err ? (
        <Card><div style={{ fontSize: 11, color: C.red }}>{`Audit analytics unavailable: ${err}`}</div></Card>
      ) : !stats ? null : <>
        <DrillHint />
        <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
          <Stat l="Events" v={stats.total} c="accent" />
          <Stat l="Not successful" v={failures} c={failures ? "amber" : "green"} />
          <Stat l="Services" v={stats.services} c="blue" />
          <Stat l="Actors" v={stats.actors} c="blue" />
        </div>

        <Row3>
          <Card>
            <div style={title}>Events by result</div>
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={byResult} cx="50%" cy="50%" innerRadius={40} outerRadius={65} dataKey="count" nameKey="key" paddingAngle={3} strokeWidth={0}
                  onClick={(d) => { const r = d?.payload as { key: string; count: number }; open(`Result: ${r.key}`, r.count, { result: r.key }); }}>
                  {byResult.map((r) => <Cell key={r.key} fill={RESULT_COLORS[r.key] || C.dim} style={clickable} />)}
                </Pie>
                <Tooltip />
                <Legend wrapperStyle={{ fontSize: 9, color: C.dim }} />
              </PieChart>
            </ResponsiveContainer>
          </Card>
          <Card>
            <div style={title}>Top services</div>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={stats.top_services.map((s) => ({ ...s, name: shortService(s.key) }))} layout="vertical" margin={{ left: 40, right: 10 }}>
                <XAxis type="number" tick={axisTick} axisLine={{ stroke: C.border }} tickLine={false} allowDecimals={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: C.dim, fontSize: 9 }} axisLine={false} tickLine={false} width={60} />
                <Tooltip />
                <Bar dataKey="count" name="Events" fill={C.blue} radius={[0, 4, 4, 0]} barSize={12} style={clickable}
                  onClick={(d) => { const s = d?.payload as { key: string; count: number }; open(`Service: ${shortService(s.key)}`, s.count, { service: s.key }); }} />
              </BarChart>
            </ResponsiveContainer>
          </Card>
          <Card>
            <div style={title}>Risk score distribution</div>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={stats.risk_buckets}>
                <XAxis dataKey="key" tick={axisTick} axisLine={{ stroke: C.border }} tickLine={false} />
                <YAxis tick={axisTick} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" name="Events" radius={[4, 4, 0, 0]} barSize={24} style={clickable}
                  onClick={(d) => {
                    const r = d?.payload as { key: string; count: number };
                    const [lo = 0, hi = 100] = r.key.split("-").map(Number);
                    open(`Risk score ${r.key}`, r.count, { risk_min: lo, risk_max: hi });
                  }}>
                  {stats.risk_buckets.map((_, i) => <Cell key={i} fill={RISK_COLORS[i] || C.dim} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </Row3>

        <div style={{ height: 10 }} />
        <Row2>
          <Card>
            <div style={title}>{`Event volume (UTC, per ${bucketUnit(stats.bucket_seconds)})`}</div>
            {stats.total === 0 ? <div style={{ fontSize: 10, color: C.muted, padding: 20, textAlign: "center" }}>No events in this window.</div> : (
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={series} margin={{ top: 5, right: 10, left: 0, bottom: 0 }} onClick={pickSeries} style={clickable}>
                  <XAxis dataKey="time" tick={axisTick} axisLine={{ stroke: C.border }} tickLine={false} interval="preserveStartEnd" />
                  <YAxis tick={axisTick} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip />
                  <Area type="monotone" dataKey="count" name="Events" stroke={C.accent} strokeWidth={2} fill={C.accentDim} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </Card>
          <Card>
            <div style={title}>Top actors</div>
            {stats.top_actors.length === 0 ? <div style={{ fontSize: 10, color: C.muted }}>No actor data.</div> : stats.top_actors.map((a) => (
              <div key={a.key} onClick={() => open(`Actor: ${a.key}`, a.count, { actor_id: a.key })}
                style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", borderBottom: `1px solid ${C.border}`, fontSize: 10, ...clickable }}>
                <span style={{ color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "75%" }}>{a.key || "-"}</span>
                <span style={{ color: C.text, fontWeight: 600 }}>{a.count}</span>
              </div>
            ))}
          </Card>
        </Row2>

        {drill && (
          <DrillPanel label={drill.label} count={drill.count} onClear={() => setDrill(null)}
            loaded={paged.rows.length} loading={paged.loading} error={paged.error} onMore={paged.done ? undefined : paged.loadMore}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>{["Time", "Service", "Action", "Actor", "Target", "Result", "Risk"].map((h) => <th key={h} style={TH}>{h}</th>)}</tr></thead>
              <tbody>
                {paged.rows.map((e) => (
                  <tr key={e.id} onClick={() => onOpenEvent(e)} style={clickable}
                    onMouseEnter={(ev) => { ev.currentTarget.style.background = C.cardHover; }}
                    onMouseLeave={(ev) => { ev.currentTarget.style.background = ""; }}>
                    <td style={TD}>{new Date(String(e.timestamp || "")).toLocaleString()}</td>
                    <td style={TD}><B c="blue">{shortService(e.service)}</B></td>
                    <td style={{ ...TD, color: C.text }} title={e.action}>{e.action}</td>
                    <td style={TD}>{e.actor_id || "-"}</td>
                    <td style={TD}>{e.target_id || "-"}</td>
                    <td style={TD}><B c={resultTone(String(e.result || "").toLowerCase())}>{e.result}</B></td>
                    <td style={TD}>{e.risk_score ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </DrillPanel>
        )}
      </>}
    </div>
  );
}
