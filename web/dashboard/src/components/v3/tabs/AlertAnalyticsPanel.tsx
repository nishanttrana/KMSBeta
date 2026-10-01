import { type ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { Area, AreaChart, Bar, BarChart, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { AuthSession } from "../../../lib/auth";
import {
  getReportingAlertStats, getReportingMTTD, getReportingMTTR, getReportingTopSources, listReportingAlerts,
  type AlertListQuery, type ReportingAlert
} from "../../../lib/reporting";
import { Btn, Card, Row2, Row3 } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import {
  bucketBounds, bucketLabel, bucketUnit, clickable, clickedIndex, DEFAULT_WINDOW, DrillHint, DrillPanel,
  usePagedDrill, windowFrom, WindowSelect, type ServerDrill, type WindowId
} from "../chartDrill";
import { C } from "../theme";

// Analytics sub-tab of the Alert Center: kms-reporting counts every alert in
// the window (a day to a year, or since uptime). Clicking a chart segment
// lists exactly the alerts it counts through GET /alerts with the same
// filters, rendered as the Alert Center's own triage cards.
const SEVERITIES = ["critical", "high", "warning", "info"];
const SEV_COLORS: Record<string, string> = { critical: C.red, high: C.orange, warning: C.amber, info: C.blue };
const STATUS_COLORS: Record<string, string> = { resolved: C.green, acknowledged: C.blue, new: C.amber, false_positive: C.muted };

const title: React.CSSProperties = { fontSize: 10, fontWeight: 600, color: C.dim, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 };
const axisTick = { fill: C.muted, fontSize: 9 };
const empty = (text: string) => <div style={{ height: 160, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, color: C.muted }}>{text}</div>;

type Stats = Awaited<ReturnType<typeof getReportingAlertStats>>;
type Sources = Awaited<ReturnType<typeof getReportingTopSources>>;
type MTTD = Awaited<ReturnType<typeof getReportingMTTD>>;

const minutesBars = (m: Record<string, number>) => SEVERITIES
  .filter((k) => Number(m[k] || 0) > 0)
  .map((k) => ({ name: k, minutes: Math.round(Number(m[k])), fill: SEV_COLORS[k] || C.dim }));

type Props = {
  session: AuthSession;
  // Bumped by the Alert Center after a triage action so the charts reload.
  refreshKey?: number;
  renderAlert: (alert: ReportingAlert) => ReactNode;
};

export function AlertAnalyticsPanel({ session, refreshKey = 0, renderAlert }: Props) {
  const [windowId, setWindowId] = useState<WindowId>(DEFAULT_WINDOW);
  const [stats, setStats] = useState<Stats | null>(null);
  const [mttr, setMttr] = useState<Record<string, number>>({});
  const [mttd, setMttd] = useState<MTTD>({ minutes: {}, measured: 0, truncated: false });
  const [sources, setSources] = useState<Sources | null>(null);
  const [drill, setDrill] = useState<ServerDrill<AlertListQuery> | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    if (!session?.token) return;
    setLoading(true); setErr(""); setDrill(null);
    try {
      // One window for every call: the stats response pins "to", so the
      // other statistics and every drill-down use the same bounds.
      const s = await getReportingAlertStats(session, { from: windowFrom(windowId) });
      const w = { from: s.from, to: s.to };
      const [r, d, t] = await Promise.all([getReportingMTTR(session, w), getReportingMTTD(session, w), getReportingTopSources(session, w)]);
      setStats(s); setMttr(r); setMttd(d); setSources(t);
    } catch (e) {
      setStats(null); setSources(null); setErr(errMsg(e));
    } finally { setLoading(false); }
  }, [session, windowId]);

  useEffect(() => { void load(); }, [load, refreshKey]);

  const fetchPage = useCallback((q: AlertListQuery, offset: number, limit: number) =>
    listReportingAlerts(session, { ...q, offset, limit }), [session]);
  const paged = usePagedDrill(drill, fetchPage);

  const bySeverity = useMemo(() => SEVERITIES
    .map((k) => ({ name: k, value: Number(stats?.by_severity?.[k] || 0), fill: SEV_COLORS[k] || C.dim }))
    .filter((d) => d.value > 0), [stats]);
  const series = useMemo(() => (stats?.series ?? []).map((p) => ({ ...p, time: bucketLabel(p.start, stats?.bucket_seconds || 3600) })), [stats]);
  const statusTotal = useMemo(() => Object.values(stats?.by_status || {}).reduce((s, v) => s + Number(v || 0), 0), [stats]);

  const open = (label: string, count: number | undefined, query: AlertListQuery) => {
    if (!stats) return;
    setDrill({ label, count, query: { from: stats.from, to: stats.to, ...query } });
  };
  const pickSeries = (state: { activeIndex?: unknown } | null) => {
    const p = series[clickedIndex(state)];
    if (!p || !stats) return;
    open(`Raised in the ${bucketUnit(stats.bucket_seconds)} from ${p.time} UTC`, p.count, bucketBounds(p.start, stats.bucket_seconds, stats.from, stats.to));
  };
  // The count behind a timing bar isn't returned per severity; the list shows
  // every alert of that severity the mean was taken over.
  const pickTiming = (kind: "detect" | "resolve", sev: string) => open(
    kind === "resolve" ? `Resolved ${sev} alerts (time to resolve)` : `${sev} alerts linked to an audit event (time to detect)`,
    undefined,
    kind === "resolve" ? { severity: sev, resolved: true } : { severity: sev, linked: true });

  if (err) return (
    <Card>
      <div style={{ fontSize: 11, color: C.red, marginBottom: 8 }}>{`Alert analytics unavailable: ${err}`}</div>
      <Btn small onClick={() => void load()}>Retry</Btn>
    </Card>
  );

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
        <WindowSelect value={windowId} onChange={setWindowId} />
        <Btn small onClick={() => void load()} disabled={loading}>{loading ? "Loading…" : "Refresh"}</Btn>
        <span style={{ fontSize: 10, color: C.muted }}>{`${stats?.total ?? 0} alerts in this window, including informational ones the triage list hides.`}</span>
      </div>
      <DrillHint />

      <Row3>
        <Card>
          <div style={title}>Alerts by severity</div>
          {bySeverity.length ? (
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie data={bySeverity} cx="50%" cy="50%" innerRadius={35} outerRadius={55} paddingAngle={3} dataKey="value" strokeWidth={0}
                  onClick={(d) => { const p = d?.payload as { name: string; value: number }; open(`Severity: ${p.name}`, p.value, { severity: p.name }); }}>
                  {bySeverity.map((d) => <Cell key={d.name} fill={d.fill} style={clickable} />)}
                </Pie>
                <Tooltip />
                <Legend verticalAlign="bottom" height={24} iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 9, color: C.dim }} />
              </PieChart>
            </ResponsiveContainer>
          ) : empty("No alerts.")}
        </Card>
        <Card>
          <div style={title}>{`Alerts over time (UTC, per ${bucketUnit(stats?.bucket_seconds || 3600)})`}</div>
          {stats?.total ? (
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={series} onClick={pickSeries} style={clickable}>
                <XAxis dataKey="time" tick={axisTick} axisLine={{ stroke: C.border }} tickLine={false} interval="preserveStartEnd" />
                <YAxis tick={axisTick} axisLine={false} tickLine={false} width={25} allowDecimals={false} />
                <Tooltip />
                <Area type="monotone" dataKey="count" name="Alerts" stroke={C.accent} strokeWidth={2} fill={C.accentDim} />
              </AreaChart>
            </ResponsiveContainer>
          ) : empty("No alerts in this window.")}
        </Card>
        <Card>
          <div style={title}>Resolution status</div>
          {statusTotal ? (
            <>
              <div style={{ display: "flex", height: 14, borderRadius: 7, overflow: "hidden", border: `1px solid ${C.border}`, margin: "20px 0 10px" }}>
                {Object.entries(stats?.by_status || {}).filter(([, v]) => Number(v) > 0).map(([k, v]) => (
                  <div key={k} title={`${k}: ${v}`} onClick={() => open(`Status: ${k.replace("_", " ")}`, Number(v), { status: k })}
                    style={{ width: `${(Number(v) / statusTotal) * 100}%`, background: STATUS_COLORS[k] || C.dim, ...clickable }} />
                ))}
              </div>
              {Object.entries(stats?.by_status || {}).map(([k, v]) => (
                <div key={k} onClick={() => open(`Status: ${k.replace("_", " ")}`, Number(v), { status: k })}
                  style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: C.dim, padding: "2px 0", ...clickable }}>
                  <span>{k.replace("_", " ")}</span><span style={{ color: C.text, fontWeight: 600 }}>{Number(v)}</span>
                </div>
              ))}
            </>
          ) : empty("No alerts.")}
        </Card>
      </Row3>

      <div style={{ height: 10 }} />
      <Row2>
        {([["Mean time to detect", mttd.minutes, "detect"], ["Mean time to resolve", mttr, "resolve"]] as const).map(([label, m, kind]) => {
          const bars = minutesBars(m);
          return (
            <Card key={label}>
              <div style={title}>{`${label} (minutes)`}</div>
              {kind === "detect" && mttd.truncated && (
                <div style={{ fontSize: 9, color: C.amber, marginBottom: 4 }}>{`Measured over the newest ${mttd.measured} linked alerts; the window has more.`}</div>
              )}
              {bars.length ? (
                <ResponsiveContainer width="100%" height={150}>
                  <BarChart data={bars} layout="vertical">
                    <XAxis type="number" tick={axisTick} axisLine={false} tickLine={false} />
                    <YAxis type="category" dataKey="name" tick={{ fill: C.dim, fontSize: 10 }} axisLine={false} tickLine={false} width={55} />
                    <Tooltip />
                    <Bar dataKey="minutes" name="Minutes" radius={[0, 4, 4, 0]} style={clickable}
                      onClick={(d) => pickTiming(kind, String((d?.payload as { name: string })?.name || ""))}>
                      {bars.map((b) => <Cell key={b.name} fill={b.fill} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : empty(kind === "detect" ? "No alerts to measure in this window." : "No resolved alerts in this window.")}
            </Card>
          );
        })}
      </Row2>

      <div style={{ height: 10 }} />
      <Row3>
        {([["Top actors", "Actor", "actor_id", sources?.top_actors], ["Top source IPs", "Source IP", "source_ip", sources?.top_ips], ["Top services", "Service", "service", sources?.top_services]] as const).map(([label, one, field, items]) => (
          <Card key={label}>
            <div style={title}>{label}</div>
            {items?.length ? items.slice(0, 5).map((it, i) => (
              <div key={i} onClick={() => open(`${one}: ${String(it?.key)}`, Number(it?.count || 0), { [field]: String(it?.key || "") })}
                style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", borderBottom: `1px solid ${C.border}`, fontSize: 10, ...clickable }}>
                <span style={{ color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "75%" }}>{String(it?.key || "-")}</span>
                <span style={{ color: C.text, fontWeight: 600 }}>{Number(it?.count || 0)}</span>
              </div>
            )) : <span style={{ fontSize: 10, color: C.muted }}>No data.</span>}
          </Card>
        ))}
      </Row3>

      {drill && (
        <DrillPanel label={drill.label} count={drill.count} onClear={() => setDrill(null)}
          loaded={paged.rows.length} loading={paged.loading} error={paged.error} onMore={paged.done ? undefined : paged.loadMore}>
          <div style={{ display: "grid", gap: 8 }}>{paged.rows.map((a) => <div key={a.id}>{renderAlert(a)}</div>)}</div>
        </DrillPanel>
      )}
    </div>
  );
}
