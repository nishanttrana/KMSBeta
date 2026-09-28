import { useCallback, useEffect, useMemo, useState } from "react";
import { Area, AreaChart, Bar, BarChart, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { AuthSession } from "../../../lib/auth";
import { getReportingAlertStats, getReportingMTTD, getReportingMTTR, getReportingTopSources } from "../../../lib/reporting";
import { Btn, Card, Row2, Row3 } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";

// Alerts section of the Analytics tab: trends over the Alert Center's store
// (kms-reporting). Triage stays in the Alert Center; this is read-only.
const SEVERITIES = ["critical", "high", "warning", "info"];
const SEV_COLORS: Record<string, string> = { critical: C.red, high: C.orange, warning: C.amber, info: C.blue };
const STATUS_COLORS: Record<string, string> = { resolved: C.green, acknowledged: C.blue, new: C.amber, false_positive: C.muted };

const title: React.CSSProperties = { fontSize: 10, fontWeight: 600, color: C.dim, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 };
const axisTick = { fill: C.muted, fontSize: 9 };
const empty = (text: string) => <div style={{ height: 160, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, color: C.muted }}>{text}</div>;

type Stats = Awaited<ReturnType<typeof getReportingAlertStats>>;
type Sources = Awaited<ReturnType<typeof getReportingTopSources>>;

const minutesBars = (m: Record<string, number>) => SEVERITIES
  .filter((k) => Number(m[k] || 0) > 0)
  .map((k) => ({ name: k, minutes: Math.round(Number(m[k])), fill: SEV_COLORS[k] || C.dim }));

export function AlertAnalyticsPanel({ session }: { session: AuthSession }) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [mttr, setMttr] = useState<Record<string, number>>({});
  const [mttd, setMttd] = useState<Record<string, number>>({});
  const [sources, setSources] = useState<Sources | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    if (!session?.token) return;
    setLoading(true); setErr("");
    try {
      const [s, r, d, t] = await Promise.all([
        getReportingAlertStats(session), getReportingMTTR(session), getReportingMTTD(session), getReportingTopSources(session)
      ]);
      setStats(s); setMttr(r); setMttd(d); setSources(t);
    } catch (e) {
      setStats(null); setSources(null); setErr(errMsg(e));
    } finally { setLoading(false); }
  }, [session]);

  useEffect(() => { void load(); }, [load]);

  const bySeverity = useMemo(() => SEVERITIES
    .map((k) => ({ name: k, value: Number(stats?.by_severity?.[k] || 0), fill: SEV_COLORS[k] || C.dim }))
    .filter((d) => d.value > 0), [stats]);
  const daily = useMemo(() => Object.entries(stats?.daily_trend || {})
    .sort(([a], [b]) => a.localeCompare(b)).slice(-14)
    .map(([date, count]) => ({ name: date.slice(5), alerts: Number(count || 0) })), [stats]);
  const statusTotal = useMemo(() => Object.values(stats?.by_status || {}).reduce((s, v) => s + Number(v || 0), 0), [stats]);

  if (err) return (
    <Card>
      <div style={{ fontSize: 11, color: C.red, marginBottom: 8 }}>{`Alert analytics unavailable: ${err}`}</div>
      <Btn small onClick={() => void load()}>Retry</Btn>
    </Card>
  );

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
        <Btn small onClick={() => void load()} disabled={loading}>{loading ? "Loading…" : "Refresh"}</Btn>
        <span style={{ fontSize: 10, color: C.muted }}>{`${stats?.total ?? 0} alerts in the Alert Center. Triage them there.`}</span>
      </div>

      <Row3>
        <Card>
          <div style={title}>Alerts by severity</div>
          {bySeverity.length ? (
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie data={bySeverity} cx="50%" cy="50%" innerRadius={35} outerRadius={55} paddingAngle={3} dataKey="value" strokeWidth={0}>
                  {bySeverity.map((d) => <Cell key={d.name} fill={d.fill} />)}
                </Pie>
                <Tooltip />
                <Legend verticalAlign="bottom" height={24} iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 9, color: C.dim }} />
              </PieChart>
            </ResponsiveContainer>
          ) : empty("No alerts.")}
        </Card>
        <Card>
          <div style={title}>Daily alerts (last 14 days)</div>
          {daily.length ? (
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={daily}>
                <XAxis dataKey="name" tick={axisTick} axisLine={{ stroke: C.border }} tickLine={false} interval="preserveStartEnd" />
                <YAxis tick={axisTick} axisLine={false} tickLine={false} width={25} allowDecimals={false} />
                <Tooltip />
                <Area type="monotone" dataKey="alerts" name="Alerts" stroke={C.accent} strokeWidth={2} fill={C.accentDim} />
              </AreaChart>
            </ResponsiveContainer>
          ) : empty("No daily trend yet.")}
        </Card>
        <Card>
          <div style={title}>Resolution status</div>
          {statusTotal ? (
            <>
              <div style={{ display: "flex", height: 14, borderRadius: 7, overflow: "hidden", border: `1px solid ${C.border}`, margin: "20px 0 10px" }}>
                {Object.entries(stats?.by_status || {}).filter(([, v]) => Number(v) > 0).map(([k, v]) => (
                  <div key={k} title={`${k}: ${v}`} style={{ width: `${(Number(v) / statusTotal) * 100}%`, background: STATUS_COLORS[k] || C.dim }} />
                ))}
              </div>
              {Object.entries(stats?.by_status || {}).map(([k, v]) => (
                <div key={k} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: C.dim, padding: "2px 0" }}>
                  <span>{k.replace("_", " ")}</span><span style={{ color: C.text, fontWeight: 600 }}>{Number(v)}</span>
                </div>
              ))}
            </>
          ) : empty("No alerts.")}
        </Card>
      </Row3>

      <div style={{ height: 10 }} />
      <Row2>
        {([["Mean time to detect", mttd], ["Mean time to resolve", mttr]] as const).map(([label, m]) => {
          const bars = minutesBars(m);
          return (
            <Card key={label}>
              <div style={title}>{`${label} (minutes)`}</div>
              {bars.length ? (
                <ResponsiveContainer width="100%" height={150}>
                  <BarChart data={bars} layout="vertical">
                    <XAxis type="number" tick={axisTick} axisLine={false} tickLine={false} />
                    <YAxis type="category" dataKey="name" tick={{ fill: C.dim, fontSize: 10 }} axisLine={false} tickLine={false} width={55} />
                    <Tooltip />
                    <Bar dataKey="minutes" name="Minutes" radius={[0, 4, 4, 0]}>
                      {bars.map((b) => <Cell key={b.name} fill={b.fill} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : empty("No resolved alerts to measure yet.")}
            </Card>
          );
        })}
      </Row2>

      <div style={{ height: 10 }} />
      <Row3>
        {([["Top actors", sources?.top_actors], ["Top source IPs", sources?.top_ips], ["Top services", sources?.top_services]] as const).map(([label, items]) => (
          <Card key={label}>
            <div style={title}>{label}</div>
            {items?.length ? items.slice(0, 5).map((it, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", borderBottom: `1px solid ${C.border}`, fontSize: 10 }}>
                <span style={{ color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "75%" }}>{String(it?.key || "-")}</span>
                <span style={{ color: C.text, fontWeight: 600 }}>{Number(it?.count || 0)}</span>
              </div>
            )) : <span style={{ fontSize: 10, color: C.muted }}>No data.</span>}
          </Card>
        ))}
      </Row3>
    </div>
  );
}
