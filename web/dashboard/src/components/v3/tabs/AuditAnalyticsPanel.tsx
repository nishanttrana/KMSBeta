import { useCallback, useEffect, useMemo, useState } from "react";
import { Area, AreaChart, Bar, BarChart, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { AuthSession } from "../../../lib/auth";
import { listAuditEvents, type AuditEvent } from "../../../lib/audit";
import { B, Btn, Card, Row2, Row3, Sel, Stat } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";

// Audit activity section of the Analytics tab. The audit service has no
// aggregate endpoint, so this pages through the newest events in the window
// (up to MAX_EVENTS) and says how many it analysed rather than calling the
// sample a total.
const PAGE = 500;
const MAX_EVENTS = 2000;

const WINDOWS: Record<string, number> = { "24h": 24, "7d": 24 * 7, "30d": 24 * 30 };
const RESULT_COLORS: Record<string, string> = { success: C.green, failure: C.red, denied: C.amber, refused: C.amber };
const RISK_BUCKETS = ["0-20", "21-40", "41-60", "61-80", "81-100"];
const RISK_COLORS: string[] = [C.green, C.green, C.amber, C.orange, C.red];

const title: React.CSSProperties = { fontSize: 10, fontWeight: 600, color: C.dim, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 };
const axisTick = { fill: C.muted, fontSize: 9 };

function countBy(events: AuditEvent[], key: (e: AuditEvent) => string, top = 0) {
  const counts: Record<string, number> = {};
  events.forEach((e) => { const k = key(e); if (k) counts[k] = (counts[k] || 0) + 1; });
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, value]) => ({ name, value }));
  return top ? rows.slice(0, top) : rows;
}

export function AuditAnalyticsPanel({ session }: { session: AuthSession }) {
  const [windowKey, setWindowKey] = useState("24h");
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    if (!session?.token) return;
    setLoading(true); setErr("");
    try {
      const from = new Date(Date.now() - (WINDOWS[windowKey] ?? 24) * 3600 * 1000).toISOString();
      const out: AuditEvent[] = [];
      let full = true;
      while (out.length < MAX_EVENTS && full) {
        const page = await listAuditEvents(session, { from, limit: PAGE, offset: out.length });
        out.push(...page);
        full = page.length === PAGE;
      }
      setEvents(out.filter((e) => !String(e.action || "").toLowerCase().includes(".http_request")));
      setTruncated(full);
    } catch (e) {
      setEvents([]); setTruncated(false); setErr(errMsg(e));
    } finally { setLoading(false); }
  }, [session, windowKey]);

  useEffect(() => { void load(); }, [load]);

  const byResult = useMemo(() => countBy(events, (e) => String(e.result || "").toLowerCase()), [events]);
  const byService = useMemo(() => countBy(events, (e) => String(e.service || "").replace(/^kms-/, ""), 10), [events]);
  const topActors = useMemo(() => countBy(events, (e) => e.actor_id, 10), [events]);
  const risk = useMemo(() => {
    const buckets = [0, 0, 0, 0, 0];
    events.forEach((e) => { const s = Math.max(0, Math.min(100, Number(e.risk_score || 0))); const b = Math.min(4, Math.floor(Math.max(0, s - 1) / 20)); buckets[b] = (buckets[b] ?? 0) + 1; });
    return RISK_BUCKETS.map((range, i) => ({ range, count: buckets[i] }));
  }, [events]);
  const volume = useMemo(() => {
    const byHour = windowKey === "24h";
    const counts: Record<string, number> = {};
    events.forEach((e) => {
      const dt = new Date(String(e.timestamp || ""));
      if (Number.isNaN(dt.getTime())) return;
      const iso = dt.toISOString();
      const k = byHour ? iso.slice(0, 13) : iso.slice(0, 10);
      counts[k] = (counts[k] || 0) + 1;
    });
    return Object.keys(counts).sort().map((k) => ({ time: byHour ? `${k.slice(5, 10)} ${k.slice(11)}:00` : k.slice(5), count: counts[k] }));
  }, [events, windowKey]);

  const failures = byResult.filter((r) => r.name !== "success").reduce((s, r) => s + r.value, 0);

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
        <Sel w={110} value={windowKey} onChange={(e) => setWindowKey(e.target.value)}>
          <option value="24h">Last 24h</option>
          <option value="7d">Last 7 days</option>
          <option value="30d">Last 30 days</option>
        </Sel>
        <Btn small onClick={() => void load()} disabled={loading}>{loading ? "Loading…" : "Refresh"}</Btn>
        {truncated && <B c="amber">{`Newest ${events.length} events analysed — window has more`}</B>}
      </div>

      {err ? (
        <Card><div style={{ fontSize: 11, color: C.red }}>{`Audit analytics unavailable: ${err}`}</div></Card>
      ) : <>
        <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
          <Stat l="Events analysed" v={events.length} c="accent" />
          <Stat l="Not successful" v={failures} c={failures ? "amber" : "green"} />
          <Stat l="Services" v={byService.length} c="blue" />
          <Stat l="Actors" v={countBy(events, (e) => e.actor_id).length} c="blue" />
        </div>

        <Row3>
          <Card>
            <div style={title}>Events by result</div>
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={byResult} cx="50%" cy="50%" innerRadius={40} outerRadius={65} dataKey="value" nameKey="name" paddingAngle={3} strokeWidth={0}>
                  {byResult.map((r) => <Cell key={r.name} fill={RESULT_COLORS[r.name] || C.dim} />)}
                </Pie>
                <Tooltip />
                <Legend wrapperStyle={{ fontSize: 9, color: C.dim }} />
              </PieChart>
            </ResponsiveContainer>
          </Card>
          <Card>
            <div style={title}>Top services</div>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={byService} layout="vertical" margin={{ left: 40, right: 10 }}>
                <XAxis type="number" tick={axisTick} axisLine={{ stroke: C.border }} tickLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: C.dim, fontSize: 9 }} axisLine={false} tickLine={false} width={60} />
                <Tooltip />
                <Bar dataKey="value" name="Events" fill={C.blue} radius={[0, 4, 4, 0]} barSize={12} />
              </BarChart>
            </ResponsiveContainer>
          </Card>
          <Card>
            <div style={title}>Risk score distribution</div>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={risk}>
                <XAxis dataKey="range" tick={axisTick} axisLine={{ stroke: C.border }} tickLine={false} />
                <YAxis tick={axisTick} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" name="Events" radius={[4, 4, 0, 0]} barSize={24}>
                  {risk.map((_, i) => <Cell key={i} fill={RISK_COLORS[i] || C.dim} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </Row3>

        <div style={{ height: 10 }} />
        <Row2>
          <Card>
            <div style={title}>{`Event volume (UTC, per ${windowKey === "24h" ? "hour" : "day"})`}</div>
            {volume.length === 0 ? <div style={{ fontSize: 10, color: C.muted, padding: 20, textAlign: "center" }}>No events in this window.</div> : (
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={volume} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
                  <XAxis dataKey="time" tick={axisTick} axisLine={{ stroke: C.border }} tickLine={false} />
                  <YAxis tick={axisTick} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip />
                  <Area type="monotone" dataKey="count" name="Events" stroke={C.accent} strokeWidth={2} fill={C.accentDim} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </Card>
          <Card>
            <div style={title}>Top actors</div>
            {topActors.length === 0 ? <div style={{ fontSize: 10, color: C.muted }}>No actor data.</div> : topActors.map((a) => (
              <div key={a.name} style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", borderBottom: `1px solid ${C.border}`, fontSize: 10 }}>
                <span style={{ color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "75%" }}>{a.name}</span>
                <span style={{ color: C.text, fontWeight: 600 }}>{a.value}</span>
              </div>
            ))}
          </Card>
        </Row2>
      </>}
    </div>
  );
}
