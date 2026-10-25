import { useCallback, useEffect, useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { AlertTriangle, CalendarClock, PauseCircle, PlayCircle } from "lucide-react";
import type { AuthSession } from "../../lib/auth";
import { isSystemAdminSession } from "../../config/moduleRegistry";
import { B, Btn, Card, Stat } from "../../components/v3/legacyPrimitives";
import { clickable } from "../../components/v3/chartDrill";
import { C } from "../../components/v3/theme";
import { dayOf, KINDS, loadSchedules, type RunResult, type ScheduleRow, type Source } from "./rows";

// Scheduling → Overview: every schedule in the platform, read from the
// service that runs it. Tiles and the upcoming-runs bars filter the table to
// exactly the schedules they count; a row opens its kind's view.

const title: React.CSSProperties = { fontSize: 10.5, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "var(--font-mono)" };
const TH: React.CSSProperties = { fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, padding: "7px 8px", textAlign: "left", borderBottom: `1px solid ${C.border}` };
const TD: React.CSSProperties = { fontSize: 11.5, color: C.dim, padding: "8px", borderBottom: `1px solid ${C.border}`, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 260 };
const DAY = 86_400_000;
const RESULT: Record<RunResult, { tone: string; label: string }> = {
  ok: { tone: "green", label: "ran" }, failed: { tone: "red", label: "failed" }, refused: { tone: "amber", label: "refused" }, never: { tone: "neutral", label: "not run yet" },
};
const when = (t: number | null) => (t ? new Date(t).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—");

type Filter = { label: string; match: (r: ScheduleRow) => boolean };

export function SchedulingOverview({ session, onOpen }: { session: AuthSession; onOpen: (sub: string) => void }) {
  const [sources, setSources] = useState<Source[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<Filter | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try { setSources(await loadSchedules(session, isSystemAdminSession(session))); } finally { setLoading(false); }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const rows = useMemo(() => (sources ?? []).flatMap((s) => s.rows ?? []).sort((a, b) => (a.next ?? Infinity) - (b.next ?? Infinity)), [sources]);
  const failed = (sources ?? []).filter((s) => s.error);
  const now = Date.now();
  const filters: Record<string, Filter> = {
    active: { label: "Active", match: (r) => r.state === "active" },
    due: { label: "Due in 24 hours", match: (r) => r.next !== null && r.next <= now + DAY },
    paused: { label: "Paused", match: (r) => r.state === "paused" },
    failing: { label: "Last run failed or refused", match: (r) => r.result === "failed" || r.result === "refused" },
  };
  const count = (f: Filter) => rows.filter(f.match).length;
  // The next seven days; anything already due counts on today.
  const days = useMemo(() => Array.from({ length: 7 }, (_, i) => {
    const day = dayOf(now + i * DAY);
    const match = (r: ScheduleRow) => r.next !== null && dayOf(Math.max(r.next, now)) === day;
    return { day, label: new Date(now + i * DAY).toLocaleDateString(undefined, { weekday: "short", day: "numeric" }), match, runs: rows.filter(match).length };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- now changes every render; the days follow the loaded rows
  }), [rows]);
  const shown = filter ? rows.filter(filter.match) : rows;

  return (
    <div style={{ display: "grid", gap: 12 }} data-testid="scheduling-overview">
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <Btn small onClick={() => void load()} disabled={loading}>{loading ? "Loading…" : "Refresh"}</Btn>
        {failed.map((s) => (
          <B key={s.kind} c="amber">{`${KINDS[s.kind].label}: unavailable`}</B>
        ))}
      </div>
      {failed.length > 0 && (
        <Card>
          <div data-keep>
            {failed.map((s) => <div key={s.kind} style={{ fontSize: 11, color: C.amberFg }}>{`${KINDS[s.kind].label} schedules unavailable: ${s.error}`}</div>)}
          </div>
        </Card>
      )}
      {sources && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(190px,1fr))", gap: 10 }}>
            {([["active", PlayCircle, undefined], ["due", CalendarClock, undefined], ["paused", PauseCircle, "amber"], ["failing", AlertTriangle, "red"]] as const).map(([id, icon, tone]) => {
              const f = filters[id]!;
              const n = count(f);
              const on = filter?.label === f.label;
              return (
                <button key={id} type="button" aria-pressed={on} onClick={() => setFilter(on ? null : f)}
                  style={{ all: "unset", display: "flex", cursor: "pointer", borderRadius: "var(--radius-md)", outline: on ? `2px solid ${C.accentFg}` : "none" }}>
                  <Stat l={f.label} v={n.toLocaleString()} i={icon} c={n && tone ? tone : "accent"} />
                </button>
              );
            })}
          </div>

          <Card>
            <div style={{ ...title, marginBottom: 8 }}>Runs due in the next 7 days</div>
            <ResponsiveContainer width="100%" height={170}>
              <BarChart data={days} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke={C.border} />
                <XAxis dataKey="label" tick={{ fill: C.muted, fontSize: 10 }} axisLine={{ stroke: C.border }} tickLine={false} />
                <YAxis tick={{ fill: C.muted, fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} width={30} />
                <Tooltip cursor={{ fill: C.dimTint }} />
                <Bar dataKey="runs" name="Schedules due" fill="var(--cls-op-ok)" radius={[2, 2, 0, 0]} style={clickable}
                  onClick={(_d, i) => { const d = days[i]; if (d?.runs) setFilter({ label: `Due ${d.label}`, match: d.match }); }} />
              </BarChart>
            </ResponsiveContainer>
          </Card>

          <Card style={{ padding: 0, overflow: "hidden" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "12px 14px 8px" }}>
              <span style={title}>{filter ? `${filter.label}: ${shown.length}` : `All schedules: ${rows.length}`}</span>
              {filter && <Btn small onClick={() => setFilter(null)}>{`Clear ${filter.label}`}</Btn>}
            </div>
            {shown.length === 0 ? <div style={{ padding: "8px 14px 16px", fontSize: 11.5, color: C.muted }}>{rows.length ? "None match." : "Nothing is scheduled yet."}</div> : (
              <table style={{ width: "100%", borderCollapse: "collapse", tableLayout: "fixed" }}>
                <thead><tr>{["What", "Name", "Runs", "Next", "Last", "Result", "On the authority of", ""].map((h) => <th key={h} style={TH}>{h}</th>)}</tr></thead>
                <tbody>
                  {shown.map((r) => (
                    <tr key={`${r.kind}:${r.id}`} data-testid="schedule-row" onClick={() => onOpen(KINDS[r.kind].sub)} style={clickable}
                      onMouseEnter={(e) => { e.currentTarget.style.background = C.cardHover; }} onMouseLeave={(e) => { e.currentTarget.style.background = ""; }}>
                      <td style={TD}>{KINDS[r.kind].label}</td>
                      <td style={{ ...TD, color: C.text, fontWeight: 600 }} title={r.detail}>{r.name}</td>
                      <td style={TD}>{r.cadence}</td>
                      <td style={TD}>{r.state === "active" ? when(r.next) : "—"}</td>
                      <td style={TD}>{when(r.last)}</td>
                      <td style={TD} title={r.detail}><B c={RESULT[r.result].tone}>{RESULT[r.result].label}</B></td>
                      <td style={{ ...TD, fontFamily: "var(--font-mono)" }}>{r.authorizedBy || "no one"}</td>
                      <td style={TD} title={r.pausedReason}>{r.state === "paused" ? <B c="amber">paused</B> : r.state === "off" ? <B c="neutral">off</B> : null}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
