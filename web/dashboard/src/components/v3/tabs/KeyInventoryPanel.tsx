import { useCallback, useEffect, useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CheckCircle2, KeyRound, Layers, PlusCircle } from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import { getKeyStats, listKeyStatKeys, type KeyItem, type KeyStatCount, type KeyStatQuery, type KeyStats } from "../../../lib/keycore";
import { B, Btn, Card, Stat } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import {
  bucketBounds, bucketLabel, bucketUnit, clickable, DEFAULT_WINDOW, DrillHint, DrillPanel,
  usePagedDrill, windowFrom, windowLabel, WindowSelect, type ServerDrill, type WindowId
} from "../chartDrill";
import { C } from "../theme";

// Key inventory view of Operations: keys that are not deleted, counted by
// keycore (GET /inventory/stats). Each bar lists exactly the keys it counts
// (GET /inventory/stats/keys, same predicate); a row opens the key in Key
// Management. Until 13.65.0-beta this view read fields the enterprise
// summary never returned at the top level, so it showed only dashes.
const axisTick = { fill: C.muted, fontSize: 10 };
const title: React.CSSProperties = { fontSize: 10.5, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "var(--font-mono)" };
const TH: React.CSSProperties = { fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, padding: "6px 8px", textAlign: "left", borderBottom: `1px solid ${C.border}` };
const TD: React.CSSProperties = { fontSize: 11, color: C.dim, padding: "6px 8px", borderBottom: `1px solid ${C.border}`, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 260 };
const FILL = "var(--cls-op-ok)";
// States that need someone's attention; the rest are neutral.
const STATE_TONE: Record<string, string> = { active: "green", compromised: "red", "destroy-pending": "amber", disabled: "amber", deactivated: "neutral", "pre-active": "neutral" };

type Props = { session: AuthSession; onOpenKey?: (keyId: string) => void };

export function KeyInventoryPanel({ session, onOpenKey }: Props) {
  const [windowId, setWindowId] = useState<WindowId>(DEFAULT_WINDOW);
  const [stats, setStats] = useState<KeyStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [drill, setDrill] = useState<ServerDrill<KeyStatQuery> | null>(null);

  const load = useCallback(async () => {
    if (!session?.token) return;
    setLoading(true); setErr(""); setDrill(null);
    try {
      setStats(await getKeyStats(session, { from: windowFrom(windowId) }));
    } catch (e) {
      setStats(null); setErr(errMsg(e));
    } finally { setLoading(false); }
  }, [session, windowId]);
  useEffect(() => { void load(); }, [load]);

  const fetchPage = useCallback((q: KeyStatQuery, offset: number, limit: number) => listKeyStatKeys(session, q, offset, limit), [session]);
  const paged = usePagedDrill(drill, fetchPage);
  const open = (label: string, count: number, query: KeyStatQuery) => { if (count) setDrill({ label, count, query }); };

  const series = useMemo(() => (stats?.series ?? []).map((p) => ({ ...p, time: bucketLabel(p.start, stats?.bucket_seconds || 86400) })), [stats]);
  const active = stats?.by_state.find((s) => s.key === "active")?.count ?? 0;

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <WindowSelect value={windowId} onChange={setWindowId} />
        <Btn small onClick={() => void load()} disabled={loading}>{loading ? "Loading…" : "Refresh"}</Btn>
      </div>

      {err ? <Card><div style={{ fontSize: 11, color: C.redFg }}>{`Key inventory unavailable: ${err}`}</div></Card> : !stats ? null : <>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 10 }}>
          <Stat l="Keys" v={stats.total.toLocaleString()} s="not deleted" i={KeyRound} />
          <Stat l="Active" v={active.toLocaleString()} s={stats.total ? `${Math.round((active / stats.total) * 100)}% of keys` : "no keys"} i={CheckCircle2} />
          <Stat l="Created" v={stats.created.toLocaleString()} s={windowLabel(windowId).toLowerCase()} i={PlusCircle} />
          <Stat l="Algorithms" v={stats.by_algorithm.length.toLocaleString()} s="in use" i={Layers} />
        </div>

        {stats.total === 0 ? <Card><div style={{ textAlign: "center", padding: 28, color: C.muted, fontSize: 12 }}>No keys yet.</div></Card> : <>
          <DrillHint />
          <Card>
            <div style={{ ...title, marginBottom: 8 }}>{`Keys created · per ${bucketUnit(stats.bucket_seconds)} (UTC)`}</div>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={series} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke={C.border} />
                <XAxis dataKey="time" tick={axisTick} axisLine={{ stroke: C.border }} tickLine={false} interval="preserveStartEnd" minTickGap={24} />
                <YAxis tick={axisTick} axisLine={false} tickLine={false} allowDecimals={false} width={36} />
                <Tooltip cursor={{ fill: C.dimTint }} />
                <Bar dataKey="count" name="Keys created" fill={FILL} radius={[2, 2, 0, 0]} style={clickable}
                  onClick={(_d, i) => {
                    const p = series[i];
                    if (p) open(`Created in the ${bucketUnit(stats.bucket_seconds)} from ${p.time} UTC`, p.count, bucketBounds(p.start, stats.bucket_seconds, stats.from, stats.to));
                  }} />
              </BarChart>
            </ResponsiveContainer>
          </Card>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(320px,1fr))", gap: 12 }}>
            <CountBars label="By state" rows={stats.by_state} onPick={(r) => open(`State: ${r.key}`, r.count, { state: r.key })} />
            <CountBars label="By algorithm" rows={stats.by_algorithm} onPick={(r) => open(`Algorithm: ${r.key}`, r.count, { algorithm: r.key })} />
          </div>
        </>}

        {drill && (
          <DrillPanel label={drill.label} count={drill.count} onClear={() => setDrill(null)}
            loaded={paged.rows.length} loading={paged.loading} error={paged.error} onMore={paged.done ? undefined : paged.loadMore}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>{["Name", "Algorithm", "State", "Version", "Created"].map((h) => <th key={h} style={TH}>{h}</th>)}</tr></thead>
              <tbody>
                {paged.rows.map((k: KeyItem) => (
                  <tr key={k.id} onClick={() => onOpenKey?.(k.id)} style={onOpenKey ? clickable : undefined} title={onOpenKey ? "Open in Key Management" : undefined}
                    onMouseEnter={(e) => { e.currentTarget.style.background = C.cardHover; }} onMouseLeave={(e) => { e.currentTarget.style.background = ""; }}>
                    <td style={{ ...TD, color: C.text, fontWeight: 600 }}>{k.name}</td>
                    <td style={{ ...TD, fontFamily: "var(--font-mono)" }}>{k.algorithm}</td>
                    <td style={TD}><B c={STATE_TONE[String(k.status).toLowerCase()] ?? "neutral"}>{k.status}</B></td>
                    <td style={TD}>{`v${k.current_version}`}</td>
                    <td style={TD}>{k.created_at ? new Date(k.created_at).toLocaleString() : "-"}</td>
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

function CountBars({ label, rows, onPick }: { label: string; rows: KeyStatCount[]; onPick: (r: KeyStatCount) => void }) {
  const top = rows.slice(0, 12);
  return (
    <Card>
      <div style={{ ...title, marginBottom: 8 }}>{label}{rows.length > top.length ? ` · top ${top.length} of ${rows.length}` : ""}</div>
      <div data-testid={`bars-${label.toLowerCase().replace(/\s+/g, "-")}`}>
      <ResponsiveContainer width="100%" height={Math.max(110, top.length * 26 + 24)}>
        <BarChart data={top} layout="vertical" margin={{ left: 8, right: 12, top: 0, bottom: 0 }}>
          <XAxis type="number" tick={axisTick} axisLine={{ stroke: C.border }} tickLine={false} allowDecimals={false} />
          <YAxis type="category" dataKey="key" tick={{ fill: C.dim, fontSize: 10.5 }} axisLine={false} tickLine={false} width={110} />
          <Tooltip cursor={{ fill: C.dimTint }} />
          <Bar dataKey="count" name="Keys" fill={FILL} barSize={14} radius={[0, 2, 2, 0]} style={clickable}
            onClick={(_d, i) => { const r = top[i]; if (r) onPick(r); }} />
        </BarChart>
      </ResponsiveContainer>
      </div>
    </Card>
  );
}
