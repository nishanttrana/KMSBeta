import { useCallback, useEffect, useMemo, useState } from "react";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { AuthSession } from "../../../lib/auth";
import {
  getAuditInvestigation, INVESTIGATE_DIMENSIONS, listAuditEvents,
  type AuditEvent, type AuditEventQuery, type AuditInvestigation, type InvestigateDimension, type InvestigatePivots
} from "../../../lib/audit";
import { B, Btn, Card, Inp, Sel, Stat } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import {
  bucketBounds, bucketLabel, bucketUnit, clickable, clickedIndex, DEFAULT_WINDOW, DrillPanel,
  usePagedDrill, windowFrom, WindowSelect, type ServerDrill, type WindowId
} from "../chartDrill";
import { C } from "../theme";
import { DIMENSION_LABEL, dimensionValue, formatAction, resultTone, shortService, shortTS } from "./auditFormat";

// Audit Log → Investigate. Start from anyone or anything (a person, an
// object, an address, a sign-in, a request) and see who, what, on what, from
// where, how and with what outcome, each counted by the audit service over
// the whole window (GET /audit/investigate). Clicking a value adds it to the
// pivots, so the events listed below are exactly the ones it counted.
const title: React.CSSProperties = { fontSize: 10, fontWeight: 600, color: C.dim, textTransform: "uppercase", letterSpacing: 0.6 };
const axisTick = { fill: C.muted, fontSize: 10 };
const cell: React.CSSProperties = { fontSize: 10, color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" };

type Bucket = { label: string; count: number; from: string; to: string };

export function AuditInvestigate({ session, pivots, onPivotsChange, onOpenEvent }: {
  session: AuthSession;
  pivots: InvestigatePivots;
  onPivotsChange: (p: InvestigatePivots) => void;
  onOpenEvent: (e: AuditEvent) => void;
}) {
  const [windowId, setWindowId] = useState<WindowId>(DEFAULT_WINDOW);
  const [inv, setInv] = useState<AuditInvestigation | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [bucket, setBucket] = useState<Bucket | null>(null);
  const [dim, setDim] = useState<InvestigateDimension>("actor_id");
  const [text, setText] = useState("");

  const load = useCallback(async () => {
    if (!session?.token) return;
    setLoading(true); setErr(""); setBucket(null);
    try {
      setInv(await getAuditInvestigation(session, pivots, { from: windowFrom(windowId) }));
    } catch (e) {
      setInv(null); setErr(errMsg(e));
    } finally { setLoading(false); }
  }, [session, pivots, windowId]);
  useEffect(() => { void load(); }, [load]);

  const set = Object.entries(pivots).filter(([, v]) => v) as Array<[InvestigateDimension, string]>;
  const narrow = (d: InvestigateDimension, v: string) => onPivotsChange({ ...pivots, [d]: v });
  const drop = (d: InvestigateDimension) => { const next = { ...pivots }; delete next[d]; onPivotsChange(next); };
  const add = () => { const v = text.trim(); if (v) { narrow(dim, v); setText(""); } };

  // The events below: the pivots over the investigated window, or over the
  // clicked bucket of the chart.
  const drill = useMemo<ServerDrill<AuditEventQuery> | null>(() => {
    if (!inv) return null;
    const win = bucket ?? { from: inv.from, to: inv.to };
    return { label: bucket ? bucket.label : "Events", count: bucket ? bucket.count : inv.total, query: { ...pivots, from: win.from, to: win.to } };
  }, [inv, bucket, pivots]);
  const fetchPage = useCallback((q: AuditEventQuery, offset: number, limit: number) =>
    listAuditEvents(session, { ...q, exclude_http_requests: true, offset, limit }), [session]);
  const paged = usePagedDrill(drill, fetchPage);

  const series = useMemo(() => (inv?.series ?? []).map((p) => ({ ...p, time: bucketLabel(p.start, inv?.bucket_seconds || 3600) })), [inv]);
  const pickBucket = (state: { activeIndex?: unknown } | null) => {
    const p = series[clickedIndex(state)];
    if (!p || !inv) return;
    setBucket({ label: `Events in the ${bucketUnit(inv.bucket_seconds)} from ${p.time} UTC`, count: p.count, ...bucketBounds(p.start, inv.bucket_seconds, inv.from, inv.to) });
  };
  const notSuccessful = (inv?.facets.result ?? []).filter((f) => f.key !== "success").reduce((n, f) => n + f.count, 0);

  return (
    <div>
      <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap", marginBottom: 8 }}>
        <Sel w={150} value={dim} onChange={(e: { target: { value: string } }) => setDim(e.target.value as InvestigateDimension)}>
          {INVESTIGATE_DIMENSIONS.map((d) => <option key={d} value={d}>{DIMENSION_LABEL[d]}</option>)}
        </Sel>
        <Inp placeholder="User, key, address, session or request ID" value={text} style={{ flex: "1 1 220px", width: "auto", minWidth: 200 }}
          onChange={(e: { target: { value: string } }) => setText(e.target.value)}
          onKeyDown={(e: { key: string }) => { if (e.key === "Enter") add(); }} />
        <Btn small primary onClick={add} disabled={!text.trim()}>Investigate</Btn>
        <WindowSelect value={windowId} onChange={setWindowId} />
        <Btn small onClick={() => void load()} disabled={loading}>{loading ? "Loading…" : "Refresh"}</Btn>
      </div>

      <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap", marginBottom: 12, minHeight: 22 }}>
        {set.length === 0 ? <span style={{ fontSize: 10, color: C.muted }}>All activity. Click any value to narrow it.</span> : set.map(([d, v]) => (
          <span key={d} style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 4px 2px 8px", borderRadius: 4, border: `1px solid ${C.accent}`, fontSize: 10, color: C.text }}>
            <span style={{ color: C.muted }}>{DIMENSION_LABEL[d]}:</span>
            <span style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={v}>{dimensionValue(d, v)}</span>
            <button type="button" aria-label={`Remove ${DIMENSION_LABEL[d]}`} onClick={() => drop(d)}
              style={{ border: 0, background: "transparent", color: C.muted, cursor: "pointer", fontSize: 12, padding: "0 4px" }}>×</button>
          </span>
        ))}
        {set.length > 1 && <Btn small onClick={() => onPivotsChange({})}>Clear all</Btn>}
      </div>

      {err ? (
        <Card><div style={{ fontSize: 11, color: C.redFg }}>{`Investigation unavailable: ${err}`}</div></Card>
      ) : !inv ? null : <>
        <div style={{ display: "flex", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
          <Stat l="Events" v={inv.total} />
          <Stat l="Not successful" v={notSuccessful} c={notSuccessful ? "amber" : "green"} />
          <Stat l="People & services" v={inv.distinct.actor_id ?? 0} />
          <Stat l="Objects" v={inv.distinct.target_id ?? 0} />
          <Stat l="Addresses" v={inv.distinct.source_ip ?? 0} />
          <Stat l="Sessions" v={inv.distinct.session_id ?? 0} />
          <Stat l="Requests" v={inv.distinct.correlation_id ?? 0} />
        </div>
        {inv.first_seen && inv.last_seen && (
          <div style={{ fontSize: 10, color: C.muted, marginBottom: 10 }}>{`First ${new Date(inv.first_seen).toLocaleString()} · last ${new Date(inv.last_seen).toLocaleString()}`}</div>
        )}

        {inv.total > 0 && (
          <Card style={{ marginBottom: 10 }}>
            <div style={{ ...title, marginBottom: 8 }}>{`When (UTC, per ${bucketUnit(inv.bucket_seconds)})`}</div>
            <ResponsiveContainer width="100%" height={140}>
              <AreaChart data={series} margin={{ top: 5, right: 10, left: 0, bottom: 0 }} onClick={pickBucket} style={clickable}>
                <XAxis dataKey="time" tick={axisTick} axisLine={{ stroke: C.border }} tickLine={false} interval="preserveStartEnd" />
                <YAxis tick={axisTick} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip />
                <Area type="monotone" dataKey="count" name="Events" stroke={C.accent} strokeWidth={2} fill={C.accentDim} />
              </AreaChart>
            </ResponsiveContainer>
          </Card>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: 10 }}>
          {INVESTIGATE_DIMENSIONS.map((d) => (
            <Card key={d}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 6 }}>
                <span style={title}>{DIMENSION_LABEL[d]}</span>
                <span style={{ fontSize: 10, color: C.muted }}>{`${inv.distinct[d] ?? 0} distinct`}</span>
              </div>
              {(inv.facets[d] ?? []).length === 0 ? <div style={{ fontSize: 10, color: C.muted }}>Not recorded</div> : inv.facets[d].map((f) => (
                <div key={f.key} role="button" tabIndex={0} title={f.key} data-facet={d}
                  onClick={() => narrow(d, f.key)} onKeyDown={(e) => { if (e.key === "Enter") narrow(d, f.key); }}
                  style={{ padding: "3px 0", borderBottom: `1px solid ${C.border}`, ...clickable }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                    <span style={{ ...cell, color: pivots[d] === f.key ? C.text : C.dim, fontWeight: pivots[d] === f.key ? 700 : 400 }}>{dimensionValue(d, f.key)}</span>
                    <span style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                      {f.kind ? <B c="neutral">{f.kind}</B> : null}
                      <span style={{ fontSize: 10, color: C.text, fontWeight: 600 }}>{f.count}</span>
                    </span>
                  </div>
                  <div style={{ height: 3, marginTop: 3, background: C.border, borderRadius: 2 }}>
                    <div style={{ height: 3, width: `${inv.total ? Math.max(2, (100 * f.count) / inv.total) : 0}%`, background: C.accent, borderRadius: 2 }} />
                  </div>
                </div>
              ))}
            </Card>
          ))}
        </div>

        {drill && (
          <DrillPanel label={drill.label} count={drill.count} onClear={() => setBucket(null)}
            loaded={paged.rows.length} loading={paged.loading} error={paged.error} onMore={paged.done ? undefined : paged.loadMore}>
            {paged.rows.map((e) => (
              <div key={e.id} role="button" tabIndex={0} onClick={() => onOpenEvent(e)} onKeyDown={(k) => { if (k.key === "Enter") onOpenEvent(e); }}
                style={{ display: "grid", gridTemplateColumns: "92px minmax(90px,1fr) minmax(120px,1.4fr) minmax(90px,1fr) minmax(90px,1fr) 70px", gap: 8, alignItems: "center", padding: "5px 2px", borderBottom: `1px solid ${C.border}`, ...clickable }}
                onMouseEnter={(ev) => { ev.currentTarget.style.background = C.cardHover; }}
                onMouseLeave={(ev) => { ev.currentTarget.style.background = ""; }}>
                <span style={cell}>{shortTS(e.timestamp)}</span>
                <span style={{ ...cell, color: C.text }} title={e.actor_id}>{e.actor_id || "-"}</span>
                <span style={{ ...cell, color: C.text }} title={e.action}>{`${formatAction(e.action)} · ${shortService(e.service)}`}</span>
                <span style={cell} title={e.target_id}>{e.target_id || "-"}</span>
                <span style={cell} title={e.user_agent}>{e.source_ip || "-"}</span>
                <span><B c={resultTone(e.result)}>{e.result}</B></span>
              </div>
            ))}
          </DrillPanel>
        )}
      </>}
    </div>
  );
}
