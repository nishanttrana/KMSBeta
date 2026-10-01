import { type ReactNode, useCallback, useEffect, useState } from "react";
import { Btn, Card, Sel } from "./legacyPrimitives";
import { errMsg } from "./runtimeUtils";
import { C } from "./theme";

// Every chart segment is clickable and lists the entries it counts
// (docs/DECISIONS.md, "Charts drill into their entries"). A drill names what
// was clicked and selects exactly the rows behind the number: either a
// predicate over the rows the chart was computed from (Drill), or a server
// query with the same filters the server counted with (ServerDrill).
export type Drill<T> = { label: string; match: (row: T) => boolean };
// count is the number on the clicked segment; undefined when the chart shows
// a measure (a mean) rather than a count.
export type ServerDrill<Q> = { label: string; count?: number | undefined; query: Q };

export const clickable = { cursor: "pointer" } as const;

// Chart windows, the same on every analytics view. "Since uptime" has no
// lower bound: everything recorded since the platform started.
export const WINDOWS = [
  { id: "uptime", label: "Since uptime", hours: 0 },
  { id: "1d", label: "Last day", hours: 24 },
  { id: "7d", label: "Last week", hours: 24 * 7 },
  { id: "30d", label: "Last month", hours: 24 * 30 },
  { id: "180d", label: "Last 6 months", hours: 24 * 182 },
  { id: "365d", label: "Last year", hours: 24 * 365 },
] as const;
export type WindowId = (typeof WINDOWS)[number]["id"];
export const DEFAULT_WINDOW: WindowId = "7d";

// RFC 3339 lower bound of a window, or "" for since uptime.
export function windowFrom(id: WindowId): string {
  const hours = WINDOWS.find((w) => w.id === id)?.hours ?? 0;
  return hours ? new Date(Date.now() - hours * 3600 * 1000).toISOString() : "";
}

export const windowLabel = (id: WindowId) => WINDOWS.find((w) => w.id === id)?.label ?? id;

export const WindowSelect = ({ value, onChange }: { value: WindowId; onChange: (id: WindowId) => void }) => (
  <Sel w={130} value={value} onChange={(e: { target: { value: string } }) => onChange(e.target.value as WindowId)}>
    {WINDOWS.map((w) => <option key={w.id} value={w.id}>{w.label}</option>)}
  </Sel>
);

// Label of a chart bucket from its UTC start and width (pkg/timebucket).
export function bucketLabel(start: string, seconds: number): string {
  const iso = new Date(start).toISOString();
  if (seconds < 86400) return `${iso.slice(5, 10)} ${iso.slice(11, 16)}`;
  return iso.slice(0, 10);
}

export function bucketUnit(seconds: number): string {
  if (seconds <= 3600) return "hour";
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
  if (seconds === 86400) return "day";
  if (seconds === 7 * 86400) return "week (from Monday)";
  return `${Math.round(seconds / 86400)} days`;
}

// A bucket's [from, to] clipped to the window. "to" is the last microsecond
// before the next bucket, since the servers' "to" bound is inclusive and
// store microsecond timestamps.
export function bucketBounds(start: string, seconds: number, winFrom: string, winTo: string): { from: string; to: string } {
  const s = new Date(start).getTime();
  const from = Math.max(s, new Date(winFrom).getTime());
  const endMs = s + seconds * 1000;
  const to = endMs <= new Date(winTo).getTime()
    ? new Date(endMs - 1).toISOString().replace(/Z$/, "999Z")
    : winTo;
  return { from: new Date(from).toISOString(), to };
}

// Index of the clicked point from a chart-level onClick (area and line charts,
// where there is no per-segment handler). -1 when nothing was under the cursor.
export function clickedIndex(state: { activeIndex?: unknown } | null | undefined): number {
  const i = Number(state?.activeIndex);
  return Number.isInteger(i) && i >= 0 ? i : -1;
}

export const DrillHint = () => (
  <div style={{ fontSize: 9, color: C.muted, marginBottom: 8 }}>Click a bar, slice or point to list the entries it counts.</div>
);

const PAGE = 100;

// Pages a ServerDrill's entries from the server, PAGE at a time.
export function usePagedDrill<T, Q>(drill: ServerDrill<Q> | null, fetchPage: (q: Q, offset: number, limit: number) => Promise<T[]>) {
  const [rows, setRows] = useState<T[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  const load = useCallback(async (offset: number) => {
    if (!drill) return;
    setLoading(true); setError("");
    try {
      const page = await fetchPage(drill.query, offset, PAGE);
      setRows((prev) => offset === 0 ? page : [...prev, ...page]);
      setDone(page.length < PAGE);
    } catch (e) {
      setError(errMsg(e));
    } finally { setLoading(false); }
  }, [drill, fetchPage]);

  useEffect(() => { setRows([]); setDone(false); void load(0); }, [load]);

  return { rows, loading, error, done, loadMore: () => void load(rows.length) };
}

type PanelProps = {
  label: string;
  count?: number | undefined;
  onClear: () => void;
  children: ReactNode;
  // Paged drill-downs: how many are loaded, and how to load more.
  loaded?: number;
  loading?: boolean;
  error?: string;
  onMore?: (() => void) | undefined;
};

export function DrillPanel({ label, count, onClear, children, loaded, loading, error, onMore }: PanelProps) {
  const shown = loaded ?? count ?? 0;
  const known = count !== undefined;
  const hasMore = known ? shown < count : Boolean(onMore);
  return (
    <Card style={{ marginTop: 10, borderColor: C.accent }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, gap: 8 }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: C.text }}>
          {known ? `${label}: ${count} ${count === 1 ? "entry" : "entries"}` : `${label}: ${shown}${hasMore ? "+" : ""} ${shown === 1 && !hasMore ? "entry" : "entries"}`}
          {known && shown < count ? <span style={{ fontWeight: 400, color: C.muted }}>{`, ${shown} loaded`}</span> : null}
        </span>
        <Btn small onClick={onClear}>Clear</Btn>
      </div>
      {error ? <div style={{ fontSize: 10, color: C.red, marginBottom: 8 }}>{`Entries unavailable: ${error}`}</div> : null}
      <div style={{ maxHeight: 420, overflow: "auto" }}>
        {(known ? count === 0 : shown === 0 && !loading && !hasMore) ? <div style={{ fontSize: 10, color: C.muted, padding: 12 }}>No entries.</div> : children}
      </div>
      {onMore && hasMore ? (
        <div style={{ marginTop: 8, textAlign: "center" }}>
          <Btn small onClick={onMore} disabled={loading}>{loading ? "Loading…" : "Load more"}</Btn>
        </div>
      ) : loading ? <div style={{ fontSize: 10, color: C.muted, marginTop: 8 }}>Loading…</div> : null}
    </Card>
  );
}
