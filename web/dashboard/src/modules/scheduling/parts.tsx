import type { CSSProperties, ReactNode } from "react";
import { B, Card } from "../../components/v3/legacyPrimitives";
import { C } from "../../components/v3/theme";

// Pieces every Scheduling view shares.

export const TH: CSSProperties = { fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, padding: "7px 8px", textAlign: "left", borderBottom: `1px solid ${C.border}` };
export const TD: CSSProperties = { fontSize: 11.5, color: C.dim, padding: "8px", borderBottom: `1px solid ${C.border}`, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 260 };

export const when = (v?: string) => {
  const t = v ? Date.parse(v) : NaN;
  return Number.isFinite(t) && t > 0 ? new Date(t).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";
};

export const every = (hours: number) => (hours % 24 === 0 ? `every ${hours / 24} day${hours === 24 ? "" : "s"}` : `every ${hours} hour${hours === 1 ? "" : "s"}`);

// Interval choices offered by the forms; a stored interval outside them is
// listed as it is, never replaced by the first.
const INTERVALS: [number, string][] = [[1, "Every hour"], [6, "Every 6 hours"], [24, "Daily"], [168, "Weekly"], [720, "Every 30 days"]];
export const intervalOptions = (current: number): [number, string][] => {
  if (INTERVALS.some(([h]) => h === current)) return INTERVALS;
  const stored: [number, string] = [current, every(current)];
  return [...INTERVALS, stored].sort((a, b) => a[0] - b[0]);
};

const TONE: Record<string, string> = { passed: "green", rotated: "green", requested: "green", assessed: "green", succeeded: "green", failed: "red", error: "red", refused: "amber" };

export const Result = ({ value, title }: { value?: string | undefined; title?: string | undefined }) =>
  value ? <span title={title}><B c={TONE[value] || "neutral"}>{value}</B></span> : <B c="neutral">not run yet</B>;

// The schedule's state: who it runs as, and why it is paused if it is.
export const Authority = ({ by, paused }: { by: string; paused?: string | undefined }) => (
  <span title={paused || undefined} style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
    <span style={{ fontFamily: "var(--font-mono)", color: by ? C.dim : C.muted }}>{by || "no one"}</span>
    {paused ? <B c="amber">paused</B> : null}
  </span>
);

export const Empty = ({ children }: { children: ReactNode }) => <div style={{ padding: "10px 14px 16px", fontSize: 11.5, color: C.muted }}>{children}</div>;

export const Failed = ({ what, error }: { what: string; error: string }) => (
  <Card><div style={{ fontSize: 11.5, color: C.redFg }}>{`${what} unavailable: ${error}`}</div></Card>
);
