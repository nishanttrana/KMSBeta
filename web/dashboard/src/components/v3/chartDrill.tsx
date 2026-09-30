import type { ReactNode } from "react";
import { Btn, Card } from "./legacyPrimitives";
import { C } from "./theme";

// Every chart segment is clickable and lists the entries it counts
// (docs/DECISIONS.md, "Charts drill into their entries"). A drill names what
// was clicked and holds a predicate over the same rows the chart was computed
// from, so the list and the bar can never disagree.
export type Drill<T> = { label: string; match: (row: T) => boolean };

export const clickable = { cursor: "pointer" } as const;

// Index of the clicked point from a chart-level onClick (area and line charts,
// where there is no per-segment handler). -1 when nothing was under the cursor.
export function clickedIndex(state: { activeIndex?: unknown } | null | undefined): number {
  const i = Number(state?.activeIndex);
  return Number.isInteger(i) && i >= 0 ? i : -1;
}

export const DrillHint = () => (
  <div style={{ fontSize: 9, color: C.muted, marginBottom: 8 }}>Click a bar, slice or point to list the entries it counts.</div>
);

export function DrillPanel({ label, count, onClear, children }: { label: string; count: number; onClear: () => void; children: ReactNode }) {
  return (
    <Card style={{ marginTop: 10, borderColor: C.accent }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, gap: 8 }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: C.text }}>{`${label}: ${count} ${count === 1 ? "entry" : "entries"}`}</span>
        <Btn small onClick={onClear}>Clear</Btn>
      </div>
      <div style={{ maxHeight: 380, overflow: "auto" }}>
        {count === 0 ? <div style={{ fontSize: 10, color: C.muted, padding: 12 }}>No entries.</div> : children}
      </div>
    </Card>
  );
}
