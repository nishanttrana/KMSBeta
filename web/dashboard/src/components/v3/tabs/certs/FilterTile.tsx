import type { ComponentProps } from "react";
import { Stat } from "../../legacyPrimitives";
import { C } from "../../theme";

// A count tile that lists what it counts: pressing it filters the list below
// to exactly those entries, pressing it again shows everything.
export function FilterTile({ on, onPress, ...stat }: ComponentProps<typeof Stat> & { on: boolean; onPress: () => void }) {
  return (
    <button type="button" aria-pressed={on} onClick={onPress}
      style={{ display: "flex", padding: 0, border: 0, background: "none", font: "inherit", color: "inherit", textAlign: "left", cursor: "pointer", borderRadius: "var(--radius-md)", outline: on ? `2px solid ${C.accent}` : undefined, outlineOffset: -1 }}>
      <Stat {...stat} />
    </button>
  );
}
