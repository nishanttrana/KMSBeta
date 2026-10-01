import { useState, type ReactNode } from "react";
import { C } from "../../theme";
import type { DiscoverySummary } from "../../../../lib/discovery";
import { CLASS_ORDER, MONO, algDrill, classDrill, classMeta, pct, sourceDrill, sourceMeta, type AssetDrill } from "./meta";

// Bars are plain HTML on theme tokens, so they follow light and dark mode.
// Every bar is labelled with the count the service's summary reports, and a
// click lists the assets the service returns for the same filter (meta.ts
// AssetDrill), so the two always agree.

export const ChartCard = ({ title, sub, children }: { title: string; sub?: ReactNode; children: ReactNode }) => (
  <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: "var(--radius-md)", padding: "14px 16px", boxShadow: "var(--shadow-sm)", minWidth: 0 }}>
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10, gap: 8 }}>
      <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{title}</span>
      {sub ? <span style={{ fontSize: 10.5, color: C.muted }}>{sub}</span> : null}
    </div>
    {children}
  </div>
);

export const Swatch = ({ color, size = 8 }: { color: string; size?: number }) => (
  <span style={{ width: size, height: size, borderRadius: 2, background: color, display: "inline-block", flexShrink: 0 }} />
);

type BarRowProps = {
  label: ReactNode;
  value: number;
  max: number;
  bar: ReactNode;
  active?: boolean;
  dim?: boolean;
  title?: string;
  mono?: boolean;
  onClick?: () => void;
};

export function BarRow({ label, value, max, bar, active, dim, title, mono, onClick }: BarRowProps) {
  return (
    <button type="button" onClick={onClick} title={title}
      style={{ display: "grid", gridTemplateColumns: "minmax(96px, 40%) 1fr 40px", alignItems: "center", gap: 10, width: "100%", background: active ? C.accentDim : "transparent", border: "none", borderRadius: 6, padding: "4px 6px", cursor: "pointer", opacity: dim ? 0.45 : 1, textAlign: "left", transition: "opacity .15s, background .15s" }}>
      <span style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 11, color: C.text, overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis", fontFamily: mono ? MONO : "inherit" }}>{label}</span>
      <span style={{ height: 10, display: "flex", width: `${max > 0 && value > 0 ? Math.max(2, (value / max) * 100) : 0}%`, transition: "width .4s" }}>{bar}</span>
      <span style={{ fontSize: 11, color: C.text, textAlign: "right", fontVariantNumeric: "tabular-nums" }}>{value.toLocaleString()}</span>
    </button>
  );
}

export const solid = (color: string) => <span style={{ flex: 1, background: color, borderRadius: "0 4px 4px 0" }} />;

type ChartProps = { summary: DiscoverySummary; active: string; onDrill: (d: AssetDrill) => void };

export function ClassBars({ summary, active, onDrill }: ChartProps) {
  const rows = CLASS_ORDER.map((c) => ({ c, d: classDrill(summary, c) }));
  const max = Math.max(0, ...rows.map((r) => r.d.count || 0));
  return (
    <div>
      {rows.map(({ c, d }) => {
        const m = classMeta(c);
        const n = d.count || 0;
        return (
          <BarRow key={c} label={<><Swatch color={m.color} />{m.label}</>} value={n} max={max} bar={solid(m.color)}
            active={active === d.key} dim={!!active && active !== d.key} title={`${m.label}: ${n} of ${summary.total_assets} (${pct(n, summary.total_assets)}%)`}
            onClick={() => onDrill(d)} />
        );
      })}
    </div>
  );
}

type StackRow = { key: string; label: ReactNode; mono?: boolean; drill: (cls?: string) => AssetDrill };

// StackedBars: one bar per row, split by class; the row and each segment
// drill into their own assets.
function StackedBars({ rows, active, onDrill, limit }: { rows: StackRow[]; active: string; onDrill: (d: AssetDrill) => void; limit?: number }) {
  const [tip, setTip] = useState("");
  const sized = rows.map((r) => ({ ...r, whole: r.drill(), n: r.drill().count || 0 })).filter((r) => r.n > 0).sort((x, y) => y.n - x.n || x.key.localeCompare(y.key));
  const shown = limit ? sized.slice(0, limit) : sized;
  const max = Math.max(0, ...shown.map((r) => r.n));
  // Dim the other rows only when the active drill belongs to this chart.
  const mine = sized.some((r) => r.whole.key === active || CLASS_ORDER.some((c) => r.drill(c).key === active));
  if (!shown.length) return <Empty />;
  return (
    <div>
      {shown.map((r) => {
        const segs = CLASS_ORDER.map((c) => ({ c, d: r.drill(c) })).filter((x) => (x.d.count || 0) > 0);
        const on = active === r.whole.key || segs.some((x) => x.d.key === active);
        return (
          <BarRow key={r.key} mono={!!r.mono} label={r.label} value={r.n} max={max} title={r.whole.label}
            active={on} dim={mine && !on} onClick={() => onDrill(r.whole)}
            bar={<span style={{ display: "flex", gap: 2, flex: 1 }}>
              {segs.map((x, i) => (
                <span key={x.c} onMouseEnter={() => setTip(`${x.d.label}: ${x.d.count} (${pct(x.d.count || 0, r.n)}%)`)} onMouseLeave={() => setTip("")}
                  onClick={(e) => { e.stopPropagation(); onDrill(x.d); }}
                  style={{ flex: x.d.count || 0, minWidth: 3, background: classMeta(x.c).color, borderRadius: i === segs.length - 1 ? "0 4px 4px 0" : 0, outline: active === x.d.key ? `2px solid ${C.text}` : "none", outlineOffset: 1 }} />
              ))}
            </span>} />
        );
      })}
      {sized.length > shown.length && <div style={{ fontSize: 10.5, color: C.muted, padding: "4px 6px 0" }}>+{sized.length - shown.length} more in the inventory</div>}
      <div style={{ display: "flex", flexWrap: "wrap", gap: "4px 12px", padding: "8px 6px 0" }}>
        {CLASS_ORDER.map((c) => <span key={c} style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 10.5, color: C.muted }}><Swatch color={classMeta(c).color} />{classMeta(c).label}</span>)}
      </div>
      <div style={{ fontSize: 10.5, color: C.dim, padding: "6px 6px 0", minHeight: 14 }}>{tip}</div>
    </div>
  );
}

export function AlgorithmBars({ summary, active, onDrill }: ChartProps) {
  const rows = Object.keys(summary.algorithm_classes || {}).map((alg): StackRow => ({
    key: alg, label: alg || "no algorithm", mono: true, drill: (c) => algDrill(summary, alg, c),
  }));
  return <StackedBars rows={rows} active={active} onDrill={onDrill} limit={8} />;
}

export function SourceStack({ summary, active, onDrill }: ChartProps) {
  const rows = Object.keys(summary.source_classification || {}).map((src): StackRow => {
    const M = sourceMeta(src);
    const Icon = M.icon;
    return { key: src, label: <><Icon size={12} color={C.muted} />{M.label}</>, drill: (c) => sourceDrill(summary, src, c) };
  });
  return <StackedBars rows={rows} active={active} onDrill={onDrill} />;
}

const Empty = () => <div style={{ fontSize: 11, color: C.muted, padding: "18px 0", textAlign: "center" }}>No data yet</div>;
