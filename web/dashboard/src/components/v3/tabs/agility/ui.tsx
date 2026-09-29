import type { CSSProperties, ReactNode } from "react";
import { C } from "../../theme";

// Building blocks shared by the Crypto Agility panes.

export function errText(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

export function daysUntil(date: string) {
  return Math.ceil((Date.parse(date.slice(0, 10) + "T00:00:00Z") - Date.now()) / 86_400_000);
}

export const inputStyle: CSSProperties = {
  background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6,
  color: C.text, padding: "8px 10px", fontSize: 13, width: "100%", fontFamily: "IBM Plex Sans, sans-serif", outline: "none",
};
export const labelStyle: CSSProperties = { fontSize: 11, color: C.dim, marginBottom: 4 };

export const S = {
  divider: { borderTop: `1px solid ${C.border}`, margin: "24px 0" } as CSSProperties,
  sectionTitle: { fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 4 } as CSSProperties,
  sectionHint: { fontSize: 11, color: C.muted, marginBottom: 12 } as CSSProperties,
  panel: { background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" } as CSSProperties,
  empty: { background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 28, textAlign: "center", color: C.muted, fontSize: 13 } as CSSProperties,
  th: { textAlign: "left", fontSize: 10, color: C.muted, fontWeight: 600, padding: "8px 12px", textTransform: "uppercase", letterSpacing: "0.06em", whiteSpace: "nowrap" } as CSSProperties,
  td: { padding: "10px 12px", fontSize: 12, color: C.text, verticalAlign: "middle" } as CSSProperties,
  mono: { fontFamily: "IBM Plex Mono, monospace", fontSize: 12 } as CSSProperties,
  smallBtn: { background: "transparent", border: `1px solid ${C.border}`, borderRadius: 5, color: C.dim, padding: "3px 7px", cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11 } as CSSProperties,
  button: { background: C.card, border: `1px solid ${C.border}`, borderRadius: 7, color: C.dim, padding: "7px 13px", cursor: "pointer", fontSize: 12, display: "inline-flex", alignItems: "center", gap: 6 } as CSSProperties,
  primary: { background: C.accent, border: "none", borderRadius: 7, color: C.bg, padding: "7px 14px", cursor: "pointer", fontSize: 12, fontWeight: 600, display: "inline-flex", alignItems: "center", gap: 6 } as CSSProperties,
};

export function Badge({ color, bg, children }: { color: string; bg: string; children: ReactNode }) {
  return <span style={{ background: bg, color, padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600, whiteSpace: "nowrap" }}>{children}</span>;
}

interface StatCardProps { icon: ReactNode; label: string; value: string | number; sub?: string; color?: string; bg?: string }
export function StatCard({ icon, label, value, sub, color = C.accent, bg = C.accentTint }: StatCardProps) {
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "14px 14px", display: "flex", alignItems: "flex-start", gap: 10, flex: 1, minWidth: 140 }}>
      <div style={{ background: bg, border: `1px solid ${color}22`, borderRadius: 8, padding: 8, flexShrink: 0, color }}>{icon}</div>
      <div>
        <div style={{ fontSize: 22, fontWeight: 700, color: C.text, lineHeight: 1 }}>{value}</div>
        <div style={{ fontSize: 11, color: C.dim, marginTop: 3 }}>{label}</div>
        {sub && <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{sub}</div>}
      </div>
    </div>
  );
}

export function Findings({ items }: { items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div style={{ marginTop: 16, ...S.panel, padding: "14px 18px" }}>
      <div style={{ fontSize: 11, color: C.muted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>Findings</div>
      {items.map(f => <div key={f} style={{ fontSize: 12, color: C.dim, marginTop: 4 }}>• {f}</div>)}
    </div>
  );
}

export function Modal({ title, hint, children, onClose, onSave, saving, valid, saveLabel }: {
  title: string; hint: string; children: ReactNode; onClose: () => void; onSave: () => void; saving: boolean; valid: boolean; saveLabel: string;
}) {
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.65)", zIndex: 9999, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: C.card, border: `1px solid ${C.borderHi}`, borderRadius: 12, padding: 28, width: 540, maxWidth: "calc(100vw - 32px)", maxHeight: "calc(100vh - 32px)", overflowY: "auto", boxShadow: "0 24px 60px rgba(0,0,0,.6)" }}>
        <div style={{ fontSize: 16, fontWeight: 600, color: C.text, marginBottom: 6 }}>{title}</div>
        <div style={{ fontSize: 11, color: C.muted, marginBottom: 18 }}>{hint}</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>{children}</div>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 22 }}>
          <button onClick={onClose} style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 6, color: C.dim, padding: "8px 16px", cursor: "pointer", fontSize: 13 }}>Cancel</button>
          <button
            onClick={onSave}
            disabled={saving || !valid}
            style={{ background: C.accent, border: "none", borderRadius: 6, color: C.bg, padding: "8px 18px", cursor: saving || !valid ? "not-allowed" : "pointer", fontSize: 13, fontWeight: 600, opacity: saving || !valid ? 0.6 : 1 }}
          >
            {saving ? "Saving…" : saveLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return <div><div style={labelStyle}>{label}</div>{children}</div>;
}

export function Grid2({ children }: { children: ReactNode }) {
  return <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>{children}</div>;
}
