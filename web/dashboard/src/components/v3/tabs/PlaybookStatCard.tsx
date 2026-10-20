import type { ReactNode } from "react";
import { C } from "../theme";

// A count is neutral; only an attention colour (amber, red) tints the icon.
// A source that failed reads "unavailable" in body text, not as a number.
export const StatCard = ({ icon, label, value, color = C.accent, sublabel }: { icon: ReactNode; label: ReactNode; value: ReactNode; color?: string; sublabel?: ReactNode }) => {
  const attention = color === C.amber || color === C.red;
  const isNumber = typeof value === "number";
  return (
    <div style={{ flex: 1, minWidth: 150, background: C.card, border: `1px solid ${C.border}`, borderRadius: "var(--radius-md)", padding: "14px 16px", display: "flex", flexDirection: "column", gap: 6, boxShadow: "var(--shadow-sm)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ color: attention ? color : C.dim, display: "inline-flex" }}>{icon}</span>
        <span style={{ fontSize: 10.5, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 500, fontFamily: "var(--font-mono)" }}>{label}</span>
      </div>
      <div className="vk-num" style={isNumber ? { fontSize: 26, fontWeight: 600, color: C.text, letterSpacing: -0.6 } : { fontSize: 12.5, color: C.muted }}>{value}</div>
      {sublabel && <div style={{ fontSize: 11, color: C.muted }}>{sublabel}</div>}
    </div>
  );
};
