export const C = {
  bg: "#060a11",
  sidebar: "#0a0f1a",
  surface: "#0f1521",
  card: "#131d2e",
  cardHover: "#182740",
  border: "#1a2944",
  borderHi: "#243656",
  accent: "#06d6e0",
  accentDim: "rgba(6,214,224,.08)",
  green: "#2dd4a0",
  greenDim: "rgba(45,212,160,.08)",
  red: "#ef4444",
  redDim: "rgba(239,68,68,.08)",
  amber: "#f59e0b",
  amberDim: "rgba(245,158,11,.08)",
  orange: "#f97316",
  orangeDim: "rgba(249,115,22,.08)",
  purple: "#a78bfa",
  purpleDim: "rgba(167,139,250,.08)",
  blue: "#3b82f6",
  blueDim: "rgba(59,130,246,.08)",
  pink: "#ec4899",
  pinkDim: "rgba(236,72,153,.08)",
  cyan: "#22d3ee",
  cyanDim: "rgba(34,211,238,.08)",
  yellow: "#facc15",
  yellowDim: "rgba(250,204,21,.08)",
  teal: "#14b8a6",
  tealDim: "rgba(20,184,166,.08)",
  text: "#e2e8f0",
  dim: "#94a3b8",
  muted: "#64748b",
  white: "#ffffff",
  glow: "rgba(6,214,224,0.12)",
  glowStrong: "rgba(6,214,224,0.25)",
  // Subtle gradient tints (4% opacity) for stat cards
  greenTint: "rgba(45,212,160,.04)",
  redTint: "rgba(239,68,68,.04)",
  amberTint: "rgba(245,158,11,.04)",
  orangeTint: "rgba(249,115,22,.04)",
  purpleTint: "rgba(167,139,250,.04)",
  blueTint: "rgba(59,130,246,.04)",
  accentTint: "rgba(6,214,224,.04)",
  pinkTint: "rgba(236,72,153,.04)",
  cyanTint: "rgba(34,211,238,.04)",
  tealTint: "rgba(20,184,166,.04)",
  yellowTint: "rgba(250,204,21,.04)",
  // Even subtler tints (3%) for protocol/feature cards
  greenTint3: "rgba(45,212,160,.03)",
  redTint3: "rgba(239,68,68,.03)",
  accentTint3: "rgba(6,214,224,.03)",
  dimTint: "rgba(148,163,184,.06)"
};

// Severity → theme color mapping (consistent across all tabs)
export function severityColor(sev: string): string {
  switch (String(sev || "").toLowerCase()) {
    case "critical": return C.red;
    case "high": return C.orange;
    case "warning": return C.amber;
    case "info": return C.blue;
    case "low": return C.green;
    default: return C.muted;
  }
}

export function severityDimColor(sev: string): string {
  switch (String(sev || "").toLowerCase()) {
    case "critical": return C.redDim;
    case "high": return C.orangeDim;
    case "warning": return C.amberDim;
    case "info": return C.blueDim;
    case "low": return C.greenDim;
    default: return "transparent";
  }
}

// Status → theme color mapping (active/enabled/running/revoked/expired/etc.)
export function statusColor(status: string): string {
  switch (String(status || "").toLowerCase()) {
    case "active": case "enabled": case "running": case "valid": case "completed": case "healthy":
      return C.green;
    case "revoked": case "error": case "failed": case "down": case "denied": case "deleted":
      return C.red;
    case "expiring": case "warning": case "degraded": case "restarting": case "pending":
      return C.amber;
    case "expired": case "disabled": case "inactive": case "suspended":
      return C.orange;
    default:
      return C.blue;
  }
}

export function statusDimColor(status: string): string {
  const color = statusColor(status);
  const palette = C as Record<string, string>;
  if (color === C.green) return C.greenDim;
  if (color === C.red) return C.redDim;
  if (color === C.amber) return C.amberDim;
  if (color === C.orange) return C.orangeDim;
  if (color === C.blue) return C.blueDim;
  return palette["accentDim"] || "transparent";
}
