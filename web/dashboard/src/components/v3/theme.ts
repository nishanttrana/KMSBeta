// Two-tier color strategy:
//   C.*     = hex literals → safe for template interpolation like `${C.amber}33`
//   C.*Fg   = CSS vars     → theme-reactive text/icon colors (dark: bright neon, light: dark shade)
//   C.*Dim  = CSS vars     → theme-reactive background tints (opacity adjusts per theme)
export const C = {
  // ── Structural (CSS vars, theme-reactive) ────────────────────────────
  bg:        "var(--c-bg)",
  sidebar:   "var(--c-sidebar)",
  surface:   "var(--c-surface)",
  card:      "var(--c-card)",
  cardHover: "var(--c-card-hover)",
  border:    "var(--c-border)",
  borderHi:  "var(--c-border-hi)",
  text:      "var(--c-text)",
  dim:       "var(--c-dim)",
  muted:     "var(--c-muted)",
  glow:      "var(--c-glow)",
  glowStrong:"var(--c-glow-strong)",
  dimTint:   "var(--c-dim-tint)",

  // ── Semantic hex (safe for `${C.color}33` alpha-suffix patterns) ─────
  white:     "#ffffff",
  accent:    "#06d6e0",
  accentMid: "rgba(6,214,224,0.12)",
  teal:      "#14b8a6",
  green:     "#2dd4a0",
  red:       "#ef4444",
  amber:     "#f59e0b",
  orange:    "#f97316",
  purple:    "#a78bfa",
  blue:      "#3b82f6",
  pink:      "#ec4899",
  cyan:      "#22d3ee",
  yellow:    "#facc15",

  // ── Fg variants = CSS vars for TEXT/ICON colors (theme-reactive) ─────
  // Dark mode: bright neons. Light mode: darker shades with real contrast.
  accentFg:  "var(--s-accent)",
  tealFg:    "var(--s-teal)",
  greenFg:   "var(--s-green)",
  redFg:     "var(--s-red)",
  amberFg:   "var(--s-amber)",
  orangeFg:  "var(--s-orange)",
  purpleFg:  "var(--s-purple)",
  blueFg:    "var(--s-blue)",
  pinkFg:    "var(--s-pink)",
  cyanFg:    "var(--s-cyan)",
  yellowFg:  "var(--s-yellow)",

  // ── Dim backgrounds (CSS vars, theme-reactive opacity) ───────────────
  accentDim: "var(--s-accent-dim)",
  tealDim:   "var(--s-teal-dim)",
  greenDim:  "var(--s-green-dim)",
  redDim:    "var(--s-red-dim)",
  amberDim:  "var(--s-amber-dim)",
  orangeDim: "var(--s-orange-dim)",
  purpleDim: "var(--s-purple-dim)",
  blueDim:   "var(--s-blue-dim)",
  pinkDim:   "var(--s-pink-dim)",
  cyanDim:   "var(--s-cyan-dim)",
  yellowDim: "var(--s-yellow-dim)",

  // ── 4% tints (decorative only — no readability impact) ───────────────
  greenTint:   "rgba(45,212,160,.04)",
  redTint:     "rgba(239,68,68,.04)",
  amberTint:   "rgba(245,158,11,.04)",
  orangeTint:  "rgba(249,115,22,.04)",
  purpleTint:  "rgba(167,139,250,.04)",
  blueTint:    "rgba(59,130,246,.04)",
  accentTint:  "rgba(6,214,224,.04)",
  pinkTint:    "rgba(236,72,153,.04)",
  cyanTint:    "rgba(34,211,238,.04)",
  tealTint:    "rgba(20,184,166,.04)",
  yellowTint:  "rgba(250,204,21,.04)",
  greenTint3:  "rgba(45,212,160,.03)",
  redTint3:    "rgba(239,68,68,.03)",
  accentTint3: "rgba(6,214,224,.03)",
};

// Status -> theme-reactive foreground color
export function statusColor(status: string): string {
  switch (String(status || "").toLowerCase()) {
    case "active": case "enabled": case "running": case "valid": case "completed": case "healthy":
      return C.greenFg;
    case "revoked": case "error": case "failed": case "down": case "denied": case "deleted":
      return C.redFg;
    case "expiring": case "warning": case "degraded": case "restarting": case "pending":
      return C.amberFg;
    case "expired": case "disabled": case "inactive": case "suspended":
      return C.orangeFg;
    default:
      return C.blueFg;
  }
}
