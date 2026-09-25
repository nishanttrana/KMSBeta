// Two-tier color strategy:
//   C.*       = hex literals → safe for `${C.color}33` alpha-suffix interpolation.
//                These are the *base* hue (Aurora dark palette); they do NOT
//                react to theme switches. Used for borders, faint backgrounds,
//                and decorative tints that don't need contrast guarantees.
//   C.*Fg     = CSS vars → theme-reactive text/icon colors. Use these whenever
//                a color carries readability (numbers, status text, icons).
//                Dark: bright neon. Light: darker shade with real contrast.
//   C.*Dim    = CSS vars → theme-reactive background tints (opacity adapts).
//   Structural (bg, card, border, etc.) = CSS vars → fully theme-reactive.
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

  // ── Aurora gradient stops (theme-reactive) ───────────────────────────
  auroraFrom: "var(--c-aurora-from)",
  auroraMid:  "var(--c-aurora-mid)",
  auroraTo:   "var(--c-aurora-to)",

  // ── Semantic hex (Aurora palette — safe for `${C.color}NN` alpha) ────
  white:     "#ffffff",
  accent:    "#7b8cff",  // Graphite indigo (single accent)
  accentMid: "rgba(123,140,255,0.16)",
  teal:      "#3cc9b4",
  green:     "#45c987",
  red:       "#f07474",
  amber:     "#e9b44c",
  orange:    "#ef9458",
  purple:    "#b39cf5",
  blue:      "#6ea8f5",
  pink:      "#ea86b8",
  cyan:      "#5cc6de",
  yellow:    "#e8d25c",

  // ── Fg variants = CSS vars (theme-reactive text/icon colors) ─────────
  // Dark: bright neon. Light: darker shade with WCAG contrast.
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

  // ── 3-4% tints (decorative only — no readability impact) ─────────────
  greenTint:   "rgba(52,211,153,.04)",
  redTint:     "rgba(248,113,113,.04)",
  amberTint:   "rgba(251,191,36,.04)",
  orangeTint:  "rgba(251,146,60,.04)",
  purpleTint:  "rgba(167,139,250,.04)",
  blueTint:    "rgba(96,165,250,.04)",
  accentTint:  "rgba(123,140,255,.05)",
  pinkTint:    "rgba(244,114,182,.04)",
  cyanTint:    "rgba(34,211,238,.04)",
  tealTint:    "rgba(45,212,191,.04)",
  yellowTint:  "rgba(253,224,71,.04)",
  greenTint3:  "rgba(52,211,153,.03)",
  redTint3:    "rgba(248,113,113,.03)",
  accentTint3: "rgba(123,140,255,.04)",
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
