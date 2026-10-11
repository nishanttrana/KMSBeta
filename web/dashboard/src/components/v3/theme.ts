// Two-tier color strategy:
//   C.*       = hex literals → safe for `${C.color}33` alpha-suffix interpolation.
//                These are the *base* hue (Basalt dark palette); they do NOT
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
  elevated:  "var(--c-elevated)",
  border:    "var(--c-border)",
  borderHi:  "var(--c-border-hi)",
  text:      "var(--c-text)",
  dim:       "var(--c-dim)",
  muted:     "var(--c-muted)",
  glow:      "var(--c-glow)",
  glowStrong:"var(--c-glow-strong)",
  dimTint:   "var(--c-dim-tint)",

  // ── Brass core of the mark (theme-reactive) ───────────────────────────
  auroraFrom: "var(--c-aurora-from)",
  auroraMid:  "var(--c-aurora-mid)",
  auroraTo:   "var(--c-aurora-to)",

  // ── Semantic hex (Basalt palette — safe for `${C.color}NN` alpha) ────
  // Mid-tones on purpose: a hue passed as a prop ends up as text or as a fill
  // on either theme, so each reads on the light and the dark card
  // (tests/unit/brandAndLegibility.test.ts).
  white:     "#ffffff",
  accent:    "#1493a8",  // Petrol (single accent)
  accentMid: "rgba(20,147,168,0.16)",
  teal:      "#17a398",
  green:     "#1fa463",
  red:       "#e8555a",
  amber:     "#c2850f",
  orange:    "#dd6b20",
  purple:    "#8b6cf0",
  blue:      "#4a90e2",
  pink:      "#d9539a",
  cyan:      "#1a9fbe",
  yellow:    "#a88d10",

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
  accentTint:  "rgba(20,147,168,.05)",
  pinkTint:    "rgba(244,114,182,.04)",
  cyanTint:    "rgba(34,211,238,.04)",
  tealTint:    "rgba(45,212,191,.04)",
  yellowTint:  "rgba(253,224,71,.04)",
  greenTint3:  "rgba(52,211,153,.03)",
  redTint3:    "rgba(248,113,113,.03)",
  accentTint3: "rgba(20,147,168,.04)",
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
