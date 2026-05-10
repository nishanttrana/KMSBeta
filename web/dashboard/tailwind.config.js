/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["selector", '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        // Theme-reactive surfaces (resolve via CSS vars in index.css)
        bg:        "var(--c-bg)",
        sidebar:   "var(--c-sidebar)",
        surface:   "var(--c-surface)",
        card:      "var(--c-card)",
        elevated:  "var(--c-elevated)",
        border:    "var(--c-border)",
        borderHi:  "var(--c-border-hi)",
        text:      "var(--c-text)",
        dim:       "var(--c-dim)",
        muted:     "var(--c-muted)",

        // Aurora gradient stops
        aurora: {
          from: "var(--c-aurora-from)",
          mid:  "var(--c-aurora-mid)",
          to:   "var(--c-aurora-to)",
        },

        // Semantic theme-reactive
        accent:  "var(--s-accent)",
        teal:    "var(--s-teal)",
        green:   "var(--s-green)",
        red:     "var(--s-red)",
        amber:   "var(--s-amber)",
        orange:  "var(--s-orange)",
        purple:  "var(--s-purple)",
        blue:    "var(--s-blue)",
        pink:    "var(--s-pink)",
        cyan:    "var(--s-cyan)",
        yellow:  "var(--s-yellow)",

        // Legacy "cyber" namespace kept for backwards compatibility with
        // existing components that hard-reference cyber.* classes. New code
        // should use the theme-reactive tokens above.
        cyber: {
          bg:       "var(--c-bg)",
          sidebar:  "var(--c-sidebar)",
          panel:    "var(--c-surface)",
          card:     "var(--c-card)",
          elevated: "var(--c-card-hover)",
          border:   "var(--c-border)",
          text:     "var(--c-text)",
          muted:    "var(--c-muted)",
          accent:   "var(--s-accent)",
          success:  "var(--s-green)",
          warning:  "var(--s-amber)",
          danger:   "var(--s-red)",
          purple:   "var(--s-purple)",
        },
      },
      fontFamily: {
        heading: ["Rajdhani", "sans-serif"],
        body:    ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "sans-serif"],
        mono:    ["JetBrains Mono", "IBM Plex Mono", "monospace"],
      },
      borderRadius: {
        sm: "var(--radius-sm)",
        md: "var(--radius-md)",
        lg: "var(--radius-lg)",
        xl: "var(--radius-xl)",
      },
      boxShadow: {
        sm:           "var(--shadow-sm)",
        md:           "var(--shadow-md)",
        lg:           "var(--shadow-lg)",
        glow:         "var(--shadow-glow)",
        "accent-glow": "0 0 0 1px var(--c-accent-dim), 0 0 18px var(--c-glow)",
        "card-depth":  "var(--shadow-md)",
      },
      backgroundImage: {
        aurora:       "linear-gradient(135deg, var(--c-aurora-from), var(--c-aurora-to))",
        "aurora-h":   "linear-gradient(90deg, var(--c-aurora-from), var(--c-aurora-mid), var(--c-aurora-to))",
        "aurora-radial":
          "radial-gradient(ellipse at top left, var(--c-aurora-from), transparent 60%), radial-gradient(ellipse at bottom right, var(--c-aurora-to), transparent 60%)",
      },
      keyframes: {
        pulseBorder: {
          "0%":   { boxShadow: "0 0 0 0 var(--c-glow-strong)" },
          "70%":  { boxShadow: "0 0 0 10px rgba(0,0,0,0)" },
          "100%": { boxShadow: "0 0 0 0 rgba(0,0,0,0)" },
        },
        fadeIn: {
          "0%":   { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        shimmer: {
          "0%":   { backgroundPosition: "-200% center" },
          "100%": { backgroundPosition: "200% center" },
        },
        slideUp: {
          "0%":   { opacity: "0", transform: "translateY(20px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        auroraShift: {
          "0%, 100%": { backgroundPosition: "0% 50%" },
          "50%":      { backgroundPosition: "100% 50%" },
        },
      },
      animation: {
        pulseBorder: "pulseBorder 2.2s ease-out infinite",
        fadeIn:      "fadeIn 0.5s ease-out",
        shimmer:     "shimmer 2.5s linear infinite",
        slideUp:     "slideUp 0.6s ease-out forwards",
        aurora:      "auroraShift 8s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
