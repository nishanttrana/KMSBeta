/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#060a11",
          sidebar: "#0a0f1a",
          panel: "#0f1521",
          card: "#131d2e",
          elevated: "#182740",
          border: "#1a2944",
          text: "#e2e8f0",
          muted: "#94a3b8",
          accent: "#06d6e0",
          success: "#2dd4a0",
          warning: "#f6ba3a",
          danger: "#ef4444",
          purple: "#a78bfa"
        }
      },
      fontFamily: {
        heading: ["Rajdhani", "sans-serif"],
        body: ["IBM Plex Sans", "sans-serif"],
        mono: ["IBM Plex Mono", "monospace"]
      },
      boxShadow: {
        "accent-glow": "0 0 12px rgba(6,214,224,0.12), 0 0 4px rgba(6,214,224,0.08)",
        "card-depth": "0 1px 2px rgba(0,0,0,0.2), 0 4px 12px rgba(0,0,0,0.15)"
      },
      keyframes: {
        pulseBorder: {
          "0%": { boxShadow: "0 0 0 0 rgba(24,210,255,0.35)" },
          "70%": { boxShadow: "0 0 0 10px rgba(24,210,255,0)" },
          "100%": { boxShadow: "0 0 0 0 rgba(24,210,255,0)" }
        },
        fadeIn: {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" }
        }
      },
      animation: {
        pulseBorder: "pulseBorder 2.2s ease-out infinite",
        fadeIn: "fadeIn 0.5s ease-out"
      }
    }
  },
  plugins: []
};
