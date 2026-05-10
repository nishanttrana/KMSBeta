import { Moon, Sun } from "lucide-react";
import { useTheme } from "../store/theme";

type Props = {
  /** "icon" = circular icon-only; "labeled" = pill with label */
  variant?: "icon" | "labeled";
  className?: string;
};

export function ThemeToggle({ variant = "icon", className = "" }: Props) {
  const theme = useTheme((s) => s.theme);
  const toggle = useTheme((s) => s.toggle);
  const isDark = theme === "dark";

  if (variant === "labeled") {
    return (
      <button
        type="button"
        onClick={toggle}
        className={`vecta-theme-toggle ${className}`}
        aria-label={`Switch to ${isDark ? "light" : "dark"} theme`}
        title={`Switch to ${isDark ? "light" : "dark"} theme`}
      >
        {isDark ? <Moon size={12} /> : <Sun size={12} />}
        <span>{isDark ? "Dark" : "Light"}</span>
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={`Switch to ${isDark ? "light" : "dark"} theme`}
      title={`Switch to ${isDark ? "light" : "dark"} theme`}
      className={className}
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        width: 32,
        height: 32,
        borderRadius: 999,
        border: "1px solid var(--c-border)",
        background: "var(--c-card)",
        color: "var(--c-dim)",
        cursor: "pointer",
        transition: "all 0.15s ease",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = "var(--s-accent)";
        e.currentTarget.style.color = "var(--s-accent)";
        e.currentTarget.style.boxShadow = "0 0 0 3px var(--c-accent-dim)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = "var(--c-border)";
        e.currentTarget.style.color = "var(--c-dim)";
        e.currentTarget.style.boxShadow = "none";
      }}
    >
      {isDark ? <Moon size={14} /> : <Sun size={14} />}
    </button>
  );
}
