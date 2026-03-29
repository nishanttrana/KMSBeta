import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { type Toast, dismiss, subscribeToasts } from "../lib/toast";

const VARIANT_STYLES: Record<
  Toast["variant"],
  { bg: string; border: string; icon: string; color: string }
> = {
  success: { bg: "#0f2818", border: "#166534", icon: "✓", color: "#4ade80" },
  error:   { bg: "#2a0f0f", border: "#991b1b", icon: "✕", color: "#f87171" },
  info:    { bg: "#0f1e35", border: "#1d4ed8", icon: "i", color: "#60a5fa" },
  warn:    { bg: "#2a1e04", border: "#92400e", icon: "!", color: "#fbbf24" },
};

function ToastItem({ toast }: { toast: Toast }) {
  const v = VARIANT_STYLES[toast.variant];
  const [visible, setVisible] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    // Trigger slide-in on mount.
    const id = setTimeout(() => setVisible(true), 10);
    return () => clearTimeout(id);
  }, []);

  // Start fade-out 400 ms before auto-dismiss.
  useEffect(() => {
    const fadeDelay = Math.max(toast.duration - 400, 100);
    timerRef.current = setTimeout(() => setVisible(false), fadeDelay);
    return () => clearTimeout(timerRef.current);
  }, [toast.duration]);

  return (
    <div
      role="alert"
      aria-live={toast.variant === "error" ? "assertive" : "polite"}
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: "10px",
        padding: "10px 14px",
        borderRadius: 8,
        background: v.bg,
        border: `1px solid ${v.border}`,
        boxShadow: "0 4px 16px rgba(0,0,0,0.5)",
        maxWidth: 380,
        minWidth: 240,
        opacity: visible ? 1 : 0,
        transform: visible ? "translateX(0)" : "translateX(24px)",
        transition: "opacity 0.25s ease, transform 0.25s ease",
        cursor: "default",
      }}
    >
      <span
        style={{
          width: 18,
          height: 18,
          borderRadius: "50%",
          border: `1.5px solid ${v.color}`,
          color: v.color,
          fontSize: 10,
          fontWeight: 700,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
          marginTop: 1,
        }}
      >
        {v.icon}
      </span>
      <span
        style={{
          flex: 1,
          fontSize: 12,
          lineHeight: 1.5,
          color: "#e2e8f0",
          fontFamily: "'IBM Plex Sans', system-ui, sans-serif",
          wordBreak: "break-word",
        }}
      >
        {toast.message}
      </span>
      <button
        onClick={() => dismiss(toast.id)}
        aria-label="Dismiss notification"
        style={{
          background: "transparent",
          border: "none",
          color: "#64748b",
          cursor: "pointer",
          fontSize: 14,
          lineHeight: 1,
          padding: "0 2px",
          flexShrink: 0,
        }}
      >
        ×
      </button>
    </div>
  );
}

/**
 * ToastStack — renders all active toasts in the bottom-right corner via a
 * React portal (mounted directly on document.body so z-index is always on top).
 * Add <ToastStack /> once in main.tsx, inside the React tree.
 */
export function ToastStack() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  useEffect(() => {
    return subscribeToasts(setToasts);
  }, []);

  if (toasts.length === 0) return null;

  return createPortal(
    <div
      style={{
        position: "fixed",
        right: 16,
        bottom: 16,
        zIndex: 10000,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        pointerEvents: "none",
      }}
    >
      {toasts.map((t) => (
        <div key={t.id} style={{ pointerEvents: "auto" }}>
          <ToastItem toast={t} />
        </div>
      ))}
    </div>,
    document.body
  );
}
