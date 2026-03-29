import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";

export type PaletteItem = {
  id: string;
  label: string;
  group: string;
  icon?: React.ComponentType<{ size?: number; strokeWidth?: number }>;
};

type Props = {
  open: boolean;
  onClose: () => void;
  items: PaletteItem[];
  onSelect: (id: string) => void;
};

function highlight(text: string, query: string): React.ReactNode {
  if (!query) return text;
  const idx = text.toLowerCase().indexOf(query.toLowerCase());
  if (idx === -1) return text;
  return (
    <>
      {text.slice(0, idx)}
      <mark
        style={{
          background: "rgba(6,214,224,0.25)",
          color: "#06d6e0",
          borderRadius: 2,
          fontWeight: 700,
        }}
      >
        {text.slice(idx, idx + query.length)}
      </mark>
      {text.slice(idx + query.length)}
    </>
  );
}

/**
 * CommandPalette — a ⌘K-style overlay for fast keyboard-driven tab navigation.
 *
 * Usage:
 *   <CommandPalette open={open} onClose={() => setOpen(false)}
 *     items={navItems} onSelect={selectTab} />
 *
 * Open with ⌘K / Ctrl+K (the parent mounts the keyboard listener).
 * Navigate with ↑ / ↓, confirm with Enter, dismiss with Escape or backdrop click.
 */
export function CommandPalette({ open, onClose, items, onSelect }: Props) {
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Reset state each time the palette opens.
  useEffect(() => {
    if (open) {
      setQuery("");
      setCursor(0);
      // Defer focus so the portal is mounted first.
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (item) =>
        item.label.toLowerCase().includes(q) ||
        item.group.toLowerCase().includes(q) ||
        item.id.toLowerCase().includes(q)
    );
  }, [items, query]);

  // Keep cursor in bounds when filter changes.
  useEffect(() => {
    setCursor((c) => Math.min(c, Math.max(filtered.length - 1, 0)));
  }, [filtered.length]);

  // Scroll active item into view.
  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-idx="${cursor}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  function handleKey(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      onClose();
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setCursor((c) => (c + 1) % Math.max(filtered.length, 1));
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      setCursor((c) => (c - 1 + Math.max(filtered.length, 1)) % Math.max(filtered.length, 1));
      return;
    }
    if (e.key === "Enter" && filtered[cursor]) {
      onSelect(filtered[cursor].id);
      onClose();
    }
  }

  if (!open) return null;

  const isMac = navigator.platform.toUpperCase().includes("MAC");

  return createPortal(
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 10001,
        background: "rgba(6,10,17,0.75)",
        backdropFilter: "blur(4px)",
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        paddingTop: "15vh",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKey}
        style={{
          width: "min(540px, 92vw)",
          background: "#0f1521",
          border: "1px solid #243656",
          borderRadius: 12,
          boxShadow: "0 24px 64px rgba(0,0,0,0.8)",
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
          maxHeight: "65vh",
        }}
      >
        {/* Search input */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "12px 16px",
            borderBottom: "1px solid #1a2944",
          }}
        >
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#64748b"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
            style={{ flexShrink: 0 }}
          >
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => { setQuery(e.target.value); setCursor(0); }}
            onKeyDown={handleKey}
            placeholder="Jump to tab…"
            aria-label="Command palette search"
            style={{
              flex: 1,
              background: "transparent",
              border: "none",
              outline: "none",
              color: "#e2e8f0",
              fontSize: 14,
              fontFamily: "'IBM Plex Sans', system-ui, sans-serif",
            }}
          />
          <kbd
            style={{
              fontSize: 10,
              color: "#475569",
              background: "#0a0f1a",
              border: "1px solid #1a2944",
              borderRadius: 4,
              padding: "2px 6px",
              fontFamily: "'IBM Plex Mono', monospace",
            }}
          >
            ESC
          </kbd>
        </div>

        {/* Results */}
        <div
          ref={listRef}
          role="listbox"
          aria-label="Navigation items"
          style={{ overflowY: "auto", flex: 1 }}
        >
          {filtered.length === 0 ? (
            <div
              style={{
                padding: "32px 16px",
                textAlign: "center",
                color: "#475569",
                fontSize: 13,
              }}
            >
              No results for &ldquo;{query}&rdquo;
            </div>
          ) : (
            filtered.map((item, idx) => {
              const Icon = item.icon;
              const active = idx === cursor;
              return (
                <div
                  key={item.id}
                  data-idx={idx}
                  role="option"
                  aria-selected={active}
                  onClick={() => { onSelect(item.id); onClose(); }}
                  onMouseEnter={() => setCursor(idx)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    padding: "9px 16px",
                    cursor: "pointer",
                    background: active ? "#182740" : "transparent",
                    transition: "background 0.1s",
                  }}
                >
                  <div
                    style={{
                      width: 28,
                      height: 28,
                      borderRadius: 6,
                      background: active ? "rgba(6,214,224,0.12)" : "#131d2e",
                      border: `1px solid ${active ? "rgba(6,214,224,0.3)" : "#1a2944"}`,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      flexShrink: 0,
                      color: active ? "#06d6e0" : "#64748b",
                    }}
                  >
                    {Icon ? (
                      <Icon size={13} strokeWidth={2} />
                    ) : (
                      <span style={{ fontSize: 11, fontWeight: 700 }}>
                        {item.label.charAt(0).toUpperCase()}
                      </span>
                    )}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        fontSize: 13,
                        color: active ? "#e2e8f0" : "#94a3b8",
                        fontWeight: active ? 600 : 400,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                      }}
                    >
                      {highlight(item.label, query)}
                    </div>
                  </div>
                  <div
                    style={{
                      fontSize: 9,
                      color: "#334155",
                      textTransform: "uppercase",
                      letterSpacing: 1,
                      flexShrink: 0,
                    }}
                  >
                    {highlight(item.group, query)}
                  </div>
                  {active && (
                    <kbd
                      style={{
                        fontSize: 9,
                        color: "#475569",
                        background: "#0a0f1a",
                        border: "1px solid #1a2944",
                        borderRadius: 3,
                        padding: "1px 5px",
                        flexShrink: 0,
                        fontFamily: "'IBM Plex Mono', monospace",
                      }}
                    >
                      ↵
                    </kbd>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Footer hint */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 14,
            padding: "8px 16px",
            borderTop: "1px solid #1a2944",
            fontSize: 10,
            color: "#334155",
            fontFamily: "'IBM Plex Mono', monospace",
          }}
        >
          <span>↑↓ navigate</span>
          <span>↵ open</span>
          <span>esc close</span>
          <span style={{ marginLeft: "auto" }}>
            {isMac ? "⌘K" : "Ctrl+K"} to reopen
          </span>
        </div>
      </div>
    </div>,
    document.body
  );
}
