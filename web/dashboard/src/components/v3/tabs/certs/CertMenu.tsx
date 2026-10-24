import type { ReactNode } from "react";
import { ChevronDown, MoreVertical, type LucideIcon } from "lucide-react";
import { Btn } from "../../legacyPrimitives";
import { C } from "../../theme";
import { usePopover } from "../../usePopover";

export type CertMenuItem = {
  label: string;
  icon?: LucideIcon;
  run?: () => void;
  danger?: boolean;
  disabled?: boolean;
  title?: string;
};

// One menu for the PKI page's grouped actions: the toolbar's Issue and
// Policies menus, and the ⋮ on each CA and certificate row. A danger item
// sits under a hairline; an item without run is a note, not an action.
export function CertMenu({ label, ariaLabel, items, children }: {
  label?: string; ariaLabel?: string; items: CertMenuItem[]; children?: ReactNode;
}) {
  const [open, setOpen, ref] = usePopover();
  const toggle = () => setOpen((v) => !v);
  return (
    <div ref={ref} style={{ position: "relative", display: "inline-flex", gap: 6 }}>
      {children}
      {label
        ? <Btn small onClick={toggle} aria-haspopup="menu" aria-expanded={open} aria-label={ariaLabel}>
            <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>{label}<ChevronDown size={12} /></span>
          </Btn>
        : <button type="button" onClick={toggle} aria-haspopup="menu" aria-expanded={open} aria-label={ariaLabel}
            style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 3, color: C.dim, width: 26, height: 24, display: "inline-flex", alignItems: "center", justifyContent: "center", cursor: "pointer" }}>
            <MoreVertical size={14} />
          </button>}
      {open && (
        <div role="menu" style={{ position: "absolute", top: "calc(100% + 4px)", right: 0, zIndex: 30, minWidth: 190, background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 4, padding: 4, boxShadow: "0 8px 24px rgba(0,0,0,.18)" }}>
          {items.map((it, i) => {
            const Icon = it.icon;
            const rule = it.danger && i > 0 && !items[i - 1]?.danger;
            const body = <>{Icon ? <Icon size={12} style={{ color: it.danger ? C.redFg : C.muted }} /> : null}{it.label}</>;
            const look = { display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "7px 9px", fontSize: 11.5, textAlign: "left" as const, borderRadius: 3 };
            return (
              <div key={it.label}>
                {rule ? <div style={{ height: 1, background: C.border, margin: "3px 0" }} /> : null}
                {it.run
                  ? <button type="button" role="menuitem" title={it.title} disabled={it.disabled} className="vk-nav-item"
                      onClick={() => { setOpen(false); it.run?.(); }}
                      style={{ ...look, border: 0, background: "transparent", color: it.danger ? C.redFg : C.text, cursor: it.disabled ? "not-allowed" : "pointer", opacity: it.disabled ? 0.6 : 1 }}>{body}</button>
                  : <div title={it.title} style={{ ...look, color: C.muted }}>{body}</div>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
