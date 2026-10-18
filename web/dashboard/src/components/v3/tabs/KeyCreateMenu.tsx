import { ArrowDownToLine, Atom, ChevronDown, PenTool, Plus, Radar } from "lucide-react";
import { Btn } from "../legacyPrimitives";
import { C } from "../theme";
import { usePopover } from "../usePopover";

const btnStyle = { height: 40, padding: "0 16px", borderRadius: 4, fontSize: 12, fontWeight: 700 } as const;

// One main action on the key page (13.23.0-beta): Create Key, with the other
// ways to add a key in one menu. They were five buttons in a row.
export function KeyCreateMenu({ onCreate, onForm, onImport, onPQC, onCanary }: {
  onCreate: () => void; onForm: () => void; onImport: () => void; onPQC: () => void; onCanary: () => void;
}) {
  const [open, setOpen, ref] = usePopover();
  const more = [
    { label: "Form Key", hint: "Form a key from key components", icon: PenTool, run: onForm },
    { label: "Import", hint: "Import existing key material", icon: ArrowDownToLine, run: onImport },
    { label: "PQC Key", hint: "Generate a post-quantum key", icon: Atom, run: onPQC },
    { label: "Canary Key", hint: "Decoy keys that alert when used", icon: Radar, run: onCanary },
  ];
  return (
    <div ref={ref} style={{ display: "inline-flex", gap: 8, position: "relative" }}>
      <Btn primary onClick={onCreate} style={{ ...btnStyle, padding: "0 20px", minWidth: 130 }}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}><Plus size={13} strokeWidth={2.2} />Create Key</span>
      </Btn>
      <Btn onClick={() => setOpen((v) => !v)} aria-haspopup="menu" aria-expanded={open} style={{ ...btnStyle, color: C.text, border: `1px solid ${C.borderHi}` }}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>More ways<ChevronDown size={13} strokeWidth={2.1} /></span>
      </Btn>
      {open && (
        <div role="menu" style={{ position: "absolute", top: 44, right: 0, zIndex: 30, minWidth: 220, background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 4, padding: 4, boxShadow: "0 8px 24px rgba(0,0,0,.18)" }}>
          {more.map((m) => (
            <button key={m.label} type="button" role="menuitem" title={m.hint} onClick={() => { setOpen(false); m.run(); }}
              className="vk-nav-item" style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "8px 10px", border: 0, borderRadius: 3, background: "transparent", color: C.text, fontSize: 12.5, cursor: "pointer", textAlign: "left" }}>
              <m.icon size={13} strokeWidth={2.1} style={{ color: C.muted }} />{m.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
