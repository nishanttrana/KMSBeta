import {
  useState,
  type ButtonHTMLAttributes,
  type CSSProperties,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes
} from "react";
import {
  Atom,
  Bell,
  Building2,
  Check,
  CheckCircle2,
  Clock3,
  Database,
  FileText,
  Gauge,
  KeyRound,
  Link,
  Lock,
  Radio as RadioIcon,
  ShieldCheck,
  X,
  Zap
} from "lucide-react";
import { C } from "./theme";

type ModalProps = {
  open: boolean;
  onClose: () => void;
  title: string;
  wide?: boolean;
  width?: number | string;
  children?: ReactNode;
};

export const Modal = ({ open, onClose, title, wide = false, width, children }: ModalProps) => !open ? null : (
  <div style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }} onClick={onClose}>
    <div style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,.7)", backdropFilter: "blur(4px)" }} />
    <div onClick={(e) => e.stopPropagation()} style={{ position: "relative", background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 14, padding: 0, width: width || (wide ? 780 : 540), maxHeight: "88vh", overflow: "auto", boxShadow: "0 24px 60px rgba(0,0,0,.5)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 20px", borderBottom: `1px solid ${C.border}`, position: "sticky", top: 0, background: C.surface, zIndex: 1, borderRadius: "14px 14px 0 0" }}>
        <span style={{ fontSize: 15, fontWeight: 700, color: C.text, letterSpacing: -0.3 }}>{title}</span>
        <button onClick={onClose} aria-label="Close" style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", padding: 4, lineHeight: 1, display: "inline-flex", alignItems: "center", justifyContent: "center" }}>
          <X size={14} strokeWidth={2} />
        </button>
      </div>
      <div style={{ padding: "16px 20px 20px" }}>{children}</div>
    </div>
  </div>
);

export function usePromptDialog() {
  const [dialog, setDialog] = useState<any>({
    open: false,
    mode: "confirm",
    title: "Confirm Action",
    message: "",
    confirmLabel: "Confirm",
    cancelLabel: "Cancel",
    danger: false,
    placeholder: "",
    value: "",
    validator: null,
    resolver: null,
    error: ""
  });

  const closeWith = (result: unknown) => {
    const resolver = dialog?.resolver;
    setDialog((prev: any) => ({ ...prev, open: false, resolver: null, error: "" }));
    if (typeof resolver === "function") {
      resolver(result);
    }
  };

  const confirm = (opts: Record<string, unknown> = {}) => new Promise<boolean>((resolve) => {
    setDialog({
      open: true,
      mode: "confirm",
      title: String(opts?.title || "Confirm Action"),
      message: String(opts?.message || ""),
      confirmLabel: String(opts?.confirmLabel || "Confirm"),
      cancelLabel: String(opts?.cancelLabel || "Cancel"),
      danger: Boolean(opts?.danger),
      placeholder: "",
      value: "",
      validator: null,
      resolver: resolve,
      error: ""
    });
  });

  const prompt = (opts: Record<string, unknown> = {}) => new Promise<string | null>((resolve) => {
    const initial = String(opts?.defaultValue ?? "");
    setDialog({
      open: true,
      mode: "prompt",
      title: String(opts?.title || "Input Required"),
      message: String(opts?.message || ""),
      confirmLabel: String(opts?.confirmLabel || "Submit"),
      cancelLabel: String(opts?.cancelLabel || "Cancel"),
      danger: Boolean(opts?.danger),
      placeholder: String(opts?.placeholder || ""),
      value: initial,
      validator: typeof opts?.validate === "function" ? (opts.validate as (value: string) => string | undefined | null) : null,
      resolver: resolve,
      error: ""
    });
  });

  const submit = () => {
    if (dialog?.mode === "prompt") {
      const value = String(dialog?.value ?? "");
      if (typeof dialog?.validator === "function") {
        const maybeError = dialog.validator(value);
        if (maybeError) {
          setDialog((prev: any) => ({ ...prev, error: String(maybeError) }));
          return;
        }
      }
      closeWith(value);
      return;
    }
    closeWith(true);
  };

  const cancel = () => {
    closeWith(dialog?.mode === "prompt" ? null : false);
  };

  const ui = <Modal open={Boolean(dialog?.open)} onClose={cancel} title={String(dialog?.title || "Confirm Action")} width={460}>
    {String(dialog?.message || "").trim() ? <div style={{ fontSize: 11, color: C.dim, whiteSpace: "pre-wrap", lineHeight: 1.5, marginBottom: dialog?.mode === "prompt" ? 10 : 14 }}>
      {dialog.message}
    </div> : null}
    {dialog?.mode === "prompt" ? <div style={{ marginBottom: 8 }}>
      <Inp
        autoFocus
        value={String(dialog?.value ?? "")}
        placeholder={String(dialog?.placeholder || "")}
        onChange={(e) => setDialog((prev: any) => ({ ...prev, value: e.target.value, error: "" }))}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            submit();
          }
        }}
      />
    </div> : null}
    {String(dialog?.error || "").trim() ? <div style={{ fontSize: 10, color: C.red, marginBottom: 8 }}>{dialog.error}</div> : null}
    <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 4 }}>
      <Btn onClick={cancel}>{String(dialog?.cancelLabel || "Cancel")}</Btn>
      <Btn primary={!dialog?.danger} danger={Boolean(dialog?.danger)} onClick={submit}>{String(dialog?.confirmLabel || "Confirm")}</Btn>
    </div>
  </Modal>;

  return { confirm, prompt, ui };
}

type FieldGroupProps = {
  label: string;
  children: ReactNode;
  hint?: ReactNode;
  required?: boolean;
};

export const FG = ({ label, children, hint, required = false }: FieldGroupProps) => (
  <div style={{ marginBottom: 12 }}>
    <label style={{ display: "block", fontSize: 10, fontWeight: 600, color: C.dim, marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.8 }}>
      {label}
      {required && <span style={{ color: C.red }}> *</span>}
    </label>
    {children}
    {hint && <div style={{ fontSize: 9, color: C.muted, marginTop: 3 }}>{hint}</div>}
  </div>
);

type InpProps = InputHTMLAttributes<HTMLInputElement> & {
  w?: number | string;
  mono?: boolean;
  style?: CSSProperties;
};

export const Inp = ({ placeholder, w, mono = false, style, ...p }: InpProps) => <input placeholder={placeholder} style={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: 7, padding: "8px 10px", color: C.text, fontSize: 11, width: w || "100%", outline: "none", fontFamily: mono ? "'JetBrains Mono',monospace" : "inherit", boxSizing: "border-box", ...(style || {}) }} {...p} />;

type TxtProps = TextareaHTMLAttributes<HTMLTextAreaElement> & {
  rows?: number;
  mono?: boolean;
  style?: CSSProperties;
};

export const Txt = ({ placeholder, rows = 3, mono = true, style, ...p }: TxtProps) => <textarea placeholder={placeholder} rows={rows} style={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: 7, padding: "8px 10px", color: C.text, fontSize: 11, width: "100%", outline: "none", resize: "vertical", fontFamily: mono ? "'JetBrains Mono',monospace" : "inherit", boxSizing: "border-box", ...(style || {}) }} {...p} />;

type SelProps = SelectHTMLAttributes<HTMLSelectElement> & {
  children?: ReactNode;
  w?: number | string;
  style?: CSSProperties;
};

export const Sel = ({ children, w, style, ...p }: SelProps) => <select style={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: 7, padding: "8px 30px 8px 10px", color: C.text, fontSize: 11, width: w || "100%", outline: "none", cursor: "pointer", boxSizing: "border-box", appearance: "none", WebkitAppearance: "none", MozAppearance: "none", backgroundImage: "linear-gradient(45deg, transparent 50%, #7f93b3 50%), linear-gradient(135deg, #7f93b3 50%, transparent 50%)", backgroundPosition: "calc(100% - 14px) calc(50% - 2px), calc(100% - 9px) calc(50% - 2px)", backgroundSize: "5px 5px, 5px 5px", backgroundRepeat: "no-repeat", ...(style || {}) }} {...p}>{children}</select>;

type ChkProps = {
  label: ReactNode;
  checked: boolean;
  onChange?: () => void;
  disabled?: boolean;
};

export const Chk = ({ label, checked, onChange, disabled = false }: ChkProps) => (
  <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: disabled ? C.muted : C.dim, cursor: disabled ? "not-allowed" : "pointer", marginBottom: 4, opacity: disabled ? 0.75 : 1 }}>
    <div style={{ width: 16, height: 16, borderRadius: 4, border: `1px solid ${checked ? C.accent : C.border}`, background: checked ? C.accentDim : "transparent", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }} onClick={disabled ? undefined : onChange}>
      {checked && <Check size={10} strokeWidth={3} color={C.accent} />}
    </div>{label}
  </label>
);

type RadioProps = {
  label: ReactNode;
  selected: boolean;
  onSelect?: () => void;
};

export const Radio = ({ label, selected, onSelect }: RadioProps) => (
  <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: selected ? C.text : C.dim, cursor: "pointer", marginBottom: 4 }} onClick={onSelect}>
    <div style={{ width: 14, height: 14, borderRadius: 7, border: `2px solid ${selected ? C.accent : C.border}`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
      {selected && <div style={{ width: 6, height: 6, borderRadius: 3, background: C.accent }} />}
    </div>{label}
  </label>
);

type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  children?: ReactNode;
  primary?: boolean;
  danger?: boolean;
  small?: boolean;
  full?: boolean;
  style?: CSSProperties;
};

export const Btn = ({ children, primary = false, danger = false, small = false, onClick, disabled = false, full = false, style, ...p }: BtnProps) => (
  <button onClick={onClick} disabled={disabled} {...p} style={{ background: danger ? C.red : primary ? C.accent : "transparent", color: danger || primary ? C.bg : C.accent, border: `1px solid ${danger ? C.red : primary ? C.accent : C.border}`, borderRadius: 7, padding: small ? "5px 10px" : "8px 16px", fontSize: small ? 10 : 11, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", opacity: disabled ? 0.5 : 1, width: full ? "100%" : "auto", letterSpacing: 0.2, display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 6, ...(style || {}) }}>{children}</button>
);

type BadgeProps = {
  children?: ReactNode;
  c?: string;
  pulse?: boolean;
};

export const B = ({ children, c = "accent", pulse = false }: BadgeProps) => {
  const palette = C as Record<string, string>;
  const textColor = palette[c] || C.accent;
  const bgColor = palette[`${c}Dim`] || "rgba(255,255,255,.05)";
  return (
    <span style={{ display: "inline-block", padding: "2px 7px", borderRadius: 5, fontSize: 9, fontWeight: 600, color: textColor, background: bgColor, letterSpacing: 0.3, animation: pulse ? "pulse 2s infinite" : "none" }}>{children}</span>
  );
};

type TabsProps = {
  tabs: string[];
  active: string;
  onChange: (tab: string) => void;
};

export const Tabs = ({ tabs, active, onChange }: TabsProps) => (
  <div style={{ display: "flex", gap: 2, marginBottom: 14, flexWrap: "wrap" }}>
    {tabs.map((t) => <button key={t} onClick={() => onChange(t)} style={{ background: active === t ? C.accentDim : "transparent", color: active === t ? C.accent : C.muted, border: `1px solid ${active === t ? C.accent : C.border}`, borderRadius: 6, padding: "5px 10px", fontSize: 10, fontWeight: active === t ? 600 : 400, cursor: "pointer", letterSpacing: 0.2 }}>{t}</button>)}
  </div>
);

function statIconForLabel(label: string) {
  const key = String(label || "").toLowerCase();
  if (key === "cas") return Building2;
  if (key.includes("pqc")) return Atom;
  if (key.includes("expiring")) return Clock3;
  if (key.includes("ops")) return Zap;
  if (key.includes("alert") || key === "open" || key === "today") return Bell;
  if (key.includes("secret")) return Lock;
  if (key.includes("cert")) return FileText;
  if (key.includes("protocol") || key.includes("channels")) return RadioIcon;
  if (key.includes("response")) return Gauge;
  if (key.includes("client")) return Link;
  if (key.includes("type")) return Database;
  if (key.includes("lease") || key === "active") return CheckCircle2;
  if (key.includes("key")) return KeyRound;
  return ShieldCheck;
}

type StatProps = {
  l: ReactNode;
  v: ReactNode;
  s?: ReactNode;
  c?: string;
  i?: (...args: any[]) => any;
};

export const Stat = ({ l, v, s, c = "accent", i }: StatProps) => {
  const Icon = typeof i === "function" ? i : statIconForLabel(String(l ?? ""));
  const palette = C as Record<string, string>;
  return (
    <div style={{ flex: 1, background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, padding: "12px 14px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>{l}</span>
        <span style={{ display: "inline-flex", color: C.dim }}><Icon size={14} strokeWidth={2} /></span>
      </div>
      <div style={{ fontSize: 22, fontWeight: 700, color: palette[c] || C.accent, marginTop: 4, letterSpacing: -0.5 }}>{v}</div>
      {s && <div style={{ fontSize: 9, color: C.dim, marginTop: 2 }}>{s}</div>}
    </div>
  );
};

type BarProps = {
  pct: number;
  color?: string;
};

export const Bar = ({ pct, color = C.accent }: BarProps) => (
  <div style={{ height: 6, borderRadius: 3, background: C.border, overflow: "hidden" }}>
    <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 3, transition: "width .5s" }} />
  </div>
);

type SectionProps = {
  title: ReactNode;
  children?: ReactNode;
  actions?: ReactNode;
};

export const Section = ({ title, children, actions }: SectionProps) => (
  <div style={{ marginBottom: 16 }}>
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
      <span style={{ fontSize: 12, fontWeight: 700, color: C.text, letterSpacing: -0.2 }}>{title}</span>
      {actions && <div style={{ display: "flex", gap: 4 }}>{actions}</div>}
    </div>{children}
  </div>
);

type CardProps = {
  children?: ReactNode;
  onClick?: () => void;
  style?: CSSProperties;
};

export const Card = ({ children, onClick, style }: CardProps) => (
  <div onClick={onClick} style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, padding: 14, cursor: onClick ? "pointer" : "default", transition: "border-color .15s", ...(style || {}) }} onMouseEnter={(e) => { if (onClick) e.currentTarget.style.borderColor = C.accent; }} onMouseLeave={(e) => { if (onClick) e.currentTarget.style.borderColor = C.border; }}>{children}</div>
);

type RowProps = {
  children?: ReactNode;
};

export const Row2 = ({ children }: RowProps) => <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>{children}</div>;
export const Row3 = ({ children }: RowProps) => <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>{children}</div>;
