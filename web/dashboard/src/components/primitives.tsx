import type { PropsWithChildren, ReactNode } from "react";

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

export function Panel(props: PropsWithChildren<{ title: string; subtitle?: string; actions?: ReactNode; className?: string }>) {
  const { title, subtitle, actions, children, className } = props;
  return (
    <section className={cx("rounded-xl border border-cyber-border bg-cyber-card p-3 shadow-lg shadow-black/25", className)}>
      <header className="mb-2 flex items-start justify-between gap-3">
        <div>
          <h3 className="font-heading text-base font-semibold tracking-wide text-cyber-text">{title}</h3>
          {subtitle ? <p className="text-xs text-cyber-muted">{subtitle}</p> : null}
        </div>
        {actions}
      </header>
      {children}
    </section>
  );
}

export function Button(
  props: PropsWithChildren<{ onClick?: () => void; kind?: "primary" | "secondary" | "danger"; className?: string; type?: "button" | "submit" }>
) {
  const { onClick, kind = "primary", children, className, type = "button" } = props;
  const classes =
    kind === "primary"
      ? "border-cyber-accent bg-cyber-accent text-cyber-bg hover:opacity-90"
      : kind === "danger"
        ? "border-cyber-danger bg-cyber-danger text-cyber-bg hover:opacity-90"
        : "border-cyber-border bg-cyber-panel text-cyber-accent hover:border-cyber-accent/50 hover:bg-cyber-accent/10";
  return (
    <button
      type={type}
      onClick={onClick}
      className={cx("rounded-md border px-3 py-1.5 text-xs font-semibold transition-colors", classes, className)}
    >
      {children}
    </button>
  );
}

export function TextInput(props: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
  type?: "text" | "password";
}) {
  const { value, onChange, placeholder, className, type = "text" } = props;
  return (
    <input
      type={type}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      placeholder={placeholder}
      className={cx(
        "w-full rounded-md border border-cyber-border bg-cyber-panel px-3 py-2 text-xs text-cyber-text outline-none ring-cyber-accent/40 focus:ring",
        className
      )}
    />
  );
}

export function SelectInput(props: { value: string; onChange: (value: string) => void; options: string[]; className?: string }) {
  const { value, onChange, options, className } = props;
  return (
    <select
      value={value}
      onChange={(event) => onChange(event.target.value)}
      className={cx(
        "w-full rounded-md border border-cyber-border bg-cyber-panel px-3 py-2 text-xs text-cyber-text outline-none ring-cyber-accent/40 focus:ring",
        className
      )}
    >
      {options.map((item) => (
        <option key={item} value={item}>
          {item}
        </option>
      ))}
    </select>
  );
}

export function Badge(props: PropsWithChildren<{ tone?: "default" | "success" | "warning" | "critical" }>) {
  const { tone = "default", children } = props;
  const cls =
    tone === "success"
      ? "bg-cyber-success/15 text-cyber-success border-cyber-success/30"
      : tone === "warning"
        ? "bg-cyber-warning/15 text-cyber-warning border-cyber-warning/40"
        : tone === "critical"
          ? "bg-cyber-danger/15 text-cyber-danger border-cyber-danger/35"
          : "bg-cyber-panel text-cyber-muted border-cyber-border";
  return <span className={cx("rounded-md border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.08em]", cls)}>{children}</span>;
}
