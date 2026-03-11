import type { PropsWithChildren, ReactNode } from "react";

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

export function Button(
  props: PropsWithChildren<{
    onClick?: (() => void) | undefined;
    kind?: "primary" | "secondary" | "danger" | undefined;
    className?: string | undefined;
    type?: "button" | "submit" | undefined;
  }>
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
