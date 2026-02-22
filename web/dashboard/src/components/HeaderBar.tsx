import { Bell } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { LiveEvent } from "../store/live";
import { Badge, Button, cx } from "./primitives";

type HeaderBarProps = {
  unreadAlerts: number;
  latestAlerts: LiveEvent[];
  markAlertsRead: () => void;
  activeTitle: string;
  tenantId: string;
  onLogout: () => void;
};

const severityTone = (severity: LiveEvent["severity"]): "critical" | "warning" | "success" => {
  if (severity === "critical") {
    return "critical";
  }
  if (severity === "warning") {
    return "warning";
  }
  return "success";
};

export function HeaderBar(props: HeaderBarProps) {
  const { unreadAlerts, latestAlerts, markAlertsRead, activeTitle, tenantId, onLogout } = props;
  const [openBell, setOpenBell] = useState(false);
  const [clock, setClock] = useState(() => new Date());
  const visibleAlerts = useMemo(() => latestAlerts.slice(0, 6), [latestAlerts]);

  useEffect(() => {
    const timer = window.setInterval(() => setClock(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const avatar = tenantId.slice(0, 2).toUpperCase();

  return (
    <header className="relative flex h-11 items-center justify-between border-b border-cyber-border bg-cyber-panel/95 px-5">
      <h2 className="font-heading text-lg font-semibold tracking-tight text-cyber-text">{activeTitle}</h2>

      <div className="flex items-center gap-2">
        <Badge tone="success">FIPS STRICT</Badge>
        <span className="hidden rounded-md border border-cyber-border bg-cyber-elevated px-2 py-1 font-mono text-xs text-cyber-accent md:inline-flex">
          {clock.toLocaleTimeString()}
        </span>

        <div className="relative">
          <button
            onClick={() => {
              const next = !openBell;
              setOpenBell(next);
              if (next) {
                markAlertsRead();
              }
            }}
            className={cx("relative rounded-md border border-cyber-border bg-cyber-elevated p-1.5 text-cyber-text transition-colors", openBell && "border-cyber-accent/60 bg-cyber-accent/10")}
            aria-label="Open alert feed"
          >
            <Bell size={15} />
            {unreadAlerts > 0 ? (
              <span className="absolute -right-1 -top-1 rounded-full bg-cyber-danger px-1 text-[10px] font-semibold text-white">
                {Math.min(unreadAlerts, 99)}
              </span>
            ) : null}
          </button>
          {openBell ? (
            <div className="absolute right-0 z-30 mt-2 w-[380px] rounded-xl border border-cyber-border bg-cyber-panel p-3 shadow-2xl shadow-black/40">
              <div className="mb-2 flex items-center justify-between">
                <h3 className="font-heading text-base text-cyber-text">Live Alerts</h3>
                <Badge tone={unreadAlerts > 0 ? "critical" : "success"}>{unreadAlerts > 0 ? `${unreadAlerts} unread` : "Synced"}</Badge>
              </div>
              <div className="max-h-80 space-y-2 overflow-auto pr-1">
                {visibleAlerts.length === 0 ? (
                  <p className="rounded-lg border border-cyber-border bg-cyber-elevated p-3 text-sm text-cyber-muted">No alerts yet.</p>
                ) : (
                  visibleAlerts.map((alert) => (
                    <div key={alert.id} className="rounded-lg border border-cyber-border bg-cyber-elevated p-3">
                      <div className="mb-1 flex items-center gap-2">
                        <Badge tone={severityTone(alert.severity)}>{alert.severity}</Badge>
                        <span className="text-xs uppercase tracking-wide text-cyber-muted">{alert.topic}</span>
                      </div>
                      <p className="text-sm text-cyber-text">{alert.message}</p>
                      <p className="mt-1 text-xs text-cyber-muted">{new Date(alert.timestamp).toLocaleString()}</p>
                    </div>
                  ))
                )}
              </div>
            </div>
          ) : null}
        </div>

        <span className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-cyber-accent/40 bg-cyber-accent/10 text-xs font-semibold text-cyber-accent">{avatar}</span>
        <Button kind="secondary" className="px-2 py-1 text-xs" onClick={onLogout}>
          Logout
        </Button>
      </div>
    </header>
  );
}
