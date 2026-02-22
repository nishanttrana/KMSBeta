import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { LoginScreen } from "./components/LoginScreen";
import VectaDashboardV3 from "./components/VectaDashboardV3";
import { clearSession, getSession, loadUIAuthConfig, refreshSession, saveSession } from "./lib/auth";
import { enabledFeatures, loadDeploymentConfig } from "./lib/deployment";
import { mapToLiveEvent, parseWSMessage, wsBaseURL } from "./lib/liveFeed";
import { getUnreadAlertCounts } from "./lib/reporting";
import { useLiveStore } from "./store/live";

export default function App() {
  const [session, setSession] = useState(getSession());
  const [unreadAlerts, setUnreadAlerts] = useState(0);
  const { alerts, audit, pushAlert, pushAudit } = useLiveStore();

  const deploymentQuery = useQuery({
    queryKey: ["deployment-config"],
    queryFn: loadDeploymentConfig,
    staleTime: 15_000
  });
  const uiAuthQuery = useQuery({
    queryKey: ["ui-auth-config"],
    queryFn: loadUIAuthConfig,
    staleTime: 15_000
  });

  const featureSet = useMemo(() => enabledFeatures(deploymentQuery.data ?? {}), [deploymentQuery.data]);

  useEffect(() => {
    if (!session) {
      return;
    }
    const alertsURL = import.meta.env.VITE_WS_ALERTS_URL || wsBaseURL("/alerts/stream");
    const auditURL = import.meta.env.VITE_WS_AUDIT_URL || wsBaseURL("/audit/stream");

    const alertSocket = new WebSocket(alertsURL);
    const auditSocket = new WebSocket(auditURL);
    let simulation: number | undefined;

    alertSocket.onmessage = (event) => {
      const payload = parseWSMessage(event.data);
      if (!payload) {
        return;
      }
      pushAlert(mapToLiveEvent(payload, "alert.stream"));
    };
    auditSocket.onmessage = (event) => {
      const payload = parseWSMessage(event.data);
      if (!payload) {
        return;
      }
      pushAudit(mapToLiveEvent(payload, "audit.stream"));
    };

    const fallback = () => {
      simulation = window.setInterval(() => {
        pushAudit(
          mapToLiveEvent(
            {
              event: "audit.dashboard.heartbeat",
              message: "Live stream heartbeat from UI fallback channel",
              severity: "info",
              source: "ui",
              timestamp: new Date().toISOString()
            },
            "audit.stream"
          )
        );
      }, 20_000);
    };

    alertSocket.onerror = fallback;
    auditSocket.onerror = fallback;

    return () => {
      alertSocket.close();
      auditSocket.close();
      if (simulation) {
        window.clearInterval(simulation);
      }
    };
  }, [session, pushAlert, pushAudit]);

  useEffect(() => {
    if (!session) {
      setUnreadAlerts(0);
      return;
    }
    let cancelled = false;
    const refreshUnread = async () => {
      try {
        const counts = await getUnreadAlertCounts(session);
        if (cancelled) {
          return;
        }
        const total = Object.values(counts || {}).reduce((sum, value) => sum + Math.max(0, Number(value || 0)), 0);
        setUnreadAlerts(total);
      } catch {
        if (!cancelled) {
          setUnreadAlerts(0);
        }
      }
    };
    void refreshUnread();
    const id = window.setInterval(() => {
      void refreshUnread();
    }, 10_000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [session]);

  useEffect(() => {
    if (!session || session.mode !== "backend") {
      return;
    }
    let cancelled = false;
    let refreshing = false;

    const maybeRefresh = async () => {
      if (refreshing) {
        return;
      }
      const expRaw = String(session.expiresAt || "").trim();
      if (expRaw) {
        const expMs = new Date(expRaw).getTime();
        if (Number.isFinite(expMs)) {
          const remaining = expMs - Date.now();
          if (remaining > 3 * 60_000) {
            return;
          }
        }
      }
      refreshing = true;
      try {
        const next = await refreshSession(session);
        if (cancelled) {
          return;
        }
        saveSession(next);
        setSession((prev) => {
          if (!prev) {
            return prev;
          }
          if (prev.token === next.token && prev.expiresAt === next.expiresAt) {
            return prev;
          }
          return next;
        });
      } catch {
        if (!cancelled) {
          clearSession();
          setSession(null);
        }
      } finally {
        refreshing = false;
      }
    };

    const expKnown = String(session.expiresAt || "").trim().length > 0;
    const intervalMs = expKnown ? 60_000 : 4 * 60_000;
    const id = window.setInterval(() => {
      void maybeRefresh();
    }, intervalMs);
    const initial = window.setTimeout(() => {
      void maybeRefresh();
    }, expKnown ? 15_000 : 60_000);

    return () => {
      cancelled = true;
      window.clearInterval(id);
      window.clearTimeout(initial);
    };
  }, [session?.mode, session?.token, session?.expiresAt]);

  if (!uiAuthQuery.data) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-cyber-bg text-cyber-text">
        Loading authentication profile...
      </main>
    );
  }

  if (!session) {
    return (
      <LoginScreen
        config={uiAuthQuery.data}
        onAuthenticated={(nextSession) => {
          saveSession(nextSession);
          setSession(nextSession);
        }}
      />
    );
  }

  return (
    <main className="min-h-screen bg-cyber-bg text-cyber-text">
      <VectaDashboardV3
        session={session}
        enabledFeatures={featureSet}
        alerts={alerts}
        audit={audit}
        unreadAlerts={unreadAlerts}
        markAlertsRead={() => undefined}
        onLogout={() => {
          clearSession();
          setSession(null);
        }}
      />
    </main>
  );
}
