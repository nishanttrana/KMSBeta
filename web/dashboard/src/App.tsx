import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import type { FeatureKey } from "./config/tabs";
import { isSystemAdminSession } from "./config/moduleRegistry";
import { BrandedLoadingOverlay, InitialLoadingScreen } from "./components/BrandedLoadingOverlay";
import { LoginScreen } from "./components/LoginScreen";
import VectaDashboardV3 from "./components/VectaDashboardV3";
import { clearSession, getSession, loadUIAuthConfig, refreshSession, saveSession, type AuthSession } from "./lib/auth";
import { getAuthSystemHealth, type AuthSystemHealthSnapshot } from "./lib/authAdmin";
import { enabledFeatures, loadDeploymentConfig } from "./lib/deployment";
import { mapToLiveEvent, parseWSMessage, wsBaseURL } from "./lib/liveFeed";
import { getUnreadAlertCounts } from "./lib/reporting";
import { getGlobalInFlightRequestCount, subscribeGlobalInFlightRequestCount } from "./lib/serviceApi";
import { useLiveStore } from "./store/live";

const FEATURE_KEYS: FeatureKey[] = [
  "secrets",
  "certs",
  "governance",
  "cloud_byok",
  "hyok_proxy",
  "kmip_server",
  "qkd_interface",
  "ekm_database",
  "payment_crypto",
  "compliance_dashboard",
  "sbom_cbom",
  "reporting_alerting",
  "ai_llm",
  "pqc_migration",
  "crypto_discovery",
  "mpc_engine",
  "data_protection",
  "clustering",
  "hsm_hardware",
  "hsm_software"
];

const FEATURE_DEPENDENCIES: Partial<Record<FeatureKey, string[]>> = {
  secrets: ["kms-secrets"],
  certs: ["kms-certs"],
  governance: ["kms-governance"],
  cloud_byok: ["kms-cloud"],
  hyok_proxy: ["kms-hyok-proxy"],
  kmip_server: ["kms-kmip"],
  qkd_interface: ["kms-qkd"],
  ekm_database: ["kms-ekm"],
  payment_crypto: ["kms-payment"],
  compliance_dashboard: ["kms-compliance"],
  sbom_cbom: ["kms-sbom"],
  reporting_alerting: ["kms-reporting"],
  ai_llm: ["kms-ai"],
  pqc_migration: ["kms-pqc"],
  crypto_discovery: ["kms-discovery"],
  mpc_engine: ["kms-mpc"],
  data_protection: ["kms-dataprotect"],
  clustering: ["cluster-manager", "kms-cluster-manager", "etcd"],
  hsm_hardware: ["hsm-connector", "kms-hsm-connector"],
  hsm_software: ["kms-software-vault"]
};

const FEATURE_ALIAS: Record<string, FeatureKey> = {
  byok: "cloud_byok",
  hyok: "hyok_proxy",
  kmip: "kmip_server",
  qkd: "qkd_interface",
  ekm: "ekm_database",
  payment: "payment_crypto",
  compliance: "compliance_dashboard",
  sbom: "sbom_cbom",
  cbom: "sbom_cbom",
  alerts: "reporting_alerting",
  reporting: "reporting_alerting",
  dataprotect: "data_protection",
  data_protect: "data_protection",
  data_encryption: "data_protection",
  mpc: "mpc_engine",
  cluster: "clustering",
  hsm: "hsm_software",
  hsm_hw: "hsm_hardware",
  hsm_sw: "hsm_software"
};

const ENFORCE_RUNTIME_FEATURE_FILTER =
  String(import.meta.env.VITE_ENFORCE_RUNTIME_FEATURE_FILTER || "")
    .trim()
    .toLowerCase() === "true";
const GLOBAL_LOADING_SHOW_DELAY_MS = 650;
const GLOBAL_LOADING_MIN_VISIBLE_MS = 260;

type FeaturePermissionScope = {
  hasRules: boolean;
  hasAllowRules: boolean;
  allowAll: boolean;
  denyAll: boolean;
  allow: Set<FeatureKey>;
  deny: Set<FeatureKey>;
};

function normalizeFeatureToken(raw: string): FeatureKey | null {
  const normalized = String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  if (!normalized) {
    return null;
  }
  if ((FEATURE_KEYS as string[]).includes(normalized)) {
    return normalized as FeatureKey;
  }
  return FEATURE_ALIAS[normalized] || null;
}

function parseFeaturePermissionScope(session: AuthSession | null): FeaturePermissionScope {
  const scope: FeaturePermissionScope = {
    hasRules: false,
    hasAllowRules: false,
    allowAll: false,
    denyAll: false,
    allow: new Set<FeatureKey>(),
    deny: new Set<FeatureKey>()
  };

  const permissions = Array.isArray(session?.permissions) ? session.permissions : [];
  permissions.forEach((rawPermission) => {
    const permission = String(rawPermission || "").trim().toLowerCase();
    if (!permission) {
      return;
    }
    if (permission === "*") {
      scope.hasRules = true;
      scope.hasAllowRules = true;
      scope.allowAll = true;
      return;
    }
    if (permission === "feature.*" || permission === "feature:*" || permission === "feature.all") {
      scope.hasRules = true;
      scope.hasAllowRules = true;
      scope.allowAll = true;
      return;
    }
    if (
      permission === "feature.deny.*" ||
      permission === "feature:*:deny" ||
      permission === "feature.all.deny" ||
      permission === "deny.feature.*"
    ) {
      scope.hasRules = true;
      scope.denyAll = true;
      return;
    }

    if (permission.startsWith("feature.")) {
      const segments = permission.split(".");
      const feature = normalizeFeatureToken(segments[1] || "");
      if (!feature) {
        return;
      }
      scope.hasRules = true;
      if (segments.includes("deny")) {
        scope.deny.add(feature);
      } else {
        scope.allow.add(feature);
        scope.hasAllowRules = true;
      }
      return;
    }
    if (permission.startsWith("feature:")) {
      const segments = permission.split(":");
      const feature = normalizeFeatureToken(segments[1] || "");
      if (!feature) {
        return;
      }
      const action = String(segments[2] || "").trim().toLowerCase();
      scope.hasRules = true;
      if (action === "deny" || action === "blocked" || action === "forbid") {
        scope.deny.add(feature);
      } else {
        scope.allow.add(feature);
        scope.hasAllowRules = true;
      }
      return;
    }
    if (permission.startsWith("deny.feature.")) {
      const feature = normalizeFeatureToken(permission.slice("deny.feature.".length));
      if (!feature) {
        return;
      }
      scope.hasRules = true;
      scope.deny.add(feature);
      return;
    }
    if (permission.startsWith("nofeature.")) {
      const feature = normalizeFeatureToken(permission.slice("nofeature.".length));
      if (!feature) {
        return;
      }
      scope.hasRules = true;
      scope.deny.add(feature);
      return;
    }
    if (permission.startsWith("domain.feature.")) {
      const segments = permission.split(".");
      const feature = normalizeFeatureToken(segments[2] || "");
      if (!feature) {
        return;
      }
      scope.hasRules = true;
      if (segments.includes("deny")) {
        scope.deny.add(feature);
      } else {
        scope.allow.add(feature);
        scope.hasAllowRules = true;
      }
    }
  });

  return scope;
}

function normalizeServiceName(raw: string): string {
  return String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
}

function isServiceAvailable(status: string): boolean {
  const normalized = String(status || "").trim().toLowerCase();
  return normalized === "running" || normalized === "degraded";
}

function deriveRuntimeFeatures(
  configuredFeatures: Set<FeatureKey>,
  snapshot?: AuthSystemHealthSnapshot
): Set<FeatureKey> {
  if (!ENFORCE_RUNTIME_FEATURE_FILTER) {
    return new Set(configuredFeatures);
  }
  const services = Array.isArray(snapshot?.services) ? snapshot.services : [];
  if (!services.length) {
    return new Set(configuredFeatures);
  }
  const availableServices = new Set(
    services
      .filter((item) => isServiceAvailable(String(item?.status || "")))
      .map((item) => normalizeServiceName(String(item?.name || "")))
      .filter(Boolean)
  );
  if (availableServices.size < 8) {
    // Incomplete health payload can hide modules by accident; keep configured
    // features visible unless runtime filtering is explicitly trusted.
    return new Set(configuredFeatures);
  }
  const out = new Set<FeatureKey>();
  configuredFeatures.forEach((feature) => {
    const deps = FEATURE_DEPENDENCIES[feature];
    if (!Array.isArray(deps) || deps.length === 0) {
      out.add(feature);
      return;
    }
    if (deps.some((dep) => availableServices.has(normalizeServiceName(dep)))) {
      out.add(feature);
    }
  });
  return out;
}

function applyPermissionScope(features: Set<FeatureKey>, session: AuthSession | null): Set<FeatureKey> {
  if (isSystemAdminSession(session)) {
    return new Set(features);
  }
  const scope = parseFeaturePermissionScope(session);
  if (!scope.hasRules) {
    return new Set(features);
  }
  if (scope.denyAll) {
    return new Set<FeatureKey>();
  }

  const filtered = new Set<FeatureKey>();
  features.forEach((feature) => {
    if (scope.deny.has(feature)) {
      return;
    }
    if (!scope.hasAllowRules || scope.allowAll || scope.allow.has(feature)) {
      filtered.add(feature);
    }
  });
  return filtered;
}

export default function App() {
  const [session, setSession] = useState<AuthSession | null>(getSession());
  const [unreadAlerts, setUnreadAlerts] = useState(0);
  const [inFlightRequests, setInFlightRequests] = useState<number>(getGlobalInFlightRequestCount());
  const [showBrandedLoader, setShowBrandedLoader] = useState(false);
  const visibleSinceRef = useRef<number>(0);
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
  const systemHealthQuery = useQuery({
    queryKey: ["auth-system-health", session?.mode, session?.token],
    enabled: Boolean(session && session.mode === "backend"),
    queryFn: async () => {
      if (!session) {
        return undefined;
      }
      return getAuthSystemHealth(session, { skipGlobalLoading: true });
    },
    staleTime: 10_000,
    refetchInterval: 15_000
  });

  const configuredFeatureSet = useMemo(() => enabledFeatures(deploymentQuery.data ?? {}), [deploymentQuery.data]);
  const runtimeFeatureSet = useMemo(
    () => deriveRuntimeFeatures(configuredFeatureSet, systemHealthQuery.data),
    [configuredFeatureSet, systemHealthQuery.data]
  );
  const featureSet = useMemo(
    () => applyPermissionScope(runtimeFeatureSet, session),
    [runtimeFeatureSet, session]
  );

  useEffect(() => {
    return subscribeGlobalInFlightRequestCount((count) => {
      setInFlightRequests(count);
    });
  }, []);

  useEffect(() => {
    let timer: number | undefined;
    if (inFlightRequests > 0) {
      if (!showBrandedLoader) {
        timer = window.setTimeout(() => {
          visibleSinceRef.current = Date.now();
          setShowBrandedLoader(true);
        }, GLOBAL_LOADING_SHOW_DELAY_MS);
      }
      return () => {
        if (timer) {
          window.clearTimeout(timer);
        }
      };
    }

    if (showBrandedLoader) {
      const elapsed = Date.now() - visibleSinceRef.current;
      const waitMs = Math.max(0, GLOBAL_LOADING_MIN_VISIBLE_MS - elapsed);
      timer = window.setTimeout(() => {
        setShowBrandedLoader(false);
      }, waitMs);
    }

    return () => {
      if (timer) {
        window.clearTimeout(timer);
      }
    };
  }, [inFlightRequests, showBrandedLoader]);

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
        const counts = await getUnreadAlertCounts(session, { skipGlobalLoading: true });
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
  }, [session]);

  useEffect(() => {
    if (!session) {
      return;
    }
    const idleMinutes = Number(session.idleTimeoutMinutes || 0);
    if (!Number.isFinite(idleMinutes) || idleMinutes <= 0) {
      return;
    }
    const timeoutMs = Math.max(60_000, Math.trunc(idleMinutes * 60_000));
    let timer: number | undefined;
    const resetTimer = () => {
      if (timer) {
        window.clearTimeout(timer);
      }
      timer = window.setTimeout(() => {
        clearSession();
        setSession(null);
      }, timeoutMs);
    };
    const events: Array<keyof WindowEventMap> = ["mousemove", "mousedown", "keydown", "scroll", "touchstart"];
    events.forEach((eventName) => {
      window.addEventListener(eventName, resetTimer, { passive: true });
    });
    resetTimer();
    return () => {
      if (timer) {
        window.clearTimeout(timer);
      }
      events.forEach((eventName) => {
        window.removeEventListener(eventName, resetTimer);
      });
    };
  }, [session]);

  if (!uiAuthQuery.data) {
    return <InitialLoadingScreen />;
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
      <BrandedLoadingOverlay visible={showBrandedLoader} />
    </main>
  );
}
