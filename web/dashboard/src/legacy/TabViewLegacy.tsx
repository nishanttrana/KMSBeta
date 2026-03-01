import { useEffect, useMemo, useState } from "react";
import type { AuthSession } from "../lib/auth";
import type { FeatureKey, TabId } from "../config/tabs";
import type { LiveEvent } from "../store/live";
import { listKeys, type KeyItem } from "../lib/keycore";
import { listReportingAlerts, getReportingAlertStats } from "../lib/reporting";
import { listGovernanceRequests, getGovernanceSystemState } from "../lib/governance";
import { listComplianceFrameworkCatalog } from "../lib/compliance";

type Props = {
  tabId: TabId;
  alerts: LiveEvent[];
  audit: LiveEvent[];
  enabledFeatures: Set<FeatureKey>;
  session: AuthSession;
};

type LegacySnapshot = {
  keys: KeyItem[];
  alerts: Array<Record<string, unknown>>;
  approvals: Array<Record<string, unknown>>;
  compliance: Array<Record<string, unknown>>;
  systemState: Record<string, unknown> | null;
};

const tabTitles: Record<string, string> = {
  dashboard: "Dashboard",
  keys: "Key Management",
  crypto_console: "Crypto Console",
  vault: "Secret Vault",
  certificates: "Certificates / PKI",
  tokenize_mask: "Token / Mask / Redact",
  payment: "Payment Policy",
  byok: "Cloud BYOK",
  hyok: "HYOK",
  cloudctl: "Cloud Key Control",
  ekm: "Enterprise Key Management",
  kmip: "KMIP",
  hsm_primus: "HSM",
  qkd: "QKD Interface",
  mpc: "MPC Engine",
  cluster: "Cluster",
  approvals: "Approvals",
  alert_center: "Alert Center",
  audit_log: "Audit Log",
  compliance: "Compliance",
  sbom_cbom: "SBOM / CBOM",
  pkcs11_jca: "PKCS#11 / JCA",
  administration: "Administration"
};

export function TabView(props: Props) {
  const { tabId, session, alerts, audit, enabledFeatures } = props;
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [snapshot, setSnapshot] = useState<LegacySnapshot>({
    keys: [],
    alerts: [],
    approvals: [],
    compliance: [],
    systemState: null
  });

  useEffect(() => {
    let cancelled = false;
    if (!session?.token) {
      setSnapshot({ keys: [], alerts: [], approvals: [], compliance: [], systemState: null });
      return;
    }
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        const [keys, alertRows, requestRows, frameworks, systemState] = await Promise.all([
          listKeys(session, { includeDeleted: false, limit: 50 }),
          listReportingAlerts(session, { limit: 30 }),
          listGovernanceRequests(session, { status: "pending" }),
          listComplianceFrameworkCatalog(session),
          getGovernanceSystemState(session)
        ]);
        if (cancelled) {
          return;
        }
        setSnapshot({
          keys,
          alerts: alertRows as Array<Record<string, unknown>>,
          approvals: requestRows as Array<Record<string, unknown>>,
          compliance: frameworks as Array<Record<string, unknown>>,
          systemState: (systemState?.state as Record<string, unknown>) || null
        });
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Legacy tab load failed");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [session, tabId]);

  const summary = useMemo(() => {
    return {
      features: Array.from(enabledFeatures).sort(),
      liveAlerts: alerts.length,
      liveAudit: audit.length,
      loadedKeys: snapshot.keys.length,
      pendingApprovals: snapshot.approvals.length
    };
  }, [alerts.length, audit.length, enabledFeatures, snapshot.approvals.length, snapshot.keys.length]);

  const title = tabTitles[tabId] || tabId;
  const liveCard = (
    <div style={{ border: "1px solid #1f3047", borderRadius: 12, padding: 12, background: "#0f1f37" }}>
      <div style={{ fontSize: 12, color: "#7f97b8", textTransform: "uppercase", letterSpacing: 0.8 }}>Legacy Compatibility Snapshot</div>
      <div style={{ marginTop: 8, fontSize: 20, fontWeight: 700, color: "#e8f2ff" }}>{title}</div>
      <div style={{ marginTop: 8, fontSize: 12, color: "#9cb2cf" }}>
        {loading ? "Loading data from typed clients..." : "Loaded through typed client modules (no direct serviceRequest usage)."}
      </div>
      {error ? <div style={{ marginTop: 10, color: "#ff6a6a", fontSize: 12 }}>{error}</div> : null}
    </div>
  );

  return (
    <div style={{ display: "grid", gap: 12 }}>
      {liveCard}
      <div style={{ border: "1px solid #1f3047", borderRadius: 12, padding: 12, background: "#0b1730" }}>
        <div style={{ fontSize: 12, color: "#7f97b8", textTransform: "uppercase", letterSpacing: 0.8 }}>Summary</div>
        <pre style={{ marginTop: 8, fontSize: 12, color: "#c6d6eb", overflow: "auto" }}>{JSON.stringify(summary, null, 2)}</pre>
      </div>
      <div style={{ border: "1px solid #1f3047", borderRadius: 12, padding: 12, background: "#0b1730" }}>
        <div style={{ fontSize: 12, color: "#7f97b8", textTransform: "uppercase", letterSpacing: 0.8 }}>Loaded Data</div>
        <pre style={{ marginTop: 8, fontSize: 12, color: "#c6d6eb", overflow: "auto" }}>
          {JSON.stringify(
            {
              alerts: snapshot.alerts.slice(0, 5),
              approvals: snapshot.approvals.slice(0, 5),
              compliance: snapshot.compliance.slice(0, 5),
              systemState: snapshot.systemState
            },
            null,
            2
          )}
        </pre>
      </div>
      <div style={{ border: "1px solid #1f3047", borderRadius: 12, padding: 12, background: "#0b1730" }}>
        <div style={{ fontSize: 12, color: "#7f97b8", textTransform: "uppercase", letterSpacing: 0.8 }}>Alert Stats</div>
        <LegacyAlertStats session={session} />
      </div>
    </div>
  );
}

function LegacyAlertStats({ session }: { session: AuthSession }) {
  const [stats, setStats] = useState<Record<string, unknown>>({});
  const [err, setErr] = useState("");

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const out = await getReportingAlertStats(session);
        if (!cancelled) {
          setStats((out || {}) as Record<string, unknown>);
        }
      } catch (error) {
        if (!cancelled) {
          setErr(error instanceof Error ? error.message : "Failed to load alert stats");
        }
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [session]);

  if (err) {
    return <div style={{ marginTop: 8, color: "#ff6a6a", fontSize: 12 }}>{err}</div>;
  }

  return <pre style={{ marginTop: 8, fontSize: 12, color: "#c6d6eb", overflow: "auto" }}>{JSON.stringify(stats, null, 2)}</pre>;
}
