// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Cloud,
  HardDrive,
  KeyRound,
  Link2,
  Package,
  Play,
  RefreshCcw,
  Server,
  ShieldAlert,
  Wrench,
  Zap
} from "lucide-react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar as RBar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  RadialBarChart,
  RadialBar,
  PieChart,
  Pie,
  Cell,
  Legend
} from "recharts";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Chk, Inp, Modal, Sel, Stat, Tabs } from "../legacyPrimitives";
import {
  executePostureAction,
  getPostureDashboard,
  getPostureRisk,
  listPostureActions,
  listPostureFindings,
  listPostureRiskHistory,
  runPostureScan,
  updatePostureFindingStatus
} from "../../../lib/posture";
import { getAuthRESTClientSecuritySummary, getAuthSCIMSummary } from "../../../lib/authAdmin";
import { getAutokeySummary } from "../../../lib/autokey";
import { getKeyAccessSummary } from "../../../lib/keyaccess";
import { getMPCOverview } from "../../../lib/mpc";
import { getSigningSummary } from "../../../lib/signing";
import { getWorkloadIdentitySummary } from "../../../lib/workloadIdentity";

// ── Constants & Helpers ─────────────────────────────────────────

const DOMAIN_META: Record<string, { label: string; icon: any }> = {
  byok: { label: "BYOK", icon: Cloud },
  hyok: { label: "HYOK", icon: Link2 },
  ekm: { label: "EKM", icon: Server },
  kmip: { label: "KMIP", icon: KeyRound },
  bitlocker: { label: "BitLocker", icon: HardDrive },
  sdk: { label: "SDK / Wrapper", icon: Package }
};

function toNum(v: any): number { const n = Number(v); return Number.isFinite(n) ? n : 0; }
function pct(n: number): number { if (!Number.isFinite(n) || n <= 0) return 0; if (n >= 1) return Math.min(100, n); return Math.min(100, n * 100); }

function severityTone(severity: string) {
  const v = String(severity || "").toLowerCase();
  if (v === "critical" || v === "high") return "red";
  if (v === "warning" || v === "medium") return "amber";
  return "green";
}

function actionStatusTone(status: string) {
  const v = String(status || "").toLowerCase();
  if (v === "failed" || v === "error") return "red";
  if (v === "executed" || v === "done" || v === "completed") return "green";
  if (v === "approved" || v === "pending" || v === "queued" || v === "suggested") return "amber";
  return "blue";
}

function healthTone(status: string) {
  const v = String(status || "").toLowerCase();
  if (v === "failing" || v === "failed" || v === "critical") return "red";
  if (v === "stale" || v === "warning" || v === "degraded") return "amber";
  if (v === "healthy" || v === "verified" || v === "ok") return "green";
  return "blue";
}

function riskTone(score: number): "green" | "amber" | "red" {
  if (score >= 75) return "red";
  if (score >= 40) return "amber";
  return "green";
}

function fmtTS(value: any) {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return dt.toLocaleString();
}

function shortTS(value: any) {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return `${dt.getMonth() + 1}/${dt.getDate()} ${dt.getHours()}:${String(dt.getMinutes()).padStart(2, "0")}`;
}

function extractDomainMetrics(topSignals: any) {
  const root = topSignals && typeof topSignals === "object" ? topSignals : {};
  const nested = root.domain_metrics && typeof root.domain_metrics === "object" ? root.domain_metrics : {};
  const keys = ["byok", "hyok", "ekm", "kmip", "bitlocker", "sdk"];
  return keys.map((key) => {
    const item = nested[key] && typeof nested[key] === "object" ? nested[key] : {};
    const events = toNum(item.events_24h ?? root[`${key}_events_24h`]);
    const failures = toNum(item.failures_24h ?? root[`${key}_failures_24h`]);
    const rate = pct(item.failure_rate_24h ?? (events > 0 ? failures / events : 0));
    const latency = toNum(item.latency_avg_ms_24h);
    const interop = key === "kmip" ? toNum(item.interop_failed_24h ?? root.kmip_interop_failed_24h) : 0;
    const receiptMissing = key === "sdk" ? toNum(item.receipt_missing_24h ?? root.sdk_receipt_missing_24h) : 0;
    return { key, label: DOMAIN_META[key]?.label || key.toUpperCase(), icon: DOMAIN_META[key]?.icon || Activity, events, failures, rate, latency, interop, receiptMissing };
  });
}

function slaBadge(slaDueAt: any) {
  const raw = String(slaDueAt || "").trim();
  if (!raw) return null;
  const due = new Date(raw);
  if (Number.isNaN(due.getTime())) return null;
  const now = Date.now();
  const diff = due.getTime() - now;
  if (diff < 0) return { label: "Overdue", tone: "red" };
  if (diff < 86400000) return { label: "Due soon", tone: "amber" };
  return { label: "On track", tone: "green" };
}

// ── Chart Tooltips ──────────────────────────────────────────────

const ChartTooltip = ({ containerStyle, children }: any) => (
  <div style={{ background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 8, padding: "8px 12px", fontSize: 10, color: C.text, boxShadow: "0 4px 20px rgba(0,0,0,.5)", ...containerStyle }}>
    {children}
  </div>
);

const RiskTrendTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return <ChartTooltip><div style={{ fontWeight: 700, marginBottom: 4, color: C.accent }}>{label}</div><div>Risk Score: <span style={{ fontWeight: 700, color: C.text }}>{payload[0]?.value}</span></div></ChartTooltip>;
};

const DomainBarTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return <ChartTooltip><div style={{ fontWeight: 700, marginBottom: 4, color: C.accent }}>{label}</div>{payload.map((entry: any) => <div key={entry.dataKey} style={{ color: entry.color }}>{entry.name}: <span style={{ fontWeight: 700, color: C.text }}>{entry.value}</span></div>)}</ChartTooltip>;
};

const HistogramTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return <ChartTooltip><div style={{ fontWeight: 700, marginBottom: 4, color: C.accent }}>Score Range: {label}</div><div>Findings: <span style={{ fontWeight: 700, color: C.text }}>{payload[0]?.value}</span></div></ChartTooltip>;
};

// ── Component ───────────────────────────────────────────────────

export const PostureTab = ({ session, onToast }: any) => {
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [syncAudit, setSyncAudit] = useState(true);
  const [risk, setRisk] = useState<any>({});
  const [dashboard, setDashboard] = useState<any>({});
  const [history, setHistory] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [actions, setActions] = useState<any[]>([]);
  const [autokeySummary, setAutokeySummary] = useState<any>(null);
  const [workloadSummary, setWorkloadSummary] = useState<any>(null);
  const [scimSummary, setScimSummary] = useState<any>(null);
  const [restClientSecurity, setRestClientSecurity] = useState<any>(null);
  const [keyAccessSummary, setKeyAccessSummary] = useState<any>(null);
  const [signingSummary, setSigningSummary] = useState<any>(null);
  const [mpcOverview, setMpcOverview] = useState<any>(null);
  const [findingStatus, setFindingStatus] = useState("");
  const [findingSeverity, setFindingSeverity] = useState("");
  const [findingSearch, setFindingSearch] = useState("");
  const [findingEngine, setFindingEngine] = useState("");
  const [actionStatus, setActionStatus] = useState("");
  const [actionSearch, setActionSearch] = useState("");
  const [tab, setTab] = useState("Dashboard");
  const [mode, setMode] = useState("Executive");
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const [selectedAction, setSelectedAction] = useState<any>(null);

  // ── Data loading ──────────────────────────────────────────────

  const load = async (silent = false) => {
    if (!session?.token) {
      setRisk({}); setDashboard({}); setHistory([]); setFindings([]); setActions([]); setAutokeySummary(null); setWorkloadSummary(null); setScimSummary(null); setRestClientSecurity(null); setKeyAccessSummary(null); setSigningSummary(null); setMpcOverview(null);
      return;
    }
    if (!silent) setLoading(true);
    try {
      const [dash, latestRisk, riskHistory, findingRows, actionRows, autokeySummaryOut, workloadSummaryOut, scimSummaryOut, restClientSecurityOut, keyAccessSummaryOut, signingSummaryOut, mpcOverviewOut] = await Promise.all([
        getPostureDashboard(session),
        getPostureRisk(session),
        listPostureRiskHistory(session, 60),
        listPostureFindings(session, { limit: 300, status: findingStatus, severity: findingSeverity, engine: findingEngine }),
        listPostureActions(session, { limit: 300, status: actionStatus }),
        getAutokeySummary(session).catch(() => null),
        getWorkloadIdentitySummary(session).catch(() => null),
        getAuthSCIMSummary(session).catch(() => null),
        getAuthRESTClientSecuritySummary(session).catch(() => null),
        getKeyAccessSummary(session).catch(() => null),
        getSigningSummary(session).catch(() => null),
        getMPCOverview(session).catch(() => null)
      ]);
      setDashboard(dash || {});
      setRisk(latestRisk || dash?.risk || {});
      setHistory(Array.isArray(riskHistory) ? riskHistory : []);
      setFindings(Array.isArray(findingRows) ? findingRows : []);
      setActions(Array.isArray(actionRows) ? actionRows : []);
      setAutokeySummary(autokeySummaryOut || null);
      setWorkloadSummary(workloadSummaryOut || null);
      setScimSummary(scimSummaryOut || null);
      setRestClientSecurity(restClientSecurityOut || null);
      setKeyAccessSummary(keyAccessSummaryOut || null);
      setSigningSummary(signingSummaryOut || null);
      setMpcOverview(mpcOverviewOut || null);
      if (!silent) onToast?.("Posture view refreshed.");
    } catch (error) {
      onToast?.(`Posture load failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    void load(true);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session?.token, session?.tenantId, findingStatus, findingSeverity, findingEngine, actionStatus]);

  // ── Action handlers ───────────────────────────────────────────

  const executeAction = async (action: any) => {
    const id = String(action?.id || "").trim();
    if (!id) return;
    try {
      await executePostureAction(session, id, { actor: String(session?.username || "dashboard") });
      onToast?.("Runbook action executed.");
      setSelectedAction(null);
      await load(true);
    } catch (error) {
      onToast?.(`Action execute failed: ${errMsg(error)}`);
    }
  };

  const patchFinding = async (finding: any, status: "acknowledged" | "resolved" | "reopened") => {
    const id = String(finding?.id || "").trim();
    if (!id) return;
    try {
      await updatePostureFindingStatus(session, id, status);
      onToast?.(`Finding marked ${status}.`);
      setSelectedFinding(null);
      await load(true);
    } catch (error) {
      onToast?.(`Finding update failed: ${errMsg(error)}`);
    }
  };

  const runScan = async () => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    try {
      setRunning(true);
      const snap = await runPostureScan(session, syncAudit);
      setRisk(snap || {});
      onToast?.("Posture scan completed.");
      await load(true);
    } catch (error) {
      onToast?.(`Posture scan failed: ${errMsg(error)}`);
    } finally {
      setRunning(false);
    }
  };

  // ── Computed data ─────────────────────────────────────────────

  const filteredFindings = useMemo(() => {
    const q = String(findingSearch || "").trim().toLowerCase();
    const rows = Array.isArray(findings) ? findings : [];
    if (!q) return rows;
    return rows.filter((item: any) => [item?.title, item?.description, item?.finding_type, item?.engine].map((v) => String(v ?? "").toLowerCase()).join(" ").includes(q));
  }, [findings, findingSearch]);

  const visibleFindings = useMemo(() => filteredFindings.slice(0, 120), [filteredFindings]);
  const visibleActions = useMemo(() => {
    let items = Array.isArray(actions) ? actions : [];
    const q = actionSearch.trim().toLowerCase();
    if (q) items = items.filter((a: any) => [a?.action_type, a?.recommended_action, a?.result_message].map((v) => String(v ?? "").toLowerCase()).join(" ").includes(q));
    return items.slice(0, 120);
  }, [actions, actionSearch]);

  const domainMetrics = useMemo(() => extractDomainMetrics(risk?.top_signals), [risk?.top_signals]);
  const riskDrivers = useMemo(() => Array.isArray(dashboard?.risk_drivers?.drivers) ? dashboard.risk_drivers.drivers : [], [dashboard?.risk_drivers]);
  const cockpitGroups = useMemo(() => Array.isArray(dashboard?.remediation_cockpit) ? dashboard.remediation_cockpit : [], [dashboard?.remediation_cockpit]);
  const scenarioCards = useMemo(() => Array.isArray(dashboard?.scenario_simulator) ? dashboard.scenario_simulator : [], [dashboard?.scenario_simulator]);
  const validationBadges = useMemo(() => Array.isArray(dashboard?.validation_badges) ? dashboard.validation_badges : [], [dashboard?.validation_badges]);
  const blastHotspots = useMemo(() => Array.isArray(dashboard?.blast_radius) ? dashboard.blast_radius : [], [dashboard?.blast_radius]);
  const slaOverview = dashboard?.sla_overview || {};
  const workloadIdentityStatus = useMemo(() => {
    if (!workloadSummary) {
      return { tone: "blue", label: "Unavailable" };
    }
    if (!workloadSummary?.enabled) {
      return { tone: "amber", label: "Disabled" };
    }
    if (Number(workloadSummary?.expired_svid_count || 0) > 0 || Number(workloadSummary?.over_privileged_count || 0) > 0) {
      return { tone: "red", label: "Drift detected" };
    }
    if (Number(workloadSummary?.expiring_svid_count || 0) > 0) {
      return { tone: "amber", label: "Rotation due" };
    }
    return { tone: "green", label: "Healthy" };
  }, [workloadSummary]);

  const autokeyStatus = useMemo(() => {
    if (!autokeySummary) {
      return { label: "Unavailable", tone: "blue" };
    }
    if (!autokeySummary?.enabled) {
      return { label: "Disabled", tone: "amber" };
    }
    if (Number(autokeySummary?.failed_count || 0) > 0) {
      return { label: "Failures", tone: "red" };
    }
    if (Number(autokeySummary?.pending_approvals || 0) > 0 || Number(autokeySummary?.policy_mismatch_count || 0) > 0) {
      return { label: "Review", tone: "amber" };
    }
    return { label: "Aligned", tone: "green" };
  }, [autokeySummary]);

  const scimStatus = useMemo(() => {
    if (!scimSummary) {
      return { tone: "blue", label: "No SCIM data" };
    }
    if (!scimSummary?.enabled) {
      return { tone: "amber", label: "Disabled" };
    }
    if (!scimSummary?.token_configured) {
      return { tone: "amber", label: "Token missing" };
    }
    if (Number(scimSummary?.disabled_users || 0) > 0) {
      return { tone: "amber", label: "Disabled identities" };
    }
    return { tone: "green", label: "Provisioning active" };
  }, [scimSummary]);
  const restClientSecurityStatus = useMemo(() => {
    if (!restClientSecurity || Number(restClientSecurity?.total_clients || 0) === 0) {
      return { tone: "blue", label: "No REST clients" };
    }
    if (Number(restClientSecurity?.replay_violations || 0) > 0 || Number(restClientSecurity?.signature_failures || 0) > 0) {
      return { tone: "red", label: "Active failures" };
    }
    if (Number(restClientSecurity?.non_compliant_clients || 0) > 0 || Number(restClientSecurity?.unsigned_rejects || 0) > 0) {
      return { tone: "amber", label: "Migration pending" };
    }
    return { tone: "green", label: "Hardened" };
  }, [restClientSecurity]);
  const keyAccessStatus = useMemo(() => {
    if (!keyAccessSummary) {
      return { tone: "blue", label: "Unavailable" };
    }
    if (!keyAccessSummary?.enabled) {
      return { tone: "amber", label: "Disabled" };
    }
    if (Number(keyAccessSummary?.bypass_count_24h || 0) > 0) {
      return { tone: "red", label: "Bypass detected" };
    }
    if (Number(keyAccessSummary?.unjustified_count_24h || 0) > 0 || Number(keyAccessSummary?.approval_count_24h || 0) > 0) {
      return { tone: "amber", label: "Review activity" };
    }
    return { tone: "green", label: "Governed" };
  }, [keyAccessSummary]);
  const signingStatus = useMemo(() => {
    if (!signingSummary) {
      return { tone: "blue", label: "Unavailable" };
    }
    if (!signingSummary?.enabled) {
      return { tone: "amber", label: "Disabled" };
    }
    if (Number(signingSummary?.verification_failures_24h || 0) > 0) {
      return { tone: "red", label: "Verification failures" };
    }
    if (Number(signingSummary?.transparency_logged_24h || 0) < Number(signingSummary?.record_count_24h || 0)) {
      return { tone: "amber", label: "Transparency gaps" };
    }
    return { tone: "green", label: "Verified" };
  }, [signingSummary]);
  const mpcStatus = useMemo(() => {
    const stats = mpcOverview?.stats;
    if (!stats) {
      return { tone: "blue", label: "Unavailable" };
    }
    if (Number(stats?.failed_ceremonies || 0) > 0) {
      return { tone: "red", label: "Failed ceremonies" };
    }
    if (Number(stats?.pending_ceremonies || 0) > 0) {
      return { tone: "amber", label: "Ceremonies pending" };
    }
    if (Number(stats?.active_keys || 0) > 0) {
      return { tone: "green", label: "Ready" };
    }
    return { tone: "amber", label: "No active quorum keys" };
  }, [mpcOverview]);
  const validationByDomain = useMemo(() => {
    const map: Record<string, any[]> = {};
    validationBadges.forEach((badge: any) => {
      const key = String(badge?.domain || "").toLowerCase();
      if (!key) return;
      if (!map[key]) map[key] = [];
      map[key].push(badge);
    });
    return map;
  }, [validationBadges]);

  const trendData = useMemo(() => {
    const items = Array.isArray(history) ? history.slice(0, 60).reverse() : [];
    return items.map((entry: any) => ({ name: shortTS(entry?.captured_at), risk: Math.max(0, Math.min(100, toNum(entry?.risk_24h))) }));
  }, [history]);

  const domainBarData = useMemo(() => domainMetrics.map((d: any) => ({ name: d.label, Events: d.events, Failures: d.failures })), [domainMetrics]);

  const severityDonut = useMemo(() => {
    const rows = Array.isArray(findings) ? findings : [];
    const counts = { critical: 0, high: 0, warning: 0, info: 0 };
    rows.forEach((f: any) => {
      const s = String(f?.severity || "").toLowerCase();
      if (s === "critical") counts.critical++;
      else if (s === "high") counts.high++;
      else if (s === "warning" || s === "medium") counts.warning++;
      else counts.info++;
    });
    return [
      { name: "Critical", value: counts.critical, fill: C.red },
      { name: "High", value: counts.high, fill: C.amber },
      { name: "Warning", value: counts.warning, fill: C.amber },
      { name: "Info", value: counts.info, fill: C.blue }
    ].filter((d) => d.value > 0);
  }, [findings]);

  const riskHistogram = useMemo(() => {
    const rows = Array.isArray(findings) ? findings : [];
    const buckets = [
      { name: "0-20", count: 0, fill: C.green },
      { name: "21-40", count: 0, fill: C.green },
      { name: "41-60", count: 0, fill: C.amber },
      { name: "61-80", count: 0, fill: C.amber },
      { name: "81-100", count: 0, fill: C.red }
    ];
    rows.forEach((f: any) => {
      const score = toNum(f?.risk_score);
      if (score <= 20) buckets[0].count++;
      else if (score <= 40) buckets[1].count++;
      else if (score <= 60) buckets[2].count++;
      else if (score <= 80) buckets[3].count++;
      else buckets[4].count++;
    });
    return buckets;
  }, [findings]);

  const statusCounts = useMemo(() => {
    const rows = Array.isArray(findings) ? findings : [];
    const counts = { open: 0, acknowledged: 0, resolved: 0, reopened: 0 };
    rows.forEach((f: any) => {
      const s = String(f?.status || "").toLowerCase();
      if (s === "open") counts.open++;
      else if (s === "acknowledged") counts.acknowledged++;
      else if (s === "resolved") counts.resolved++;
      else if (s === "reopened") counts.reopened++;
      else counts.open++;
    });
    return counts;
  }, [findings]);
  const statusTotal = statusCounts.open + statusCounts.acknowledged + statusCounts.resolved + statusCounts.reopened;

  const radarData = useMemo(() => {
    const pred = Math.max(0, Math.min(100, Number(risk?.predictive_score || 0)));
    const prev = Math.max(0, Math.min(100, Number(risk?.preventive_score || 0)));
    const corr = Math.max(0, Math.min(100, Number(risk?.corrective_score || 0)));
    return [{ axis: "Predictive", value: pred }, { axis: "Preventive", value: prev }, { axis: "Corrective", value: corr }];
  }, [risk?.predictive_score, risk?.preventive_score, risk?.corrective_score]);

  const risk24 = Math.max(0, Math.min(100, Number(risk?.risk_24h || 0)));
  const risk7d = Math.max(0, Math.min(100, Number(risk?.risk_7d || 0)));
  const pred = Math.max(0, Math.min(100, Number(risk?.predictive_score || 0)));
  const prev = Math.max(0, Math.min(100, Number(risk?.preventive_score || 0)));
  const corr = Math.max(0, Math.min(100, Number(risk?.corrective_score || 0)));
  const riskTone24 = riskTone(risk24);
  const riskColor24 = riskTone24 === "red" ? C.red : riskTone24 === "amber" ? C.amber : C.green;
  const riskTone7d = riskTone(risk7d);
  const riskColor7d = riskTone7d === "red" ? C.red : riskTone7d === "amber" ? C.amber : C.green;
  const gaugeData = [{ name: "7d", value: risk7d, fill: riskColor7d }, { name: "24h", value: risk24, fill: riskColor24 }];
  const pendingActionCount = (Array.isArray(actions) ? actions : []).filter((a: any) => { const s = String(a?.status || "").toLowerCase(); return s === "pending" || s === "suggested" || s === "approved" || s === "queued"; }).length;

  // ── Domain drill-down helper ──────────────────────────────────
  const drillDomain = (domainKey: string) => {
    setFindingEngine("");
    setFindingSearch(domainKey);
    setTab("Findings");
  };

  // ── Render ────────────────────────────────────────────────────

  return <div style={{ display: "grid", gap: 14 }}>
    {/* Header Stats Row */}
    <div style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 10 }}>
      <Stat l="Risk Score" v={`${risk24}/100`} s={`7d: ${risk7d}`} c={riskTone24} i={ShieldAlert} />
      <Stat l="Open Findings" v={Number(dashboard?.open_findings || 0)} s={`${findings.length} total`} c="amber" i={AlertTriangle} />
      <Stat l="Critical" v={Number(dashboard?.critical_findings || 0)} s={Number(dashboard?.critical_findings || 0) > 0 ? "Action needed" : "All clear"} c="red" i={Zap} />
      <Stat l="Pending Actions" v={pendingActionCount} s={`${actions.length} total`} c="blue" i={Clock} />
      <Stat l="Resolved" v={statusCounts.resolved} s={statusTotal > 0 ? `${Math.round((statusCounts.resolved / statusTotal) * 100)}% resolved` : "No findings"} c="green" i={CheckCircle2} />
    </div>

    {/* Sub-tabs + Controls */}
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <Tabs tabs={["Dashboard", "Findings", "Actions", "Domains"]} active={tab} onChange={setTab} />
        <Tabs tabs={["Executive", "Operations"]} active={mode} onChange={setMode} />
      </div>
      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
        <Chk label="Sync audit" checked={syncAudit} onChange={() => setSyncAudit((v) => !v)} />
        <Btn small onClick={() => load(false)} disabled={loading}><RefreshCcw size={12} /> {loading ? "..." : "Refresh"}</Btn>
        <Btn small primary onClick={runScan} disabled={running}>{running ? "Running..." : "Run Scan"}</Btn>
      </div>
    </div>

    {/* ══════════════════════════════════════════════════════════════ */}
    {/* DASHBOARD TAB                                                 */}
    {/* ══════════════════════════════════════════════════════════════ */}
    {tab === "Dashboard" && <>
      {mode === "Executive" && <div style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr", gap: 10 }}>
        <Card style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Risk Driver Explainer</span>
            <B c={Number(dashboard?.risk_drivers?.net_delta || 0) > 0 ? "red" : Number(dashboard?.risk_drivers?.net_delta || 0) < 0 ? "green" : "blue"}>
              {Number(dashboard?.risk_drivers?.net_delta || 0) >= 0 ? "+" : ""}{Number(dashboard?.risk_drivers?.net_delta || 0)} vs last scan
            </B>
          </div>
          <div style={{ fontSize: 10, color: C.dim, marginBottom: 10 }}>{String(dashboard?.risk_drivers?.summary || "No scan delta available yet.")}</div>
          <div style={{ display: "grid", gap: 8 }}>
            {riskDrivers.slice(0, 5).map((driver: any) => (
              <div key={String(driver?.id || driver?.label)} style={{ display: "grid", gridTemplateColumns: "90px 1fr", gap: 10, padding: "8px 0", borderTop: `1px solid ${C.border}` }}>
                <div>
                  <div style={{ fontSize: 18, fontWeight: 800, color: C.accent }}>{Number(driver?.delta_points || 0) >= 0 ? "+" : ""}{Number(driver?.delta_points || 0)}</div>
                  <div style={{ fontSize: 8, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>{String(driver?.domain || "risk")}</div>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>{String(driver?.label || "-")}</div>
                  <div style={{ fontSize: 10, color: C.dim, marginTop: 3, lineHeight: 1.45 }}>{String(driver?.explanation || "")}</div>
                </div>
              </div>
            ))}
            {!riskDrivers.length && <div style={{ fontSize: 10, color: C.muted }}>Run posture scans over time to build risk delta explainers.</div>}
          </div>
        </Card>

        <div style={{ display: "grid", gap: 10 }}>
          <Card style={{ padding: "14px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Validation Badges</span>
              <B c="green">{validationBadges.filter((badge: any) => String(badge?.status || "").toLowerCase() === "healthy").length} healthy</B>
            </div>
            <div style={{ display: "grid", gap: 6 }}>
              {validationBadges.slice(0, 6).map((badge: any) => (
                <div key={`${badge?.domain}-${badge?.kind}`} style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10, background: C.surface }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                    <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{String(badge?.label || "-")}</div>
                    <B c={healthTone(String(badge?.status || ""))}>{String(badge?.status || "unknown")}</B>
                  </div>
                  <div style={{ fontSize: 9, color: C.dim, marginTop: 4 }}>{String(badge?.detail || "-")}</div>
                </div>
              ))}
              {!validationBadges.length && <div style={{ fontSize: 10, color: C.muted }}>No validation telemetry yet.</div>}
            </div>
          </Card>

          <Card style={{ padding: "14px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Autokey Drift</span>
              <B c={autokeyStatus.tone}>{autokeyStatus.label}</B>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
              <Stat l="Managed Handles" v={String(Number(autokeySummary?.handle_count || 0))} c="green" />
              <Stat l="Pending Approvals" v={String(Number(autokeySummary?.pending_approvals || 0))} c={Number(autokeySummary?.pending_approvals || 0) > 0 ? "amber" : "green"} />
              <Stat l="Policy Mismatches" v={String(Number(autokeySummary?.policy_mismatch_count || 0))} c={Number(autokeySummary?.policy_mismatch_count || 0) > 0 ? "amber" : "green"} />
              <Stat l="Provisioned 24h" v={String(Number(autokeySummary?.provisioned_24h || 0))} c="blue" />
            </div>
            <div style={{ fontSize: 9, color: C.dim, lineHeight: 1.5 }}>
              {Boolean(autokeySummary?.enabled)
                ? "Autokey templates and per-service defaults are active. Watch approval backlog and policy mismatches to keep self-service provisioning aligned."
                : "Autokey is disabled, so teams still need manual key creation instead of central-policy handle provisioning."}
            </div>
          </Card>

          <Card style={{ padding: "14px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Workload Identity Drift</span>
              <B c={workloadIdentityStatus.tone}>{workloadIdentityStatus.label}</B>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
              <Stat l="Expired SVIDs" v={String(Number(workloadSummary?.expired_svid_count || 0))} c={Number(workloadSummary?.expired_svid_count || 0) > 0 ? "red" : "green"} />
              <Stat l="Over-Privileged" v={String(Number(workloadSummary?.over_privileged_count || 0))} c={Number(workloadSummary?.over_privileged_count || 0) > 0 ? "amber" : "green"} />
              <Stat l="Trust Domain" v={String(workloadSummary?.trust_domain || "-")} c="accent" />
              <Stat l="Key Use 24h" v={String(Number(workloadSummary?.key_usage_count_24h || 0))} c="blue" />
            </div>
            <div style={{ fontSize: 9, color: C.dim, lineHeight: 1.5 }}>
              {Boolean(workloadSummary?.disable_static_api_keys)
                ? "Static API keys are disabled for workload callers."
                : "Static API keys are still allowed; move workload-facing clients to SPIFFE/SVID token exchange."}
            </div>
          </Card>

          <Card style={{ padding: "14px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>SCIM Provisioning Drift</span>
              <B c={scimStatus.tone}>{scimStatus.label}</B>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
              <Stat l="Managed Users" v={String(Number(scimSummary?.managed_users || 0))} c="blue" />
              <Stat l="Managed Groups" v={String(Number(scimSummary?.managed_groups || 0))} c="green" />
              <Stat l="Disabled Users" v={String(Number(scimSummary?.disabled_users || 0))} c={Number(scimSummary?.disabled_users || 0) > 0 ? "amber" : "green"} />
              <Stat l="Role-Mapped Groups" v={String(Number(scimSummary?.role_mapped_groups || 0))} c="blue" />
            </div>
            <div style={{ fontSize: 9, color: C.dim, lineHeight: 1.5 }}>
              {Boolean(scimSummary?.enabled)
                ? (Boolean(scimSummary?.token_configured)
                  ? "Tenant SCIM provisioning is active. Track disabled identities and unmapped groups so inbound provisioning stays aligned with least-privilege RBAC."
                  : "SCIM is enabled but the bearer token has not been rotated yet, so external provisioning cannot authenticate.")
                : "SCIM provisioning is disabled, so user and group onboarding still depends on manual admin actions or directory import jobs."}
            </div>
          </Card>

          <Card style={{ padding: "14px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Remediation SLA</span>
              <B c={Number(slaOverview?.overdue_count || 0) > 0 ? "red" : "green"}>{Number(slaOverview?.overdue_count || 0)} overdue</B>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8 }}>
              {[["Open", Number(slaOverview?.open_count || 0), C.blue], ["Due Soon", Number(slaOverview?.due_soon_count || 0), C.amber], ["Avg Age", `${Math.round(Number(slaOverview?.average_age_hours || 0))}h`, C.accent]].map(([label, value, color]) => (
                <div key={String(label)} style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10, textAlign: "center" }}>
                  <div style={{ fontSize: 16, fontWeight: 800, color: color as string }}>{value}</div>
                  <div style={{ fontSize: 8, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>{label}</div>
                </div>
              ))}
            </div>
          </Card>

          <Card style={{ padding: "14px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>REST Client Security</span>
              <B c={restClientSecurityStatus.tone}>{restClientSecurityStatus.label}</B>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
              <Stat l="Sender-Constrained" v={`${Number(restClientSecurity?.sender_constrained_clients || 0)}/${Number(restClientSecurity?.total_clients || 0)}`} c={Number(restClientSecurity?.non_compliant_clients || 0) > 0 ? "amber" : "green"} />
              <Stat l="Replay Protected" v={String(Number(restClientSecurity?.replay_protected_clients || 0))} c="blue" />
              <Stat l="Replay Violations" v={String(Number(restClientSecurity?.replay_violations || 0))} c={Number(restClientSecurity?.replay_violations || 0) > 0 ? "red" : "green"} />
              <Stat l="Unsigned Rejects" v={String(Number(restClientSecurity?.unsigned_rejects || 0))} c={Number(restClientSecurity?.unsigned_rejects || 0) > 0 ? "amber" : "green"} />
            </div>
            <div style={{ fontSize: 9, color: C.dim, lineHeight: 1.5 }}>
              {Number(restClientSecurity?.non_compliant_clients || 0) > 0
                ? `${Number(restClientSecurity?.non_compliant_clients || 0)} REST clients still use legacy API key or bearer mode. Move them to OAuth mTLS, DPoP, or HTTP Message Signatures to remove replayable tokens from the posture backlog.`
                : "All tracked REST clients are using sender-constrained authentication modes."}
            </div>
          </Card>

          <Card style={{ padding: "14px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Key Access Justifications</span>
              <B c={keyAccessStatus.tone}>{keyAccessStatus.label}</B>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
              <Stat l="Requests 24h" v={String(Number(keyAccessSummary?.total_requests_24h || 0))} c="blue" />
              <Stat l="Approval Holds" v={String(Number(keyAccessSummary?.approval_count_24h || 0))} c={Number(keyAccessSummary?.approval_count_24h || 0) > 0 ? "amber" : "green"} />
              <Stat l="Unjustified" v={String(Number(keyAccessSummary?.unjustified_count_24h || 0))} c={Number(keyAccessSummary?.unjustified_count_24h || 0) > 0 ? "amber" : "green"} />
              <Stat l="Bypass Signals" v={String(Number(keyAccessSummary?.bypass_count_24h || 0))} c={Number(keyAccessSummary?.bypass_count_24h || 0) > 0 ? "red" : "green"} />
            </div>
            <div style={{ fontSize: 9, color: C.dim, lineHeight: 1.5 }}>
              {Boolean(keyAccessSummary?.enabled)
                ? "External decrypt, sign, wrap, and HYOK/EKM access paths are governed by justification codes and optional approval rules. Treat bypass or unjustified requests as posture regressions."
                : "Per-request usage justifications are disabled, so external key use is not being explained or policy-bound at request time."}
            </div>
          </Card>

          <Card style={{ padding: "14px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Artifact Signing</span>
              <B c={signingStatus.tone}>{signingStatus.label}</B>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
              <Stat l="Profiles" v={String(Number(signingSummary?.profile_count || 0))} c="accent" />
              <Stat l="Signed 24h" v={String(Number(signingSummary?.record_count_24h || 0))} c="blue" />
              <Stat l="Transparency Logged" v={String(Number(signingSummary?.transparency_logged_24h || 0))} c={Number(signingSummary?.transparency_logged_24h || 0) < Number(signingSummary?.record_count_24h || 0) ? "amber" : "green"} />
              <Stat l="Verify Failures" v={String(Number(signingSummary?.verification_failures_24h || 0))} c={Number(signingSummary?.verification_failures_24h || 0) > 0 ? "red" : "green"} />
            </div>
            <div style={{ fontSize: 9, color: C.dim, lineHeight: 1.5 }}>
              {Boolean(signingSummary?.enabled)
                ? "Artifact and Git signing are backed by KMS keys, workload/OIDC identity constraints, and transparency-linked records. Watch verification failures and unsigned transparency gaps before treating supply-chain posture as healthy."
                : "Artifact signing is disabled, so release provenance and workload-bound signing policy are not enforced for blobs, OCI metadata, or Git artifacts."}
            </div>
          </Card>

          <Card style={{ padding: "14px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Threshold Signing / FROST</span>
              <B c={mpcStatus.tone}>{mpcStatus.label}</B>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
              <Stat l="Active Keys" v={String(Number(mpcOverview?.stats?.active_keys || 0))} c="green" />
              <Stat l="Pending Ceremonies" v={String(Number(mpcOverview?.stats?.pending_ceremonies || 0))} c={Number(mpcOverview?.stats?.pending_ceremonies || 0) > 0 ? "amber" : "green"} />
              <Stat l="Participants" v={String(Number(mpcOverview?.stats?.total_participants || 0))} c="blue" />
              <Stat l="Failed Ceremonies" v={String(Number(mpcOverview?.stats?.failed_ceremonies || 0))} c={Number(mpcOverview?.stats?.failed_ceremonies || 0) > 0 ? "red" : "green"} />
            </div>
            <div style={{ fontSize: 9, color: C.dim, lineHeight: 1.5 }}>
              {Number(mpcOverview?.stats?.total_keys || 0) > 0
                ? "Quorum-backed signing and decryption ceremonies are active. Use this to spot stalled ceremonies, participant drift, or failed threshold operations before they affect high-assurance workflows."
                : "No quorum-backed keys are currently active. Create MPC/FROST ceremony policy when high-assurance signing or split-operator approval must avoid a single private-key holder."}
            </div>
          </Card>
        </div>
      </div>}

      {mode === "Operations" && <div style={{ display: "grid", gap: 10 }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 10 }}>
          {cockpitGroups.map((group: any) => (
            <Card key={String(group?.id || group?.label)} style={{ padding: "14px 16px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{String(group?.label || "-")}</span>
                <B c={group?.id === "approval-required" ? "red" : group?.id === "manual" ? "amber" : "green"}>{Number(group?.count || 0)}</B>
              </div>
              <div style={{ fontSize: 9, color: C.dim, marginBottom: 8 }}>{String(group?.description || "")}</div>
              <div style={{ display: "grid", gap: 6 }}>
                {(Array.isArray(group?.actions) ? group.actions : []).slice(0, 3).map((action: any) => (
                  <div key={String(action?.id || action?.action_type)} style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10, background: C.surface }}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                      <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{String(action?.action_type || "-")}</div>
                      <B c={actionStatusTone(String(action?.status || ""))}>{String(action?.status || "-")}</B>
                    </div>
                    <div style={{ fontSize: 9, color: C.dim, marginTop: 4 }}>{String(action?.recommended_action || "")}</div>
                    <div style={{ fontSize: 8, color: C.muted, marginTop: 4 }}>Impact: {Number(action?.impact_estimate?.risk_reduction || 0)} points, rollback: {String(action?.rollback_hint || "-")}</div>
                  </div>
                ))}
                {!group?.count && <div style={{ fontSize: 10, color: C.muted }}>No actions in this bucket.</div>}
              </div>
            </Card>
          ))}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <Card style={{ padding: "14px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Blast Radius View</span>
              <B c="amber">{blastHotspots.length} hotspots</B>
            </div>
            <div style={{ display: "grid", gap: 8 }}>
              {blastHotspots.slice(0, 4).map((blast: any, idx: number) => (
                <div key={`${blast?.summary}-${idx}`} style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10, background: C.surface }}>
                  <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{String(blast?.summary || "-")}</div>
                  <div style={{ display: "flex", gap: 10, flexWrap: "wrap", fontSize: 8, color: C.muted, marginTop: 5 }}>
                    <span>{Number(blast?.event_count || 0)} events</span>
                    <span>{Array.isArray(blast?.services) ? blast.services.length : 0} services</span>
                    <span>{Array.isArray(blast?.apps) ? blast.apps.length : 0} apps</span>
                    <span>{Array.isArray(blast?.resources) ? blast.resources.length : 0} resources</span>
                  </div>
                </div>
              ))}
              {!blastHotspots.length && <div style={{ fontSize: 10, color: C.muted }}>No blast radius hotspots yet.</div>}
            </div>
          </Card>

          <Card style={{ padding: "14px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Scenario Simulator</span>
              <B c="blue">Read-only</B>
            </div>
            <div style={{ display: "grid", gap: 8 }}>
              {scenarioCards.slice(0, 4).map((scenario: any) => (
                <div key={String(scenario?.id || scenario?.label)} style={{ padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 10, background: C.surface }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                    <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{String(scenario?.label || "-")}</div>
                    <B c={Number(scenario?.risk_delta || 0) < 0 ? "green" : "amber"}>{Number(scenario?.risk_delta || 0)}</B>
                  </div>
                  <div style={{ fontSize: 9, color: C.dim, marginTop: 4 }}>{String(scenario?.summary || "")}</div>
                  {Array.isArray(scenario?.based_on) && scenario.based_on.length > 0 && <div style={{ fontSize: 8, color: C.muted, marginTop: 4 }}>Based on: {scenario.based_on.slice(0, 3).join(" · ")}</div>}
                </div>
              ))}
              {!scenarioCards.length && <div style={{ fontSize: 10, color: C.muted }}>No open actions to simulate yet.</div>}
            </div>
          </Card>
        </div>
      </div>}

      {/* Row 1: Risk Gauge + Engine Radar + Severity Donut */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
        {/* Risk Gauge */}
        <Card style={{ padding: "12px 14px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}><ShieldAlert size={14} color={C.accent} /><span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Risk Window</span></div>
            <B c={riskTone24}>{`${risk24}/100`}</B>
          </div>
          <ResponsiveContainer width="100%" height={140}>
            <RadialBarChart cx="50%" cy="50%" innerRadius="40%" outerRadius="90%" startAngle={210} endAngle={-30} data={gaugeData} barSize={10}>
              <RadialBar dataKey="value" cornerRadius={5} background={{ fill: C.border }} />
            </RadialBarChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", justifyContent: "center", gap: 16, marginTop: 2 }}>
            <div style={{ textAlign: "center" }}><div style={{ fontSize: 9, color: C.muted }}>24h</div><div style={{ fontSize: 14, fontWeight: 700, color: riskColor24 }}>{risk24}</div></div>
            <div style={{ textAlign: "center" }}><div style={{ fontSize: 9, color: C.muted }}>7d</div><div style={{ fontSize: 14, fontWeight: 700, color: riskColor7d }}>{risk7d}</div></div>
          </div>
          <div style={{ fontSize: 9, color: C.muted, textAlign: "center", marginTop: 4 }}>Captured: {fmtTS(risk?.captured_at)}</div>
        </Card>

        {/* Engine Radar */}
        <Card style={{ padding: "12px 14px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}><Activity size={14} color={C.green} /><span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Engine Scores</span></div>
            <B c="blue">Live</B>
          </div>
          <ResponsiveContainer width="100%" height={160}>
            <RadarChart data={radarData} cx="50%" cy="50%" outerRadius="70%">
              <PolarGrid stroke={C.border} />
              <PolarAngleAxis dataKey="axis" tick={{ fill: C.dim, fontSize: 10 }} />
              <PolarRadiusAxis angle={90} domain={[0, 100]} tick={{ fill: C.muted, fontSize: 8 }} tickCount={4} />
              <Radar dataKey="value" stroke={C.accent} fill={C.accent} fillOpacity={0.2} strokeWidth={2} />
            </RadarChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", justifyContent: "center", gap: 14, marginTop: 2 }}>
            <div style={{ fontSize: 9, color: C.muted }}>Predictive: <span style={{ color: C.blue, fontWeight: 700 }}>{pred}</span></div>
            <div style={{ fontSize: 9, color: C.muted }}>Preventive: <span style={{ color: C.amber, fontWeight: 700 }}>{prev}</span></div>
            <div style={{ fontSize: 9, color: C.muted }}>Corrective: <span style={{ color: C.green, fontWeight: 700 }}>{corr}</span></div>
          </div>
        </Card>

        {/* Severity Donut */}
        <Card style={{ padding: "12px 14px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}><Wrench size={14} color={C.amber} /><span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Findings Breakdown</span></div>
            <B c={Number(dashboard?.critical_findings || 0) > 0 ? "red" : "green"}>{Number(dashboard?.critical_findings || 0)} critical</B>
          </div>
          {severityDonut.length > 0 ? <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie data={severityDonut} cx="50%" cy="50%" innerRadius={35} outerRadius={55} paddingAngle={3} dataKey="value" strokeWidth={0}>
                {severityDonut.map((entry, idx) => <Cell key={idx} fill={entry.fill} />)}
              </Pie>
              <Tooltip content={({ active, payload }) => active && payload?.length ? <ChartTooltip><span style={{ color: payload[0]?.payload?.fill, fontWeight: 700 }}>{payload[0]?.name}</span>: {payload[0]?.value}</ChartTooltip> : null} />
              <Legend verticalAlign="bottom" height={28} iconType="circle" iconSize={8} formatter={(value) => <span style={{ color: C.dim, fontSize: 9 }}>{value}</span>} />
            </PieChart>
          </ResponsiveContainer> : <div style={{ height: 160, display: "flex", alignItems: "center", justifyContent: "center" }}><span style={{ fontSize: 10, color: C.muted }}>No findings data</span></div>}
        </Card>
      </div>

      {/* Row 2: Risk Trend + Histogram */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 10 }}>
        <Card style={{ padding: "12px 14px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Risk Trend</span>
            <B c="blue">{trendData.length ? `${trendData[trendData.length - 1]?.risk || 0} latest` : "No history"}</B>
          </div>
          {trendData.length > 0 ? <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={trendData}>
              <defs><linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={C.accent} stopOpacity={0.25} /><stop offset="95%" stopColor={C.accent} stopOpacity={0} /></linearGradient></defs>
              <XAxis dataKey="name" tick={{ fill: C.muted, fontSize: 8 }} axisLine={{ stroke: C.border }} tickLine={false} interval="preserveStartEnd" />
              <YAxis domain={[0, 100]} tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} width={30} />
              <Tooltip content={RiskTrendTooltip} cursor={{ stroke: C.borderHi, strokeDasharray: "3 3" }} />
              <Area type="monotone" dataKey="risk" stroke={C.accent} strokeWidth={2} fill="url(#riskGradient)" dot={{ fill: C.accent, r: 2, strokeWidth: 0 }} activeDot={{ fill: C.accent, r: 4, stroke: C.bg, strokeWidth: 2 }} />
            </AreaChart>
          </ResponsiveContainer> : <div style={{ height: 180, display: "flex", alignItems: "center", justifyContent: "center" }}><span style={{ fontSize: 10, color: C.muted }}>No risk history yet.</span></div>}
        </Card>

        <Card style={{ padding: "12px 14px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Risk Distribution</span>
            <B c="accent">{findings.length} findings</B>
          </div>
          {findings.length > 0 ? <ResponsiveContainer width="100%" height={180}>
            <BarChart data={riskHistogram}>
              <XAxis dataKey="name" tick={{ fill: C.dim, fontSize: 9 }} axisLine={{ stroke: C.border }} tickLine={false} />
              <YAxis tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} width={25} allowDecimals={false} />
              <Tooltip content={HistogramTooltip} cursor={{ fill: C.accentDim }} />
              <RBar dataKey="count" radius={[4, 4, 0, 0]}>{riskHistogram.map((entry, idx) => <Cell key={idx} fill={entry.fill} />)}</RBar>
            </BarChart>
          </ResponsiveContainer> : <div style={{ height: 180, display: "flex", alignItems: "center", justifyContent: "center" }}><span style={{ fontSize: 10, color: C.muted }}>No findings data</span></div>}
        </Card>
      </div>

      {/* Row 3: Resolution Progress */}
      {statusTotal > 0 && <Card style={{ padding: "12px 14px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <span style={{ fontSize: 11, fontWeight: 700, color: C.text }}>Findings Resolution Status</span>
          <span style={{ fontSize: 9, color: C.muted }}>{statusTotal} total</span>
        </div>
        <div style={{ display: "flex", height: 14, borderRadius: 7, overflow: "hidden", border: `1px solid ${C.border}` }}>
          {statusCounts.resolved > 0 && <div style={{ width: `${(statusCounts.resolved / statusTotal) * 100}%`, background: C.green, transition: "width .4s" }} title={`Resolved: ${statusCounts.resolved}`} />}
          {statusCounts.acknowledged > 0 && <div style={{ width: `${(statusCounts.acknowledged / statusTotal) * 100}%`, background: C.blue, transition: "width .4s" }} title={`Acknowledged: ${statusCounts.acknowledged}`} />}
          {statusCounts.open > 0 && <div style={{ width: `${(statusCounts.open / statusTotal) * 100}%`, background: C.amber, transition: "width .4s" }} title={`Open: ${statusCounts.open}`} />}
          {statusCounts.reopened > 0 && <div style={{ width: `${(statusCounts.reopened / statusTotal) * 100}%`, background: C.red, transition: "width .4s" }} title={`Reopened: ${statusCounts.reopened}`} />}
        </div>
        <div style={{ display: "flex", gap: 14, marginTop: 6, flexWrap: "wrap" }}>
          {[{ label: "Resolved", color: C.green, count: statusCounts.resolved }, { label: "Acknowledged", color: C.blue, count: statusCounts.acknowledged }, { label: "Open", color: C.amber, count: statusCounts.open }, { label: "Reopened", color: C.red, count: statusCounts.reopened }].map((s) => <div key={s.label} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 9, color: C.dim }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: s.color }} />{s.label} ({s.count})
          </div>)}
        </div>
      </Card>}
    </>}

    {/* ══════════════════════════════════════════════════════════════ */}
    {/* FINDINGS TAB                                                  */}
    {/* ══════════════════════════════════════════════════════════════ */}
    {tab === "Findings" && <>
      {/* Filter bar */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
        <Inp value={findingSearch} onChange={(e: any) => setFindingSearch(e.target.value)} placeholder="Search finding title/engine/type..." style={{ height: 30, fontSize: 11, width: 250 }} />
        <Sel value={findingSeverity} onChange={(e: any) => setFindingSeverity(String(e.target.value || ""))} style={{ height: 30, fontSize: 11 }}>
          <option value="">All Severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="warning">Warning</option>
          <option value="info">Info</option>
        </Sel>
        <Sel value={findingStatus} onChange={(e: any) => setFindingStatus(String(e.target.value || ""))} style={{ height: 30, fontSize: 11 }}>
          <option value="">All Status</option>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
          <option value="reopened">Reopened</option>
        </Sel>
        <Sel value={findingEngine} onChange={(e: any) => setFindingEngine(String(e.target.value || ""))} style={{ height: 30, fontSize: 11 }}>
          <option value="">All Engines</option>
          <option value="predictive">Predictive</option>
          <option value="preventive">Preventive</option>
          <option value="corrective">Corrective</option>
        </Sel>
        {findingEngine && <Btn small onClick={() => setFindingEngine("")} style={{ height: 30, fontSize: 10 }}>Clear engine filter</Btn>}
        <span style={{ fontSize: 10, color: C.muted, marginLeft: "auto" }}>{visibleFindings.length} of {filteredFindings.length} shown</span>
      </div>

      {/* Findings table */}
      <Card style={{ padding: "12px 14px" }}>
        <div style={{ maxHeight: 500, overflow: "auto" }}>
          <div style={{ display: "grid", gridTemplateColumns: "2.5fr 1fr 80px 60px 1fr 80px", gap: 8, padding: "6px 0", borderBottom: `1px solid ${C.borderHi}`, fontSize: 9, color: C.muted, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5, position: "sticky", top: 0, background: C.card, zIndex: 1 }}>
            <span>Title</span><span>Engine</span><span>Severity</span><span>Risk</span><span>Status</span><span>Detected</span>
          </div>
          {visibleFindings.map((item: any) => {
            const sla = slaBadge(item?.sla_due_at);
            const reopens = Number(item?.reopen_count || 0);
            return <div key={String(item.id)} onClick={() => setSelectedFinding(item)} style={{ display: "grid", gridTemplateColumns: "2.5fr 1fr 80px 60px 1fr 80px", gap: 8, padding: "8px 0", borderBottom: `1px solid ${C.border}`, fontSize: 11, alignItems: "center", cursor: "pointer", transition: "background .15s" }} onMouseEnter={(e) => (e.currentTarget.style.background = C.cardHover)} onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
              <div>
                <div style={{ fontWeight: 600, color: C.text }}>{String(item?.title || item?.finding_type || "-")}</div>
                <div style={{ fontSize: 9, color: C.muted, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 400 }}>{String(item?.recommended_action || "-")}</div>
              </div>
              <span style={{ color: C.dim, fontSize: 10 }}>{String(item?.engine || "-")}</span>
              <span><B c={severityTone(String(item?.severity || ""))}>{String(item?.severity || "-")}</B></span>
              <span style={{ color: C.text, fontWeight: 700 }}>{Number(item?.risk_score || 0)}</span>
              <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                <span style={{ color: C.dim, fontSize: 10 }}>{String(item?.status || "-")}</span>
                {reopens > 0 && <span style={{ fontSize: 8, color: C.red, fontWeight: 700 }}>(×{reopens})</span>}
                {sla && <B c={sla.tone}>{sla.label}</B>}
              </div>
              <span style={{ color: C.muted, fontSize: 10 }}>{shortTS(item?.detected_at)}</span>
            </div>;
          })}
          {visibleFindings.length === 0 && <div style={{ padding: "20px 0", textAlign: "center", fontSize: 10, color: C.muted }}>No findings for current filters.</div>}
        </div>
      </Card>
    </>}

    {/* ══════════════════════════════════════════════════════════════ */}
    {/* ACTIONS TAB                                                   */}
    {/* ══════════════════════════════════════════════════════════════ */}
    {tab === "Actions" && <>
      {/* Filter bar */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
        <Inp value={actionSearch} onChange={(e: any) => setActionSearch(e.target.value)} placeholder="Search action type, recommendation..." style={{ height: 30, fontSize: 11, width: 280 }} />
        <Sel value={actionStatus} onChange={(e: any) => setActionStatus(String(e.target.value || ""))} style={{ height: 30, fontSize: 11 }}>
          <option value="">All Status</option>
          <option value="suggested">Suggested</option>
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="executed">Executed</option>
          <option value="failed">Failed</option>
        </Sel>
        <span style={{ fontSize: 10, color: C.muted, marginLeft: "auto" }}>{visibleActions.length} actions</span>
      </div>

      {/* Actions table */}
      <Card style={{ padding: "12px 14px" }}>
        <div style={{ maxHeight: 500, overflow: "auto" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr 80px 100px 2fr", gap: 8, padding: "6px 0", borderBottom: `1px solid ${C.borderHi}`, fontSize: 9, color: C.muted, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5, position: "sticky", top: 0, background: C.card, zIndex: 1 }}>
            <span>Action Type</span><span>Safety Gate</span><span>Status</span><span>Approval</span><span>Recommendation</span>
          </div>
          {visibleActions.map((item: any) => {
            const status = String(item?.status || "").toLowerCase();
            return <div key={String(item.id)} onClick={() => setSelectedAction(item)} style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr 80px 100px 2fr", gap: 8, padding: "8px 0", borderBottom: `1px solid ${C.border}`, fontSize: 11, alignItems: "center", cursor: "pointer", transition: "background .15s" }} onMouseEnter={(e) => (e.currentTarget.style.background = C.cardHover)} onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
              <span style={{ color: C.text, fontWeight: 600 }}>{String(item?.action_type || "-")}</span>
              <span style={{ color: C.dim }}>{String(item?.safety_gate || "-")}</span>
              <span><B c={actionStatusTone(status)}>{String(item?.status || "-")}</B></span>
              <span>{item?.approval_required ? <B c="amber">Required</B> : <span style={{ fontSize: 10, color: C.muted }}>No</span>}</span>
              <span style={{ color: C.muted, fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(item?.recommended_action || "-")}</span>
            </div>;
          })}
          {visibleActions.length === 0 && <div style={{ padding: "20px 0", textAlign: "center", fontSize: 10, color: C.muted }}>No remediation actions.</div>}
        </div>
      </Card>
    </>}

    {/* ══════════════════════════════════════════════════════════════ */}
    {/* DOMAINS TAB                                                   */}
    {/* ══════════════════════════════════════════════════════════════ */}
    {tab === "Domains" && <>
      {/* Domain Bar Chart */}
      <Card style={{ padding: "14px 16px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Domain Posture (24h)</span>
          <B c="accent">Events vs Failures</B>
        </div>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={domainBarData} barGap={2} barCategoryGap="20%">
            <XAxis dataKey="name" tick={{ fill: C.dim, fontSize: 10 }} axisLine={{ stroke: C.border }} tickLine={false} />
            <YAxis tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} width={35} />
            <Tooltip content={DomainBarTooltip} cursor={{ fill: C.accentDim }} />
            <RBar dataKey="Events" fill={C.blue} radius={[3, 3, 0, 0]} />
            <RBar dataKey="Failures" fill={C.red} radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </Card>

      {/* Domain Cards Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 10 }}>
        {domainMetrics.map((domain: any) => {
          const Icon = domain.icon;
          const tone = riskTone(domain.rate);
          const toneColor = tone === "red" ? C.red : tone === "amber" ? C.amber : C.green;
          return <Card key={domain.key} style={{ padding: "14px 16px", cursor: "pointer", transition: "border-color .15s, box-shadow .15s" }} onClick={() => drillDomain(domain.key)} onMouseEnter={(e) => { e.currentTarget.style.borderColor = C.accent; e.currentTarget.style.boxShadow = `0 0 12px ${C.glow}`; }} onMouseLeave={(e) => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.boxShadow = "none"; }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{ width: 32, height: 32, borderRadius: 8, background: C.accentDim, display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Icon size={16} color={C.accent} />
                </div>
                <span style={{ fontSize: 13, color: C.text, fontWeight: 700 }}>{domain.label}</span>
              </div>
              <B c={tone}>{`${domain.rate.toFixed(1)}%`}</B>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, marginBottom: 8 }}>
              <div><div style={{ fontSize: 9, color: C.muted }}>Events</div><div style={{ fontSize: 18, fontWeight: 700, color: C.text }}>{domain.events}</div></div>
              <div><div style={{ fontSize: 9, color: C.muted }}>Failures</div><div style={{ fontSize: 18, fontWeight: 700, color: domain.failures > 0 ? C.red : C.text }}>{domain.failures}</div></div>
            </div>

            <div style={{ fontSize: 10, color: C.dim, marginBottom: 6 }}>Avg latency: <span style={{ color: C.text, fontWeight: 600 }}>{domain.latency > 0 ? `${domain.latency.toFixed(1)} ms` : "-"}</span></div>

            {domain.key === "kmip" && <div style={{ fontSize: 9, color: C.muted }}>Interop failed: <span style={{ color: domain.interop > 0 ? C.red : C.green, fontWeight: 700 }}>{domain.interop}</span></div>}
            {domain.key === "sdk" && <div style={{ fontSize: 9, color: C.muted }}>Missing receipts: <span style={{ color: domain.receiptMissing > 0 ? C.red : C.green, fontWeight: 700 }}>{domain.receiptMissing}</span></div>}

            {(validationByDomain[domain.key] || []).length > 0 && <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
              {(validationByDomain[domain.key] || []).slice(0, 2).map((badge: any) => (
                <div key={`${badge?.domain}-${badge?.kind}`} style={{ padding: "5px 8px", borderRadius: 999, border: `1px solid ${C.border}`, background: C.surface }}>
                  <span style={{ fontSize: 8, color: C.muted }}>{String(badge?.kind || "").replace(/_/g, " ")}</span>{" "}
                  <span style={{ fontSize: 8, color: healthTone(String(badge?.status || "")) === "red" ? C.red : healthTone(String(badge?.status || "")) === "amber" ? C.amber : healthTone(String(badge?.status || "")) === "green" ? C.green : C.blue, fontWeight: 700 }}>
                    {String(badge?.status || "unknown")}
                  </span>
                </div>
              ))}
            </div>}

            {/* Failure rate bar */}
            <div style={{ marginTop: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 8, color: C.muted, marginBottom: 2 }}><span>Failure Rate</span><span>{domain.rate.toFixed(1)}%</span></div>
              <div style={{ height: 5, borderRadius: 999, border: `1px solid ${C.border}`, background: C.bg }}>
                <div style={{ width: `${Math.max(2, Math.min(100, domain.rate))}%`, height: "100%", borderRadius: 999, background: toneColor }} />
              </div>
            </div>
            {/* Latency bar */}
            <div style={{ marginTop: 4 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 8, color: C.muted, marginBottom: 2 }}><span>Latency</span><span>{domain.latency > 0 ? `${domain.latency.toFixed(0)}ms` : "-"}</span></div>
              <div style={{ height: 5, borderRadius: 999, border: `1px solid ${C.border}`, background: C.bg }}>
                <div style={{ width: `${Math.max(2, Math.min(100, domain.latency > 0 ? Math.min(100, (domain.latency / 500) * 100) : 0))}%`, height: "100%", borderRadius: 999, background: domain.latency >= 500 ? C.red : domain.latency >= 100 ? C.amber : C.green }} />
              </div>
            </div>

            <div style={{ marginTop: 8, fontSize: 9, color: C.accent, fontWeight: 600 }}>Click to view findings →</div>
          </Card>;
        })}
      </div>
    </>}

    {/* ══════════════════════════════════════════════════════════════ */}
    {/* FINDING DETAIL MODAL                                          */}
    {/* ══════════════════════════════════════════════════════════════ */}
    <Modal open={Boolean(selectedFinding)} onClose={() => setSelectedFinding(null)} title={String(selectedFinding?.title || "Finding Detail")} wide>
      {selectedFinding && <>
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 12 }}>
          <B c={severityTone(String(selectedFinding.severity || ""))}>{String(selectedFinding.severity || "-")}</B>
          <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Risk: {Number(selectedFinding.risk_score || 0)}</span>
          <span style={{ fontSize: 10, color: C.dim }}>Engine: {String(selectedFinding.engine || "-")}</span>
          <span style={{ fontSize: 10, color: C.dim }}>Type: {String(selectedFinding.finding_type || "-")}</span>
          {(() => { const sla = slaBadge(selectedFinding.sla_due_at); return sla ? <B c={sla.tone}>{sla.label}</B> : null; })()}
          {Number(selectedFinding.reopen_count || 0) > 0 && <span style={{ fontSize: 10, color: C.red, fontWeight: 700 }}>Reopened ×{selectedFinding.reopen_count}</span>}
        </div>

        {/* Description */}
        {selectedFinding.description && <Card style={{ padding: "10px 14px", marginBottom: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>Description</div>
          <div style={{ fontSize: 11, color: C.text, lineHeight: 1.5 }}>{String(selectedFinding.description)}</div>
        </Card>}

        {/* Recommended Action */}
        {selectedFinding.recommended_action && <Card style={{ padding: "10px 14px", marginBottom: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>Recommended Action</div>
          <div style={{ fontSize: 11, color: C.accent, lineHeight: 1.5 }}>{String(selectedFinding.recommended_action)}</div>
        </Card>}

        {Array.isArray(selectedFinding.risk_drivers) && selectedFinding.risk_drivers.length > 0 && <Card style={{ padding: "10px 14px", marginBottom: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6 }}>Risk Driver Explainer</div>
          <div style={{ display: "grid", gap: 8 }}>
            {selectedFinding.risk_drivers.map((driver: any) => (
              <div key={String(driver?.id || driver?.label)} style={{ display: "grid", gridTemplateColumns: "70px 1fr", gap: 10, alignItems: "start", paddingTop: 6, borderTop: `1px solid ${C.border}` }}>
                <div>
                  <div style={{ fontSize: 18, fontWeight: 800, color: C.accent }}>+{Number(driver?.delta_points || 0)}</div>
                  <div style={{ fontSize: 8, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>{String(driver?.domain || "risk")}</div>
                </div>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>{String(driver?.label || "-")}</div>
                  <div style={{ fontSize: 10, color: C.dim, marginTop: 3 }}>{String(driver?.explanation || "")}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>}

        {selectedFinding.blast_radius && ((selectedFinding.blast_radius.event_count || 0) > 0 || (selectedFinding.blast_radius.services || []).length > 0) && <Card style={{ padding: "10px 14px", marginBottom: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6 }}>Blast Radius</div>
          <div style={{ fontSize: 10, color: C.text, marginBottom: 6 }}>{String(selectedFinding.blast_radius.summary || "-")}</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 8 }}>
            {[["Services", selectedFinding.blast_radius.services], ["Apps", selectedFinding.blast_radius.apps], ["Resources", selectedFinding.blast_radius.resources], ["Actors", selectedFinding.blast_radius.actors]].map(([label, values]) => (
              <div key={String(label)} style={{ fontSize: 9, color: C.dim }}>
                <div style={{ textTransform: "uppercase", letterSpacing: 0.7, marginBottom: 4 }}>{label}</div>
                <div style={{ color: C.text, lineHeight: 1.45 }}>{Array.isArray(values) && values.length ? values.slice(0, 4).join(", ") : "-"}</div>
              </div>
            ))}
          </div>
        </Card>}

        {/* Evidence */}
        {selectedFinding.evidence && Object.keys(selectedFinding.evidence).length > 0 && <Card style={{ padding: "10px 14px", marginBottom: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>Evidence</div>
          <pre style={{ fontSize: 10, color: C.dim, background: C.surface, borderRadius: 6, padding: 10, overflow: "auto", maxHeight: 160, margin: 0, border: `1px solid ${C.border}` }}>{JSON.stringify(selectedFinding.evidence, null, 2)}</pre>
        </Card>}

        {/* Timeline */}
        <Card style={{ padding: "10px 14px", marginBottom: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6 }}>Timeline</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 8 }}>
            <div><div style={{ fontSize: 9, color: C.muted }}>Detected</div><div style={{ fontSize: 10, color: C.text }}>{fmtTS(selectedFinding.detected_at)}</div></div>
            <div><div style={{ fontSize: 9, color: C.muted }}>Updated</div><div style={{ fontSize: 10, color: C.text }}>{fmtTS(selectedFinding.updated_at)}</div></div>
            <div><div style={{ fontSize: 9, color: C.muted }}>Resolved</div><div style={{ fontSize: 10, color: C.text }}>{fmtTS(selectedFinding.resolved_at)}</div></div>
            <div><div style={{ fontSize: 9, color: C.muted }}>SLA Due</div><div style={{ fontSize: 10, color: C.text }}>{fmtTS(selectedFinding.sla_due_at)}</div></div>
          </div>
        </Card>

        {/* Metadata */}
        <div style={{ display: "flex", gap: 12, fontSize: 9, color: C.muted, marginBottom: 12 }}>
          <span>ID: <span style={{ color: C.dim }}>{String(selectedFinding.id || "-")}</span></span>
          <span>Fingerprint: <span style={{ color: C.dim }}>{String(selectedFinding.fingerprint || "-")}</span></span>
          <span>Status: <span style={{ color: C.text, fontWeight: 700 }}>{String(selectedFinding.status || "-")}</span></span>
        </div>

        {/* Actions */}
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <Btn small onClick={() => patchFinding(selectedFinding, "acknowledged")} disabled={String(selectedFinding.status || "").toLowerCase() === "acknowledged"}>Acknowledge</Btn>
          <Btn small onClick={() => patchFinding(selectedFinding, "resolved")} disabled={String(selectedFinding.status || "").toLowerCase() === "resolved"}>Resolve</Btn>
          <Btn small onClick={() => patchFinding(selectedFinding, "reopened")}>Reopen</Btn>
          <Btn onClick={() => setSelectedFinding(null)}>Close</Btn>
        </div>
      </>}
    </Modal>

    {/* ══════════════════════════════════════════════════════════════ */}
    {/* ACTION DETAIL MODAL                                           */}
    {/* ══════════════════════════════════════════════════════════════ */}
    <Modal open={Boolean(selectedAction)} onClose={() => setSelectedAction(null)} title={`Action: ${String(selectedAction?.action_type || "Detail")}`} wide>
      {selectedAction && <>
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 12 }}>
          <B c={actionStatusTone(String(selectedAction.status || ""))}>{String(selectedAction.status || "-")}</B>
          <span style={{ fontSize: 10, color: C.dim }}>Safety Gate: {String(selectedAction.safety_gate || "-")}</span>
          {selectedAction.approval_required ? <B c="amber">Approval Required</B> : <span style={{ fontSize: 10, color: C.muted }}>No approval needed</span>}
        </div>

        {/* Recommended Action */}
        <Card style={{ padding: "10px 14px", marginBottom: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>Recommended Action</div>
          <div style={{ fontSize: 11, color: C.accent, lineHeight: 1.5 }}>{String(selectedAction.recommended_action || "-")}</div>
        </Card>

        {(selectedAction.impact_estimate || selectedAction.rollback_hint) && <Card style={{ padding: "10px 14px", marginBottom: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6 }}>Impact Estimate</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8 }}>
            <div>
              <div style={{ fontSize: 9, color: C.muted }}>Risk Reduction</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: C.green }}>{Number(selectedAction?.impact_estimate?.risk_reduction || 0)} pts</div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: C.muted }}>Operational Cost</div>
              <div style={{ fontSize: 11, color: C.text }}>{String(selectedAction?.impact_estimate?.operational_cost || "-")}</div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: C.muted }}>Time To Apply</div>
              <div style={{ fontSize: 11, color: C.text }}>{String(selectedAction?.impact_estimate?.time_to_apply || "-")}</div>
            </div>
          </div>
          {selectedAction?.rollback_hint && <div style={{ fontSize: 10, color: C.dim, marginTop: 8 }}>Rollback: {String(selectedAction.rollback_hint)}</div>}
        </Card>}

        {selectedAction.blast_radius && ((selectedAction.blast_radius.event_count || 0) > 0 || (selectedAction.blast_radius.services || []).length > 0) && <Card style={{ padding: "10px 14px", marginBottom: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6 }}>Blast Radius</div>
          <div style={{ fontSize: 10, color: C.text, marginBottom: 6 }}>{String(selectedAction.blast_radius.summary || "-")}</div>
          <div style={{ fontSize: 9, color: C.dim, lineHeight: 1.5 }}>
            Services: {Array.isArray(selectedAction.blast_radius.services) && selectedAction.blast_radius.services.length ? selectedAction.blast_radius.services.join(", ") : "-"}
            <br />
            Apps: {Array.isArray(selectedAction.blast_radius.apps) && selectedAction.blast_radius.apps.length ? selectedAction.blast_radius.apps.join(", ") : "-"}
          </div>
        </Card>}

        {/* Result */}
        {selectedAction.result_message && <Card style={{ padding: "10px 14px", marginBottom: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>Result</div>
          <div style={{ fontSize: 11, color: C.text, lineHeight: 1.5 }}>{String(selectedAction.result_message)}</div>
        </Card>}

        {/* Evidence */}
        {selectedAction.evidence && Object.keys(selectedAction.evidence).length > 0 && <Card style={{ padding: "10px 14px", marginBottom: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>Evidence</div>
          <pre style={{ fontSize: 10, color: C.dim, background: C.surface, borderRadius: 6, padding: 10, overflow: "auto", maxHeight: 160, margin: 0, border: `1px solid ${C.border}` }}>{JSON.stringify(selectedAction.evidence, null, 2)}</pre>
        </Card>}

        {/* Timeline */}
        <Card style={{ padding: "10px 14px", marginBottom: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6 }}>Timeline</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}>
            <div><div style={{ fontSize: 9, color: C.muted }}>Created</div><div style={{ fontSize: 10, color: C.text }}>{fmtTS(selectedAction.created_at)}</div></div>
            <div><div style={{ fontSize: 9, color: C.muted }}>Updated</div><div style={{ fontSize: 10, color: C.text }}>{fmtTS(selectedAction.updated_at)}</div></div>
            <div><div style={{ fontSize: 9, color: C.muted }}>Executed</div><div style={{ fontSize: 10, color: C.text }}>{fmtTS(selectedAction.executed_at)}</div></div>
          </div>
        </Card>

        {/* Metadata */}
        <div style={{ display: "flex", gap: 12, fontSize: 9, color: C.muted, marginBottom: 12 }}>
          <span>ID: <span style={{ color: C.dim }}>{String(selectedAction.id || "-")}</span></span>
          <span>Finding: <span style={{ color: C.accent, cursor: "pointer", textDecoration: "underline" }} onClick={() => {
            const finding = findings.find((f: any) => f.id === selectedAction.finding_id);
            if (finding) { setSelectedAction(null); setSelectedFinding(finding); } else { setSelectedAction(null); setTab("Findings"); }
          }}>{String(selectedAction.finding_id || "-")}</span></span>
          {selectedAction.executed_by && <span>By: <span style={{ color: C.dim }}>{String(selectedAction.executed_by)}</span></span>}
          {selectedAction.approval_request_id && <span>Approval: <span style={{ color: C.dim }}>{String(selectedAction.approval_request_id)}</span></span>}
        </div>

        {/* Actions */}
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          {(() => {
            const s = String(selectedAction.status || "").toLowerCase();
            const canExec = s === "pending" || s === "approved" || s === "queued" || s === "suggested";
            return canExec ? <Btn small primary onClick={() => executeAction(selectedAction)}><Play size={11} /> Execute</Btn> : null;
          })()}
          <Btn onClick={() => setSelectedAction(null)}>Close</Btn>
        </div>
      </>}
    </Modal>
  </div>;
};
