// @ts-nocheck
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
  const [findingStatus, setFindingStatus] = useState("");
  const [findingSeverity, setFindingSeverity] = useState("");
  const [findingSearch, setFindingSearch] = useState("");
  const [findingEngine, setFindingEngine] = useState("");
  const [actionStatus, setActionStatus] = useState("");
  const [actionSearch, setActionSearch] = useState("");
  const [tab, setTab] = useState("Dashboard");
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const [selectedAction, setSelectedAction] = useState<any>(null);

  // ── Data loading ──────────────────────────────────────────────

  const load = async (silent = false) => {
    if (!session?.token) {
      setRisk({}); setDashboard({}); setHistory([]); setFindings([]); setActions([]);
      return;
    }
    if (!silent) setLoading(true);
    try {
      const [dash, latestRisk, riskHistory, findingRows, actionRows] = await Promise.all([
        getPostureDashboard(session),
        getPostureRisk(session),
        listPostureRiskHistory(session, 60),
        listPostureFindings(session, { limit: 300, status: findingStatus, severity: findingSeverity, engine: findingEngine }),
        listPostureActions(session, { limit: 300, status: actionStatus })
      ]);
      setDashboard(dash || {});
      setRisk(latestRisk || dash?.risk || {});
      setHistory(Array.isArray(riskHistory) ? riskHistory : []);
      setFindings(Array.isArray(findingRows) ? findingRows : []);
      setActions(Array.isArray(actionRows) ? actionRows : []);
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
    setFindingEngine(domainKey);
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
      <Tabs tabs={["Dashboard", "Findings", "Actions", "Domains"]} active={tab} onChange={setTab} />
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
