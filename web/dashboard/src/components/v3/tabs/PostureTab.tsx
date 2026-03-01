// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  Cloud,
  HardDrive,
  KeyRound,
  Link2,
  Package,
  Play,
  RefreshCcw,
  Server,
  ShieldAlert,
  Wrench
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
import { B, Btn, Card, Chk, Inp, Row2, Section, Sel } from "../legacyPrimitives";
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

const DOMAIN_META = {
  byok: { label: "BYOK", icon: Cloud },
  hyok: { label: "HYOK", icon: Link2 },
  ekm: { label: "EKM", icon: Server },
  kmip: { label: "KMIP", icon: KeyRound },
  bitlocker: { label: "BitLocker", icon: HardDrive },
  sdk: { label: "SDK / Wrapper", icon: Package }
};

function toNum(v: any): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function pct(n: number): number {
  if (!Number.isFinite(n) || n <= 0) return 0;
  if (n >= 1) return Math.min(100, n);
  return Math.min(100, n * 100);
}

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
    return {
      key,
      label: DOMAIN_META[key]?.label || key.toUpperCase(),
      icon: DOMAIN_META[key]?.icon || Activity,
      events,
      failures,
      rate,
      latency,
      interop,
      receiptMissing
    };
  });
}

/* ── Recharts custom tooltip ── */
const ChartTooltip = ({ containerStyle, children }: any) => (
  <div style={{ background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 8, padding: "8px 12px", fontSize: 10, color: C.text, boxShadow: "0 4px 20px rgba(0,0,0,.5)", ...containerStyle }}>
    {children}
  </div>
);

const RiskTrendTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <ChartTooltip>
      <div style={{ fontWeight: 700, marginBottom: 4, color: C.accent }}>{label}</div>
      <div>Risk Score: <span style={{ fontWeight: 700, color: C.text }}>{payload[0]?.value}</span></div>
    </ChartTooltip>
  );
};

const DomainBarTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <ChartTooltip>
      <div style={{ fontWeight: 700, marginBottom: 4, color: C.accent }}>{label}</div>
      {payload.map((entry: any) => (
        <div key={entry.dataKey} style={{ color: entry.color }}>
          {entry.name}: <span style={{ fontWeight: 700, color: C.text }}>{entry.value}</span>
        </div>
      ))}
    </ChartTooltip>
  );
};

const HistogramTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <ChartTooltip>
      <div style={{ fontWeight: 700, marginBottom: 4, color: C.accent }}>Score Range: {label}</div>
      <div>Findings: <span style={{ fontWeight: 700, color: C.text }}>{payload[0]?.value}</span></div>
    </ChartTooltip>
  );
};

export const PostureTab = ({ session, onToast }) => {
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
  const [actionStatus, setActionStatus] = useState("");

  const load = async (silent = false) => {
    if (!session?.token) {
      setRisk({});
      setDashboard({});
      setHistory([]);
      setFindings([]);
      setActions([]);
      return;
    }
    if (!silent) setLoading(true);
    try {
      const [dash, latestRisk, riskHistory, findingRows, actionRows] = await Promise.all([
        getPostureDashboard(session),
        getPostureRisk(session),
        listPostureRiskHistory(session, 60),
        listPostureFindings(session, { limit: 300, status: findingStatus, severity: findingSeverity }),
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
  }, [session?.token, session?.tenantId, findingStatus, findingSeverity, actionStatus]);

  const filteredFindings = useMemo(() => {
    const q = String(findingSearch || "").trim().toLowerCase();
    const rows = Array.isArray(findings) ? findings : [];
    if (!q) return rows;
    return rows.filter((item: any) => {
      const title = String(item?.title || "").toLowerCase();
      const desc = String(item?.description || "").toLowerCase();
      const ftype = String(item?.finding_type || "").toLowerCase();
      const engine = String(item?.engine || "").toLowerCase();
      return title.includes(q) || desc.includes(q) || ftype.includes(q) || engine.includes(q);
    });
  }, [findings, findingSearch]);

  const visibleFindings = useMemo(() => filteredFindings.slice(0, 120), [filteredFindings]);
  const visibleActions = useMemo(() => (Array.isArray(actions) ? actions.slice(0, 120) : []), [actions]);
  const domainMetrics = useMemo(() => extractDomainMetrics(risk?.top_signals), [risk?.top_signals]);

  /* ── Risk trend data for Recharts ── */
  const trendData = useMemo(() => {
    const items = Array.isArray(history) ? history.slice(0, 60).reverse() : [];
    return items.map((entry: any) => ({
      name: shortTS(entry?.captured_at),
      risk: Math.max(0, Math.min(100, toNum(entry?.risk_24h)))
    }));
  }, [history]);

  /* ── Domain bar chart data ── */
  const domainBarData = useMemo(() => {
    return domainMetrics.map((d: any) => ({
      name: d.label,
      Events: d.events,
      Failures: d.failures
    }));
  }, [domainMetrics]);

  /* ── Severity distribution donut data ── */
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
      { name: "Warning", value: counts.warning, fill: "#d97706" },
      { name: "Info", value: counts.info, fill: C.blue }
    ].filter((d) => d.value > 0);
  }, [findings]);

  /* ── Risk score histogram data ── */
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

  /* ── Findings status counts for progress bar ── */
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

  /* ── Radar chart data for engine scores ── */
  const radarData = useMemo(() => {
    const pred = Math.max(0, Math.min(100, Number(risk?.predictive_score || 0)));
    const prev = Math.max(0, Math.min(100, Number(risk?.preventive_score || 0)));
    const corr = Math.max(0, Math.min(100, Number(risk?.corrective_score || 0)));
    return [
      { axis: "Predictive", value: pred },
      { axis: "Preventive", value: prev },
      { axis: "Corrective", value: corr }
    ];
  }, [risk?.predictive_score, risk?.preventive_score, risk?.corrective_score]);

  const executeAction = async (action: any) => {
    const id = String(action?.id || "").trim();
    if (!id) return;
    try {
      await executePostureAction(session, id, { actor: String(session?.username || "dashboard") });
      onToast?.("Runbook action executed.");
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
      await load(true);
    } catch (error) {
      onToast?.(`Finding update failed: ${errMsg(error)}`);
    }
  };

  const runScan = async () => {
    if (!session?.token) {
      onToast?.("Login is required.");
      return;
    }
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

  const risk24 = Math.max(0, Math.min(100, Number(risk?.risk_24h || 0)));
  const risk7d = Math.max(0, Math.min(100, Number(risk?.risk_7d || 0)));
  const pred = Math.max(0, Math.min(100, Number(risk?.predictive_score || 0)));
  const prev = Math.max(0, Math.min(100, Number(risk?.preventive_score || 0)));
  const corr = Math.max(0, Math.min(100, Number(risk?.corrective_score || 0)));
  const riskTone24 = riskTone(risk24);
  const riskColor24 = riskTone24 === "red" ? C.red : riskTone24 === "amber" ? C.amber : C.green;
  const riskTone7d = riskTone(risk7d);
  const riskColor7d = riskTone7d === "red" ? C.red : riskTone7d === "amber" ? C.amber : C.green;

  /* ── Radial gauge data ── */
  const gaugeData = [
    { name: "7d", value: risk7d, fill: riskColor7d },
    { name: "24h", value: risk24, fill: riskColor24 }
  ];

  return (
    <div>
      <Section title="Posture Management" subtitle="Predictive, preventive, and corrective posture controls across core KMS + BYOK/HYOK/EKM/KMIP/BitLocker/SDK domains.">

        {/* ═══════ ROW 1: Risk Gauge + Engine Radar + Severity Donut ═══════ */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>

          {/* ── Risk Gauge (RadialBarChart) ── */}
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <ShieldAlert size={14} color={C.accent} />
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Risk Window</span>
              </div>
              <B c={riskTone24}>{`${risk24}/100`}</B>
            </div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
              <ResponsiveContainer width="100%" height={140}>
                <RadialBarChart
                  cx="50%" cy="50%"
                  innerRadius="40%" outerRadius="90%"
                  startAngle={210} endAngle={-30}
                  data={gaugeData}
                  barSize={10}
                >
                  <RadialBar
                    dataKey="value"
                    cornerRadius={5}
                    background={{ fill: C.border }}
                  />
                </RadialBarChart>
              </ResponsiveContainer>
            </div>
            <div style={{ display: "flex", justifyContent: "center", gap: 16, marginTop: 2 }}>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 9, color: C.muted }}>24h</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: riskColor24 }}>{risk24}</div>
              </div>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 9, color: C.muted }}>7d</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: riskColor7d }}>{risk7d}</div>
              </div>
            </div>
            <div style={{ fontSize: 9, color: C.muted, textAlign: "center", marginTop: 4 }}>Captured: {fmtTS(risk?.captured_at)}</div>
          </Card>

          {/* ── Engine Score Radar ── */}
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <Activity size={14} color={C.green} />
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Engine Scores</span>
              </div>
              <B c="blue">Live</B>
            </div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
              <ResponsiveContainer width="100%" height={160}>
                <RadarChart data={radarData} cx="50%" cy="50%" outerRadius="70%">
                  <PolarGrid stroke={C.border} />
                  <PolarAngleAxis
                    dataKey="axis"
                    tick={{ fill: C.dim, fontSize: 10 }}
                  />
                  <PolarRadiusAxis
                    angle={90}
                    domain={[0, 100]}
                    tick={{ fill: C.muted, fontSize: 8 }}
                    tickCount={4}
                  />
                  <Radar
                    dataKey="value"
                    stroke={C.accent}
                    fill={C.accent}
                    fillOpacity={0.2}
                    strokeWidth={2}
                  />
                </RadarChart>
              </ResponsiveContainer>
            </div>
            <div style={{ display: "flex", justifyContent: "center", gap: 14, marginTop: 2 }}>
              <div style={{ fontSize: 9, color: C.muted }}>
                Predictive: <span style={{ color: C.blue, fontWeight: 700 }}>{pred}</span>
              </div>
              <div style={{ fontSize: 9, color: C.muted }}>
                Preventive: <span style={{ color: C.amber, fontWeight: 700 }}>{prev}</span>
              </div>
              <div style={{ fontSize: 9, color: C.muted }}>
                Corrective: <span style={{ color: C.green, fontWeight: 700 }}>{corr}</span>
              </div>
            </div>
          </Card>

          {/* ── Severity Donut ── */}
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <Wrench size={14} color={C.amber} />
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Findings Breakdown</span>
              </div>
              <B c={Number(dashboard?.critical_findings || 0) > 0 ? "red" : "green"}>{Number(dashboard?.critical_findings || 0)} critical</B>
            </div>
            {severityDonut.length > 0 ? (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center" }}>
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie
                      data={severityDonut}
                      cx="50%" cy="50%"
                      innerRadius={35}
                      outerRadius={55}
                      paddingAngle={3}
                      dataKey="value"
                      strokeWidth={0}
                    >
                      {severityDonut.map((entry, idx) => (
                        <Cell key={idx} fill={entry.fill} />
                      ))}
                    </Pie>
                    <Tooltip
                      content={({ active, payload }) => {
                        if (!active || !payload?.length) return null;
                        return (
                          <ChartTooltip>
                            <span style={{ color: payload[0]?.payload?.fill, fontWeight: 700 }}>{payload[0]?.name}</span>: {payload[0]?.value}
                          </ChartTooltip>
                        );
                      }}
                    />
                    <Legend
                      verticalAlign="bottom"
                      height={28}
                      iconType="circle"
                      iconSize={8}
                      formatter={(value) => <span style={{ color: C.dim, fontSize: 9 }}>{value}</span>}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div style={{ height: 160, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <span style={{ fontSize: 10, color: C.muted }}>No findings data</span>
              </div>
            )}
            <div style={{ display: "flex", justifyContent: "center", gap: 14, marginTop: 2 }}>
              <div style={{ fontSize: 9, color: C.muted }}>
                Open: <span style={{ color: C.text, fontWeight: 700 }}>{Number(dashboard?.open_findings || 0)}</span>
              </div>
              <div style={{ fontSize: 9, color: C.muted }}>
                Pending: <span style={{ color: C.text, fontWeight: 700 }}>{Array.isArray(actions) ? actions.length : 0}</span>
              </div>
              <div style={{ fontSize: 9, color: C.muted }}>
                Tenant: <span style={{ color: C.text, fontWeight: 700 }}>{String(session?.tenantId || "-")}</span>
              </div>
            </div>
          </Card>
        </div>

        {/* ═══════ ROW 2: Domain Bar Chart + Domain Detail Cards ═══════ */}
        <Card style={{ marginTop: 10 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Domain Posture (24h)</span>
            <B c="accent">Events vs Failures</B>
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={domainBarData} barGap={2} barCategoryGap="20%">
              <XAxis
                dataKey="name"
                tick={{ fill: C.dim, fontSize: 10 }}
                axisLine={{ stroke: C.border }}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: C.muted, fontSize: 9 }}
                axisLine={false}
                tickLine={false}
                width={35}
              />
              <Tooltip content={DomainBarTooltip} cursor={{ fill: "rgba(6,214,224,.04)" }} />
              <RBar dataKey="Events" fill={C.blue} radius={[3, 3, 0, 0]} />
              <RBar dataKey="Failures" fill={C.red} radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(190px,1fr))", gap: 8, marginTop: 10 }}>
            {domainMetrics.map((domain: any) => {
              const Icon = domain.icon;
              const tone = riskTone(domain.rate);
              return (
                <div key={domain.key} style={{ border: `1px solid ${C.border}`, borderRadius: 10, padding: 10, background: C.card }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <Icon size={12} color={C.accent} />
                      <span style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>{domain.label}</span>
                    </div>
                    <B c={tone}>{`${domain.rate.toFixed(1)}%`}</B>
                  </div>
                  <div style={{ fontSize: 10, color: C.dim, marginBottom: 2 }}>
                    Events: <span style={{ color: C.text }}>{domain.events}</span>
                  </div>
                  <div style={{ fontSize: 10, color: C.dim, marginBottom: 2 }}>
                    Failures: <span style={{ color: C.text }}>{domain.failures}</span>
                  </div>
                  <div style={{ fontSize: 10, color: C.dim, marginBottom: 6 }}>
                    Avg latency: <span style={{ color: C.text }}>{domain.latency > 0 ? `${domain.latency.toFixed(1)} ms` : "-"}</span>
                  </div>
                  {domain.key === "kmip" && (
                    <div style={{ fontSize: 9, color: C.muted, marginBottom: 6 }}>
                      Interop failed: <span style={{ color: domain.interop > 0 ? C.red : C.green }}>{domain.interop}</span>
                    </div>
                  )}
                  {domain.key === "sdk" && (
                    <div style={{ fontSize: 9, color: C.muted, marginBottom: 6 }}>
                      Missing receipts: <span style={{ color: domain.receiptMissing > 0 ? C.red : C.green }}>{domain.receiptMissing}</span>
                    </div>
                  )}
                  {/* Failure rate bar */}
                  <div style={{ marginBottom: 4 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 8, color: C.muted, marginBottom: 2 }}>
                      <span>Failure Rate</span>
                      <span>{domain.rate.toFixed(1)}%</span>
                    </div>
                    <div style={{ height: 5, borderRadius: 999, border: `1px solid ${C.border}`, background: C.bg }}>
                      <div
                        style={{
                          width: `${Math.max(2, Math.min(100, domain.rate))}%`,
                          height: "100%",
                          borderRadius: 999,
                          background: tone === "red" ? C.red : tone === "amber" ? C.amber : C.green
                        }}
                      />
                    </div>
                  </div>
                  {/* Latency bar */}
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 8, color: C.muted, marginBottom: 2 }}>
                      <span>Latency</span>
                      <span>{domain.latency > 0 ? `${domain.latency.toFixed(0)}ms` : "-"}</span>
                    </div>
                    <div style={{ height: 5, borderRadius: 999, border: `1px solid ${C.border}`, background: C.bg }}>
                      <div
                        style={{
                          width: `${Math.max(2, Math.min(100, domain.latency > 0 ? Math.min(100, (domain.latency / 500) * 100) : 0))}%`,
                          height: "100%",
                          borderRadius: 999,
                          background: domain.latency >= 500 ? C.red : domain.latency >= 100 ? C.amber : C.green
                        }}
                      />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </Card>

        {/* ═══════ ROW 3: Risk Trend AreaChart + Risk Score Histogram ═══════ */}
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 10, marginTop: 10 }}>
          {/* ── Risk Trend AreaChart ── */}
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Risk Trend</span>
              <B c="blue">{trendData.length ? `${trendData[trendData.length - 1]?.risk || 0} latest` : "No history"}</B>
            </div>
            {trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <AreaChart data={trendData}>
                  <defs>
                    <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={C.accent} stopOpacity={0.25} />
                      <stop offset="95%" stopColor={C.accent} stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="name"
                    tick={{ fill: C.muted, fontSize: 8 }}
                    axisLine={{ stroke: C.border }}
                    tickLine={false}
                    interval="preserveStartEnd"
                  />
                  <YAxis
                    domain={[0, 100]}
                    tick={{ fill: C.muted, fontSize: 9 }}
                    axisLine={false}
                    tickLine={false}
                    width={30}
                  />
                  <Tooltip content={RiskTrendTooltip} cursor={{ stroke: C.borderHi, strokeDasharray: "3 3" }} />
                  <Area
                    type="monotone"
                    dataKey="risk"
                    stroke={C.accent}
                    strokeWidth={2}
                    fill="url(#riskGradient)"
                    dot={{ fill: C.accent, r: 2, strokeWidth: 0 }}
                    activeDot={{ fill: C.accent, r: 4, stroke: C.bg, strokeWidth: 2 }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: 180, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <span style={{ fontSize: 10, color: C.muted }}>No risk history yet.</span>
              </div>
            )}
          </Card>

          {/* ── Risk Score Distribution Histogram ── */}
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Risk Distribution</span>
              <B c="accent">{findings.length} findings</B>
            </div>
            {findings.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={riskHistogram}>
                  <XAxis
                    dataKey="name"
                    tick={{ fill: C.dim, fontSize: 9 }}
                    axisLine={{ stroke: C.border }}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: C.muted, fontSize: 9 }}
                    axisLine={false}
                    tickLine={false}
                    width={25}
                    allowDecimals={false}
                  />
                  <Tooltip content={HistogramTooltip} cursor={{ fill: "rgba(6,214,224,.04)" }} />
                  <RBar dataKey="count" radius={[4, 4, 0, 0]}>
                    {riskHistogram.map((entry, idx) => (
                      <Cell key={idx} fill={entry.fill} />
                    ))}
                  </RBar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: 180, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <span style={{ fontSize: 10, color: C.muted }}>No findings data</span>
              </div>
            )}
          </Card>
        </div>

        {/* ═══════ Control Bar ═══════ */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 10, marginBottom: 10, alignItems: "center" }}>
          <Inp w={250} value={findingSearch} onChange={(e) => setFindingSearch(e.target.value)} placeholder="Search finding title/engine/type..." />
          <Sel w={130} value={findingSeverity} onChange={(e) => setFindingSeverity(String(e.target.value || ""))}>
            <option value="">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
          </Sel>
          <Sel w={150} value={findingStatus} onChange={(e) => setFindingStatus(String(e.target.value || ""))}>
            <option value="">All Finding Status</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
            <option value="reopened">Reopened</option>
          </Sel>
          <Sel w={140} value={actionStatus} onChange={(e) => setActionStatus(String(e.target.value || ""))}>
            <option value="">All Action Status</option>
            <option value="suggested">Suggested</option>
            <option value="pending">Pending</option>
            <option value="approved">Approved</option>
            <option value="executed">Executed</option>
            <option value="failed">Failed</option>
          </Sel>
          <Chk label="Sync audit before scan" checked={syncAudit} onChange={() => setSyncAudit((v) => !v)} />
          <Btn small onClick={() => load(false)} disabled={loading}>
            <RefreshCcw size={12} /> {loading ? "Refreshing..." : "Refresh"}
          </Btn>
          <Btn small primary onClick={runScan} disabled={running}>
            {running ? "Running..." : "Run Scan"}
          </Btn>
        </div>

        {/* ═══════ Findings Status Progress Bar ═══════ */}
        {statusTotal > 0 && (
          <Card style={{ marginBottom: 10 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: C.text }}>Findings Resolution Status</span>
              <span style={{ fontSize: 9, color: C.muted }}>{statusTotal} total</span>
            </div>
            <div style={{ display: "flex", height: 14, borderRadius: 7, overflow: "hidden", border: `1px solid ${C.border}` }}>
              {statusCounts.resolved > 0 && (
                <div style={{ width: `${(statusCounts.resolved / statusTotal) * 100}%`, background: C.green, transition: "width .4s" }} title={`Resolved: ${statusCounts.resolved}`} />
              )}
              {statusCounts.acknowledged > 0 && (
                <div style={{ width: `${(statusCounts.acknowledged / statusTotal) * 100}%`, background: C.blue, transition: "width .4s" }} title={`Acknowledged: ${statusCounts.acknowledged}`} />
              )}
              {statusCounts.open > 0 && (
                <div style={{ width: `${(statusCounts.open / statusTotal) * 100}%`, background: C.amber, transition: "width .4s" }} title={`Open: ${statusCounts.open}`} />
              )}
              {statusCounts.reopened > 0 && (
                <div style={{ width: `${(statusCounts.reopened / statusTotal) * 100}%`, background: C.red, transition: "width .4s" }} title={`Reopened: ${statusCounts.reopened}`} />
              )}
            </div>
            <div style={{ display: "flex", gap: 14, marginTop: 6, flexWrap: "wrap" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 9, color: C.dim }}>
                <div style={{ width: 8, height: 8, borderRadius: 2, background: C.green }} />
                Resolved ({statusCounts.resolved})
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 9, color: C.dim }}>
                <div style={{ width: 8, height: 8, borderRadius: 2, background: C.blue }} />
                Acknowledged ({statusCounts.acknowledged})
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 9, color: C.dim }}>
                <div style={{ width: 8, height: 8, borderRadius: 2, background: C.amber }} />
                Open ({statusCounts.open})
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 9, color: C.dim }}>
                <div style={{ width: 8, height: 8, borderRadius: 2, background: C.red }} />
                Reopened ({statusCounts.reopened})
              </div>
            </div>
          </Card>
        )}

        {/* ═══════ Findings Table ═══════ */}
        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Findings</span>
            <span style={{ fontSize: 9, color: C.muted }}>{visibleFindings.length} shown</span>
          </div>
          <div style={{ maxHeight: 280, overflow: "auto", border: `1px solid ${C.border}`, borderRadius: 8 }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Title</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Engine</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Severity</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Risk</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Status</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Detected</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {visibleFindings.map((item: any) => (
                  <tr key={String(item.id)} style={{ borderBottom: `1px solid ${C.border}` }}>
                    <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, maxWidth: 320 }}>
                      <div style={{ fontWeight: 600 }}>{String(item?.title || item?.finding_type || "-")}</div>
                      <div style={{ fontSize: 9, color: C.muted, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {String(item?.recommended_action || "-")}
                      </div>
                    </td>
                    <td style={{ padding: "8px 10px", fontSize: 10, color: C.dim }}>{String(item?.engine || "-")}</td>
                    <td style={{ padding: "8px 10px", fontSize: 10 }}>
                      <B c={severityTone(String(item?.severity || ""))}>{String(item?.severity || "-")}</B>
                    </td>
                    <td style={{ padding: "8px 10px", fontSize: 10, color: C.text, fontWeight: 700 }}>{Number(item?.risk_score || 0)}</td>
                    <td style={{ padding: "8px 10px", fontSize: 10, color: C.dim }}>{String(item?.status || "-")}</td>
                    <td style={{ padding: "8px 10px", fontSize: 10, color: C.muted }}>{fmtTS(item?.detected_at)}</td>
                    <td style={{ padding: "8px 10px", fontSize: 10 }}>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        <Btn small onClick={() => patchFinding(item, "acknowledged")} disabled={String(item?.status || "").toLowerCase() === "acknowledged"}>
                          Ack
                        </Btn>
                        <Btn small onClick={() => patchFinding(item, "resolved")} disabled={String(item?.status || "").toLowerCase() === "resolved"}>
                          Resolve
                        </Btn>
                        <Btn small onClick={() => patchFinding(item, "reopened")}>Reopen</Btn>
                      </div>
                    </td>
                  </tr>
                ))}
                {visibleFindings.length === 0 && (
                  <tr>
                    <td colSpan={7} style={{ padding: 12, fontSize: 10, color: C.muted }}>
                      No findings for current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {filteredFindings.length > visibleFindings.length && (
            <div style={{ marginTop: 6, fontSize: 9, color: C.muted }}>
              Showing first {visibleFindings.length} findings of {filteredFindings.length}. Narrow filters to inspect specific domains faster.
            </div>
          )}
        </Card>

        {/* ═══════ Remediation Actions Table ═══════ */}
        <Card style={{ marginTop: 10 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Remediation Actions</span>
            <span style={{ fontSize: 9, color: C.muted }}>{visibleActions.length} actions</span>
          </div>
          <div style={{ maxHeight: 220, overflow: "auto", border: `1px solid ${C.border}`, borderRadius: 8 }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Action Type</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Safety Gate</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Status</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Result</th>
                  <th style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, color: C.muted }}>Execute</th>
                </tr>
              </thead>
              <tbody>
                {visibleActions.map((item: any) => {
                  const status = String(item?.status || "").toLowerCase();
                  const canExec = status === "pending" || status === "approved" || status === "queued" || status === "suggested";
                  return (
                    <tr key={String(item.id)} style={{ borderBottom: `1px solid ${C.border}` }}>
                      <td style={{ padding: "8px 10px", fontSize: 10, color: C.text }}>{String(item?.action_type || "-")}</td>
                      <td style={{ padding: "8px 10px", fontSize: 10, color: C.dim }}>{String(item?.safety_gate || "-")}</td>
                      <td style={{ padding: "8px 10px", fontSize: 10 }}>
                        <B c={actionStatusTone(status)}>{String(item?.status || "-")}</B>
                      </td>
                      <td style={{ padding: "8px 10px", fontSize: 10, color: C.muted, maxWidth: 320, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {String(item?.result_message || item?.recommended_action || "-")}
                      </td>
                      <td style={{ padding: "8px 10px", fontSize: 10 }}>
                        <Btn small primary onClick={() => executeAction(item)} disabled={!canExec}>
                          <Play size={11} /> Execute
                        </Btn>
                      </td>
                    </tr>
                  );
                })}
                {visibleActions.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{ padding: 12, fontSize: 10, color: C.muted }}>
                      No remediation actions.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>

        <div style={{ marginTop: 8, fontSize: 9, color: C.muted }}>
          Posture scoring now includes BYOK, HYOK, EKM, KMIP, BitLocker, and SDK/Wrapper activity in addition to core KMS risk signals.
        </div>
      </Section>
    </div>
  );
};
