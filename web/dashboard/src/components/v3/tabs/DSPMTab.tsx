// @ts-nocheck
import React, { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  FileSearch,
  KeyRound,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Scan,
  Tag,
  TrendingUp,
  XCircle,
  Zap,
} from "lucide-react";
import { B, Bar, Btn, Card, FG, Inp, Row3, Section, Sel, Stat } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  classifyAsset,
  getDiscoverySummary,
  listDiscoveryAssets,
  listDiscoveryScans,
  startDiscoveryScan,
} from "../../../lib/discovery";
import { getCompliancePostureBreakdown, getComplianceAuditAnomalies } from "../../../lib/compliance";
import { getDataRiskSummary, getKeyRiskRanking, getRiskRemediation } from "../../../lib/dri";

// ─── Shared styles ────────────────────────────────────────────────────────────
const CELL: React.CSSProperties = {
  padding: "10px 14px",
  color: C.dim,
  fontSize: 11,
  verticalAlign: "middle",
};
const TH: React.CSSProperties = {
  padding: "8px 14px",
  fontSize: 9,
  fontWeight: 700,
  color: C.muted,
  textTransform: "uppercase",
  letterSpacing: "0.1em",
  textAlign: "left",
  background: C.surface,
  borderBottom: `1px solid ${C.border}`,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
function riskScore(asset: any): number {
  let score = 0;
  if (!asset.pqc_ready) score += 30;
  if (asset.strength_bits > 0 && asset.strength_bits < 128) score += 40;
  if (asset.classification === "unclassified") score += 20;
  if (asset.status === "active" && !asset.pqc_ready) score += 10;
  return Math.min(100, score);
}

function riskLevel(score: number): string {
  if (score >= 70) return "critical";
  if (score >= 40) return "high";
  if (score >= 20) return "medium";
  return "low";
}

function riskColor(level: string): string {
  switch (level) {
    case "critical": return C.red;
    case "high": return C.orange;
    case "medium": return C.amber;
    default: return C.green;
  }
}

function riskDimColor(level: string): string {
  switch (level) {
    case "critical": return C.redDim;
    case "high": return C.orangeDim;
    case "medium": return C.amberDim;
    default: return C.greenDim;
  }
}

function scoreColor(n: number): string {
  if (n >= 80) return C.green;
  if (n >= 60) return C.amber;
  return C.red;
}

function fmtDate(s: string): string {
  if (!s) return "—";
  const d = new Date(s);
  if (isNaN(d.getTime())) return s;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function fmtDuration(start: string, end?: string): string {
  if (!start) return "—";
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const sec = Math.round((e - s) / 1000);
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.round(sec / 60)}m`;
  return `${(sec / 3600).toFixed(1)}h`;
}

function RiskBadge({ level }: { level: string }) {
  return (
    <span style={{
      background: riskDimColor(level),
      color: riskColor(level),
      borderRadius: 5,
      padding: "2px 8px",
      fontSize: 9,
      fontWeight: 700,
      textTransform: "uppercase",
      letterSpacing: 0.4,
    }}>
      {level}
    </span>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────
export function DSPMTab({ session }: { session: any }) {
  const [summary, setSummary] = useState<any>(null);
  const [assets, setAssets] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [posture, setPosture] = useState<any>(null);
  const [anomalies, setAnomalies] = useState<any[]>([]);
  const [driSummary, setDriSummary] = useState<any>(null);
  const [keyRisks, setKeyRisks] = useState<any[]>([]);
  const [remediations, setRemediations] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [classifyingId, setClassifyingId] = useState<string | null>(null);

  // Filters
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterAlgo, setFilterAlgo] = useState("all");
  const [filterClass, setFilterClass] = useState("all");
  const [filterRisk, setFilterRisk] = useState("all");
  const [searchText, setSearchText] = useState("");
  const [expandedScan, setExpandedScan] = useState<string | null>(null);
  const [expandedAsset, setExpandedAsset] = useState<string | null>(null);

  // Scan config
  const [scanScope, setScanScope] = useState("all");

  const [view, setView] = useState<"overview" | "assets" | "scans" | "risk">("overview");

  async function load() {
    setLoading(true);
    try {
      const [sumRes, assetsRes, scansRes, postureRes, anomalyRes, driSumRes, keyRiskRes, remRes] =
        await Promise.allSettled([
          getDiscoverySummary(session),
          listDiscoveryAssets(session, { limit: 200 }),
          listDiscoveryScans(session, 20),
          getCompliancePostureBreakdown(session),
          getComplianceAuditAnomalies(session),
          getDataRiskSummary(session),
          getKeyRiskRanking(session, 50),
          getRiskRemediation(session),
        ]);
      if (sumRes.status === "fulfilled") setSummary(sumRes.value);
      if (assetsRes.status === "fulfilled") setAssets(assetsRes.value);
      if (scansRes.status === "fulfilled") setScans(scansRes.value);
      if (postureRes.status === "fulfilled") setPosture(postureRes.value);
      if (anomalyRes.status === "fulfilled") setAnomalies(anomalyRes.value);
      if (driSumRes.status === "fulfilled") setDriSummary(driSumRes.value);
      if (keyRiskRes.status === "fulfilled") setKeyRisks(keyRiskRes.value);
      if (remRes.status === "fulfilled") setRemediations(remRes.value);
    } finally {
      setLoading(false);
    }
  }

  async function handleScan() {
    setScanning(true);
    try {
      const scopeTypes =
        scanScope === "all"
          ? ["keys", "certificates", "secrets"]
          : scanScope === "keys"
          ? ["keys"]
          : scanScope === "certs"
          ? ["certificates"]
          : ["secrets"];
      await startDiscoveryScan(session, scopeTypes);
      setTimeout(() => void load(), 2000);
    } finally {
      setScanning(false);
    }
  }

  async function handleClassify(assetId: string, classification: string) {
    setClassifyingId(assetId);
    try {
      await classifyAsset(session, assetId, classification);
      setAssets(prev => prev.map(a => (a.id === assetId ? { ...a, classification } : a)));
    } finally {
      setClassifyingId(null);
    }
  }

  useEffect(() => { void load(); }, [session?.token, session?.tenantId]);

  const assetsWithRisk = useMemo(() =>
    assets.map(a => ({ ...a, _score: riskScore(a), _level: riskLevel(riskScore(a)) })),
    [assets]
  );

  const filteredAssets = useMemo(() => {
    return assetsWithRisk.filter(a => {
      if (filterStatus !== "all" && a.status !== filterStatus) return false;
      if (filterAlgo !== "all" && a.algorithm !== filterAlgo) return false;
      if (filterClass !== "all" && a.classification !== filterClass) return false;
      if (filterRisk !== "all" && a._level !== filterRisk) return false;
      if (searchText && !((a.name || a.id || "").toLowerCase().includes(searchText.toLowerCase()))) return false;
      return true;
    });
  }, [assetsWithRisk, filterStatus, filterAlgo, filterClass, filterRisk, searchText]);

  const uniqueAlgos = useMemo(() => [...new Set(assets.map(a => a.algorithm).filter(Boolean))], [assets]);

  const riskDist = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    assetsWithRisk.forEach(a => { counts[a._level] = (counts[a._level] || 0) + 1; });
    return counts;
  }, [assetsWithRisk]);

  const totalAssets = assets.length;
  const criticalCount = assetsWithRisk.filter(a => a._level === "critical").length;
  const pqcPct = summary?.pqc_readiness_percent ?? 0;
  const overallScore = useMemo(() => {
    if (!assetsWithRisk.length) return posture?.overall_score ?? 0;
    const avg = assetsWithRisk.reduce((s, a) => s + a._score, 0) / assetsWithRisk.length;
    return Math.round(100 - avg);
  }, [assetsWithRisk, posture]);

  const tabDefs = [
    { id: "overview", label: "Overview" },
    { id: "assets", label: `Asset Inventory${totalAssets ? ` (${totalAssets})` : ""}` },
    { id: "scans", label: `Scan History${scans.length ? ` (${scans.length})` : ""}` },
    { id: "risk", label: "Risk Intelligence" },
  ] as const;

  return (
    <div style={{ padding: "20px 24px", fontFamily: '"IBM Plex Sans", sans-serif', color: C.text, minHeight: "100%" }}>

      {/* ── Page header ────────────────────────────────────────────────────── */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 5 }}>
            <div style={{ width: 34, height: 34, borderRadius: 9, background: C.accentDim, display: "flex", alignItems: "center", justifyContent: "center" }}>
              <ShieldCheck size={17} color={C.accent} />
            </div>
            <div>
              <div style={{ fontSize: 17, fontWeight: 700, color: C.text, letterSpacing: -0.4 }}>Data Security Posture</div>
              <div style={{ fontSize: 11, color: C.muted, marginTop: 1 }}>Crypto asset discovery, risk scoring, and guided remediation</div>
            </div>
            <B c="green" pulse>Live</B>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <Btn onClick={() => void load()} disabled={loading}>
            <RefreshCw size={11} style={{ animation: loading ? "spin 1s linear infinite" : "none" }} />
            {loading ? "Loading…" : "Refresh"}
          </Btn>
          <Btn primary onClick={() => void handleScan()} disabled={scanning}>
            <FileSearch size={12} />
            {scanning ? "Scanning…" : "Run Discovery"}
          </Btn>
        </div>
      </div>

      {/* ── Hero stat row ────────────────────────────────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10, marginBottom: 20 }}>
        <div style={{ background: `linear-gradient(135deg, ${C.card} 0%, ${scoreColor(overallScore) === C.green ? C.greenTint : scoreColor(overallScore) === C.amber ? C.amberTint : C.redTint} 100%)`, borderRadius: 11, border: `1px solid ${C.border}`, padding: "14px 16px" }}>
          <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.9, marginBottom: 6 }}>Overall Risk Score</div>
          <div style={{ fontSize: 34, fontWeight: 800, color: scoreColor(overallScore), letterSpacing: -1.5, lineHeight: 1 }}>{loading ? "—" : overallScore}</div>
          <div style={{ fontSize: 9, color: C.muted, marginTop: 4 }}>/ 100 — {overallScore >= 80 ? "Healthy" : overallScore >= 60 ? "Moderate" : "At Risk"}</div>
          <div style={{ marginTop: 8 }}>
            <Bar pct={overallScore} color={scoreColor(overallScore)} />
          </div>
        </div>
        <Stat l="Total Assets" v={loading ? "—" : totalAssets} s={`${summary?.total_scanned ?? 0} scanned`} c="accent" i={Shield} />
        <Stat l="Critical Assets" v={loading ? "—" : criticalCount} s={criticalCount > 0 ? "require attention" : "all clear"} c={criticalCount > 0 ? "red" : "green"} i={ShieldAlert} />
        <Stat l="PQC Readiness" v={loading ? "—" : `${pqcPct.toFixed(0)}%`} s={`${summary?.pqc_ready_count ?? 0} of ${totalAssets} keys`} c="accent" i={Zap} />
        <Stat l="Compliance Health" v={loading ? "—" : `${posture?.overall_score ?? 0}`} s="posture score" c={scoreColor(posture?.overall_score ?? 0) === C.green ? "green" : scoreColor(posture?.overall_score ?? 0) === C.amber ? "amber" : "red"} i={ShieldCheck} />
      </div>

      {/* ── Tab navigation ──────────────────────────────────────────────────── */}
      <div style={{ display: "flex", gap: 0, marginBottom: 20, borderBottom: `1px solid ${C.border}` }}>
        {tabDefs.map(t => (
          <button
            key={t.id}
            onClick={() => setView(t.id as any)}
            style={{
              padding: "9px 18px",
              border: "none",
              background: "transparent",
              cursor: "pointer",
              fontSize: 11,
              fontWeight: view === t.id ? 700 : 400,
              color: view === t.id ? C.accent : C.muted,
              borderBottom: view === t.id ? `2px solid ${C.accent}` : "2px solid transparent",
              marginBottom: -1,
              letterSpacing: 0.1,
              transition: "color .15s",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ══════════════════════════════════════════════════════════════════════
          OVERVIEW VIEW
      ══════════════════════════════════════════════════════════════════════ */}
      {view === "overview" && (
        <div>
          {/* Risk distribution + Top risks */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 16 }}>
            {/* Risk distribution */}
            <Card>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 14, letterSpacing: -0.1 }}>Risk Distribution</div>
              {totalAssets === 0 ? (
                <div style={{ textAlign: "center", padding: "24px 0", color: C.muted, fontSize: 11 }}>Run a discovery scan to populate data.</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {[
                    { label: "Critical", key: "critical", color: C.red },
                    { label: "High", key: "high", color: C.orange },
                    { label: "Medium", key: "medium", color: C.amber },
                    { label: "Low", key: "low", color: C.green },
                  ].map(({ label, key, color }) => {
                    const count = riskDist[key] || 0;
                    const pct = totalAssets > 0 ? Math.round((count / totalAssets) * 100) : 0;
                    return (
                      <div key={key}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                          <span style={{ fontSize: 10, color: C.dim, fontWeight: 600 }}>{label}</span>
                          <span style={{ fontSize: 10, color, fontWeight: 700 }}>{count} <span style={{ color: C.muted, fontWeight: 400 }}>({pct}%)</span></span>
                        </div>
                        <Bar pct={pct} color={color} />
                      </div>
                    );
                  })}
                  <div style={{ marginTop: 4, paddingTop: 10, borderTop: `1px solid ${C.border}`, display: "flex", gap: 6, flexWrap: "wrap" }}>
                    {Object.entries(summary?.algorithm_distribution ?? {}).slice(0, 6).map(([algo, count]) => (
                      <span key={algo} style={{ fontSize: 9, background: C.accentDim, color: C.accent, borderRadius: 4, padding: "2px 7px", fontWeight: 600 }}>
                        {algo}: {String(count)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </Card>

            {/* Top risks */}
            <Card>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 14, letterSpacing: -0.1 }}>Top Risk Items</div>
              {assetsWithRisk.length === 0 ? (
                <div style={{ textAlign: "center", padding: "24px 0", color: C.muted, fontSize: 11 }}>No assets found yet.</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                  {assetsWithRisk
                    .sort((a, b) => b._score - a._score)
                    .slice(0, 5)
                    .map((a, idx) => (
                      <div key={a.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 10px", background: C.surface, borderRadius: 7, border: `1px solid ${C.border}` }}>
                        <div style={{ width: 20, height: 20, borderRadius: 10, background: riskDimColor(a._level), display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                          <span style={{ fontSize: 9, fontWeight: 700, color: riskColor(a._level) }}>#{idx + 1}</span>
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: 11, color: C.text, fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                            {a.name || a.id?.slice(0, 16) + "…"}
                          </div>
                          <div style={{ fontSize: 9, color: C.muted, marginTop: 1 }}>
                            {[
                              !a.pqc_ready && "Non-PQC",
                              a.strength_bits > 0 && a.strength_bits < 128 && "Weak key (<128b)",
                              a.classification === "unclassified" && "Unclassified",
                            ].filter(Boolean).join(" · ") || a.algorithm || "Review recommended"}
                          </div>
                        </div>
                        <RiskBadge level={a._level} />
                        <div style={{ display: "flex", alignItems: "center", gap: 4, flexShrink: 0 }}>
                          <div style={{ width: 36, height: 4, background: C.border, borderRadius: 2, overflow: "hidden" }}>
                            <div style={{ width: `${a._score}%`, height: "100%", background: riskColor(a._level), borderRadius: 2 }} />
                          </div>
                          <span style={{ fontSize: 9, color: riskColor(a._level), fontWeight: 700, width: 18 }}>{a._score}</span>
                        </div>
                      </div>
                    ))}
                </div>
              )}
            </Card>
          </div>

          {/* Security posture scores */}
          {posture && (
            <Section title="Security Posture Scores">
              <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 10 }}>
                {[
                  { label: "Overall", value: posture.overall_score },
                  { label: "Key Hygiene", value: posture.key_hygiene },
                  { label: "Policy Compliance", value: posture.policy_compliance },
                  { label: "Access Security", value: posture.access_security },
                  { label: "Crypto Posture", value: posture.crypto_posture },
                  { label: "PQC Readiness", value: posture.pqc_readiness },
                ].map(({ label, value }) => (
                  <div key={label} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "12px 14px" }}>
                    <div style={{ fontSize: 9, color: C.muted, marginBottom: 6, textTransform: "uppercase", letterSpacing: 0.8 }}>{label}</div>
                    <div style={{ fontSize: 24, fontWeight: 800, color: scoreColor(value ?? 0), letterSpacing: -0.8 }}>{value ?? 0}</div>
                    <div style={{ marginTop: 6 }}>
                      <Bar pct={value ?? 0} color={scoreColor(value ?? 0)} />
                    </div>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {/* Recent scans + start scan */}
          <Section
            title={`Recent Scans${scans.length ? ` (${scans.length})` : ""}`}
            actions={
              <Btn primary small onClick={() => void handleScan()} disabled={scanning}>
                <FileSearch size={11} />{scanning ? "Starting…" : "Start New Scan"}
              </Btn>
            }
          >
            {scans.length === 0 ? (
              <div style={{ textAlign: "center", padding: "20px 0", color: C.muted, fontSize: 11 }}>No scans have been run yet.</div>
            ) : (
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Scan ID", "Type", "Status", "Started", "Duration", "Assets Found"].map(h => (
                        <th key={h} style={TH}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {scans.slice(0, 6).map((s: any, idx) => (
                      <tr
                        key={s.id}
                        style={{ background: idx % 2 === 0 ? "transparent" : C.surface, borderBottom: `1px solid ${C.border}22` }}
                      >
                        <td style={{ ...CELL, fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: C.accent }}>{s.id?.slice(0, 14)}…</td>
                        <td style={CELL}>{Array.isArray(s.scan_type) ? s.scan_type.join(", ") : String(s.scan_type || "full")}</td>
                        <td style={CELL}>
                          <B c={s.status === "completed" ? "green" : s.status === "running" ? "amber" : s.status === "failed" ? "red" : "blue"}>
                            {s.status}
                          </B>
                        </td>
                        <td style={{ ...CELL, fontSize: 10 }}>{fmtDate(s.started_at)}</td>
                        <td style={{ ...CELL, fontSize: 10 }}>{fmtDuration(s.started_at, s.completed_at)}</td>
                        <td style={{ ...CELL, color: C.text, fontWeight: 600 }}>{s.assets_found ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>

          {/* Anomalies */}
          {anomalies.length > 0 && (
            <Section title="Detected Anomalies">
              <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                {anomalies.slice(0, 5).map((a: any, i) => (
                  <div key={a.id || i} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 14px", background: C.card, borderRadius: 8, border: `1px solid ${a.severity === "critical" ? C.red + "44" : C.border}` }}>
                    <AlertTriangle size={14} color={a.severity === "critical" ? C.red : C.amber} strokeWidth={2} />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{a.description}</div>
                      <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{a.type} · {a.count} occurrence{a.count !== 1 ? "s" : ""} · {fmtDate(a.detected_at)}</div>
                    </div>
                    <B c={a.severity === "critical" ? "red" : a.severity === "warning" ? "amber" : "green"}>{a.severity}</B>
                  </div>
                ))}
              </div>
            </Section>
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          ASSETS VIEW
      ══════════════════════════════════════════════════════════════════════ */}
      {view === "assets" && (
        <div>
          {/* Filter bar */}
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 14, flexWrap: "wrap" }}>
            <div style={{ flex: "1 1 180px", minWidth: 160 }}>
              <Inp
                placeholder="Search by name or key ID…"
                value={searchText}
                onChange={e => setSearchText(e.target.value)}
              />
            </div>
            <div style={{ minWidth: 130 }}>
              <Sel value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
                <option value="all">All Status</option>
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
                <option value="revoked">Revoked</option>
              </Sel>
            </div>
            <div style={{ minWidth: 140 }}>
              <Sel value={filterAlgo} onChange={e => setFilterAlgo(e.target.value)}>
                <option value="all">All Algorithms</option>
                {uniqueAlgos.map(a => <option key={a} value={a}>{a}</option>)}
              </Sel>
            </div>
            <div style={{ minWidth: 140 }}>
              <Sel value={filterClass} onChange={e => setFilterClass(e.target.value)}>
                <option value="all">All Classifications</option>
                {["public", "internal", "confidential", "restricted", "unclassified"].map(c => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </Sel>
            </div>
            <div style={{ minWidth: 120 }}>
              <Sel value={filterRisk} onChange={e => setFilterRisk(e.target.value)}>
                <option value="all">All Risk</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </Sel>
            </div>
            <span style={{ fontSize: 10, color: C.muted, whiteSpace: "nowrap", padding: "0 4px" }}>
              {filteredAssets.length} / {totalAssets} assets
            </span>
          </div>

          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
            {filteredAssets.length === 0 ? (
              <div style={{ textAlign: "center", padding: "48px 20px", color: C.muted }}>
                <Shield size={28} color={C.border} style={{ marginBottom: 10 }} />
                <div style={{ fontSize: 12 }}>
                  {totalAssets === 0
                    ? "No assets discovered. Run a discovery scan to populate inventory."
                    : "No assets match the current filters."}
                </div>
              </div>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {["Key ID / Name", "Algorithm", "Strength", "Status", "Classification", "PQC Ready", "Risk Score", "Last Seen"].map(h => (
                      <th key={h} style={TH}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredAssets.map((a, idx) => (
                    <React.Fragment key={a.id}>
                      <tr
                        onClick={() => setExpandedAsset(expandedAsset === a.id ? null : a.id)}
                        style={{
                          background: idx % 2 === 0 ? "transparent" : C.surface,
                          borderBottom: expandedAsset === a.id ? "none" : `1px solid ${C.border}22`,
                          cursor: "pointer",
                        }}
                        onMouseEnter={e => { e.currentTarget.style.background = C.cardHover; }}
                        onMouseLeave={e => { e.currentTarget.style.background = idx % 2 === 0 ? "transparent" : C.surface; }}
                      >
                        <td style={{ ...CELL, color: C.text }}>
                          <div style={{ fontWeight: 600, fontSize: 11 }}>{a.name || a.id?.slice(0, 18) + "…"}</div>
                          <div style={{ fontSize: 9, color: C.muted, marginTop: 1, fontFamily: "'JetBrains Mono',monospace" }}>{a.source} · {a.location}</div>
                        </td>
                        <td style={CELL}><B c="accent">{a.algorithm || "—"}</B></td>
                        <td style={{ ...CELL, color: (a.strength_bits > 0 && a.strength_bits < 128) ? C.red : C.text, fontWeight: 600 }}>
                          {a.strength_bits > 0 ? `${a.strength_bits}b` : "—"}
                        </td>
                        <td style={CELL}><B c={a.status === "active" ? "green" : a.status === "revoked" ? "red" : "amber"}>{a.status || "unknown"}</B></td>
                        <td style={CELL}>
                          <select
                            value={a.classification || "unclassified"}
                            onClick={e => e.stopPropagation()}
                            onChange={e => { e.stopPropagation(); void handleClassify(a.id, e.target.value); }}
                            disabled={classifyingId === a.id}
                            style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 5, padding: "3px 7px", color: C.text, fontSize: 10, cursor: "pointer" }}
                          >
                            {["unclassified", "public", "internal", "confidential", "restricted"].map(c => (
                              <option key={c} value={c}>{c}</option>
                            ))}
                          </select>
                        </td>
                        <td style={{ ...CELL, textAlign: "center" }}>
                          {a.pqc_ready
                            ? <CheckCircle2 size={14} color={C.green} />
                            : <XCircle size={14} color={C.red} />}
                        </td>
                        <td style={CELL}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <div style={{ width: 44, height: 5, background: C.border, borderRadius: 3, overflow: "hidden" }}>
                              <div style={{ width: `${a._score}%`, height: "100%", background: riskColor(a._level), borderRadius: 3 }} />
                            </div>
                            <span style={{ fontSize: 10, color: riskColor(a._level), fontWeight: 700, minWidth: 18 }}>{a._score}</span>
                            <RiskBadge level={a._level} />
                          </div>
                        </td>
                        <td style={{ ...CELL, fontSize: 10 }}>{fmtDate(a.last_seen)}</td>
                      </tr>
                      {expandedAsset === a.id && (
                        <tr key={a.id + "-detail"} style={{ background: C.accentDim, borderBottom: `1px solid ${C.border}22` }}>
                          <td colSpan={8} style={{ padding: "12px 20px" }}>
                            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, fontSize: 11 }}>
                              <div><span style={{ color: C.muted }}>Full ID: </span><span style={{ color: C.accent, fontFamily: "'JetBrains Mono',monospace", fontSize: 10 }}>{a.id}</span></div>
                              <div><span style={{ color: C.muted }}>Source: </span><span style={{ color: C.text }}>{a.source || "—"}</span></div>
                              <div><span style={{ color: C.muted }}>Location: </span><span style={{ color: C.text }}>{a.location || "—"}</span></div>
                              <div><span style={{ color: C.muted }}>Key Type: </span><span style={{ color: C.text }}>{a.asset_type || a.key_type || "—"}</span></div>
                              <div><span style={{ color: C.muted }}>Created: </span><span style={{ color: C.text }}>{fmtDate(a.created_at)}</span></div>
                              <div><span style={{ color: C.muted }}>Expires: </span><span style={{ color: C.text }}>{fmtDate(a.expires_at)}</span></div>
                              <div><span style={{ color: C.muted }}>Risk Factors: </span><span style={{ color: C.red }}>
                                {[!a.pqc_ready && "Non-PQC", a.strength_bits < 128 && a.strength_bits > 0 && "Weak strength", a.classification === "unclassified" && "Unclassified"].filter(Boolean).join(", ") || "None"}
                              </span></div>
                              <div><span style={{ color: C.muted }}>Metadata: </span><span style={{ color: C.dim, fontFamily: "'JetBrains Mono',monospace", fontSize: 10 }}>{JSON.stringify(a.metadata ?? {}).slice(0, 60)}</span></div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          SCANS VIEW
      ══════════════════════════════════════════════════════════════════════ */}
      {view === "scans" && (
        <div>
          {/* Scan launcher */}
          <Card style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 12 }}>Start New Discovery Scan</div>
            <div style={{ display: "flex", gap: 12, alignItems: "flex-end", flexWrap: "wrap" }}>
              <div style={{ minWidth: 200 }}>
                <FG label="Scope">
                  <Sel value={scanScope} onChange={e => setScanScope(e.target.value)}>
                    <option value="all">Full Scope (keys, certs, secrets)</option>
                    <option value="keys">Keys Only</option>
                    <option value="certs">Certificates Only</option>
                    <option value="secrets">Secrets Only</option>
                  </Sel>
                </FG>
              </div>
              <div>
                <Btn primary onClick={() => void handleScan()} disabled={scanning}>
                  <Scan size={12} />
                  {scanning ? "Launching scan…" : "Start Discovery Scan"}
                </Btn>
              </div>
            </div>
          </Card>

          {/* Scan history table */}
          <Section title={`Scan History (${scans.length})`}>
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
              {scans.length === 0 ? (
                <div style={{ textAlign: "center", padding: "48px 20px", color: C.muted }}>
                  <FileSearch size={28} color={C.border} style={{ marginBottom: 10 }} />
                  <div style={{ fontSize: 12 }}>No scans have been run yet.</div>
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Scan ID", "Scope / Type", "Status", "Started", "Duration", "Assets Found", ""].map(h => (
                        <th key={h} style={TH}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map((s: any, idx) => (
                      <React.Fragment key={s.id}>
                        <tr
                          onClick={() => setExpandedScan(expandedScan === s.id ? null : s.id)}
                          style={{
                            background: idx % 2 === 0 ? "transparent" : C.surface,
                            borderBottom: expandedScan === s.id ? "none" : `1px solid ${C.border}22`,
                            cursor: "pointer",
                          }}
                          onMouseEnter={e => { e.currentTarget.style.background = C.cardHover; }}
                          onMouseLeave={e => { e.currentTarget.style.background = idx % 2 === 0 ? "transparent" : C.surface; }}
                        >
                          <td style={{ ...CELL, fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: C.accent }}>{s.id?.slice(0, 18)}…</td>
                          <td style={CELL}>{Array.isArray(s.scan_type) ? s.scan_type.join(", ") : String(s.scan_type || "full discovery")}</td>
                          <td style={CELL}>
                            <B c={s.status === "completed" ? "green" : s.status === "running" ? "amber" : s.status === "failed" ? "red" : "blue"} pulse={s.status === "running"}>
                              {s.status}
                            </B>
                          </td>
                          <td style={{ ...CELL, fontSize: 10 }}>{fmtDate(s.started_at)}</td>
                          <td style={{ ...CELL, fontSize: 10 }}>{fmtDuration(s.started_at, s.completed_at)}</td>
                          <td style={{ ...CELL, color: C.text, fontWeight: 600 }}>{s.assets_found ?? "—"}</td>
                          <td style={CELL}>
                            <span style={{ fontSize: 9, color: C.muted }}>{expandedScan === s.id ? "▲ Hide" : "▼ Details"}</span>
                          </td>
                        </tr>
                        {expandedScan === s.id && (
                          <tr key={s.id + "-detail"} style={{ background: C.accentDim }}>
                            <td colSpan={7} style={{ padding: "12px 20px" }}>
                              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, fontSize: 11 }}>
                                <div><span style={{ color: C.muted }}>Full Scan ID: </span><span style={{ color: C.accent, fontFamily: "'JetBrains Mono',monospace", fontSize: 10 }}>{s.id}</span></div>
                                <div><span style={{ color: C.muted }}>Initiated by: </span><span style={{ color: C.text }}>{s.initiated_by || "system"}</span></div>
                                <div><span style={{ color: C.muted }}>Completed: </span><span style={{ color: C.text }}>{s.completed_at ? fmtDate(s.completed_at) : "—"}</span></div>
                                <div><span style={{ color: C.muted }}>New Assets: </span><span style={{ color: C.green, fontWeight: 600 }}>{s.new_assets ?? "—"}</span></div>
                                <div><span style={{ color: C.muted }}>Risk Changes: </span><span style={{ color: s.risk_changes > 0 ? C.red : C.green }}>{s.risk_changes ?? 0}</span></div>
                                <div><span style={{ color: C.muted }}>Errors: </span><span style={{ color: s.error_count > 0 ? C.red : C.muted }}>{s.error_count ?? 0}</span></div>
                                <div><span style={{ color: C.muted }}>Summary: </span><span style={{ color: C.dim }}>{s.summary || "Discovery scan completed."}</span></div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Section>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          RISK INTELLIGENCE VIEW
      ══════════════════════════════════════════════════════════════════════ */}
      {view === "risk" && (
        <div>
          {/* DRI summary stats */}
          {driSummary && (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 10, marginBottom: 20 }}>
              {[
                { label: "Overall Risk Score", value: driSummary.overall_score, sub: driSummary.overall_level, c: riskColor(driSummary.overall_level) },
                { label: "Critical Keys", value: driSummary.critical_count, c: driSummary.critical_count > 0 ? C.red : C.green },
                { label: "Weak Algorithms", value: driSummary.weak_algo_count, c: driSummary.weak_algo_count > 0 ? C.red : C.green },
                { label: "Unrotated >1yr", value: driSummary.unrotated_count, c: driSummary.unrotated_count > 0 ? C.amber : C.green },
                { label: "Exportable Keys", value: driSummary.exportable_count, c: driSummary.exportable_count > 0 ? C.amber : C.green },
                { label: "Expiring 30d", value: driSummary.expiring_count, c: driSummary.expiring_count > 0 ? C.amber : C.green },
              ].map(({ label, value, sub, c }) => (
                <div key={label} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "12px 14px" }}>
                  <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 5 }}>{label}</div>
                  <div style={{ fontSize: 26, fontWeight: 800, color: c, letterSpacing: -0.8 }}>{value ?? 0}</div>
                  {sub && <div style={{ fontSize: 9, color: c, marginTop: 2, fontWeight: 600, textTransform: "uppercase" }}>{sub}</div>}
                </div>
              ))}
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 20 }}>
            {/* Key Risk Ranking */}
            <Section title={`Key Risk Ranking (${keyRisks.length})`}>
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden", maxHeight: 380, overflowY: "auto" }}>
                {keyRisks.length === 0 ? (
                  <div style={{ textAlign: "center", padding: "32px 20px", color: C.muted, fontSize: 11 }}>No key risk data available.</div>
                ) : (
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead style={{ position: "sticky", top: 0 }}>
                      <tr>
                        {["#", "Key", "Algorithm", "Score", "Level"].map(h => (
                          <th key={h} style={TH}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {keyRisks.map((k, idx) => (
                        <tr
                          key={k.id}
                          style={{ borderBottom: `1px solid ${C.border}22`, background: idx % 2 === 0 ? "transparent" : C.surface }}
                          onMouseEnter={e => { e.currentTarget.style.background = C.cardHover; }}
                          onMouseLeave={e => { e.currentTarget.style.background = idx % 2 === 0 ? "transparent" : C.surface; }}
                        >
                          <td style={{ ...CELL, color: C.muted, fontWeight: 700, width: 30 }}>{idx + 1}</td>
                          <td style={{ ...CELL, color: C.text }}>
                            <div style={{ fontWeight: 600, fontSize: 11 }}>{k.name || k.id?.slice(0, 14) + "…"}</div>
                            <div style={{ fontSize: 9, color: C.muted, marginTop: 1 }}>{k.risk_factors?.slice(0, 1).join("") || k.recommendation?.slice(0, 40) || "—"}</div>
                          </td>
                          <td style={CELL}><B c="accent">{k.algorithm || "—"}</B></td>
                          <td style={CELL}>
                            <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                              <div style={{ width: 36, height: 4, background: C.border, borderRadius: 2, overflow: "hidden" }}>
                                <div style={{ width: `${k.risk_score}%`, height: "100%", background: riskColor(k.risk_level), borderRadius: 2 }} />
                              </div>
                              <span style={{ fontSize: 10, color: riskColor(k.risk_level), fontWeight: 700 }}>{k.risk_score}</span>
                            </div>
                          </td>
                          <td style={CELL}><RiskBadge level={k.risk_level} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </Section>

            {/* Risk by algorithm */}
            <Section title="Risk by Algorithm">
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 16 }}>
                {Object.keys(summary?.algorithm_distribution ?? {}).length === 0 ? (
                  <div style={{ textAlign: "center", padding: "32px 0", color: C.muted, fontSize: 11 }}>No algorithm data.</div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {Object.entries(summary?.algorithm_distribution ?? {})
                      .sort((a, b) => Number(b[1]) - Number(a[1]))
                      .map(([algo, count]) => {
                        const total = totalAssets || 1;
                        const pct = Math.round((Number(count) / total) * 100);
                        // assign color based on algorithm strength heuristic
                        const isWeak = ["DES", "3DES", "RC4", "MD5"].some(w => algo.toUpperCase().includes(w));
                        const isPQC = ["KYBER", "DILITHIUM", "FALCON"].some(w => algo.toUpperCase().includes(w));
                        const color = isPQC ? C.accent : isWeak ? C.red : C.green;
                        return (
                          <div key={algo}>
                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                <span style={{ fontSize: 10, color: C.text, fontWeight: 600, fontFamily: "'JetBrains Mono',monospace" }}>{algo}</span>
                                {isPQC && <B c="accent">PQC</B>}
                                {isWeak && <B c="red">Weak</B>}
                              </div>
                              <span style={{ fontSize: 10, color: C.muted }}>{String(count)} keys ({pct}%)</span>
                            </div>
                            <Bar pct={pct} color={color} />
                          </div>
                        );
                      })}
                  </div>
                )}
              </div>
            </Section>
          </div>

          {/* Remediation Workboard */}
          {remediations.length > 0 && (
            <Section title="Remediation Workboard">
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 12 }}>
                {remediations.map(r => {
                  const priorityColor = r.priority <= 1 ? C.red : r.priority <= 3 ? C.amber : C.blue;
                  const priorityDim = r.priority <= 1 ? C.redDim : r.priority <= 3 ? C.amberDim : C.blueDim;
                  return (
                    <div key={r.priority} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "14px 16px", borderLeft: `3px solid ${priorityColor}` }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                        <span style={{ fontSize: 9, background: priorityDim, color: priorityColor, borderRadius: 4, padding: "2px 8px", fontWeight: 700 }}>
                          P{r.priority}
                        </span>
                        <span style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5 }}>{r.category}</span>
                        <span style={{ fontSize: 9, color: C.muted, marginLeft: "auto" }}>{r.affected_count} affected</span>
                      </div>
                      <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 5 }}>{r.title}</div>
                      <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.5, marginBottom: 12 }}>{r.description}</div>
                      <Btn small>
                        <TrendingUp size={10} />
                        Begin Remediation
                      </Btn>
                    </div>
                  );
                })}
              </div>
            </Section>
          )}
        </div>
      )}
    </div>
  );
}
