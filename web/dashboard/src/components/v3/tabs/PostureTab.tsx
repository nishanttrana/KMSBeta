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

function buildRiskTrendPoints(history: any[]) {
  const items = Array.isArray(history) ? history.slice(0, 30).reverse() : [];
  if (!items.length) return [];
  const maxRisk = Math.max(1, ...items.map((entry: any) => toNum(entry?.risk_24h)));
  const span = Math.max(1, items.length - 1);
  return items.map((entry: any, index: number) => {
    const value = Math.max(0, Math.min(100, toNum(entry?.risk_24h)));
    return {
      id: String(entry?.id || `${entry?.captured_at || index}`),
      x: (index / span) * 100,
      y: 100 - (value / maxRisk) * 100,
      value,
      label: fmtTS(entry?.captured_at)
    };
  });
}

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
  const trendPoints = useMemo(() => buildRiskTrendPoints(history), [history]);
  const trendPolyline = trendPoints.map((point: any) => `${point.x},${point.y}`).join(" ");

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

  return (
    <div>
      <Section title="Posture Management" subtitle="Predictive, preventive, and corrective posture controls across core KMS + BYOK/HYOK/EKM/KMIP/BitLocker/SDK domains.">
        <Row2>
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <ShieldAlert size={14} color={C.accent} />
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Risk Window</span>
              </div>
              <B c={riskTone24}>{`${risk24}/100`}</B>
            </div>
            <div style={{ fontSize: 10, color: C.dim, marginBottom: 4 }}>
              24h risk: <span style={{ color: C.text, fontWeight: 700 }}>{risk24}</span>
            </div>
            <div style={{ fontSize: 10, color: C.dim, marginBottom: 4 }}>
              7d risk: <span style={{ color: C.text, fontWeight: 700 }}>{risk7d}</span>
            </div>
            <div style={{ fontSize: 9, color: C.muted }}>Captured: {fmtTS(risk?.captured_at)}</div>
          </Card>
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <Activity size={14} color={C.green} />
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Engine Scores</span>
              </div>
              <B c="blue">Live</B>
            </div>
            <div style={{ fontSize: 10, color: C.dim, marginBottom: 4 }}>
              Predictive: <span style={{ color: C.text, fontWeight: 700 }}>{pred}</span>
            </div>
            <div style={{ fontSize: 10, color: C.dim, marginBottom: 4 }}>
              Preventive: <span style={{ color: C.text, fontWeight: 700 }}>{prev}</span>
            </div>
            <div style={{ fontSize: 10, color: C.dim, marginBottom: 6 }}>
              Corrective: <span style={{ color: C.text, fontWeight: 700 }}>{corr}</span>
            </div>
            <div style={{ display: "grid", gap: 4 }}>
              {[
                { key: "Predictive", value: pred, color: C.blue },
                { key: "Preventive", value: prev, color: C.amber },
                { key: "Corrective", value: corr, color: C.green }
              ].map((item) => (
                <div key={item.key}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: C.muted, marginBottom: 2 }}>
                    <span>{item.key}</span>
                    <span>{item.value}</span>
                  </div>
                  <div style={{ height: 5, borderRadius: 999, background: C.panel2, border: `1px solid ${C.border}` }}>
                    <div style={{ width: `${Math.max(2, Math.min(100, item.value))}%`, height: "100%", borderRadius: 999, background: item.color }} />
                  </div>
                </div>
              ))}
            </div>
          </Card>
          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <Wrench size={14} color={C.amber} />
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Open Items</span>
              </div>
              <B c={Number(dashboard?.critical_findings || 0) > 0 ? "red" : "green"}>{Number(dashboard?.critical_findings || 0)} critical</B>
            </div>
            <div style={{ fontSize: 10, color: C.dim, marginBottom: 4 }}>
              Open findings: <span style={{ color: C.text, fontWeight: 700 }}>{Number(dashboard?.open_findings || 0)}</span>
            </div>
            <div style={{ fontSize: 10, color: C.dim, marginBottom: 4 }}>
              Pending actions: <span style={{ color: C.text, fontWeight: 700 }}>{Array.isArray(actions) ? actions.length : 0}</span>
            </div>
            <div style={{ fontSize: 9, color: C.muted }}>Tenant: {String(session?.tenantId || "-")}</div>
          </Card>
        </Row2>

        <Card title="Domain Posture (24h)" style={{ marginTop: 10 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(190px,1fr))", gap: 8 }}>
            {domainMetrics.map((domain: any) => {
              const Icon = domain.icon;
              const tone = riskTone(domain.rate);
              return (
                <div key={domain.key} style={{ border: `1px solid ${C.border}`, borderRadius: 10, padding: 10, background: C.panel2 }}>
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
                  <div style={{ height: 6, borderRadius: 999, border: `1px solid ${C.border}`, background: C.panel }}>
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
              );
            })}
          </div>
        </Card>

        <Card title="Risk Trend" style={{ marginTop: 10 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <div style={{ fontSize: 10, color: C.dim }}>Latest 24h risk snapshots</div>
            <B c="blue">{trendPoints.length ? `${trendPoints[trendPoints.length - 1]?.value || 0} latest` : "No history"}</B>
          </div>
          {trendPoints.length ? (
            <div>
              <svg viewBox="0 0 100 100" preserveAspectRatio="none" style={{ width: "100%", height: 120, display: "block", border: `1px solid ${C.border}`, borderRadius: 8, background: C.panel2 }}>
                <line x1="0" x2="100" y1="80" y2="80" stroke={C.border} strokeWidth="0.6" />
                <line x1="0" x2="100" y1="60" y2="60" stroke={C.border} strokeWidth="0.6" />
                <line x1="0" x2="100" y1="40" y2="40" stroke={C.border} strokeWidth="0.6" />
                <line x1="0" x2="100" y1="20" y2="20" stroke={C.border} strokeWidth="0.6" />
                <polyline fill="none" stroke={C.accent} strokeWidth="2" points={trendPolyline} />
                {trendPoints.map((point: any, index: number) => (
                  <circle key={`${point.id}-${index}`} cx={point.x} cy={point.y} r="1.6" fill={C.accent} />
                ))}
              </svg>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: C.muted, marginTop: 4 }}>
                <span>{trendPoints[0]?.label || "-"}</span>
                <span>{trendPoints[trendPoints.length - 1]?.label || "-"}</span>
              </div>
            </div>
          ) : (
            <div style={{ fontSize: 10, color: C.muted }}>No risk history yet.</div>
          )}
        </Card>

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

        <Card title="Findings">
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

        <Card title="Remediation Actions" style={{ marginTop: 10 }}>
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
