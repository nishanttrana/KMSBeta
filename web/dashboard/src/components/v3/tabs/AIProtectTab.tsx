// @ts-nocheck
import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  FileSearch,
  Plus,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  XCircle,
} from "lucide-react";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import {
  B,
  Bar,
  Btn,
  Card,
  Chk,
  FG,
  Inp,
  Row2,
  Section,
  Sel,
  Stat,
  Tabs as TabBar,
  Txt,
} from "../legacyPrimitives";
import { serviceRequest } from "../../../lib/serviceApi";

// ── types ──────────────────────────────────────────────────────────

type DLPPolicy = {
  id: string;
  name: string;
  description?: string;
  patterns: string[];
  action: "redact" | "block" | "warn";
  scope: "input" | "output" | "both";
  enabled: boolean;
  created_at?: string;
};

type ScanFinding = {
  pattern: string;
  match_preview: string;
  offset: number;
  count: number;
};

type ScanResult = {
  safe: boolean;
  action: "allow" | "block" | "warn";
  findings: ScanFinding[];
  redacted_text?: string;
};

type AuditEntry = {
  id?: string;
  timestamp: string;
  action: string;
  patterns_matched: string[];
  finding_count: number;
  context: "input" | "output";
};

// ── constants ──────────────────────────────────────────────────────

const ALL_PATTERNS = [
  "email", "credit_card", "ssn", "api_key", "private_key",
  "jwt", "phone", "aws_key", "password",
];

const EMPTY_POLICY_FORM = {
  name: "", description: "",
  patterns: ALL_PATTERNS.slice(),
  action: "redact" as const,
  scope: "both" as const,
  enabled: true,
};

type View = "overview" | "scan" | "policies" | "audit";

// ── helpers ────────────────────────────────────────────────────────

const TH: React.CSSProperties = {
  padding: "8px 12px", fontSize: 10, fontWeight: 700, color: C.muted,
  textTransform: "uppercase", letterSpacing: "0.08em", textAlign: "left",
  background: C.card, borderBottom: `1px solid ${C.border}`,
};
const TD = (i: number): React.CSSProperties => ({
  padding: "9px 12px", color: C.dim, fontSize: 11, verticalAlign: "middle",
  background: i % 2 === 0 ? C.card : "#0f1824",
  borderBottom: `1px solid ${C.border}22`,
});

function fmtDatetime(s?: string): string {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleString();
}

function actionBadgeColor(action: string): string {
  if (action === "block") return "red";
  if (action === "warn") return "amber";
  return "green";
}

// ── component ──────────────────────────────────────────────────────

export function AIProtectTab({ session }: { session: any }) {
  const [view, setView] = useState<View>("overview");

  // Policies state
  const [policies, setPolicies] = useState<DLPPolicy[]>([]);
  const [loadingPolicies, setLoadingPolicies] = useState(false);
  const [deleteBusy, setDeleteBusy] = useState<string | null>(null);
  const [policyForm, setPolicyForm] = useState({ ...EMPTY_POLICY_FORM });
  const [policyFormErr, setPolicyFormErr] = useState("");
  const [policyFormBusy, setPolicyFormBusy] = useState(false);

  // Scan state
  const [scanText, setScanText] = useState("");
  const [scanPatterns, setScanPatterns] = useState<string[]>(ALL_PATTERNS.slice());
  const [scanContext, setScanContext] = useState<"input" | "output">("input");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanErr, setScanErr] = useState("");

  // Audit state
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [auditPage, setAuditPage] = useState(0);
  const [auditFilterType, setAuditFilterType] = useState("");
  const AUDIT_PAGE_SIZE = 20;

  // Global error
  const [err, setErr] = useState("");

  const loadPolicies = useCallback(async () => {
    setLoadingPolicies(true);
    setErr("");
    try {
      const data = await serviceRequest(
        session, "ai", `/protect/policies?tenant_id=${encodeURIComponent(session.tenantId)}`
      );
      setPolicies(data?.policies ?? []);
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setLoadingPolicies(false);
    }
  }, [session]);

  const loadAudit = useCallback(async () => {
    setLoadingAudit(true);
    try {
      const data = await serviceRequest(
        session, "ai", `/protect/audit?tenant_id=${encodeURIComponent(session.tenantId)}&limit=200`
      );
      setAuditEntries(data?.entries ?? []);
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setLoadingAudit(false);
    }
  }, [session]);

  useEffect(() => { void loadPolicies(); }, [loadPolicies]);

  // ── derived stats ────────────────────────────────────────────────

  const activePolicies = policies.filter(p => p.enabled).length;
  const scansToday = auditEntries.filter(e => {
    if (!e.timestamp) return false;
    const d = new Date(e.timestamp);
    const now = new Date();
    return d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  }).length;
  const findingsBlocked = auditEntries.filter(e => e.action === "block").length;
  const redactionsApplied = auditEntries.filter(e => e.action === "redact").length;

  // ── actions ──────────────────────────────────────────────────────

  async function doScan(redact: boolean) {
    if (!scanText.trim()) { setScanErr("Paste some text to scan."); return; }
    if (scanPatterns.length === 0) { setScanErr("Select at least one pattern."); return; }
    setScanErr(""); setScanResult(null); setScanning(true);
    try {
      const endpoint = redact ? "/protect/redact" : "/protect/scan";
      const result = await serviceRequest(session, "ai", endpoint, {
        method: "POST",
        body: JSON.stringify({ tenant_id: session.tenantId, text: scanText, patterns: scanPatterns, context: scanContext }),
      });
      setScanResult(result);
    } catch (e) {
      setScanErr(errMsg(e));
    } finally {
      setScanning(false);
    }
  }

  async function doCreatePolicy() {
    setPolicyFormErr("");
    if (!policyForm.name.trim()) { setPolicyFormErr("Policy name is required."); return; }
    if (policyForm.patterns.length === 0) { setPolicyFormErr("Select at least one pattern."); return; }
    setPolicyFormBusy(true);
    try {
      const created = await serviceRequest(session, "ai", "/protect/policies", {
        method: "POST",
        body: JSON.stringify({ tenant_id: session.tenantId, ...policyForm }),
      });
      setPolicies(prev => [created, ...prev]);
      setPolicyForm({ ...EMPTY_POLICY_FORM });
      setPolicyFormErr("");
    } catch (e) {
      setPolicyFormErr(errMsg(e));
    } finally {
      setPolicyFormBusy(false);
    }
  }

  async function doDeletePolicy(id: string) {
    if (!confirm("Delete this DLP policy?")) return;
    setDeleteBusy(id);
    try {
      await serviceRequest(session, "ai", `/protect/policies/${id}`, { method: "DELETE" });
      setPolicies(prev => prev.filter(p => p.id !== id));
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setDeleteBusy(null);
    }
  }

  function toggleScanPattern(p: string) {
    setScanPatterns(prev => prev.includes(p) ? prev.filter(x => x !== p) : [...prev, p]);
  }

  function togglePolicyPattern(p: string) {
    setPolicyForm(f => ({
      ...f,
      patterns: f.patterns.includes(p) ? f.patterns.filter(x => x !== p) : [...f.patterns, p],
    }));
  }

  // ── audit filter / pagination ────────────────────────────────────

  const filteredAudit = auditEntries.filter(e => !auditFilterType || e.action === auditFilterType);
  const totalPages = Math.max(1, Math.ceil(filteredAudit.length / AUDIT_PAGE_SIZE));
  const pageEntries = filteredAudit.slice(auditPage * AUDIT_PAGE_SIZE, (auditPage + 1) * AUDIT_PAGE_SIZE);

  // ── view labels ──────────────────────────────────────────────────

  const VIEW_TABS = ["overview", "scan", "policies", "audit"];
  const VIEW_LABELS = ["Overview", "Scan", `Policies (${policies.length})`, `Audit (${auditEntries.length})`];

  return (
    <div style={{ padding: 24, fontFamily: '"IBM Plex Sans", sans-serif', color: C.text, minHeight: "100%" }}>

      {/* ── Header ── */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            <ShieldCheck size={18} color={C.accent} strokeWidth={2} />
            <span style={{ fontSize: 16, fontWeight: 700, color: C.text, letterSpacing: -0.3 }}>AI Data Protection</span>
            <B c="green" pulse>Real-time</B>
          </div>
          <div style={{ fontSize: 11, color: C.muted }}>DLP scanning, PII redaction, and policy enforcement for AI pipelines</div>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <Btn small onClick={() => { void loadPolicies(); if (view === "audit") void loadAudit(); }} disabled={loadingPolicies || loadingAudit}>
            <RefreshCw size={11} /> Refresh
          </Btn>
        </div>
      </div>

      {/* ── Error banner ── */}
      {err && (
        <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 11, marginBottom: 14, display: "flex", alignItems: "center", gap: 8 }}>
          <AlertTriangle size={13} /> {err}
        </div>
      )}

      {/* ── Stats row ── */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
        <Stat l="Active Policies" v={activePolicies} s={`${policies.length} total configured`} c="accent" i={Shield} />
        <Stat l="Scans Today" v={scansToday} s="last 24 hours" c="blue" i={FileSearch} />
        <Stat l="PII Findings Blocked" v={findingsBlocked} s="policy-blocked events" c={findingsBlocked > 0 ? "red" : "green"} i={ShieldAlert} />
        <Stat l="Redactions Applied" v={redactionsApplied} s="PII masked in-flight" c="amber" i={ShieldCheck} />
      </div>

      {/* ── View tabs ── */}
      <div style={{ display: "flex", gap: 2, marginBottom: 18, borderBottom: `1px solid ${C.border}` }}>
        {VIEW_TABS.map((key, idx) => (
          <button key={key} onClick={() => {
            setView(key as View);
            if (key === "audit" && auditEntries.length === 0) void loadAudit();
          }} style={{
            padding: "8px 16px", border: "none", background: "transparent", cursor: "pointer",
            fontSize: 11, fontWeight: view === key ? 700 : 400,
            color: view === key ? C.accent : C.muted,
            borderBottom: view === key ? `2px solid ${C.accent}` : "2px solid transparent",
            marginBottom: -1, letterSpacing: 0.1,
          }}>{VIEW_LABELS[idx]}</button>
        ))}
      </div>

      {/* ════════════════════════════════════════════════════════════
          OVERVIEW
      ════════════════════════════════════════════════════════════ */}
      {view === "overview" && (
        <>
          <Section title="Active Protection Policies" actions={
            <Btn small primary onClick={() => setView("policies")}>
              <Plus size={10} /> Manage Policies
            </Btn>
          }>
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {loadingPolicies && policies.length === 0 ? (
                <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>Loading policies…</div>
              ) : policies.length === 0 ? (
                <div style={{ padding: "36px 20px", textAlign: "center" }}>
                  <Shield size={28} color={C.border} style={{ marginBottom: 8 }} />
                  <div style={{ color: C.muted, fontSize: 11 }}>No policies configured. Switch to the Policies tab to create one.</div>
                  <div style={{ marginTop: 12 }}>
                    <Btn small primary onClick={() => setView("policies")}><Plus size={10} /> Create Policy</Btn>
                  </div>
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Name", "Patterns", "Action", "Scope", "Status"].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {policies.map((p, i) => (
                      <tr key={p.id}
                        onMouseEnter={e => e.currentTarget.style.filter = "brightness(1.07)"}
                        onMouseLeave={e => e.currentTarget.style.filter = ""}>
                        <td style={{ ...TD(i), color: C.text, fontWeight: 600 }}>
                          {p.name}
                          {p.description && <div style={{ fontSize: 10, color: C.muted, fontWeight: 400, marginTop: 1 }}>{p.description}</div>}
                        </td>
                        <td style={{ ...TD(i), fontSize: 10, maxWidth: 200, color: C.dim }}>{p.patterns.join(", ")}</td>
                        <td style={TD(i)}><B c={actionBadgeColor(p.action)}>{p.action}</B></td>
                        <td style={{ ...TD(i), color: C.dim }}>{p.scope}</td>
                        <td style={TD(i)}><B c={p.enabled ? "green" : "amber"}>{p.enabled ? "Enabled" : "Disabled"}</B></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Section>

          {auditEntries.length > 0 && (
            <Section title="Recent Activity" actions={
              <Btn small onClick={() => setView("audit")}>View All</Btn>
            }>
              <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Timestamp", "Action", "Patterns Matched", "Findings", "Context"].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {auditEntries.slice(0, 5).map((e, i) => (
                      <tr key={e.id || i}
                        onMouseEnter={ev => ev.currentTarget.style.filter = "brightness(1.07)"}
                        onMouseLeave={ev => ev.currentTarget.style.filter = ""}>
                        <td style={{ ...TD(i), whiteSpace: "nowrap", fontSize: 10 }}>{fmtDatetime(e.timestamp)}</td>
                        <td style={TD(i)}><B c={actionBadgeColor(e.action)}>{e.action}</B></td>
                        <td style={{ ...TD(i), fontSize: 10, maxWidth: 200 }}>{(e.patterns_matched ?? []).join(", ") || "—"}</td>
                        <td style={{ ...TD(i), color: e.finding_count > 0 ? C.amber : C.green, fontWeight: 700 }}>{e.finding_count}</td>
                        <td style={{ ...TD(i), color: C.dim }}>{e.context}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          )}

          <div style={{ marginTop: 8 }}>
            <Btn primary onClick={() => setView("scan")}><FileSearch size={12} /> Quick Scan</Btn>
          </div>
        </>
      )}

      {/* ════════════════════════════════════════════════════════════
          SCAN
      ════════════════════════════════════════════════════════════ */}
      {view === "scan" && (
        <>
          <Section title="AI Text Scanner">
            <Card>
              <FG label="Text to Scan" required>
                <Txt
                  rows={8}
                  value={scanText}
                  onChange={e => setScanText(e.target.value)}
                  placeholder="Paste AI prompt, completion, or any text to scan for PII…"
                />
              </FG>

              <FG label="Patterns to Detect">
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 4 }}>
                  {ALL_PATTERNS.map(p => (
                    <Chk
                      key={p}
                      label={p}
                      checked={scanPatterns.includes(p)}
                      onChange={() => toggleScanPattern(p)}
                    />
                  ))}
                </div>
              </FG>

              <FG label="Context">
                <div style={{ display: "flex", gap: 6 }}>
                  {(["input", "output"] as const).map(ctx => (
                    <button key={ctx} onClick={() => setScanContext(ctx)} style={{
                      background: scanContext === ctx ? C.accentDim : "transparent",
                      border: `1px solid ${scanContext === ctx ? C.accent : C.border}`,
                      color: scanContext === ctx ? C.accent : C.muted,
                      borderRadius: 6, padding: "5px 14px", fontSize: 11, cursor: "pointer", fontWeight: scanContext === ctx ? 600 : 400,
                    }}>
                      {ctx === "input" ? "Input (before LLM)" : "Output (after LLM)"}
                    </button>
                  ))}
                </div>
              </FG>

              {scanErr && (
                <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "8px 12px", color: C.red, fontSize: 11, marginBottom: 10 }}>
                  {scanErr}
                </div>
              )}

              <div style={{ display: "flex", gap: 8 }}>
                <Btn primary onClick={() => doScan(false)} disabled={scanning}>
                  <FileSearch size={12} /> {scanning ? "Scanning…" : "Scan for PII"}
                </Btn>
                <Btn onClick={() => doScan(true)} disabled={scanning} style={{ background: C.purple, color: C.bg, border: `1px solid ${C.purple}` }}>
                  <ShieldCheck size={12} /> {scanning ? "Scanning…" : "Scan & Redact"}
                </Btn>
              </div>
            </Card>
          </Section>

          {scanResult && (() => {
            const hasBlock = scanResult.action === "block";
            const hasWarn = !scanResult.safe && scanResult.action === "warn";
            const bannerColor = hasBlock ? C.red : hasWarn ? C.amber : C.green;
            const bannerDim = hasBlock ? C.redDim : hasWarn ? C.amberDim : C.greenDim;
            return (
              <Section title="Scan Results">
                <Card>
                  {/* Result banner */}
                  <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", borderRadius: 8, border: `1px solid ${bannerColor}`, background: bannerDim, marginBottom: 14 }}>
                    {scanResult.safe
                      ? <CheckCircle2 size={16} color={C.green} />
                      : hasBlock ? <XCircle size={16} color={C.red} />
                      : <AlertTriangle size={16} color={C.amber} />
                    }
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 700, color: bannerColor }}>
                        {scanResult.safe ? "No sensitive data detected — safe to proceed."
                          : hasBlock ? "Content blocked — sensitive patterns detected."
                          : "Warning — sensitive patterns detected."}
                      </div>
                      <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>
                        {scanResult.findings.length} finding{scanResult.findings.length !== 1 ? "s" : ""} · action: {scanResult.action}
                      </div>
                    </div>
                  </div>

                  {/* Findings table */}
                  {scanResult.findings.length > 0 && (
                    <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden", marginBottom: 14 }}>
                      <table style={{ width: "100%", borderCollapse: "collapse" }}>
                        <thead>
                          <tr>
                            {["Pattern", "Match Preview", "Offset", "Count"].map(h => <th key={h} style={TH}>{h}</th>)}
                          </tr>
                        </thead>
                        <tbody>
                          {scanResult.findings.map((f, i) => (
                            <tr key={i}>
                              <td style={TD(i)}><B c="amber">{f.pattern}</B></td>
                              <td style={{ ...TD(i), fontFamily: "'JetBrains Mono', monospace", color: C.text }}>{f.match_preview}</td>
                              <td style={TD(i)}>{f.offset}</td>
                              <td style={{ ...TD(i), color: C.text, fontWeight: 700 }}>{f.count}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {/* Redacted output */}
                  {scanResult.redacted_text != null && (
                    <FG label="Redacted Output">
                      <pre style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: "10px 12px", color: C.text, fontSize: 11, overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all", fontFamily: "'JetBrains Mono', monospace", margin: 0 }}>
                        {scanResult.redacted_text}
                      </pre>
                    </FG>
                  )}
                </Card>
              </Section>
            );
          })()}
        </>
      )}

      {/* ════════════════════════════════════════════════════════════
          POLICIES
      ════════════════════════════════════════════════════════════ */}
      {view === "policies" && (
        <Row2>
          {/* Left: create form */}
          <div>
            <Section title="Create New Policy">
              <Card>
                <FG label="Policy Name" required>
                  <Inp
                    value={policyForm.name}
                    onChange={e => setPolicyForm(f => ({ ...f, name: e.target.value }))}
                    placeholder="e.g. Block PII in AI Output"
                  />
                </FG>

                <FG label="Description">
                  <Inp
                    value={policyForm.description}
                    onChange={e => setPolicyForm(f => ({ ...f, description: e.target.value }))}
                    placeholder="Optional description"
                  />
                </FG>

                <FG label="Patterns to Enforce">
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 2 }}>
                    {ALL_PATTERNS.map(p => (
                      <Chk
                        key={p}
                        label={p}
                        checked={policyForm.patterns.includes(p)}
                        onChange={() => togglePolicyPattern(p)}
                      />
                    ))}
                  </div>
                </FG>

                <FG label="Action">
                  <Sel value={policyForm.action} onChange={e => setPolicyForm(f => ({ ...f, action: e.target.value as any }))}>
                    <option value="redact">Redact</option>
                    <option value="block">Block</option>
                    <option value="warn">Warn</option>
                  </Sel>
                </FG>

                <FG label="Scope">
                  <Sel value={policyForm.scope} onChange={e => setPolicyForm(f => ({ ...f, scope: e.target.value as any }))}>
                    <option value="input">Input (before LLM)</option>
                    <option value="output">Output (after LLM)</option>
                    <option value="both">Both</option>
                  </Sel>
                </FG>

                <div style={{ marginBottom: 12 }}>
                  <Chk
                    label="Enable policy immediately"
                    checked={policyForm.enabled}
                    onChange={() => setPolicyForm(f => ({ ...f, enabled: !f.enabled }))}
                  />
                </div>

                {policyFormErr && (
                  <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11, marginBottom: 10 }}>
                    {policyFormErr}
                  </div>
                )}

                <Btn primary full onClick={doCreatePolicy} disabled={policyFormBusy}>
                  <Plus size={11} /> {policyFormBusy ? "Creating…" : "Create Policy"}
                </Btn>
              </Card>
            </Section>
          </div>

          {/* Right: existing policies */}
          <div>
            <Section title={`Existing Policies (${policies.length})`} actions={
              <Btn small onClick={loadPolicies} disabled={loadingPolicies}><RefreshCw size={10} /></Btn>
            }>
              {loadingPolicies && policies.length === 0 ? (
                <Card><div style={{ textAlign: "center", padding: "24px 0", color: C.muted, fontSize: 11 }}>Loading…</div></Card>
              ) : policies.length === 0 ? (
                <Card>
                  <div style={{ textAlign: "center", padding: "24px 0" }}>
                    <Shield size={24} color={C.border} style={{ marginBottom: 6 }} />
                    <div style={{ color: C.muted, fontSize: 11 }}>No policies yet. Create one using the form.</div>
                  </div>
                </Card>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {policies.map(p => (
                    <Card key={p.id}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                        <div style={{ flex: 1, minWidth: 0, marginRight: 8 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                            <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{p.name}</span>
                            <B c={p.enabled ? "green" : "amber"}>{p.enabled ? "Enabled" : "Disabled"}</B>
                          </div>
                          {p.description && <div style={{ fontSize: 10, color: C.muted, marginBottom: 4 }}>{p.description}</div>}
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 4 }}>
                            <B c={actionBadgeColor(p.action)}>{p.action}</B>
                            <B c="blue">{p.scope}</B>
                          </div>
                          <div style={{ fontSize: 10, color: C.dim, marginTop: 2 }}>
                            {p.patterns.join(", ")}
                          </div>
                        </div>
                        <Btn small danger onClick={() => doDeletePolicy(p.id)} disabled={deleteBusy === p.id}>
                          <Trash2 size={10} /> {deleteBusy === p.id ? "…" : "Delete"}
                        </Btn>
                      </div>
                    </Card>
                  ))}
                </div>
              )}
            </Section>
          </div>
        </Row2>
      )}

      {/* ════════════════════════════════════════════════════════════
          AUDIT
      ════════════════════════════════════════════════════════════ */}
      {view === "audit" && (
        <>
          <Section title="Audit Log" actions={
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <Sel w={160} value={auditFilterType} onChange={e => { setAuditFilterType(e.target.value); setAuditPage(0); }}>
                <option value="">All Actions</option>
                <option value="block">Block</option>
                <option value="redact">Redact</option>
                <option value="warn">Warn</option>
                <option value="allow">Allow</option>
              </Sel>
              <Btn small onClick={loadAudit} disabled={loadingAudit}><RefreshCw size={10} /> Reload</Btn>
            </div>
          }>
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {loadingAudit && auditEntries.length === 0 ? (
                <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>Loading audit log…</div>
              ) : filteredAudit.length === 0 ? (
                <div style={{ padding: "36px 20px", textAlign: "center" }}>
                  <FileSearch size={26} color={C.border} style={{ marginBottom: 8 }} />
                  <div style={{ color: C.muted, fontSize: 11 }}>No audit entries yet. Run scans to populate this log.</div>
                </div>
              ) : (
                <>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr>
                        {["Timestamp", "Action", "Patterns Matched", "Findings", "Context"].map(h => <th key={h} style={TH}>{h}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {pageEntries.map((e, i) => (
                        <tr key={e.id || i}
                          onMouseEnter={ev => ev.currentTarget.style.filter = "brightness(1.07)"}
                          onMouseLeave={ev => ev.currentTarget.style.filter = ""}>
                          <td style={{ ...TD(i), whiteSpace: "nowrap", fontSize: 10 }}>{fmtDatetime(e.timestamp)}</td>
                          <td style={TD(i)}><B c={actionBadgeColor(e.action)}>{e.action}</B></td>
                          <td style={{ ...TD(i), fontSize: 10, maxWidth: 240 }}>{(e.patterns_matched ?? []).join(", ") || "—"}</td>
                          <td style={{ ...TD(i), color: e.finding_count > 0 ? C.amber : C.green, fontWeight: 700 }}>{e.finding_count}</td>
                          <td style={{ ...TD(i), color: C.dim }}>{e.context}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {totalPages > 1 && (
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 14px", borderTop: `1px solid ${C.border}` }}>
                      <span style={{ fontSize: 10, color: C.muted }}>Page {auditPage + 1} of {totalPages} · {filteredAudit.length} entries</span>
                      <div style={{ display: "flex", gap: 6 }}>
                        <Btn small onClick={() => setAuditPage(p => Math.max(0, p - 1))} disabled={auditPage === 0}>← Prev</Btn>
                        <Btn small onClick={() => setAuditPage(p => Math.min(totalPages - 1, p + 1))} disabled={auditPage >= totalPages - 1}>Next →</Btn>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </Section>
        </>
      )}
    </div>
  );
}
