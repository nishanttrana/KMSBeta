// @ts-nocheck
import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Eye,
  GitBranch,
  Package,
  Play,
  RefreshCcw,
  ScrollText,
  Search,
  ShieldAlert,
  Target,
  Trash2,
  X
} from "lucide-react";
import {
  listLeakTargets,
  addLeakTarget,
  deleteLeakTarget,
  triggerLeakScan,
  listLeakFindings,
  resolveLeakFinding,
  listLeakJobs
} from "../../../lib/leakScanner";
import { B, Bar, Btn, Card, FG, Inp, Modal, Section, Sel, Stat, Tabs } from "../legacyPrimitives";
import { C } from "../../v3/theme";

// ─── Types ────────────────────────────────────────────────────────────────────

type TargetType = "git_repo" | "container_image" | "log_stream";

interface LeakTarget {
  id: string;
  name: string;
  type: TargetType;
  uri: string;
  enabled: boolean;
  last_scanned?: string;
  open_findings: number;
}

interface LeakFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  secret_type: string;
  target_id: string;
  target_name: string;
  location: string;
  entropy: number;
  status: "open" | "acknowledged" | "resolved";
  detected_at: string;
}

interface LeakJob {
  id: string;
  target_name: string;
  target_type: TargetType;
  status: "running" | "queued" | "completed" | "failed";
  progress: number;
  started_at: string;
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_TARGETS: LeakTarget[] = [
  { id: "tgt-001", name: "vecta-core", type: "git_repo", uri: "https://github.com/vecta-io/vecta-core.git", enabled: true, last_scanned: new Date(Date.now() - 3600 * 1000).toISOString(), open_findings: 3 },
  { id: "tgt-002", name: "api-gateway:latest", type: "container_image", uri: "registry.vecta.io/api-gateway:latest", enabled: true, last_scanned: new Date(Date.now() - 7200 * 1000).toISOString(), open_findings: 1 },
  { id: "tgt-003", name: "prod-audit-logs", type: "log_stream", uri: "cloudwatch://us-east-1/prod/audit", enabled: false, last_scanned: new Date(Date.now() - 86400 * 1000).toISOString(), open_findings: 2 }
];

const MOCK_FINDINGS: LeakFinding[] = [
  { id: "fnd-001", severity: "critical", secret_type: "aws_access_key", target_id: "tgt-001", target_name: "vecta-core", location: "src/config/aws.ts:L42", entropy: 4.92, status: "open", detected_at: new Date(Date.now() - 900 * 1000).toISOString() },
  { id: "fnd-002", severity: "high", secret_type: "jwt_token", target_id: "tgt-001", target_name: "vecta-core", location: "tests/fixtures/auth.json:L18", entropy: 4.61, status: "open", detected_at: new Date(Date.now() - 1800 * 1000).toISOString() },
  { id: "fnd-003", severity: "high", secret_type: "generic_api_key", target_id: "tgt-002", target_name: "api-gateway:latest", location: "/etc/gateway/config.yaml:L7", entropy: 4.44, status: "acknowledged", detected_at: new Date(Date.now() - 7200 * 1000).toISOString() },
  { id: "fnd-004", severity: "medium", secret_type: "private_key_pem", target_id: "tgt-001", target_name: "vecta-core", location: "scripts/deploy.sh:L93", entropy: 4.28, status: "open", detected_at: new Date(Date.now() - 3600 * 1000).toISOString() },
  { id: "fnd-005", severity: "low", secret_type: "slack_webhook", target_id: "tgt-003", target_name: "prod-audit-logs", location: "log-line:2024-03-20T08:12:31Z", entropy: 3.87, status: "resolved", detected_at: new Date(Date.now() - 86400 * 1000).toISOString() },
  { id: "fnd-006", severity: "critical", secret_type: "gcp_service_account_key", target_id: "tgt-003", target_name: "prod-audit-logs", location: "log-line:2024-03-21T14:03:55Z", entropy: 5.01, status: "open", detected_at: new Date(Date.now() - 43200 * 1000).toISOString() }
];

const MOCK_JOBS: LeakJob[] = [
  { id: "job-001", target_name: "vecta-core", target_type: "git_repo", status: "running", progress: 67, started_at: new Date(Date.now() - 120 * 1000).toISOString() },
  { id: "job-002", target_name: "api-gateway:latest", target_type: "container_image", status: "queued", progress: 0, started_at: new Date(Date.now() - 30 * 1000).toISOString() }
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatAgo(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  const s = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function truncate(str: string, max = 40): string {
  return str.length > max ? `…${str.slice(-max + 1)}` : str;
}

function severityColor(sev: string): string {
  switch (sev) {
    case "critical": return C.red;
    case "high": return C.orange;
    case "medium": return C.amber;
    case "low": return C.blue;
    default: return C.muted;
  }
}

function severityTone(sev: string): string {
  switch (sev) {
    case "critical": return "red";
    case "high": return "orange";
    case "medium": return "amber";
    case "low": return "blue";
    default: return "muted";
  }
}

function targetTypeIcon(t: TargetType) {
  if (t === "git_repo") return <GitBranch size={11} color={C.accent} />;
  if (t === "container_image") return <Package size={11} color={C.purple} />;
  return <ScrollText size={11} color={C.teal} />;
}

function uriPlaceholder(t: TargetType): string {
  if (t === "git_repo") return "https://github.com/org/repo.git";
  if (t === "container_image") return "registry.example.io/image:tag";
  return "cloudwatch://region/group/stream";
}

const TH: React.CSSProperties = {
  padding: "6px 10px",
  fontSize: 9,
  fontWeight: 600,
  color: C.muted,
  textTransform: "uppercase",
  letterSpacing: 0.8,
  textAlign: "left",
  whiteSpace: "nowrap"
};

const TD: React.CSSProperties = {
  padding: "8px 10px",
  fontSize: 11,
  color: C.text,
  borderTop: `1px solid ${C.border}`,
  verticalAlign: "middle"
};

// ─── Add Target Modal ─────────────────────────────────────────────────────────

interface AddTargetModalProps {
  open: boolean;
  onClose: () => void;
  onAdd: (payload: { name: string; type: TargetType; uri: string; enabled: boolean }) => Promise<void>;
}

function AddTargetModal({ open, onClose, onAdd }: AddTargetModalProps) {
  const [name, setName] = useState("");
  const [type, setType] = useState<TargetType>("git_repo");
  const [uri, setUri] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (open) { setName(""); setType("git_repo"); setUri(""); setEnabled(true); setError(""); setBusy(false); }
  }, [open]);

  const submit = async () => {
    if (!name.trim()) { setError("Name is required."); return; }
    if (!uri.trim()) { setError("URI is required."); return; }
    setBusy(true);
    setError("");
    try {
      await onAdd({ name: name.trim(), type, uri: uri.trim(), enabled });
      onClose();
    } catch (e: any) {
      setError(String(e?.message || "Failed to add target."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal open={open} onClose={onClose} title="Add Scan Target">
      <FG label="Name" required>
        <Inp value={name} onChange={e => setName(e.target.value)} placeholder="my-service-repo" />
      </FG>
      <FG label="Target Type" required>
        <Sel value={type} onChange={e => setType(e.target.value as TargetType)}>
          <option value="git_repo">Git Repository</option>
          <option value="container_image">Container Image</option>
          <option value="log_stream">Log Stream</option>
        </Sel>
      </FG>
      <FG label="URI" required>
        <Inp value={uri} onChange={e => setUri(e.target.value)} placeholder={uriPlaceholder(type)} />
      </FG>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
        <div
          onClick={() => setEnabled(v => !v)}
          style={{ width: 36, height: 20, borderRadius: 10, background: enabled ? C.accent : C.border, cursor: "pointer", position: "relative", transition: "background .2s" }}
        >
          <div style={{ position: "absolute", top: 3, left: enabled ? 18 : 3, width: 14, height: 14, borderRadius: 7, background: C.bg, transition: "left .2s" }} />
        </div>
        <span style={{ fontSize: 11, color: C.dim }}>Enabled</span>
      </div>
      {error && <div style={{ fontSize: 10, color: C.red, marginBottom: 8 }}>{error}</div>}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Btn onClick={onClose}>Cancel</Btn>
        <Btn primary onClick={submit} disabled={busy}>{busy ? "Adding…" : "Add Target"}</Btn>
      </div>
    </Modal>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

interface LeakScannerTabProps {
  session: any;
  enabledFeatures?: any;
  keyCatalog?: any[];
}

export const LeakScannerTab = ({ session }: LeakScannerTabProps) => {
  const [targets, setTargets] = useState<LeakTarget[]>([]);
  const [findings, setFindings] = useState<LeakFinding[]>([]);
  const [jobs, setJobs] = useState<LeakJob[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeSection, setActiveSection] = useState("Targets");
  const [sevFilter, setSevFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [addOpen, setAddOpen] = useState(false);
  const [scanBusy, setScanBusy] = useState<string>("");
  const [deleteBusy, setDeleteBusy] = useState<string>("");
  const [resolveBusy, setResolveBusy] = useState<string>("");

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setError("");
    try {
      const [t, f, j] = await Promise.all([
        listLeakTargets(session),
        listLeakFindings(session),
        listLeakJobs(session)
      ]);
      setTargets(Array.isArray(t) ? t : MOCK_TARGETS);
      setFindings(Array.isArray(f) ? f : MOCK_FINDINGS);
      setJobs(Array.isArray(j) ? j : MOCK_JOBS);
    } catch {
      setTargets(MOCK_TARGETS);
      setFindings(MOCK_FINDINGS);
      setJobs(MOCK_JOBS);
    } finally {
      if (!silent) setLoading(false);
    }
  }, [session]);

  useEffect(() => { void load(false); }, [load]);

  const handleAdd = async (payload: { name: string; type: TargetType; uri: string; enabled: boolean }) => {
    try {
      await addLeakTarget(session, payload);
    } catch {
      // optimistic fallback
    }
    await load(true);
  };

  const handleDelete = async (id: string) => {
    setDeleteBusy(id);
    try { await deleteLeakTarget(session, id); } catch { /* ignore */ }
    setTargets(prev => prev.filter(t => t.id !== id));
    setDeleteBusy("");
  };

  const handleScan = async (id: string) => {
    setScanBusy(id);
    try { await triggerLeakScan(session, id); } catch { /* ignore */ }
    await load(true);
    setScanBusy("");
  };

  const handleResolve = async (id: string) => {
    setResolveBusy(id);
    try { await resolveLeakFinding(session, id); } catch { /* ignore */ }
    setFindings(prev => prev.map(f => f.id === id ? { ...f, status: "resolved" as const } : f));
    setResolveBusy("");
  };

  // ─── Stats ─────────────────────────────────────────────────────────────────

  const openFindings = findings.filter(f => f.status === "open");
  const criticalFindings = openFindings.filter(f => f.severity === "critical");
  const lastScannedAll = targets.map(t => t.last_scanned).filter(Boolean) as string[];
  const lastScan = lastScannedAll.length
    ? formatAgo(lastScannedAll.sort().reverse()[0])
    : "—";

  // ─── Filtered findings ─────────────────────────────────────────────────────

  const filteredFindings = findings.filter(f => {
    if (sevFilter !== "all" && f.severity !== sevFilter) return false;
    if (statusFilter !== "all" && f.status !== statusFilter) return false;
    return true;
  });

  // ─── Table styles ──────────────────────────────────────────────────────────

  const tableStyle: React.CSSProperties = {
    width: "100%",
    borderCollapse: "collapse",
    fontSize: 11,
    tableLayout: "fixed"
  };

  return (
    <div>
      {/* Stat Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 8, marginBottom: 14 }}>
        <Stat l="Scan Targets" v={targets.length} s={`${targets.filter(t => t.enabled).length} enabled`} c="accent" i={Target} />
        <Stat l="Open Findings" v={openFindings.length} s={`${findings.length} total`} c="orange" i={Eye} />
        <Stat l="Critical Findings" v={criticalFindings.length} s={criticalFindings.length > 0 ? "needs immediate action" : "all clear"} c={criticalFindings.length > 0 ? "red" : "green"} i={ShieldAlert} />
        <Stat l="Last Scan" v={lastScan} s={`${jobs.filter(j => j.status === "running").length} active jobs`} c="blue" i={Search} />
      </div>

      {error && (
        <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 8, padding: "8px 12px", fontSize: 11, color: C.red, marginBottom: 10, display: "flex", alignItems: "center", gap: 8 }}>
          <AlertTriangle size={13} /> {error}
          <button onClick={() => setError("")} style={{ marginLeft: "auto", background: "none", border: "none", color: C.red, cursor: "pointer" }}><X size={12} /></button>
        </div>
      )}

      {/* Section Tabs */}
      <Tabs
        tabs={["Targets", "Findings", "Active Jobs"]}
        active={activeSection}
        onChange={setActiveSection}
      />

      {/* ── Targets Section ── */}
      {activeSection === "Targets" && (
        <Section
          title="Scan Targets"
          actions={
            <div style={{ display: "flex", gap: 6 }}>
              <Btn small onClick={() => void load(false)}><RefreshCcw size={11} />{loading ? "Loading…" : "Refresh"}</Btn>
              <Btn small primary onClick={() => setAddOpen(true)}>+ Add Target</Btn>
            </div>
          }
        >
          <Card style={{ padding: 0, overflow: "hidden" }}>
            <table style={tableStyle}>
              <colgroup>
                <col style={{ width: "16%" }} />
                <col style={{ width: "14%" }} />
                <col style={{ width: "26%" }} />
                <col style={{ width: "13%" }} />
                <col style={{ width: "10%" }} />
                <col style={{ width: "10%" }} />
                <col style={{ width: "11%" }} />
              </colgroup>
              <thead>
                <tr style={{ background: C.surface }}>
                  <th style={TH}>Name</th>
                  <th style={TH}>Type</th>
                  <th style={TH}>URI</th>
                  <th style={TH}>Last Scanned</th>
                  <th style={TH}>Findings</th>
                  <th style={TH}>Status</th>
                  <th style={TH}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {targets.map(t => (
                  <tr key={t.id} style={{ transition: "background .1s" }}
                    onMouseEnter={e => (e.currentTarget.style.background = C.surface)}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                    <td style={TD}><span style={{ fontWeight: 600, color: C.text }}>{t.name}</span></td>
                    <td style={TD}>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                        {targetTypeIcon(t.type)}
                        <span style={{ fontSize: 10, color: C.dim }}>{t.type.replace("_", " ")}</span>
                      </span>
                    </td>
                    <td style={{ ...TD, fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: C.dim }} title={t.uri}>
                      {truncate(t.uri, 38)}
                    </td>
                    <td style={{ ...TD, color: C.dim }}>{formatAgo(t.last_scanned)}</td>
                    <td style={TD}>
                      <span style={{ color: t.open_findings > 0 ? C.orange : C.green, fontWeight: 600 }}>{t.open_findings}</span>
                    </td>
                    <td style={TD}>
                      <B c={t.enabled ? "green" : "muted"}>{t.enabled ? "enabled" : "disabled"}</B>
                    </td>
                    <td style={TD}>
                      <div style={{ display: "flex", gap: 4 }}>
                        <Btn small onClick={() => void handleScan(t.id)} disabled={scanBusy === t.id || !t.enabled}>
                          <Play size={10} />{scanBusy === t.id ? "…" : "Scan"}
                        </Btn>
                        <Btn small danger onClick={() => void handleDelete(t.id)} disabled={deleteBusy === t.id}>
                          <Trash2 size={10} />
                        </Btn>
                      </div>
                    </td>
                  </tr>
                ))}
                {!targets.length && !loading && (
                  <tr><td colSpan={7} style={{ ...TD, color: C.muted, textAlign: "center", padding: 20 }}>No scan targets configured.</td></tr>
                )}
              </tbody>
            </table>
          </Card>
        </Section>
      )}

      {/* ── Findings Section ── */}
      {activeSection === "Findings" && (
        <Section
          title="Secret Findings"
          actions={
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <Sel w={120} value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </Sel>
              <Sel w={120} value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
                <option value="all">All Statuses</option>
                <option value="open">Open</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="resolved">Resolved</option>
              </Sel>
            </div>
          }
        >
          <Card style={{ padding: 0, overflow: "hidden" }}>
            <table style={tableStyle}>
              <colgroup>
                <col style={{ width: "9%" }} />
                <col style={{ width: "15%" }} />
                <col style={{ width: "13%" }} />
                <col style={{ width: "20%" }} />
                <col style={{ width: "8%" }} />
                <col style={{ width: "10%" }} />
                <col style={{ width: "11%" }} />
                <col style={{ width: "14%" }} />
              </colgroup>
              <thead>
                <tr style={{ background: C.surface }}>
                  <th style={TH}>Severity</th>
                  <th style={TH}>Type</th>
                  <th style={TH}>Target</th>
                  <th style={TH}>Location</th>
                  <th style={TH}>Entropy</th>
                  <th style={TH}>Status</th>
                  <th style={TH}>Detected</th>
                  <th style={TH}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map(f => (
                  <tr key={f.id}
                    onMouseEnter={e => (e.currentTarget.style.background = C.surface)}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                    <td style={TD}>
                      <span style={{
                        display: "inline-block", padding: "2px 7px", borderRadius: 5,
                        fontSize: 9, fontWeight: 700, letterSpacing: 0.4,
                        color: severityColor(f.severity),
                        background: `${severityColor(f.severity)}18`
                      }}>
                        {f.severity.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ ...TD, fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: C.accent }}>
                      {f.secret_type}
                    </td>
                    <td style={{ ...TD, color: C.dim }}>{f.target_name}</td>
                    <td style={{ ...TD, fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: C.dim }} title={f.location}>
                      {truncate(f.location, 30)}
                    </td>
                    <td style={TD}>
                      <span style={{ color: f.entropy > 4.5 ? C.red : f.entropy > 4.0 ? C.orange : C.dim, fontWeight: 600 }}>
                        {f.entropy.toFixed(2)}
                      </span>
                    </td>
                    <td style={TD}><B c={f.status === "open" ? "orange" : f.status === "resolved" ? "green" : "blue"}>{f.status}</B></td>
                    <td style={{ ...TD, color: C.dim }}>{formatAgo(f.detected_at)}</td>
                    <td style={TD}>
                      {f.status !== "resolved" ? (
                        <Btn small onClick={() => void handleResolve(f.id)} disabled={resolveBusy === f.id}>
                          {resolveBusy === f.id ? "…" : "Resolve"}
                        </Btn>
                      ) : (
                        <span style={{ fontSize: 10, color: C.muted }}>—</span>
                      )}
                    </td>
                  </tr>
                ))}
                {!filteredFindings.length && (
                  <tr><td colSpan={8} style={{ ...TD, color: C.muted, textAlign: "center", padding: 20 }}>No findings match the current filters.</td></tr>
                )}
              </tbody>
            </table>
          </Card>
        </Section>
      )}

      {/* ── Active Jobs Section ── */}
      {activeSection === "Active Jobs" && (
        <Section
          title="Active Scan Jobs"
          actions={
            <Btn small onClick={() => void load(false)}><RefreshCcw size={11} />Refresh</Btn>
          }
        >
          <div style={{ display: "grid", gap: 8 }}>
            {jobs.map(j => (
              <Card key={j.id} style={{ padding: "12px 14px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                      {targetTypeIcon(j.target_type)}
                      <span style={{ fontWeight: 600, fontSize: 12, color: C.text }}>{j.target_name}</span>
                      <B c={j.status === "running" ? "accent" : j.status === "queued" ? "blue" : j.status === "completed" ? "green" : "red"} pulse={j.status === "running"}>
                        {j.status}
                      </B>
                    </div>
                    <Bar pct={j.progress} color={j.status === "failed" ? C.red : j.status === "completed" ? C.green : C.accent} />
                    <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4, fontSize: 9, color: C.muted }}>
                      <span>{j.progress}% complete</span>
                      <span>Started {formatAgo(j.started_at)}</span>
                    </div>
                  </div>
                </div>
              </Card>
            ))}
            {!jobs.length && (
              <Card><div style={{ fontSize: 11, color: C.muted, textAlign: "center" }}>No active scan jobs.</div></Card>
            )}
          </div>
        </Section>
      )}

      <AddTargetModal open={addOpen} onClose={() => setAddOpen(false)} onAdd={handleAdd} />
    </div>
  );
};
