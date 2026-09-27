import { useCallback, useEffect, useState, type CSSProperties } from "react";
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
  listTargets,
  createTarget,
  deleteTarget,
  triggerScan,
  listFindings,
  updateFinding,
  listJobs,
  type ScanTarget as LeakTarget,
  type ScanTargetType as TargetType,
  type LeakFinding,
  type ScanJob as LeakJob,
} from "../../../lib/leakScanner";
import { B, Bar, Btn, Card, FG, Inp, Modal, Section, Sel, Stat, Tabs, Txt } from "../legacyPrimitives";
import { C } from "../../v3/theme";

// Every row comes from posture's /leaks routes. When they can't be read the
// tab says so with the error; it never substitutes sample data.

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

const TARGET_TYPES: { v: TargetType; l: string }[] = [
  { v: "git_repo", l: "Git Repository" },
  { v: "container_image", l: "Container Image (unpacked)" },
  { v: "log_stream", l: "Log Files" },
  { v: "s3_bucket", l: "Bucket Export" },
  { v: "env_file", l: "Env / Config File" },
];

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

const TH: CSSProperties = {
  padding: "6px 10px",
  fontSize: 9,
  fontWeight: 600,
  color: C.muted,
  textTransform: "uppercase",
  letterSpacing: 0.8,
  textAlign: "left",
  whiteSpace: "nowrap"
};

const TD: CSSProperties = {
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
          {TARGET_TYPES.map(t => <option key={t.v} value={t.v}>{t.l}</option>)}
        </Sel>
      </FG>
      <FG label="Path" required hint="A path under the server's LEAK_SCAN_ROOT (relative or file://). Remote URLs are not fetched: scanning one fails with that reason. You can also paste content to scan from the target's row.">
        <Inp value={uri} onChange={e => setUri(e.target.value)} placeholder="repos/payments-service" mono />
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

// ─── Paste Content Modal ──────────────────────────────────────────────────────

function PasteScanModal({ target, onClose, onScan }: {
  target: LeakTarget | null;
  onClose: () => void;
  onScan: (content: { content: string; filename: string }) => Promise<void>;
}) {
  const [content, setContent] = useState("");
  const [filename, setFilename] = useState("");
  useEffect(() => { if (target) { setContent(""); setFilename(""); } }, [target]);
  return (
    <Modal open={Boolean(target)} onClose={onClose} title={`Scan content: ${target?.name ?? ""}`}>
      <FG label="File name" hint="Used as the finding location, e.g. .env or deploy.sh">
        <Inp value={filename} onChange={e => setFilename(e.target.value)} placeholder=".env" mono />
      </FG>
      <FG label="Content" required hint="Scanned on the server and discarded; findings keep a redacted preview only.">
        <Txt rows={8} value={content} onChange={e => setContent(e.target.value)} placeholder="Paste a config file, diff or log excerpt" />
      </FG>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Btn onClick={onClose}>Cancel</Btn>
        <Btn primary disabled={!content.trim()} onClick={() => void onScan({ content, filename: filename.trim() })}>Scan</Btn>
      </div>
    </Modal>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

interface LeakScannerTabProps {
  session: any;
  enabledFeatures?: any;
  keyCatalog?: any[];
  configOnly?: boolean;
}

// configOnly drops the Findings section (covered by the unified Threat &
// Exposure Triage view) so this can embed as the console's scan-target
// management surface.
export const LeakScannerTab = ({ session, configOnly }: LeakScannerTabProps) => {
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

  const [unavailable, setUnavailable] = useState("");
  const [pasteTarget, setPasteTarget] = useState<LeakTarget | null>(null);

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [t, f, j] = await Promise.all([listTargets(session), listFindings(session), listJobs(session)]);
      setTargets(t); setFindings(f); setJobs(j);
      setUnavailable("");
    } catch (e) {
      setTargets([]); setFindings([]); setJobs([]);
      setUnavailable(errText(e));
    } finally {
      if (!silent) setLoading(false);
    }
  }, [session]);

  useEffect(() => { void load(false); }, [load]);

  // Every action surfaces its error; nothing is changed locally unless the
  // server confirmed it.
  const act = async (fn: () => Promise<unknown>, label: string) => {
    setError("");
    try {
      await fn();
    } catch (e) {
      setError(`${label}: ${errText(e)}`);
    }
    await load(true);
  };

  const handleAdd = async (payload: { name: string; type: TargetType; uri: string; enabled: boolean }) => {
    await createTarget(session, payload); // errors show in the modal
    await load(true);
  };

  const handleDelete = async (id: string) => {
    setDeleteBusy(id);
    await act(() => deleteTarget(session, id), "Delete failed");
    setDeleteBusy("");
  };

  const handleScan = async (id: string, content?: { content: string; filename: string }) => {
    setScanBusy(id);
    await act(() => triggerScan(session, id, content), "Scan not started");
    setScanBusy("");
  };

  const handleResolve = async (id: string) => {
    setResolveBusy(id);
    await act(() => updateFinding(session, id, { status: "resolved" }), "Not resolved");
    setResolveBusy("");
  };

  // ─── Stats ─────────────────────────────────────────────────────────────────

  const openFindings = findings.filter(f => f.status === "open");
  const criticalFindings = openFindings.filter(f => f.severity === "critical");
  const lastScannedAll = targets.map(t => t.last_scanned_at).filter(Boolean) as string[];
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

  const tableStyle: CSSProperties = {
    width: "100%",
    borderCollapse: "collapse",
    fontSize: 11,
    tableLayout: "fixed"
  };

  if (unavailable) {
    return (
      <Card style={{ padding: 20 }}>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
          <AlertTriangle size={16} color={C.red} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>Not assessed: leak scanner data is unavailable</div>
            <div style={{ fontSize: 11, color: C.dim, marginTop: 4 }}>The posture service did not return scan targets, findings or jobs, so none are shown.</div>
            <div style={{ fontSize: 10, color: C.red, marginTop: 6, fontFamily: "'JetBrains Mono',monospace", wordBreak: "break-word" }}>{unavailable}</div>
            <div style={{ marginTop: 10 }}><Btn small onClick={() => void load(false)}><RefreshCcw size={11} />Retry</Btn></div>
          </div>
        </div>
      </Card>
    );
  }

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
        tabs={configOnly ? ["Targets", "Active Jobs"] : ["Targets", "Findings", "Active Jobs"]}
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
                    <td style={{ ...TD, color: C.dim }}>{formatAgo(t.last_scanned_at)}</td>
                    <td style={TD}>
                      <span style={{ color: t.open_findings > 0 ? C.orange : C.green, fontWeight: 600 }}>{t.open_findings}</span>
                    </td>
                    <td style={TD}>
                      <B c={t.enabled ? "green" : "muted"}>{t.enabled ? "enabled" : "disabled"}</B>
                    </td>
                    <td style={TD}>
                      <div style={{ display: "flex", gap: 4 }}>
                        <Btn small onClick={() => void handleScan(t.id)} disabled={scanBusy === t.id || !t.enabled} title="Scan the target's files under LEAK_SCAN_ROOT">
                          <Play size={10} />{scanBusy === t.id ? "…" : "Scan"}
                        </Btn>
                        <Btn small onClick={() => setPasteTarget(t)} disabled={scanBusy === t.id || !t.enabled} title="Scan pasted content against this target">
                          Paste
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
                <option value="false_positive">False positive</option>
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
                      <span title={f.description}>{f.type}</span>
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
                    <td style={TD} title={f.resolved_by ? `by ${f.resolved_by}` : undefined}><B c={f.status === "open" ? "orange" : f.status === "resolved" ? "green" : "blue"}>{f.status.replace("_", " ")}</B></td>
                    <td style={{ ...TD, color: C.dim }}>{formatAgo(f.detected_at)}</td>
                    <td style={TD}>
                      {f.status !== "resolved" && f.status !== "false_positive" ? (
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
                    <Bar pct={j.progress_pct} color={j.status === "failed" ? C.red : j.status === "completed" ? C.green : C.accent} />
                    {j.error && <div style={{ fontSize: 10, color: j.status === "failed" ? C.red : C.muted, marginTop: 4 }}>{j.error}</div>}
                    <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4, fontSize: 9, color: C.muted }}>
                      <span>{j.status === "completed" ? `${j.findings_count} finding${j.findings_count === 1 ? "" : "s"}` : `${j.progress_pct}% complete`}</span>
                      <span>Started {formatAgo(j.started_at ?? j.created_at)}</span>
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
      <PasteScanModal
        target={pasteTarget}
        onClose={() => setPasteTarget(null)}
        onScan={async (content) => { if (pasteTarget) await handleScan(pasteTarget.id, content); setPasteTarget(null); }}
      />
    </div>
  );
};
