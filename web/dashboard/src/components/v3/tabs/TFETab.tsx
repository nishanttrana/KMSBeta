// @ts-nocheck
import React, { useEffect, useState } from "react";
import {
  CheckCircle2,
  FolderLock,
  HardDrive,
  KeyRound,
  Monitor,
  Plus,
  RefreshCw,
  Shield,
  Trash2,
  UserPlus,
  XCircle,
} from "lucide-react";
import { B, Bar, Btn, Card, FG, Inp, Row2, Section, Sel, Stat } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  createTFEPolicy,
  deleteTFEPolicy,
  getTFESummary,
  listTFEAgents,
  listTFEPolicies,
} from "../../../lib/tfe";

// ─── Shared table styles ──────────────────────────────────────────────────────
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
function agentStatusColor(s: string): string {
  if (s === "active" || s === "online") return C.green;
  if (s === "degraded" || s === "pending") return C.amber;
  return C.red;
}

function agentStatusBadgeC(s: string): string {
  if (s === "active" || s === "online") return "green";
  if (s === "degraded" || s === "pending") return "amber";
  return "red";
}

function fmtDate(s?: string): string {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function fmtDatetime(s?: string): string {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

const EMPTY_POLICY = {
  path: "",
  recursive: true,
  key_id: "",
  algorithm: "AES-256-XTS",
  include_globs: "*.doc,*.pdf,*.xls",
  exclude_globs: "*.tmp",
};

const EMPTY_AGENT = {
  hostname: "",
  os: "linux",
  version: "1.0.0",
  token: "",
};

// ─── Agent health dot ─────────────────────────────────────────────────────────
function AgentDot({ status }: { status: string }) {
  const color = agentStatusColor(status);
  const isOnline = status === "active" || status === "online";
  return (
    <span style={{ position: "relative", display: "inline-flex", width: 10, height: 10, marginRight: 4 }}>
      <span style={{
        display: "inline-block", width: 10, height: 10, borderRadius: 5,
        background: color,
        boxShadow: isOnline ? `0 0 6px ${color}` : "none",
      }} />
    </span>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────
export function TFETab({ session }: { session: any }) {
  const [view, setView] = useState<"overview" | "agents" | "policies" | "register">("overview");
  const [agents, setAgents] = useState<any[]>([]);
  const [policies, setPolicies] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  // Policy form
  const [policyForm, setPolicyForm] = useState({ ...EMPTY_POLICY, agent_id: "" });
  const [policyFormErr, setPolicyFormErr] = useState("");
  const [policyFormBusy, setPolicyFormBusy] = useState(false);

  // Agent registration form
  const [agentForm, setAgentForm] = useState({ ...EMPTY_AGENT });
  const [agentFormErr, setAgentFormErr] = useState("");
  const [agentFormBusy, setAgentFormBusy] = useState(false);

  const [deleteBusy, setDeleteBusy] = useState<string | null>(null);
  const [expandedAgent, setExpandedAgent] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setErr("");
    try {
      const [ag, pol, sum] = await Promise.all([
        listTFEAgents(session),
        listTFEPolicies(session),
        getTFESummary(session),
      ]);
      setAgents(ag);
      setPolicies(pol);
      setSummary(sum);
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, [session?.token, session?.tenantId]);

  async function doDeletePolicy(id: string) {
    if (!confirm("Delete this encryption policy? Files in the protected path will no longer be transparently encrypted.")) return;
    setDeleteBusy(id);
    try {
      await deleteTFEPolicy(session, id);
      setPolicies(ps => ps.filter(p => p.id !== id));
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setDeleteBusy(null);
    }
  }

  async function doCreatePolicy() {
    setPolicyFormErr("");
    if (!policyForm.path.trim()) { setPolicyFormErr("Path is required"); return; }
    if (!policyForm.key_id.trim()) { setPolicyFormErr("Key ID is required"); return; }
    if (!policyForm.agent_id) { setPolicyFormErr("Select an agent"); return; }
    setPolicyFormBusy(true);
    try {
      const pol = await createTFEPolicy(session, {
        agent_id: policyForm.agent_id,
        path: policyForm.path.trim(),
        recursive: policyForm.recursive,
        key_id: policyForm.key_id.trim(),
        algorithm: policyForm.algorithm,
        include_globs: policyForm.include_globs.split(",").map(s => s.trim()).filter(Boolean),
        exclude_globs: policyForm.exclude_globs.split(",").map(s => s.trim()).filter(Boolean),
      });
      setPolicies(ps => [pol, ...ps]);
      setPolicyForm({ ...EMPTY_POLICY, agent_id: "" });
      setPolicyFormErr("");
      setView("policies");
    } catch (e) {
      setPolicyFormErr(errMsg(e));
    } finally {
      setPolicyFormBusy(false);
    }
  }

  const activeAgents = agents.filter(a => a.status === "active" || a.status === "online").length;
  const offlineAgents = agents.filter(a => a.status === "offline" || a.status === "down").length;
  const activePolicies = policies.filter(p => p.status === "active").length;
  const protectedPaths = policies.map(p => p.path).filter(Boolean).length;

  const tabDefs = [
    { id: "overview", label: "Overview" },
    { id: "agents", label: `Agents (${agents.length})` },
    { id: "policies", label: `Policies (${policies.length})` },
    { id: "register", label: "Register" },
  ] as const;

  return (
    <div style={{ padding: "20px 24px", fontFamily: '"IBM Plex Sans", sans-serif', color: C.text, minHeight: "100%" }}>

      {/* ── Page header ──────────────────────────────────────────────────────── */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 34, height: 34, borderRadius: 9, background: C.accentDim, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <FolderLock size={17} color={C.accent} />
          </div>
          <div>
            <div style={{ fontSize: 17, fontWeight: 700, color: C.text, letterSpacing: -0.4 }}>Transparent File Encryption</div>
            <div style={{ fontSize: 11, color: C.muted, marginTop: 1 }}>Agent-based filesystem encryption with centralized key management</div>
          </div>
          <B c="green" pulse>Live</B>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn onClick={() => setView("register")}>
            <Plus size={11} />
            Register Agent / Policy
          </Btn>
          <Btn onClick={load} disabled={loading}>
            <RefreshCw size={11} style={{ animation: loading ? "spin 1s linear infinite" : "none" }} />
            {loading ? "Loading…" : "Refresh"}
          </Btn>
        </div>
      </div>

      {/* ── Error banner ─────────────────────────────────────────────────────── */}
      {err && (
        <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 11, marginBottom: 14, display: "flex", alignItems: "center", gap: 8 }}>
          <XCircle size={13} />
          {err}
        </div>
      )}

      {/* ── Stat row ─────────────────────────────────────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 20 }}>
        <Stat l="Active Agents" v={loading ? "—" : String(activeAgents)} s={`${agents.length} total registered`} c="green" i={CheckCircle2} />
        <Stat l="Active Policies" v={loading ? "—" : String(activePolicies)} s={`${policies.length} total defined`} c="accent" i={Shield} />
        <Stat l="Protected Paths" v={loading ? "—" : String(protectedPaths)} s="unique filesystem paths" c="blue" i={FolderLock} />
        <Stat l="Offline Agents" v={loading ? "—" : String(offlineAgents)} s={offlineAgents > 0 ? "require attention" : "all agents online"} c={offlineAgents > 0 ? "red" : "green"} i={HardDrive} />
      </div>

      {/* ── Tab navigation ───────────────────────────────────────────────────── */}
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
          {/* Agent health grid */}
          <Section title="Agent Health">
            {loading && agents.length === 0 ? (
              <div style={{ color: C.muted, fontSize: 11 }}>Loading agents…</div>
            ) : agents.length === 0 ? (
              <div style={{ color: C.muted, fontSize: 11 }}>No agents registered. Install the kms-tfe agent on your hosts.</div>
            ) : (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 10 }}>
                {agents.map(a => (
                  <div
                    key={a.id}
                    style={{
                      background: C.card,
                      border: `1px solid ${agentStatusColor(a.status) + "33"}`,
                      borderRadius: 9,
                      padding: "11px 14px",
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                    }}
                  >
                    <AgentDot status={a.status} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 11, fontWeight: 600, color: C.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{a.hostname}</div>
                      <div style={{ fontSize: 9, color: C.muted, marginTop: 2 }}>{a.os} · v{a.agent_version}</div>
                    </div>
                    <B c={agentStatusBadgeC(a.status)}>{a.status}</B>
                  </div>
                ))}
              </div>
            )}
          </Section>

          {/* Agent OS breakdown */}
          {summary && Object.keys(summary.by_os ?? {}).length > 0 && (
            <Section title="Fleet by OS">
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                {Object.entries(summary.by_os).map(([os, cnt]) => (
                  <div key={os} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: "8px 14px", display: "flex", alignItems: "center", gap: 8 }}>
                    <Monitor size={13} color={C.muted} />
                    <span style={{ fontWeight: 600, color: C.text, fontSize: 11 }}>{os}</span>
                    <span style={{ color: C.muted, fontSize: 10 }}>{String(cnt)} agents</span>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {/* Recent policy violations / events */}
          <Section title="Recent Policy Violations">
            {(summary?.recent_violations ?? []).length === 0 ? (
              <Card>
                <div style={{ textAlign: "center", padding: "16px 0", color: C.muted, fontSize: 11 }}>
                  <CheckCircle2 size={22} color={C.green} style={{ display: "block", margin: "0 auto 8px" }} />
                  No policy violations detected. All paths are compliant.
                </div>
              </Card>
            ) : (
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Agent", "Path", "Event", "Severity", "Timestamp"].map(h => (
                        <th key={h} style={TH}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {(summary.recent_violations ?? []).map((v: any, idx: number) => (
                      <tr key={idx} style={{ borderBottom: `1px solid ${C.border}22`, background: idx % 2 === 0 ? "transparent" : C.surface }}>
                        <td style={{ ...CELL, fontWeight: 600, color: C.text }}>{v.hostname || v.agent_id?.slice(0, 10)}</td>
                        <td style={{ ...CELL, fontFamily: "'JetBrains Mono',monospace", fontSize: 10 }}>{v.path}</td>
                        <td style={CELL}>{v.event}</td>
                        <td style={CELL}><B c={v.severity === "critical" ? "red" : v.severity === "high" ? "orange" : "amber"}>{v.severity}</B></td>
                        <td style={{ ...CELL, fontSize: 10 }}>{fmtDatetime(v.timestamp)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>

          {/* How TFE works */}
          <Card style={{ background: `linear-gradient(135deg, ${C.card} 0%, ${C.accentTint} 100%)` }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 10 }}>How TFE Works</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
              {[
                { step: "1", title: "Install Agent", desc: "Deploy the kms-tfe binary on the host. It connects to Vecta KMS at startup." },
                { step: "2", title: "Create Policy", desc: "Define which filesystem paths and file patterns to protect, and which key to use." },
                { step: "3", title: "Transparent Encryption", desc: "The agent fetches the key from KMS and applies AES-256-XTS encryption on the fly." },
                { step: "4", title: "Central Key Rotation", desc: "Rotate keys centrally — no manual file re-encryption. The agent re-wraps transparently." },
              ].map(({ step, title, desc }) => (
                <div key={step} style={{ display: "flex", gap: 10 }}>
                  <div style={{ width: 24, height: 24, borderRadius: 12, background: C.accentDim, border: `1px solid ${C.accent}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, marginTop: 1 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, color: C.accent }}>{step}</span>
                  </div>
                  <div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 3 }}>{title}</div>
                    <div style={{ fontSize: 10, color: C.muted, lineHeight: 1.5 }}>{desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          AGENTS VIEW
      ══════════════════════════════════════════════════════════════════════ */}
      {view === "agents" && (
        <div>
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
            <Btn primary onClick={() => setView("register")}>
              <UserPlus size={11} />
              Register New Agent
            </Btn>
          </div>
          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
            {loading && agents.length === 0 ? (
              <div style={{ textAlign: "center", padding: "48px 20px", color: C.muted, fontSize: 11 }}>Loading agents…</div>
            ) : agents.length === 0 ? (
              <div style={{ textAlign: "center", padding: "48px 20px", color: C.muted }}>
                <HardDrive size={28} color={C.border} style={{ display: "block", margin: "0 auto 10px" }} />
                <div style={{ fontSize: 12 }}>No agents registered. Install the kms-tfe agent on your hosts.</div>
              </div>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {["Hostname", "OS", "Version", "Status", "Policies", "Last Seen", "Registered", ""].map(h => (
                      <th key={h} style={TH}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {agents.map((a, idx) => (
                    <React.Fragment key={a.id}>
                      <tr
                        onClick={() => setExpandedAgent(expandedAgent === a.id ? null : a.id)}
                        style={{
                          borderBottom: expandedAgent === a.id ? "none" : `1px solid ${C.border}22`,
                          background: idx % 2 === 0 ? "transparent" : C.surface,
                          cursor: "pointer",
                        }}
                        onMouseEnter={e => { e.currentTarget.style.background = C.cardHover; }}
                        onMouseLeave={e => { e.currentTarget.style.background = idx % 2 === 0 ? "transparent" : C.surface; }}
                      >
                        <td style={{ ...CELL, color: C.text, fontWeight: 600 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                            <AgentDot status={a.status} />
                            <HardDrive size={12} color={C.muted} />
                            {a.hostname}
                          </div>
                        </td>
                        <td style={CELL}><B c="blue">{a.os}</B></td>
                        <td style={{ ...CELL, fontFamily: "'JetBrains Mono',monospace", fontSize: 10 }}>v{a.agent_version}</td>
                        <td style={CELL}><B c={agentStatusBadgeC(a.status)}>{a.status}</B></td>
                        <td style={{ ...CELL, color: C.text, fontWeight: 600 }}>{a.policy_count ?? 0}</td>
                        <td style={{ ...CELL, fontSize: 10 }}>{fmtDatetime(a.last_seen)}</td>
                        <td style={{ ...CELL, fontSize: 10 }}>{fmtDate(a.created_at)}</td>
                        <td style={CELL}>
                          <span style={{ fontSize: 9, color: C.muted }}>{expandedAgent === a.id ? "▲" : "▼"}</span>
                        </td>
                      </tr>
                      {expandedAgent === a.id && (
                        <tr key={a.id + "-detail"}>
                          <td colSpan={8} style={{ padding: "12px 20px", background: C.accentDim, borderBottom: `1px solid ${C.border}22` }}>
                            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, fontSize: 11 }}>
                              <div><span style={{ color: C.muted }}>Agent ID: </span><span style={{ color: C.accent, fontFamily: "'JetBrains Mono',monospace", fontSize: 10 }}>{a.id}</span></div>
                              <div><span style={{ color: C.muted }}>Hostname: </span><span style={{ color: C.text }}>{a.hostname}</span></div>
                              <div><span style={{ color: C.muted }}>OS: </span><span style={{ color: C.text }}>{a.os}</span></div>
                              <div><span style={{ color: C.muted }}>Version: </span><span style={{ color: C.text }}>v{a.agent_version}</span></div>
                              <div><span style={{ color: C.muted }}>Last Heartbeat: </span><span style={{ color: C.text }}>{fmtDatetime(a.last_heartbeat ?? a.last_seen)}</span></div>
                              <div><span style={{ color: C.muted }}>Installed Policies: </span><span style={{ color: C.text, fontWeight: 600 }}>{a.policy_count ?? 0}</span></div>
                              <div><span style={{ color: C.muted }}>Encrypted Files: </span><span style={{ color: C.green, fontWeight: 600 }}>{(a.files_encrypted ?? 0).toLocaleString()}</span></div>
                              <div><span style={{ color: C.muted }}>Tags: </span><span style={{ color: C.dim }}>{Object.entries(a.tags ?? {}).map(([k, v]) => `${k}=${v}`).join(", ") || "none"}</span></div>
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
          POLICIES VIEW
      ══════════════════════════════════════════════════════════════════════ */}
      {view === "policies" && (
        <div>
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
            <Btn primary onClick={() => setView("register")}>
              <Plus size={11} />
              Create Policy
            </Btn>
          </div>

          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
            {loading && policies.length === 0 ? (
              <div style={{ textAlign: "center", padding: "48px 20px", color: C.muted, fontSize: 11 }}>Loading policies…</div>
            ) : policies.length === 0 ? (
              <div style={{ textAlign: "center", padding: "48px 20px", color: C.muted }}>
                <FolderLock size={28} color={C.border} style={{ display: "block", margin: "0 auto 10px" }} />
                <div style={{ fontSize: 12 }}>No policies defined. Create your first encryption policy above.</div>
              </div>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {["Agent", "Protected Path", "Algorithm", "Files Encrypted", "Include Patterns", "Status", "Recursive", "Created", ""].map(h => (
                      <th key={h} style={TH}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {policies.map((p, idx) => {
                    const agent = agents.find(a => a.id === p.agent_id);
                    return (
                      <tr
                        key={p.id}
                        style={{ borderBottom: `1px solid ${C.border}22`, background: idx % 2 === 0 ? "transparent" : C.surface }}
                        onMouseEnter={e => { e.currentTarget.style.background = C.cardHover; }}
                        onMouseLeave={e => { e.currentTarget.style.background = idx % 2 === 0 ? "transparent" : C.surface; }}
                      >
                        <td style={{ ...CELL, color: C.text, fontWeight: 600 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            {agent && <AgentDot status={agent.status} />}
                            {agent?.hostname ?? p.agent_id?.slice(0, 10) + "…"}
                          </div>
                        </td>
                        <td style={{ ...CELL, fontFamily: "'JetBrains Mono',monospace", fontSize: 10 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                            <FolderLock size={11} color={C.accent} />
                            {p.path}
                          </div>
                        </td>
                        <td style={CELL}><B c="accent">{p.algorithm}</B></td>
                        <td style={{ ...CELL, color: C.text, fontWeight: 600 }}>{(p.files_encrypted ?? 0).toLocaleString()}</td>
                        <td style={{ ...CELL, fontSize: 10, color: C.dim, fontFamily: "'JetBrains Mono',monospace" }}>
                          {Array.isArray(p.include_globs) ? p.include_globs.slice(0, 3).join(", ") : p.include_globs || "—"}
                        </td>
                        <td style={CELL}><B c={p.status === "active" ? "green" : "red"}>{p.status}</B></td>
                        <td style={{ ...CELL, textAlign: "center" }}>
                          {p.recursive ? <CheckCircle2 size={13} color={C.green} /> : <XCircle size={13} color={C.muted} />}
                        </td>
                        <td style={{ ...CELL, fontSize: 10 }}>{fmtDate(p.created_at)}</td>
                        <td style={CELL}>
                          <Btn small danger onClick={() => doDeletePolicy(p.id)} disabled={deleteBusy === p.id}>
                            <Trash2 size={10} />
                            {deleteBusy === p.id ? "…" : "Delete"}
                          </Btn>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          REGISTER VIEW — two-column form
      ══════════════════════════════════════════════════════════════════════ */}
      {view === "register" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>

          {/* ── Agent Registration ──────────────────────────────────────────── */}
          <Card>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16, paddingBottom: 12, borderBottom: `1px solid ${C.border}` }}>
              <div style={{ width: 28, height: 28, borderRadius: 7, background: C.blueDim, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <UserPlus size={13} color={C.blue} />
              </div>
              <div>
                <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Register Agent</div>
                <div style={{ fontSize: 10, color: C.muted }}>Provision a new TFE agent on a host</div>
              </div>
            </div>

            <FG label="Hostname" required>
              <Inp
                placeholder="prod-web-01.internal"
                value={agentForm.hostname}
                onChange={e => setAgentForm(f => ({ ...f, hostname: e.target.value }))}
              />
            </FG>
            <FG label="Operating System">
              <Sel value={agentForm.os} onChange={e => setAgentForm(f => ({ ...f, os: e.target.value }))}>
                <option value="linux">Linux</option>
                <option value="windows">Windows</option>
                <option value="macos">macOS</option>
                <option value="freebsd">FreeBSD</option>
              </Sel>
            </FG>
            <FG label="Agent Version">
              <Inp
                placeholder="1.0.0"
                value={agentForm.version}
                onChange={e => setAgentForm(f => ({ ...f, version: e.target.value }))}
              />
            </FG>
            <FG label="Install Token" hint="One-time token used to authenticate the agent on first boot.">
              <Inp
                placeholder="tok_…"
                mono
                value={agentForm.token}
                onChange={e => setAgentForm(f => ({ ...f, token: e.target.value }))}
              />
            </FG>

            {agentFormErr && (
              <div style={{ color: C.red, fontSize: 10, marginBottom: 10 }}>{agentFormErr}</div>
            )}

            <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
              <Btn primary onClick={() => {}} disabled={agentFormBusy}>
                <UserPlus size={11} />
                {agentFormBusy ? "Registering…" : "Register Agent"}
              </Btn>
              <Btn onClick={() => setAgentForm({ ...EMPTY_AGENT })}>Reset</Btn>
            </div>

            {/* Install instructions */}
            <div style={{ marginTop: 16, paddingTop: 14, borderTop: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 10, color: C.muted, marginBottom: 8, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.6 }}>Quick Install</div>
              <pre style={{ background: "#0d1117", border: `1px solid ${C.border}`, borderRadius: 7, padding: "10px 14px", fontSize: 10, fontFamily: "'JetBrains Mono',monospace", color: "#e6edf3", overflowX: "auto", margin: 0, lineHeight: 1.6 }}>
                {`curl -sSL https://your-kms.example.com/install/tfe \\
  | INSTALL_TOKEN=${agentForm.token || "<token>"} bash`}
              </pre>
            </div>
          </Card>

          {/* ── Policy Creation ─────────────────────────────────────────────── */}
          <Card>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16, paddingBottom: 12, borderBottom: `1px solid ${C.border}` }}>
              <div style={{ width: 28, height: 28, borderRadius: 7, background: C.accentDim, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <FolderLock size={13} color={C.accent} />
              </div>
              <div>
                <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Create Encryption Policy</div>
                <div style={{ fontSize: 10, color: C.muted }}>Define a filesystem encryption rule for an agent</div>
              </div>
            </div>

            <FG label="Agent" required>
              <Sel
                value={policyForm.agent_id}
                onChange={e => setPolicyForm(f => ({ ...f, agent_id: e.target.value }))}
              >
                <option value="">Select agent…</option>
                {agents.map(a => (
                  <option key={a.id} value={a.id}>{a.hostname} ({a.status})</option>
                ))}
              </Sel>
            </FG>
            <FG label="Policy Name / Path" required hint="Absolute filesystem path to protect.">
              <Inp
                placeholder="/data/sensitive"
                mono
                value={policyForm.path}
                onChange={e => setPolicyForm(f => ({ ...f, path: e.target.value }))}
              />
            </FG>
            <FG label="Algorithm">
              <Sel
                value={policyForm.algorithm}
                onChange={e => setPolicyForm(f => ({ ...f, algorithm: e.target.value }))}
              >
                <option>AES-256-XTS</option>
                <option>AES-256-CBC</option>
                <option>ChaCha20-Poly1305</option>
              </Sel>
            </FG>
            <FG label="Key ID" required hint="The Vecta KMS key used to encrypt files.">
              <Inp
                placeholder="key_abc123…"
                mono
                value={policyForm.key_id}
                onChange={e => setPolicyForm(f => ({ ...f, key_id: e.target.value }))}
              />
            </FG>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <FG label="Include Globs" hint="Comma-separated patterns.">
                <Inp
                  placeholder="*.doc,*.pdf"
                  mono
                  value={policyForm.include_globs}
                  onChange={e => setPolicyForm(f => ({ ...f, include_globs: e.target.value }))}
                />
              </FG>
              <FG label="Exclude Globs">
                <Inp
                  placeholder="*.tmp"
                  mono
                  value={policyForm.exclude_globs}
                  onChange={e => setPolicyForm(f => ({ ...f, exclude_globs: e.target.value }))}
                />
              </FG>
            </div>

            <FG label="Mode">
              <Sel>
                <option value="transparent">Transparent (on-access encryption)</option>
                <option value="batch">Batch (encrypt-in-place)</option>
                <option value="shadow">Shadow (encrypted copy)</option>
              </Sel>
            </FG>

            <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 12 }}>
              <input
                type="checkbox"
                id="recursive-chk"
                checked={policyForm.recursive}
                onChange={e => setPolicyForm(f => ({ ...f, recursive: e.target.checked }))}
                style={{ accentColor: C.accent, width: 13, height: 13 }}
              />
              <label htmlFor="recursive-chk" style={{ fontSize: 11, color: C.dim, cursor: "pointer" }}>Recursive — include subdirectories</label>
            </div>

            {policyFormErr && (
              <div style={{ color: C.red, fontSize: 10, marginBottom: 10 }}>{policyFormErr}</div>
            )}

            <div style={{ display: "flex", gap: 8 }}>
              <Btn primary onClick={doCreatePolicy} disabled={policyFormBusy}>
                <Plus size={11} />
                {policyFormBusy ? "Creating…" : "Create Policy"}
              </Btn>
              <Btn onClick={() => { setPolicyForm({ ...EMPTY_POLICY, agent_id: "" }); setPolicyFormErr(""); }}>Reset</Btn>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
