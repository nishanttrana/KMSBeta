// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useState } from "react";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Inp, Modal, Section, Sel, Tabs } from "../legacyPrimitives";
import {
  listAuditEvents,
  getAuditTimeline,
  getAuditSession,
  getAuditCorrelation,
  verifyAuditChain,
  getAuditConfig,
  exportEventsAsCSV,
  exportEventsAsCEF,
  listAuditCheckpoints,
  type AuditEvent,
  type AuditConfig,
  type AuditCheckpoint,
  type ChainVerifyResult
} from "../../../lib/audit";

/* ── constants ── */

const SERVICES = [
  "auth", "key", "keycore", "secrets", "certs", "policy", "governance",
  "audit", "compliance", "posture", "reporting", "cluster",
  "payment", "confidential", "hyok", "byok", "ekm",
  "pqc",
  "autokey", "keyaccess", "signing",
  "workload", "dataprotect", "kmip", "sbom",
  "discovery", "cloud", "hsm",
];

const PAGE_SIZE = 100;

const RESULT_COLORS: Record<string, string> = { success: C.green, failure: C.red, denied: C.amber };

/* ── helpers ── */

function fmtTS(v: any) {
  const raw = String(v || "").trim();
  if (!raw) return "-";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return dt.toLocaleString();
}

function shortTS(v: any) {
  const raw = String(v || "").trim();
  if (!raw) return "-";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return `${dt.getMonth() + 1}/${dt.getDate()} ${dt.getHours()}:${String(dt.getMinutes()).padStart(2, "0")}`;
}

function resultTone(r: string) {
  const v = String(r || "").toLowerCase();
  if (v === "success") return "green";
  if (v === "failure") return "red";
  if (v === "denied") return "amber";
  return "blue";
}

function eventOrigin(e: AuditEvent): { origin: string; agentId: string } {
  const d = (e.details || {}) as Record<string, unknown>;
  const origin = typeof d.origin === "string" && d.origin ? d.origin : "service";
  const agentId = typeof d.agent_id === "string" ? d.agent_id : "";
  return { origin, agentId };
}

function riskColor(score: number): string {
  if (score >= 80) return C.red;
  if (score >= 60) return C.orange;
  if (score >= 40) return C.amber;
  return C.green;
}

function abbrevHash(hash: string) {
  const h = String(hash || "");
  if (h.length <= 12) return h || "-";
  return `${h.slice(0, 6)}...${h.slice(-6)}`;
}

function isHTTPRequestAction(action: any) {
  return String(action || "").trim().toLowerCase().includes(".http_request");
}

function formatAction(action: any) {
  const raw = String(action || "").trim();
  if (!raw) return "-";
  const parts = raw.split(".").filter(Boolean);
  if (parts.length >= 3 && parts[0].toLowerCase() === "audit") {
    const actionWords = parts.slice(2).join(" ").replaceAll("_", " ");
    return actionWords.replace(/\b\w/g, (c) => c.toUpperCase());
  }
  return raw
    .replaceAll("_", " ")
    .replaceAll(".", " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatChainBreakReason(reason: any) {
  return String(reason || "")
    .replaceAll("_", " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function timeRangeToFrom(range: string): string {
  const now = Date.now();
  switch (range) {
    case "24h": return new Date(now - 24 * 60 * 60 * 1000).toISOString();
    case "7d":  return new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
    case "30d": return new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();
    default:    return "";
  }
}

/* ── table header style ── */

const TH: React.CSSProperties = {
  fontSize: 9, fontWeight: 600, color: C.muted, textTransform: "uppercase",
  letterSpacing: 0.6, padding: "6px 6px", textAlign: "left",
  borderBottom: `1px solid ${C.border}`, whiteSpace: "nowrap"
};
const TD: React.CSSProperties = {
  fontSize: 10, color: C.dim, padding: "5px 6px",
  borderBottom: `1px solid ${C.border}`, whiteSpace: "nowrap",
  maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis"
};

/* ── main component ── */

// ── Signed checkpoints ───────────────────────────────────────

const CHECKPOINT_STATUS: Record<string, { label: string; color: string }> = {
  verified: { label: "VERIFIED", color: C.green },
  key_unknown: { label: "KEY NOT TRUSTED", color: C.red },
  signature_invalid: { label: "SIGNATURE INVALID", color: C.red },
  head_mismatch: { label: "HISTORY CHANGED", color: C.red },
};

const CheckpointsSection = ({ session }: { session: any }) => {
  const [items, setItems] = useState<AuditCheckpoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [open, setOpen] = useState<AuditCheckpoint | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      setItems(await listAuditCheckpoints(session, 50));
      setError("");
    } catch (e) {
      setItems([]);
      setError(errMsg(e));
    } finally {
      setLoading(false);
    }
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
  useEffect(() => { load(); }, []);

  const failed = items.filter((c) => c.status !== "verified").length;
  const mono = { fontFamily: "monospace", fontSize: 10 };

  return (
    <div>
      <Section t="Signed Checkpoints" act={<Btn l={loading ? "Verifying..." : "Re-verify"} c={C.cyan} click={load} />}>
        <Card>
          <div style={{ fontSize: 11, color: C.muted, marginBottom: 12 }}>
            Every 10 minutes each node signs the head of each chain it writes (sequence and chain hash) with an
            ECDSA-P384 key held only in memory. The chain hash commits to every earlier event, so a verified
            checkpoint proves nothing before it has changed since. Keys and checkpoints are audit events, so they
            also reach your event streams. Listing re-verifies each signature and the stored head.
          </div>
          {error ? (
            <div style={{ color: C.red, padding: 12 }}>Checkpoints unavailable: {error}</div>
          ) : items.length === 0 && !loading ? (
            <div style={{ color: C.dim, padding: 16, textAlign: "center" }}>
              No checkpoints yet. The first is signed within 10 minutes of audit activity.
            </div>
          ) : (
            <>
              {failed > 0 && (
                <div style={{ color: C.red, fontSize: 11, marginBottom: 8 }}>
                  {failed} checkpoint(s) failed verification. A critical chain_broken audit event was raised.
                </div>
              )}
              <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}`, color: C.dim, textAlign: "left" }}>
                    <th style={{ padding: "6px" }}>Status</th>
                    <th style={{ padding: "6px" }}>Head</th>
                    <th style={{ padding: "6px" }}>Chain</th>
                    <th style={{ padding: "6px" }}>Chain hash</th>
                    <th style={{ padding: "6px" }}>Key</th>
                    <th style={{ padding: "6px" }}>Signed</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((c) => {
                    const st = CHECKPOINT_STATUS[c.status] || { label: c.status, color: C.amber };
                    return (
                      <tr key={c.event_id} style={{ borderBottom: `1px solid ${C.border}10`, cursor: "pointer" }} onClick={() => setOpen(c)}>
                        <td style={{ padding: "6px", color: st.color, fontWeight: 600 }}>{st.label}</td>
                        <td style={{ padding: "6px", color: C.cyan }}>#{c.sequence}</td>
                        <td style={{ padding: "6px" }}>{c.chain_node || "local"}</td>
                        <td style={{ padding: "6px", ...mono, color: C.fg }}>{c.chain_hash.slice(0, 16)}…</td>
                        <td style={{ padding: "6px", ...mono, color: C.dim }}>{c.key_id.slice(0, 12)}…</td>
                        <td style={{ padding: "6px", color: C.dim, fontSize: 10 }}>{c.signed_at ? new Date(c.signed_at).toLocaleString() : "--"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </>
          )}
        </Card>
      </Section>

      {open && (
        <Modal open wide title={`Checkpoint #${open.sequence}`} onClose={() => setOpen(null)}>
          <div style={{ fontSize: 11, color: C.muted, marginBottom: 8 }}>
            Verify outside the KMS: save the message exactly (no trailing newline), the base64-decoded signature
            (DER) and the public key, then
            run <span style={mono}>openssl dgst -sha384 -verify key.pem -signature sig.der message.json</span>.
          </div>
          {[
            ["Status", (CHECKPOINT_STATUS[open.status] || { label: open.status }).label],
            ["Algorithm", open.algorithm],
            ["Key ID", open.key_id],
            ["Signed message", open.message],
            ["Signature (base64 DER)", open.signature],
            ["Public key", open.public_key_pem || "not available: the key is not trusted"],
          ].map(([k, v]) => (
            <div key={k} style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6 }}>{k}</div>
              <div style={{ ...mono, color: C.fg, wordBreak: "break-all", whiteSpace: "pre-wrap" }}>{v}</div>
            </div>
          ))}
        </Modal>
      )}
    </div>
  );
};

export const AuditLogTab = ({ session, onToast }: any) => {
  const [loading, setLoading] = useState(false);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [config, setConfig] = useState<AuditConfig | null>(null);
  const [chainResult, setChainResult] = useState<ChainVerifyResult | null>(null);
  const [chainVerifying, setChainVerifying] = useState(false);

  // filters
  const [serviceFilter, setServiceFilter] = useState("");
  const [originFilter, setOriginFilter] = useState("");
  const [resultFilter, setResultFilter] = useState("");
  const [timeRange, setTimeRange] = useState("24h");
  const [searchQuery, setSearchQuery] = useState("");
  const [offset, setOffset] = useState(0);

  // audit export signing
  const [signingKeyId, setSigningKeyId] = useState("");

  // sub-tab
  const [subTab, setSubTab] = useState("Events");

  // event detail
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  // forensics
  const [forensicMode, setForensicMode] = useState("Timeline");
  const [forensicInput, setForensicInput] = useState("");
  const [forensicEvents, setForensicEvents] = useState<AuditEvent[]>([]);
  const [forensicLoading, setForensicLoading] = useState(false);

  /* ── data loading ── */

  const load = async (silent = false) => {
    if (!session?.token) return;
    if (!silent) setLoading(true);
    try {
      const from = timeRangeToFrom(timeRange);
      const [eventList, cfg] = await Promise.all([
        listAuditEvents(session, {
          result: resultFilter || undefined,
          from: from || undefined,
          limit: PAGE_SIZE,
          offset
        }),
        getAuditConfig(session)
      ]);
      setEvents(Array.isArray(eventList) ? eventList : []);
      setConfig(cfg);
      if (!silent) onToast?.("Audit log refreshed.");
    } catch (error) {
      onToast?.(`Audit load failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
  useEffect(() => { void load(true); }, [session?.token, session?.tenantId, resultFilter, timeRange, offset]);

  /* ── client-side filters (service + search) ── */

  const filteredEvents = useMemo(() => {
    let out = events.filter((e) => !isHTTPRequestAction(e.action));
    if (serviceFilter) out = out.filter((e) => e.service === serviceFilter);
    if (originFilter) out = out.filter((e) => eventOrigin(e).origin === originFilter);
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      out = out.filter((e) =>
        (e.action || "").toLowerCase().includes(q) ||
        (e.actor_id || "").toLowerCase().includes(q) ||
        (e.target_id || "").toLowerCase().includes(q) ||
        (e.service || "").toLowerCase().includes(q)
      );
    }
    return out;
  }, [events, serviceFilter, originFilter, searchQuery]);



  /* ── chain verification ── */

  const verifyChain = async () => {
    setChainVerifying(true);
    try {
      const result = await verifyAuditChain(session);
      setChainResult(result);
      onToast?.(result.ok ? "Chain integrity verified — no tampering detected." : `Chain broken! ${result.breaks.length} break(s) detected.`);
    } catch (error) {
      onToast?.(`Chain verification failed: ${errMsg(error)}`);
    } finally {
      setChainVerifying(false);
    }
  };

  /* ── forensic loaders ── */

  const loadForensic = async () => {
    const id = forensicInput.trim();
    if (!id) { onToast?.("Enter an ID to search."); return; }
    setForensicLoading(true);
    try {
      let results: AuditEvent[] = [];
      if (forensicMode === "Timeline") results = await getAuditTimeline(session, id);
      else if (forensicMode === "Session") results = await getAuditSession(session, id);
      else results = await getAuditCorrelation(session, id);
      const cleanResults = results.filter((ev) => !isHTTPRequestAction(ev.action));
      setForensicEvents(cleanResults);
      onToast?.(`${cleanResults.length} event(s) loaded.`);
    } catch (error) {
      onToast?.(`Forensic query failed: ${errMsg(error)}`);
    } finally {
      setForensicLoading(false);
    }
  };

  const openForensic = (mode: string, id: string) => {
    setSubTab("Forensics");
    setForensicMode(mode);
    setForensicInput(id);
    setTimeout(async () => {
      setForensicLoading(true);
      try {
        let results: AuditEvent[] = [];
        if (mode === "Timeline") results = await getAuditTimeline(session, id);
        else if (mode === "Session") results = await getAuditSession(session, id);
        else results = await getAuditCorrelation(session, id);
        setForensicEvents(results.filter((ev) => !isHTTPRequestAction(ev.action)));
      } catch (error) {
        onToast?.(`Forensic query failed: ${errMsg(error)}`);
      } finally {
        setForensicLoading(false);
      }
    }, 50);
  };



  /* ── integrity status bar ── */

  const chainOk = chainResult ? chainResult.ok : null;

  const IntegrityBar = () => (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", marginBottom: 14, padding: "8px 12px", borderRadius: 8, background: C.card, border: `1px solid ${C.border}` }}>
      <B c={chainOk === false ? "red" : "green"} pulse={chainOk === false}>
        {chainOk === null ? "CHAIN: UNVERIFIED" : chainOk ? "CHAIN: INTACT" : "CHAIN: BROKEN"}
      </B>
      <B c="accent">{filteredEvents.length} events loaded</B>
      <B c={config?.fail_closed ? "green" : "amber"}>
        Fail-closed: {config?.fail_closed ? "ACTIVE" : "INACTIVE"}
      </B>
      <B c="purple">SHA-256 hash chain</B>
      <B c="accent">Immutable storage</B>
      {chainResult && !chainResult.ok && (
        <B c="red">{chainResult.breaks.length} break(s) detected</B>
      )}
    </div>
  );

  /* ── render: Events sub-tab ── */

  const renderEvents = () => {
    const chainBreaks = chainResult && !chainResult.ok ? (Array.isArray(chainResult.breaks) ? chainResult.breaks : []) : [];
    const previewBreaks = chainBreaks.slice(0, 5);
    const hiddenBreakCount = Math.max(0, chainBreaks.length - previewBreaks.length);

    return <>
      {/* filter bar */}
      <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap", alignItems: "center" }}>
        <Inp placeholder="Search actions, actors, targets..." w={240} value={searchQuery}
          onChange={(e: any) => setSearchQuery(e.target.value)} />
        <Sel w={140} value={serviceFilter} onChange={(e: any) => { setServiceFilter(e.target.value); setOffset(0); }}>
          <option value="">All Services</option>
          {SERVICES.map((s) => <option key={s} value={s}>{s}</option>)}
        </Sel>
        <Sel w={110} value={originFilter} onChange={(e: any) => { setOriginFilter(e.target.value); setOffset(0); }}>
          <option value="">All Origins</option>
          <option value="service">Services</option>
          <option value="agent">Agents</option>
        </Sel>
        <Sel w={100} value={resultFilter} onChange={(e: any) => { setResultFilter(e.target.value); setOffset(0); }}>
          <option value="">All Results</option>
          <option value="success">Success</option>
          <option value="failure">Failure</option>
          <option value="denied">Denied</option>
        </Sel>
        <Sel w={100} value={timeRange} onChange={(e: any) => { setTimeRange(e.target.value); setOffset(0); }}>
          <option value="24h">Last 24h</option>
          <option value="7d">Last 7d</option>
          <option value="30d">Last 30d</option>
          <option value="all">All Time</option>
        </Sel>
        <Inp style={{width:160,height:28,fontSize:10}} value={signingKeyId} onChange={(e:any)=>setSigningKeyId(e.target.value)} placeholder="Signing Key ID (optional)"/>
        <Btn small onClick={() => void exportEventsAsCSV(filteredEvents, signingKeyId ? session : undefined, signingKeyId || undefined)}>{signingKeyId ? "Export Signed CSV" : "Export CSV"}</Btn>
        <Btn small onClick={() => void exportEventsAsCEF(filteredEvents, signingKeyId ? session : undefined, signingKeyId || undefined)}>{signingKeyId ? "Export Signed CEF" : "Export CEF"}</Btn>
        <Btn small primary onClick={verifyChain} disabled={chainVerifying}>
          {chainVerifying ? "Verifying..." : "Verify Chain"}
        </Btn>
        <Btn small onClick={() => load()} disabled={loading}>Refresh</Btn>
      </div>

      {/* chain breaks display */}
      {chainBreaks.length > 0 && (
        <Card style={{ marginBottom: 10, borderColor: C.red }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.red, marginBottom: 6 }}>Chain Integrity Breaks Detected</div>
          <div style={{ fontSize: 10, color: C.muted, marginBottom: 6 }}>
            {chainBreaks.length} issue(s) found. Showing {previewBreaks.length} most recent.
          </div>
          <div style={{ display: "grid", gap: 4 }}>
            {previewBreaks.map((b, i) => (
              <div key={i} style={{ fontSize: 10, color: C.dim }} title={`Event ${b.event_id}`}>
                Seq #{b.sequence} — {formatChainBreakReason(b.reason)}
              </div>
            ))}
            {hiddenBreakCount > 0 && (
              <div style={{ fontSize: 10, color: C.muted }}>
                +{hiddenBreakCount} more break(s)
              </div>
            )}
          </div>
        </Card>
      )}

      {/* event table */}
      <Card style={{ marginBottom: 10 }}>
        <div style={{ overflowX: "auto", maxHeight: 480 }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={TH}>Timestamp</th>
                <th style={TH}>Service</th>
                <th style={TH}>Action</th>
                <th style={TH}>Actor</th>
                <th style={TH}>Origin</th>
                <th style={TH}>Target</th>
                <th style={TH}>Result</th>
                <th style={TH}>Risk</th>
                <th style={TH}>FIPS</th>
                <th style={TH}>Chain</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.length === 0 && (
                <tr><td colSpan={10} style={{ ...TD, textAlign: "center", color: C.muted, padding: 20 }}>
                  {loading ? "Loading audit events..." : "No audit events found for the selected filters."}
                </td></tr>
              )}
              {filteredEvents.map((ev) => (
                <tr key={ev.id} onClick={() => setSelectedEvent(ev)}
                  style={{ cursor: "pointer" }}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = C.cardHover; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = ""; }}>
                  <td style={TD}>{shortTS(ev.timestamp)}</td>
                  <td style={TD}><B c="blue">{(ev.service || "").replace("kms-", "")}</B></td>
                  <td style={{ ...TD, color: C.text, fontWeight: 500 }} title={ev.action}>
                    {formatAction(ev.action)}
                  </td>
                  <td style={TD}>{ev.actor_id || "-"}</td>
                  <td style={TD}>{(() => { const o = eventOrigin(ev); return o.origin === "agent"
                    ? <span title={o.agentId ? `agent: ${o.agentId}` : "agent-originated"}><B c="amber">agent</B></span>
                    : <span style={{ color: C.muted, fontSize: 9 }}>service</span>; })()}</td>
                  <td style={TD}>{ev.target_id || "-"}</td>
                  <td style={TD}><B c={resultTone(ev.result)}>{ev.result}</B></td>
                  <td style={TD}>
                    <span style={{ color: riskColor(Number(ev.risk_score || 0)), fontWeight: 600 }}>
                      {ev.risk_score ?? 0}
                    </span>
                  </td>
                  <td style={TD}>
                    <span style={{ color: ev.fips_compliant ? C.green : C.muted }}>
                      {ev.fips_compliant ? "\u2713" : "-"}
                    </span>
                  </td>
                  <td style={{ ...TD, fontFamily: "'JetBrains Mono',monospace", fontSize: 9 }}>
                    {abbrevHash(ev.chain_hash)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* pagination */}
      <div style={{ display: "flex", gap: 8, alignItems: "center", justifyContent: "space-between" }}>
        <span style={{ fontSize: 10, color: C.muted }}>
          Showing {filteredEvents.length > 0 ? offset + 1 : 0}–{offset + filteredEvents.length} (page size {PAGE_SIZE})
        </span>
        <div style={{ display: "flex", gap: 6 }}>
          <Btn small disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous</Btn>
          <Btn small disabled={events.length < PAGE_SIZE} onClick={() => setOffset(offset + PAGE_SIZE)}>Next</Btn>
        </div>
      </div>
    </>;
  };



  /* ── render: Forensics sub-tab ── */

  const renderForensics = () => (
    <>
      <Tabs tabs={["Timeline", "Session", "Correlation"]} active={forensicMode} onChange={setForensicMode} />

      <div style={{ display: "flex", gap: 6, marginBottom: 14, alignItems: "center" }}>
        <Inp
          placeholder={
            forensicMode === "Timeline" ? "Enter target ID (e.g., key ID)..." :
            forensicMode === "Session" ? "Enter session ID..." :
            "Enter correlation ID..."
          }
          w={320}
          value={forensicInput}
          onChange={(e: any) => setForensicInput(e.target.value)}
          onKeyDown={(e: any) => { if (e.key === "Enter") loadForensic(); }}
        />
        <Btn small primary onClick={loadForensic} disabled={forensicLoading}>
          {forensicLoading ? "Loading..." : "Load"}
        </Btn>
        <span style={{ fontSize: 10, color: C.muted }}>
          {forensicMode === "Timeline" && "View all audit events for a specific entity (key, policy, user)"}
          {forensicMode === "Session" && "Trace a user's complete session activity"}
          {forensicMode === "Correlation" && "Follow a chain of correlated operations"}
        </span>
      </div>

      {forensicEvents.length > 0 && (
        <Card>
          <div style={{ fontSize: 10, fontWeight: 600, color: C.dim, marginBottom: 10, textTransform: "uppercase", letterSpacing: 0.6 }}>
            {forensicMode} — {forensicEvents.length} event(s)
          </div>
          <div style={{ position: "relative", paddingLeft: 20 }}>
            {/* vertical timeline line */}
            <div style={{ position: "absolute", left: 7, top: 0, bottom: 0, width: 2, background: C.border }} />
            {forensicEvents.map((ev, idx) => (
              <div key={ev.id || idx} style={{ position: "relative", marginBottom: 12, paddingLeft: 16 }}>
                {/* timeline dot */}
                <div style={{
                  position: "absolute", left: -17, top: 4, width: 10, height: 10, borderRadius: 5,
                  background: RESULT_COLORS[ev.result] || C.dim,
                  border: `2px solid ${C.card}`
                }} />
                <div style={{
                  background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: "8px 12px",
                  cursor: "pointer"
                }} onClick={() => setSelectedEvent(ev)}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.borderColor = C.accent; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.borderColor = C.border; }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 4 }}>
                    <span style={{ fontSize: 9, color: C.muted }}>{fmtTS(ev.timestamp)}</span>
                    <B c="blue">{(ev.service || "").replace("kms-", "")}</B>
                    <B c={resultTone(ev.result)}>{ev.result}</B>
                    <span style={{ fontSize: 10, color: C.text, fontWeight: 600 }} title={ev.action}>
                      {formatAction(ev.action)}
                    </span>
                  </div>
                  <div style={{ fontSize: 9, color: C.dim }}>
                    Actor: {ev.actor_id || "-"} &bull; Target: {ev.target_id || "-"} &bull;
                    Risk: <span style={{ color: riskColor(Number(ev.risk_score || 0)) }}>{ev.risk_score ?? 0}</span> &bull;
                    Seq: {ev.sequence} &bull; Hash: <span style={{ fontFamily: "'JetBrains Mono',monospace" }}>{abbrevHash(ev.chain_hash)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {forensicEvents.length === 0 && forensicInput.trim() && !forensicLoading && (
        <Card>
          <div style={{ textAlign: "center", color: C.muted, fontSize: 10, padding: 20 }}>
            No events found for this {forensicMode.toLowerCase()} query.
          </div>
        </Card>
      )}
    </>
  );

  /* ── event detail modal ── */

  const renderEventModal = () => {
    if (!selectedEvent) return null;
    const ev = selectedEvent;
    const fields = [
      ["ID", ev.id],
      ["Timestamp", fmtTS(ev.timestamp)],
      ["Service", ev.service],
      ["Action", ev.action],
      ["Result", ev.result],
      ["Actor", `${ev.actor_id} (${ev.actor_type || "unknown"})`],
      ["Target", `${ev.target_id} (${ev.target_type || "unknown"})`],
      ["Source IP", ev.source_ip],
      ["Method", ev.method],
      ["Endpoint", ev.endpoint],
      ["Status Code", ev.status_code],
      ["Duration", `${ev.duration_ms ?? 0}ms`],
      ["Risk Score", ev.risk_score],
      ["FIPS Compliant", ev.fips_compliant ? "Yes" : "No"],
      ["Sequence", ev.sequence],
      ["Chain Hash", ev.chain_hash],
      ["Previous Hash", ev.previous_hash],
      ["Session ID", ev.session_id],
      ["Correlation ID", ev.correlation_id],
      ["Node ID", ev.node_id],
      ["User Agent", ev.user_agent],
      ["Error", ev.error_message]
    ];

    return (
      <Modal open={true} onClose={() => setSelectedEvent(null)} title="Audit Event Detail" wide>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px 16px", marginBottom: 14 }}>
          {fields.map(([label, value]) => (
            <div key={String(label)}>
              <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6 }}>{label}</div>
              <div style={{ fontSize: 10, color: C.text, wordBreak: "break-all", fontFamily: String(label).includes("Hash") ? "'JetBrains Mono',monospace" : "inherit" }}>
                {String(value ?? "-") || "-"}
              </div>
            </div>
          ))}
        </div>

        {/* forensic navigation links */}
        <div style={{ display: "flex", gap: 6, marginBottom: 12, flexWrap: "wrap" }}>
          {ev.target_id && (
            <Btn small onClick={() => { setSelectedEvent(null); openForensic("Timeline", ev.target_id); }}>
              View Timeline ({ev.target_id})
            </Btn>
          )}
          {ev.session_id && (
            <Btn small onClick={() => { setSelectedEvent(null); openForensic("Session", ev.session_id); }}>
              View Session ({abbrevHash(ev.session_id)})
            </Btn>
          )}
          {ev.correlation_id && (
            <Btn small onClick={() => { setSelectedEvent(null); openForensic("Correlation", ev.correlation_id); }}>
              View Correlation ({abbrevHash(ev.correlation_id)})
            </Btn>
          )}
        </div>

        {/* metadata JSON */}
        {ev.details && Object.keys(ev.details).length > 0 && (
          <>
            <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, marginBottom: 4 }}>Metadata</div>
            <pre style={{
              background: C.bg, border: `1px solid ${C.border}`, borderRadius: 6, padding: 10,
              fontSize: 9, color: C.dim, overflow: "auto", maxHeight: 160,
              fontFamily: "'JetBrains Mono',monospace"
            }}>
              {JSON.stringify(ev.details, null, 2)}
            </pre>
          </>
        )}

        {/* tags */}
        {Array.isArray(ev.tags) && ev.tags.length > 0 && (
          <div style={{ marginTop: 8 }}>
            <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, marginBottom: 4 }}>Tags</div>
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {ev.tags.map((t, i) => <B key={i} c="purple">{t}</B>)}
            </div>
          </div>
        )}
      </Modal>
    );
  };

  /* ── main render ── */

  return (
    <div>
      <IntegrityBar />
      <Tabs tabs={["Events", "Forensics", "Checkpoints"]} active={subTab} onChange={setSubTab} />

      {subTab === "Events" && renderEvents()}
      {subTab === "Forensics" && renderForensics()}
      {subTab === "Checkpoints" && <CheckpointsSection session={session} />}

      {renderEventModal()}

      {/* audit integration note */}
      <div style={{ marginTop: 16, padding: "8px 12px", borderRadius: 8, background: C.card, border: `1px solid ${C.border}`, fontSize: 9, color: C.muted }}>
        Every service publishes to the single audit stream. Events are hash-chained (SHA-256), HMAC-signed, covered
        by signed checkpoints (ECDSA-P384) and stored append-only; a fail-closed WAL covers outages. Charts are under Overview → Analytics →
        Audit activity; alerts raised from these events are triaged in the Alert Center.
      </div>
    </div>
  );
};
