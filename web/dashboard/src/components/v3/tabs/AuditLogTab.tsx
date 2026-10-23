// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useState } from "react";
import { ChainStatus } from "./ChainStatus";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Inp, Modal, Section, Sel } from "../legacyPrimitives";
import {
  listAuditEvents,
  verifyAuditChain,
  getAuditConfig,
  exportEventsAsCSV,
  exportEventsAsCEF,
  listAuditCheckpoints,
  type AuditEvent,
  type AuditConfig,
  type AuditCheckpoint,
  type ChainVerifyResult,
  type InvestigatePivots
} from "../../../lib/audit";
import { AuditAnalyticsPanel } from "./AuditAnalyticsPanel";
import { AuditEventDetail } from "./AuditEventDetail";
import { AuditInvestigate } from "./AuditInvestigate";
import { AnchorSettings } from "./AnchorSettings";
import { abbrevHash, eventOrigin, formatAction, isHTTPRequestAction, resultTone, riskColor, shortTS } from "./auditFormat";

/* ── constants ── */

const SERVICES = [
  "auth", "key", "keycore", "secrets", "certs", "policy", "governance",
  "audit", "compliance", "posture", "reporting", "cluster",
  "confidential", "hyok", "byok", "ekm",
  "pqc",
  "autokey", "keyaccess", "signing",
  "workload", "dataprotect", "kmip", "sbom",
  "discovery", "cloud", "hsm",
];

const PAGE_SIZE = 100;

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
  fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase",
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

const ANCHOR_LABEL: Record<string, { label: string; color: string }> = {
  anchored: { label: "Timestamped", color: C.greenFg },
  late: { label: "Timestamped late", color: C.amberFg },
  invalid: { label: "Token invalid", color: C.redFg },
  not_anchored: { label: "-", color: C.muted },
};

const CheckpointsSection = ({ session, onToast, onNavigate }: { session: any; onToast?: (m: string) => void; onNavigate?: (t: string) => void }) => {
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
  const mono = { fontFamily: "var(--font-mono)", fontSize: 10 };

  return (
    <div>
      <AnchorSettings session={session} onToast={onToast} onNavigate={onNavigate} />
      <Section t="Signed Checkpoints" act={<Btn l={loading ? "Verifying..." : "Re-verify"} c={C.cyan} click={load} />}>
        <Card>
          <div className="vk-fold" tabIndex={0} style={{ fontSize: 11, color: C.muted, marginBottom: 12 }}>
            Every 10 minutes each node signs the head of each chain it writes (sequence and chain hash) with an
            ECDSA-P384 key held only in memory. The chain hash commits to every earlier event, so a verified
            checkpoint proves nothing before it has changed since. Keys and checkpoints are audit events, so they
            also reach your event streams. Listing re-verifies each signature and the stored head.
          </div>
          {error ? (
            <div style={{ color: C.redFg, padding: 12 }}>Checkpoints unavailable: {error}</div>
          ) : items.length === 0 && !loading ? (
            <div style={{ color: C.dim, padding: 16, textAlign: "center" }}>
              No checkpoints yet. The first is signed within 10 minutes of audit activity.
            </div>
          ) : (
            <>
              {failed > 0 && (
                <div style={{ color: C.redFg, fontSize: 11, marginBottom: 8 }}>
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
                    <th style={{ padding: "6px" }}>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((c) => {
                    const st = CHECKPOINT_STATUS[c.status] || { label: c.status, color: C.amber };
                    return (
                      <tr key={c.event_id} style={{ borderBottom: `1px solid ${C.border}10`, cursor: "pointer" }} onClick={() => setOpen(c)}>
                        <td style={{ padding: "6px", color: st.color, fontWeight: 600 }}>{st.label}</td>
                        <td style={{ padding: "6px", color: C.cyanFg }}>#{c.sequence}</td>
                        <td style={{ padding: "6px" }}>{c.chain_node || "local"}</td>
                        <td style={{ padding: "6px", ...mono, color: C.text }}>{c.chain_hash.slice(0, 16)}…</td>
                        <td style={{ padding: "6px", ...mono, color: C.dim }}>{c.key_id.slice(0, 12)}…</td>
                        <td style={{ padding: "6px", color: C.dim, fontSize: 10 }}>{c.signed_at ? new Date(c.signed_at).toLocaleString() : "--"}</td>
                        <td style={{ padding: "6px", fontSize: 10, color: (ANCHOR_LABEL[c.anchor?.status || "not_anchored"] || ANCHOR_LABEL.invalid!).color }} title={c.anchor?.error || c.anchor?.tsa || ""}>
                          {(ANCHOR_LABEL[c.anchor?.status || "not_anchored"] || ANCHOR_LABEL.invalid!).label}
                        </td>
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
          <div className="vk-fold" tabIndex={0} style={{ fontSize: 11, color: C.muted, marginBottom: 8 }}>
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
            ["Timestamp", open.anchor && open.anchor.status !== "not_anchored"
              ? `${(ANCHOR_LABEL[open.anchor.status] || ANCHOR_LABEL.invalid!).label}${open.anchor.gen_time ? ` at ${new Date(open.anchor.gen_time).toLocaleString()}` : ""} by ${open.anchor.tsa || "?"} (serial ${open.anchor.serial || "?"}, ${open.anchor.trust || "?"})${open.anchor.error ? `: ${open.anchor.error}` : ""}`
              : "not timestamped"],
            ...(open.anchor?.token_b64 ? [["RFC 3161 token (base64 DER)", open.anchor.token_b64]] : []),
          ].map(([k, v]) => (
            <div key={k} style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6 }}>{k}</div>
              <div style={{ ...mono, color: C.text, wordBreak: "break-all", whiteSpace: "pre-wrap" }}>{v}</div>
            </div>
          ))}
        </Modal>
      )}
    </div>
  );
};

// The view comes from the sidebar (SUB_PANES.audit); a view may switch to
// another, as the event card does to Investigate.
const VIEWS = ["events", "activity", "investigate", "checkpoints"];

export const AuditLogTab = ({ session, onToast, subView, onSubViewChange, onNavigate }: any) => {
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

  const view = VIEWS.includes(String(subView || "")) ? String(subView) : "events";

  // event detail
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  // Investigate: the pivots outlive a switch of view.
  const [pivots, setPivots] = useState<InvestigatePivots>({});
  const investigate = (p: InvestigatePivots) => { setPivots(p); onSubViewChange?.("investigate"); };

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

  /* ── integrity status bar ── */


  const IntegrityBar = () => (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", marginBottom: 14, padding: "8px 12px", borderRadius: 4, background: C.card, border: `1px solid ${C.border}` }}>
      <ChainStatus result={chainResult} />
      <B c="neutral">{filteredEvents.length} events loaded</B>
      <B c={config?.fail_closed ? "neutral" : "amber"}>
        Fail-closed: {config?.fail_closed ? "ACTIVE" : "INACTIVE"}
      </B>
      <B c="neutral">SHA-256 hash chain</B>
      <B c="neutral">Immutable storage</B>
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
      <div style={{ display: "flex", gap: 8, marginBottom: 10, flexWrap: "wrap", alignItems: "center", justifyContent: "space-between" }}>
       <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", flex: "1 1 100%", minWidth: 0 }}>
        <Inp placeholder="Search actions, actors, targets..." value={searchQuery} style={{ flex: "1 1 200px", width: "auto", minWidth: 180 }}
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
       </div><div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap", justifyContent: "flex-end", flex: "1 1 100%" }}>
        <Inp style={{ width: 170 }} value={signingKeyId} onChange={(e:any)=>setSigningKeyId(e.target.value)} placeholder="Signing key ID (optional)" title="Sign exported files with this key"/>
        <Btn small onClick={() => void exportEventsAsCSV(filteredEvents, signingKeyId ? session : undefined, signingKeyId || undefined)}>{signingKeyId ? "Export Signed CSV" : "Export CSV"}</Btn>
        <Btn small onClick={() => void exportEventsAsCEF(filteredEvents, signingKeyId ? session : undefined, signingKeyId || undefined)}>{signingKeyId ? "Export Signed CEF" : "Export CEF"}</Btn>
        <Btn small primary onClick={verifyChain} disabled={chainVerifying}>
          {chainVerifying ? "Verifying..." : "Verify Chain"}
        </Btn>
        <Btn small onClick={() => load()} disabled={loading}>Refresh</Btn>
      </div></div>

      {/* chain breaks display */}
      {chainBreaks.length > 0 && (
        <Card style={{ marginBottom: 10, borderColor: C.red }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.redFg, marginBottom: 6 }}>Chain Integrity Breaks Detected</div>
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
                    : <span style={{ color: C.muted, fontSize: 10 }}>service</span>; })()}</td>
                  <td style={TD}>{ev.target_id || "-"}</td>
                  <td style={TD}><B c={resultTone(ev.result)}>{ev.result}</B></td>
                  <td style={TD}>
                    <span style={{ color: riskColor(Number(ev.risk_score || 0)), fontWeight: 600 }}>
                      {ev.risk_score ?? 0}
                    </span>
                  </td>
                  <td style={TD}>
                    <span style={{ color: ev.fips_compliant ? C.greenFg : C.muted }}>
                      {ev.fips_compliant ? "\u2713" : "-"}
                    </span>
                  </td>
                  <td style={{ ...TD, fontFamily: "var(--font-mono)", fontSize: 10 }}>
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



  /* ── main render ── */

  return (
    <div>
      <IntegrityBar />

      {view === "events" && renderEvents()}
      {view === "activity" && <AuditAnalyticsPanel session={session} onOpenEvent={setSelectedEvent} />}
      {view === "investigate" && <AuditInvestigate session={session} pivots={pivots} onPivotsChange={setPivots} onOpenEvent={setSelectedEvent} />}
      {view === "checkpoints" && <CheckpointsSection session={session} onToast={onToast} onNavigate={onNavigate} />}

      <AuditEventDetail event={selectedEvent} onClose={() => setSelectedEvent(null)} onInvestigate={investigate} />

      {/* audit integration note */}
      <div className="vk-fold" tabIndex={0} style={{ marginTop: 16, padding: "8px 12px", borderRadius: 4, background: C.card, border: `1px solid ${C.border}`, fontSize: 10, color: C.muted }}>
        Every service publishes to the single audit stream. Events are hash-chained (SHA-256), HMAC-signed, covered
        by signed checkpoints (ECDSA-P384) and stored append-only; a fail-closed WAL covers outages. Charts are under Activity;
        Investigate follows a person, object, address, sign-in or request; alerts are triaged in the Alert Center.
      </div>
    </div>
  );
};
