// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar as RBar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  RadialBarChart,
  RadialBar,
  PieChart,
  Pie,
  Cell,
  Legend
} from "recharts";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Inp, Modal, Row2, Row3, Section, Sel, Stat, Tabs } from "../legacyPrimitives";
import {
  listAuditEvents,
  getAuditEvent,
  getAuditTimeline,
  getAuditSession,
  getAuditCorrelation,
  verifyAuditChain,
  getAuditConfig,
  getAuditAlertStats,
  listAuditAlerts,
  acknowledgeAuditAlert,
  resolveAuditAlert,
  exportEventsAsCSV,
  exportEventsAsCEF,
  listMerkleEpochs,
  getEventMerkleProof,
  verifyMerkleProof,
  buildMerkleEpoch,
  type AuditEvent,
  type AuditAlert,
  type AuditAlertStats,
  type AuditConfig,
  type ChainVerifyResult,
  type MerkleEpoch,
  type MerkleProofResponse
} from "../../../lib/audit";

/* ── constants ── */

const SERVICES = [
  "kms-keycore", "kms-auth", "kms-policy", "kms-audit", "kms-compliance",
  "kms-posture", "kms-reporting", "kms-cluster", "kms-billing", "kms-payment",
  "kms-connector-aws", "kms-connector-azure", "kms-connector-gcp",
  "kms-connector-hashicorp", "kms-connector-thales",
  "kms-sdk-go", "kms-sdk-python", "kms-sdk-java", "kms-sdk-node", "kms-sdk-rest",
  "kms-pkcs11", "kms-kmip", "kms-jce", "kms-cng", "kms-certauth",
  "kms-byok", "kms-fips", "kms-hsm", "kms-secret-engine",
  "kms-governance", "kms-rotation", "kms-data-protection", "kms-workbench"
];

const PAGE_SIZE = 100;

const RESULT_COLORS: Record<string, string> = { success: C.green, failure: C.red, denied: C.amber };
const SEVERITY_COLORS: Record<string, string> = { critical: C.red, high: C.orange, medium: C.amber, low: C.blue, info: C.dim };
const RISK_BUCKET_COLORS = [C.green, C.green, C.amber, C.orange, C.red];

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

function sevTone(s: string) {
  const v = String(s || "").toLowerCase();
  if (v === "critical" || v === "high") return "red";
  if (v === "medium" || v === "warning") return "amber";
  return "blue";
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

function timeRangeToFrom(range: string): string {
  const now = Date.now();
  switch (range) {
    case "24h": return new Date(now - 24 * 60 * 60 * 1000).toISOString();
    case "7d":  return new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
    case "30d": return new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();
    default:    return "";
  }
}

/* ── chart tooltips ── */

const ChartTooltip = ({ containerStyle, children }: any) => (
  <div style={{ background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 8, padding: "8px 12px", fontSize: 10, color: C.text, boxShadow: "0 4px 20px rgba(0,0,0,.5)", ...containerStyle }}>
    {children}
  </div>
);

const VolumeTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <ChartTooltip>
      <div style={{ fontWeight: 700, marginBottom: 4, color: C.accent }}>{label}</div>
      <div>Events: <span style={{ fontWeight: 700, color: C.text }}>{payload[0]?.value}</span></div>
    </ChartTooltip>
  );
};

const BarTooltip = ({ active, payload, label }: any) => {
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
      <div style={{ fontWeight: 700, marginBottom: 4, color: C.accent }}>Risk: {label}</div>
      <div>Events: <span style={{ fontWeight: 700, color: C.text }}>{payload[0]?.value}</span></div>
    </ChartTooltip>
  );
};

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

// ── Merkle Tree Integrity Section ────────────────────────────

const MerkleSection = ({ session }: { session: any }) => {
  const [epochs, setEpochs] = useState<MerkleEpoch[]>([]);
  const [loading, setLoading] = useState(true);
  const [building, setBuilding] = useState(false);
  const [proofResult, setProofResult] = useState<{ eventId: string; proof?: MerkleProofResponse; verified?: boolean; error?: string } | null>(null);
  const [proofEventId, setProofEventId] = useState("");

  const loadEpochs = async () => {
    try {
      setLoading(true);
      const items = await listMerkleEpochs(session, 50);
      setEpochs(items);
    } catch { /* ignore */ } finally { setLoading(false); }
  };

  useEffect(() => { loadEpochs(); }, []);

  const handleBuild = async () => {
    try {
      setBuilding(true);
      const result = await buildMerkleEpoch(session, 1000);
      if (result.epoch) {
        loadEpochs();
      }
    } catch { /* ignore */ } finally { setBuilding(false); }
  };

  const handleVerifyEvent = async () => {
    const id = proofEventId.trim();
    if (!id) return;
    try {
      const proof = await getEventMerkleProof(session, id);
      const result = await verifyMerkleProof(session, {
        leaf_hash: proof.leaf_hash,
        leaf_index: proof.leaf_index,
        siblings: proof.siblings,
        root: proof.root,
      });
      setProofResult({ eventId: id, proof, verified: result.valid });
    } catch (e) {
      setProofResult({ eventId: id, error: errMsg(e) });
    }
  };

  return (
    <div>
      <Section t="Merkle Tree Integrity" act={
        <div style={{ display: "flex", gap: 8 }}>
          <Btn l={building ? "Building..." : "Build Epoch"} c={C.green} click={handleBuild} />
          <Btn l="Refresh" c={C.cyan} click={loadEpochs} />
        </div>
      }>
        <Card>
          <div style={{ fontSize: 11, color: C.muted, marginBottom: 12 }}>
            Merkle trees are built over batches of audit events (epochs). Each epoch produces a root hash that
            cryptographically commits to all events in the batch. Any single event can be verified with an O(log N)
            inclusion proof — no need to replay the full chain.
          </div>

          {/* Epoch table */}
          {epochs.length === 0 && !loading ? (
            <div style={{ color: C.dim, padding: 16, textAlign: "center" }}>
              No Merkle epochs built yet. Click "Build Epoch" to create the first one from existing audit events.
            </div>
          ) : (
            <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}`, color: C.dim, textAlign: "left" }}>
                  <th style={{ padding: "6px" }}>Epoch</th>
                  <th style={{ padding: "6px" }}>Seq Range</th>
                  <th style={{ padding: "6px" }}>Leaves</th>
                  <th style={{ padding: "6px" }}>Root Hash</th>
                  <th style={{ padding: "6px" }}>Built</th>
                </tr>
              </thead>
              <tbody>
                {epochs.map((e) => (
                  <tr key={e.id} style={{ borderBottom: `1px solid ${C.border}10` }}>
                    <td style={{ padding: "6px", color: C.cyan, fontWeight: 600 }}>#{e.epoch_number}</td>
                    <td style={{ padding: "6px", color: C.fg }}>{e.seq_from} — {e.seq_to}</td>
                    <td style={{ padding: "6px" }}>{e.leaf_count}</td>
                    <td style={{ padding: "6px", fontFamily: "monospace", fontSize: 10, color: C.green }}>
                      {e.tree_root.slice(0, 16)}...{e.tree_root.slice(-8)}
                    </td>
                    <td style={{ padding: "6px", color: C.dim, fontSize: 10 }}>
                      {e.created_at ? new Date(e.created_at).toLocaleString() : "--"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </Section>

      {/* Event Proof Verification */}
      <Section t="Event Inclusion Proof">
        <Card>
          <div style={{ display: "flex", gap: 8, alignItems: "flex-end", marginBottom: 12 }}>
            <div style={{ flex: 1 }}>
              <Inp l="Event ID" v={proofEventId} set={setProofEventId} placeholder="evt_..." />
            </div>
            <Btn l="Verify" c={C.cyan} click={handleVerifyEvent} />
          </div>

          {proofResult && (
            <div style={{ padding: 12, borderRadius: 8, background: C.card, border: `1px solid ${C.border}`, fontSize: 11 }}>
              {proofResult.error ? (
                <div style={{ color: C.red }}>{proofResult.error}</div>
              ) : proofResult.proof ? (
                <div>
                  <div style={{ marginBottom: 8 }}>
                    <span style={{ fontWeight: 600, color: proofResult.verified ? C.green : C.red }}>
                      {proofResult.verified ? "VERIFIED" : "VERIFICATION FAILED"}
                    </span>
                    {" — "}Event <span style={{ color: C.cyan }}>{proofResult.eventId}</span>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, color: C.dim }}>
                    <div>Epoch: <span style={{ color: C.fg }}>{proofResult.proof.epoch_id.slice(0, 12)}</span></div>
                    <div>Leaf Index: <span style={{ color: C.fg }}>{proofResult.proof.leaf_index}</span></div>
                    <div>Sequence: <span style={{ color: C.fg }}>{proofResult.proof.sequence}</span></div>
                    <div>Proof Steps: <span style={{ color: C.fg }}>{proofResult.proof.siblings.length}</span></div>
                  </div>
                  <div style={{ marginTop: 8 }}>
                    <div style={{ fontSize: 10, color: C.muted, marginBottom: 4 }}>Root Hash</div>
                    <div style={{ fontFamily: "monospace", fontSize: 10, color: C.green, wordBreak: "break-all" }}>
                      {proofResult.proof.root}
                    </div>
                  </div>
                  <div style={{ marginTop: 8 }}>
                    <div style={{ fontSize: 10, color: C.muted, marginBottom: 4 }}>Inclusion Path</div>
                    {proofResult.proof.siblings.map((s, i) => (
                      <div key={i} style={{ fontFamily: "monospace", fontSize: 10, color: C.dim, marginBottom: 2 }}>
                        [{i}] {s.position.toUpperCase()}: {s.hash.slice(0, 24)}...
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          )}
        </Card>
      </Section>
    </div>
  );
};

export const AuditLogTab = ({ session, onToast }: any) => {
  const [loading, setLoading] = useState(false);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [config, setConfig] = useState<AuditConfig | null>(null);
  const [chainResult, setChainResult] = useState<ChainVerifyResult | null>(null);
  const [chainVerifying, setChainVerifying] = useState(false);
  const [alertStats, setAlertStats] = useState<AuditAlertStats | null>(null);
  const [alerts, setAlerts] = useState<AuditAlert[]>([]);

  // filters
  const [serviceFilter, setServiceFilter] = useState("");
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
      const [eventList, cfg, stats, alertList] = await Promise.all([
        listAuditEvents(session, {
          result: resultFilter || undefined,
          from: from || undefined,
          limit: PAGE_SIZE,
          offset
        }),
        getAuditConfig(session),
        getAuditAlertStats(session),
        listAuditAlerts(session, { limit: 100 })
      ]);
      setEvents(Array.isArray(eventList) ? eventList : []);
      setConfig(cfg);
      setAlertStats(stats);
      setAlerts(Array.isArray(alertList) ? alertList : []);
      if (!silent) onToast?.("Audit log refreshed.");
    } catch (error) {
      onToast?.(`Audit load failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => { void load(true); }, [session?.token, session?.tenantId, resultFilter, timeRange, offset]);

  /* ── client-side filters (service + search) ── */

  const filteredEvents = useMemo(() => {
    let out = events;
    if (serviceFilter) out = out.filter((e) => e.service === serviceFilter);
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      out = out.filter((e) =>
        (e.action || "").toLowerCase().includes(q) ||
        (e.actor_id || "").toLowerCase().includes(q) ||
        (e.target_id || "").toLowerCase().includes(q) ||
        (e.service || "").toLowerCase().includes(q) ||
        (e.description || "").toLowerCase().includes(q)
      );
    }
    return out;
  }, [events, serviceFilter, searchQuery]);

  /* ── analytics computed data ── */

  const resultDistribution = useMemo(() => {
    const counts: Record<string, number> = {};
    filteredEvents.forEach((e) => { counts[e.result] = (counts[e.result] || 0) + 1; });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [filteredEvents]);

  const serviceDistribution = useMemo(() => {
    const counts: Record<string, number> = {};
    filteredEvents.forEach((e) => { counts[e.service] = (counts[e.service] || 0) + 1; });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, value]) => ({ name: name.replace("kms-", ""), fullName: name, value }));
  }, [filteredEvents]);

  const riskHistogram = useMemo(() => {
    const buckets = [0, 0, 0, 0, 0];
    filteredEvents.forEach((e) => {
      const s = Math.max(0, Math.min(100, Number(e.risk_score || 0)));
      if (s <= 20) buckets[0]++;
      else if (s <= 40) buckets[1]++;
      else if (s <= 60) buckets[2]++;
      else if (s <= 80) buckets[3]++;
      else buckets[4]++;
    });
    return ["0-20", "21-40", "41-60", "61-80", "81-100"].map((range, i) => ({
      range, count: buckets[i]
    }));
  }, [filteredEvents]);

  const volumeTimeline = useMemo(() => {
    const buckets: Record<string, number> = {};
    filteredEvents.forEach((e) => {
      const ts = String(e.timestamp || e.created_at || "").trim();
      if (!ts) return;
      const dt = new Date(ts);
      if (Number.isNaN(dt.getTime())) return;
      const key = `${dt.getMonth() + 1}/${dt.getDate()} ${String(dt.getHours()).padStart(2, "0")}:00`;
      buckets[key] = (buckets[key] || 0) + 1;
    });
    return Object.entries(buckets)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([time, count]) => ({ time, count }));
  }, [filteredEvents]);

  const topActors = useMemo(() => {
    const counts: Record<string, number> = {};
    filteredEvents.forEach((e) => {
      if (e.actor_id) counts[e.actor_id] = (counts[e.actor_id] || 0) + 1;
    });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([actor, count]) => ({ actor, count }));
  }, [filteredEvents]);

  const severityGaugeData = useMemo(() => {
    if (!alertStats?.open_by_severity) return [];
    return Object.entries(alertStats.open_by_severity).map(([name, value]) => ({
      name, value, fill: SEVERITY_COLORS[name.toLowerCase()] || C.dim
    }));
  }, [alertStats]);

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
      setForensicEvents(results);
      onToast?.(`${results.length} event(s) loaded.`);
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
        setForensicEvents(results);
      } catch (error) {
        onToast?.(`Forensic query failed: ${errMsg(error)}`);
      } finally {
        setForensicLoading(false);
      }
    }, 50);
  };

  /* ── alert actions ── */

  const handleAcknowledge = async (alertId: string) => {
    try {
      await acknowledgeAuditAlert(session, alertId, session?.username);
      onToast?.("Alert acknowledged.");
      void load(true);
    } catch (error) {
      onToast?.(`Acknowledge failed: ${errMsg(error)}`);
    }
  };

  const handleResolve = async (alertId: string) => {
    try {
      await resolveAuditAlert(session, alertId, session?.username, "Resolved via dashboard");
      onToast?.("Alert resolved.");
      void load(true);
    } catch (error) {
      onToast?.(`Resolve failed: ${errMsg(error)}`);
    }
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
      <B c="blue">250+ event types</B>
      <B c="purple">SHA-256 hash chain</B>
      <B c="accent">Immutable storage</B>
      {chainResult && !chainResult.ok && (
        <B c="red">{chainResult.breaks.length} break(s) detected</B>
      )}
    </div>
  );

  /* ── render: Events sub-tab ── */

  const renderEvents = () => (
    <>
      {/* filter bar */}
      <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap", alignItems: "center" }}>
        <Inp placeholder="Search actions, actors, targets..." w={240} value={searchQuery}
          onChange={(e: any) => setSearchQuery(e.target.value)} />
        <Sel w={140} value={serviceFilter} onChange={(e: any) => { setServiceFilter(e.target.value); setOffset(0); }}>
          <option value="">All Services</option>
          {SERVICES.map((s) => <option key={s} value={s}>{s}</option>)}
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
      {chainResult && !chainResult.ok && chainResult.breaks.length > 0 && (
        <Card style={{ marginBottom: 10, borderColor: C.red }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.red, marginBottom: 6 }}>Chain Integrity Breaks Detected</div>
          <div style={{ maxHeight: 120, overflow: "auto" }}>
            {chainResult.breaks.map((b, i) => (
              <div key={i} style={{ fontSize: 10, color: C.dim, marginBottom: 3 }}>
                Seq #{b.sequence} — Event: {abbrevHash(b.event_id)} — {b.reason}
              </div>
            ))}
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
                <th style={TH}>Target</th>
                <th style={TH}>Result</th>
                <th style={TH}>Risk</th>
                <th style={TH}>FIPS</th>
                <th style={TH}>Chain</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.length === 0 && (
                <tr><td colSpan={9} style={{ ...TD, textAlign: "center", color: C.muted, padding: 20 }}>
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
                  <td style={{ ...TD, color: C.text, fontWeight: 500 }}>{ev.action}</td>
                  <td style={TD}>{ev.actor_id || "-"}</td>
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
    </>
  );

  /* ── render: Analytics sub-tab ── */

  const renderAnalytics = () => (
    <>
      {/* stat cards */}
      <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
        <Stat l="Total Events" v={filteredEvents.length} c="accent" />
        <Stat l="Open Alerts" v={alertStats?.total_open ?? 0} c={alertStats && alertStats.total_open > 0 ? "red" : "green"} />
        <Stat l="Acknowledged" v={alertStats?.total_acknowledged ?? 0} c="amber" />
        <Stat l="Resolved" v={alertStats?.total_resolved ?? 0} c="green" />
      </div>

      {/* row 1: three charts */}
      <Row3>
        {/* events by result donut */}
        <Card>
          <div style={{ fontSize: 10, fontWeight: 600, color: C.dim, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 }}>Events by Result</div>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={resultDistribution} cx="50%" cy="50%" innerRadius={40} outerRadius={65}
                dataKey="value" nameKey="name" paddingAngle={3} strokeWidth={0}>
                {resultDistribution.map((entry) => (
                  <Cell key={entry.name} fill={RESULT_COLORS[entry.name] || C.dim} />
                ))}
              </Pie>
              <Tooltip content={<BarTooltip />} />
              <Legend wrapperStyle={{ fontSize: 9, color: C.dim }} />
            </PieChart>
          </ResponsiveContainer>
        </Card>

        {/* events by service bar */}
        <Card>
          <div style={{ fontSize: 10, fontWeight: 600, color: C.dim, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 }}>Top Services</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={serviceDistribution} layout="vertical" margin={{ left: 40, right: 10 }}>
              <XAxis type="number" tick={{ fill: C.muted, fontSize: 9 }} axisLine={{ stroke: C.border }} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: C.dim, fontSize: 9 }} axisLine={false} tickLine={false} width={60} />
              <Tooltip content={<BarTooltip />} />
              <RBar dataKey="value" name="Events" fill={C.blue} radius={[0, 4, 4, 0]} barSize={12} />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* risk distribution histogram */}
        <Card>
          <div style={{ fontSize: 10, fontWeight: 600, color: C.dim, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 }}>Risk Distribution</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={riskHistogram} margin={{ left: 0, right: 10 }}>
              <XAxis dataKey="range" tick={{ fill: C.muted, fontSize: 9 }} axisLine={{ stroke: C.border }} tickLine={false} />
              <YAxis tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} />
              <Tooltip content={<HistogramTooltip />} />
              <RBar dataKey="count" name="Events" radius={[4, 4, 0, 0]} barSize={24}>
                {riskHistogram.map((_, i) => (
                  <Cell key={i} fill={RISK_BUCKET_COLORS[i]} />
                ))}
              </RBar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </Row3>

      {/* event volume timeline */}
      <Section title="Event Volume Timeline">
        <Card>
          {volumeTimeline.length === 0 ? (
            <div style={{ textAlign: "center", color: C.muted, fontSize: 10, padding: 20 }}>No volume data available.</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={volumeTimeline} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="auditVolumeGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={C.accent} stopOpacity={0.25} />
                    <stop offset="95%" stopColor={C.accent} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" tick={{ fill: C.muted, fontSize: 9 }} axisLine={{ stroke: C.border }} tickLine={false} />
                <YAxis tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} />
                <Tooltip content={<VolumeTooltip />} />
                <Area type="monotone" dataKey="count" stroke={C.accent} strokeWidth={2} fill="url(#auditVolumeGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </Card>
      </Section>

      {/* row 2: top actors + severity gauge */}
      <Row2>
        <Card>
          <div style={{ fontSize: 10, fontWeight: 600, color: C.dim, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 }}>Top Actors</div>
          {topActors.length === 0 ? (
            <div style={{ fontSize: 10, color: C.muted }}>No actor data.</div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <th style={TH}>Actor</th>
                  <th style={{ ...TH, textAlign: "right" }}>Events</th>
                </tr>
              </thead>
              <tbody>
                {topActors.map((a) => (
                  <tr key={a.actor}>
                    <td style={TD}>{a.actor}</td>
                    <td style={{ ...TD, textAlign: "right", fontWeight: 600, color: C.text }}>{a.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card>
          <div style={{ fontSize: 10, fontWeight: 600, color: C.dim, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 }}>Alert Severity</div>
          {severityGaugeData.length === 0 ? (
            <div style={{ fontSize: 10, color: C.muted, textAlign: "center", padding: 20 }}>No open alerts.</div>
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <RadialBarChart cx="50%" cy="50%" innerRadius="30%" outerRadius="90%"
                data={severityGaugeData} startAngle={180} endAngle={0} barSize={14}>
                <RadialBar dataKey="value" cornerRadius={6} background={{ fill: C.border }} />
                <Tooltip content={<BarTooltip />} />
                <Legend wrapperStyle={{ fontSize: 9, color: C.dim }} />
              </RadialBarChart>
            </ResponsiveContainer>
          )}
        </Card>
      </Row2>
    </>
  );

  /* ── render: Alerts sub-tab ── */

  const renderAlerts = () => (
    <>
      <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
        <Stat l="Open" v={alertStats?.total_open ?? 0} c="red" />
        <Stat l="Acknowledged" v={alertStats?.total_acknowledged ?? 0} c="amber" />
        <Stat l="Resolved" v={alertStats?.total_resolved ?? 0} c="green" />
      </div>

      {alertStats?.open_by_severity && Object.keys(alertStats.open_by_severity).length > 0 && (
        <Card style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 10, fontWeight: 600, color: C.dim, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 }}>Open by Severity</div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            {Object.entries(alertStats.open_by_severity).map(([sev, count]) => (
              <div key={sev} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <B c={sevTone(sev)}>{sev}</B>
                <span style={{ fontSize: 14, fontWeight: 700, color: SEVERITY_COLORS[sev.toLowerCase()] || C.text }}>{count}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card>
        <div style={{ overflowX: "auto", maxHeight: 400 }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={TH}>Severity</th>
                <th style={TH}>Title</th>
                <th style={TH}>Category</th>
                <th style={TH}>Service</th>
                <th style={TH}>Status</th>
                <th style={TH}>Count</th>
                <th style={TH}>Created</th>
                <th style={TH}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 && (
                <tr><td colSpan={8} style={{ ...TD, textAlign: "center", color: C.muted, padding: 20 }}>
                  No audit alerts.
                </td></tr>
              )}
              {alerts.map((al) => (
                <tr key={al.id}>
                  <td style={TD}><B c={sevTone(al.severity)}>{al.severity}</B></td>
                  <td style={{ ...TD, color: C.text, fontWeight: 500, maxWidth: 200 }}>{al.title}</td>
                  <td style={TD}>{al.category}</td>
                  <td style={TD}><B c="blue">{(al.source_service || "").replace("kms-", "")}</B></td>
                  <td style={TD}><B c={al.status === "open" ? "red" : al.status === "acknowledged" ? "amber" : "green"}>{al.status}</B></td>
                  <td style={{ ...TD, fontWeight: 600, color: C.text }}>{al.occurrence_count || 1}</td>
                  <td style={TD}>{shortTS(al.created_at)}</td>
                  <td style={TD}>
                    <div style={{ display: "flex", gap: 4 }}>
                      {al.status === "open" && (
                        <Btn small onClick={() => handleAcknowledge(al.id)}>Ack</Btn>
                      )}
                      {(al.status === "open" || al.status === "acknowledged") && (
                        <Btn small primary onClick={() => handleResolve(al.id)}>Resolve</Btn>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );

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
                    <span style={{ fontSize: 10, color: C.text, fontWeight: 600 }}>{ev.action}</span>
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
      <Tabs tabs={["Events", "Analytics", "Alerts", "Forensics", "Merkle"]} active={subTab} onChange={setSubTab} />

      {subTab === "Events" && renderEvents()}
      {subTab === "Analytics" && renderAnalytics()}
      {subTab === "Alerts" && renderAlerts()}
      {subTab === "Forensics" && renderForensics()}
      {subTab === "Merkle" && <MerkleSection session={session} />}

      {renderEventModal()}

      {/* audit integration note */}
      <div style={{ marginTop: 16, padding: "8px 12px", borderRadius: 8, background: C.card, border: `1px solid ${C.border}`, fontSize: 9, color: C.muted }}>
        All audit events are cryptographically chained (SHA-256), stored in immutable PostgreSQL partitions
        (UPDATE/DELETE triggers blocked), and protected by HMAC-signed WAL for fail-closed operation.
        Audit data feeds into Compliance (anomaly detection) and Posture (risk scoring) modules automatically.
        33 services across KMS core, connectors (AWS, Azure, GCP, HashiCorp, Thales), SDKs (Go, Python, Java, Node, REST),
        and interfaces (PKCS#11, KMIP, JCE, CNG) publish immutable audit events.
      </div>
    </div>
  );
};
