// @ts-nocheck
import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  GitMerge,
  Network,
  RefreshCw,
  Search,
  Server,
  Shield,
  User,
} from "lucide-react";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import {
  B,
  Btn,
  Card,
  FG,
  Inp,
  Row2,
  Section,
  Sel,
  Stat,
} from "../legacyPrimitives";
import { serviceRequest } from "../../../lib/serviceApi";

// ── types ──────────────────────────────────────────────────────────

type LineageEdge = {
  from_id: string;
  from_label?: string;
  to_id: string;
  to_label?: string;
  event_type: string;
  count: number;
};

type LineageNode = {
  id: string;
  type: string;
  label: string;
  event_count: number;
};

type LineageGraph = {
  edges: LineageEdge[];
  nodes: LineageNode[];
  total_events: number;
  unique_sources: number;
  unique_destinations: number;
  services_tracked: number;
};

type LineageEvent = {
  id?: string;
  timestamp: string;
  event_type: string;
  source_id: string;
  source_type: string;
  destination_id?: string;
  destination_type?: string;
  actor_id: string;
  actor_type: string;
  service_name: string;
};

type ImpactAnalysis = {
  key_id: string;
  direct_usage_count: number;
  affected_services: string[];
  affected_actors_count: number;
  risk_level: "critical" | "high" | "medium" | "low";
  rotation_impact: string;
};

// ── constants ──────────────────────────────────────────────────────

const EVENT_TYPES = ["encrypt", "decrypt", "sign", "verify", "wrap", "unwrap", "derive", "export", "import"];
const SOURCE_TYPES = ["key", "secret", "certificate", "dataset", "application"];
const ACTOR_TYPES = ["user", "service", "automation"];
const TIME_FILTERS = [
  { label: "24h", value: "24h", hours: 24 },
  { label: "7d", value: "7d", hours: 168 },
  { label: "30d", value: "30d", hours: 720 },
];

type View = "graph" | "search" | "record";

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

function sinceISO(hours: number): string {
  const d = new Date(Date.now() - hours * 3600 * 1000);
  return d.toISOString();
}

function riskBadgeColor(level: string): string {
  if (level === "critical") return "red";
  if (level === "high") return "orange";
  if (level === "medium") return "amber";
  return "green";
}

function riskColor(level: string): string {
  if (level === "critical") return C.red;
  if (level === "high") return C.orange;
  if (level === "medium") return C.amber;
  return C.green;
}

// ── component ──────────────────────────────────────────────────────

export function LineageTab({ session }: { session: any }) {
  const [view, setView] = useState<View>("graph");

  // Graph state
  const [graph, setGraph] = useState<LineageGraph | null>(null);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [timeFilter, setTimeFilter] = useState("30d");
  const [nodeFilter, setNodeFilter] = useState("");

  // Search state
  const [searchKeyId, setSearchKeyId] = useState("");
  const [searchResults, setSearchResults] = useState<LineageEvent[] | null>(null);
  const [impact, setImpact] = useState<ImpactAnalysis | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchErr, setSearchErr] = useState("");

  // Record state
  const [recordForm, setRecordForm] = useState({
    event_type: "encrypt", source_id: "", source_type: "key", source_label: "",
    destination_id: "", destination_type: "key", actor_id: "", actor_type: "user", service_name: "",
  });
  const [recording, setRecording] = useState(false);
  const [recordErr, setRecordErr] = useState("");
  const [recordSuccess, setRecordSuccess] = useState(false);

  const [err, setErr] = useState("");

  // ── load graph ──────────────────────────────────────────────────

  const loadGraph = useCallback(async (tf?: string) => {
    const activeFilter = tf ?? timeFilter;
    const filterHours = TIME_FILTERS.find(f => f.value === activeFilter)?.hours ?? 720;
    setLoadingGraph(true);
    setErr("");
    try {
      const data = await serviceRequest(
        session, "discovery",
        `/lineage/graph?tenant_id=${encodeURIComponent(session.tenantId)}&since=${encodeURIComponent(sinceISO(filterHours))}`
      );
      setGraph(data ?? { edges: [], nodes: [], total_events: 0, unique_sources: 0, unique_destinations: 0, services_tracked: 0 });
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setLoadingGraph(false);
    }
  }, [session, timeFilter]);

  useEffect(() => { void loadGraph(); }, [loadGraph]);

  // ── search ──────────────────────────────────────────────────────

  async function doSearch() {
    if (!searchKeyId.trim()) { setSearchErr("Enter a Key ID to search."); return; }
    setSearchErr(""); setSearchResults(null); setImpact(null); setSearching(true);
    try {
      const [eventsData, impactData] = await Promise.allSettled([
        serviceRequest(session, "discovery", `/lineage/key/${encodeURIComponent(searchKeyId.trim())}`),
        serviceRequest(session, "discovery", `/lineage/impact/${encodeURIComponent(searchKeyId.trim())}`),
      ]);
      if (eventsData.status === "fulfilled") {
        setSearchResults(eventsData.value?.events ?? []);
      } else {
        setSearchErr(errMsg(eventsData.reason));
      }
      if (impactData.status === "fulfilled") {
        setImpact(impactData.value);
      }
    } catch (e) {
      setSearchErr(errMsg(e));
    } finally {
      setSearching(false);
    }
  }

  // ── record event ────────────────────────────────────────────────

  async function doRecordEvent() {
    setRecordErr(""); setRecordSuccess(false);
    if (!recordForm.source_id.trim()) { setRecordErr("Source ID is required."); return; }
    if (!recordForm.actor_id.trim()) { setRecordErr("Actor ID is required."); return; }
    if (!recordForm.service_name.trim()) { setRecordErr("Service Name is required."); return; }
    setRecording(true);
    try {
      await serviceRequest(session, "discovery", "/lineage/record", {
        method: "POST",
        body: JSON.stringify({
          tenant_id: session.tenantId,
          event_type: recordForm.event_type,
          source: { id: recordForm.source_id.trim(), type: recordForm.source_type, label: recordForm.source_label.trim() || recordForm.source_id.trim() },
          destination: recordForm.destination_id.trim() ? { id: recordForm.destination_id.trim(), type: recordForm.destination_type } : undefined,
          actor: { id: recordForm.actor_id.trim(), type: recordForm.actor_type },
          service_name: recordForm.service_name.trim(),
        }),
      });
      setRecordSuccess(true);
      setRecordForm({ event_type: "encrypt", source_id: "", source_type: "key", source_label: "", destination_id: "", destination_type: "key", actor_id: "", actor_type: "user", service_name: "" });
    } catch (e) {
      setRecordErr(errMsg(e));
    } finally {
      setRecording(false);
    }
  }

  // ── derived ─────────────────────────────────────────────────────

  const filteredNodes = (graph?.nodes ?? []).filter(n =>
    !nodeFilter ||
    n.id.toLowerCase().includes(nodeFilter.toLowerCase()) ||
    n.label.toLowerCase().includes(nodeFilter.toLowerCase()) ||
    n.type.toLowerCase().includes(nodeFilter.toLowerCase())
  );

  const filteredEdges = (graph?.edges ?? []).filter(e =>
    !nodeFilter ||
    (e.from_id ?? "").toLowerCase().includes(nodeFilter.toLowerCase()) ||
    (e.to_id ?? "").toLowerCase().includes(nodeFilter.toLowerCase()) ||
    (e.from_label ?? "").toLowerCase().includes(nodeFilter.toLowerCase()) ||
    (e.to_label ?? "").toLowerCase().includes(nodeFilter.toLowerCase())
  );

  const VIEWS = ["graph", "search", "record"];
  const VIEW_LABELS = ["Data Flow Graph", "Search", "Record Event"];

  return (
    <div style={{ padding: 24, fontFamily: '"IBM Plex Sans", sans-serif', color: C.text, minHeight: "100%" }}>

      {/* ── Header ── */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            <GitMerge size={18} color={C.accent} strokeWidth={2} />
            <span style={{ fontSize: 16, fontWeight: 700, color: C.text, letterSpacing: -0.3 }}>Source Traceability</span>
            <B c="green" pulse>Live</B>
          </div>
          <div style={{ fontSize: 11, color: C.muted }}>Track cryptographic key lineage, data flow edges, and rotation impact analysis</div>
        </div>
        {view === "graph" && (
          <Btn small onClick={() => void loadGraph()} disabled={loadingGraph}>
            <RefreshCw size={11} /> {loadingGraph ? "Loading…" : "Refresh"}
          </Btn>
        )}
      </div>

      {/* ── Error banner ── */}
      {err && (
        <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 11, marginBottom: 14, display: "flex", alignItems: "center", gap: 8 }}>
          <AlertTriangle size={13} /> {err}
        </div>
      )}

      {/* ── Stats row ── */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
        <Stat l="Total Events" v={(graph?.total_events ?? 0).toLocaleString()} s="lineage records" c="accent" i={GitMerge} />
        <Stat l="Sources" v={graph?.unique_sources ?? 0} s="distinct origins" c="blue" i={ArrowRight} />
        <Stat l="Destinations" v={graph?.unique_destinations ?? 0} s="distinct targets" c="purple" i={Network} />
        <Stat l="Services" v={graph?.services_tracked ?? 0} s="active callers" c="teal" i={Server} />
      </div>

      {/* ── View tabs ── */}
      <div style={{ display: "flex", gap: 2, marginBottom: 18, borderBottom: `1px solid ${C.border}` }}>
        {VIEWS.map((key, idx) => (
          <button key={key} onClick={() => setView(key as View)} style={{
            padding: "8px 16px", border: "none", background: "transparent", cursor: "pointer",
            fontSize: 11, fontWeight: view === key ? 700 : 400,
            color: view === key ? C.accent : C.muted,
            borderBottom: view === key ? `2px solid ${C.accent}` : "2px solid transparent",
            marginBottom: -1, letterSpacing: 0.1,
          }}>{VIEW_LABELS[idx]}</button>
        ))}
      </div>

      {/* ════════════════════════════════════════════════════════════
          GRAPH
      ════════════════════════════════════════════════════════════ */}
      {view === "graph" && (
        <>
          {/* Time filter pill + search */}
          <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 16, flexWrap: "wrap" }}>
            {/* Segmented pill */}
            <div style={{ display: "flex", background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
              {TIME_FILTERS.map(tf => (
                <button key={tf.value} onClick={() => { setTimeFilter(tf.value); void loadGraph(tf.value); }} style={{
                  background: timeFilter === tf.value ? C.accentDim : "transparent",
                  border: "none",
                  borderRight: tf.value !== "30d" ? `1px solid ${C.border}` : "none",
                  color: timeFilter === tf.value ? C.accent : C.muted,
                  padding: "6px 14px", fontSize: 11, cursor: "pointer",
                  fontWeight: timeFilter === tf.value ? 700 : 400,
                  transition: "all .15s",
                }}>{tf.label}</button>
              ))}
            </div>
            <Inp
              w={200}
              value={nodeFilter}
              onChange={e => setNodeFilter(e.target.value)}
              placeholder="Filter by node ID or label…"
            />
          </div>

          {/* Lineage Graph edges */}
          <Section title={`Lineage Graph — Edges (${filteredEdges.length})`}>
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {loadingGraph && (!graph || graph.edges.length === 0) ? (
                <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>Loading graph data…</div>
              ) : filteredEdges.length === 0 ? (
                <div style={{ padding: "36px 20px", textAlign: "center" }}>
                  <Network size={26} color={C.border} style={{ marginBottom: 8 }} />
                  <div style={{ color: C.muted, fontSize: 11 }}>No lineage edges recorded in this time window.</div>
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["From", "", "To", "Event Type", "Count"].map((h, i) => <th key={i} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEdges.map((e, i) => (
                      <tr key={i}
                        onMouseEnter={ev => ev.currentTarget.style.filter = "brightness(1.07)"}
                        onMouseLeave={ev => ev.currentTarget.style.filter = ""}>
                        <td style={{ ...TD(i) }}>
                          <div style={{ color: C.text, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 600 }}>{e.from_label || e.from_id}</div>
                          {e.from_label && e.from_label !== e.from_id && <div style={{ fontSize: 10, color: C.muted }}>{e.from_id}</div>}
                        </td>
                        <td style={{ ...TD(i), padding: "9px 4px", color: C.muted }}><ArrowRight size={13} /></td>
                        <td style={{ ...TD(i) }}>
                          <div style={{ color: C.text, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 600 }}>{e.to_label || e.to_id}</div>
                          {e.to_label && e.to_label !== e.to_id && <div style={{ fontSize: 10, color: C.muted }}>{e.to_id}</div>}
                        </td>
                        <td style={TD(i)}><B c="accent">{e.event_type}</B></td>
                        <td style={{ ...TD(i), color: C.text, fontWeight: 700, fontSize: 13 }}>{e.count.toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Section>

          {/* Lineage Nodes */}
          {filteredNodes.length > 0 && (
            <Section title={`Lineage Nodes (${filteredNodes.length})`}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
                {filteredNodes.map((n, i) => (
                  <Card key={n.id || i}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                      <B c="accent">{n.type}</B>
                      <span style={{ fontSize: 10, color: C.muted }}>{n.event_count.toLocaleString()} events</span>
                    </div>
                    <div style={{ fontSize: 12, color: C.text, fontWeight: 600, marginBottom: 2 }}>{n.label}</div>
                    <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono', monospace" }}>{n.id}</div>
                  </Card>
                ))}
              </div>
            </Section>
          )}
        </>
      )}

      {/* ════════════════════════════════════════════════════════════
          SEARCH
      ════════════════════════════════════════════════════════════ */}
      {view === "search" && (
        <>
          <Section title="Search Key Lineage">
            <Card>
              <FG label="Key ID" required>
                <div style={{ display: "flex", gap: 8 }}>
                  <Inp
                    value={searchKeyId}
                    onChange={e => setSearchKeyId(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && doSearch()}
                    placeholder="key_abc123…"
                    mono
                    style={{ flex: 1 }}
                  />
                  <Btn primary onClick={doSearch} disabled={searching}>
                    <Search size={12} /> {searching ? "Searching…" : "Search"}
                  </Btn>
                </div>
              </FG>
              {searchErr && (
                <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11 }}>
                  {searchErr}
                </div>
              )}
            </Card>
          </Section>

          {searchResults !== null && (
            <Section title={`Lineage Timeline — ${searchResults.length} events`}>
              <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
                {searchResults.length === 0 ? (
                  <div style={{ padding: "36px 20px", textAlign: "center" }}>
                    <Search size={26} color={C.border} style={{ marginBottom: 8 }} />
                    <div style={{ color: C.muted, fontSize: 11 }}>No lineage events found for this key.</div>
                  </div>
                ) : (
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr>
                        {["Timestamp", "Event Type", "Source", "Destination", "Actor", "Service"].map(h => <th key={h} style={TH}>{h}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {searchResults.map((e, i) => (
                        <tr key={e.id || i}
                          onMouseEnter={ev => ev.currentTarget.style.filter = "brightness(1.07)"}
                          onMouseLeave={ev => ev.currentTarget.style.filter = ""}>
                          <td style={{ ...TD(i), whiteSpace: "nowrap", fontSize: 10 }}>{fmtDatetime(e.timestamp)}</td>
                          <td style={TD(i)}><B c="accent">{e.event_type}</B></td>
                          <td style={TD(i)}>
                            <div style={{ color: C.text, fontSize: 11 }}>{e.source_id}</div>
                            <div style={{ color: C.muted, fontSize: 10 }}>{e.source_type}</div>
                          </td>
                          <td style={TD(i)}>
                            {e.destination_id ? (
                              <>
                                <div style={{ color: C.text, fontSize: 11 }}>{e.destination_id}</div>
                                <div style={{ color: C.muted, fontSize: 10 }}>{e.destination_type}</div>
                              </>
                            ) : <span style={{ color: C.muted }}>—</span>}
                          </td>
                          <td style={TD(i)}>
                            <div style={{ display: "flex", alignItems: "center", gap: 4, color: C.dim, fontSize: 11 }}>
                              <User size={10} />{e.actor_id}
                            </div>
                            <div style={{ fontSize: 10, color: C.muted }}>{e.actor_type}</div>
                          </td>
                          <td style={{ ...TD(i), fontSize: 10 }}>{e.service_name}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </Section>
          )}

          {impact && (
            <Section title="Impact Analysis">
              <Card>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr 1fr", gap: 10, marginBottom: 14 }}>
                  <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 14px" }}>
                    <div style={{ fontSize: 10, color: C.muted, marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.6 }}>Direct Usage Count</div>
                    <div style={{ fontSize: 24, fontWeight: 800, color: C.accent }}>{impact.direct_usage_count.toLocaleString()}</div>
                  </div>
                  <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 14px" }}>
                    <div style={{ fontSize: 10, color: C.muted, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 }}>Affected Services</div>
                    {impact.affected_services.length === 0 ? (
                      <div style={{ fontSize: 11, color: C.muted }}>None</div>
                    ) : (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                        {impact.affected_services.map(s => <B key={s} c="blue">{s}</B>)}
                      </div>
                    )}
                  </div>
                  <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 14px" }}>
                    <div style={{ fontSize: 10, color: C.muted, marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.6 }}>Affected Actors</div>
                    <div style={{ fontSize: 24, fontWeight: 800, color: impact.affected_actors_count > 10 ? C.amber : C.text }}>
                      {impact.affected_actors_count}
                    </div>
                  </div>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", borderRadius: 8, border: `1px solid ${riskColor(impact.risk_level)}`, background: `${riskColor(impact.risk_level)}14`, marginBottom: 12 }}>
                  {(impact.risk_level === "critical" || impact.risk_level === "high")
                    ? <AlertTriangle size={14} color={riskColor(impact.risk_level)} />
                    : <Shield size={14} color={riskColor(impact.risk_level)} />
                  }
                  <B c={riskBadgeColor(impact.risk_level)}>{impact.risk_level}</B>
                  <span style={{ fontSize: 11, color: riskColor(impact.risk_level), fontWeight: 600 }}>rotation risk</span>
                </div>

                {impact.rotation_impact && (
                  <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 14px" }}>
                    <div style={{ fontSize: 10, color: C.muted, marginBottom: 6, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em" }}>Rotation Impact</div>
                    <div style={{ color: C.dim, fontSize: 11, lineHeight: 1.6 }}>{impact.rotation_impact}</div>
                  </div>
                )}
              </Card>
            </Section>
          )}
        </>
      )}

      {/* ════════════════════════════════════════════════════════════
          RECORD EVENT
      ════════════════════════════════════════════════════════════ */}
      {view === "record" && (
        <Section title="Record Lineage Event">
          <Card style={{ maxWidth: 760 }}>
            {recordSuccess && (
              <div style={{ display: "flex", alignItems: "center", gap: 8, background: C.greenDim, border: `1px solid ${C.green}`, borderRadius: 8, padding: "10px 14px", marginBottom: 16, color: C.green, fontSize: 11 }}>
                <CheckCircle2 size={14} /> Lineage event recorded successfully.
              </div>
            )}

            <Row2>
              <FG label="Event Type" required>
                <Sel value={recordForm.event_type} onChange={e => setRecordForm(f => ({ ...f, event_type: e.target.value }))}>
                  {EVENT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                </Sel>
              </FG>
              <FG label="Service Name" required>
                <Inp
                  value={recordForm.service_name}
                  onChange={e => setRecordForm(f => ({ ...f, service_name: e.target.value }))}
                  placeholder="e.g. payment-service"
                />
              </FG>
            </Row2>

            <Row2>
              <FG label="Source ID" required>
                <Inp
                  value={recordForm.source_id}
                  onChange={e => setRecordForm(f => ({ ...f, source_id: e.target.value }))}
                  placeholder="key_abc123…"
                  mono
                />
              </FG>
              <FG label="Source Type">
                <Sel value={recordForm.source_type} onChange={e => setRecordForm(f => ({ ...f, source_type: e.target.value }))}>
                  {SOURCE_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                </Sel>
              </FG>
            </Row2>

            <FG label="Source Label">
              <Inp
                value={recordForm.source_label}
                onChange={e => setRecordForm(f => ({ ...f, source_label: e.target.value }))}
                placeholder="Human-readable name (optional, defaults to Source ID)"
              />
            </FG>

            <Row2>
              <FG label="Destination ID">
                <Inp
                  value={recordForm.destination_id}
                  onChange={e => setRecordForm(f => ({ ...f, destination_id: e.target.value }))}
                  placeholder="dest_xyz… (optional)"
                  mono
                />
              </FG>
              <FG label="Destination Type">
                <Sel value={recordForm.destination_type} onChange={e => setRecordForm(f => ({ ...f, destination_type: e.target.value }))}>
                  {SOURCE_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                </Sel>
              </FG>
            </Row2>

            <Row2>
              <FG label="Actor ID" required>
                <Inp
                  value={recordForm.actor_id}
                  onChange={e => setRecordForm(f => ({ ...f, actor_id: e.target.value }))}
                  placeholder="user@example.com or svc-name"
                  mono
                />
              </FG>
              <FG label="Actor Type">
                <Sel value={recordForm.actor_type} onChange={e => setRecordForm(f => ({ ...f, actor_type: e.target.value }))}>
                  {ACTOR_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                </Sel>
              </FG>
            </Row2>

            {recordErr && (
              <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11, marginBottom: 12 }}>
                {recordErr}
              </div>
            )}

            <Btn primary onClick={doRecordEvent} disabled={recording}>
              <Clock size={12} /> {recording ? "Recording…" : "Record Event"}
            </Btn>
          </Card>
        </Section>
      )}
    </div>
  );
}
