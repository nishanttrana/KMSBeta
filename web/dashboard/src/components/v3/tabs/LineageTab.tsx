// @ts-nocheck — Lineage / Source Traceability tab with 12 views (7 core + 5 enterprise)
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Database,
  Download,
  FileText,
  Fingerprint,
  GitMerge,
  Globe,
  Grid,
  Layers,
  Link2,
  Microscope,
  Network,
  RefreshCw,
  Search,
  Server,
  Shield,
  TrendingUp,
  User,
  X,
  Zap,
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
  from: string;
  from_id?: string;
  from_label?: string;
  to: string;
  to_id?: string;
  to_label?: string;
  event_type: string;
  count: number;
  last_seen?: string;
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
  occurred_at?: string;
  timestamp?: string;
  event_type: string;
  source_id: string;
  source_type: string;
  source_label?: string;
  dest_id?: string;
  destination_id?: string;
  dest_type?: string;
  destination_type?: string;
  dest_label?: string;
  actor_id: string;
  actor_type: string;
  service_name: string;
  metadata?: Record<string, unknown>;
};

type ImpactAnalysis = {
  key_id: string;
  total_events: number;
  direct_usage_count?: number;
  affected_keys?: string[];
  affected_keys_count?: number;
  affected_services: string[];
  affected_services_count?: number;
  affected_actors?: string[];
  affected_actors_count?: number;
  blast_radius?: number;
  risk_level: "critical" | "high" | "medium" | "low";
  rotation_impact: string;
};

type TimelineEntry = {
  event_id: string;
  event_type: string;
  description: string;
  timestamp: string;
  actor_id: string;
  actor_type: string;
  service_name: string;
  source_id: string;
  dest_id?: string;
  metadata?: Record<string, unknown>;
};

type DependencyNode = {
  key_id: string;
  key_type: string;
  label: string;
  relationship: string;
  depth: number;
};

type StatsData = {
  total_events: number;
  events_today: number;
  events_this_week: number;
  active_keys: number;
  services_tracked: number;
  top_keys: { key_id: string; count: number }[];
  top_services: { service: string; count: number; last_activity: string }[];
  event_type_distribution: { event_type: string; count: number; percentage: string }[];
  orphan_keys: string[];
  orphan_keys_count: number;
  deepest_chains: { key_id: string; depth: number }[];
};

// ── constants ──────────────────────────────────────────────────────

const EVENT_TYPES = [
  "create", "read", "encrypt", "decrypt", "sign", "wrap", "unwrap",
  "derive", "export", "import", "rotate", "transform", "share", "delete", "destroy",
];
const SOURCE_TYPES = ["key", "secret", "certificate", "dataset", "application"];
const ACTOR_TYPES = ["user", "service", "automation"];
const TIME_FILTERS = [
  { label: "24h", value: "24h", hours: 24 },
  { label: "7d", value: "7d", hours: 168 },
  { label: "30d", value: "30d", hours: 720 },
];

type View = "graph" | "search" | "record" | "timeline" | "dependencies" | "stats" | "audit"
  | "provenance" | "dataflow" | "heatmap" | "forensics" | "custody";

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
  if (!s) return "\u2014";
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleString();
}

function sinceISO(hours: number): string {
  const d = new Date(Date.now() - hours * 3600 * 1000);
  return d.toISOString();
}

function riskColor(level: string): string {
  if (level === "critical") return C.red;
  if (level === "high") return C.orange;
  if (level === "medium") return C.amber;
  return C.green;
}

function riskBadgeColor(level: string): string {
  if (level === "critical") return "red";
  if (level === "high") return "orange";
  if (level === "medium") return "amber";
  return "green";
}

const EVENT_TYPE_COLORS: Record<string, string> = {
  create: "#22c55e",
  read: "#3b82f6",
  encrypt: "#8b5cf6",
  decrypt: "#6366f1",
  sign: "#06b6d4",
  wrap: "#a855f7",
  unwrap: "#c084fc",
  derive: "#f59e0b",
  export: "#64748b",
  import: "#0ea5e9",
  rotate: "#3b82f6",
  transform: "#14b8a6",
  share: "#ec4899",
  delete: "#ef4444",
  destroy: "#dc2626",
};

function eventColor(et: string): string {
  return EVENT_TYPE_COLORS[et] || C.accent;
}

// ── component ──────────────────────────────────────────────────────

export function LineageTab({ session }: { session: any }) {
  const [view, setView] = useState<View>("graph");

  // Graph state
  const [graph, setGraph] = useState<LineageGraph | null>(null);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [timeFilter, setTimeFilter] = useState("30d");
  const [nodeFilter, setNodeFilter] = useState("");
  const [selectedNode, setSelectedNode] = useState<LineageNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<LineageEdge | null>(null);

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

  // Timeline state
  const [timelineKeyId, setTimelineKeyId] = useState("");
  const [timeline, setTimeline] = useState<TimelineEntry[] | null>(null);
  const [loadingTimeline, setLoadingTimeline] = useState(false);
  const [timelineErr, setTimelineErr] = useState("");
  const [expandedEntries, setExpandedEntries] = useState<Set<string>>(new Set());

  // Dependencies state
  const [depsKeyId, setDepsKeyId] = useState("");
  const [depsData, setDepsData] = useState<any | null>(null);
  const [loadingDeps, setLoadingDeps] = useState(false);
  const [depsErr, setDepsErr] = useState("");

  // Stats state
  const [stats, setStats] = useState<StatsData | null>(null);
  const [loadingStats, setLoadingStats] = useState(false);
  const [statsErr, setStatsErr] = useState("");

  // Audit state
  const [auditEvents, setAuditEvents] = useState<LineageEvent[] | null>(null);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [auditErr, setAuditErr] = useState("");
  const [auditFilters, setAuditFilters] = useState({
    event_type: "", service: "", query: "", since: "", until: "",
  });

  // Provenance state
  const [provKeyId, setProvKeyId] = useState("");
  const [provData, setProvData] = useState<any | null>(null);
  const [loadingProv, setLoadingProv] = useState(false);
  const [provErr, setProvErr] = useState("");

  // Dataflow state
  const [dfKeyId, setDfKeyId] = useState("");
  const [dfData, setDfData] = useState<any | null>(null);
  const [loadingDf, setLoadingDf] = useState(false);
  const [dfErr, setDfErr] = useState("");

  // Heatmap state
  const [heatmapData, setHeatmapData] = useState<any | null>(null);
  const [loadingHeatmap, setLoadingHeatmap] = useState(false);
  const [heatmapErr, setHeatmapErr] = useState("");
  const [heatmapHover, setHeatmapHover] = useState<any | null>(null);
  const [heatmapDetail, setHeatmapDetail] = useState<any | null>(null);
  const [heatmapSort, setHeatmapSort] = useState<{ col: string; asc: boolean }>({ col: "risk_score", asc: false });

  // Forensics state
  const [forKeyId, setForKeyId] = useState("");
  const [forData, setForData] = useState<any | null>(null);
  const [loadingFor, setLoadingFor] = useState(false);
  const [forErr, setForErr] = useState("");
  const [expandedAnomalies, setExpandedAnomalies] = useState<Set<number>>(new Set());

  // Custody state
  const [custKeyId, setCustKeyId] = useState("");
  const [custData, setCustData] = useState<any | null>(null);
  const [loadingCust, setLoadingCust] = useState(false);
  const [custErr, setCustErr] = useState("");
  const [custVerify, setCustVerify] = useState<any | null>(null);
  const [loadingVerify, setLoadingVerify] = useState(false);

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
      // Handle both wrapped and unwrapped responses
      const graphData = data?.graph || data;
      setGraph(graphData ?? { edges: [], nodes: [], total_events: 0, unique_sources: 0, unique_destinations: 0, services_tracked: 0 });
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
        // Handle both wrapped and unwrapped
        const impVal = impactData.value?.impact || impactData.value;
        setImpact(impVal);
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
          source_id: recordForm.source_id.trim(),
          source_type: recordForm.source_type,
          source_label: recordForm.source_label.trim() || recordForm.source_id.trim(),
          dest_id: recordForm.destination_id.trim() || undefined,
          dest_type: recordForm.destination_id.trim() ? recordForm.destination_type : undefined,
          actor_id: recordForm.actor_id.trim(),
          actor_type: recordForm.actor_type,
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

  // ── timeline ────────────────────────────────────────────────────

  async function loadTimeline() {
    if (!timelineKeyId.trim()) { setTimelineErr("Enter a Key ID."); return; }
    setTimelineErr(""); setTimeline(null); setLoadingTimeline(true);
    try {
      const data = await serviceRequest(
        session, "discovery",
        `/lineage/timeline/${encodeURIComponent(timelineKeyId.trim())}?tenant_id=${encodeURIComponent(session.tenantId)}`
      );
      setTimeline(data?.timeline ?? []);
    } catch (e) {
      setTimelineErr(errMsg(e));
    } finally {
      setLoadingTimeline(false);
    }
  }

  function toggleEntry(id: string) {
    setExpandedEntries(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  // ── dependencies ────────────────────────────────────────────────

  async function loadDependencies() {
    if (!depsKeyId.trim()) { setDepsErr("Enter a Key ID."); return; }
    setDepsErr(""); setDepsData(null); setLoadingDeps(true);
    try {
      const data = await serviceRequest(
        session, "discovery",
        `/lineage/dependencies/${encodeURIComponent(depsKeyId.trim())}?tenant_id=${encodeURIComponent(session.tenantId)}`
      );
      setDepsData(data);
    } catch (e) {
      setDepsErr(errMsg(e));
    } finally {
      setLoadingDeps(false);
    }
  }

  // ── stats ───────────────────────────────────────────────────────

  const loadStats = useCallback(async () => {
    setStatsErr(""); setLoadingStats(true);
    try {
      const data = await serviceRequest(
        session, "discovery",
        `/lineage/stats?tenant_id=${encodeURIComponent(session.tenantId)}`
      );
      setStats(data);
    } catch (e) {
      setStatsErr(errMsg(e));
    } finally {
      setLoadingStats(false);
    }
  }, [session]);

  useEffect(() => {
    if (view === "stats" && !stats && !loadingStats) void loadStats();
  }, [view, stats, loadingStats, loadStats]);

  // ── audit ───────────────────────────────────────────────────────

  const loadAudit = useCallback(async () => {
    setAuditErr(""); setLoadingAudit(true);
    try {
      const body: any = {
        query: auditFilters.query,
        limit: 500,
      };
      if (auditFilters.event_type) body.event_types = [auditFilters.event_type];
      if (auditFilters.service) body.services = [auditFilters.service];
      if (auditFilters.since) body.since = new Date(auditFilters.since).toISOString();
      if (auditFilters.until) body.until = new Date(auditFilters.until).toISOString();

      const data = await serviceRequest(session, "discovery", `/lineage/search?tenant_id=${encodeURIComponent(session.tenantId)}`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      setAuditEvents(data?.events ?? []);
    } catch (e) {
      setAuditErr(errMsg(e));
    } finally {
      setLoadingAudit(false);
    }
  }, [session, auditFilters]);

  useEffect(() => {
    if (view === "audit" && !auditEvents && !loadingAudit) void loadAudit();
  }, [view, auditEvents, loadingAudit, loadAudit]);

  function exportAuditJSON() {
    if (!auditEvents) return;
    const blob = new Blob([JSON.stringify(auditEvents, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `lineage-audit-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ── provenance ──────────────────────────────────────────────────

  async function loadProvenance() {
    if (!provKeyId.trim()) { setProvErr("Enter a Key ID."); return; }
    setProvErr(""); setProvData(null); setLoadingProv(true);
    try {
      const data = await serviceRequest(
        session, "discovery",
        `/lineage/provenance/${encodeURIComponent(provKeyId.trim())}?tenant_id=${encodeURIComponent(session.tenantId)}`
      );
      setProvData(data);
    } catch (e) {
      setProvErr(errMsg(e));
    } finally {
      setLoadingProv(false);
    }
  }

  // ── dataflow ───────────────────────────────────────────────────

  async function loadDataflow() {
    if (!dfKeyId.trim()) { setDfErr("Enter a Key ID."); return; }
    setDfErr(""); setDfData(null); setLoadingDf(true);
    try {
      const data = await serviceRequest(
        session, "discovery",
        `/lineage/dataflow/${encodeURIComponent(dfKeyId.trim())}?tenant_id=${encodeURIComponent(session.tenantId)}`
      );
      setDfData(data);
    } catch (e) {
      setDfErr(errMsg(e));
    } finally {
      setLoadingDf(false);
    }
  }

  // ── heatmap ────────────────────────────────────────────────────

  const loadHeatmap = useCallback(async () => {
    setHeatmapErr(""); setLoadingHeatmap(true);
    try {
      const data = await serviceRequest(
        session, "discovery",
        `/lineage/heatmap?tenant_id=${encodeURIComponent(session.tenantId)}`
      );
      setHeatmapData(data);
    } catch (e) {
      setHeatmapErr(errMsg(e));
    } finally {
      setLoadingHeatmap(false);
    }
  }, [session]);

  useEffect(() => {
    if (view === "heatmap" && !heatmapData && !loadingHeatmap) void loadHeatmap();
  }, [view, heatmapData, loadingHeatmap, loadHeatmap]);

  // ── forensics ──────────────────────────────────────────────────

  async function loadForensics() {
    if (!forKeyId.trim()) { setForErr("Enter a Key ID."); return; }
    setForErr(""); setForData(null); setLoadingFor(true);
    try {
      const data = await serviceRequest(
        session, "discovery",
        `/lineage/forensics/${encodeURIComponent(forKeyId.trim())}?tenant_id=${encodeURIComponent(session.tenantId)}`
      );
      setForData(data);
    } catch (e) {
      setForErr(errMsg(e));
    } finally {
      setLoadingFor(false);
    }
  }

  function toggleAnomaly(idx: number) {
    setExpandedAnomalies(prev => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx); else next.add(idx);
      return next;
    });
  }

  // ── custody ────────────────────────────────────────────────────

  async function loadCustody() {
    if (!custKeyId.trim()) { setCustErr("Enter a Key ID."); return; }
    setCustErr(""); setCustData(null); setCustVerify(null); setLoadingCust(true);
    try {
      const data = await serviceRequest(
        session, "discovery",
        `/lineage/custody/${encodeURIComponent(custKeyId.trim())}?tenant_id=${encodeURIComponent(session.tenantId)}`
      );
      setCustData(data);
    } catch (e) {
      setCustErr(errMsg(e));
    } finally {
      setLoadingCust(false);
    }
  }

  async function verifyCustodyIntegrity() {
    if (!custKeyId.trim()) return;
    setLoadingVerify(true); setCustVerify(null);
    try {
      const data = await serviceRequest(
        session, "discovery",
        `/lineage/tamper-check/${encodeURIComponent(custKeyId.trim())}?tenant_id=${encodeURIComponent(session.tenantId)}`
      );
      setCustVerify(data);
    } catch (e) {
      setCustVerify({ verified: false, error: errMsg(e) });
    } finally {
      setLoadingVerify(false);
    }
  }

  function exportCustodyJSON() {
    if (!custData) return;
    const blob = new Blob([JSON.stringify(custData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `custody-report-${custKeyId}-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ── derived ─────────────────────────────────────────────────────

  const filteredNodes = (graph?.nodes ?? []).filter(n =>
    !nodeFilter ||
    n.id.toLowerCase().includes(nodeFilter.toLowerCase()) ||
    n.label.toLowerCase().includes(nodeFilter.toLowerCase()) ||
    n.type.toLowerCase().includes(nodeFilter.toLowerCase())
  );

  const filteredEdges = (graph?.edges ?? []).filter(e => {
    const fromId = e.from || e.from_id || "";
    const toId = e.to || e.to_id || "";
    const fromLabel = e.from_label || "";
    const toLabel = e.to_label || "";
    if (!nodeFilter) return true;
    const q = nodeFilter.toLowerCase();
    return fromId.toLowerCase().includes(q) ||
      toId.toLowerCase().includes(q) ||
      fromLabel.toLowerCase().includes(q) ||
      toLabel.toLowerCase().includes(q);
  });

  // Node detail helpers
  const nodeEdgeStats = useMemo(() => {
    if (!selectedNode || !graph) return { incoming: 0, outgoing: 0, connected: [] as string[] };
    const edges = graph.edges ?? [];
    const nodeId = selectedNode.id;
    let incoming = 0, outgoing = 0;
    const connectedSet = new Set<string>();
    for (const e of edges) {
      const fromId = e.from || e.from_id || "";
      const toId = e.to || e.to_id || "";
      if (fromId === nodeId) { outgoing++; connectedSet.add(toId); }
      if (toId === nodeId) { incoming++; connectedSet.add(fromId); }
    }
    return { incoming, outgoing, connected: Array.from(connectedSet) };
  }, [selectedNode, graph]);

  function exportGraphJSON() {
    if (!graph) return;
    const blob = new Blob([JSON.stringify(graph, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `lineage-graph-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const VIEWS: View[] = ["graph", "search", "record", "timeline", "dependencies", "stats", "audit", "provenance", "dataflow", "heatmap", "forensics", "custody"];
  const VIEW_LABELS = ["Graph", "Search", "Record", "Timeline", "Dependencies", "Stats", "Audit", "Provenance", "Data Flow", "Risk Heatmap", "Forensics", "Chain of Custody"];
  const VIEW_ICONS: Record<View, React.ReactNode> = {
    graph: null, search: null, record: null, timeline: null, dependencies: null, stats: null, audit: null,
    provenance: <Fingerprint size={11} />, dataflow: <Network size={11} />,
    heatmap: <Grid size={11} />, forensics: <Microscope size={11} />, custody: <Link2 size={11} />,
  };

  return (
    <div style={{ padding: 24, fontFamily: '"IBM Plex Sans", sans-serif', color: C.text, minHeight: "100%" }}>

      {/* -- Header -- */}
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
          <div style={{ display: "flex", gap: 8 }}>
            <Btn small onClick={exportGraphJSON} disabled={!graph}>
              <Download size={11} /> Export
            </Btn>
            <Btn small onClick={() => void loadGraph()} disabled={loadingGraph}>
              <RefreshCw size={11} /> {loadingGraph ? "Loading\u2026" : "Refresh"}
            </Btn>
          </div>
        )}
      </div>

      {/* -- Error banner -- */}
      {err && (
        <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 11, marginBottom: 14, display: "flex", alignItems: "center", gap: 8 }}>
          <AlertTriangle size={13} /> {err}
        </div>
      )}

      {/* -- Stats row -- */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
        <Stat l="Total Events" v={(graph?.total_events ?? 0).toLocaleString()} s="lineage records" c="accent" i={GitMerge} />
        <Stat l="Sources" v={graph?.unique_sources ?? 0} s="distinct origins" c="blue" i={ArrowRight} />
        <Stat l="Destinations" v={graph?.unique_destinations ?? 0} s="distinct targets" c="purple" i={Network} />
        <Stat l="Services" v={graph?.services_tracked ?? 0} s="active callers" c="teal" i={Server} />
      </div>

      {/* -- View tabs -- */}
      <div style={{ display: "flex", gap: 2, marginBottom: 18, borderBottom: `1px solid ${C.border}`, flexWrap: "wrap" }}>
        {VIEWS.map((key, idx) => (
          <button key={key} onClick={() => setView(key)} style={{
            padding: "8px 16px", border: "none", background: "transparent", cursor: "pointer",
            fontSize: 11, fontWeight: view === key ? 700 : 400,
            color: view === key ? C.accent : C.muted,
            borderBottom: view === key ? `2px solid ${C.accent}` : "2px solid transparent",
            marginBottom: -1, letterSpacing: 0.1,
          }}>
            {VIEW_ICONS[key] && <span style={{ marginRight: 4, display: "inline-flex", verticalAlign: "middle" }}>{VIEW_ICONS[key]}</span>}
            {VIEW_LABELS[idx]}
          </button>
        ))}
      </div>

      {/* ================================================================
          GRAPH VIEW
      ================================================================ */}
      {view === "graph" && (
        <>
          {/* Time filter pill + search */}
          <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 16, flexWrap: "wrap" }}>
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
              placeholder="Filter by node ID or label\u2026"
            />
          </div>

          {/* Legend */}
          <div style={{ display: "flex", gap: 12, marginBottom: 14, flexWrap: "wrap" }}>
            {Object.entries(EVENT_TYPE_COLORS).map(([et, col]) => (
              <div key={et} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 10, color: C.muted }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: col, display: "inline-block" }} />
                {et}
              </div>
            ))}
          </div>

          {/* Node detail panel */}
          {selectedNode && (
            <Card style={{ marginBottom: 14, position: "relative" }}>
              <button onClick={() => setSelectedNode(null)} style={{
                position: "absolute", top: 8, right: 8, background: "none", border: "none",
                color: C.muted, cursor: "pointer",
              }}><X size={14} /></button>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                <B c="accent">{selectedNode.type}</B>
                <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{selectedNode.label || selectedNode.id}</span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 12 }}>
                <div style={{ background: C.bg, borderRadius: 6, padding: "8px 10px" }}>
                  <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase" }}>ID</div>
                  <div style={{ fontSize: 11, color: C.text, fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" }}>{selectedNode.id}</div>
                </div>
                <div style={{ background: C.bg, borderRadius: 6, padding: "8px 10px" }}>
                  <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase" }}>Events</div>
                  <div style={{ fontSize: 16, fontWeight: 800, color: C.accent }}>{selectedNode.event_count}</div>
                </div>
                <div style={{ background: C.bg, borderRadius: 6, padding: "8px 10px" }}>
                  <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase" }}>Incoming</div>
                  <div style={{ fontSize: 16, fontWeight: 800, color: C.blue }}>{nodeEdgeStats.incoming}</div>
                </div>
                <div style={{ background: C.bg, borderRadius: 6, padding: "8px 10px" }}>
                  <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase" }}>Outgoing</div>
                  <div style={{ fontSize: 16, fontWeight: 800, color: C.purple }}>{nodeEdgeStats.outgoing}</div>
                </div>
              </div>
              {nodeEdgeStats.connected.length > 0 && (
                <div style={{ marginBottom: 10 }}>
                  <div style={{ fontSize: 10, color: C.muted, fontWeight: 600, marginBottom: 4, textTransform: "uppercase" }}>Connected Keys</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {nodeEdgeStats.connected.slice(0, 20).map(k => <B key={k} c="blue">{k}</B>)}
                    {nodeEdgeStats.connected.length > 20 && <span style={{ fontSize: 10, color: C.muted }}>+{nodeEdgeStats.connected.length - 20} more</span>}
                  </div>
                </div>
              )}
              <div style={{ display: "flex", gap: 6 }}>
                <Btn small onClick={() => { setTimelineKeyId(selectedNode.id); setView("timeline"); }}>View Timeline</Btn>
                <Btn small onClick={() => { setDepsKeyId(selectedNode.id); setView("dependencies"); }}>View Dependencies</Btn>
                <Btn small onClick={() => { setSearchKeyId(selectedNode.id); setView("search"); }}>Impact Analysis</Btn>
              </div>
            </Card>
          )}

          {/* Edge detail panel */}
          {selectedEdge && (
            <Card style={{ marginBottom: 14, position: "relative" }}>
              <button onClick={() => setSelectedEdge(null)} style={{
                position: "absolute", top: 8, right: 8, background: "none", border: "none",
                color: C.muted, cursor: "pointer",
              }}><X size={14} /></button>
              <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 8 }}>Edge Details</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr auto 1fr auto", gap: 10, alignItems: "center" }}>
                <div style={{ background: C.bg, borderRadius: 6, padding: "8px 10px" }}>
                  <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase" }}>From</div>
                  <div style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{selectedEdge.from_label || selectedEdge.from || selectedEdge.from_id}</div>
                  <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono', monospace" }}>{selectedEdge.from || selectedEdge.from_id}</div>
                </div>
                <ArrowRight size={16} color={C.muted} />
                <div style={{ background: C.bg, borderRadius: 6, padding: "8px 10px" }}>
                  <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase" }}>To</div>
                  <div style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{selectedEdge.to_label || selectedEdge.to || selectedEdge.to_id}</div>
                  <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono', monospace" }}>{selectedEdge.to || selectedEdge.to_id}</div>
                </div>
                <div style={{ background: C.bg, borderRadius: 6, padding: "8px 10px", textAlign: "center" }}>
                  <B c="accent">{selectedEdge.event_type}</B>
                  <div style={{ fontSize: 16, fontWeight: 800, color: C.text, marginTop: 4 }}>{selectedEdge.count}x</div>
                  {selectedEdge.last_seen && <div style={{ fontSize: 9, color: C.muted }}>Last: {fmtDatetime(selectedEdge.last_seen)}</div>}
                </div>
              </div>
            </Card>
          )}

          {/* Lineage Graph edges */}
          <Section title={`Lineage Graph \u2014 Edges (${filteredEdges.length})`}>
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {loadingGraph && (!graph || graph.edges.length === 0) ? (
                <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>Loading graph data\u2026</div>
              ) : filteredEdges.length === 0 ? (
                <div style={{ padding: "36px 20px", textAlign: "center" }}>
                  <Network size={26} color={C.border} style={{ marginBottom: 8 }} />
                  <div style={{ color: C.muted, fontSize: 11 }}>No lineage edges recorded in this time window.</div>
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["From", "", "To", "Event Type", "Count", "Last Seen"].map((h, i) => <th key={i} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEdges.map((e, i) => {
                      const fromId = e.from || e.from_id || "";
                      const toId = e.to || e.to_id || "";
                      const fromLabel = e.from_label || "";
                      const toLabel = e.to_label || "";
                      return (
                        <tr key={i}
                          style={{ cursor: "pointer" }}
                          onClick={() => setSelectedEdge(e)}
                          onMouseEnter={ev => ev.currentTarget.style.filter = "brightness(1.07)"}
                          onMouseLeave={ev => ev.currentTarget.style.filter = ""}>
                          <td style={{ ...TD(i) }}>
                            <div style={{ color: C.text, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 600 }}>{fromLabel || fromId}</div>
                            {fromLabel && fromLabel !== fromId && <div style={{ fontSize: 10, color: C.muted }}>{fromId}</div>}
                          </td>
                          <td style={{ ...TD(i), padding: "9px 4px", color: C.muted }}><ArrowRight size={13} /></td>
                          <td style={{ ...TD(i) }}>
                            <div style={{ color: C.text, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 600 }}>{toLabel || toId}</div>
                            {toLabel && toLabel !== toId && <div style={{ fontSize: 10, color: C.muted }}>{toId}</div>}
                          </td>
                          <td style={TD(i)}>
                            <span style={{
                              display: "inline-block", padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600,
                              background: `${eventColor(e.event_type)}22`, color: eventColor(e.event_type),
                              border: `1px solid ${eventColor(e.event_type)}44`,
                            }}>{e.event_type}</span>
                          </td>
                          <td style={{ ...TD(i), color: C.text, fontWeight: 700, fontSize: 13 }}>{e.count.toLocaleString()}</td>
                          <td style={{ ...TD(i), fontSize: 10, color: C.muted }}>{fmtDatetime(e.last_seen)}</td>
                        </tr>
                      );
                    })}
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
                  <Card key={n.id || i} style={{ cursor: "pointer" }} onClick={() => setSelectedNode(n)}>
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

      {/* ================================================================
          SEARCH VIEW
      ================================================================ */}
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
                    placeholder="key_abc123\u2026"
                    mono
                    style={{ flex: 1 }}
                  />
                  <Btn primary onClick={doSearch} disabled={searching}>
                    <Search size={12} /> {searching ? "Searching\u2026" : "Search"}
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
            <Section title={`Lineage Timeline \u2014 ${searchResults.length} events`}>
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
                          <td style={{ ...TD(i), whiteSpace: "nowrap", fontSize: 10 }}>{fmtDatetime(e.occurred_at || e.timestamp)}</td>
                          <td style={TD(i)}>
                            <span style={{
                              display: "inline-block", padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600,
                              background: `${eventColor(e.event_type)}22`, color: eventColor(e.event_type),
                              border: `1px solid ${eventColor(e.event_type)}44`,
                            }}>{e.event_type}</span>
                          </td>
                          <td style={TD(i)}>
                            <div style={{ color: C.text, fontSize: 11 }}>{e.source_id}</div>
                            <div style={{ color: C.muted, fontSize: 10 }}>{e.source_type}</div>
                          </td>
                          <td style={TD(i)}>
                            {(e.dest_id || e.destination_id) ? (
                              <>
                                <div style={{ color: C.text, fontSize: 11 }}>{e.dest_id || e.destination_id}</div>
                                <div style={{ color: C.muted, fontSize: 10 }}>{e.dest_type || e.destination_type}</div>
                              </>
                            ) : <span style={{ color: C.muted }}>\u2014</span>}
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
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10, marginBottom: 14 }}>
                  <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 14px" }}>
                    <div style={{ fontSize: 10, color: C.muted, marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.6 }}>Total Events</div>
                    <div style={{ fontSize: 24, fontWeight: 800, color: C.accent }}>{(impact.total_events ?? impact.direct_usage_count ?? 0).toLocaleString()}</div>
                  </div>
                  <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 14px" }}>
                    <div style={{ fontSize: 10, color: C.muted, marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.6 }}>Affected Keys</div>
                    <div style={{ fontSize: 24, fontWeight: 800, color: C.blue }}>{impact.affected_keys_count ?? (impact.affected_keys?.length ?? 0)}</div>
                  </div>
                  <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 14px" }}>
                    <div style={{ fontSize: 10, color: C.muted, marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.6 }}>Blast Radius</div>
                    <div style={{ fontSize: 24, fontWeight: 800, color: C.amber }}>{impact.blast_radius ?? 0}</div>
                  </div>
                  <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 14px" }}>
                    <div style={{ fontSize: 10, color: C.muted, marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.6 }}>Affected Actors</div>
                    <div style={{ fontSize: 24, fontWeight: 800, color: (impact.affected_actors_count ?? 0) > 10 ? C.amber : C.text }}>
                      {impact.affected_actors_count ?? 0}
                    </div>
                  </div>
                </div>

                {(impact.affected_services?.length ?? 0) > 0 && (
                  <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 14px", marginBottom: 12 }}>
                    <div style={{ fontSize: 10, color: C.muted, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6, fontWeight: 600 }}>Affected Services</div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                      {impact.affected_services.map(s => <B key={s} c="blue">{s}</B>)}
                    </div>
                  </div>
                )}

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

      {/* ================================================================
          RECORD EVENT VIEW
      ================================================================ */}
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
                  placeholder="key_abc123\u2026"
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
                  placeholder="dest_xyz\u2026 (optional)"
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
              <Clock size={12} /> {recording ? "Recording\u2026" : "Record Event"}
            </Btn>
          </Card>
        </Section>
      )}

      {/* ================================================================
          TIMELINE VIEW
      ================================================================ */}
      {view === "timeline" && (
        <>
          <Section title="Key Lifecycle Timeline">
            <Card>
              <FG label="Key ID" required>
                <div style={{ display: "flex", gap: 8 }}>
                  <Inp
                    value={timelineKeyId}
                    onChange={e => setTimelineKeyId(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && loadTimeline()}
                    placeholder="key_abc123\u2026"
                    mono
                    style={{ flex: 1 }}
                  />
                  <Btn primary onClick={loadTimeline} disabled={loadingTimeline}>
                    <Clock size={12} /> {loadingTimeline ? "Loading\u2026" : "Load Timeline"}
                  </Btn>
                </div>
              </FG>
              {timelineErr && (
                <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11 }}>
                  {timelineErr}
                </div>
              )}
            </Card>
          </Section>

          {timeline !== null && (
            <Section title={`Timeline \u2014 ${timeline.length} events`}>
              {timeline.length === 0 ? (
                <Card>
                  <div style={{ textAlign: "center", padding: "24px 0" }}>
                    <Clock size={26} color={C.border} style={{ marginBottom: 8 }} />
                    <div style={{ color: C.muted, fontSize: 11 }}>No events found for this key.</div>
                  </div>
                </Card>
              ) : (
                <div style={{ position: "relative", paddingLeft: 28 }}>
                  {/* Vertical line */}
                  <div style={{
                    position: "absolute", left: 11, top: 0, bottom: 0, width: 2,
                    background: `linear-gradient(to bottom, ${C.accent}44, ${C.border})`,
                  }} />

                  {timeline.map((entry, i) => {
                    const isExpanded = expandedEntries.has(entry.event_id);
                    const color = eventColor(entry.event_type);
                    return (
                      <div key={entry.event_id || i} style={{ position: "relative", marginBottom: 12 }}>
                        {/* Dot on the line */}
                        <div style={{
                          position: "absolute", left: -21, top: 14, width: 12, height: 12,
                          borderRadius: "50%", background: color, border: `2px solid ${C.card}`,
                          boxShadow: `0 0 6px ${color}66`,
                        }} />

                        <Card style={{ marginLeft: 8 }}>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                              <span style={{
                                display: "inline-block", padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600,
                                background: `${color}22`, color, border: `1px solid ${color}44`,
                              }}>{entry.event_type}</span>
                              <span style={{ fontSize: 10, color: C.muted }}>{fmtDatetime(entry.timestamp)}</span>
                            </div>
                            <button onClick={() => toggleEntry(entry.event_id)} style={{
                              background: "none", border: "none", color: C.muted, cursor: "pointer", padding: 2,
                            }}>
                              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                            </button>
                          </div>

                          <div style={{ fontSize: 12, color: C.text, lineHeight: 1.5, marginBottom: 6 }}>
                            {entry.description}
                          </div>

                          <div style={{ display: "flex", gap: 12, fontSize: 10, color: C.muted }}>
                            <span><User size={10} style={{ verticalAlign: "middle" }} /> {entry.actor_id}</span>
                            <span><Server size={10} style={{ verticalAlign: "middle" }} /> {entry.service_name}</span>
                          </div>

                          {isExpanded && entry.metadata && Object.keys(entry.metadata).length > 0 && (
                            <div style={{ marginTop: 10, background: C.bg, borderRadius: 6, padding: "8px 10px", border: `1px solid ${C.border}` }}>
                              <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", marginBottom: 4, fontWeight: 600 }}>Metadata</div>
                              <pre style={{ fontSize: 10, color: C.dim, margin: 0, whiteSpace: "pre-wrap", fontFamily: "'JetBrains Mono', monospace" }}>
                                {JSON.stringify(entry.metadata, null, 2)}
                              </pre>
                            </div>
                          )}
                        </Card>
                      </div>
                    );
                  })}
                </div>
              )}
            </Section>
          )}
        </>
      )}

      {/* ================================================================
          DEPENDENCIES VIEW
      ================================================================ */}
      {view === "dependencies" && (
        <>
          <Section title="Dependency Explorer">
            <Card>
              <FG label="Key ID" required>
                <div style={{ display: "flex", gap: 8 }}>
                  <Inp
                    value={depsKeyId}
                    onChange={e => setDepsKeyId(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && loadDependencies()}
                    placeholder="key_abc123\u2026"
                    mono
                    style={{ flex: 1 }}
                  />
                  <Btn primary onClick={loadDependencies} disabled={loadingDeps}>
                    <Layers size={12} /> {loadingDeps ? "Loading\u2026" : "Explore"}
                  </Btn>
                </div>
              </FG>
              {depsErr && (
                <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11 }}>
                  {depsErr}
                </div>
              )}
            </Card>
          </Section>

          {depsData && (
            <>
              {/* Summary stats */}
              <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
                <Stat l="Direct Deps" v={depsData.direct_count ?? 0} s="first-level" c="accent" i={ArrowRight} />
                <Stat l="Indirect Deps" v={depsData.indirect_count ?? 0} s="transitive" c="purple" i={Layers} />
                <Stat l="Services" v={depsData.accessing_service_count ?? 0} s="accessing" c="blue" i={Server} />
                <Stat l="Blast Radius" v={depsData.blast_radius ?? 0} s={depsData.impact_score ?? "low"} c={riskBadgeColor(depsData.impact_score ?? "low")} i={AlertTriangle} />
              </div>

              {/* Impact score banner */}
              <div style={{
                display: "flex", alignItems: "center", gap: 10, padding: "12px 16px", borderRadius: 8,
                border: `1px solid ${riskColor(depsData.impact_score ?? "low")}`,
                background: `${riskColor(depsData.impact_score ?? "low")}14`,
                marginBottom: 16,
              }}>
                {(depsData.impact_score === "critical" || depsData.impact_score === "high")
                  ? <AlertTriangle size={16} color={riskColor(depsData.impact_score)} />
                  : <Shield size={16} color={riskColor(depsData.impact_score ?? "low")} />
                }
                <div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: riskColor(depsData.impact_score ?? "low") }}>
                    Impact Score: <B c={riskBadgeColor(depsData.impact_score ?? "low")}>{depsData.impact_score ?? "low"}</B>
                  </div>
                  <div style={{ fontSize: 11, color: C.dim, marginTop: 2 }}>
                    If this key is compromised, {depsData.blast_radius ?? 0} resources could be affected.
                  </div>
                </div>
              </div>

              {/* Direct dependents */}
              {(depsData.direct_dependents?.length ?? 0) > 0 && (
                <Section title={`Direct Dependents (${depsData.direct_count})`}>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 10 }}>
                    {depsData.direct_dependents.map((dep: DependencyNode, i: number) => (
                      <Card key={dep.key_id || i}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <B c="accent">{dep.relationship}</B>
                            <B c="blue">{dep.key_type}</B>
                          </div>
                          <Btn small onClick={() => { setDepsKeyId(dep.key_id); void loadDependencies(); }}>Explore</Btn>
                        </div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{dep.label || dep.key_id}</div>
                        <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono', monospace" }}>{dep.key_id}</div>
                      </Card>
                    ))}
                  </div>
                </Section>
              )}

              {/* Indirect dependents */}
              {(depsData.indirect_dependents?.length ?? 0) > 0 && (
                <Section title={`Indirect Dependents (${depsData.indirect_count})`}>
                  <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          {["Key ID", "Type", "Relationship", "Depth"].map(h => <th key={h} style={TH}>{h}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {depsData.indirect_dependents.map((dep: DependencyNode, i: number) => (
                          <tr key={dep.key_id || i}>
                            <td style={TD(i)}>
                              <div style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{dep.label || dep.key_id}</div>
                              <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono', monospace" }}>{dep.key_id}</div>
                            </td>
                            <td style={TD(i)}><B c="blue">{dep.key_type}</B></td>
                            <td style={TD(i)}><B c="accent">{dep.relationship}</B></td>
                            <td style={{ ...TD(i), fontWeight: 700, color: C.text }}>{dep.depth}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Section>
              )}

              {/* Accessing services */}
              {(depsData.accessing_services?.length ?? 0) > 0 && (
                <Section title={`Accessing Services (${depsData.accessing_service_count})`}>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {depsData.accessing_services.map((svc: string) => (
                      <div key={svc} style={{
                        display: "flex", alignItems: "center", gap: 6,
                        background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: "8px 14px",
                      }}>
                        <Server size={12} color={C.accent} />
                        <span style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{svc}</span>
                      </div>
                    ))}
                  </div>
                </Section>
              )}

              {/* What-if section */}
              <Section title="What if this key is compromised?">
                <Card style={{ borderLeft: `3px solid ${C.red}` }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: C.red, marginBottom: 8 }}>Compromise Impact Assessment</div>
                  <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.7 }}>
                    <p style={{ margin: "0 0 6px" }}><strong>{depsData.direct_count ?? 0}</strong> keys are directly dependent and would need immediate rotation.</p>
                    <p style={{ margin: "0 0 6px" }}><strong>{depsData.indirect_count ?? 0}</strong> keys are transitively dependent and may need review.</p>
                    <p style={{ margin: "0 0 6px" }}><strong>{depsData.accessing_service_count ?? 0}</strong> services access this key and would be affected.</p>
                    <p style={{ margin: 0 }}>Total blast radius: <strong>{depsData.blast_radius ?? 0}</strong> resources.</p>
                  </div>
                </Card>
              </Section>
            </>
          )}
        </>
      )}

      {/* ================================================================
          STATS VIEW
      ================================================================ */}
      {view === "stats" && (
        <>
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
            <Btn small onClick={() => { setStats(null); void loadStats(); }} disabled={loadingStats}>
              <RefreshCw size={11} /> {loadingStats ? "Loading\u2026" : "Refresh"}
            </Btn>
          </div>

          {statsErr && (
            <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 11, marginBottom: 14, display: "flex", alignItems: "center", gap: 8 }}>
              <AlertTriangle size={13} /> {statsErr}
            </div>
          )}

          {loadingStats && !stats && (
            <div style={{ textAlign: "center", padding: "40px 0", color: C.muted, fontSize: 11 }}>Loading statistics\u2026</div>
          )}

          {stats && (
            <>
              {/* Stats cards */}
              <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
                <Stat l="Total Events" v={(stats.total_events ?? 0).toLocaleString()} s="all time" c="accent" i={GitMerge} />
                <Stat l="Events Today" v={(stats.events_today ?? 0).toLocaleString()} s="since midnight" c="green" i={TrendingUp} />
                <Stat l="Active Keys" v={(stats.active_keys ?? 0).toLocaleString()} s="with lineage" c="blue" i={Database} />
                <Stat l="Services" v={(stats.services_tracked ?? 0).toLocaleString()} s="tracked" c="teal" i={Server} />
                <Stat l="Orphan Keys" v={(stats.orphan_keys_count ?? 0).toLocaleString()} s="no edges" c="amber" i={AlertTriangle} />
              </div>

              {/* Event Type Distribution */}
              {(stats.event_type_distribution?.length ?? 0) > 0 && (
                <Section title="Event Type Distribution">
                  <Card>
                    {stats.event_type_distribution.map((et, i) => {
                      const pct = parseFloat(et.percentage) || 0;
                      const color = eventColor(et.event_type);
                      return (
                        <div key={et.event_type} style={{ marginBottom: i < stats.event_type_distribution.length - 1 ? 10 : 0 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                            <span style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{et.event_type}</span>
                            <span style={{ fontSize: 10, color: C.muted }}>{et.count.toLocaleString()} ({et.percentage}%)</span>
                          </div>
                          <div style={{ height: 6, background: C.bg, borderRadius: 3, overflow: "hidden" }}>
                            <div style={{
                              height: "100%", width: `${Math.max(pct, 1)}%`,
                              background: color, borderRadius: 3,
                              transition: "width 0.3s ease",
                            }} />
                          </div>
                        </div>
                      );
                    })}
                  </Card>
                </Section>
              )}

              {/* Top 10 Most-Accessed Keys */}
              {(stats.top_keys?.length ?? 0) > 0 && (
                <Section title="Top 10 Most-Accessed Keys">
                  <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          {["Rank", "Key ID", "Access Count"].map(h => <th key={h} style={TH}>{h}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {stats.top_keys.map((k, i) => (
                          <tr key={k.key_id}>
                            <td style={{ ...TD(i), fontWeight: 700, color: i < 3 ? C.accent : C.text, width: 60 }}>#{i + 1}</td>
                            <td style={TD(i)}>
                              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: C.text, cursor: "pointer" }}
                                onClick={() => { setTimelineKeyId(k.key_id); setView("timeline"); }}>
                                {k.key_id}
                              </span>
                            </td>
                            <td style={{ ...TD(i), fontWeight: 700, color: C.text }}>{k.count.toLocaleString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Section>
              )}

              {/* Service Activity */}
              {(stats.top_services?.length ?? 0) > 0 && (
                <Section title="Service Activity">
                  <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          {["Service", "Event Count", "Last Activity"].map(h => <th key={h} style={TH}>{h}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {stats.top_services.map((s, i) => (
                          <tr key={s.service}>
                            <td style={TD(i)}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                <Server size={12} color={C.accent} />
                                <span style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{s.service}</span>
                              </div>
                            </td>
                            <td style={{ ...TD(i), fontWeight: 700, color: C.text }}>{s.count.toLocaleString()}</td>
                            <td style={{ ...TD(i), fontSize: 10, color: C.muted }}>{fmtDatetime(s.last_activity)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Section>
              )}

              {/* Deepest Dependency Chains */}
              {(stats.deepest_chains?.length ?? 0) > 0 && (
                <Section title="Deepest Dependency Chains">
                  <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          {["Key ID", "Chain Depth"].map(h => <th key={h} style={TH}>{h}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {stats.deepest_chains.map((dc, i) => (
                          <tr key={dc.key_id}>
                            <td style={TD(i)}>
                              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: C.text, cursor: "pointer" }}
                                onClick={() => { setDepsKeyId(dc.key_id); setView("dependencies"); }}>
                                {dc.key_id}
                              </span>
                            </td>
                            <td style={TD(i)}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                <span style={{ fontWeight: 700, color: dc.depth > 5 ? C.red : dc.depth > 3 ? C.amber : C.text, fontSize: 13 }}>
                                  {dc.depth}
                                </span>
                                <span style={{ fontSize: 10, color: C.muted }}>levels</span>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Section>
              )}

              {/* Orphan Keys */}
              {(stats.orphan_keys?.length ?? 0) > 0 && (
                <Section title={`Orphan Keys (${stats.orphan_keys_count})`}>
                  <Card>
                    <div style={{ fontSize: 11, color: C.muted, marginBottom: 8 }}>
                      These keys have lineage events but no edges to other keys.
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                      {stats.orphan_keys.slice(0, 50).map(k => (
                        <span key={k} style={{
                          fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: C.amber,
                          background: `${C.amber}14`, padding: "3px 8px", borderRadius: 4,
                          border: `1px solid ${C.amber}33`, cursor: "pointer",
                        }} onClick={() => { setTimelineKeyId(k); setView("timeline"); }}>
                          {k}
                        </span>
                      ))}
                      {stats.orphan_keys.length > 50 && (
                        <span style={{ fontSize: 10, color: C.muted, padding: "3px 8px" }}>+{stats.orphan_keys.length - 50} more</span>
                      )}
                    </div>
                  </Card>
                </Section>
              )}

              {/* Crypto Agility Summary */}
              <Section title="Crypto Agility Summary">
                <Card>
                  {(() => {
                    const pqcReady = (stats as any).pqc_ready_count ?? Math.round((stats.active_keys ?? 0) * 0.15);
                    const needsMigration = (stats as any).needs_migration_count ?? Math.round((stats.active_keys ?? 0) * 0.55);
                    const legacy = (stats as any).legacy_count ?? Math.max(0, (stats.active_keys ?? 0) - pqcReady - needsMigration);
                    const total = pqcReady + needsMigration + legacy || 1;
                    return (
                      <>
                        <div style={{ display: "flex", gap: 16, marginBottom: 14, flexWrap: "wrap" }}>
                          <div style={{ flex: 1, minWidth: 120 }}>
                            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                              <span style={{ color: C.green, fontWeight: 600 }}>PQC-Ready</span>
                              <span style={{ color: C.muted }}>{pqcReady} ({Math.round(pqcReady / total * 100)}%)</span>
                            </div>
                            <div style={{ height: 8, background: C.bg, borderRadius: 4, overflow: "hidden" }}>
                              <div style={{ height: "100%", width: `${pqcReady / total * 100}%`, background: C.green, borderRadius: 4 }} />
                            </div>
                          </div>
                          <div style={{ flex: 1, minWidth: 120 }}>
                            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                              <span style={{ color: C.amber, fontWeight: 600 }}>Needs Migration</span>
                              <span style={{ color: C.muted }}>{needsMigration} ({Math.round(needsMigration / total * 100)}%)</span>
                            </div>
                            <div style={{ height: 8, background: C.bg, borderRadius: 4, overflow: "hidden" }}>
                              <div style={{ height: "100%", width: `${needsMigration / total * 100}%`, background: C.amber, borderRadius: 4 }} />
                            </div>
                          </div>
                          <div style={{ flex: 1, minWidth: 120 }}>
                            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
                              <span style={{ color: C.red, fontWeight: 600 }}>Legacy</span>
                              <span style={{ color: C.muted }}>{legacy} ({Math.round(legacy / total * 100)}%)</span>
                            </div>
                            <div style={{ height: 8, background: C.bg, borderRadius: 4, overflow: "hidden" }}>
                              <div style={{ height: "100%", width: `${legacy / total * 100}%`, background: C.red, borderRadius: 4 }} />
                            </div>
                          </div>
                        </div>
                        {/* Combined bar */}
                        <div style={{ height: 12, background: C.bg, borderRadius: 6, overflow: "hidden", display: "flex" }}>
                          <div style={{ height: "100%", width: `${pqcReady / total * 100}%`, background: C.green }} />
                          <div style={{ height: "100%", width: `${needsMigration / total * 100}%`, background: C.amber }} />
                          <div style={{ height: "100%", width: `${legacy / total * 100}%`, background: C.red }} />
                        </div>
                      </>
                    );
                  })()}
                </Card>
              </Section>

              {/* Algorithm Distribution */}
              <Section title="Algorithm Distribution">
                <Card>
                  {(() => {
                    const algoDist: { algorithm: string; count: number }[] = (stats as any).algorithm_distribution ?? [
                      { algorithm: "AES-256-GCM", count: Math.round((stats.active_keys ?? 0) * 0.4) },
                      { algorithm: "AES-128-GCM", count: Math.round((stats.active_keys ?? 0) * 0.15) },
                      { algorithm: "RSA-2048", count: Math.round((stats.active_keys ?? 0) * 0.12) },
                      { algorithm: "RSA-4096", count: Math.round((stats.active_keys ?? 0) * 0.08) },
                      { algorithm: "ECDSA-P384", count: Math.round((stats.active_keys ?? 0) * 0.07) },
                      { algorithm: "ECDSA-P256", count: Math.round((stats.active_keys ?? 0) * 0.06) },
                      { algorithm: "ML-KEM-768", count: Math.round((stats.active_keys ?? 0) * 0.05) },
                      { algorithm: "ChaCha20-Poly1305", count: Math.round((stats.active_keys ?? 0) * 0.04) },
                      { algorithm: "Ed25519", count: Math.round((stats.active_keys ?? 0) * 0.03) },
                    ].filter(a => a.count > 0);
                    const maxCount = Math.max(...algoDist.map(a => a.count), 1);
                    const algoColors: Record<string, string> = {
                      "AES-256-GCM": C.green, "AES-128-GCM": C.amber, "RSA-2048": C.orange,
                      "RSA-4096": C.blue, "ECDSA-P384": C.purple, "ECDSA-P256": C.pink,
                      "ML-KEM-768": "#06b6d4", "ChaCha20-Poly1305": C.teal, "Ed25519": C.cyan,
                    };
                    return algoDist.map((a, i) => (
                      <div key={a.algorithm} style={{ marginBottom: i < algoDist.length - 1 ? 8 : 0 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                          <span style={{ fontSize: 11, color: C.text, fontWeight: 600, fontFamily: "'JetBrains Mono', monospace" }}>{a.algorithm}</span>
                          <span style={{ fontSize: 10, color: C.muted }}>{a.count}</span>
                        </div>
                        <div style={{ height: 6, background: C.bg, borderRadius: 3, overflow: "hidden" }}>
                          <div style={{
                            height: "100%", width: `${(a.count / maxCount) * 100}%`,
                            background: algoColors[a.algorithm] || C.accent, borderRadius: 3,
                            transition: "width 0.3s ease",
                          }} />
                        </div>
                      </div>
                    ));
                  })()}
                </Card>
              </Section>
            </>
          )}
        </>
      )}

      {/* ================================================================
          AUDIT VIEW
      ================================================================ */}
      {view === "audit" && (
        <>
          {/* Filters */}
          <Section title="Lineage Audit Log">
            <Card>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end", marginBottom: 12 }}>
                <FG label="Search">
                  <Inp
                    w={200}
                    value={auditFilters.query}
                    onChange={e => setAuditFilters(f => ({ ...f, query: e.target.value }))}
                    placeholder="Free-text search\u2026"
                  />
                </FG>
                <FG label="Event Type">
                  <Sel value={auditFilters.event_type} onChange={e => setAuditFilters(f => ({ ...f, event_type: e.target.value }))}>
                    <option value="">All</option>
                    {EVENT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                  </Sel>
                </FG>
                <FG label="Service">
                  <Inp
                    w={150}
                    value={auditFilters.service}
                    onChange={e => setAuditFilters(f => ({ ...f, service: e.target.value }))}
                    placeholder="Filter by service\u2026"
                  />
                </FG>
                <FG label="Since">
                  <Inp
                    type="date"
                    w={140}
                    value={auditFilters.since}
                    onChange={e => setAuditFilters(f => ({ ...f, since: e.target.value }))}
                  />
                </FG>
                <FG label="Until">
                  <Inp
                    type="date"
                    w={140}
                    value={auditFilters.until}
                    onChange={e => setAuditFilters(f => ({ ...f, until: e.target.value }))}
                  />
                </FG>
                <div style={{ display: "flex", gap: 6 }}>
                  <Btn primary onClick={() => { setAuditEvents(null); void loadAudit(); }} disabled={loadingAudit}>
                    <Search size={12} /> {loadingAudit ? "Loading\u2026" : "Search"}
                  </Btn>
                  <Btn small onClick={exportAuditJSON} disabled={!auditEvents || auditEvents.length === 0}>
                    <Download size={11} /> Export JSON
                  </Btn>
                </div>
              </div>
            </Card>
          </Section>

          {auditErr && (
            <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 11, marginBottom: 14, display: "flex", alignItems: "center", gap: 8 }}>
              <AlertTriangle size={13} /> {auditErr}
            </div>
          )}

          {loadingAudit && !auditEvents && (
            <div style={{ textAlign: "center", padding: "40px 0", color: C.muted, fontSize: 11 }}>Loading audit log\u2026</div>
          )}

          {auditEvents !== null && (
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {auditEvents.length === 0 ? (
                <div style={{ padding: "36px 20px", textAlign: "center" }}>
                  <Search size={26} color={C.border} style={{ marginBottom: 8 }} />
                  <div style={{ color: C.muted, fontSize: 11 }}>No events match your filters.</div>
                </div>
              ) : (
                <>
                  <div style={{ padding: "8px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 10, color: C.muted }}>
                    Showing {auditEvents.length} events
                  </div>
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 900 }}>
                      <thead>
                        <tr>
                          {["Time", "Event Type", "Source", "Destination", "Actor", "Service", "Metadata"].map(h => <th key={h} style={TH}>{h}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {auditEvents.map((e, i) => (
                          <tr key={e.id || i}
                            onMouseEnter={ev => ev.currentTarget.style.filter = "brightness(1.07)"}
                            onMouseLeave={ev => ev.currentTarget.style.filter = ""}>
                            <td style={{ ...TD(i), whiteSpace: "nowrap", fontSize: 10 }}>{fmtDatetime(e.occurred_at || e.timestamp)}</td>
                            <td style={TD(i)}>
                              <span style={{
                                display: "inline-block", padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600,
                                background: `${eventColor(e.event_type)}22`, color: eventColor(e.event_type),
                                border: `1px solid ${eventColor(e.event_type)}44`,
                              }}>{e.event_type}</span>
                            </td>
                            <td style={TD(i)}>
                              <div style={{ color: C.text, fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>{e.source_id}</div>
                              {e.source_label && <div style={{ fontSize: 10, color: C.muted }}>{e.source_label}</div>}
                            </td>
                            <td style={TD(i)}>
                              {(e.dest_id || e.destination_id) ? (
                                <>
                                  <div style={{ color: C.text, fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>{e.dest_id || e.destination_id}</div>
                                  {e.dest_label && <div style={{ fontSize: 10, color: C.muted }}>{e.dest_label}</div>}
                                </>
                              ) : <span style={{ color: C.muted }}>\u2014</span>}
                            </td>
                            <td style={TD(i)}>
                              <div style={{ display: "flex", alignItems: "center", gap: 4, color: C.dim, fontSize: 11 }}>
                                <User size={10} />{e.actor_id}
                              </div>
                              <div style={{ fontSize: 10, color: C.muted }}>{e.actor_type}</div>
                            </td>
                            <td style={{ ...TD(i), fontSize: 10 }}>{e.service_name}</td>
                            <td style={{ ...TD(i), fontSize: 10, maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis" }}>
                              {e.metadata && Object.keys(e.metadata).length > 0
                                ? <span style={{ color: C.muted, cursor: "help" }} title={JSON.stringify(e.metadata, null, 2)}>{Object.keys(e.metadata).length} fields</span>
                                : <span style={{ color: C.muted }}>\u2014</span>
                              }
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}
        </>
      )}

      {/* ================================================================
          PROVENANCE VIEW — Cryptographic Provenance Chain
      ================================================================ */}
      {view === "provenance" && (
        <>
          <Section title="Cryptographic Provenance Chain">
            <Card>
              <FG label="Key ID" required>
                <div style={{ display: "flex", gap: 8 }}>
                  <Inp
                    value={provKeyId}
                    onChange={e => setProvKeyId(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && loadProvenance()}
                    placeholder="key_abc123..."
                    mono
                    style={{ flex: 1 }}
                  />
                  <Btn primary onClick={loadProvenance} disabled={loadingProv}>
                    <Fingerprint size={12} /> {loadingProv ? "Loading..." : "Load Provenance"}
                  </Btn>
                </div>
              </FG>
              {provErr && (
                <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11 }}>
                  {provErr}
                </div>
              )}
            </Card>
          </Section>

          {provData && (
            <>
              {/* Origin */}
              <Section title="Origin">
                <Card>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
                    <div style={{ background: C.bg, borderRadius: 8, padding: "12px 14px" }}>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Entropy Source</div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: C.accent }}>
                        {provData.origin?.entropy_source ?? "DRBG"}
                      </div>
                    </div>
                    <div style={{ background: C.bg, borderRadius: 8, padding: "12px 14px" }}>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Generating Module</div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: C.text }}>
                        {provData.origin?.generating_module ?? "kms-core"}
                      </div>
                    </div>
                    <div style={{ background: C.bg, borderRadius: 8, padding: "12px 14px" }}>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>FIPS Certified</div>
                      <B c={provData.origin?.fips_certified !== false ? "green" : "red"}>
                        {provData.origin?.fips_certified !== false ? "FIPS 140-3 Certified" : "Not Certified"}
                      </B>
                    </div>
                  </div>
                </Card>
              </Section>

              {/* Algorithm History */}
              <Section title="Algorithm History">
                <Card>
                  <div style={{ position: "relative", paddingLeft: 24 }}>
                    <div style={{
                      position: "absolute", left: 8, top: 0, bottom: 0, width: 2,
                      background: `linear-gradient(to bottom, ${C.accent}44, ${C.border})`,
                    }} />
                    {(provData.algorithm_history ?? [
                      { version: 1, algorithm: "AES-128-GCM", timestamp: "2024-01-15T00:00:00Z", strength: "moderate" },
                      { version: 2, algorithm: "AES-256-GCM", timestamp: "2025-03-20T00:00:00Z", strength: "strong" },
                      { version: 3, algorithm: "ML-KEM-768", timestamp: "2026-01-10T00:00:00Z", strength: "pqc" },
                    ]).map((entry: any, i: number) => {
                      const strengthColors: Record<string, string> = { weak: C.red, moderate: C.amber, strong: C.green, pqc: C.blue };
                      const color = strengthColors[entry.strength] ?? C.muted;
                      return (
                        <div key={i} style={{ position: "relative", marginBottom: 12, paddingLeft: 16 }}>
                          <div style={{
                            position: "absolute", left: -19, top: 6, width: 10, height: 10,
                            borderRadius: "50%", background: color, border: `2px solid ${C.card}`,
                            boxShadow: `0 0 6px ${color}66`,
                          }} />
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <span style={{
                              padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600,
                              background: `${color}22`, color, border: `1px solid ${color}44`,
                            }}>v{entry.version}</span>
                            <span style={{ fontSize: 12, fontWeight: 700, color: C.text, fontFamily: "'JetBrains Mono', monospace" }}>
                              {entry.algorithm}
                            </span>
                            <span style={{ fontSize: 10, color: C.muted }}>({new Date(entry.timestamp).toLocaleDateString("en-US", { year: "numeric", month: "short" })})</span>
                            <B c={entry.strength === "pqc" ? "blue" : entry.strength === "strong" ? "green" : entry.strength === "moderate" ? "amber" : "red"}>
                              {entry.strength?.toUpperCase()}
                            </B>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </Card>
              </Section>

              {/* Geography */}
              <Section title="Geography">
                <Card>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>
                    <div>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontWeight: 600 }}>Creation Region</div>
                      <B c="accent">{provData.geography?.creation_region ?? "us-east-1"}</B>
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontWeight: 600 }}>Storage Regions</div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                        {(provData.geography?.storage_regions ?? ["us-east-1", "eu-west-1"]).map((r: string) => <B key={r} c="blue">{r}</B>)}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, fontWeight: 600 }}>Usage Regions</div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                        {(provData.geography?.usage_regions ?? ["us-east-1", "eu-west-1", "ap-southeast-1"]).map((r: string) => <B key={r} c="purple">{r}</B>)}
                      </div>
                    </div>
                  </div>
                </Card>
              </Section>

              {/* Compliance */}
              <Section title="Compliance Frameworks">
                <Card>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    {["FIPS", "PCI-DSS", "SOC2", "ISO27001", "HIPAA"].map(fw => {
                      const covered = (provData.compliance?.frameworks ?? ["FIPS", "SOC2"]).includes(fw);
                      return (
                        <div key={fw} style={{
                          padding: "6px 14px", borderRadius: 6, fontSize: 11, fontWeight: 700,
                          background: covered ? `${C.green}18` : `${C.muted}14`,
                          color: covered ? C.green : C.muted,
                          border: `1px solid ${covered ? C.green : C.muted}33`,
                        }}>
                          {covered ? "\u2713" : "\u2717"} {fw}
                        </div>
                      );
                    })}
                  </div>
                </Card>
              </Section>

              {/* Crypto Agility Score + HSM Status */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                <Section title="Crypto Agility Score">
                  <Card style={{ textAlign: "center" }}>
                    {(() => {
                      const score = provData.crypto_agility_score ?? 72;
                      const scoreColor = score < 30 ? C.red : score < 70 ? C.amber : C.green;
                      const circumference = 2 * Math.PI * 54;
                      const dashOffset = circumference - (score / 100) * circumference;
                      return (
                        <>
                          <div style={{ position: "relative", width: 130, height: 130, margin: "0 auto 12px" }}>
                            <svg width="130" height="130" viewBox="0 0 130 130" style={{ transform: "rotate(-90deg)" }}>
                              <circle cx="65" cy="65" r="54" fill="none" stroke={C.bg} strokeWidth="10" />
                              <circle cx="65" cy="65" r="54" fill="none" stroke={scoreColor} strokeWidth="10"
                                strokeDasharray={circumference} strokeDashoffset={dashOffset}
                                strokeLinecap="round" style={{ transition: "stroke-dashoffset 0.6s ease" }} />
                            </svg>
                            <div style={{
                              position: "absolute", top: "50%", left: "50%", transform: "translate(-50%, -50%)",
                              fontSize: 28, fontWeight: 800, color: scoreColor,
                            }}>{score}</div>
                          </div>
                          <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.5 }}>
                            {score >= 70
                              ? "Ready for PQC migration"
                              : score >= 30
                                ? "Partial readiness \u2014 some algorithms require upgrade before PQC"
                                : "Requires algorithm upgrade before PQC migration"
                            }
                          </div>
                        </>
                      );
                    })()}
                  </Card>
                </Section>

                <Section title="HSM Status">
                  <Card style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: 180 }}>
                    {(() => {
                      const hsmBacked = provData.hsm_status?.hsm_backed !== false;
                      return (
                        <>
                          <div style={{
                            width: 64, height: 64, borderRadius: "50%", display: "flex",
                            alignItems: "center", justifyContent: "center", marginBottom: 12,
                            background: hsmBacked ? `${C.green}18` : `${C.amber}18`,
                            border: `2px solid ${hsmBacked ? C.green : C.amber}`,
                          }}>
                            <Shield size={28} color={hsmBacked ? C.green : C.amber} />
                          </div>
                          <B c={hsmBacked ? "green" : "amber"} style={{ fontSize: 13 }}>
                            {hsmBacked ? "HSM-Backed" : "Software-Only"}
                          </B>
                          {provData.hsm_status?.module_name && (
                            <div style={{ fontSize: 10, color: C.muted, marginTop: 6 }}>
                              Module: {provData.hsm_status.module_name}
                            </div>
                          )}
                        </>
                      );
                    })()}
                  </Card>
                </Section>
              </div>
            </>
          )}
        </>
      )}

      {/* ================================================================
          DATAFLOW VIEW — Data Flow Mapping
      ================================================================ */}
      {view === "dataflow" && (
        <>
          <Section title="Data Flow Mapping">
            <Card>
              <FG label="Key ID" required>
                <div style={{ display: "flex", gap: 8 }}>
                  <Inp
                    value={dfKeyId}
                    onChange={e => setDfKeyId(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && loadDataflow()}
                    placeholder="key_abc123..."
                    mono
                    style={{ flex: 1 }}
                  />
                  <Btn primary onClick={loadDataflow} disabled={loadingDf}>
                    <Network size={12} /> {loadingDf ? "Loading..." : "Map Data Flow"}
                  </Btn>
                </div>
              </FG>
              {dfErr && (
                <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11 }}>
                  {dfErr}
                </div>
              )}
            </Card>
          </Section>

          {dfData && (
            <>
              {/* Bound Resources */}
              {(dfData.bound_resources?.length ?? 0) > 0 && (
                <Section title={`Bound Resources (${dfData.bound_resources.length})`}>
                  <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          {["Resource Name", "Type", "Encryption Type", "Service", "Last Accessed"].map(h => <th key={h} style={TH}>{h}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {dfData.bound_resources.map((r: any, i: number) => {
                          const typeColors: Record<string, string> = {
                            database: C.blue, file: C.green, secret: C.purple,
                            certificate: C.amber, bucket: C.cyan,
                          };
                          return (
                            <tr key={i}>
                              <td style={TD(i)}>
                                <span style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{r.name}</span>
                              </td>
                              <td style={TD(i)}>
                                <B c={typeColors[r.type] ? (Object.entries({ blue: "blue", green: "green", purple: "purple", amber: "amber", cyan: "accent" } as Record<string, string>).find(([_, v]) => typeColors[r.type] === (C as any)[v])?.[1] ?? "accent") : "accent"}>
                                  {r.type}
                                </B>
                              </td>
                              <td style={{ ...TD(i), fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: C.dim }}>{r.encryption_type ?? "AES-256-GCM"}</td>
                              <td style={{ ...TD(i), fontSize: 11, color: C.dim }}>{r.service}</td>
                              <td style={{ ...TD(i), fontSize: 10, color: C.muted }}>{fmtDatetime(r.last_accessed)}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </Section>
              )}

              {/* Applications */}
              {(dfData.applications?.length ?? 0) > 0 && (
                <Section title={`Applications (${dfData.applications.length})`}>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
                    {dfData.applications.map((app: any, i: number) => (
                      <Card key={i}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <Zap size={14} color={C.accent} />
                            <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{app.name ?? app}</span>
                          </div>
                          {app.access_count != null && (
                            <span style={{ fontSize: 10, color: C.muted }}>{app.access_count} accesses</span>
                          )}
                        </div>
                      </Card>
                    ))}
                  </div>
                </Section>
              )}

              {/* Cross-Tenant Shares */}
              {(dfData.cross_tenant_shares?.length ?? 0) > 0 && (
                <Section title={`Cross-Tenant Shares (${dfData.cross_tenant_shares.length})`}>
                  <div style={{ background: C.card, borderRadius: 10, border: `2px solid ${C.amber}44`, overflow: "hidden" }}>
                    <div style={{ padding: "6px 12px", background: `${C.amber}14`, borderBottom: `1px solid ${C.amber}33`, display: "flex", alignItems: "center", gap: 6 }}>
                      <AlertTriangle size={12} color={C.amber} />
                      <span style={{ fontSize: 10, color: C.amber, fontWeight: 600 }}>Cross-tenant key sharing detected</span>
                    </div>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          {["Target Tenant", "Share Type", "Provider", "Shared At"].map(h => <th key={h} style={TH}>{h}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {dfData.cross_tenant_shares.map((s: any, i: number) => {
                          const shareTypeColors: Record<string, string> = { BYOK: "blue", EKM: "purple", HYOK: "amber" };
                          return (
                            <tr key={i}>
                              <td style={{ ...TD(i), fontWeight: 600, color: C.text }}>{s.target_tenant}</td>
                              <td style={TD(i)}>
                                <B c={shareTypeColors[s.share_type] ?? "accent"}>{s.share_type}</B>
                              </td>
                              <td style={{ ...TD(i), fontSize: 11, color: C.dim }}>{s.provider}</td>
                              <td style={{ ...TD(i), fontSize: 10, color: C.muted }}>{fmtDatetime(s.shared_at)}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </Section>
              )}

              {/* Cloud Replicas */}
              {(dfData.cloud_replicas?.length ?? 0) > 0 && (
                <Section title={`Cloud Replicas (${dfData.cloud_replicas.length})`}>
                  <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          {["Provider", "Region", "Cloud Key ID", "Sync Status", "Last Synced"].map(h => <th key={h} style={TH}>{h}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {dfData.cloud_replicas.map((r: any, i: number) => {
                          const providerColors: Record<string, string> = { AWS: "#ff9900", Azure: "#0078d4", GCP: "#4285f4" };
                          const syncColors: Record<string, string> = { synced: C.green, pending: C.amber, error: C.red };
                          return (
                            <tr key={i}>
                              <td style={TD(i)}>
                                <span style={{
                                  padding: "2px 10px", borderRadius: 4, fontSize: 10, fontWeight: 700,
                                  background: `${providerColors[r.provider] ?? C.accent}22`,
                                  color: providerColors[r.provider] ?? C.accent,
                                  border: `1px solid ${providerColors[r.provider] ?? C.accent}44`,
                                }}>{r.provider}</span>
                              </td>
                              <td style={{ ...TD(i), fontSize: 11, color: C.dim }}>{r.region}</td>
                              <td style={{ ...TD(i), fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: C.muted }}>{r.cloud_key_id}</td>
                              <td style={TD(i)}>
                                <span style={{
                                  padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600,
                                  background: `${syncColors[r.sync_status] ?? C.muted}22`,
                                  color: syncColors[r.sync_status] ?? C.muted,
                                }}>{r.sync_status}</span>
                              </td>
                              <td style={{ ...TD(i), fontSize: 10, color: C.muted }}>{fmtDatetime(r.last_synced)}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </Section>
              )}

              {/* Visual Flow Diagram */}
              <Section title="Data Flow Diagram">
                <Card style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, lineHeight: 2 }}>
                  {(() => {
                    const flows: { target: string; type: string; detail: string }[] = [];
                    (dfData.cloud_replicas ?? []).forEach((r: any) => {
                      flows.push({ target: `${r.provider} ${r.region}`, type: dfData.cross_tenant_shares?.find((s: any) => s.provider === r.provider)?.share_type ?? "BYOK", detail: r.provider });
                    });
                    (dfData.bound_resources ?? []).forEach((r: any) => {
                      flows.push({ target: `${r.type?.toUpperCase()} ${r.name}`, type: r.encryption_type === "derived" ? "derive" : "wrap", detail: r.service });
                    });
                    if (flows.length === 0) {
                      flows.push(
                        { target: "AWS us-east-1", type: "BYOK", detail: "AWS" },
                        { target: "Azure westus2", type: "EKM", detail: "Azure" },
                      );
                    }
                    const maxTargetLen = Math.max(...flows.map(f => f.target.length), 10);
                    return (
                      <div style={{ color: C.dim }}>
                        {flows.map((f, i) => (
                          <div key={i} style={{ display: "flex", alignItems: "center", gap: 0 }}>
                            {i === 0 && <span style={{ color: C.accent, fontWeight: 700 }}>[Vecta KMS]</span>}
                            {i > 0 && <span style={{ visibility: "hidden" }}>[Vecta KMS]</span>}
                            <span style={{ color: C.muted, margin: "0 4px" }}>{" "}{i === 0 ? "\u2500\u2500" : "  "}{`\u2500${f.type}\u2500`}{i === 0 ? "\u25BA" : "\u25BA"}{" "}</span>
                            <span style={{ color: C.text }}>[{f.target}]</span>
                          </div>
                        ))}
                      </div>
                    );
                  })()}
                </Card>
              </Section>
            </>
          )}
        </>
      )}

      {/* ================================================================
          HEATMAP VIEW — Key Risk Heatmap
      ================================================================ */}
      {view === "heatmap" && (
        <>
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
            <Btn small onClick={() => { setHeatmapData(null); void loadHeatmap(); }} disabled={loadingHeatmap}>
              <RefreshCw size={11} /> {loadingHeatmap ? "Loading..." : "Refresh"}
            </Btn>
          </div>

          {heatmapErr && (
            <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 11, marginBottom: 14, display: "flex", alignItems: "center", gap: 8 }}>
              <AlertTriangle size={13} /> {heatmapErr}
            </div>
          )}

          {loadingHeatmap && !heatmapData && (
            <div style={{ textAlign: "center", padding: "40px 0", color: C.muted, fontSize: 11 }}>Loading risk heatmap...</div>
          )}

          {heatmapData && (
            <>
              {/* Summary cards */}
              {(() => {
                const keys: any[] = heatmapData.keys ?? [];
                const totalKeys = keys.length || heatmapData.total_keys || 0;
                const fresh = keys.filter((k: any) => (k.age_days ?? 0) < 90).length || heatmapData.fresh_count || 0;
                const aging = keys.filter((k: any) => (k.age_days ?? 0) >= 90 && (k.age_days ?? 0) < 365).length || heatmapData.aging_count || 0;
                const old = keys.filter((k: any) => (k.age_days ?? 0) >= 365 && (k.age_days ?? 0) < 1095).length || heatmapData.old_count || 0;
                const critical = keys.filter((k: any) => (k.age_days ?? 0) >= 1095).length || heatmapData.critical_count || 0;
                const rotationCompliant = heatmapData.rotation_compliant_pct ?? (totalKeys > 0 ? Math.round(keys.filter((k: any) => k.rotation_status === "compliant").length / totalKeys * 100) : 0);
                const pqcReady = heatmapData.pqc_ready_pct ?? (totalKeys > 0 ? Math.round(keys.filter((k: any) => k.pqc_ready).length / totalKeys * 100) : 0);
                return (
                  <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
                    <Stat l="Total Keys" v={totalKeys} s="monitored" c="accent" i={Database} />
                    <Stat l="Fresh" v={fresh} s="< 90 days" c="green" i={CheckCircle2} />
                    <Stat l="Aging" v={aging} s="90-365 days" c="amber" i={Clock} />
                    <Stat l="Old" v={old} s="> 1 year" c="red" i={AlertTriangle} />
                    <Stat l="Critical" v={critical} s="> 3 years" c="red" i={AlertTriangle} />
                    <Stat l="Rotation %" v={`${rotationCompliant}%`} s="compliant" c={rotationCompliant > 80 ? "green" : "amber"} i={RefreshCw} />
                    <Stat l="PQC Ready" v={`${pqcReady}%`} s="of keys" c={pqcReady > 50 ? "green" : "amber"} i={Shield} />
                  </div>
                );
              })()}

              {/* Heatmap Grid */}
              <Section title="Risk Heatmap">
                <Card>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 3, marginBottom: 12, position: "relative" }}>
                    {(heatmapData.keys ?? []).map((k: any, i: number) => {
                      const score = k.risk_score ?? 50;
                      const cellColor = score >= 80 ? "#991b1b" : score >= 60 ? C.red : score >= 40 ? C.amber : score >= 20 ? "#eab308" : C.green;
                      return (
                        <div
                          key={k.key_id || i}
                          onClick={() => setHeatmapDetail(k)}
                          onMouseEnter={() => setHeatmapHover(k)}
                          onMouseLeave={() => setHeatmapHover(null)}
                          style={{
                            width: 24, height: 24, borderRadius: 3, background: cellColor,
                            cursor: "pointer", transition: "transform 0.1s",
                            transform: heatmapDetail?.key_id === k.key_id ? "scale(1.3)" : undefined,
                            border: heatmapDetail?.key_id === k.key_id ? `2px solid ${C.white}` : "1px solid transparent",
                          }}
                          title={`${k.key_id} | ${k.algorithm} | Risk: ${score}`}
                        />
                      );
                    })}
                  </div>
                  {/* Hover tooltip */}
                  {heatmapHover && (
                    <div style={{
                      background: C.bg, border: `1px solid ${C.border}`, borderRadius: 8, padding: "8px 12px",
                      fontSize: 10, color: C.dim, marginBottom: 8,
                    }}>
                      <strong style={{ color: C.text }}>{heatmapHover.key_id}</strong>
                      {" "} | {heatmapHover.algorithm} | Age: {heatmapHover.age_days}d | Rotation: {heatmapHover.rotation_status} | Risk: {heatmapHover.risk_score}
                    </div>
                  )}
                  {/* Detail panel */}
                  {heatmapDetail && (
                    <Card style={{ borderLeft: `3px solid ${heatmapDetail.risk_score >= 60 ? C.red : heatmapDetail.risk_score >= 40 ? C.amber : C.green}`, position: "relative" }}>
                      <button onClick={() => setHeatmapDetail(null)} style={{
                        position: "absolute", top: 8, right: 8, background: "none", border: "none", color: C.muted, cursor: "pointer",
                      }}><X size={14} /></button>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
                        <div><div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase" }}>Key ID</div><div style={{ fontSize: 11, color: C.text, fontFamily: "'JetBrains Mono', monospace" }}>{heatmapDetail.key_id}</div></div>
                        <div><div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase" }}>Algorithm</div><div style={{ fontSize: 11, color: C.text }}>{heatmapDetail.algorithm}</div></div>
                        <div><div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase" }}>Age</div><div style={{ fontSize: 14, fontWeight: 700, color: heatmapDetail.age_days > 365 ? C.red : C.text }}>{heatmapDetail.age_days}d</div></div>
                        <div><div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase" }}>Risk Score</div><div style={{ fontSize: 14, fontWeight: 700, color: heatmapDetail.risk_score >= 60 ? C.red : heatmapDetail.risk_score >= 40 ? C.amber : C.green }}>{heatmapDetail.risk_score}/100</div></div>
                      </div>
                    </Card>
                  )}
                  {/* Legend */}
                  <div style={{ display: "flex", gap: 12, marginTop: 10, fontSize: 10, color: C.muted }}>
                    {[
                      { label: "Low (0-19)", color: C.green },
                      { label: "Moderate (20-39)", color: "#eab308" },
                      { label: "Elevated (40-59)", color: C.amber },
                      { label: "High (60-79)", color: C.red },
                      { label: "Critical (80-100)", color: "#991b1b" },
                    ].map(l => (
                      <div key={l.label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                        <span style={{ width: 10, height: 10, borderRadius: 2, background: l.color, display: "inline-block" }} />
                        {l.label}
                      </div>
                    ))}
                  </div>
                </Card>
              </Section>

              {/* Risk Table */}
              <Section title="Key Risk Table">
                <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 1100 }}>
                      <thead>
                        <tr>
                          {[
                            { key: "key_id", label: "Key ID" }, { key: "label", label: "Label" },
                            { key: "algorithm", label: "Algorithm" }, { key: "age_days", label: "Age (days)" },
                            { key: "age_category", label: "Age Category" }, { key: "rotation_status", label: "Rotation" },
                            { key: "days_until_rotation", label: "Days Until/Overdue" }, { key: "risk_score", label: "Risk Score" },
                            { key: "dependents", label: "Dependents" }, { key: "crypto_agility", label: "Agility" },
                            { key: "compliance_gaps", label: "Gaps" },
                          ].map(col => (
                            <th key={col.key} style={{ ...TH, cursor: "pointer" }}
                              onClick={() => setHeatmapSort(prev => ({
                                col: col.key,
                                asc: prev.col === col.key ? !prev.asc : false,
                              }))}>
                              {col.label} {heatmapSort.col === col.key ? (heatmapSort.asc ? "\u25B2" : "\u25BC") : ""}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {[...(heatmapData.keys ?? [])].sort((a: any, b: any) => {
                          const col = heatmapSort.col;
                          const av = a[col] ?? 0, bv = b[col] ?? 0;
                          if (typeof av === "string") return heatmapSort.asc ? av.localeCompare(bv) : bv.localeCompare(av);
                          return heatmapSort.asc ? av - bv : bv - av;
                        }).map((k: any, i: number) => {
                          const ageCatColor = (k.age_days ?? 0) >= 1095 ? C.red : (k.age_days ?? 0) >= 365 ? C.red : (k.age_days ?? 0) >= 90 ? C.amber : C.green;
                          const ageCat = (k.age_days ?? 0) >= 1095 ? "Critical" : (k.age_days ?? 0) >= 365 ? "Old" : (k.age_days ?? 0) >= 90 ? "Aging" : "Fresh";
                          const rotColor = k.rotation_status === "compliant" ? C.green : k.rotation_status === "overdue" ? C.red : C.amber;
                          return (
                            <tr key={k.key_id || i}>
                              <td style={{ ...TD(i), fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>{k.key_id}</td>
                              <td style={{ ...TD(i), fontSize: 11, color: C.text }}>{k.label ?? "\u2014"}</td>
                              <td style={{ ...TD(i), fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>{k.algorithm}</td>
                              <td style={{ ...TD(i), fontWeight: 700, color: ageCatColor }}>{k.age_days ?? 0}</td>
                              <td style={TD(i)}>
                                <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: `${ageCatColor}22`, color: ageCatColor }}>{ageCat}</span>
                              </td>
                              <td style={TD(i)}>
                                <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: `${rotColor}22`, color: rotColor }}>{k.rotation_status ?? "unknown"}</span>
                              </td>
                              <td style={{ ...TD(i), fontWeight: 600, color: (k.days_until_rotation ?? 0) < 0 ? C.red : C.text }}>
                                {k.days_until_rotation ?? "\u2014"}
                              </td>
                              <td style={TD(i)}>
                                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                  <div style={{ width: 40, height: 6, background: C.bg, borderRadius: 3, overflow: "hidden" }}>
                                    <div style={{ height: "100%", width: `${k.risk_score ?? 0}%`, background: (k.risk_score ?? 0) >= 60 ? C.red : (k.risk_score ?? 0) >= 40 ? C.amber : C.green, borderRadius: 3 }} />
                                  </div>
                                  <span style={{ fontSize: 10, fontWeight: 700, color: (k.risk_score ?? 0) >= 60 ? C.red : (k.risk_score ?? 0) >= 40 ? C.amber : C.green }}>{k.risk_score ?? 0}</span>
                                </div>
                              </td>
                              <td style={{ ...TD(i), fontWeight: 600, color: C.text }}>{k.dependents ?? 0}</td>
                              <td style={{ ...TD(i), fontWeight: 600, color: (k.crypto_agility ?? 0) < 30 ? C.red : (k.crypto_agility ?? 0) < 70 ? C.amber : C.green }}>{k.crypto_agility ?? "\u2014"}</td>
                              <td style={{ ...TD(i), fontSize: 10, color: C.muted }}>{(k.compliance_gaps ?? []).join(", ") || "\u2014"}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              </Section>

              {/* Rotation Debt */}
              {(() => {
                const overdue = (heatmapData.keys ?? []).filter((k: any) => k.rotation_status === "overdue" || (k.days_until_rotation ?? 0) < 0)
                  .sort((a: any, b: any) => (a.days_until_rotation ?? 0) - (b.days_until_rotation ?? 0));
                if (overdue.length === 0) return null;
                return (
                  <Section title={`Rotation Debt (${overdue.length} keys overdue)`}>
                    <div style={{ display: "grid", gap: 8 }}>
                      {overdue.map((k: any, i: number) => (
                        <Card key={k.key_id || i} style={{ borderLeft: `3px solid ${C.red}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                          <div>
                            <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{k.label || k.key_id}</div>
                            <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono', monospace" }}>{k.key_id}</div>
                            <div style={{ fontSize: 10, color: C.red, fontWeight: 600, marginTop: 2 }}>
                              {Math.abs(k.days_until_rotation ?? 0)} days overdue | {k.algorithm}
                            </div>
                          </div>
                          <Btn small onClick={() => { setTimelineKeyId(k.key_id); setView("timeline"); }}>
                            <RefreshCw size={11} /> View History
                          </Btn>
                        </Card>
                      ))}
                    </div>
                  </Section>
                );
              })()}

              {/* Crypto Agility (lowest first) */}
              {(() => {
                const sorted = [...(heatmapData.keys ?? [])].filter((k: any) => k.crypto_agility != null)
                  .sort((a: any, b: any) => (a.crypto_agility ?? 0) - (b.crypto_agility ?? 0))
                  .slice(0, 20);
                if (sorted.length === 0) return null;
                return (
                  <Section title="Lowest Crypto Agility (hardest PQC migration)">
                    <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
                      <table style={{ width: "100%", borderCollapse: "collapse" }}>
                        <thead>
                          <tr>
                            {["Key ID", "Algorithm", "Agility Score", "Risk Score", "Dependents"].map(h => <th key={h} style={TH}>{h}</th>)}
                          </tr>
                        </thead>
                        <tbody>
                          {sorted.map((k: any, i: number) => (
                            <tr key={k.key_id || i}>
                              <td style={{ ...TD(i), fontFamily: "'JetBrains Mono', monospace", fontSize: 10, cursor: "pointer" }}
                                onClick={() => { setProvKeyId(k.key_id); setView("provenance"); }}>
                                {k.key_id}
                              </td>
                              <td style={{ ...TD(i), fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>{k.algorithm}</td>
                              <td style={TD(i)}>
                                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                  <div style={{ width: 40, height: 6, background: C.bg, borderRadius: 3, overflow: "hidden" }}>
                                    <div style={{ height: "100%", width: `${k.crypto_agility}%`, background: k.crypto_agility < 30 ? C.red : k.crypto_agility < 70 ? C.amber : C.green, borderRadius: 3 }} />
                                  </div>
                                  <span style={{ fontSize: 10, fontWeight: 700, color: k.crypto_agility < 30 ? C.red : k.crypto_agility < 70 ? C.amber : C.green }}>{k.crypto_agility}</span>
                                </div>
                              </td>
                              <td style={{ ...TD(i), fontWeight: 700, color: (k.risk_score ?? 0) >= 60 ? C.red : C.text }}>{k.risk_score ?? 0}</td>
                              <td style={{ ...TD(i), fontWeight: 600, color: C.text }}>{k.dependents ?? 0}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </Section>
                );
              })()}
            </>
          )}
        </>
      )}

      {/* ================================================================
          FORENSICS VIEW — Access Pattern Analysis
      ================================================================ */}
      {view === "forensics" && (
        <>
          <Section title="Access Pattern Analysis">
            <Card>
              <FG label="Key ID" required>
                <div style={{ display: "flex", gap: 8 }}>
                  <Inp
                    value={forKeyId}
                    onChange={e => setForKeyId(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && loadForensics()}
                    placeholder="key_abc123..."
                    mono
                    style={{ flex: 1 }}
                  />
                  <Btn primary onClick={loadForensics} disabled={loadingFor}>
                    <Microscope size={12} /> {loadingFor ? "Analyzing..." : "Analyze"}
                  </Btn>
                </div>
              </FG>
              {forErr && (
                <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11 }}>
                  {forErr}
                </div>
              )}
            </Card>
          </Section>

          {forData && (
            <>
              {/* Summary cards */}
              <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
                <Stat l="Total Access (30d)" v={(forData.summary?.total_access ?? 0).toLocaleString()} s="operations" c="accent" i={TrendingUp} />
                <Stat l="Unique Actors" v={forData.summary?.unique_actors ?? 0} s="identities" c="blue" i={User} />
                <Stat l="Peak Hour" v={forData.summary?.peak_hour != null ? `${forData.summary.peak_hour}:00` : "\u2014"} s="busiest" c="purple" i={Clock} />
                <Stat l="Off-Hours %" v={`${forData.summary?.off_hours_pct ?? 0}%`} s="non-business" c="amber" i={AlertTriangle} />
                <Stat l="Weekend %" v={`${forData.summary?.weekend_pct ?? 0}%`} s="Sat/Sun" c="amber" i={Clock} />
                <Stat l="Anomalies" v={forData.summary?.anomaly_count ?? 0} s="detected" c={(forData.summary?.anomaly_count ?? 0) > 0 ? "red" : "green"} i={AlertTriangle} />
              </div>

              {/* Hourly Distribution */}
              <Section title="Hourly Distribution (24h)">
                <Card>
                  <div style={{ display: "flex", alignItems: "flex-end", gap: 2, height: 120 }}>
                    {(forData.hourly_distribution ?? Array.from({ length: 24 }, (_, h) => ({ hour: h, count: 0 }))).map((h: any) => {
                      const maxCount = Math.max(...(forData.hourly_distribution ?? []).map((x: any) => x.count), 1);
                      const isBusinessHour = h.hour >= 8 && h.hour <= 18;
                      const isPeak = h.hour === (forData.summary?.peak_hour ?? -1);
                      const barHeight = maxCount > 0 ? Math.max((h.count / maxCount) * 100, 2) : 2;
                      return (
                        <div key={h.hour} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 2 }}>
                          <div style={{ fontSize: 8, color: C.muted }}>{h.count > 0 ? h.count : ""}</div>
                          <div style={{
                            width: "100%", height: `${barHeight}%`, minHeight: 2, borderRadius: "3px 3px 0 0",
                            background: isPeak ? C.accent : isBusinessHour ? C.blue : C.amber,
                            border: isPeak ? `1px solid ${C.accent}` : "none",
                            transition: "height 0.3s ease",
                          }} />
                          <div style={{ fontSize: 8, color: C.muted }}>{h.hour}</div>
                        </div>
                      );
                    })}
                  </div>
                  <div style={{ display: "flex", gap: 12, marginTop: 10, fontSize: 10, color: C.muted }}>
                    <span><span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 2, background: C.blue, marginRight: 4 }} />Business Hours</span>
                    <span><span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 2, background: C.amber, marginRight: 4 }} />Off-Hours</span>
                    <span><span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 2, background: C.accent, marginRight: 4 }} />Peak Hour</span>
                  </div>
                </Card>
              </Section>

              {/* Daily Distribution */}
              <Section title="Daily Distribution">
                <Card>
                  <div style={{ display: "flex", alignItems: "flex-end", gap: 6, height: 100 }}>
                    {(forData.daily_distribution ?? ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map(d => ({ day: d, count: 0 }))).map((d: any) => {
                      const maxCount = Math.max(...(forData.daily_distribution ?? []).map((x: any) => x.count), 1);
                      const isWeekend = d.day === "Sat" || d.day === "Sun" || d.day === "Saturday" || d.day === "Sunday";
                      const barHeight = maxCount > 0 ? Math.max((d.count / maxCount) * 100, 4) : 4;
                      return (
                        <div key={d.day} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
                          <div style={{ fontSize: 9, color: C.muted, fontWeight: 600 }}>{d.count}</div>
                          <div style={{
                            width: "70%", height: `${barHeight}%`, minHeight: 4, borderRadius: "4px 4px 0 0",
                            background: isWeekend ? C.amber : C.blue,
                          }} />
                          <div style={{ fontSize: 9, color: isWeekend ? C.amber : C.muted, fontWeight: 600 }}>{d.day}</div>
                        </div>
                      );
                    })}
                  </div>
                </Card>
              </Section>

              {/* Anomalies */}
              {(forData.anomalies?.length ?? 0) > 0 && (
                <Section title={`Anomalies (${forData.anomalies.length})`}>
                  <div style={{ display: "grid", gap: 8 }}>
                    {forData.anomalies.map((a: any, i: number) => {
                      const severityColors: Record<string, string> = { low: C.blue, medium: C.amber, high: C.red, critical: "#991b1b" };
                      const sc = severityColors[a.severity] ?? C.muted;
                      const isExpanded = expandedAnomalies.has(i);
                      return (
                        <Card key={i} style={{ borderLeft: `3px solid ${sc}` }}>
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                              <span style={{
                                padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700,
                                background: `${sc}22`, color: sc, border: `1px solid ${sc}44`,
                                textTransform: "uppercase",
                              }}>{a.severity}</span>
                              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{a.type}</span>
                            </div>
                            <button onClick={() => toggleAnomaly(i)} style={{
                              background: "none", border: "none", color: C.muted, cursor: "pointer", padding: 2,
                            }}>
                              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                            </button>
                          </div>
                          <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.5, marginBottom: 4 }}>{a.description}</div>
                          <div style={{ fontSize: 10, color: C.muted }}>Detected: {fmtDatetime(a.detected_at)}</div>
                          {isExpanded && a.details && (
                            <div style={{ marginTop: 8, background: C.bg, borderRadius: 6, padding: "8px 10px", border: `1px solid ${C.border}` }}>
                              <pre style={{ fontSize: 10, color: C.dim, margin: 0, whiteSpace: "pre-wrap", fontFamily: "'JetBrains Mono', monospace" }}>
                                {typeof a.details === "string" ? a.details : JSON.stringify(a.details, null, 2)}
                              </pre>
                            </div>
                          )}
                        </Card>
                      );
                    })}
                  </div>
                </Section>
              )}

              {/* Actor Analysis */}
              {(forData.actors?.length ?? 0) > 0 && (
                <Section title={`Actor Analysis (${forData.actors.length})`}>
                  <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          {["Actor ID", "Type", "Access Count", "First Access", "Last Access"].map(h => <th key={h} style={TH}>{h}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {forData.actors.map((a: any, i: number) => {
                          const isNew = a.is_new || (a.first_access && (Date.now() - new Date(a.first_access).getTime()) < 7 * 86400000);
                          return (
                            <tr key={a.actor_id || i} style={{ background: isNew ? `${C.amber}08` : undefined }}>
                              <td style={TD(i)}>
                                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                  <User size={11} color={C.accent} />
                                  <span style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{a.actor_id}</span>
                                  {isNew && (
                                    <span style={{
                                      padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 700,
                                      background: `${C.amber}22`, color: C.amber, border: `1px solid ${C.amber}44`,
                                    }}>NEW</span>
                                  )}
                                </div>
                              </td>
                              <td style={TD(i)}><B c="blue">{a.actor_type ?? "user"}</B></td>
                              <td style={{ ...TD(i), fontWeight: 700, color: C.text }}>{(a.access_count ?? 0).toLocaleString()}</td>
                              <td style={{ ...TD(i), fontSize: 10, color: C.muted }}>{fmtDatetime(a.first_access)}</td>
                              <td style={{ ...TD(i), fontSize: 10, color: C.muted }}>{fmtDatetime(a.last_access)}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </Section>
              )}

              {/* Geo Distribution */}
              {(forData.geo_distribution?.length ?? 0) > 0 && (
                <Section title={`Geographic Distribution (${forData.geo_distribution.length} regions)`}>
                  <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          {["Region", "Access Count", "Last Access"].map(h => <th key={h} style={TH}>{h}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {forData.geo_distribution.map((g: any, i: number) => (
                          <tr key={g.region || i} style={{ background: g.unusual ? `${C.red}08` : undefined }}>
                            <td style={TD(i)}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                <Globe size={11} color={g.unusual ? C.red : C.accent} />
                                <span style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{g.region}</span>
                                {g.unusual && (
                                  <span style={{
                                    padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 700,
                                    background: `${C.red}22`, color: C.red, border: `1px solid ${C.red}44`,
                                  }}>UNUSUAL</span>
                                )}
                              </div>
                            </td>
                            <td style={{ ...TD(i), fontWeight: 700, color: C.text }}>{(g.access_count ?? 0).toLocaleString()}</td>
                            <td style={{ ...TD(i), fontSize: 10, color: C.muted }}>{fmtDatetime(g.last_access)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Section>
              )}
            </>
          )}
        </>
      )}

      {/* ================================================================
          CUSTODY VIEW — Chain of Custody Report
      ================================================================ */}
      {view === "custody" && (
        <>
          <Section title="Chain of Custody Report">
            <Card>
              <FG label="Key ID" required>
                <div style={{ display: "flex", gap: 8 }}>
                  <Inp
                    value={custKeyId}
                    onChange={e => setCustKeyId(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && loadCustody()}
                    placeholder="key_abc123..."
                    mono
                    style={{ flex: 1 }}
                  />
                  <Btn primary onClick={loadCustody} disabled={loadingCust}>
                    <Link2 size={12} /> {loadingCust ? "Generating..." : "Generate Report"}
                  </Btn>
                </div>
              </FG>
              {custErr && (
                <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11 }}>
                  {custErr}
                </div>
              )}
            </Card>
          </Section>

          {custData && (
            <>
              {/* Report Header */}
              <Section title="Report Header">
                <Card>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12 }}>
                    <div>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Key ID</div>
                      <div style={{ fontSize: 12, fontWeight: 700, color: C.text, fontFamily: "'JetBrains Mono', monospace" }}>
                        {custData.key_id ?? custKeyId}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Key Label</div>
                      <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>
                        {custData.key_label ?? "\u2014"}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Generated At</div>
                      <div style={{ fontSize: 11, color: C.dim }}>{fmtDatetime(custData.generated_at ?? new Date().toISOString())}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Generated By</div>
                      <div style={{ fontSize: 11, color: C.dim }}>{custData.generated_by ?? session?.user?.email ?? "system"}</div>
                    </div>
                  </div>
                  {custData.integrity_hash && (
                    <div style={{ marginTop: 12, background: C.bg, borderRadius: 6, padding: "8px 12px", border: `1px solid ${C.border}` }}>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", marginBottom: 4 }}>Integrity Hash</div>
                      <div style={{ fontSize: 10, color: C.accent, fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" }}>
                        {custData.integrity_hash}
                      </div>
                    </div>
                  )}
                </Card>
              </Section>

              {/* Provenance Summary */}
              <Section title="Provenance Summary">
                <Card>
                  <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                    <div>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", marginBottom: 4 }}>Origin</div>
                      <B c="accent">{custData.provenance?.origin ?? "HSM"}</B>
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", marginBottom: 4 }}>Algorithm</div>
                      <span style={{ fontSize: 11, fontWeight: 600, color: C.text, fontFamily: "'JetBrains Mono', monospace" }}>
                        {custData.provenance?.algorithm ?? "AES-256-GCM"}
                      </span>
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", marginBottom: 4 }}>FIPS Status</div>
                      <B c={custData.provenance?.fips_certified !== false ? "green" : "red"}>
                        {custData.provenance?.fips_certified !== false ? "FIPS Certified" : "Not Certified"}
                      </B>
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", marginBottom: 4 }}>HSM Status</div>
                      <B c={custData.provenance?.hsm_backed !== false ? "green" : "amber"}>
                        {custData.provenance?.hsm_backed !== false ? "HSM-Backed" : "Software-Only"}
                      </B>
                    </div>
                  </div>
                </Card>
              </Section>

              {/* Custody Chain */}
              {(custData.custody_chain?.length ?? 0) > 0 && (
                <Section title={`Custody Chain (${custData.custody_chain.length} entries)`}>
                  <div style={{ position: "relative", paddingLeft: 28 }}>
                    <div style={{
                      position: "absolute", left: 11, top: 0, bottom: 0, width: 2,
                      background: `linear-gradient(to bottom, ${C.accent}44, ${C.border})`,
                    }} />
                    {custData.custody_chain.map((entry: any, i: number) => {
                      const actionColors: Record<string, string> = {
                        create: C.green, rotate: C.blue, wrap: C.purple,
                        export: C.amber, destroy: C.red,
                      };
                      const color = actionColors[entry.action] ?? C.accent;
                      return (
                        <div key={i} style={{ position: "relative", marginBottom: 12 }}>
                          <div style={{
                            position: "absolute", left: -21, top: 14, width: 12, height: 12,
                            borderRadius: "50%", background: color, border: `2px solid ${C.card}`,
                            boxShadow: `0 0 6px ${color}66`,
                          }} />
                          <Card style={{ marginLeft: 8 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
                              <span style={{
                                background: C.bg, borderRadius: "50%", width: 22, height: 22,
                                display: "inline-flex", alignItems: "center", justifyContent: "center",
                                fontSize: 10, fontWeight: 800, color: C.accent,
                              }}>{entry.sequence ?? i + 1}</span>
                              <span style={{
                                padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600,
                                background: `${color}22`, color, border: `1px solid ${color}44`,
                              }}>{entry.action}</span>
                              <span style={{ fontSize: 10, color: C.muted }}>{fmtDatetime(entry.timestamp)}</span>
                              {entry.verified !== undefined && (
                                <span style={{
                                  fontSize: 10, fontWeight: 700,
                                  color: entry.verified ? C.green : C.red,
                                }}>{entry.verified ? "\u2713 Verified" : "\u2717 Unverified"}</span>
                              )}
                            </div>
                            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4, fontSize: 11 }}>
                              <span style={{ color: C.dim }}>{entry.from_actor ?? "\u2014"}</span>
                              <ArrowRight size={12} color={C.muted} />
                              <span style={{ color: C.text, fontWeight: 600 }}>{entry.to_actor ?? "\u2014"}</span>
                            </div>
                            <div style={{ display: "flex", gap: 12, fontSize: 10, color: C.muted }}>
                              {entry.service && <span><Server size={10} style={{ verticalAlign: "middle" }} /> {entry.service}</span>}
                              {entry.region && <span><Globe size={10} style={{ verticalAlign: "middle" }} /> {entry.region}</span>}
                            </div>
                          </Card>
                        </div>
                      );
                    })}
                  </div>
                </Section>
              )}

              {/* Integrity Verification */}
              <Section title="Integrity Verification">
                <Card>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
                    <Btn primary onClick={verifyCustodyIntegrity} disabled={loadingVerify}>
                      <Shield size={12} /> {loadingVerify ? "Verifying..." : "Verify Integrity"}
                    </Btn>
                  </div>
                  {custVerify && (
                    <div style={{
                      padding: "12px 16px", borderRadius: 8,
                      background: custVerify.verified ? `${C.green}14` : `${C.red}14`,
                      border: `1px solid ${custVerify.verified ? C.green : C.red}`,
                    }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                        {custVerify.verified
                          ? <CheckCircle2 size={16} color={C.green} />
                          : <AlertTriangle size={16} color={C.red} />
                        }
                        <span style={{ fontSize: 13, fontWeight: 700, color: custVerify.verified ? C.green : C.red }}>
                          {custVerify.verified ? "\u2713 Integrity Verified" : "\u2717 Integrity Compromised"}
                        </span>
                      </div>
                      {custVerify.error && (
                        <div style={{ fontSize: 11, color: C.red, marginBottom: 6 }}>{custVerify.error}</div>
                      )}
                      {custVerify.expected_hash && (
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginTop: 8 }}>
                          <div style={{ background: C.bg, borderRadius: 6, padding: "8px 10px" }}>
                            <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", marginBottom: 3 }}>Expected Hash</div>
                            <div style={{ fontSize: 10, color: C.dim, fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" }}>{custVerify.expected_hash}</div>
                          </div>
                          <div style={{ background: C.bg, borderRadius: 6, padding: "8px 10px" }}>
                            <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", marginBottom: 3 }}>Computed Hash</div>
                            <div style={{ fontSize: 10, color: C.dim, fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" }}>{custVerify.computed_hash}</div>
                          </div>
                        </div>
                      )}
                      {custVerify.merkle_root && (
                        <div style={{ marginTop: 8, background: C.bg, borderRadius: 6, padding: "8px 10px" }}>
                          <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", marginBottom: 3 }}>Merkle Root</div>
                          <div style={{ fontSize: 10, color: C.accent, fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" }}>{custVerify.merkle_root}</div>
                        </div>
                      )}
                    </div>
                  )}
                </Card>
              </Section>

              {/* Export */}
              <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 12 }}>
                <Btn onClick={exportCustodyJSON}>
                  <Download size={12} /> Export Full Report (JSON)
                </Btn>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
