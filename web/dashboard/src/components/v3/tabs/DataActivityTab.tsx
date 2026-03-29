// @ts-nocheck
import { useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Database,
  Plus,
  RefreshCw,
  Server,
  User,
} from "lucide-react";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import {
  B,
  Bar,
  Btn,
  Card,
  FG,
  Inp,
  Row2,
  Section,
  Sel,
  Stat,
  Txt,
} from "../legacyPrimitives";
import {
  getActivityStats,
  listActivityActors,
  listActivityEvents,
  listActivitySources,
  ingestActivityEvent,
} from "../../../lib/dam";

type Props = { session: any };
type View = "monitor" | "actors" | "sources" | "ingest";

// ── constants ──────────────────────────────────────────────────────

const RISK_BADGE_COLOR: Record<string, string> = {
  critical: "red",
  high: "orange",
  medium: "amber",
  low: "green",
};

const RISK_COLOR: Record<string, string> = {
  critical: C.red,
  high: C.orange,
  medium: C.amber,
  low: C.green,
};

const EVENT_TYPE_OPTIONS = [
  "read", "write", "delete", "query", "export", "import", "encrypt", "decrypt", "access_denied",
];

const ACTOR_TYPE_OPTIONS = ["user", "service", "automation", "system"];
const SOURCE_TYPE_OPTIONS = ["database", "api", "file", "stream", "app"];
const RISK_LEVEL_OPTIONS = ["low", "medium", "high", "critical"];

const EMPTY_INGEST = {
  event_type: "read",
  source_id: "", source_type: "database",
  actor_id: "", actor_type: "user",
  risk_level: "low",
  data_labels: "",
  metadata: "",
};

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

function riskLabel(score: number): string {
  if (score >= 4) return "critical";
  if (score >= 3) return "high";
  if (score >= 2) return "medium";
  return "low";
}

// ── component ──────────────────────────────────────────────────────

export function DataActivityTab({ session }: Props) {
  const [view, setView] = useState<View>("monitor");
  const [stats, setStats] = useState<any | null>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [actors, setActors] = useState<any[]>([]);
  const [sources, setSources] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  // Monitor filters
  const [filterType, setFilterType] = useState("");
  const [filterRisk, setFilterRisk] = useState("");
  const [filterSince, setFilterSince] = useState("");

  // Ingest form
  const [ingestForm, setIngestForm] = useState({ ...EMPTY_INGEST });
  const [ingestBusy, setIngestBusy] = useState(false);
  const [ingestErr, setIngestErr] = useState("");
  const [ingestSuccess, setIngestSuccess] = useState(false);

  // Auto-refresh ref
  const refreshRef = useRef<ReturnType<typeof setInterval> | null>(null);

  async function load(silent = false) {
    if (!silent) setLoading(true);
    setErr("");
    try {
      const [st, ev, ac, so] = await Promise.all([
        getActivityStats(session),
        listActivityEvents(session, { limit: 100 }),
        listActivityActors(session),
        listActivitySources(session),
      ]);
      setStats(st);
      setEvents(ev ?? []);
      setActors(ac ?? []);
      setSources(so ?? []);
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      if (!silent) setLoading(false);
    }
  }

  useEffect(() => {
    void load();
    // Auto-refresh every 5s on monitor view
    refreshRef.current = setInterval(() => {
      void load(true);
    }, 5000);
    return () => { if (refreshRef.current) clearInterval(refreshRef.current); };
  }, []);

  async function doIngest() {
    setIngestErr(""); setIngestSuccess(false);
    if (!ingestForm.source_id.trim()) { setIngestErr("Source ID is required."); return; }
    if (!ingestForm.actor_id.trim()) { setIngestErr("Actor ID is required."); return; }
    setIngestBusy(true);
    try {
      let metadata: any = undefined;
      if (ingestForm.metadata.trim()) {
        try { metadata = JSON.parse(ingestForm.metadata); } catch { setIngestErr("Metadata must be valid JSON."); setIngestBusy(false); return; }
      }
      const payload = {
        tenant_id: session.tenantId,
        event_type: ingestForm.event_type,
        source_id: ingestForm.source_id.trim(),
        source_type: ingestForm.source_type,
        actor_id: ingestForm.actor_id.trim(),
        actor_type: ingestForm.actor_type,
        risk_level: ingestForm.risk_level,
        data_labels: ingestForm.data_labels.trim()
          ? ingestForm.data_labels.split(",").map(s => s.trim()).filter(Boolean)
          : [],
        metadata,
      };
      await ingestActivityEvent(session, payload);
      setIngestSuccess(true);
      setIngestForm({ ...EMPTY_INGEST });
      void load(true);
    } catch (e) {
      setIngestErr(errMsg(e));
    } finally {
      setIngestBusy(false);
    }
  }

  // ── derived ─────────────────────────────────────────────────────

  const filteredEvents = events.filter(e => {
    if (filterRisk && e.risk_level !== filterRisk) return false;
    if (filterType && e.event_type !== filterType) return false;
    if (filterSince) {
      const since = new Date(filterSince);
      if (!isNaN(since.getTime()) && new Date(e.occurred_at) < since) return false;
    }
    return true;
  });

  const eventTypes = [...new Set(events.map(e => e.event_type))].sort();
  const criticalEvents = events.filter(e => e.risk_level === "critical" || !e.allowed).length;

  const VIEWS = ["monitor", "actors", "sources", "ingest"];
  const VIEW_LABELS = ["Monitor", `Actors (${actors.length})`, `Sources (${sources.length})`, "Ingest"];

  return (
    <div style={{ padding: 24, fontFamily: '"IBM Plex Sans", sans-serif', color: C.text, minHeight: "100%" }}>

      {/* ── Header ── */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            <Activity size={18} color={C.accent} strokeWidth={2} />
            <span style={{ fontSize: 16, fontWeight: 700, color: C.text, letterSpacing: -0.3 }}>Data Activity Monitor</span>
            <B c="green" pulse>Real-time</B>
          </div>
          <div style={{ fontSize: 11, color: C.muted }}>Track and audit data access events across all sources and actors · auto-refreshes every 5s</div>
        </div>
        <Btn small onClick={() => void load()} disabled={loading}>
          <RefreshCw size={11} /> Refresh
        </Btn>
      </div>

      {/* ── Error banner ── */}
      {err && (
        <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 11, marginBottom: 14, display: "flex", alignItems: "center", gap: 8 }}>
          <AlertTriangle size={13} /> {err}
        </div>
      )}

      {/* ── Stats row ── */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
        <Stat l="Total Events" v={loading ? "—" : (stats?.total_events ?? events.length).toLocaleString()} s="all-time records" c="accent" i={Activity} />
        <Stat l="Critical Events" v={loading ? "—" : String(criticalEvents)} s="high-risk or denied" c={criticalEvents > 0 ? "red" : "green"} i={AlertTriangle} />
        <Stat l="Actors" v={loading ? "—" : String(stats?.unique_actors ?? actors.length)} s="distinct identities" c="blue" i={User} />
        <Stat l="Sources" v={loading ? "—" : String(sources.length)} s="data sources tracked" c="teal" i={Server} />
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
          MONITOR
      ════════════════════════════════════════════════════════════ */}
      {view === "monitor" && (
        <>
          {/* Filters */}
          <div style={{ display: "flex", gap: 10, alignItems: "flex-end", marginBottom: 14, flexWrap: "wrap" }}>
            <div style={{ width: 180 }}>
              <div style={{ fontSize: 10, color: C.muted, marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.6 }}>Event Type</div>
              <Sel value={filterType} onChange={e => setFilterType(e.target.value)}>
                <option value="">All Types</option>
                {eventTypes.map(t => <option key={t} value={t}>{t}</option>)}
              </Sel>
            </div>
            <div style={{ width: 170 }}>
              <div style={{ fontSize: 10, color: C.muted, marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.6 }}>Risk Level</div>
              <Sel value={filterRisk} onChange={e => setFilterRisk(e.target.value)}>
                <option value="">All Levels</option>
                {["critical", "high", "medium", "low"].map(r => <option key={r} value={r}>{r}</option>)}
              </Sel>
            </div>
            <div style={{ flex: 1, minWidth: 200 }}>
              <div style={{ fontSize: 10, color: C.muted, marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.6 }}>Since</div>
              <Inp
                type="datetime-local"
                value={filterSince}
                onChange={e => setFilterSince(e.target.value)}
              />
            </div>
          </div>

          <Section title={`Live Activity Feed (${filteredEvents.length} events)`} actions={
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ width: 6, height: 6, borderRadius: 3, background: C.green, animation: "pulse 2s infinite" }} />
              <span style={{ fontSize: 10, color: C.green }}>Live</span>
            </div>
          }>
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {loading && events.length === 0 ? (
                <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>Loading events…</div>
              ) : filteredEvents.length === 0 ? (
                <div style={{ padding: "36px 20px", textAlign: "center" }}>
                  <Activity size={26} color={C.border} style={{ marginBottom: 8 }} />
                  <div style={{ color: C.muted, fontSize: 11 }}>No events match the current filters.</div>
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Timestamp", "Event Type", "Source", "Actor", "Data Labels", "Risk"].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEvents.slice(0, 100).map((ev, i) => (
                      <tr key={ev.id || i}
                        onMouseEnter={e => e.currentTarget.style.filter = "brightness(1.07)"}
                        onMouseLeave={e => e.currentTarget.style.filter = ""}>
                        <td style={{ ...TD(i), whiteSpace: "nowrap", fontSize: 10 }}>{fmtDatetime(ev.occurred_at)}</td>
                        <td style={TD(i)}><B c="accent">{ev.event_type}</B></td>
                        <td style={TD(i)}>
                          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                            <Database size={10} color={C.muted} />
                            <span style={{ fontSize: 11, color: C.text }}>{ev.source}</span>
                          </div>
                        </td>
                        <td style={TD(i)}>
                          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                            <User size={10} color={C.muted} />
                            <span style={{ fontSize: 11, color: C.dim }}>{ev.actor}</span>
                          </div>
                        </td>
                        <td style={TD(i)}>
                          <div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
                            {(ev.data_labels ?? []).slice(0, 3).map((lbl: string, j: number) => (
                              <B key={j} c="purple">{lbl}</B>
                            ))}
                            {(ev.data_labels ?? []).length === 0 && <span style={{ color: C.muted, fontSize: 10 }}>—</span>}
                          </div>
                        </td>
                        <td style={TD(i)}>
                          <B c={RISK_BADGE_COLOR[ev.risk_level] ?? "blue"}>{ev.risk_level}</B>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Section>
        </>
      )}

      {/* ════════════════════════════════════════════════════════════
          ACTORS
      ════════════════════════════════════════════════════════════ */}
      {view === "actors" && (
        <Section title="Top Actors by Risk">
          <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
            {loading && actors.length === 0 ? (
              <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>Loading actors…</div>
            ) : actors.length === 0 ? (
              <div style={{ padding: "36px 20px", textAlign: "center" }}>
                <User size={26} color={C.border} style={{ marginBottom: 8 }} />
                <div style={{ color: C.muted, fontSize: 11 }}>No actors observed yet.</div>
              </div>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {["Actor ID", "Actor Type", "Event Count", "Denied", "Risk Level", "Last Seen"].map(h => <th key={h} style={TH}>{h}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {actors
                    .slice()
                    .sort((a, b) => (b.denied_count ?? 0) - (a.denied_count ?? 0))
                    .map((a, i) => {
                      const rl = a.denied_count > 5 ? "critical" : a.denied_count > 2 ? "high" : a.denied_count > 0 ? "medium" : "low";
                      return (
                        <tr key={a.actor || i}
                          onMouseEnter={e => e.currentTarget.style.filter = "brightness(1.07)"}
                          onMouseLeave={e => e.currentTarget.style.filter = ""}>
                          <td style={{ ...TD(i), color: C.text, fontWeight: 600 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                              <User size={12} color={C.muted} />
                              {a.actor}
                            </div>
                          </td>
                          <td style={TD(i)}><B c="blue">{a.actor_type ?? "user"}</B></td>
                          <td style={{ ...TD(i), color: C.text, fontWeight: 700 }}>{(a.event_count ?? 0).toLocaleString()}</td>
                          <td style={{ ...TD(i), color: a.denied_count > 0 ? C.red : C.green, fontWeight: 700 }}>
                            {a.denied_count > 0 ? a.denied_count : <span style={{ color: C.green }}>0</span>}
                          </td>
                          <td style={TD(i)}><B c={RISK_BADGE_COLOR[rl] ?? "blue"}>{rl}</B></td>
                          <td style={{ ...TD(i), fontSize: 10 }}>{fmtDatetime(a.last_seen)}</td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            )}
          </div>
        </Section>
      )}

      {/* ════════════════════════════════════════════════════════════
          SOURCES
      ════════════════════════════════════════════════════════════ */}
      {view === "sources" && (
        <Section title="Data Sources Overview">
          {loading && sources.length === 0 ? (
            <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>Loading sources…</div>
          ) : sources.length === 0 ? (
            <Card>
              <div style={{ padding: "24px 0", textAlign: "center" }}>
                <Server size={26} color={C.border} style={{ marginBottom: 8 }} />
                <div style={{ color: C.muted, fontSize: 11 }}>No sources observed yet.</div>
              </div>
            </Card>
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              {sources.map((s, i) => {
                const rl = riskLabel(s.risk_score ?? 0);
                const pct = Math.min(100, ((s.risk_score ?? 0) / 4) * 100);
                return (
                  <Card key={s.source || i}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <Server size={14} color={C.muted} />
                        <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{s.source}</span>
                      </div>
                      <B c={RISK_BADGE_COLOR[rl] ?? "blue"}>{rl}</B>
                    </div>
                    <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, marginBottom: 2 }}>Events</div>
                        <div style={{ fontSize: 16, fontWeight: 700, color: C.text }}>{(s.event_count ?? 0).toLocaleString()}</div>
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, marginBottom: 2 }}>Last Seen</div>
                        <div style={{ fontSize: 10, color: C.dim }}>{fmtDatetime(s.last_seen)}</div>
                      </div>
                    </div>
                    <div style={{ fontSize: 9, color: C.muted, marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.6 }}>
                      Risk Score — {(s.risk_score ?? 0).toFixed(1)} / 4
                    </div>
                    <Bar pct={pct} color={RISK_COLOR[rl] ?? C.accent} />
                  </Card>
                );
              })}
            </div>
          )}
        </Section>
      )}

      {/* ════════════════════════════════════════════════════════════
          INGEST
      ════════════════════════════════════════════════════════════ */}
      {view === "ingest" && (
        <Section title="Manual Event Ingest">
          <Card style={{ maxWidth: 700 }}>
            {ingestSuccess && (
              <div style={{ display: "flex", alignItems: "center", gap: 8, background: C.greenDim, border: `1px solid ${C.green}`, borderRadius: 8, padding: "10px 14px", marginBottom: 16, color: C.green, fontSize: 11 }}>
                <Activity size={14} /> Event ingested successfully.
              </div>
            )}

            <Row2>
              <FG label="Event Type" required>
                <Sel value={ingestForm.event_type} onChange={e => setIngestForm(f => ({ ...f, event_type: e.target.value }))}>
                  {EVENT_TYPE_OPTIONS.map(t => <option key={t} value={t}>{t}</option>)}
                </Sel>
              </FG>
              <FG label="Risk Level">
                <Sel value={ingestForm.risk_level} onChange={e => setIngestForm(f => ({ ...f, risk_level: e.target.value }))}>
                  {RISK_LEVEL_OPTIONS.map(r => <option key={r} value={r}>{r}</option>)}
                </Sel>
              </FG>
            </Row2>

            <Row2>
              <FG label="Source ID" required>
                <Inp
                  value={ingestForm.source_id}
                  onChange={e => setIngestForm(f => ({ ...f, source_id: e.target.value }))}
                  placeholder="db-prod-1"
                  mono
                />
              </FG>
              <FG label="Source Type">
                <Sel value={ingestForm.source_type} onChange={e => setIngestForm(f => ({ ...f, source_type: e.target.value }))}>
                  {SOURCE_TYPE_OPTIONS.map(t => <option key={t} value={t}>{t}</option>)}
                </Sel>
              </FG>
            </Row2>

            <Row2>
              <FG label="Actor ID" required>
                <Inp
                  value={ingestForm.actor_id}
                  onChange={e => setIngestForm(f => ({ ...f, actor_id: e.target.value }))}
                  placeholder="user@example.com"
                  mono
                />
              </FG>
              <FG label="Actor Type">
                <Sel value={ingestForm.actor_type} onChange={e => setIngestForm(f => ({ ...f, actor_type: e.target.value }))}>
                  {ACTOR_TYPE_OPTIONS.map(t => <option key={t} value={t}>{t}</option>)}
                </Sel>
              </FG>
            </Row2>

            <FG label="Data Labels" hint="Comma-separated, e.g. PII, HIPAA, PCI">
              <Inp
                value={ingestForm.data_labels}
                onChange={e => setIngestForm(f => ({ ...f, data_labels: e.target.value }))}
                placeholder="PII, HIPAA, PCI"
              />
            </FG>

            <FG label="Metadata (JSON)" hint="Optional structured metadata for this event">
              <Txt
                rows={4}
                value={ingestForm.metadata}
                onChange={e => setIngestForm(f => ({ ...f, metadata: e.target.value }))}
                placeholder='{"query": "SELECT * FROM users", "ip": "10.0.0.1"}'
              />
            </FG>

            {ingestErr && (
              <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11, marginBottom: 12 }}>
                {ingestErr}
              </div>
            )}

            <div style={{ display: "flex", gap: 8 }}>
              <Btn primary onClick={doIngest} disabled={ingestBusy}>
                <Plus size={12} /> {ingestBusy ? "Ingesting…" : "Ingest Event"}
              </Btn>
              <Btn onClick={() => { setIngestForm({ ...EMPTY_INGEST }); setIngestErr(""); setIngestSuccess(false); }}>
                Reset
              </Btn>
            </div>
          </Card>
        </Section>
      )}
    </div>
  );
}
