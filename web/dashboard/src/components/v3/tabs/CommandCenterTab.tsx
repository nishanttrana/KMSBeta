import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  Atom,
  CheckCircle2,
  ChevronDown,
  CircleDashed,
  FileCheck2,
  KeyRound,
  LifeBuoy,
  RefreshCw,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import { loadPlatformSnapshot } from "../../../lib/platformSnapshot";
import {
  evaluate,
  isQuantumVulnerable,
  algoStrength,
  postureScore,
  SEVERITY_ORDER,
  type ControlCheck,
  type PlatformSnapshot,
  type RecCategory,
  type Recommendation,
  type Severity,
} from "../../../lib/recommendations";
import { isFipsModeEnabled } from "../runtimeUtils";
import { C } from "../theme";

type Props = {
  session: AuthSession | null;
  fipsMode?: string;
  onNavigate?: (tabId: string) => void;
};

const SEV_COLOR: Record<Severity, { fg: string; bg: string; label: string }> = {
  critical: { fg: C.redFg, bg: C.redDim, label: "Critical" },
  high: { fg: C.orangeFg, bg: C.orangeDim, label: "High" },
  medium: { fg: C.amberFg, bg: C.amberDim, label: "Medium" },
  low: { fg: C.blueFg, bg: C.blueDim, label: "Low" },
};

const SNOOZE_DAYS = 30;

// ── Per-viewer snooze state (browser-local convenience only) ─────────────
function snoozeKey(tenant: string) {
  return `vecta.recs.snoozed.${tenant || "default"}`;
}
function readSnoozed(tenant: string): Record<string, number> {
  try {
    const raw = JSON.parse(window.localStorage.getItem(snoozeKey(tenant)) || "{}");
    const now = Date.now();
    return Object.fromEntries(Object.entries(raw).filter(([, until]) => Number(until) > now)) as Record<string, number>;
  } catch {
    return {};
  }
}
function writeSnoozed(tenant: string, v: Record<string, number>) {
  try {
    window.localStorage.setItem(snoozeKey(tenant), JSON.stringify(v));
  } catch {
    /* storage unavailable — snooze lasts for this view only */
  }
}

// ── Shared data hook ─────────────────────────────────────────────────────
export function useRecommendations(session: AuthSession | null, fipsMode?: string) {
  const [snapshot, setSnapshot] = useState<PlatformSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [snoozed, setSnoozed] = useState<Record<string, number>>(() => readSnoozed(session?.tenantId || ""));

  const refresh = useCallback(async () => {
    if (!session) return;
    setLoading(true);
    setError("");
    try {
      setSnapshot(await loadPlatformSnapshot(session, fipsMode === undefined ? undefined : isFipsModeEnabled(fipsMode)));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [session, fipsMode]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const result = useMemo(() => (snapshot ? evaluate(snapshot) : { recommendations: [], checks: [] as ControlCheck[] }), [snapshot]);
  const visible = useMemo(() => result.recommendations.filter((r) => !snoozed[r.id]), [result, snoozed]);
  const score = useMemo(() => postureScore(visible, result.checks), [visible, result.checks]);

  const snooze = (id: string) => {
    const next = { ...snoozed, [id]: Date.now() + SNOOZE_DAYS * 86_400_000 };
    setSnoozed(next);
    writeSnoozed(session?.tenantId || "", next);
  };
  const unsnoozeAll = () => {
    setSnoozed({});
    writeSnoozed(session?.tenantId || "", {});
  };

  return { snapshot, loading, error, refresh, all: result.recommendations, visible, checks: result.checks, score, snooze, snoozed, unsnoozeAll };
}

// ── Small building blocks ────────────────────────────────────────────────
const card: React.CSSProperties = {
  background: C.card,
  border: `1px solid ${C.border}`,
  borderRadius: "var(--radius-lg)",
  boxShadow: "var(--shadow-sm)",
};

function SevPill({ s }: { s: Severity }) {
  const c = SEV_COLOR[s];
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11, fontWeight: 600, color: c.fg, background: c.bg, borderRadius: 999, padding: "2px 9px", whiteSpace: "nowrap" }}>
      <span style={{ width: 6, height: 6, borderRadius: 3, background: c.fg }} />
      {c.label}
    </span>
  );
}

function ScoreRing({ score, grade, assessed }: { score: number; grade: string; assessed: number }) {
  const r = 52;
  const circ = 2 * Math.PI * r;
  const color = !assessed ? C.muted : score >= 80 ? C.greenFg : score >= 65 ? C.amberFg : C.redFg;
  return (
    <svg width="132" height="132" viewBox="0 0 132 132" role="img" style={{ flexShrink: 0 }} aria-label={`Posture score ${score} of 100`}>
      <circle cx="66" cy="66" r={r} fill="none" stroke={C.border} strokeWidth="10" />
      <circle
        cx="66" cy="66" r={r} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
        strokeDasharray={`${(assessed ? score / 100 : 0) * circ} ${circ}`}
        transform="rotate(-90 66 66)" style={{ transition: "stroke-dasharray .6s ease" }}
      />
      <text x="66" y="64" textAnchor="middle" fontSize="30" fontWeight="650" fill={C.text} fontFamily="Inter, system-ui, -apple-system, sans-serif">{assessed ? score : "–"}</text>
      <text x="66" y="86" textAnchor="middle" fontSize="12" fill={C.muted} fontFamily="Inter, system-ui, -apple-system, sans-serif">Grade {grade}</text>
    </svg>
  );
}

function Kpi({ icon: Icon, label, value, sub, tone }: { icon: typeof KeyRound; label: string; value: string; sub: string; tone?: string | undefined }) {
  return (
    <div style={{ ...card, padding: "14px 16px", display: "flex", flexDirection: "column", gap: 6, minWidth: 0 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, color: C.muted, fontSize: 12 }}>
        <Icon size={14} strokeWidth={2} />
        {label}
      </div>
      <div style={{ fontSize: 26, fontWeight: 650, letterSpacing: -0.6, color: tone || C.text, fontVariantNumeric: "tabular-nums" }}>{value}</div>
      <div style={{ fontSize: 12, color: C.muted, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{sub}</div>
    </div>
  );
}

export function RecommendationRow({ r, onNavigate, onSnooze, defaultOpen = false }: { r: Recommendation; onNavigate?: ((tab: string) => void) | undefined; onSnooze?: ((id: string) => void) | undefined; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ borderTop: `1px solid ${C.border}`, padding: "12px 16px" }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
        <div style={{ paddingTop: 1, width: 78, flexShrink: 0 }}><SevPill s={r.severity} /></div>
        <button
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          style={{ flex: 1, minWidth: 0, textAlign: "left", background: "none", border: 0, padding: 0, cursor: "pointer", color: C.text }}
        >
          <div style={{ fontSize: 13.5, fontWeight: 600, lineHeight: 1.35 }}>{r.title}</div>
          <div style={{ fontSize: 12.5, color: C.dim, marginTop: 3, lineHeight: 1.5 }}>{r.why}</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 7 }}>
            <span style={{ fontSize: 11, color: C.muted }}>{r.category}</span>
            {r.frameworks.map((f) => (
              <span key={f} style={{ fontSize: 10.5, color: C.dim, border: `1px solid ${C.border}`, borderRadius: 4, padding: "0 6px", lineHeight: "17px" }}>{f}</span>
            ))}
          </div>
        </button>
        <div style={{ display: "flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
          {onNavigate && (
            <button
              onClick={() => onNavigate(r.action.tab)}
              style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 600, color: C.accentFg, background: C.accentDim, border: 0, borderRadius: 7, padding: "6px 10px", cursor: "pointer", whiteSpace: "nowrap" }}
            >
              {r.action.label} <ArrowRight size={13} />
            </button>
          )}
          <button onClick={() => setOpen((v) => !v)} aria-label="Details" style={{ background: "none", border: 0, color: C.muted, cursor: "pointer", padding: 4 }}>
            <ChevronDown size={16} style={{ transform: open ? "rotate(180deg)" : "none", transition: "transform .15s" }} />
          </button>
        </div>
      </div>
      {open && (
        <div style={{ margin: "10px 0 0 90px", padding: 12, background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, fontSize: 12.5, color: C.dim, lineHeight: 1.55 }}>
          <div><span style={{ color: C.text, fontWeight: 600 }}>How to fix: </span>{r.fix}</div>
          {r.evidence.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <span style={{ color: C.text, fontWeight: 600 }}>Affected{r.affected ? ` (${r.affected})` : ""}: </span>
              <span style={{ fontFamily: "'JetBrains Mono',ui-monospace,monospace", fontSize: 11.5 }}>{r.evidence.join(" · ")}</span>
            </div>
          )}
          {onSnooze && (
            <button onClick={() => onSnooze(r.id)} style={{ marginTop: 10, fontSize: 12, color: C.muted, background: "none", border: `1px solid ${C.border}`, borderRadius: 6, padding: "4px 9px", cursor: "pointer" }}>
              Snooze {SNOOZE_DAYS} days (this browser)
            </button>
          )}
        </div>
      )}
    </div>
  );
}

const CATEGORY_ORDER: RecCategory[] = ["Key lifecycle", "Algorithms", "Post-quantum", "Access control", "Certificates", "Resilience", "Posture"];

function Coverage({ checks }: { checks: ControlCheck[] }) {
  return (
    <div style={{ ...card, padding: 16 }}>
      <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 2 }}>Control coverage</div>
      <div style={{ fontSize: 12, color: C.muted, marginBottom: 12 }}>Evaluated against live tenant state</div>
      {CATEGORY_ORDER.map((cat) => {
        const items = checks.filter((c) => c.category === cat);
        if (!items.length) return null;
        return (
          <div key={cat} style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 11, color: C.muted, marginBottom: 4 }}>{cat}</div>
            {items.map((c) => {
              const Icon = c.status === "pass" ? CheckCircle2 : c.status === "fail" ? XCircle : CircleDashed;
              const color = c.status === "pass" ? C.greenFg : c.status === "fail" ? C.redFg : C.muted;
              return (
                <div key={c.id} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12.5, padding: "3px 0", color: c.status === "unknown" ? C.muted : C.text }}>
                  <Icon size={14} color={color} strokeWidth={2.2} />
                  <span style={{ flex: 1 }}>{c.label}</span>
                  {c.status === "unknown" && <span style={{ fontSize: 11 }}>not assessed</span>}
                </div>
              );
            })}
          </div>
        );
      })}
    </div>
  );
}

function InventoryMix({ snapshot }: { snapshot: PlatformSnapshot | null }) {
  const keys = (snapshot?.keys || []).filter((k) => !/destroy|deleted/i.test(k.status));
  if (!snapshot?.keys) return null;
  const buckets = { "Quantum-safe / symmetric": 0, "Classical asymmetric": 0, "Legacy / disallowed": 0 };
  keys.forEach((k) => {
    const st = algoStrength(k.algorithm);
    if (st === "broken" || st === "legacy") buckets["Legacy / disallowed"]++;
    else if (isQuantumVulnerable(k.algorithm)) buckets["Classical asymmetric"]++;
    else buckets["Quantum-safe / symmetric"]++;
  });
  const total = Math.max(1, keys.length);
  const colors = [C.greenFg, C.amberFg, C.redFg];
  return (
    <div style={{ ...card, padding: 16 }}>
      <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 2 }}>Crypto inventory</div>
      <div style={{ fontSize: 12, color: C.muted, marginBottom: 12 }}>{keys.length.toLocaleString()} keys by quantum exposure</div>
      <div style={{ display: "flex", height: 10, borderRadius: 5, overflow: "hidden", background: C.border, gap: 2 }}>
        {Object.values(buckets).map((v, i) => v > 0 && <div key={i} style={{ width: `${(v / total) * 100}%`, background: colors[i] }} />)}
      </div>
      <div style={{ marginTop: 10, display: "grid", gap: 4 }}>
        {Object.entries(buckets).map(([k, v], i) => (
          <div key={k} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12.5 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: colors[i] }} />
            <span style={{ flex: 1, color: C.dim }}>{k}</span>
            <span style={{ fontVariantNumeric: "tabular-nums" }}>{v}</span>
            <span style={{ color: C.muted, width: 40, textAlign: "right", fontVariantNumeric: "tabular-nums" }}>{Math.round((v / total) * 100)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function greeting(): string {
  const h = new Date().getHours();
  return h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
}

// ── Command Center (home) ────────────────────────────────────────────────
export const CommandCenterTab = ({ session, fipsMode, onNavigate }: Props) => {
  const { snapshot, loading, error, refresh, visible, checks, score, snooze } = useRecommendations(session, fipsMode);
  const now = snapshot?.now.getTime() ?? 0;

  const activeKeys = (snapshot?.keys || []).filter((k) => /active|enabled/i.test(k.status));
  const pqcExposed = activeKeys.filter((k) => isQuantumVulnerable(k.algorithm)).length;
  const certsSoon = (snapshot?.certs || []).filter((c) => {
    const e = Date.parse(c.not_after || "");
    return !/revoked|deleted/i.test(c.status) && Number.isFinite(e) && e - now < 30 * 86_400_000;
  }).length;
  const bySev = SEVERITY_ORDER.map((s) => visible.filter((r) => r.severity === s).length);
  const lastBackup = (snapshot?.backupRuns || []).filter((r) => r.status === "completed").map((r) => Date.parse(r.started_at)).sort((a, b) => b - a)[0];

  return (
    <div style={{ maxWidth: 1360, margin: "0 auto", display: "grid", gap: 16 }}>
      <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontSize: 13, color: C.muted }}>{greeting()}, {session?.username || "operator"}</div>
          <h1 style={{ margin: "2px 0 0", fontSize: 24, fontWeight: 650, letterSpacing: -0.6 }}>Security command center</h1>
          <div style={{ fontSize: 13, color: C.dim, marginTop: 4 }}>
            Tenant <b style={{ fontWeight: 600 }}>{session?.tenantId || "—"}</b>
            {snapshot && <> · evaluated {snapshot.now.toLocaleTimeString()}</>}
          </div>
        </div>
        <button
          onClick={() => void refresh()}
          disabled={loading}
          style={{ display: "inline-flex", alignItems: "center", gap: 7, fontSize: 12.5, fontWeight: 600, color: C.text, background: C.card, border: `1px solid ${C.borderHi}`, borderRadius: 8, padding: "7px 12px", cursor: loading ? "wait" : "pointer" }}
        >
          <RefreshCw size={14} style={{ animation: loading ? "spinArc 1s linear infinite" : "none" }} /> {loading ? "Evaluating…" : "Re-evaluate"}
        </button>
      </div>

      {error && <div style={{ ...card, padding: 12, color: C.redFg, fontSize: 13 }}>Could not evaluate posture: {error}</div>}

      <div style={{ display: "grid", gridTemplateColumns: "minmax(340px, 1.6fr) repeat(4, minmax(150px, 1fr))", gap: 12 }} className="vk-cc-kpis">
        <div style={{ ...card, padding: 16, display: "flex", alignItems: "center", gap: 16 }}>
          <ScoreRing {...score} />
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 14, fontWeight: 600 }}>Key management posture</div>
            <div style={{ fontSize: 12.5, color: C.dim, marginTop: 4, lineHeight: 1.5 }}>
              {score.assessed
                ? <>{checks.filter((c) => c.status === "pass").length} of {score.assessed} controls passing. {visible.length ? `${visible.length} open recommendation${visible.length > 1 ? "s" : ""}.` : "No open recommendations."}</>
                : loading ? "Collecting live state…" : "No data sources reachable yet."}
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 8, flexWrap: "wrap" }}>
              {SEVERITY_ORDER.map((s, i) => bySev[i] ? <span key={s} style={{ fontSize: 11, color: SEV_COLOR[s].fg, background: SEV_COLOR[s].bg, borderRadius: 999, padding: "1px 8px" }}>{bySev[i]} {SEV_COLOR[s].label.toLowerCase()}</span> : null)}
            </div>
          </div>
        </div>
        <Kpi icon={KeyRound} label="Active keys" value={snapshot?.keys ? activeKeys.length.toLocaleString() : "—"} sub={snapshot?.keys ? `${pqcExposed} quantum-vulnerable` : "keycore unreachable"} />
        <Kpi icon={FileCheck2} label="Certs expiring ≤30d" value={snapshot?.certs ? String(certsSoon) : "—"} sub={snapshot?.certs ? `${snapshot.certs.length} certificates tracked` : "PKI not reachable"} tone={certsSoon ? C.amberFg : undefined} />
        <Kpi icon={Atom} label="PQC readiness" value={snapshot?.pqc ? `${Math.round(snapshot.pqc.readiness_score)}%` : "—"} sub={snapshot?.pqc ? `${snapshot.pqc.classical_assets} classical assets` : "no scan on record"} />
        <Kpi icon={LifeBuoy} label="Last good backup" value={lastBackup ? `${Math.max(0, Math.floor((now - lastBackup) / 86_400_000))}d` : "—"} sub={lastBackup ? new Date(lastBackup).toLocaleDateString() : snapshot?.backupPolicies ? "none completed" : "backup service unreachable"} tone={!lastBackup && snapshot?.backupPolicies ? C.redFg : undefined} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 2fr) minmax(280px, 1fr)", gap: 16, alignItems: "start" }} className="vk-cc-main">
        <div style={{ ...card, overflow: "hidden" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 16px" }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 600, display: "flex", alignItems: "center", gap: 8 }}><ShieldAlert size={16} color={C.accentFg} /> Recommended actions</div>
              <div style={{ fontSize: 12, color: C.muted, marginTop: 2 }}>Prioritised by severity and blast radius, mapped to NIST, PCI DSS 4.0, DORA and CNSA 2.0</div>
            </div>
            {onNavigate && visible.length > 6 && (
              <button onClick={() => onNavigate("recommendations")} style={{ fontSize: 12.5, fontWeight: 600, color: C.accentFg, background: "none", border: 0, cursor: "pointer" }}>View all {visible.length} →</button>
            )}
          </div>
          {visible.slice(0, 6).map((r) => <RecommendationRow key={r.id} r={r} onNavigate={onNavigate} onSnooze={snooze} />)}
          {!visible.length && !loading && (
            <div style={{ borderTop: `1px solid ${C.border}`, padding: 28, textAlign: "center", color: C.dim, fontSize: 13 }}>
              <CheckCircle2 size={22} color={C.greenFg} style={{ marginBottom: 6 }} />
              <div>{score.assessed ? "Nothing needs attention right now." : "Recommendations appear once platform services respond."}</div>
            </div>
          )}
        </div>
        <div style={{ display: "grid", gap: 16 }}>
          <Coverage checks={checks} />
          <InventoryMix snapshot={snapshot} />
          {onNavigate && (
            <button onClick={() => onNavigate("ops")} style={{ ...card, padding: "12px 16px", display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer", color: C.text, fontSize: 13, fontWeight: 600 }}>
              Operations dashboard <ArrowRight size={15} color={C.muted} />
            </button>
          )}
        </div>
      </div>
      <style>{`@media (max-width: 1100px){.vk-cc-kpis{grid-template-columns:repeat(2,minmax(0,1fr))!important}.vk-cc-kpis>:first-child{grid-column:1/-1}.vk-cc-main{grid-template-columns:1fr!important}}`}</style>
    </div>
  );
};

// ── Full recommendations list ────────────────────────────────────────────
export const RecommendationsTab = ({ session, fipsMode, onNavigate }: Props) => {
  const { all, visible, loading, refresh, snooze, snoozed, unsnoozeAll } = useRecommendations(session, fipsMode);
  const [sev, setSev] = useState<Severity | "all">("all");
  const [cat, setCat] = useState<RecCategory | "all">("all");
  const [q, setQ] = useState("");
  const rows = visible.filter((r) =>
    (sev === "all" || r.severity === sev) &&
    (cat === "all" || r.category === cat) &&
    (!q || `${r.title} ${r.why} ${r.frameworks.join(" ")}`.toLowerCase().includes(q.toLowerCase()))
  );
  const snoozedCount = all.filter((r) => snoozed[r.id]).length;
  const chip = (active: boolean): React.CSSProperties => ({ fontSize: 12, fontWeight: 500, borderRadius: 999, padding: "4px 11px", cursor: "pointer", border: `1px solid ${active ? C.accentFg : C.border}`, background: active ? C.accentDim : "transparent", color: active ? C.accentFg : C.dim });
  return (
    <div style={{ maxWidth: 1200, margin: "0 auto", display: "grid", gap: 14 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", gap: 12, flexWrap: "wrap" }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 650, letterSpacing: -0.5 }}>Recommendations</h1>
          <div style={{ fontSize: 13, color: C.dim, marginTop: 4 }}>Every finding is computed from live tenant state and links to the control it satisfies.</div>
        </div>
        <button onClick={() => void refresh()} disabled={loading} style={{ ...chip(false), display: "inline-flex", alignItems: "center", gap: 6 }}>
          <RefreshCw size={13} /> {loading ? "Evaluating…" : "Re-evaluate"}
        </button>
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <button style={chip(sev === "all")} onClick={() => setSev("all")}>All ({visible.length})</button>
        {SEVERITY_ORDER.map((s) => (
          <button key={s} style={chip(sev === s)} onClick={() => setSev(s)}>{SEV_COLOR[s].label} ({visible.filter((r) => r.severity === s).length})</button>
        ))}
        <select value={cat} onChange={(e) => setCat(e.target.value as RecCategory | "all")} style={{ ...chip(cat !== "all"), appearance: "auto" }} aria-label="Category">
          <option value="all">All categories</option>
          {CATEGORY_ORDER.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title or framework (e.g. PCI, DORA)…" style={{ flex: 1, minWidth: 220, fontSize: 12.5, padding: "6px 10px", borderRadius: 8, border: `1px solid ${C.border}`, background: C.surface, color: C.text }} />
        {snoozedCount > 0 && <button style={chip(false)} onClick={unsnoozeAll}>Show {snoozedCount} snoozed</button>}
      </div>
      <div style={{ ...card, overflow: "hidden" }}>
        {rows.map((r) => <RecommendationRow key={r.id} r={r} onNavigate={onNavigate} onSnooze={snooze} />)}
        {!rows.length && <div style={{ padding: 28, textAlign: "center", color: C.dim, fontSize: 13 }}>{loading ? "Evaluating…" : "No recommendations match these filters."}</div>}
      </div>
    </div>
  );
};
