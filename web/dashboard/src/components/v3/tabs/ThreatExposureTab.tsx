// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useMemo, useState } from "react";
import { ShieldAlert, RefreshCcw, CheckCircle2, AlertTriangle, XCircle, Link2, Radar, ScanSearch } from "lucide-react";
import { C } from "../../v3/theme";
import { loadUnifiedFindings, resolveFinding } from "../../../lib/securityFindings";

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};

const sevColor = (s: string) => s === "critical" ? C.red : s === "high" ? "#f97316" : s === "medium" ? C.amber : s === "low" ? C.accent : C.muted;
const fmtDate = (iso?: string) => iso ? new Date(iso).toLocaleString() : "—";

export function ThreatExposureTab({ session }: any) {
  const [data, setData] = useState<any>({ findings: [], correlations: 0, counts: { open: 0, bySeverity: {}, threat: 0, leak: 0 } });
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [sourceFilter, setSourceFilter] = useState<"all" | "threat" | "leak" | "correlated">("all");
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [busyId, setBusyId] = useState<string>("");

  const load = useCallback(async () => {
    if (!session?.token) return;
    setLoading(true); setErr("");
    try {
      setData(await loadUnifiedFindings(session));
    } catch (e: any) { setErr(e.message ?? "Failed to load findings"); }
    finally { setLoading(false); }
  }, [session]);

  useEffect(() => { load(); }, [load]);

  const handleResolve = async (f: any) => {
    setBusyId(f.id);
    try { await resolveFinding(session, f); await load(); }
    catch (e: any) { setErr(e.message ?? "Action failed"); }
    finally { setBusyId(""); }
  };

  const visible = useMemo(() => {
    return (data.findings ?? []).filter((f: any) => {
      if (sourceFilter === "correlated" && !f.correlated) return false;
      if (sourceFilter !== "all" && sourceFilter !== "correlated" && f.source !== sourceFilter) return false;
      if (sevFilter !== "all" && f.severity !== sevFilter) return false;
      return true;
    });
  }, [data, sourceFilter, sevFilter]);

  const bs = data.counts?.bySeverity ?? {};
  const cards = [
    { label: "Open Findings", val: data.counts?.open ?? 0, color: C.text, icon: ShieldAlert },
    { label: "Critical", val: bs.critical ?? 0, color: C.red, icon: XCircle },
    { label: "High", val: bs.high ?? 0, color: "#f97316", icon: AlertTriangle },
    { label: "Correlated", val: data.correlations ?? 0, color: C.red, icon: Link2 },
    { label: "Threat / Leak", val: `${data.counts?.threat ?? 0} / ${data.counts?.leak ?? 0}`, color: C.accent, icon: Radar },
  ];

  return (
    <div style={{ padding: 24, maxWidth: 1280 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <ShieldAlert size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Threat &amp; Exposure</span>
        </div>
        <Btn onClick={load} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
      </div>
      <div style={{ fontSize: 12, color: C.muted, marginBottom: 20 }}>
        Unified triage of key-usage threat signals and secret-leak findings. Correlated items — a key exposed in code and then used anomalously — are surfaced first.
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 12, marginBottom: 20 }}>
        {cards.map(({ label, val, color, icon: Icon }: any) => (
          <Card key={label} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ background: color + "18", borderRadius: 8, padding: 8 }}><Icon size={14} style={{ color }} /></div>
            <div><div style={{ fontSize: 18, fontWeight: 700, color }}>{val}</div><div style={{ fontSize: 10, color: C.muted }}>{label}</div></div>
          </Card>
        ))}
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap" }}>
        {(["all", "correlated", "threat", "leak"] as const).map(v => (
          <button key={v} onClick={() => setSourceFilter(v)} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", border: `1px solid ${C.border}`, background: sourceFilter === v ? C.accent : "transparent", color: sourceFilter === v ? C.bg : C.dim }}>
            {v === "all" ? "All" : v === "correlated" ? "Correlated" : v === "threat" ? "Threat signals" : "Leak findings"}
          </button>
        ))}
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)} style={{ marginLeft: "auto", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "6px 10px", color: C.text, fontSize: 12 }}>
          {["all", "critical", "high", "medium", "low"].map(s => <option key={s} value={s}>{s === "all" ? "All severities" : s}</option>)}
        </select>
      </div>

      <Card style={{ padding: 0 }}>
        {visible.length === 0 ? (
          <div style={{ color: C.green, fontSize: 12, padding: 24, textAlign: "center", display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}>
            <CheckCircle2 size={14} /> No matching findings.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Sev" /><TH c="Source" /><TH c="Finding" /><TH c="Subject" /><TH c="Detected" /><TH c="Status" /><TH c="Action" /></tr></thead>
              <tbody>
                {visible.map((f: any) => (
                  <tr key={f.id} style={f.correlated ? { background: C.redDim } : undefined}>
                    <TD c={<Badge color={sevColor(f.severity)}>{f.severity}</Badge>} />
                    <TD c={
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 4, color: C.muted, fontSize: 10 }}>
                        {f.source === "threat" ? <Radar size={11} /> : <ScanSearch size={11} />}{f.source}
                      </span>
                    } />
                    <TD c={
                      <div>
                        <div style={{ fontWeight: 600 }}>{f.title}</div>
                        <div style={{ color: C.muted, fontSize: 10 }}>{f.description}</div>
                        {f.correlated && (
                          <div style={{ marginTop: 4, display: "inline-flex", alignItems: "center", gap: 4, color: C.red, fontSize: 10, fontWeight: 600 }}>
                            <Link2 size={11} /> {f.correlated.summary}
                          </div>
                        )}
                      </div>
                    } />
                    <TD c={f.subject} mono />
                    <TD c={fmtDate(f.detectedAt)} />
                    <TD c={
                      f.status === "open"
                        ? <Badge color={C.amber}>open</Badge>
                        : <span style={{ color: C.muted, fontSize: 11 }}>{f.status}</span>
                    } />
                    <TD c={
                      f.status === "open"
                        ? <Btn small variant="ghost" disabled={busyId === f.id} onClick={() => handleResolve(f)}>
                            <CheckCircle2 size={11} /> {f.source === "threat" ? "Acknowledge" : "Resolve"}
                          </Btn>
                        : "—"
                    } />
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
