// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { Brain, RefreshCcw, Play, CheckCircle2 } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });
const post = (path: string, tok: string, tid: string) =>
  fetch(`${base}${path}`, { method: "POST", headers: { ...hdr(tok, tid), "Content-Type": "application/json" } });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` }, amber: { background: C.amberDim, color: C.amber, border: `1px solid ${C.amber}33` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;

export function MLAnomalyTab({ session }: any) {
  const [anomalies, setAnomalies] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [detecting, setDetecting] = useState(false);
  const [err, setErr] = useState("");
  const [lastRun, setLastRun] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const r = await fetch(`${base}/ml/anomalies`, { headers: hdr(session.token, tid) });
      const d = await r.json().catch(() => ({}));
      setAnomalies(Array.isArray(d.anomalies) ? d.anomalies : Array.isArray(d) ? d : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleDetect = async () => {
    const tid = session?.tenantId ?? "";
    setDetecting(true);
    try {
      await post("/ml/detect", session.token, tid);
      setLastRun(new Date().toLocaleTimeString());
      await load();
    } catch (e: any) { setErr(e.message); }
    finally { setDetecting(false); }
  };

  const handleDismiss = async (id: string) => {
    const tid = session?.tenantId ?? "";
    try {
      await post(`/ml/anomalies/${id}/dismiss`, session.token, tid);
      await load();
    } catch (e: any) { setErr(e.message); }
  };

  const sevColor = (s: string) => s === "critical" ? C.red : s === "high" ? "#f97316" : s === "medium" ? C.amber : C.green;
  const fmtDate = (iso?: string) => iso ? new Date(iso).toLocaleString() : "—";
  const active = anomalies.filter((a: any) => !a.dismissed);

  return (
    <div style={{ padding: 24, maxWidth: 1100 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Brain size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>ML & Anomaly Detection</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn onClick={handleDetect} disabled={detecting} variant="amber" small><Play size={12} />{detecting ? "Scanning…" : "Run Detection"}</Btn>
          <Btn onClick={load} small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}
      {lastRun && <div style={{ padding: 10, borderRadius: 6, background: C.green + "12", color: C.green, fontSize: 12, marginBottom: 16, display: "flex", alignItems: "center", gap: 6 }}><CheckCircle2 size={13} /> Detection run completed at {lastRun}</div>}

      <div style={{ display: "flex", gap: 12, marginBottom: 20 }}>
        {["critical", "high", "medium", "low"].map(s => (
          <Card key={s} style={{ minWidth: 90, textAlign: "center" }}>
            <div style={{ fontSize: 20, fontWeight: 700, color: sevColor(s) }}>{active.filter((a: any) => a.severity === s).length}</div>
            <div style={{ fontSize: 10, color: C.muted, textTransform: "capitalize" }}>{s}</div>
          </Card>
        ))}
        <Card style={{ minWidth: 90, textAlign: "center" }}>
          <div style={{ fontSize: 20, fontWeight: 700, color: C.muted }}>{anomalies.filter((a: any) => a.dismissed).length}</div>
          <div style={{ fontSize: 10, color: C.muted }}>Dismissed</div>
        </Card>
      </div>

      <Card>
        <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 }}>Active Anomalies</div>
        {active.length === 0 ? (
          <div style={{ color: C.green, fontSize: 12, padding: 16, textAlign: "center", display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}><CheckCircle2 size={14} /> No active anomalies detected.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Type" /><TH c="Key ID" /><TH c="Severity" /><TH c="Score" /><TH c="Detected" /><TH c="Description" /><TH c="Actions" /></tr></thead>
              <tbody>
                {active.map((a: any, i: number) => (
                  <tr key={i}>
                    <TD c={a.anomaly_type} /><TD c={a.key_id} mono /><TD c={<Badge color={sevColor(a.severity)}>{a.severity}</Badge>} />
                    <TD c={a.score?.toFixed(2)} /><TD c={fmtDate(a.detected_at)} /><TD c={a.description} />
                    <TD c={<Btn small variant="ghost" onClick={() => handleDismiss(a.id)}><CheckCircle2 size={11} /> Dismiss</Btn>} />
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
