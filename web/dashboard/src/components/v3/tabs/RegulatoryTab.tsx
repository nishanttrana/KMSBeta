// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { ClipboardCheck, RefreshCcw, Download, CheckCircle2, XCircle, AlertTriangle } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Btn = ({ onClick, children, small, variant = "default" }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` } };
  return <button onClick={onClick} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", border: "none", ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;

function ScoreMeter({ score, max = 100 }: any) {
  const pct = Math.min(100, (score / max) * 100);
  const color = pct >= 85 ? C.green : pct >= 65 ? C.amber : C.red;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ flex: 1, height: 8, borderRadius: 4, background: C.border, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 4, transition: "width .3s" }} />
      </div>
      <span style={{ fontSize: 12, fontWeight: 700, color }}>{score?.toFixed(0) ?? 0}%</span>
    </div>
  );
}

export function RegulatoryTab({ session }: any) {
  const [dashboard, setDashboard] = useState<any>({});
  const [frameworks, setFrameworks] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [selectedFramework, setSelectedFramework] = useState("FIPS-140-3");

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const [dRes, rRes] = await Promise.all([
        fetch(`${base}/compliance/dashboard`, { headers: hdr(session.token, tid) }),
        fetch(`${base}/compliance/regulatory`, { headers: hdr(session.token, tid) }),
      ]);
      const d = await dRes.json().catch(() => ({}));
      const r = await rRes.json().catch(() => ({}));
      setDashboard(d);
      setFrameworks(Array.isArray(r.frameworks) ? r.frameworks : Array.isArray(r) ? r : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleExport = async () => {
    const tid = session?.tenantId ?? "";
    const r = await fetch(`${base}/compliance/report?framework=${encodeURIComponent(selectedFramework)}`, { headers: hdr(session.token, tid) });
    const d = await r.json();
    const blob = new Blob([JSON.stringify(d, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `compliance-${selectedFramework}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const iconFor = (s: string) => s === "pass" ? <CheckCircle2 size={13} style={{ color: C.green }} /> : s === "fail" ? <XCircle size={13} style={{ color: C.red }} /> : <AlertTriangle size={13} style={{ color: C.amber }} />;
  const colorFor = (s: string) => s === "pass" ? C.green : s === "fail" ? C.red : C.amber;

  return (
    <div style={{ padding: 24, maxWidth: 1100 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <ClipboardCheck size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Regulatory Compliance Dashboard</span>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <select value={selectedFramework} onChange={(e: any) => setSelectedFramework(e.target.value)} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "5px 10px", color: C.text, fontSize: 12, outline: "none" }}>
            {["FIPS-140-3", "SOC2", "ISO-27001", "GDPR", "HIPAA", "PCI-DSS"].map(f => <option key={f}>{f}</option>)}
          </select>
          <Btn onClick={handleExport} variant="ghost" small><Download size={12} /> Export</Btn>
          <Btn onClick={load} small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))", gap: 12, marginBottom: 24 }}>
        {[
          { label: "Overall Score", value: dashboard.overall_score, color: C.green },
          { label: "Controls Passing", value: dashboard.controls_passing, color: C.green },
          { label: "Controls Failing", value: dashboard.controls_failing, color: C.red },
          { label: "Under Review", value: dashboard.controls_review, color: C.amber },
        ].map(({ label, value, color }: any) => (
          <Card key={label}>
            <div style={{ fontSize: 22, fontWeight: 800, color }}>{value ?? "—"}{label === "Overall Score" && value ? "%" : ""}</div>
            <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>{label}</div>
          </Card>
        ))}
      </div>

      {dashboard.overall_score != null && (
        <Card style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 12, color: C.dim, marginBottom: 8 }}>Overall Compliance Score</div>
          <ScoreMeter score={dashboard.overall_score} />
        </Card>
      )}

      <Card>
        <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 }}>Frameworks</div>
        {frameworks.length === 0 ? (
          <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No framework data available.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Framework" /><TH c="Version" /><TH c="Status" /><TH c="Score" /><TH c="Last Assessed" /></tr></thead>
              <tbody>
                {frameworks.map((f: any, i: number) => (
                  <tr key={i}>
                    <TD c={f.name ?? f.framework} />
                    <TD c={f.version} />
                    <TD c={<span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11, color: colorFor(f.status), fontWeight: 600 }}>{iconFor(f.status)}{f.status}</span>} />
                    <TD c={<ScoreMeter score={f.score ?? f.compliance_score} />} />
                    <TD c={f.last_assessed ? new Date(f.last_assessed).toLocaleDateString() : "—"} />
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
