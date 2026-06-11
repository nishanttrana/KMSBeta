// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { BarChart3, RefreshCcw, Download, TrendingUp } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default" }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` } };
  return <button onClick={onClick} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", border: "none", ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;

export function KeyAnalyticsTab({ session }: any) {
  const [analytics, setAnalytics] = useState<any>({});
  const [keyStats, setKeyStats] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const [aRes, sRes] = await Promise.all([
        fetch(`${base}/enterprise/summary`, { headers: hdr(session.token, tid) }),
        fetch(`${base}/rotation/analytics`, { headers: hdr(session.token, tid) }),
      ]);
      const a = await aRes.json().catch(() => ({}));
      const s = await sRes.json().catch(() => ({}));
      setAnalytics(a);
      setKeyStats(Array.isArray(a.by_algorithm) ? a.by_algorithm : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleExport = async () => {
    const tid = session?.tenantId ?? "";
    const r = await fetch(`${base}/enterprise/summary`, { headers: hdr(session.token, tid) });
    const d = await r.json();
    const blob = new Blob([JSON.stringify(d, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "key-analytics-report.json"; a.click();
    URL.revokeObjectURL(url);
  };

  const algColor = (a: string) => a?.includes("RSA") ? C.accent : a?.includes("EC") ? C.green : C.amber;

  return (
    <div style={{ padding: 24, maxWidth: 1100 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <BarChart3 size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Advanced Key Analytics & Reporting</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn onClick={handleExport} variant="ghost" small><Download size={12} /> Export JSON</Btn>
          <Btn onClick={load} small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))", gap: 12, marginBottom: 24 }}>
        {[
          { label: "Total Keys", value: analytics.total_keys, icon: TrendingUp },
          { label: "Active Keys", value: analytics.active_keys, icon: BarChart3 },
          { label: "Total Rotations", value: analytics.total_rotations?.toLocaleString?.(), icon: BarChart3 },
          { label: "Avg Key Age (days)", value: analytics.avg_age_days?.toFixed?.(1), icon: TrendingUp },
        ].map(({ label, value, icon: Icon }: any) => (
          <Card key={label} style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ background: C.accent + "22", borderRadius: 8, padding: 10 }}><Icon size={16} style={{ color: C.accent }} /></div>
            <div>
              <div style={{ fontSize: 20, fontWeight: 700, color: C.text }}>{value ?? "—"}</div>
              <div style={{ fontSize: 11, color: C.muted }}>{label}</div>
            </div>
          </Card>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <Card>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 }}>By Algorithm</div>
          {keyStats.length === 0 ? (
            <div style={{ color: C.muted, fontSize: 12 }}>No data available.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {keyStats.map((s: any, i: number) => (
                <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <Badge color={algColor(s.algorithm)}>{s.algorithm}</Badge>
                  <span style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{s.count}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
        <Card>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 }}>Rotation Summary</div>
          {[
            { label: "Total Rotations", val: analytics.total_rotations },
            { label: "Successful", val: analytics.successful },
            { label: "Failed", val: analytics.failed },
            { label: "Avg Duration (s)", val: analytics.avg_duration_seconds?.toFixed?.(1) },
          ].map(({ label, val }: any) => (
            <div key={label} style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: `1px solid ${C.border}` }}>
              <span style={{ fontSize: 12, color: C.dim }}>{label}</span>
              <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{val?.toLocaleString?.() ?? val ?? "—"}</span>
            </div>
          ))}
        </Card>
      </div>
    </div>
  );
}
