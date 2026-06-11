// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { BarChart2, RefreshCcw, Clock, TrendingUp, AlertTriangle, CheckCircle2 } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", alignItems: "center", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600, textTransform: "capitalize" }}>{children}</span>;
const Btn = ({ onClick, children, small }: any) => <button onClick={onClick} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: small ? 11 : 12, fontWeight: 600, cursor: "pointer", border: "none", background: C.accent, color: C.bg }}>{children}</button>;
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;

function StatCard({ icon: Icon, label, value, color }: any) {
  return (
    <Card style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 160 }}>
      <div style={{ background: (color ?? C.accent) + "22", borderRadius: 8, padding: 10 }}>
        <Icon size={18} style={{ color: color ?? C.accent }} />
      </div>
      <div>
        <div style={{ fontSize: 20, fontWeight: 700, color: C.text }}>{value ?? "—"}</div>
        <div style={{ fontSize: 11, color: C.muted }}>{label}</div>
      </div>
    </Card>
  );
}

export function RotationAnalyticsTab({ session }: any) {
  const [analytics, setAnalytics] = useState<any>(null);
  const [runs, setRuns] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const [aRes, rRes] = await Promise.all([
        fetch(`${base}/rotation/analytics`, { headers: hdr(session.token, tid) }),
        fetch(`${base}/rotation/runs?limit=20`, { headers: hdr(session.token, tid) }),
      ]);
      const aData = await aRes.json().catch(() => ({}));
      const rData = await rRes.json().catch(() => ({}));
      setAnalytics(aData.analytics ?? aData);
      setRuns(rData.runs ?? (Array.isArray(rData) ? rData : []));
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const fmtDate = (iso?: string) => iso ? new Date(iso).toLocaleString() : "—";

  return (
    <div style={{ padding: 24, maxWidth: 1200 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <BarChart2 size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Key Rotation Analytics</span>
        </div>
        <Btn onClick={load} small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
        <StatCard icon={TrendingUp} label="Total Rotations" value={analytics?.total_rotations} />
        <StatCard icon={CheckCircle2} label="Successful" value={analytics?.successful} color={C.green} />
        <StatCard icon={AlertTriangle} label="Failed" value={analytics?.failed} color={C.red} />
        <StatCard icon={Clock} label="Avg Duration (s)" value={analytics?.avg_duration_seconds?.toFixed(1)} color={C.amber} />
        <StatCard icon={BarChart2} label="p95 Duration (s)" value={analytics?.p95_duration_seconds?.toFixed(1)} color={C.accent} />
      </div>

      <Card>
        <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 }}>Recent Rotation Runs</div>
        {runs.length === 0 ? (
          <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No rotation runs recorded yet.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr><TH c="Key ID" /><TH c="Policy" /><TH c="Status" /><TH c="Started" /><TH c="Completed" /><TH c="Error" /></tr>
              </thead>
              <tbody>
                {runs.map((r: any, i: number) => (
                  <tr key={i}>
                    <TD c={r.key_id} mono /><TD c={r.policy_id} /><TD c={
                      <Badge color={r.status === "success" ? C.green : r.status === "failed" ? C.red : C.amber}>{r.status}</Badge>
                    } /><TD c={fmtDate(r.started_at)} /><TD c={fmtDate(r.completed_at)} /><TD c={r.error_message} />
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
