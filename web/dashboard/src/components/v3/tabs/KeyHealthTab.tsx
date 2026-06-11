// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { Activity, RefreshCcw, RotateCw } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;

function GradeChip({ grade }: { grade: string }) {
  const colors: Record<string, string> = { A: C.green, B: "#84cc16", C: C.amber, D: "#f97316", F: C.red };
  const c = colors[grade] ?? C.muted;
  return <span style={{ fontWeight: 800, fontSize: 14, color: c, background: c + "18", padding: "2px 8px", borderRadius: 5 }}>{grade ?? "?"}</span>;
}

function ScoreBar({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score ?? 0));
  const color = pct >= 80 ? C.green : pct >= 60 ? C.amber : C.red;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ flex: 1, height: 6, borderRadius: 3, background: C.border, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 3 }} />
      </div>
      <span style={{ fontSize: 11, color: C.text, minWidth: 28 }}>{pct}</span>
    </div>
  );
}

export function KeyHealthTab({ session }: any) {
  const [scores, setScores] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>({});
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [refreshing, setRefreshing] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const [hRes, sRes] = await Promise.all([
        fetch(`${base}/health/summary`, { headers: hdr(session.token, tid) }),
        fetch(`${base}/health/summary`, { headers: hdr(session.token, tid) }),
      ]);
      const h = await hRes.json().catch(() => ({}));
      setSummary(h);
      setScores(Array.isArray(h.scores) ? h.scores : Array.isArray(h.keys) ? h.keys : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleRefresh = async (keyId: string) => {
    const tid = session?.tenantId ?? "";
    setRefreshing(keyId);
    try {
      await fetch(`${base}/keys/${keyId}/health`, { headers: hdr(session.token, tid) });
      await load();
    } catch (e: any) { setErr(e.message); }
    finally { setRefreshing(null); }
  };

  const grades = scores.reduce((acc: any, s: any) => { acc[s.grade] = (acc[s.grade] ?? 0) + 1; return acc; }, {} as any);

  return (
    <div style={{ padding: 24, maxWidth: 1100 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Activity size={20} style={{ color: C.green }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Key Health Scoring & Monitoring</span>
        </div>
        <Btn onClick={load} small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
        {["A", "B", "C", "D", "F"].map(g => (
          <Card key={g} style={{ minWidth: 80, textAlign: "center" }}>
            <GradeChip grade={g} />
            <div style={{ fontSize: 18, fontWeight: 700, color: C.text, marginTop: 6 }}>{grades[g] ?? 0}</div>
            <div style={{ fontSize: 10, color: C.muted }}>Grade {g}</div>
          </Card>
        ))}
        {summary.total_keys != null && (
          <Card style={{ minWidth: 100, textAlign: "center" }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: C.text }}>{summary.total_keys}</div>
            <div style={{ fontSize: 10, color: C.muted }}>Total Keys</div>
          </Card>
        )}
        {summary.avg_score != null && (
          <Card style={{ minWidth: 100, textAlign: "center" }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: C.accent }}>{summary.avg_score?.toFixed?.(0)}</div>
            <div style={{ fontSize: 10, color: C.muted }}>Avg Score</div>
          </Card>
        )}
      </div>

      <Card>
        <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 }}>Health Scores</div>
        {scores.length === 0 ? (
          <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No health scores yet. Scores are computed automatically.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Key ID" /><TH c="Grade" /><TH c="Score" /><TH c="Age Risk" /><TH c="Usage Risk" /><TH c="Rotation Risk" /><TH c="Actions" /></tr></thead>
              <tbody>
                {scores.map((s: any, i: number) => (
                  <tr key={i}>
                    <TD c={s.key_id} mono />
                    <TD c={<GradeChip grade={s.grade} />} />
                    <TD c={<ScoreBar score={s.score} />} />
                    <TD c={s.age_risk_score} />
                    <TD c={s.usage_risk_score} />
                    <TD c={s.rotation_risk_score} />
                    <TD c={<Btn small variant="ghost" onClick={() => handleRefresh(s.key_id)} disabled={refreshing === s.key_id}><RotateCw size={11} />{refreshing === s.key_id ? "…" : "Refresh"}</Btn>} />
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
