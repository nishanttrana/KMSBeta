// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { DollarSign, RefreshCcw, Zap, TrendingDown, CheckCircle2 } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` }, green: { background: C.green + "18", color: C.green, border: `1px solid ${C.green}33` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;

export function CostOptimizationTab({ session }: any) {
  const [metrics, setMetrics] = useState<any>({});
  const [suggestions, setSuggestions] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [applying, setApplying] = useState<string | null>(null);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const [mRes, sRes] = await Promise.all([
        fetch(`${base}/cost/metrics`, { headers: hdr(session.token, tid) }),
        fetch(`${base}/cost/suggestions`, { headers: hdr(session.token, tid) }),
      ]);
      const m = await mRes.json().catch(() => ({}));
      const s = await sRes.json().catch(() => ({}));
      setMetrics(m.metrics ?? m ?? {});
      setSuggestions(Array.isArray(s.suggestions) ? s.suggestions : Array.isArray(s) ? s : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleApply = async (id: string) => {
    const tid = session?.tenantId ?? "";
    setApplying(id);
    try {
      await fetch(`${base}/cost/suggestions/${id}/apply`, { method: "POST", headers: hdr(session.token, tid) });
      await load();
    } catch (e: any) { setErr(e.message); }
    finally { setApplying(null); }
  };

  const impactColor = (i: string) => i === "high" ? C.green : i === "medium" ? C.amber : C.muted;
  const totalSavings = suggestions.filter((s: any) => !s.applied).reduce((acc: number, s: any) => acc + (s.estimated_savings_pct ?? 0), 0);

  return (
    <div style={{ padding: 24, maxWidth: 1100 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <DollarSign size={20} style={{ color: C.green }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Cost & Optimization Dashboard</span>
        </div>
        <Btn onClick={load} small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 12, marginBottom: 24 }}>
        {[
          { label: "Total Keys", icon: DollarSign, value: metrics.total_keys },
          { label: "Active Keys", icon: Zap, value: metrics.active_keys, color: C.green },
          { label: "Unused Keys", icon: TrendingDown, value: metrics.unused_keys, color: C.amber },
          { label: "Expired Keys", icon: TrendingDown, value: metrics.expired_keys, color: C.red },
          { label: "Avg Age (days)", icon: DollarSign, value: metrics.avg_age_days?.toFixed(0), color: C.accent },
        ].map(({ label, icon: Icon, value, color }: any) => (
          <Card key={label} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ background: (color ?? C.accent) + "22", borderRadius: 8, padding: 8 }}><Icon size={16} style={{ color: color ?? C.accent }} /></div>
            <div>
              <div style={{ fontSize: 18, fontWeight: 700, color: C.text }}>{value ?? "—"}</div>
              <div style={{ fontSize: 10, color: C.muted }}>{label}</div>
            </div>
          </Card>
        ))}
      </div>

      <Card>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>Optimization Suggestions</div>
          {totalSavings > 0 && <Badge color={C.green}>~{totalSavings.toFixed(0)}% potential savings</Badge>}
        </div>
        {suggestions.length === 0 ? (
          <div style={{ color: C.green, fontSize: 12, padding: 16, textAlign: "center", display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}><CheckCircle2 size={14} /> No optimizations needed — your key estate is efficient.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Type" /><TH c="Description" /><TH c="Impact" /><TH c="Est. Savings" /><TH c="Status" /><TH c="Actions" /></tr></thead>
              <tbody>
                {suggestions.map((s: any, i: number) => (
                  <tr key={i}>
                    <TD c={<Badge color={C.accent}>{s.suggestion_type ?? s.type}</Badge>} />
                    <TD c={s.description} />
                    <TD c={<Badge color={impactColor(s.impact)}>{s.impact}</Badge>} />
                    <TD c={s.estimated_savings_pct != null ? `~${s.estimated_savings_pct}%` : "—"} />
                    <TD c={<Badge color={s.applied ? C.green : C.muted}>{s.applied ? "applied" : "pending"}</Badge>} />
                    <TD c={
                      !s.applied
                        ? <Btn small variant="green" onClick={() => handleApply(s.id)} disabled={applying === s.id}><Zap size={11} />{applying === s.id ? "Applying…" : "Apply"}</Btn>
                        : <span style={{ color: C.muted, fontSize: 11 }}>—</span>
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
