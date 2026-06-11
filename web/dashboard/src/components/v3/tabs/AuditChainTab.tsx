// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { Link, RefreshCcw, ShieldCheck, Anchor, CheckCircle2, XCircle } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });
const post = (path: string, tok: string, tid: string) =>
  fetch(`${base}${path}`, { method: "POST", headers: { ...hdr(tok, tid), "Content-Type": "application/json" } });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` }, green: { background: C.green + "18", color: C.green, border: `1px solid ${C.green}33` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;

export function AuditChainTab({ session }: any) {
  const [chain, setChain] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [anchoring, setAnchoring] = useState(false);
  const [err, setErr] = useState("");
  const [view, setView] = useState<"chain" | "events">("chain");

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const [cRes, eRes] = await Promise.all([
        fetch(`${base}/audit/chain?limit=50`, { headers: hdr(session.token, tid) }),
        fetch(`${base}/audit/events?limit=100`, { headers: hdr(session.token, tid) }),
      ]);
      const c = await cRes.json().catch(() => ({}));
      const e = await eRes.json().catch(() => ({}));
      setChain(Array.isArray(c.entries) ? c.entries : Array.isArray(c) ? c : []);
      setEvents(Array.isArray(e.events) ? e.events : Array.isArray(e) ? e : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleVerify = async () => {
    const tid = session?.tenantId ?? "";
    setVerifying(true);
    try {
      const r = await post("/audit/chain/verify", session.token, tid);
      const d = await r.json();
      setVerifyResult(d);
    } catch (e: any) { setErr(e.message); }
    finally { setVerifying(false); }
  };

  const handleAnchor = async () => {
    const tid = session?.tenantId ?? "";
    setAnchoring(true);
    try {
      await post("/audit/chain/anchor", session.token, tid);
      await load();
    } catch (e: any) { setErr(e.message); }
    finally { setAnchoring(false); }
  };

  const fmtDate = (iso?: string) => iso ? new Date(iso).toLocaleString() : "—";

  return (
    <div style={{ padding: 24, maxWidth: 1200 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Link size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Blockchain-Backed Audit Chain</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn onClick={handleVerify} disabled={verifying} variant="green" small><ShieldCheck size={12} />{verifying ? "Verifying…" : "Verify Chain"}</Btn>
          <Btn onClick={handleAnchor} disabled={anchoring} small><Anchor size={12} />{anchoring ? "Anchoring…" : "Anchor Now"}</Btn>
          <Btn onClick={load} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      {verifyResult && (
        <div style={{ padding: 12, borderRadius: 6, background: verifyResult.valid ? C.green + "12" : C.red + "12", border: `1px solid ${verifyResult.valid ? C.green : C.red}30`, color: verifyResult.valid ? C.green : C.red, fontSize: 12, marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
          {verifyResult.valid ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
          {verifyResult.valid ? `Chain verified — ${verifyResult.entry_count ?? 0} entries valid, root hash: ${verifyResult.root_hash?.slice(0, 16)}…` : `Chain integrity failure: ${verifyResult.error ?? "unknown error"}`}
        </div>
      )}

      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {(["chain", "events"] as const).map(v => (
          <button key={v} onClick={() => setView(v)} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", border: `1px solid ${C.border}`, background: view === v ? C.accent : "transparent", color: view === v ? C.bg : C.dim }}>
            {v === "chain" ? `Chain Entries (${chain.length})` : `Audit Events (${events.length})`}
          </button>
        ))}
      </div>

      {view === "chain" ? (
        <Card>
          {chain.length === 0 ? (
            <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No chain entries. Use "Anchor Now" to create the first block.</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr><TH c="Seq" /><TH c="Hash" /><TH c="Previous Hash" /><TH c="Event Count" /><TH c="Anchored At" /></tr></thead>
                <tbody>
                  {chain.map((e: any, i: number) => (
                    <tr key={i}>
                      <TD c={e.sequence_number} /><TD c={e.hash?.slice(0, 20) + "…"} mono /><TD c={e.previous_hash?.slice(0, 20) + "…"} mono />
                      <TD c={e.event_count} /><TD c={fmtDate(e.anchored_at)} />
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      ) : (
        <Card>
          {events.length === 0 ? (
            <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No audit events.</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr><TH c="Event Type" /><TH c="Actor" /><TH c="Key ID" /><TH c="Outcome" /><TH c="Timestamp" /></tr></thead>
                <tbody>
                  {events.map((e: any, i: number) => (
                    <tr key={i}>
                      <TD c={e.event_type} /><TD c={e.actor} /><TD c={e.key_id} mono />
                      <TD c={<Badge color={e.outcome === "success" ? C.green : C.red}>{e.outcome}</Badge>} />
                      <TD c={fmtDate(e.timestamp ?? e.created_at)} />
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
