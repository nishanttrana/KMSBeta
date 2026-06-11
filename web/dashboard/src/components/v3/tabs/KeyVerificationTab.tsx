// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { ShieldCheck, RefreshCcw, Search, CheckCircle2, XCircle } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;

export function KeyVerificationTab({ session }: any) {
  const [keys, setKeys] = useState<any[]>([]);
  const [results, setResults] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const [search, setSearch] = useState("");

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const r = await fetch(`${base}/keys`, { headers: hdr(session.token, tid) });
      const d = await r.json().catch(() => ({}));
      setKeys(Array.isArray(d.keys) ? d.keys : Array.isArray(d) ? d : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleVerify = async (keyId: string) => {
    const tid = session?.tenantId ?? "";
    setVerifying(keyId);
    try {
      const r = await fetch(`${base}/keys/${keyId}/verify-material`, { method: "POST", headers: hdr(session.token, tid) });
      const d = await r.json();
      setResults(prev => ({ ...prev, [keyId]: d }));
    } catch (e: any) {
      setResults(prev => ({ ...prev, [keyId]: { valid: false, error: e.message } }));
    } finally { setVerifying(null); }
  };

  const handleVerifyAll = async () => {
    const visible = filtered.slice(0, 20);
    for (const k of visible) { await handleVerify(k.id); }
  };

  const filtered = keys.filter((k: any) => !search || k.id?.includes(search) || k.label?.toLowerCase().includes(search.toLowerCase()));
  const verifiedCount = Object.values(results).filter((r: any) => r.valid).length;
  const failedCount = Object.values(results).filter((r: any) => r.valid === false).length;

  return (
    <div style={{ padding: 24, maxWidth: 1100 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <ShieldCheck size={20} style={{ color: C.green }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Key Material Verification</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn onClick={handleVerifyAll} small>Verify All Visible</Btn>
          <Btn onClick={load} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      {Object.keys(results).length > 0 && (
        <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
          <div style={{ padding: "8px 16px", borderRadius: 6, background: C.green + "15", color: C.green, fontSize: 12, fontWeight: 600 }}><CheckCircle2 size={12} style={{ display: "inline", marginRight: 5 }} />{verifiedCount} verified</div>
          {failedCount > 0 && <div style={{ padding: "8px 16px", borderRadius: 6, background: C.red + "15", color: C.red, fontSize: 12, fontWeight: 600 }}><XCircle size={12} style={{ display: "inline", marginRight: 5 }} />{failedCount} failed</div>}
        </div>
      )}

      <div style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 8, background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "6px 10px" }}>
        <Search size={13} style={{ color: C.muted }} />
        <input value={search} onChange={(e: any) => setSearch(e.target.value)} placeholder="Filter by key ID or label…" style={{ background: "none", border: "none", outline: "none", color: C.text, fontSize: 12, flex: 1 }} />
      </div>

      <Card>
        {filtered.length === 0 ? (
          <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No keys found.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Key ID" /><TH c="Label" /><TH c="Algorithm" /><TH c="Status" /><TH c="Verification" /><TH c="Fingerprint" /><TH c="Actions" /></tr></thead>
              <tbody>
                {filtered.map((k: any, i: number) => {
                  const res = results[k.id];
                  return (
                    <tr key={i}>
                      <TD c={k.id} mono /><TD c={k.label} /><TD c={k.algorithm} />
                      <TD c={<Badge color={k.status === "active" ? C.green : C.amber}>{k.status}</Badge>} />
                      <TD c={
                        res
                          ? <Badge color={res.valid ? C.green : C.red}>{res.valid ? "Valid" : "Failed"}</Badge>
                          : <Badge color={C.muted}>Unverified</Badge>
                      } />
                      <TD c={res?.fingerprint?.slice(0, 24) ? res.fingerprint.slice(0, 24) + "…" : "—"} mono />
                      <TD c={
                        <Btn small variant="ghost" onClick={() => handleVerify(k.id)} disabled={verifying === k.id}>
                          <ShieldCheck size={11} />{verifying === k.id ? "Verifying…" : "Verify"}
                        </Btn>
                      } />
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
