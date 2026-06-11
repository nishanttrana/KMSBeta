// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { KeyRound, RefreshCcw, Plus, Play } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });
const jsonHdr = (tok: string, tid: string) => ({ ...hdr(tok, tid), "Content-Type": "application/json" });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` }, amber: { background: C.amberDim, color: C.amber, border: `1px solid ${C.amber}33` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;
const Inp = ({ label, ...p }: any) => <div style={{ marginBottom: 12 }}><div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div><input {...p} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box" }} /></div>;

export function KeyRecoveryTab({ session }: any) {
  const [records, setRecords] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [showEscrow, setShowEscrow] = useState(false);
  const [showRecover, setShowRecover] = useState(false);
  const [escrowForm, setEscrowForm] = useState({ key_id: "", shares: 5, threshold: 3 });
  const [recoverForm, setRecoverForm] = useState({ key_id: "", shares_csv: "" });
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<any>(null);

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const r = await fetch(`${base}/recovery/escrow`, { headers: hdr(session.token, tid) });
      const d = await r.json().catch(() => ({}));
      setRecords(Array.isArray(d.records) ? d.records : Array.isArray(d) ? d : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleEscrow = async () => {
    const tid = session?.tenantId ?? "";
    setSaving(true); setResult(null);
    try {
      const r = await fetch(`${base}/recovery/escrow`, { method: "POST", headers: jsonHdr(session.token, tid), body: JSON.stringify(escrowForm) });
      const d = await r.json();
      setResult(d);
      setShowEscrow(false); await load();
    } catch (e: any) { setErr(e.message); }
    finally { setSaving(false); }
  };

  const handleRecover = async () => {
    const tid = session?.tenantId ?? "";
    setSaving(true); setResult(null);
    try {
      const shares = recoverForm.shares_csv.split(",").map(s => s.trim()).filter(Boolean);
      const r = await fetch(`${base}/recovery/initiate`, { method: "POST", headers: jsonHdr(session.token, tid), body: JSON.stringify({ key_id: recoverForm.key_id, shares }) });
      const d = await r.json();
      setResult(d);
    } catch (e: any) { setErr(e.message); }
    finally { setSaving(false); }
  };

  const fmtDate = (iso?: string) => iso ? new Date(iso).toLocaleString() : "—";

  return (
    <div style={{ padding: 24, maxWidth: 1100 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <KeyRound size={20} style={{ color: C.amber }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Enhanced Key Recovery & Escrow</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn onClick={() => { setShowEscrow(!showEscrow); setShowRecover(false); }} small><Plus size={12} /> Escrow Key</Btn>
          <Btn onClick={() => { setShowRecover(!showRecover); setShowEscrow(false); }} variant="amber" small><Play size={12} /> Recover</Btn>
          <Btn onClick={load} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      {result && (
        <Card style={{ marginBottom: 16, borderColor: C.green + "50" }}>
          <div style={{ fontSize: 12, color: C.green, fontWeight: 600, marginBottom: 8 }}>Operation Result</div>
          {result.shares && (
            <div>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 6 }}>Shamir Shares — store each separately and securely:</div>
              {result.shares.map((s: string, i: number) => (
                <div key={i} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, background: C.bg, padding: "4px 8px", borderRadius: 4, marginBottom: 4, color: C.text, wordBreak: "break-all" }}>
                  Share {i + 1}: {s}
                </div>
              ))}
            </div>
          )}
          {result.recovered && <div style={{ fontSize: 11, color: C.green }}>Key successfully recovered. Ensure it is re-escrowed after use.</div>}
        </Card>
      )}

      {showEscrow && (
        <Card style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 14 }}>Escrow Key (Shamir Split)</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            <Inp label="Key ID" value={escrowForm.key_id} onChange={(e: any) => setEscrowForm({ ...escrowForm, key_id: e.target.value })} placeholder="key_xxxxxxxx" />
            <Inp label="Total Shares" type="number" min={2} max={20} value={escrowForm.shares} onChange={(e: any) => setEscrowForm({ ...escrowForm, shares: +e.target.value })} />
            <Inp label="Threshold (min shares to recover)" type="number" min={2} max={20} value={escrowForm.threshold} onChange={(e: any) => setEscrowForm({ ...escrowForm, threshold: +e.target.value })} />
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <Btn onClick={handleEscrow} disabled={saving || !escrowForm.key_id}>{saving ? "Escrowing…" : "Escrow Key"}</Btn>
            <Btn onClick={() => setShowEscrow(false)} variant="ghost">Cancel</Btn>
          </div>
        </Card>
      )}

      {showRecover && (
        <Card style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 14 }}>Recover Key from Shares</div>
          <Inp label="Key ID" value={recoverForm.key_id} onChange={(e: any) => setRecoverForm({ ...recoverForm, key_id: e.target.value })} placeholder="key_xxxxxxxx" />
          <Inp label="Shares (comma-separated)" value={recoverForm.shares_csv} onChange={(e: any) => setRecoverForm({ ...recoverForm, shares_csv: e.target.value })} placeholder="share1, share2, share3" />
          <div style={{ display: "flex", gap: 8 }}>
            <Btn onClick={handleRecover} disabled={saving || !recoverForm.key_id || !recoverForm.shares_csv} variant="amber">{saving ? "Recovering…" : "Recover Key"}</Btn>
            <Btn onClick={() => setShowRecover(false)} variant="ghost">Cancel</Btn>
          </div>
        </Card>
      )}

      <Card>
        <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 }}>Escrow Records</div>
        {records.length === 0 ? (
          <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No keys in escrow.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Key ID" /><TH c="Shares" /><TH c="Threshold" /><TH c="Status" /><TH c="Escrowed At" /></tr></thead>
              <tbody>
                {records.map((r: any, i: number) => (
                  <tr key={i}>
                    <TD c={r.key_id} mono /><TD c={r.total_shares} /><TD c={r.threshold} />
                    <TD c={<Badge color={r.status === "active" ? C.green : C.amber}>{r.status}</Badge>} />
                    <TD c={fmtDate(r.created_at)} />
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
