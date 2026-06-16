// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { ShieldCheck, RefreshCcw, Search, CheckCircle2, XCircle, FileBadge, Download, Copy, X } from "lucide-react";
import { C } from "../../v3/theme";
import { listKeys } from "../../../lib/keycore";

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
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const [search, setSearch] = useState("");
  const [attestation, setAttestation] = useState<any>(null);

  const load = useCallback(async () => {
    if (!session?.token) return;
    setLoading(true); setErr("");
    try {
      const items = await listKeys(session, { limit: 2000 });
      setKeys(Array.isArray(items) ? items : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session]);

  useEffect(() => { load(); }, [load]);

  const handleVerify = async (keyId: string) => {
    const tid = session?.tenantId ?? "";
    setBusy(keyId + ":v");
    try {
      const r = await fetch(`${base}/keys/${keyId}/verify-material`, { method: "POST", headers: hdr(session.token, tid) });
      const d = await r.json();
      setResults(prev => ({ ...prev, [keyId]: d.result ?? d }));
    } catch (e: any) {
      setResults(prev => ({ ...prev, [keyId]: { verified: false, detail: e.message } }));
    } finally { setBusy(null); }
  };

  const handleAttest = async (keyId: string) => {
    const tid = session?.tenantId ?? "";
    setBusy(keyId + ":a");
    try {
      const r = await fetch(`${base}/keys/${keyId}/attest`, { method: "POST", headers: hdr(session.token, tid) });
      const d = await r.json();
      if (!r.ok) throw new Error(d?.error?.message ?? "Attestation failed");
      setAttestation(d.attestation ?? d);
      // reflect the integrity result the attestation carried
      if (d.attestation?.statement) {
        const st = d.attestation.statement;
        setResults(prev => ({ ...prev, [keyId]: { verified: st.integrity_verified, detail: st.integrity_detail, kcv_checked: !!st.kcv } }));
      }
    } catch (e: any) { setErr(e.message); }
    finally { setBusy(null); }
  };

  const handleVerifyAll = async () => {
    for (const k of filtered.slice(0, 25)) { await handleVerify(k.id); }
  };

  const filtered = keys.filter((k: any) => {
    const q = search.trim().toLowerCase();
    return !q || k.id?.toLowerCase().includes(q) || k.name?.toLowerCase().includes(q);
  });
  const verifiedCount = Object.values(results).filter((r: any) => r.verified).length;
  const failedCount = Object.values(results).filter((r: any) => r.verified === false).length;

  const copyAttestation = () => navigator.clipboard?.writeText(JSON.stringify(attestation, null, 2));
  const downloadAttestation = () => {
    const blob = new Blob([JSON.stringify(attestation, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `attestation-${attestation?.statement?.key_id ?? "key"}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div style={{ padding: 24, maxWidth: 1180 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <ShieldCheck size={20} style={{ color: C.green }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Key Verification &amp; Attestation</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn onClick={handleVerifyAll} small>Verify All Visible</Btn>
          <Btn onClick={load} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>
      <div style={{ fontSize: 12, color: C.muted, marginBottom: 20 }}>
        Verify recomputes each key's KCV from its live material under the master key (detects corruption, tampering, or a wrong MEK). Attest issues a signed, offline-verifiable statement of the key's properties and integrity.
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
        <input value={search} onChange={(e: any) => setSearch(e.target.value)} placeholder="Filter by key ID or name…" style={{ background: "none", border: "none", outline: "none", color: C.text, fontSize: 12, flex: 1 }} />
      </div>

      <Card>
        {filtered.length === 0 ? (
          <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>{loading ? "Loading keys…" : "No keys found."}</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Key ID" /><TH c="Name" /><TH c="Algorithm" /><TH c="Status" /><TH c="Integrity" /><TH c="Detail" /><TH c="Actions" /></tr></thead>
              <tbody>
                {filtered.map((k: any, i: number) => {
                  const res = results[k.id];
                  return (
                    <tr key={i}>
                      <TD c={k.id} mono /><TD c={k.name} /><TD c={k.algorithm} />
                      <TD c={<Badge color={k.status === "active" ? C.green : C.amber}>{k.status}</Badge>} />
                      <TD c={
                        res
                          ? <Badge color={res.verified ? C.green : C.red}>{res.verified ? (res.kcv_checked ? "KCV verified" : "Verified") : "FAILED"}</Badge>
                          : <Badge color={C.muted}>Unverified</Badge>
                      } />
                      <TD c={res?.detail ?? "—"} />
                      <TD c={
                        <div style={{ display: "flex", gap: 6 }}>
                          <Btn small variant="ghost" onClick={() => handleVerify(k.id)} disabled={busy === k.id + ":v"}>
                            <ShieldCheck size={11} />{busy === k.id + ":v" ? "…" : "Verify"}
                          </Btn>
                          <Btn small onClick={() => handleAttest(k.id)} disabled={busy === k.id + ":a"}>
                            <FileBadge size={11} />{busy === k.id + ":a" ? "…" : "Attest"}
                          </Btn>
                        </div>
                      } />
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {attestation && (
        <div onClick={() => setAttestation(null)} style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 50, padding: 24 }}>
          <div onClick={(e: any) => e.stopPropagation()} style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 20, width: 720, maxWidth: "100%", maxHeight: "80vh", overflowY: "auto" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 14, fontWeight: 700, color: C.text }}><FileBadge size={16} style={{ color: C.accent }} /> Signed Key Attestation</div>
              <Btn small variant="ghost" onClick={() => setAttestation(null)}><X size={12} /></Btn>
            </div>
            <div style={{ fontSize: 11, color: C.muted, marginBottom: 10 }}>
              {attestation.signing_algorithm} · pubkey {String(attestation.public_key_fingerprint).slice(0, 16)}… · verify offline against <code style={{ color: C.accent }}>GET /attestation/public-key</code>
            </div>
            <pre style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 6, padding: 12, fontSize: 10, color: C.text, overflowX: "auto", maxHeight: "48vh" }}>{JSON.stringify(attestation, null, 2)}</pre>
            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <Btn small onClick={downloadAttestation}><Download size={11} /> Download</Btn>
              <Btn small variant="ghost" onClick={copyAttestation}><Copy size={11} /> Copy</Btn>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
