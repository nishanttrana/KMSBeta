// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { Network, RefreshCcw, Plus, Trash2, RotateCw } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string) => ({ "Authorization": `Bearer ${tok}` });
const jsonHdr = (tok: string) => ({ ...hdr(tok), "Content-Type": "application/json" });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` }, danger: { background: C.redDim, color: C.red, border: `1px solid ${C.red}33` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;
const Inp = ({ label, ...p }: any) => <div style={{ marginBottom: 12 }}><div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div><input {...p} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box" }} /></div>;

const defForm = { name: "", endpoint: "", tls_cert: "" };

export function KeyFederationTab({ session }: any) {
  const [peers, setPeers] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ ...defForm });
  const [saving, setSaving] = useState(false);
  const [syncing, setSyncing] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!session?.token) return;
    setLoading(true); setErr("");
    try {
      const r = await fetch(`${base}/federation/peers`, { headers: hdr(session.token) });
      const d = await r.json().catch(() => ({}));
      setPeers(d.peers ?? d ?? []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token]);

  useEffect(() => { load(); }, [load]);

  const handleAdd = async () => {
    setSaving(true);
    try {
      const body: any = { name: form.name, endpoint: form.endpoint };
      if (form.tls_cert) body.tls_cert = form.tls_cert;
      await fetch(`${base}/federation/peers`, { method: "POST", headers: jsonHdr(session.token), body: JSON.stringify(body) });
      setShowForm(false); setForm({ ...defForm }); await load();
    } catch (e: any) { setErr(e.message); }
    finally { setSaving(false); }
  };

  const handleSync = async (peerId: string) => {
    setSyncing(peerId);
    try {
      await fetch(`${base}/federation/peers/${peerId}/sync`, { method: "POST", headers: hdr(session.token) });
      await load();
    } catch (e: any) { setErr(e.message); }
    finally { setSyncing(null); }
  };

  const handleRemove = async (peerId: string) => {
    await fetch(`${base}/federation/peers/${peerId}`, { method: "DELETE", headers: hdr(session.token) });
    await load();
  };

  const statusColor = (s: string) => s === "healthy" ? C.green : s === "degraded" ? C.amber : C.red;
  const fmtDate = (iso?: string) => iso ? new Date(iso).toLocaleString() : "—";

  return (
    <div style={{ padding: 24, maxWidth: 1100 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Network size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Key Federation & Multi-KMS Orchestration</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn onClick={() => setShowForm(!showForm)} small><Plus size={12} /> Add Peer</Btn>
          <Btn onClick={load} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      {showForm && (
        <Card style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 14 }}>Add Federation Peer</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Inp label="Peer Name" value={form.name} onChange={(e: any) => setForm({ ...form, name: e.target.value })} placeholder="us-west-kms" />
            <Inp label="Endpoint URL" value={form.endpoint} onChange={(e: any) => setForm({ ...form, endpoint: e.target.value })} placeholder="https://kms.example.com" />
          </div>
          <Inp label="TLS Certificate (PEM, optional)" value={form.tls_cert} onChange={(e: any) => setForm({ ...form, tls_cert: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" />
          <div style={{ display: "flex", gap: 8 }}>
            <Btn onClick={handleAdd} disabled={saving || !form.name || !form.endpoint}>{saving ? "Adding…" : "Add Peer"}</Btn>
            <Btn onClick={() => setShowForm(false)} variant="ghost">Cancel</Btn>
          </div>
        </Card>
      )}

      <Card>
        {peers.length === 0 ? (
          <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No federation peers configured.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Name" /><TH c="Endpoint" /><TH c="Status" /><TH c="Last Sync" /><TH c="Keys Synced" /><TH c="Actions" /></tr></thead>
              <tbody>
                {peers.map((p: any, i: number) => (
                  <tr key={i}>
                    <TD c={p.name} />
                    <TD c={p.endpoint} mono />
                    <TD c={<Badge color={statusColor(p.status)}>{p.status ?? "unknown"}</Badge>} />
                    <TD c={fmtDate(p.last_sync_at)} />
                    <TD c={p.synced_key_count} />
                    <TD c={
                      <div style={{ display: "flex", gap: 6 }}>
                        <Btn small variant="ghost" onClick={() => handleSync(p.id)} disabled={syncing === p.id}><RotateCw size={11} />{syncing === p.id ? "Syncing…" : "Sync"}</Btn>
                        <Btn small variant="danger" onClick={() => handleRemove(p.id)}><Trash2 size={11} /></Btn>
                      </div>
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
