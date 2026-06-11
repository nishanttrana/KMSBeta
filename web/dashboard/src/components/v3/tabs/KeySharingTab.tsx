// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { Share2, RefreshCcw, Plus, XCircle } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });
const jsonHdr = (tok: string, tid: string) => ({ ...hdr(tok, tid), "Content-Type": "application/json" });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` }, danger: { background: C.redDim, color: C.red, border: `1px solid ${C.red}33` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;
const Inp = ({ label, ...p }: any) => <div style={{ marginBottom: 12 }}><div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div><input {...p} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box" }} /></div>;

const defForm = { key_id: "", grantee_email: "", permissions: "encrypt,decrypt", expires_at: "", max_uses: 0 };

export function KeySharingTab({ session }: any) {
  const [tokens, setTokens] = useState<any[]>([]);
  const [keys, setKeys] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ ...defForm });
  const [saving, setSaving] = useState(false);
  const [newToken, setNewToken] = useState<any>(null);

  const loadAll = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const [tRes, kRes] = await Promise.all([
        fetch(`${base}/sharing/tokens`, { headers: hdr(session.token, tid) }),
        fetch(`${base}/keys`, { headers: hdr(session.token, tid) }),
      ]);
      const t = await tRes.json().catch(() => ({}));
      const k = await kRes.json().catch(() => ({}));
      setTokens(Array.isArray(t.tokens) ? t.tokens : Array.isArray(t) ? t : []);
      setKeys((Array.isArray(k.keys) ? k.keys : Array.isArray(k) ? k : []).filter((k: any) => k.status === "active"));
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { loadAll(); }, [loadAll]);

  const handleCreate = async () => {
    if (!form.key_id) return;
    const tid = session?.tenantId ?? "";
    setSaving(true); setNewToken(null);
    try {
      const body: any = { permissions: form.permissions.split(",").map((p: string) => p.trim()).filter(Boolean) };
      if (form.grantee_email) body.grantee_email = form.grantee_email;
      if (form.expires_at) body.expires_at = new Date(form.expires_at).toISOString();
      if (form.max_uses) body.max_uses = form.max_uses;
      const r = await fetch(`${base}/keys/${form.key_id}/sharing-tokens`, { method: "POST", headers: jsonHdr(session.token, tid), body: JSON.stringify(body) });
      const d = await r.json();
      setNewToken(d);
      setShowForm(false); setForm({ ...defForm }); await loadAll();
    } catch (e: any) { setErr(e.message); }
    finally { setSaving(false); }
  };

  const handleRevoke = async (keyId: string, tokenId: string) => {
    const tid = session?.tenantId ?? "";
    try {
      await fetch(`${base}/keys/${keyId}/sharing-tokens/${tokenId}/revoke`, { method: "POST", headers: hdr(session.token, tid) });
      await loadAll();
    } catch (e: any) { setErr(e.message); }
  };

  const fmtDate = (iso?: string) => iso ? new Date(iso).toLocaleString() : "—";
  const active = tokens.filter((t: any) => !t.revoked_at);

  return (
    <div style={{ padding: 24, maxWidth: 1200 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Share2 size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Fine-Grained Key Sharing</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn onClick={() => setShowForm(!showForm)} small><Plus size={12} /> Create Share</Btn>
          <Btn onClick={loadAll} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      {newToken && (
        <Card style={{ marginBottom: 16, borderColor: C.green + "50" }}>
          <div style={{ fontSize: 12, color: C.green, fontWeight: 600, marginBottom: 6 }}>Share token created — copy and send to grantee:</div>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, background: C.bg, padding: "8px 12px", borderRadius: 5, color: C.text, wordBreak: "break-all" }}>{newToken.token ?? newToken.share_token}</div>
          <Btn small variant="ghost" onClick={() => setNewToken(null)} style={{ marginTop: 8 }}>Dismiss</Btn>
        </Card>
      )}

      {showForm && (
        <Card style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 14 }}>Create Sharing Token</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Key to Share</div>
              <select value={form.key_id} onChange={(e: any) => setForm({ ...form, key_id: e.target.value })} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>
                <option value="">— select key —</option>
                {keys.map((k: any) => <option key={k.id} value={k.id}>{k.label ?? k.id}</option>)}
              </select>
            </div>
            <Inp label="Grantee Email (optional)" type="email" value={form.grantee_email} onChange={(e: any) => setForm({ ...form, grantee_email: e.target.value })} placeholder="user@example.com" />
            <Inp label="Permissions (comma-separated)" value={form.permissions} onChange={(e: any) => setForm({ ...form, permissions: e.target.value })} placeholder="encrypt, decrypt, sign" />
            <Inp label="Expires At (optional)" type="datetime-local" value={form.expires_at} onChange={(e: any) => setForm({ ...form, expires_at: e.target.value })} />
            <Inp label="Max Uses (0 = unlimited)" type="number" min={0} value={form.max_uses} onChange={(e: any) => setForm({ ...form, max_uses: +e.target.value })} />
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <Btn onClick={handleCreate} disabled={saving || !form.key_id}>{saving ? "Creating…" : "Create Token"}</Btn>
            <Btn onClick={() => setShowForm(false)} variant="ghost">Cancel</Btn>
          </div>
        </Card>
      )}

      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <Badge color={C.green}>{active.length} active</Badge>
        <Badge color={C.muted}>{tokens.length - active.length} revoked</Badge>
      </div>

      <Card>
        {tokens.length === 0 ? (
          <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No sharing tokens. Create one to grant fine-grained access.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Key ID" /><TH c="Grantee" /><TH c="Permissions" /><TH c="Uses" /><TH c="Expires" /><TH c="Status" /><TH c="Actions" /></tr></thead>
              <tbody>
                {tokens.map((t: any, i: number) => (
                  <tr key={i}>
                    <TD c={t.key_id} mono />
                    <TD c={t.grantee_email ?? "—"} />
                    <TD c={(t.permissions ?? []).map((p: string) => <Badge key={p} color={C.accent}>{p}</Badge>)} />
                    <TD c={t.use_count != null ? `${t.use_count}${t.max_uses ? `/${t.max_uses}` : ""}` : "—"} />
                    <TD c={fmtDate(t.expires_at)} />
                    <TD c={<Badge color={t.revoked_at ? C.red : C.green}>{t.revoked_at ? "revoked" : "active"}</Badge>} />
                    <TD c={
                      !t.revoked_at
                        ? <Btn small variant="danger" onClick={() => handleRevoke(t.key_id, t.id)}><XCircle size={11} /> Revoke</Btn>
                        : "—"
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
