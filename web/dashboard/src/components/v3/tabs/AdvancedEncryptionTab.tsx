// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { Lock, RefreshCcw, Unlock } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string) => ({ "Authorization": `Bearer ${tok}` });
const jsonHdr = (tok: string) => ({ ...hdr(tok), "Content-Type": "application/json" });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)` }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default", disabled }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` }, amber: { background: C.amberDim, color: C.amber, border: `1px solid ${C.amber}33` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;
const Inp = ({ label, ...p }: any) => <div style={{ marginBottom: 12 }}><div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div><input {...p} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box" }} /></div>;

const MODES = ["AES-256-GCM", "AES-256-CBC", "ChaCha20-Poly1305", "AES-256-CCM", "AES-256-SIV"];

export function AdvancedEncryptionTab({ session }: any) {
  const [keys, setKeys] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [encForm, setEncForm] = useState({ key_id: "", plaintext: "", mode: "AES-256-GCM", aad: "" });
  const [decForm, setDecForm] = useState({ key_id: "", ciphertext_b64: "", mode: "AES-256-GCM", aad: "", iv_b64: "" });
  const [encResult, setEncResult] = useState<any>(null);
  const [decResult, setDecResult] = useState<any>(null);
  const [working, setWorking] = useState(false);
  const [op, setOp] = useState<"enc" | "dec">("enc");

  const load = useCallback(async () => {
    if (!session?.token) return;
    setLoading(true);
    try {
      const r = await fetch(`${base}/keys`, { headers: hdr(session.token) });
      const d = await r.json().catch(() => ({}));
      setKeys((d.keys ?? d ?? []).filter((k: any) => k.status === "active"));
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token]);

  useEffect(() => { load(); }, [load]);

  const handleEncrypt = async () => {
    setWorking(true); setEncResult(null);
    try {
      const plaintext_b64 = btoa(encForm.plaintext);
      const body: any = { key_id: encForm.key_id, plaintext_b64, mode: encForm.mode };
      if (encForm.aad) body.aad = encForm.aad;
      const r = await fetch(`${base}/encryption/encrypt`, { method: "POST", headers: jsonHdr(session.token), body: JSON.stringify(body) });
      const d = await r.json();
      setEncResult(d);
    } catch (e: any) { setErr(e.message); }
    finally { setWorking(false); }
  };

  const handleDecrypt = async () => {
    setWorking(true); setDecResult(null);
    try {
      const body: any = { key_id: decForm.key_id, ciphertext_b64: decForm.ciphertext_b64, mode: decForm.mode };
      if (decForm.aad) body.aad = decForm.aad;
      if (decForm.iv_b64) body.iv_b64 = decForm.iv_b64;
      const r = await fetch(`${base}/encryption/decrypt`, { method: "POST", headers: jsonHdr(session.token), body: JSON.stringify(body) });
      const d = await r.json();
      setDecResult(d);
    } catch (e: any) { setErr(e.message); }
    finally { setWorking(false); }
  };

  return (
    <div style={{ padding: 24, maxWidth: 1100 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Lock size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Advanced Encryption Modes</span>
        </div>
        <Btn onClick={load} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <button onClick={() => setOp("enc")} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", border: `1px solid ${C.border}`, background: op === "enc" ? C.accent : "transparent", color: op === "enc" ? C.bg : C.dim }}>Encrypt</button>
        <button onClick={() => setOp("dec")} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", border: `1px solid ${C.border}`, background: op === "dec" ? C.accent : "transparent", color: op === "dec" ? C.bg : C.dim }}>Decrypt</button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {op === "enc" ? (
          <Card>
            <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 14 }}>Encrypt Payload</div>
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Key</div>
              <select value={encForm.key_id} onChange={(e: any) => setEncForm({ ...encForm, key_id: e.target.value })} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>
                <option value="">— select key —</option>
                {keys.map((k: any) => <option key={k.id} value={k.id}>{k.label ?? k.id}</option>)}
              </select>
            </div>
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Mode</div>
              <select value={encForm.mode} onChange={(e: any) => setEncForm({ ...encForm, mode: e.target.value })} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>
                {MODES.map(m => <option key={m}>{m}</option>)}
              </select>
            </div>
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Plaintext</div>
              <textarea value={encForm.plaintext} onChange={(e: any) => setEncForm({ ...encForm, plaintext: e.target.value })} rows={4} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", resize: "vertical", boxSizing: "border-box" }} />
            </div>
            <Inp label="AAD (optional)" value={encForm.aad} onChange={(e: any) => setEncForm({ ...encForm, aad: e.target.value })} />
            <Btn onClick={handleEncrypt} disabled={working || !encForm.key_id || !encForm.plaintext}><Lock size={12} />{working ? "Encrypting…" : "Encrypt"}</Btn>
          </Card>
        ) : (
          <Card>
            <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 14 }}>Decrypt Ciphertext</div>
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Key</div>
              <select value={decForm.key_id} onChange={(e: any) => setDecForm({ ...decForm, key_id: e.target.value })} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>
                <option value="">— select key —</option>
                {keys.map((k: any) => <option key={k.id} value={k.id}>{k.label ?? k.id}</option>)}
              </select>
            </div>
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Mode</div>
              <select value={decForm.mode} onChange={(e: any) => setDecForm({ ...decForm, mode: e.target.value })} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>
                {MODES.map(m => <option key={m}>{m}</option>)}
              </select>
            </div>
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Ciphertext (base64)</div>
              <textarea value={decForm.ciphertext_b64} onChange={(e: any) => setDecForm({ ...decForm, ciphertext_b64: e.target.value })} rows={3} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", resize: "vertical", boxSizing: "border-box" }} />
            </div>
            <Inp label="IV/Nonce (base64, if applicable)" value={decForm.iv_b64} onChange={(e: any) => setDecForm({ ...decForm, iv_b64: e.target.value })} />
            <Inp label="AAD (optional)" value={decForm.aad} onChange={(e: any) => setDecForm({ ...decForm, aad: e.target.value })} />
            <Btn onClick={handleDecrypt} disabled={working || !decForm.key_id || !decForm.ciphertext_b64} variant="ghost"><Unlock size={12} />{working ? "Decrypting…" : "Decrypt"}</Btn>
          </Card>
        )}

        <Card>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 }}>Result</div>
          {op === "enc" ? (
            encResult ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div>
                  <div style={{ fontSize: 10, color: C.dim, marginBottom: 4 }}>Ciphertext (base64)</div>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, background: C.bg, padding: "8px 10px", borderRadius: 5, wordBreak: "break-all", color: C.text }}>{encResult.ciphertext_b64}</div>
                </div>
                {encResult.iv_b64 && <div><div style={{ fontSize: 10, color: C.dim, marginBottom: 4 }}>IV/Nonce</div><div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, background: C.bg, padding: "8px 10px", borderRadius: 5, color: C.text, wordBreak: "break-all" }}>{encResult.iv_b64}</div></div>}
                <div style={{ display: "flex", gap: 8 }}><Badge color={C.green}>{encResult.mode ?? encForm.mode}</Badge><Badge color={C.accent}>{encResult.key_id ?? encForm.key_id}</Badge></div>
              </div>
            ) : <div style={{ color: C.muted, fontSize: 12 }}>Encrypt a payload to see results here.</div>
          ) : (
            decResult ? (
              <div>
                <div style={{ fontSize: 10, color: C.dim, marginBottom: 4 }}>Plaintext</div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, background: C.bg, padding: "10px 12px", borderRadius: 5, color: C.green, wordBreak: "break-all" }}>
                  {decResult.plaintext ?? (decResult.plaintext_b64 ? atob(decResult.plaintext_b64) : JSON.stringify(decResult))}
                </div>
              </div>
            ) : <div style={{ color: C.muted, fontSize: 12 }}>Decrypt a ciphertext to see results here.</div>
          )}

          <div style={{ marginTop: 20 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 8 }}>Supported Modes</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {MODES.map(m => <Badge key={m} color={C.accent}>{m}</Badge>)}
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
