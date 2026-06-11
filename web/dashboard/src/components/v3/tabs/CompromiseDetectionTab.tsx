// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { ShieldAlert, RefreshCcw, RotateCw, AlertTriangle, CheckCircle2 } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });
const post = (path: string, tok: string, tid: string, body?: any) =>
  fetch(`${base}${path}`, { method: "POST", headers: { ...hdr(tok, tid), "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, variant = "default", small, disabled }: any) => {
  const styles: any = { default: { background: C.accent, color: C.bg }, danger: { background: C.redDim, color: C.red, border: `1px solid ${C.red}33` }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` } };
  return <button onClick={disabled ? undefined : onClick} disabled={disabled} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", opacity: disabled ? 0.5 : 1, ...styles[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;
const Inp = ({ label, ...p }: any) => <div style={{ marginBottom: 12 }}><div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div><input {...p} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box" }} /></div>;

export function CompromiseDetectionTab({ session }: any) {
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [reporting, setReporting] = useState(false);
  const [form, setForm] = useState({ key_id: "", reason: "", severity: "high" });

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const r = await fetch(`${base}/compromise/events`, { headers: hdr(session.token, tid) });
      const d = await r.json().catch(() => ({}));
      setEvents(Array.isArray(d.events) ? d.events : Array.isArray(d) ? d : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleReport = async () => {
    if (!form.key_id || !form.reason) return;
    const tid = session?.tenantId ?? "";
    setReporting(true);
    try {
      await post("/compromise/report", session.token, tid, form);
      setForm({ key_id: "", reason: "", severity: "high" });
      await load();
    } catch (e: any) { setErr(e.message); }
    finally { setReporting(false); }
  };

  const handleRotate = async (keyId: string) => {
    const tid = session?.tenantId ?? "";
    try { await post(`/compromise/keys/${keyId}/rotate`, session.token, tid); await load(); }
    catch (e: any) { setErr(e.message); }
  };

  const severityColor = (s: string) => s === "critical" ? C.red : s === "high" ? "#f97316" : s === "medium" ? C.amber : C.green;
  const fmtDate = (iso?: string) => iso ? new Date(iso).toLocaleString() : "—";

  return (
    <div style={{ padding: 24, maxWidth: 1100 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <ShieldAlert size={20} style={{ color: C.red }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Key Compromise Detection & Response</span>
        </div>
        <Btn onClick={load} small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
        <Card>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 14 }}>Report Compromise</div>
          <Inp label="Key ID" value={form.key_id} onChange={(e: any) => setForm({ ...form, key_id: e.target.value })} placeholder="key_xxxxxxxx" />
          <Inp label="Reason" value={form.reason} onChange={(e: any) => setForm({ ...form, reason: e.target.value })} placeholder="Describe the incident…" />
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Severity</div>
            <select value={form.severity} onChange={(e: any) => setForm({ ...form, severity: e.target.value })} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <Btn onClick={handleReport} disabled={reporting || !form.key_id || !form.reason} variant="danger">
            <AlertTriangle size={12} />{reporting ? "Reporting…" : "Report Compromise"}
          </Btn>
        </Card>

        <Card style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 4 }}>Summary</div>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            {["critical", "high", "medium", "low"].map(s => (
              <div key={s} style={{ textAlign: "center", padding: "10px 16px", borderRadius: 8, background: severityColor(s) + "15", border: `1px solid ${severityColor(s)}30` }}>
                <div style={{ fontSize: 20, fontWeight: 700, color: severityColor(s) }}>{events.filter((e: any) => e.severity === s).length}</div>
                <div style={{ fontSize: 10, color: C.muted, textTransform: "capitalize" }}>{s}</div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 8, color: C.muted, fontSize: 11 }}>
            {events.filter((e: any) => e.status !== "resolved").length} unresolved events
          </div>
        </Card>
      </div>

      <Card>
        <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 }}>Compromise Events</div>
        {events.length === 0 ? (
          <div style={{ color: C.green, fontSize: 12, padding: 16, textAlign: "center", display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}><CheckCircle2 size={14} /> No compromise events recorded.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH c="Key ID" /><TH c="Severity" /><TH c="Reason" /><TH c="Status" /><TH c="Reported At" /><TH c="Actions" /></tr></thead>
              <tbody>
                {events.map((e: any, i: number) => (
                  <tr key={i}>
                    <TD c={e.key_id} mono />
                    <TD c={<Badge color={severityColor(e.severity)}>{e.severity}</Badge>} />
                    <TD c={e.reason} />
                    <TD c={<Badge color={e.status === "resolved" ? C.green : C.red}>{e.status ?? "open"}</Badge>} />
                    <TD c={fmtDate(e.reported_at)} />
                    <TD c={
                      e.status !== "resolved" ? (
                        <Btn small variant="ghost" onClick={() => handleRotate(e.key_id)}><RotateCw size={11} /> Rotate Key</Btn>
                      ) : "—"
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
