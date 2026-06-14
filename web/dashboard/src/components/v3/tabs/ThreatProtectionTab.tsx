// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { Shield, RefreshCcw, Plus, CheckCircle2, AlertTriangle, XCircle } from "lucide-react";
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

// configOnly renders just the canary-key management surface (no signals list,
// summary cards or view toggle) for embedding inside the unified Threat &
// Exposure console, whose Triage view already covers threat signals.
export function ThreatProtectionTab({ session, configOnly }: any) {
  const [signals, setSignals] = useState<any[]>([]);
  const [canaryKeys, setCanaryKeys] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [view, setView] = useState<"signals" | "canary">(configOnly ? "canary" : "signals");
  const [showCanaryForm, setShowCanaryForm] = useState(false);
  const [canaryForm, setCanaryForm] = useState({ label: "", alert_on_use: true });
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const [sRes, cRes] = await Promise.all([
        fetch(`${base}/threat/signals`, { headers: hdr(session.token, tid) }),
        fetch(`${base}/canary/keys`, { headers: hdr(session.token, tid) }),
      ]);
      const s = await sRes.json().catch(() => ({}));
      const c = await cRes.json().catch(() => ({}));
      setSignals(Array.isArray(s.signals) ? s.signals : Array.isArray(s) ? s : []);
      setCanaryKeys(Array.isArray(c.canary_keys) ? c.canary_keys : Array.isArray(c) ? c : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleAck = async (id: string) => {
    const tid = session?.tenantId ?? "";
    await fetch(`${base}/threat/signals/${id}/ack`, { method: "POST", headers: hdr(session.token, tid) });
    await load();
  };

  const handleCreateCanary = async () => {
    const tid = session?.tenantId ?? "";
    setSaving(true);
    try {
      await fetch(`${base}/canary/keys`, { method: "POST", headers: jsonHdr(session.token, tid), body: JSON.stringify(canaryForm) });
      setShowCanaryForm(false); setCanaryForm({ label: "", alert_on_use: true }); await load();
    } catch (e: any) { setErr(e.message); }
    finally { setSaving(false); }
  };

  const sevColor = (s: string) => s === "critical" ? C.red : s === "high" ? "#f97316" : s === "medium" ? C.amber : C.green;
  const fmtDate = (iso?: string) => iso ? new Date(iso).toLocaleString() : "—";
  const active = signals.filter((s: any) => !s.acknowledged_at);

  return (
    <div style={{ padding: 24, maxWidth: 1200 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Shield size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Advanced Threat Protection</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {view === "canary" && <Btn onClick={() => setShowCanaryForm(!showCanaryForm)} small><Plus size={12} /> Add Canary</Btn>}
          <Btn onClick={load} variant="ghost" small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      {!configOnly && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))", gap: 12, marginBottom: 20 }}>
          {[
            { label: "Critical", val: signals.filter((s: any) => s.severity === "critical" && !s.acknowledged_at).length, color: C.red, icon: XCircle },
            { label: "High", val: signals.filter((s: any) => s.severity === "high" && !s.acknowledged_at).length, color: "#f97316", icon: AlertTriangle },
            { label: "Medium", val: signals.filter((s: any) => s.severity === "medium" && !s.acknowledged_at).length, color: C.amber, icon: AlertTriangle },
            { label: "Acknowledged", val: signals.filter((s: any) => s.acknowledged_at).length, color: C.green, icon: CheckCircle2 },
            { label: "Canary Keys", val: canaryKeys.length, color: C.accent, icon: Shield },
          ].map(({ label, val, color, icon: Icon }: any) => (
            <Card key={label} style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ background: color + "18", borderRadius: 8, padding: 8 }}><Icon size={14} style={{ color }} /></div>
              <div><div style={{ fontSize: 18, fontWeight: 700, color }}>{val}</div><div style={{ fontSize: 10, color: C.muted }}>{label}</div></div>
            </Card>
          ))}
        </div>
      )}

      {!configOnly && (
        <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
          {(["signals", "canary"] as const).map(v => (
            <button key={v} onClick={() => setView(v)} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", border: `1px solid ${C.border}`, background: view === v ? C.accent : "transparent", color: view === v ? C.bg : C.dim }}>
              {v === "signals" ? `Threat Signals (${active.length} active)` : `Canary Keys (${canaryKeys.length})`}
            </button>
          ))}
        </div>
      )}

      {view === "signals" ? (
        <Card>
          {active.length === 0 ? (
            <div style={{ color: C.green, fontSize: 12, padding: 16, textAlign: "center", display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}><CheckCircle2 size={14} /> No active threat signals.</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr><TH c="Type" /><TH c="Key ID" /><TH c="Severity" /><TH c="Description" /><TH c="Detected" /><TH c="Actions" /></tr></thead>
                <tbody>
                  {signals.map((s: any, i: number) => (
                    <tr key={i}>
                      <TD c={<Badge color={sevColor(s.severity)}>{s.signal_type ?? s.type}</Badge>} />
                      <TD c={s.key_id} mono />
                      <TD c={<Badge color={sevColor(s.severity)}>{s.severity}</Badge>} />
                      <TD c={s.description} />
                      <TD c={fmtDate(s.detected_at ?? s.created_at)} />
                      <TD c={
                        !s.acknowledged_at
                          ? <Btn small variant="ghost" onClick={() => handleAck(s.id)}><CheckCircle2 size={11} /> Acknowledge</Btn>
                          : <span style={{ color: C.muted, fontSize: 11 }}>Acked {fmtDate(s.acknowledged_at)}</span>
                      } />
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      ) : (
        <>
          {showCanaryForm && (
            <Card style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 12 }}>Add Canary Key</div>
              <Inp label="Label" value={canaryForm.label} onChange={(e: any) => setCanaryForm({ ...canaryForm, label: e.target.value })} placeholder="canary-prod-01" />
              <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", marginBottom: 12 }}>
                <input type="checkbox" checked={canaryForm.alert_on_use} onChange={(e: any) => setCanaryForm({ ...canaryForm, alert_on_use: e.target.checked })} />
                <span style={{ fontSize: 12, color: C.text }}>Alert immediately on any use</span>
              </label>
              <div style={{ display: "flex", gap: 8 }}>
                <Btn onClick={handleCreateCanary} disabled={saving || !canaryForm.label}>{saving ? "Creating…" : "Create Canary"}</Btn>
                <Btn onClick={() => setShowCanaryForm(false)} variant="ghost">Cancel</Btn>
              </div>
            </Card>
          )}
          <Card>
            {canaryKeys.length === 0 ? (
              <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No canary keys. Create honeypot keys to detect unauthorized access attempts.</div>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead><tr><TH c="Label" /><TH c="Key ID" /><TH c="Alert on Use" /><TH c="Triggered" /><TH c="Last Triggered" /></tr></thead>
                  <tbody>
                    {canaryKeys.map((k: any, i: number) => (
                      <tr key={i}>
                        <TD c={k.label} />
                        <TD c={k.key_id ?? k.id} mono />
                        <TD c={<Badge color={k.alert_on_use ? C.green : C.muted}>{k.alert_on_use ? "Yes" : "No"}</Badge>} />
                        <TD c={k.trigger_count ?? 0} />
                        <TD c={fmtDate(k.last_triggered_at)} />
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
