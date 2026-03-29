// @ts-nocheck
import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle, Shield, Activity, Clock, Plus, RefreshCcw,
  Trash2, Play, ChevronDown, ChevronRight, Eye, CheckCircle2, XCircle
} from "lucide-react";
import { C } from "../../v3/theme";

// ── helpers ──────────────────────────────────────────────────────────────────

function fmtDate(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function fmtAgo(iso?: string): string {
  if (!iso) return "—";
  const diff = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

const base = "/svc/keycore";

async function apiGet(path: string, tenantId: string) {
  const r = await fetch(`${base}${path}`, { headers: { "X-Tenant-ID": tenantId } });
  return r.json();
}

async function apiPost(path: string, tenantId: string, body: any) {
  const r = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Tenant-ID": tenantId },
    body: JSON.stringify(body),
  });
  return r.json();
}

async function apiDelete(path: string, tenantId: string) {
  const r = await fetch(`${base}${path}`, { method: "DELETE", headers: { "X-Tenant-ID": tenantId } });
  return r.json();
}

// ── shared primitives ─────────────────────────────────────────────────────────

const TH = ({ children }: any) => (
  <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}`, whiteSpace: "nowrap" }}>{children}</th>
);
const TD = ({ children, mono }: any) => (
  <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{children}</td>
);
const Badge = ({ color, children }: any) => (
  <span style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600, textTransform: "capitalize", letterSpacing: 0.3 }}>{children}</span>
);
const Btn = ({ onClick, children, variant = "default", disabled = false, small = false }: any) => {
  const base: any = { display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: small ? 11 : 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", transition: "opacity .15s", opacity: disabled ? 0.5 : 1 };
  const styles: any = {
    default: { background: C.accent, color: C.bg },
    ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` },
    danger: { background: C.redDim, color: C.red, border: `1px solid ${C.red}33` },
    amber: { background: C.amberDim, color: C.amber, border: `1px solid ${C.amber}33` },
  };
  return <button onClick={disabled ? undefined : onClick} style={{ ...base, ...styles[variant] }}>{children}</button>;
};
const Inp = ({ label, ...props }: any) => (
  <div style={{ marginBottom: 12 }}>
    {label && <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div>}
    <input {...props} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box", ...props.style }} />
  </div>
);
const Sel = ({ label, children, ...props }: any) => (
  <div style={{ marginBottom: 12 }}>
    {label && <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div>}
    <select {...props} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box", ...props.style }}>{children}</select>
  </div>
);
const Txt = ({ label, ...props }: any) => (
  <div style={{ marginBottom: 12 }}>
    {label && <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div>}
    <textarea {...props} rows={props.rows || 3} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", resize: "vertical", boxSizing: "border-box", fontFamily: "inherit", ...props.style }} />
  </div>
);
const StatCard = ({ icon, label, value, color = C.accent, tint, sublabel }: any) => (
  <div style={{ flex: 1, minWidth: 150, background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "14px 16px", display: "flex", flexDirection: "column", gap: 6, backgroundImage: tint ? `linear-gradient(135deg, ${tint}, transparent)` : undefined }}>
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <span style={{ color }}>{icon}</span>
      <span style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, fontWeight: 600 }}>{label}</span>
    </div>
    <div style={{ fontSize: 22, fontWeight: 700, color, letterSpacing: -0.5 }}>{value}</div>
    {sublabel && <div style={{ fontSize: 10, color: C.muted }}>{sublabel}</div>}
  </div>
);

const purposeLabel: Record<string, string> = {
  detect_exfiltration: "Exfiltration Detection",
  detect_unauthorized_access: "Unauthorized Access",
  honeypot: "Honeypot",
};

// ── main component ────────────────────────────────────────────────────────────

export function CanaryKeysTab({ session }: { session: any }) {
  const tenantId = session?.tenantId || "";
  const [view, setView] = useState<"overview" | "canaries" | "create">("overview");
  const [canaries, setCanaries] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [recentTrips, setRecentTrips] = useState<any[]>([]);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [rowTrips, setRowTrips] = useState<Record<string, any[]>>({});
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState("");

  // create form state
  const [form, setForm] = useState({ name: "", algorithm: "AES-256-GCM", purpose: "detect_exfiltration", notify_email: "", description: "" });
  const [creating, setCreating] = useState(false);

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(""), 3500);
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [keysRes, summaryRes] = await Promise.all([
        apiGet("/canary", tenantId),
        apiGet("/canary/summary", tenantId),
      ]);
      setCanaries(keysRes.data || []);
      setSummary(summaryRes.data || {});
      // Collect recent trips from the top 3 most recently tripped canaries.
      const tripped = (keysRes.data || []).filter((c: any) => c.trip_count > 0).slice(0, 3);
      const tripResults = await Promise.all(
        tripped.map((c: any) => apiGet(`/canary/${c.id}/trips?limit=5`, tenantId))
      );
      const allTrips = tripResults.flatMap((r: any) => r.data || []);
      allTrips.sort((a: any, b: any) => new Date(b.tripped_at).getTime() - new Date(a.tripped_at).getTime());
      setRecentTrips(allTrips.slice(0, 10));
    } catch (e) {
      // ignore
    } finally {
      setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => { load(); }, [load]);

  const toggleRow = async (id: string) => {
    const next = new Set(expandedRows);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
      if (!rowTrips[id]) {
        const res = await apiGet(`/canary/${id}/trips?limit=10`, tenantId);
        setRowTrips(prev => ({ ...prev, [id]: res.data || [] }));
      }
    }
    setExpandedRows(next);
  };

  const handleDeactivate = async (id: string) => {
    if (!window.confirm("Deactivate this canary key?")) return;
    await apiDelete(`/canary/${id}`, tenantId);
    showToast("Canary key deactivated.");
    load();
  };

  const handleTestTrip = async (id: string) => {
    const res = await apiPost(`/canary/${id}/trip`, tenantId, {});
    if (res.data) showToast("Canary tripped! Alert event recorded.");
    else showToast("Trip failed: " + (res.message || "unknown error"));
    load();
  };

  const handleCreate = async () => {
    if (!form.name) { showToast("Name is required."); return; }
    setCreating(true);
    try {
      const res = await apiPost("/canary", tenantId, {
        tenant_id: tenantId,
        name: form.name,
        algorithm: form.algorithm,
        purpose: form.purpose,
        notify_email: form.notify_email,
        metadata: form.description ? { description: form.description } : {},
      });
      if (res.data?.id) {
        showToast(`Canary key "${form.name}" deployed.`);
        setForm({ name: "", algorithm: "AES-256-GCM", purpose: "detect_exfiltration", notify_email: "", description: "" });
        setView("canaries");
        load();
      } else {
        showToast("Create failed: " + (res.message || "unknown error"));
      }
    } finally {
      setCreating(false);
    }
  };

  const trips24h = summary?.trips_24h || 0;

  return (
    <div style={{ padding: "24px 28px", maxWidth: 1200, margin: "0 auto" }}>
      {/* Toast */}
      {toast && (
        <div style={{ position: "fixed", bottom: 24, right: 24, background: C.card, border: `1px solid ${C.borderHi}`, borderRadius: 8, padding: "10px 16px", color: C.text, fontSize: 12, zIndex: 999, boxShadow: "0 8px 24px rgba(0,0,0,.4)" }}>
          {toast}
        </div>
      )}

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <AlertTriangle size={20} color={C.amber} />
          <span style={{ fontSize: 18, fontWeight: 700, color: C.text, letterSpacing: -0.4 }}>Canary / Honeypot Keys</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {(["overview", "canaries", "create"] as const).map(v => (
            <Btn key={v} variant={view === v ? "default" : "ghost"} small onClick={() => setView(v)}>
              {v === "create" ? <><Plus size={12} /> Deploy</>
               : v === "canaries" ? <><Shield size={12} /> Keys</>
               : <><Activity size={12} /> Overview</>}
            </Btn>
          ))}
          <Btn variant="ghost" small onClick={load}><RefreshCcw size={12} /></Btn>
        </div>
      </div>

      {/* Alert banner */}
      {trips24h > 0 && (
        <div style={{ background: C.redDim, border: `1px solid ${C.red}44`, borderRadius: 8, padding: "10px 14px", marginBottom: 20, display: "flex", alignItems: "center", gap: 8, color: C.red }}>
          <AlertTriangle size={16} />
          <span style={{ fontSize: 12, fontWeight: 600 }}>ALERT: {trips24h} canary trip{trips24h > 1 ? "s" : ""} detected in the last 24 hours — potential insider threat or key exfiltration attempt.</span>
        </div>
      )}

      {/* ── OVERVIEW ── */}
      {view === "overview" && (
        <>
          {/* Stat cards */}
          <div style={{ display: "flex", gap: 14, marginBottom: 24, flexWrap: "wrap" }}>
            <StatCard icon={<Shield size={16} />} label="Total Canaries" value={summary?.total_canaries ?? "—"} color={C.accent} tint={C.accentTint} />
            <StatCard icon={<AlertTriangle size={16} />} label="Trips (24h)" value={trips24h} color={trips24h > 0 ? C.red : C.green} tint={trips24h > 0 ? C.redTint : C.greenTint} />
            <StatCard icon={<Activity size={16} />} label="Total Trips" value={summary?.total_trips ?? "—"} color={C.amber} tint={C.amberTint} />
            <StatCard icon={<Clock size={16} />} label="Most Recent Trip" value={summary?.most_recent_trip ? fmtAgo(summary.most_recent_trip) : "None"} color={C.muted} sublabel={summary?.most_recent_canary_id ? `canary: ${summary.most_recent_canary_id}` : undefined} />
          </div>

          {/* Recent Trips Table */}
          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden", marginBottom: 24 }}>
            <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 8 }}>
              <AlertTriangle size={14} color={C.red} />
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Recent Trips</span>
            </div>
            {recentTrips.length === 0 ? (
              <div style={{ padding: 24, textAlign: "center", color: C.muted, fontSize: 12 }}>No trips recorded yet. Canary keys are armed and monitoring.</div>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr><TH>Canary ID</TH><TH>Actor ID</TH><TH>Actor IP</TH><TH>Tripped At</TH><TH>Severity</TH></tr></thead>
                <tbody>
                  {recentTrips.map((t: any) => (
                    <tr key={t.id}>
                      <TD mono>{t.canary_id}</TD>
                      <TD>{t.actor_id || "—"}</TD>
                      <TD mono>{t.actor_ip || "—"}</TD>
                      <TD>{fmtDate(t.tripped_at)}</TD>
                      <TD><Badge color={C.red}>{t.severity || "critical"}</Badge></TD>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Active Canaries mini-list */}
          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
            <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 8 }}>
              <Shield size={14} color={C.accent} />
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Active Canaries</span>
            </div>
            {canaries.filter((c: any) => c.active).length === 0 ? (
              <div style={{ padding: 20, textAlign: "center", color: C.muted, fontSize: 12 }}>No active canary keys. <span style={{ color: C.accent, cursor: "pointer" }} onClick={() => setView("create")}>Deploy one now.</span></div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column" }}>
                {canaries.filter((c: any) => c.active).map((c: any) => (
                  <div key={c.id} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 16px", borderBottom: `1px solid rgba(26,41,68,.5)` }}>
                    <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                      <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{c.name}</span>
                      <span style={{ fontSize: 10, color: C.muted }}>{purposeLabel[c.purpose] || c.purpose} · {c.algorithm}</span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      {c.last_tripped ? (
                        <Badge color={C.red}>Tripped {fmtAgo(c.last_tripped)}</Badge>
                      ) : (
                        <Badge color={C.green}>Armed</Badge>
                      )}
                      <span style={{ fontSize: 10, color: C.muted }}>{c.trip_count} trips</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}

      {/* ── CANARIES VIEW ── */}
      {view === "canaries" && (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
          <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Shield size={14} color={C.accent} />
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>All Canary Keys</span>
            </div>
            <Btn variant="default" small onClick={() => setView("create")}><Plus size={11} /> Deploy New</Btn>
          </div>
          {canaries.length === 0 ? (
            <div style={{ padding: 32, textAlign: "center", color: C.muted, fontSize: 12 }}>No canary keys found. Deploy your first honeypot key to start monitoring.</div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH></TH><TH>Name</TH><TH>Algorithm</TH><TH>Purpose</TH><TH>Trips</TH><TH>Last Tripped</TH><TH>Status</TH><TH>Actions</TH></tr></thead>
              <tbody>
                {canaries.map((c: any) => (
                  <>
                    <tr key={c.id}>
                      <TD>
                        <button onClick={() => toggleRow(c.id)} style={{ background: "none", border: "none", cursor: "pointer", color: C.muted, padding: 0 }}>
                          {expandedRows.has(c.id) ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                        </button>
                      </TD>
                      <TD><span style={{ fontWeight: 600 }}>{c.name}</span></TD>
                      <TD mono>{c.algorithm}</TD>
                      <TD>{purposeLabel[c.purpose] || c.purpose}</TD>
                      <TD><span style={{ color: c.trip_count > 0 ? C.red : C.muted, fontWeight: c.trip_count > 0 ? 700 : 400 }}>{c.trip_count}</span></TD>
                      <TD>{c.last_tripped ? fmtDate(c.last_tripped) : "Never"}</TD>
                      <TD>
                        {c.active
                          ? <Badge color={C.green}><CheckCircle2 size={9} /> Active</Badge>
                          : <Badge color={C.muted}><XCircle size={9} /> Inactive</Badge>}
                      </TD>
                      <TD>
                        <div style={{ display: "flex", gap: 6 }}>
                          <Btn variant="ghost" small onClick={() => toggleRow(c.id)}><Eye size={11} /> Trips</Btn>
                          <Btn variant="amber" small onClick={() => handleTestTrip(c.id)} disabled={!c.active}><Play size={11} /> Test</Btn>
                          <Btn variant="danger" small onClick={() => handleDeactivate(c.id)} disabled={!c.active}><Trash2 size={11} /> Deactivate</Btn>
                        </div>
                      </TD>
                    </tr>
                    {expandedRows.has(c.id) && (
                      <tr key={c.id + "_trips"}>
                        <td colSpan={8} style={{ padding: "0 0 0 32px", background: C.bg }}>
                          <div style={{ padding: "12px 16px" }}>
                            <div style={{ fontSize: 10, color: C.muted, fontWeight: 600, marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.6 }}>Trip History</div>
                            {(rowTrips[c.id] || []).length === 0 ? (
                              <div style={{ fontSize: 11, color: C.muted }}>No trips recorded for this canary.</div>
                            ) : (
                              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                                <thead><tr><TH>Trip ID</TH><TH>Actor ID</TH><TH>Actor IP</TH><TH>User Agent</TH><TH>Tripped At</TH></tr></thead>
                                <tbody>
                                  {(rowTrips[c.id] || []).map((t: any) => (
                                    <tr key={t.id}>
                                      <TD mono>{t.id}</TD>
                                      <TD>{t.actor_id || "—"}</TD>
                                      <TD mono>{t.actor_ip || "—"}</TD>
                                      <TD><span style={{ color: C.dim, fontSize: 10 }}>{t.user_agent?.substring(0, 40) || "—"}</span></TD>
                                      <TD>{fmtDate(t.tripped_at)}</TD>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── CREATE VIEW ── */}
      {view === "create" && (
        <div style={{ maxWidth: 560 }}>
          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "20px 24px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 20 }}>
              <AlertTriangle size={16} color={C.amber} />
              <span style={{ fontSize: 14, fontWeight: 700, color: C.text }}>Deploy Canary Key</span>
            </div>
            <Inp label="Name *" placeholder="e.g. prod-exfil-canary-01" value={form.name} onChange={(e: any) => setForm(p => ({ ...p, name: e.target.value }))} />
            <Sel label="Algorithm" value={form.algorithm} onChange={(e: any) => setForm(p => ({ ...p, algorithm: e.target.value }))}>
              <option value="AES-256-GCM">AES-256-GCM</option>
              <option value="RSA-4096">RSA-4096</option>
              <option value="ECDSA-P384">ECDSA-P384</option>
            </Sel>
            <Sel label="Purpose" value={form.purpose} onChange={(e: any) => setForm(p => ({ ...p, purpose: e.target.value }))}>
              <option value="detect_exfiltration">Detect Exfiltration</option>
              <option value="detect_unauthorized_access">Detect Unauthorized Access</option>
              <option value="honeypot">Honeypot</option>
            </Sel>
            <Inp label="Notify Email" placeholder="soc@company.com" value={form.notify_email} onChange={(e: any) => setForm(p => ({ ...p, notify_email: e.target.value }))} />
            <Txt label="Description" placeholder="What this canary key monitors..." value={form.description} onChange={(e: any) => setForm(p => ({ ...p, description: e.target.value }))} rows={3} />
            <div style={{ marginTop: 4, padding: "10px 12px", background: C.amberDim, border: `1px solid ${C.amber}33`, borderRadius: 6, fontSize: 11, color: C.amber }}>
              <AlertTriangle size={11} style={{ display: "inline", marginRight: 5 }} />
              This key will never be used in real operations. Any access to it will immediately trigger a critical security alert.
            </div>
            <div style={{ marginTop: 16, display: "flex", gap: 8 }}>
              <Btn variant="default" onClick={handleCreate} disabled={creating}>
                <Shield size={13} /> {creating ? "Deploying..." : "Deploy Canary Key"}
              </Btn>
              <Btn variant="ghost" onClick={() => setView("overview")}>Cancel</Btn>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
