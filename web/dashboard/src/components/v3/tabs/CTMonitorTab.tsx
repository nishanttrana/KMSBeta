// @ts-nocheck
import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Bell,
  CheckCircle2,
  Globe,
  RefreshCcw,
  ShieldAlert,
  ShieldCheck,
  X
} from "lucide-react";
import {
  listWatchedDomains,
  addWatchedDomain,
  deleteWatchedDomain,
  toggleWatchedDomain,
  listCTLogEntries,
  listCTAlerts,
  acknowledgeCTAlert
} from "../../../lib/ctMonitor";
import { B, Btn, Card, FG, Inp, Modal, Section, Sel, Stat, Tabs } from "../legacyPrimitives";
import { C } from "../../v3/theme";

// ─── Types ────────────────────────────────────────────────────────────────────

interface WatchedDomain {
  id: string;
  domain: string;
  include_subdomains: boolean;
  alert_unknown_ca: boolean;
  alert_expiring_days: number;
  cert_count: number;
  alert_count: number;
  last_checked?: string;
  enabled: boolean;
}

interface CTLogEntry {
  id: string;
  domain: string;
  subject_cn: string;
  issuer: string;
  not_before: string;
  not_after: string;
  ct_log: string;
  logged_at: string;
  known_ca: boolean;
  revoked: boolean;
}

interface CTAlert {
  id: string;
  domain: string;
  reason: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "open" | "acknowledged";
  triggered_at: string;
  cert_subject: string;
  cert_issuer: string;
  cert_not_after: string;
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_DOMAINS: WatchedDomain[] = [
  { id: "dom-001", domain: "vecta.io", include_subdomains: true, alert_unknown_ca: true, alert_expiring_days: 30, cert_count: 12, alert_count: 2, last_checked: new Date(Date.now() - 600 * 1000).toISOString(), enabled: true },
  { id: "dom-002", domain: "api.vecta.io", include_subdomains: false, alert_unknown_ca: true, alert_expiring_days: 14, cert_count: 3, alert_count: 0, last_checked: new Date(Date.now() - 1200 * 1000).toISOString(), enabled: true },
  { id: "dom-003", domain: "internal.vecta.corp", include_subdomains: true, alert_unknown_ca: false, alert_expiring_days: 7, cert_count: 8, alert_count: 1, last_checked: new Date(Date.now() - 86400 * 1000).toISOString(), enabled: false }
];

const MOCK_CT_ENTRIES: CTLogEntry[] = [
  { id: "ct-001", domain: "vecta.io", subject_cn: "*.vecta.io", issuer: "Let's Encrypt R3", not_before: "2024-01-15T00:00:00Z", not_after: "2024-04-15T00:00:00Z", ct_log: "Google Xenon2024", logged_at: new Date(Date.now() - 300 * 1000).toISOString(), known_ca: true, revoked: false },
  { id: "ct-002", domain: "vecta.io", subject_cn: "vecta.io", issuer: "Unknown CA (Self-Signed)", not_before: "2024-03-01T00:00:00Z", not_after: "2025-03-01T00:00:00Z", ct_log: "Cloudflare Nimbus2024", logged_at: new Date(Date.now() - 900 * 1000).toISOString(), known_ca: false, revoked: false },
  { id: "ct-003", domain: "api.vecta.io", subject_cn: "api.vecta.io", issuer: "DigiCert TLS RSA SHA256 2020 CA1", not_before: "2023-12-01T00:00:00Z", not_after: "2024-12-01T00:00:00Z", ct_log: "Google Argon2024", logged_at: new Date(Date.now() - 3600 * 1000).toISOString(), known_ca: true, revoked: false },
  { id: "ct-004", domain: "internal.vecta.corp", subject_cn: "*.internal.vecta.corp", issuer: "Rogue Issuer Corp", not_before: "2024-02-20T00:00:00Z", not_after: "2026-02-20T00:00:00Z", ct_log: "DigiCert Yeti2024", logged_at: new Date(Date.now() - 7200 * 1000).toISOString(), known_ca: false, revoked: true },
  { id: "ct-005", domain: "vecta.io", subject_cn: "www.vecta.io", issuer: "Let's Encrypt R3", not_before: "2024-03-10T00:00:00Z", not_after: "2024-06-10T00:00:00Z", ct_log: "Google Xenon2024", logged_at: new Date(Date.now() - 14400 * 1000).toISOString(), known_ca: true, revoked: false }
];

const MOCK_ALERTS: CTAlert[] = [
  { id: "alt-001", domain: "vecta.io", reason: "Certificate issued by unknown CA not in trusted root store", severity: "critical", status: "open", triggered_at: new Date(Date.now() - 900 * 1000).toISOString(), cert_subject: "vecta.io", cert_issuer: "Unknown CA (Self-Signed)", cert_not_after: "2025-03-01T00:00:00Z" },
  { id: "alt-002", domain: "internal.vecta.corp", reason: "Certificate from Rogue Issuer Corp detected and marked revoked", severity: "critical", status: "open", triggered_at: new Date(Date.now() - 7200 * 1000).toISOString(), cert_subject: "*.internal.vecta.corp", cert_issuer: "Rogue Issuer Corp", cert_not_after: "2026-02-20T00:00:00Z" },
  { id: "alt-003", domain: "api.vecta.io", reason: "Certificate expiring within alert threshold (14 days)", severity: "high", status: "acknowledged", triggered_at: new Date(Date.now() - 86400 * 1000).toISOString(), cert_subject: "api.vecta.io", cert_issuer: "DigiCert TLS RSA SHA256 2020 CA1", cert_not_after: "2024-12-01T00:00:00Z" }
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatAgo(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  const s = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function formatDate(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function severityColor(sev: string): string {
  switch (sev) {
    case "critical": return C.red;
    case "high": return C.orange;
    case "medium": return C.amber;
    default: return C.blue;
  }
}

const TH: React.CSSProperties = {
  padding: "6px 10px",
  fontSize: 9,
  fontWeight: 600,
  color: C.muted,
  textTransform: "uppercase",
  letterSpacing: 0.8,
  textAlign: "left",
  whiteSpace: "nowrap"
};

const TD: React.CSSProperties = {
  padding: "8px 10px",
  fontSize: 11,
  color: C.text,
  borderTop: `1px solid ${C.border}`,
  verticalAlign: "middle"
};

// ─── Add Domain Modal ─────────────────────────────────────────────────────────

interface AddDomainModalProps {
  open: boolean;
  onClose: () => void;
  onAdd: (payload: { domain: string; include_subdomains: boolean; alert_unknown_ca: boolean; alert_expiring_days: number }) => Promise<void>;
}

function AddDomainModal({ open, onClose, onAdd }: AddDomainModalProps) {
  const [domain, setDomain] = useState("");
  const [includeSubdomains, setIncludeSubdomains] = useState(true);
  const [alertUnknownCA, setAlertUnknownCA] = useState(true);
  const [expiringDays, setExpiringDays] = useState(30);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (open) {
      setDomain(""); setIncludeSubdomains(true); setAlertUnknownCA(true);
      setExpiringDays(30); setError(""); setBusy(false);
    }
  }, [open]);

  const submit = async () => {
    const trimmed = domain.trim();
    if (!trimmed) { setError("Domain is required."); return; }
    if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(trimmed)) {
      setError("Enter a valid domain (e.g. example.com).");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await onAdd({ domain: trimmed, include_subdomains: includeSubdomains, alert_unknown_ca: alertUnknownCA, alert_expiring_days: expiringDays });
      onClose();
    } catch (e: any) {
      setError(String(e?.message || "Failed to add domain."));
    } finally {
      setBusy(false);
    }
  };

  const Toggle = ({ value, onChange, label }: { value: boolean; onChange: (v: boolean) => void; label: string }) => (
    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
      <div
        onClick={() => onChange(!value)}
        style={{ width: 36, height: 20, borderRadius: 10, background: value ? C.accent : C.border, cursor: "pointer", position: "relative", transition: "background .2s", flexShrink: 0 }}
      >
        <div style={{ position: "absolute", top: 3, left: value ? 18 : 3, width: 14, height: 14, borderRadius: 7, background: C.bg, transition: "left .2s" }} />
      </div>
      <span style={{ fontSize: 11, color: C.dim }}>{label}</span>
    </div>
  );

  return (
    <Modal open={open} onClose={onClose} title="Add Watched Domain">
      <FG label="Domain" required hint="e.g. example.com">
        <Inp value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com" />
      </FG>
      <Toggle value={includeSubdomains} onChange={setIncludeSubdomains} label="Include Subdomains" />
      <Toggle value={alertUnknownCA} onChange={setAlertUnknownCA} label="Alert on Unknown CA" />
      <FG label="Alert on certs expiring within N days">
        <Inp
          type="number"
          value={String(expiringDays)}
          onChange={e => setExpiringDays(Math.max(1, Number(e.target.value) || 30))}
          placeholder="30"
          w={100}
        />
      </FG>
      {error && <div style={{ fontSize: 10, color: C.red, marginBottom: 8 }}>{error}</div>}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Btn onClick={onClose}>Cancel</Btn>
        <Btn primary onClick={submit} disabled={busy}>{busy ? "Adding…" : "Add Domain"}</Btn>
      </div>
    </Modal>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

interface CTMonitorTabProps {
  session: any;
  enabledFeatures?: any;
  keyCatalog?: any[];
}

export const CTMonitorTab = ({ session }: CTMonitorTabProps) => {
  const [domains, setDomains] = useState<WatchedDomain[]>([]);
  const [ctEntries, setCtEntries] = useState<CTLogEntry[]>([]);
  const [alerts, setAlerts] = useState<CTAlert[]>([]);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [activeSection, setActiveSection] = useState("Watched Domains");
  const [addOpen, setAddOpen] = useState(false);
  const [toggleBusy, setToggleBusy] = useState<string>("");
  const [deleteBusy, setDeleteBusy] = useState<string>("");
  const [ackBusy, setAckBusy] = useState<string>("");

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setErrorMsg("");
    try {
      const [d, e, a] = await Promise.all([
        listWatchedDomains(session),
        listCTLogEntries(session),
        listCTAlerts(session)
      ]);
      setDomains(Array.isArray(d) ? d : MOCK_DOMAINS);
      setCtEntries(Array.isArray(e) ? e : MOCK_CT_ENTRIES);
      setAlerts(Array.isArray(a) ? a : MOCK_ALERTS);
    } catch {
      setDomains(MOCK_DOMAINS);
      setCtEntries(MOCK_CT_ENTRIES);
      setAlerts(MOCK_ALERTS);
    } finally {
      if (!silent) setLoading(false);
    }
  }, [session]);

  useEffect(() => { void load(false); }, [load]);

  const handleAdd = async (payload: { domain: string; include_subdomains: boolean; alert_unknown_ca: boolean; alert_expiring_days: number }) => {
    try { await addWatchedDomain(session, payload); } catch { /* optimistic */ }
    await load(true);
  };

  const handleToggle = async (id: string, currentEnabled: boolean) => {
    setToggleBusy(id);
    try { await toggleWatchedDomain(session, id, !currentEnabled); } catch { /* ignore */ }
    setDomains(prev => prev.map(d => d.id === id ? { ...d, enabled: !currentEnabled } : d));
    setToggleBusy("");
  };

  const handleDelete = async (id: string) => {
    setDeleteBusy(id);
    try { await deleteWatchedDomain(session, id); } catch { /* ignore */ }
    setDomains(prev => prev.filter(d => d.id !== id));
    setDeleteBusy("");
  };

  const handleAck = async (id: string) => {
    setAckBusy(id);
    try { await acknowledgeCTAlert(session, id); } catch { /* ignore */ }
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: "acknowledged" as const } : a));
    setAckBusy("");
  };

  // ─── Stats ─────────────────────────────────────────────────────────────────

  const certsToday = ctEntries.filter(e => {
    const d = new Date(e.logged_at);
    const now = new Date();
    return d.getUTCFullYear() === now.getUTCFullYear() &&
      d.getUTCMonth() === now.getUTCMonth() &&
      d.getUTCDate() === now.getUTCDate();
  }).length;

  const openAlerts = alerts.filter(a => a.status === "open");
  const unknownCADetections = ctEntries.filter(e => !e.known_ca).length;

  const tableStyle: React.CSSProperties = {
    width: "100%",
    borderCollapse: "collapse",
    fontSize: 11,
    tableLayout: "fixed"
  };

  return (
    <div>
      {/* Stat Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 8, marginBottom: 14 }}>
        <Stat l="Watched Domains" v={domains.length} s={`${domains.filter(d => d.enabled).length} monitoring`} c="accent" i={Globe} />
        <Stat l="Certs Logged Today" v={certsToday} s={`${ctEntries.length} total`} c="blue" i={ShieldCheck} />
        <Stat l="Active Alerts" v={openAlerts.length} s={openAlerts.length > 0 ? "requires review" : "all clear"} c={openAlerts.length > 0 ? "red" : "green"} i={Bell} />
        <Stat l="Unknown CA Detections" v={unknownCADetections} s={unknownCADetections > 0 ? "investigate immediately" : "none found"} c={unknownCADetections > 0 ? "orange" : "green"} i={ShieldAlert} />
      </div>

      {errorMsg && (
        <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 8, padding: "8px 12px", fontSize: 11, color: C.red, marginBottom: 10, display: "flex", alignItems: "center", gap: 8 }}>
          <AlertTriangle size={13} /> {errorMsg}
          <button onClick={() => setErrorMsg("")} style={{ marginLeft: "auto", background: "none", border: "none", color: C.red, cursor: "pointer" }}><X size={12} /></button>
        </div>
      )}

      {/* Section Tabs */}
      <Tabs
        tabs={["Watched Domains", "CT Log Entries", "Alerts"]}
        active={activeSection}
        onChange={setActiveSection}
      />

      {/* ── Watched Domains Section ── */}
      {activeSection === "Watched Domains" && (
        <Section
          title="Watched Domains"
          actions={
            <div style={{ display: "flex", gap: 6 }}>
              <Btn small onClick={() => void load(false)}><RefreshCcw size={11} />{loading ? "Loading…" : "Refresh"}</Btn>
              <Btn small primary onClick={() => setAddOpen(true)}>+ Add Domain</Btn>
            </div>
          }
        >
          <Card style={{ padding: 0, overflow: "hidden" }}>
            <table style={tableStyle}>
              <colgroup>
                <col style={{ width: "18%" }} />
                <col style={{ width: "12%" }} />
                <col style={{ width: "13%" }} />
                <col style={{ width: "12%" }} />
                <col style={{ width: "8%" }} />
                <col style={{ width: "8%" }} />
                <col style={{ width: "12%" }} />
                <col style={{ width: "17%" }} />
              </colgroup>
              <thead>
                <tr style={{ background: C.surface }}>
                  <th style={TH}>Domain</th>
                  <th style={TH}>Subdomains</th>
                  <th style={TH}>Alert Unknown CA</th>
                  <th style={TH}>Expiry Alert</th>
                  <th style={TH}>Certs</th>
                  <th style={TH}>Alerts</th>
                  <th style={TH}>Last Checked</th>
                  <th style={TH}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {domains.map(d => (
                  <tr key={d.id}
                    onMouseEnter={e => (e.currentTarget.style.background = C.surface)}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                    <td style={TD}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <Globe size={11} color={d.enabled ? C.accent : C.muted} />
                        <span style={{ fontWeight: 600, color: d.enabled ? C.text : C.muted }}>{d.domain}</span>
                      </div>
                    </td>
                    <td style={TD}><B c={d.include_subdomains ? "accent" : "muted"}>{d.include_subdomains ? "yes" : "no"}</B></td>
                    <td style={TD}><B c={d.alert_unknown_ca ? "orange" : "muted"}>{d.alert_unknown_ca ? "enabled" : "off"}</B></td>
                    <td style={{ ...TD, color: C.dim }}>{d.alert_expiring_days}d</td>
                    <td style={{ ...TD, color: C.dim }}>{d.cert_count}</td>
                    <td style={TD}>
                      <span style={{ color: d.alert_count > 0 ? C.red : C.green, fontWeight: 600 }}>{d.alert_count}</span>
                    </td>
                    <td style={{ ...TD, color: C.dim }}>{formatAgo(d.last_checked)}</td>
                    <td style={TD}>
                      <div style={{ display: "flex", gap: 4 }}>
                        <Btn small onClick={() => void handleToggle(d.id, d.enabled)} disabled={toggleBusy === d.id}>
                          {toggleBusy === d.id ? "…" : d.enabled ? "Disable" : "Enable"}
                        </Btn>
                        <Btn small danger onClick={() => void handleDelete(d.id)} disabled={deleteBusy === d.id}>
                          <X size={10} />
                        </Btn>
                      </div>
                    </td>
                  </tr>
                ))}
                {!domains.length && !loading && (
                  <tr><td colSpan={8} style={{ ...TD, color: C.muted, textAlign: "center", padding: 20 }}>No domains watched. Add one to begin monitoring.</td></tr>
                )}
              </tbody>
            </table>
          </Card>
        </Section>
      )}

      {/* ── CT Log Entries Section ── */}
      {activeSection === "CT Log Entries" && (
        <Section title="Certificate Transparency Log Entries">
          <Card style={{ padding: 0, overflow: "hidden" }}>
            <table style={tableStyle}>
              <colgroup>
                <col style={{ width: "12%" }} />
                <col style={{ width: "16%" }} />
                <col style={{ width: "18%" }} />
                <col style={{ width: "10%" }} />
                <col style={{ width: "10%" }} />
                <col style={{ width: "15%" }} />
                <col style={{ width: "11%" }} />
                <col style={{ width: "8%" }} />
              </colgroup>
              <thead>
                <tr style={{ background: C.surface }}>
                  <th style={TH}>Domain</th>
                  <th style={TH}>Subject CN</th>
                  <th style={TH}>Issuer</th>
                  <th style={TH}>Not Before</th>
                  <th style={TH}>Not After</th>
                  <th style={TH}>CT Log</th>
                  <th style={TH}>Logged At</th>
                  <th style={TH}>Flags</th>
                </tr>
              </thead>
              <tbody>
                {ctEntries.map(e => (
                  <tr key={e.id}
                    onMouseEnter={ev => (ev.currentTarget.style.background = C.surface)}
                    onMouseLeave={ev => (ev.currentTarget.style.background = "transparent")}>
                    <td style={TD}><span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: C.accent }}>{e.domain}</span></td>
                    <td style={{ ...TD, fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: C.text }} title={e.subject_cn}>
                      {e.subject_cn.length > 22 ? `…${e.subject_cn.slice(-21)}` : e.subject_cn}
                    </td>
                    <td style={{ ...TD, fontSize: 10, color: e.known_ca ? C.dim : C.orange }} title={e.issuer}>
                      {e.issuer.length > 26 ? `${e.issuer.slice(0, 25)}…` : e.issuer}
                    </td>
                    <td style={{ ...TD, fontSize: 10, color: C.dim }}>{formatDate(e.not_before)}</td>
                    <td style={{ ...TD, fontSize: 10, color: C.dim }}>{formatDate(e.not_after)}</td>
                    <td style={{ ...TD, fontSize: 10, color: C.dim }}>{e.ct_log}</td>
                    <td style={{ ...TD, color: C.dim }}>{formatAgo(e.logged_at)}</td>
                    <td style={TD}>
                      <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                        {!e.known_ca && <B c="orange">unknown CA</B>}
                        {e.revoked && <B c="red">revoked</B>}
                        {e.known_ca && !e.revoked && <CheckCircle2 size={12} color={C.green} />}
                      </div>
                    </td>
                  </tr>
                ))}
                {!ctEntries.length && (
                  <tr><td colSpan={8} style={{ ...TD, color: C.muted, textAlign: "center", padding: 20 }}>No CT log entries found.</td></tr>
                )}
              </tbody>
            </table>
          </Card>
        </Section>
      )}

      {/* ── Alerts Section ── */}
      {activeSection === "Alerts" && (
        <Section
          title="CT Monitor Alerts"
          actions={
            <Btn small onClick={() => void load(false)}><RefreshCcw size={11} />Refresh</Btn>
          }
        >
          <div style={{ display: "grid", gap: 8 }}>
            {alerts.map(a => (
              <Card key={a.id} style={{ padding: "12px 14px", borderLeft: `3px solid ${severityColor(a.severity)}` }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
                      <span style={{
                        display: "inline-block", padding: "2px 7px", borderRadius: 5,
                        fontSize: 9, fontWeight: 700, letterSpacing: 0.4,
                        color: severityColor(a.severity),
                        background: `${severityColor(a.severity)}18`
                      }}>
                        {a.severity.toUpperCase()}
                      </span>
                      <Globe size={11} color={C.accent} />
                      <span style={{ fontWeight: 700, fontSize: 12, color: C.text }}>{a.domain}</span>
                      <B c={a.status === "open" ? "red" : "green"}>{a.status}</B>
                    </div>
                    <div style={{ fontSize: 11, color: C.dim, marginBottom: 6 }}>{a.reason}</div>
                    <div style={{ display: "flex", gap: 16, flexWrap: "wrap", fontSize: 10, color: C.muted }}>
                      <span>Subject: <span style={{ color: C.text, fontFamily: "'JetBrains Mono',monospace" }}>{a.cert_subject}</span></span>
                      <span>Issuer: <span style={{ color: a.cert_issuer.includes("Unknown") || a.cert_issuer.includes("Rogue") ? C.orange : C.text }}>{a.cert_issuer}</span></span>
                      <span>Expires: <span style={{ color: C.text }}>{formatDate(a.cert_not_after)}</span></span>
                    </div>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 8, minWidth: 130 }}>
                    <span style={{ fontSize: 10, color: C.muted }}>{formatAgo(a.triggered_at)}</span>
                    {a.status === "open" && (
                      <Btn small onClick={() => void handleAck(a.id)} disabled={ackBusy === a.id}>
                        {ackBusy === a.id ? "Ack…" : "Acknowledge"}
                      </Btn>
                    )}
                  </div>
                </div>
              </Card>
            ))}
            {!alerts.length && (
              <Card>
                <div style={{ fontSize: 11, color: C.muted, textAlign: "center", padding: 10 }}>No alerts at this time.</div>
              </Card>
            )}
          </div>
        </Section>
      )}

      <AddDomainModal open={addOpen} onClose={() => setAddOpen(false)} onAdd={handleAdd} />
    </div>
  );
};
