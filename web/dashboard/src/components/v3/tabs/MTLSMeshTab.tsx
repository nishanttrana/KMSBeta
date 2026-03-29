// @ts-nocheck
import { useEffect, useState } from "react";
import {
  Shield, ShieldCheck, ShieldX, RefreshCcw, Plus, Server, Link2, Key,
  CheckCircle2, AlertTriangle, XCircle, Clock, Edit2, Zap, Network,
  Fingerprint, ChevronRight, ToggleLeft, ToggleRight, Anchor
} from "lucide-react";
import {
  listServices,
  registerService,
  renewServiceCert,
  listCertificates,
  listTrustAnchors,
  getTopology,
  type MeshService,
  type MeshCertificate,
  type TrustAnchor,
  type MeshTopologyEdge,
} from "../../../lib/mtlsMesh";
import { C } from "../../v3/theme";

/* ─── Mock Data ─── */
const MOCK_SERVICES: MeshService[] = [
  { id: "svc-1", name: "auth-service", namespace: "platform", endpoint: "https://auth.platform.svc.cluster.local:8443", cert_id: "cert-1", cert_cn: "auth-service.platform.svc", cert_expiry: "2026-08-14T00:00:00Z", cert_status: "valid", last_renewed_at: "2026-02-14T10:00:00Z", auto_renew: true, renew_days_before: 30, trust_anchors: ["ta-1"], created_at: "2025-10-01T00:00:00Z", mtls_enabled: true },
  { id: "svc-2", name: "payments-api", namespace: "finance", endpoint: "https://payments.finance.svc.cluster.local:9443", cert_id: "cert-2", cert_cn: "payments-api.finance.svc", cert_expiry: "2026-04-10T00:00:00Z", cert_status: "expiring", last_renewed_at: "2026-01-10T08:00:00Z", auto_renew: false, renew_days_before: 14, trust_anchors: ["ta-1", "ta-2"], created_at: "2025-10-15T00:00:00Z", mtls_enabled: true },
  { id: "svc-3", name: "audit-logger", namespace: "infra", endpoint: "https://audit.infra.svc.cluster.local:7443", cert_id: "cert-3", cert_cn: "audit-logger.infra.svc", cert_expiry: "2025-12-01T00:00:00Z", cert_status: "expired", last_renewed_at: "2025-06-01T00:00:00Z", auto_renew: true, renew_days_before: 30, trust_anchors: ["ta-2"], created_at: "2025-09-01T00:00:00Z", mtls_enabled: false },
  { id: "svc-4", name: "user-profile", namespace: "core", endpoint: "https://profile.core.svc.cluster.local:6443", cert_id: undefined, cert_cn: undefined, cert_expiry: undefined, cert_status: "missing", last_renewed_at: undefined, auto_renew: false, renew_days_before: 30, trust_anchors: [], created_at: "2026-01-20T00:00:00Z", mtls_enabled: false },
];
const MOCK_CERTS: MeshCertificate[] = [
  { id: "cert-1", service_id: "svc-1", service_name: "auth-service", cn: "auth-service.platform.svc", san: ["auth-service", "auth-service.platform", "auth-service.platform.svc.cluster.local"], issuer: "Vecta Internal CA", not_before: "2026-02-14T00:00:00Z", not_after: "2026-08-14T00:00:00Z", serial: "0a:1b:2c:3d:4e:5f", fingerprint: "SHA256:Ab3xYz9Qr7Lm2Pk1Nt8Vw4Uj6Sd0Fc5He", key_algorithm: "ECDSA P-256", revoked: false, created_at: "2026-02-14T10:00:00Z" },
  { id: "cert-2", service_id: "svc-2", service_name: "payments-api", cn: "payments-api.finance.svc", san: ["payments-api", "payments-api.finance"], issuer: "Vecta Internal CA", not_before: "2026-01-10T00:00:00Z", not_after: "2026-04-10T00:00:00Z", serial: "1f:2e:3d:4c:5b:6a", fingerprint: "SHA256:Bc4yZa0Rs8Mn3Ql2Ou9Wx5Vk7Te1Gd6If", key_algorithm: "RSA 2048", revoked: false, created_at: "2026-01-10T08:00:00Z" },
  { id: "cert-3", service_id: "svc-3", service_name: "audit-logger", cn: "audit-logger.infra.svc", san: ["audit-logger", "audit-logger.infra"], issuer: "Vecta Internal CA", not_before: "2025-06-01T00:00:00Z", not_after: "2025-12-01T00:00:00Z", serial: "2g:3f:4e:5d:6c:7b", fingerprint: "SHA256:Cd5zA1St9No4Rm3Pv0Xy6Wl8Uf2He7Jg", key_algorithm: "ECDSA P-384", revoked: true, created_at: "2025-06-01T00:00:00Z" },
];
const MOCK_ANCHORS: TrustAnchor[] = [
  { id: "ta-1", name: "Vecta Root CA", fingerprint: "SHA256:De6aB2Tu0Op5Sn4Qw1Yz7Xm9Vg3If8Kh", subject: "CN=Vecta Root CA, O=Vecta Security, C=US", not_before: "2024-01-01T00:00:00Z", not_after: "2034-01-01T00:00:00Z", services_count: 3, created_at: "2024-01-01T00:00:00Z" },
  { id: "ta-2", name: "Finance Intermediate CA", fingerprint: "SHA256:Ef7bC3Uv1Pq6To5Rx2Za8Yn0Wh4Jg9Li", subject: "CN=Finance Int CA, O=Vecta Security, OU=Finance, C=US", not_before: "2025-01-01T00:00:00Z", not_after: "2030-01-01T00:00:00Z", services_count: 2, created_at: "2025-01-01T00:00:00Z" },
];
const MOCK_TOPOLOGY: MeshTopologyEdge[] = [
  { from_service: "auth-service", to_service: "payments-api", mtls_verified: true, last_handshake_at: "2026-03-25T09:12:00Z" },
  { from_service: "payments-api", to_service: "audit-logger", mtls_verified: false, last_handshake_at: "2026-03-25T08:55:00Z" },
  { from_service: "auth-service", to_service: "user-profile", mtls_verified: true, last_handshake_at: "2026-03-25T09:10:00Z" },
];

/* ─── Helpers ─── */
function fmt(iso?: string) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}
function trunc(s: string, n: number) {
  return s && s.length > n ? s.slice(0, n) + "…" : (s || "—");
}
function certStatusColor(s: string) {
  if (s === "valid") return C.green;
  if (s === "expiring") return C.amber;
  if (s === "expired") return C.red;
  return C.muted;
}
function certStatusIcon(s: string) {
  if (s === "valid") return <ShieldCheck size={13} />;
  if (s === "expiring") return <AlertTriangle size={13} />;
  if (s === "expired") return <ShieldX size={13} />;
  return <XCircle size={13} />;
}

/* ─── Shared Primitives ─── */
const TH = ({ children }: any) => (
  <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}`, whiteSpace: "nowrap" }}>{children}</th>
);
const TD = ({ children, mono }: any) => (
  <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{children}</td>
);
const Badge = ({ color, children }: any) => (
  <span style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.4 }}>{children}</span>
);
const Btn = ({ onClick, children, variant = "default", disabled = false, small = false }: any) => {
  const base: any = { display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: small ? 11 : 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", transition: "opacity .15s", opacity: disabled ? 0.5 : 1 };
  const styles: any = {
    default: { background: C.accent, color: C.bg },
    ghost: { background: `rgba(255,255,255,.06)`, color: C.dim, border: `1px solid ${C.border}` },
    danger: { background: C.redDim, color: C.red, border: `1px solid ${C.red}33` },
  };
  return <button onClick={disabled ? undefined : onClick} style={{ ...base, ...styles[variant] }}>{children}</button>;
};
const Inp = ({ label, ...props }: any) => (
  <div style={{ marginBottom: 12 }}>
    {label && <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div>}
    <input {...props} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box", ...props.style }} />
  </div>
);
const StatCard = ({ icon, label, value, color = C.accent, tint }: any) => (
  <div style={{ flex: 1, minWidth: 140, background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "14px 16px", display: "flex", flexDirection: "column", gap: 8, backgroundImage: tint ? `linear-gradient(135deg, ${tint}, transparent)` : undefined }}>
    <div style={{ display: "flex", alignItems: "center", gap: 6, color }}>
      {icon}
      <span style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, fontWeight: 600 }}>{label}</span>
    </div>
    <div style={{ fontSize: 26, fontWeight: 800, color, lineHeight: 1 }}>{value}</div>
  </div>
);
const SubTab = ({ active, onClick, children }: any) => (
  <button onClick={onClick} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", border: "none", background: active ? C.accent : "transparent", color: active ? C.bg : C.dim, transition: "all .15s" }}>{children}</button>
);

/* ─── Register Service Modal ─── */
const RegisterServiceModal = ({ open, onClose, onSubmit, busy }: any) => {
  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [autoRenew, setAutoRenew] = useState(true);
  const [renewDays, setRenewDays] = useState("30");

  function reset() { setName(""); setNamespace(""); setEndpoint(""); setAutoRenew(true); setRenewDays("30"); }
  function handleClose() { reset(); onClose(); }
  function handleSubmit() {
    if (!name.trim() || !namespace.trim() || !endpoint.trim()) return;
    onSubmit({ name: name.trim(), namespace: namespace.trim(), endpoint: endpoint.trim(), auto_renew: autoRenew, renew_days_before: Number(renewDays) || 30 });
    reset();
  }

  if (!open) return null;
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }} onClick={handleClose}>
      <div style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,.7)", backdropFilter: "blur(4px)" }} />
      <div onClick={e => e.stopPropagation()} style={{ position: "relative", background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 14, width: 520, maxHeight: "88vh", overflow: "auto", boxShadow: "0 24px 60px rgba(0,0,0,.5)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 20px", borderBottom: `1px solid ${C.border}`, position: "sticky", top: 0, background: C.surface, zIndex: 1, borderRadius: "14px 14px 0 0" }}>
          <span style={{ fontSize: 15, fontWeight: 700, color: C.text }}>Register Mesh Service</span>
          <button onClick={handleClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 18, lineHeight: 1 }}>✕</button>
        </div>
        <div style={{ padding: "20px" }}>
          <Inp label="Service Name" placeholder="e.g. payments-api" value={name} onChange={e => setName(e.target.value)} />
          <Inp label="Namespace" placeholder="e.g. finance" value={namespace} onChange={e => setNamespace(e.target.value)} />
          <Inp label="Endpoint" placeholder="https://service.namespace.svc.cluster.local:8443" value={endpoint} onChange={e => setEndpoint(e.target.value)} />
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12, padding: "10px 12px", background: C.card, borderRadius: 7, border: `1px solid ${C.border}` }}>
            <span style={{ fontSize: 12, color: C.text, fontWeight: 500 }}>Auto-Renew Certificate</span>
            <button onClick={() => setAutoRenew(v => !v)} style={{ background: "none", border: "none", cursor: "pointer", color: autoRenew ? C.green : C.muted, display: "flex", alignItems: "center" }}>
              {autoRenew ? <ToggleRight size={22} /> : <ToggleLeft size={22} />}
            </button>
          </div>
          <Inp label="Renew Days Before Expiry" type="number" min="1" max="90" value={renewDays} onChange={e => setRenewDays(e.target.value)} />
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 16 }}>
            <Btn variant="ghost" onClick={handleClose}>Cancel</Btn>
            <Btn onClick={handleSubmit} disabled={busy || !name.trim() || !namespace.trim() || !endpoint.trim()}>{busy ? "Registering…" : "Register Service"}</Btn>
          </div>
        </div>
      </div>
    </div>
  );
};

/* ─── Add Trust Anchor Modal ─── */
const AddTrustAnchorModal = ({ open, onClose }: any) => {
  const [name, setName] = useState("");
  const [pem, setPem] = useState("");
  function reset() { setName(""); setPem(""); }
  function handleClose() { reset(); onClose(); }
  if (!open) return null;
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }} onClick={handleClose}>
      <div style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,.7)", backdropFilter: "blur(4px)" }} />
      <div onClick={e => e.stopPropagation()} style={{ position: "relative", background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 14, width: 520, maxHeight: "88vh", overflow: "auto", boxShadow: "0 24px 60px rgba(0,0,0,.5)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 20px", borderBottom: `1px solid ${C.border}`, position: "sticky", top: 0, background: C.surface, zIndex: 1, borderRadius: "14px 14px 0 0" }}>
          <span style={{ fontSize: 15, fontWeight: 700, color: C.text }}>Add Trust Anchor</span>
          <button onClick={handleClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 18, lineHeight: 1 }}>✕</button>
        </div>
        <div style={{ padding: "20px" }}>
          <Inp label="Anchor Name" placeholder="e.g. Internal Root CA" value={name} onChange={e => setName(e.target.value)} />
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>PEM Certificate</div>
            <textarea value={pem} onChange={e => setPem(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" style={{ width: "100%", minHeight: 140, background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "8px 10px", color: C.text, fontSize: 11, fontFamily: "'JetBrains Mono', monospace", outline: "none", resize: "vertical", boxSizing: "border-box" }} />
          </div>
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 4 }}>
            <Btn variant="ghost" onClick={handleClose}>Cancel</Btn>
            <Btn disabled={!name.trim() || !pem.trim()}>Add Trust Anchor</Btn>
          </div>
        </div>
      </div>
    </div>
  );
};

/* ─── Main Component ─── */
export const MTLSMeshTab = ({ session, enabledFeatures, keyCatalog }: { session: any; enabledFeatures?: any; keyCatalog?: any[] }) => {
  const [section, setSection] = useState<"services" | "certificates" | "trust_anchors" | "topology">("services");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [services, setServices] = useState<MeshService[]>(MOCK_SERVICES);
  const [certs, setCerts] = useState<MeshCertificate[]>(MOCK_CERTS);
  const [anchors, setAnchors] = useState<TrustAnchor[]>(MOCK_ANCHORS);
  const [topology, setTopology] = useState<MeshTopologyEdge[]>(MOCK_TOPOLOGY);
  const [regModal, setRegModal] = useState(false);
  const [anchorModal, setAnchorModal] = useState(false);
  const [regBusy, setRegBusy] = useState(false);
  const [renewBusy, setRenewBusy] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [svcs, cs, as, topo] = await Promise.all([
        listServices(session),
        listCertificates(session),
        listTrustAnchors(session),
        getTopology(session),
      ]);
      setServices(svcs?.length ? svcs : MOCK_SERVICES);
      setCerts(cs?.length ? cs : MOCK_CERTS);
      setAnchors(as?.length ? as : MOCK_ANCHORS);
      setTopology(topo?.length ? topo : MOCK_TOPOLOGY);
    } catch {
      setServices(MOCK_SERVICES);
      setCerts(MOCK_CERTS);
      setAnchors(MOCK_ANCHORS);
      setTopology(MOCK_TOPOLOGY);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleRegister(data: any) {
    setRegBusy(true);
    try {
      const svc = await registerService(session, data);
      setServices(prev => [svc, ...prev]);
      setRegModal(false);
    } catch {
      setServices(prev => [{ id: `svc-${Date.now()}`, ...data, cert_status: "missing", trust_anchors: [], created_at: new Date().toISOString(), mtls_enabled: false }, ...prev]);
      setRegModal(false);
    } finally {
      setRegBusy(false);
    }
  }

  async function handleRenew(svcId: string) {
    setRenewBusy(svcId);
    try {
      await renewServiceCert(session, svcId);
      setServices(prev => prev.map(s => s.id === svcId ? { ...s, cert_status: "valid", last_renewed_at: new Date().toISOString() } : s));
    } catch {
      // silently fail
    } finally {
      setRenewBusy(null);
    }
  }

  /* Stat counts */
  const validCount = services.filter(s => s.cert_status === "valid").length;
  const expiringCount = services.filter(s => s.cert_status === "expiring").length;
  const autoRenewCount = services.filter(s => s.auto_renew).length;

  return (
    <div style={{ padding: "20px 24px", display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
            <Network size={18} color={C.accent} />
            <span style={{ fontSize: 17, fontWeight: 800, color: C.text, letterSpacing: -0.4 }}>mTLS Service Mesh</span>
          </div>
          <div style={{ fontSize: 12, color: C.muted }}>Mutual TLS certificate management for service-to-service authentication</div>
        </div>
        <Btn onClick={load} variant="ghost" small><RefreshCcw size={13} />Refresh</Btn>
      </div>

      {/* Stat Cards */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <StatCard icon={<Server size={14} />} label="Registered Services" value={services.length} color={C.accent} tint={C.accentTint} />
        <StatCard icon={<ShieldCheck size={14} />} label="Valid Certs" value={validCount} color={C.green} tint={C.greenTint} />
        <StatCard icon={<AlertTriangle size={14} />} label="Expiring Soon" value={expiringCount} color={C.amber} tint={C.amberTint} />
        <StatCard icon={<Zap size={14} />} label="Auto-Renew Enabled" value={autoRenewCount} color={C.purple} tint={C.purpleTint} />
      </div>

      {/* Loading / Error */}
      {loading && (
        <div style={{ textAlign: "center", padding: "40px 0", color: C.muted, fontSize: 13 }}>
          <RefreshCcw size={20} style={{ display: "block", margin: "0 auto 10px", opacity: 0.5 }} />Loading mesh data…
        </div>
      )}

      {!loading && (
        <>
          {/* Section Tabs */}
          <div style={{ display: "flex", gap: 4, background: C.card, padding: 4, borderRadius: 8, width: "fit-content", border: `1px solid ${C.border}` }}>
            <SubTab active={section === "services"} onClick={() => setSection("services")}>Services</SubTab>
            <SubTab active={section === "certificates"} onClick={() => setSection("certificates")}>Certificates</SubTab>
            <SubTab active={section === "trust_anchors"} onClick={() => setSection("trust_anchors")}>Trust Anchors</SubTab>
            <SubTab active={section === "topology"} onClick={() => setSection("topology")}>Topology</SubTab>
          </div>

          {/* ── Services Section ── */}
          {section === "services" && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: `1px solid ${C.border}` }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>Mesh Services</span>
                <Btn onClick={() => setRegModal(true)} small><Plus size={12} />Register Service</Btn>
              </div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ background: "rgba(0,0,0,.2)" }}>
                      <TH>Service Name</TH>
                      <TH>Namespace</TH>
                      <TH>Endpoint</TH>
                      <TH>Cert Status</TH>
                      <TH>Cert CN</TH>
                      <TH>Expiry</TH>
                      <TH>Auto Renew</TH>
                      <TH>Last Renewed</TH>
                      <TH>Actions</TH>
                    </tr>
                  </thead>
                  <tbody>
                    {services.map(svc => {
                      const sc = certStatusColor(svc.cert_status);
                      return (
                        <tr key={svc.id} style={{ transition: "background .1s" }} onMouseEnter={e => (e.currentTarget.style.background = C.cardHover)} onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                          <TD><div style={{ display: "flex", alignItems: "center", gap: 6 }}><Server size={12} color={C.accent} /><span style={{ fontWeight: 600 }}>{svc.name}</span></div></TD>
                          <TD><Badge color={C.blue}>{svc.namespace}</Badge></TD>
                          <TD><span title={svc.endpoint} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: C.dim }}>{trunc(svc.endpoint, 36)}</span></TD>
                          <TD>
                            <div style={{ display: "flex", alignItems: "center", gap: 5, color: sc }}>
                              {certStatusIcon(svc.cert_status)}
                              <span style={{ fontSize: 11, fontWeight: 600, textTransform: "capitalize" }}>{svc.cert_status}</span>
                            </div>
                          </TD>
                          <TD mono>{trunc(svc.cert_cn || "—", 28)}</TD>
                          <TD><span style={{ color: svc.cert_status === "expired" ? C.red : svc.cert_status === "expiring" ? C.amber : C.dim }}>{fmt(svc.cert_expiry)}</span></TD>
                          <TD>
                            <Badge color={svc.auto_renew ? C.green : C.muted}>{svc.auto_renew ? "On" : "Off"}</Badge>
                          </TD>
                          <TD>{fmt(svc.last_renewed_at)}</TD>
                          <TD>
                            <div style={{ display: "flex", gap: 5 }}>
                              <Btn small variant="ghost" onClick={() => handleRenew(svc.id)} disabled={renewBusy === svc.id}><RefreshCcw size={11} />{renewBusy === svc.id ? "…" : "Renew"}</Btn>
                              <Btn small variant="ghost"><Edit2 size={11} />Edit</Btn>
                            </div>
                          </TD>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Certificates Section ── */}
          {section === "certificates" && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
              <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}` }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>Mesh Certificates</span>
              </div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ background: "rgba(0,0,0,.2)" }}>
                      <TH>Service</TH>
                      <TH>Common Name</TH>
                      <TH>SAN</TH>
                      <TH>Issuer</TH>
                      <TH>Not Before</TH>
                      <TH>Not After</TH>
                      <TH>Serial</TH>
                      <TH>Algorithm</TH>
                      <TH>Status</TH>
                    </tr>
                  </thead>
                  <tbody>
                    {certs.map(cert => (
                      <tr key={cert.id} style={{ transition: "background .1s" }} onMouseEnter={e => (e.currentTarget.style.background = C.cardHover)} onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                        <TD><div style={{ display: "flex", alignItems: "center", gap: 5 }}><Server size={11} color={C.accent} />{cert.service_name}</div></TD>
                        <TD mono>{cert.cn}</TD>
                        <TD><span title={cert.san.join(", ")} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: C.dim }}>{trunc(cert.san.join(", "), 28)}</span></TD>
                        <TD>{cert.issuer}</TD>
                        <TD>{fmt(cert.not_before)}</TD>
                        <TD>{fmt(cert.not_after)}</TD>
                        <TD mono>{trunc(cert.serial, 18)}</TD>
                        <TD>{cert.key_algorithm}</TD>
                        <TD>{cert.revoked ? <Badge color={C.red}>Revoked</Badge> : <Badge color={C.green}>Active</Badge>}</TD>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Trust Anchors Section ── */}
          {section === "trust_anchors" && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: `1px solid ${C.border}` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                  <Anchor size={14} color={C.accent} />
                  <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>Trust Anchors</span>
                </div>
                <Btn small onClick={() => setAnchorModal(true)}><Plus size={12} />Add Trust Anchor</Btn>
              </div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ background: "rgba(0,0,0,.2)" }}>
                      <TH>Name</TH>
                      <TH>Subject</TH>
                      <TH>Fingerprint</TH>
                      <TH>Not After</TH>
                      <TH>Services</TH>
                    </tr>
                  </thead>
                  <tbody>
                    {anchors.map(anchor => (
                      <tr key={anchor.id} style={{ transition: "background .1s" }} onMouseEnter={e => (e.currentTarget.style.background = C.cardHover)} onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                        <TD><div style={{ display: "flex", alignItems: "center", gap: 6 }}><Fingerprint size={12} color={C.purple} /><span style={{ fontWeight: 600 }}>{anchor.name}</span></div></TD>
                        <TD><span style={{ fontSize: 10, color: C.dim }}>{trunc(anchor.subject, 40)}</span></TD>
                        <TD mono><span title={anchor.fingerprint} style={{ fontSize: 10 }}>{trunc(anchor.fingerprint, 28)}</span></TD>
                        <TD><span style={{ color: new Date(anchor.not_after) < new Date() ? C.red : C.dim }}>{fmt(anchor.not_after)}</span></TD>
                        <TD><Badge color={C.accent}>{anchor.services_count}</Badge></TD>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Topology Section ── */}
          {section === "topology" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "12px 16px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 14 }}>
                  <Network size={14} color={C.accent} />
                  <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>Service mTLS Connections</span>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 10 }}>
                  {topology.map((edge, i) => (
                    <div key={i} style={{ background: C.surface, border: `1px solid ${edge.mtls_verified ? C.green + "44" : C.amber + "44"}`, borderRadius: 8, padding: "12px 14px", display: "flex", flexDirection: "column", gap: 8 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <div style={{ flex: 1, background: C.card, borderRadius: 5, padding: "6px 10px", fontSize: 11, fontWeight: 600, color: C.text, textAlign: "center" }}>{edge.from_service}</div>
                        <div style={{ display: "flex", alignItems: "center", gap: 2, color: C.accent, fontSize: 10, fontWeight: 700 }}>
                          <ChevronRight size={14} />
                        </div>
                        <div style={{ flex: 1, background: C.card, borderRadius: 5, padding: "6px 10px", fontSize: 11, fontWeight: 600, color: C.text, textAlign: "center" }}>{edge.to_service}</div>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                        {edge.mtls_verified ? (
                          <Badge color={C.green}><ShieldCheck size={10} />mTLS Verified</Badge>
                        ) : (
                          <Badge color={C.amber}><AlertTriangle size={10} />Unverified</Badge>
                        )}
                        <span style={{ fontSize: 10, color: C.muted }}>{edge.last_handshake_at ? fmt(edge.last_handshake_at) : "No handshake"}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* Modals */}
      <RegisterServiceModal open={regModal} onClose={() => setRegModal(false)} onSubmit={handleRegister} busy={regBusy} />
      <AddTrustAnchorModal open={anchorModal} onClose={() => setAnchorModal(false)} />
    </div>
  );
};
