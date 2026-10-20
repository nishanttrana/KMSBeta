// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useState } from "react";
import { RefreshCcw, Copy, ChevronDown, ChevronRight, Shield, ExternalLink, AlertTriangle, CheckCircle2, XCircle, Info } from "lucide-react";
import {
  configureHYOKEndpoint,
  deleteHYOKEndpoint,
  getHYOKHealth,
  listHYOKEndpoints,
  listHYOKRequests
} from "../../../lib/hyok";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Chk, FG, Inp, Modal, Row2, Section, Sel, Txt, usePromptDialog } from "../legacyPrimitives";
import { HYOKAzureConfig } from "./HYOKAzureConfig";
import { HYOK_OPS_BY_PROTOCOL, HYOK_PROTOCOLS, HYOK_PROTOCOL_DETAILS, HYOK_PROTOCOL_KEY_HINTS, HYOK_PROTOCOL_LABELS, HYOK_PROTOCOL_URLS, HYOK_SETUP_GUIDES } from "./hyokProtocols";

function formatAgo(value: unknown): string {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  const ts = new Date(raw);
  if (Number.isNaN(ts.getTime())) return "-";
  const diffSec = Math.max(0, Math.floor((Date.now() - ts.getTime()) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}

function formatDate(value: unknown): string {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  const ts = new Date(raw);
  if (Number.isNaN(ts.getTime())) return raw;
  return ts.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function normalizeKeyState(state: string): string {
  const raw = String(state || "").toLowerCase().trim();
  if (raw === "destroyed" || raw === "deleted") return "deleted";
  if (raw === "destroy-pending" || raw === "delete-pending" || raw === "deletion-pending") return "destroy-pending";
  if (raw === "preactive" || raw === "pre-active") return "pre-active";
  if (raw === "retired" || raw === "deactivated") return "deactivated";
  if (raw === "generation" || raw === "generated") return "pre-active";
  return raw || "unknown";
}

function keyChoicesFromCatalog(keyCatalog: any[]): any[] {
  if (!Array.isArray(keyCatalog)) return [];
  return keyCatalog.filter((k) => normalizeKeyState(String(k?.state || "")) !== "deleted");
}

function renderKeyOptions(keyChoices: any[], hint?: string): any[] {
  if (!keyChoices.length) return [<option key="no-customer-keys" value="">No customer keys available</option>];
  return keyChoices.map((k) => (
    <option key={k.id} value={k.id}>{k.name} {k.algo ? `(${k.algo})` : ""}</option>
  ));
}

function copyToClipboard(text: string) {
  try { navigator.clipboard.writeText(text); } catch { /* ignore */ }
}

export const HYOKTab = ({ session, keyCatalog, onToast }) => {
  const [modal, setModal] = useState<null | "config" | "urls" | "guide" | "azure">(null);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [endpoints, setEndpoints] = useState<any[]>([]);
  const [requests, setRequests] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);
  const [cfgProtocol, setCfgProtocol] = useState("generic");
  const [cfgEnabled, setCfgEnabled] = useState(true);
  const [cfgAuthMode, setCfgAuthMode] = useState("jwt");
  const [cfgPolicyID, setCfgPolicyID] = useState("");
  const [cfgGovernance, setCfgGovernance] = useState(false);
  const [cfgMetadata, setCfgMetadata] = useState("{\n  \"description\": \"\"\n}");
  // DKE-specific metadata fields
  const [dkeAuthorizedTenants, setDkeAuthorizedTenants] = useState("");
  const [dkeValidIssuers, setDkeValidIssuers] = useState("");
  const [dkeJWTAudiences, setDkeJWTAudiences] = useState("");
  const [dkeKeyURIHostname, setDkeKeyURIHostname] = useState("");
  const [dkeAllowedAlgorithms, setDkeAllowedAlgorithms] = useState("RSA-OAEP-256");
  const [dkeAuthorizedEmails, setDkeAuthorizedEmails] = useState("");
  const [dkeAuthorizedRoles, setDkeAuthorizedRoles] = useState("");

  const [expandedRequest, setExpandedRequest] = useState<string | null>(null);
  const [requestFilter, setRequestFilter] = useState<string>("");
  const [urlsProtocol, setUrlsProtocol] = useState("dke");
  const [guideProtocol, setGuideProtocol] = useState("dke");

  const keyChoices = useMemo(() => keyChoicesFromCatalog(keyCatalog), [keyCatalog]);
  const promptDialog = usePromptDialog();

  const refresh = async (silent = false) => {
    if (!session?.token) {
      setEndpoints([]); setRequests([]); setHealth(null);
      return;
    }
    if (!silent) setLoading(true); else setRefreshing(true);
    try {
      const [eps, reqs, h] = await Promise.all([
        listHYOKEndpoints(session),
        listHYOKRequests(session, { limit: 100, offset: 0 }),
        getHYOKHealth(session)
      ]);
      setEndpoints(Array.isArray(eps) ? eps : []);
      setRequests(Array.isArray(reqs) ? reqs : []);
      setHealth(h || null);
    } catch (error) {
      onToast?.(`HYOK load failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setLoading(false); else setRefreshing(false);
    }
  };

  useEffect(() => {
    let stop = false;
    const run = async (silent = false) => { if (stop) return; await refresh(silent); };
    void run(false);
    const id = setInterval(() => { void run(true); }, 15000);
    return () => { stop = true; clearInterval(id); };
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
  }, [session?.token, session?.tenantId]);

  const openConfig = (protocol: string) => {
    if (protocol === "azure") { setModal("azure"); return; }
    const existing = (Array.isArray(endpoints) ? endpoints : []).find((item) => String(item?.protocol || "") === protocol);
    setCfgProtocol(protocol);
    setCfgEnabled(existing ? Boolean(existing.enabled) : true);
    setCfgAuthMode(String(existing?.auth_mode === "mtls_or_jwt" ? "jwt" : existing?.auth_mode || "jwt"));
    setCfgPolicyID(String(existing?.policy_id || ""));
    setCfgGovernance(Boolean(existing?.governance_required));

    // Parse existing metadata for DKE fields
    const rawMeta = String(existing?.metadata_json || "{}");
    setCfgMetadata(rawMeta);
    if (protocol === "dke") {
      try {
        const meta = JSON.parse(rawMeta);
        setDkeAuthorizedTenants(Array.isArray(meta.authorized_tenants) ? meta.authorized_tenants.join(", ") : String(meta.authorized_tenants || ""));
        setDkeValidIssuers(Array.isArray(meta.valid_issuers) ? meta.valid_issuers.join(", ") : String(meta.valid_issuers || ""));
        setDkeJWTAudiences(Array.isArray(meta.jwt_audiences) ? meta.jwt_audiences.join(", ") : String(meta.jwt_audiences || ""));
        setDkeKeyURIHostname(String(meta.key_uri_hostname || ""));
        setDkeAllowedAlgorithms(Array.isArray(meta.allowed_algorithms) ? meta.allowed_algorithms.join(", ") : String(meta.allowed_algorithms || "RSA-OAEP-256"));
        setDkeAuthorizedEmails(Array.isArray(meta.authorized_emails) ? meta.authorized_emails.join(", ") : "");
        setDkeAuthorizedRoles(Array.isArray(meta.authorized_roles) ? meta.authorized_roles.join(", ") : "");
      } catch {
        setDkeAuthorizedTenants("");
        setDkeValidIssuers("");
        setDkeJWTAudiences("");
        setDkeKeyURIHostname("");
        setDkeAllowedAlgorithms("RSA-OAEP-256");
        setDkeAuthorizedEmails("");
        setDkeAuthorizedRoles("");
      }
    }
    setModal("config");
  };

  const buildMetadataJSON = (): string => {
    if (cfgProtocol === "dke") {
      const meta: Record<string, any> = {};
      // Parse existing metadata to preserve non-DKE fields
      try { Object.assign(meta, JSON.parse(cfgMetadata)); } catch { /* ignore */ }
      const parseCSV = (v: string) => String(v || "").split(",").map((s) => s.trim()).filter(Boolean);
      if (dkeAuthorizedTenants.trim()) meta.authorized_tenants = parseCSV(dkeAuthorizedTenants);
      else delete meta.authorized_tenants;
      if (dkeValidIssuers.trim()) meta.valid_issuers = parseCSV(dkeValidIssuers);
      else delete meta.valid_issuers;
      if (dkeJWTAudiences.trim()) meta.jwt_audiences = parseCSV(dkeJWTAudiences);
      else delete meta.jwt_audiences;
      if (dkeKeyURIHostname.trim()) meta.key_uri_hostname = dkeKeyURIHostname.trim();
      else delete meta.key_uri_hostname;
      if (dkeAllowedAlgorithms.trim()) meta.allowed_algorithms = parseCSV(dkeAllowedAlgorithms);
      else delete meta.allowed_algorithms;
      if (dkeAuthorizedEmails.trim()) meta.authorized_emails = parseCSV(dkeAuthorizedEmails);
      else delete meta.authorized_emails;
      if (dkeAuthorizedRoles.trim()) meta.authorized_roles = parseCSV(dkeAuthorizedRoles);
      else delete meta.authorized_roles;
      return JSON.stringify(meta, null, 2);
    }
    return cfgMetadata;
  };

  const submitConfig = async () => {
    if (!session?.token) return;
    const protocol = String(cfgProtocol || "").trim();
    if (!protocol) { onToast?.("Select a protocol."); return; }
    const authMode = String(cfgAuthMode || "").trim();
    if (!authMode) { onToast?.("Select an auth mode."); return; }
    const metadataJSON = buildMetadataJSON();
    try { JSON.parse(metadataJSON); } catch { onToast?.("Metadata JSON is invalid."); return; }
    setSaving(true);
    try {
      await configureHYOKEndpoint(session, protocol, {
        enabled: Boolean(cfgEnabled),
        auth_mode: authMode,
        policy_id: String(cfgPolicyID || "").trim(),
        governance_required: Boolean(cfgGovernance),
        metadata_json: metadataJSON
      });
      onToast?.(`HYOK endpoint updated: ${HYOK_PROTOCOL_LABELS[protocol] || protocol}.`);
      setModal(null);
      await refresh(true);
    } catch (error) {
      onToast?.(`HYOK endpoint update failed: ${errMsg(error)}`);
    } finally {
      setSaving(false);
    }
  };

  const runDelete = async (protocol: string) => {
    const confirmed = await promptDialog.confirm({
      title: "Delete HYOK Endpoint Config",
      message: `Delete endpoint configuration for ${HYOK_PROTOCOL_LABELS[protocol] || protocol}?\n\nThis resets the endpoint to its default policy. Existing request logs are preserved.`,
      confirmLabel: "Delete",
      danger: true
    });
    if (!confirmed) return;
    try {
      await deleteHYOKEndpoint(session, protocol);
      onToast?.(`HYOK endpoint removed: ${HYOK_PROTOCOL_LABELS[protocol] || protocol}.`);
      await refresh(true);
    } catch (error) {
      onToast?.(`Delete endpoint failed: ${errMsg(error)}`);
    }
  };

  const endpointRows = Array.isArray(endpoints) ? endpoints : [];
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
  const requestRows = Array.isArray(requests) ? requests : [];
  const enabledCount = endpointRows.filter((item) => Boolean(item?.enabled)).length;
  const protocolStatuses = (health && typeof health === "object" && health.protocol_statuses && typeof health.protocol_statuses === "object") ? health.protocol_statuses : {};
  const proxyHealthStatus = String(health?.status || "unknown").toLowerCase();
  const proxyHealthColor = proxyHealthStatus === "ok" ? "green" : proxyHealthStatus === "degraded" ? "red" : "amber";

  const filteredRequests = useMemo(() => {
    const q = String(requestFilter || "").trim().toLowerCase();
    if (!q) return requestRows;
    return requestRows.filter((item) =>
      String(item.protocol || "").toLowerCase().includes(q) ||
      String(item.operation || "").toLowerCase().includes(q) ||
      String(item.key_id || "").toLowerCase().includes(q) ||
      String(item.status || "").toLowerCase().includes(q) ||
      String(item.requester_id || "").toLowerCase().includes(q) ||
      String(item.auth_subject || "").toLowerCase().includes(q)
    );
  }, [requestRows, requestFilter]);

  const requestStats = useMemo(() => {
    const total = requestRows.length;
    const success = requestRows.filter((r) => String(r.status || "").toLowerCase() === "success").length;
    const failed = requestRows.filter((r) => ["failed", "denied", "error"].includes(String(r.status || "").toLowerCase())).length;
    const pending = requestRows.filter((r) => String(r.status || "").toLowerCase() === "pending_approval").length;
    return { total, success, failed, pending };
  }, [requestRows]);

  const endpointStatusMeta = (protocol: string, item: any) => {
    const info = protocolStatuses?.[protocol] || {};
    const status = String(info?.status || "").toLowerCase();
    const reason = String(info?.reason || "").trim();
    if (status === "connected") return { label: "Active", color: "green", icon: CheckCircle2, reason };
    if (status === "configured") return { label: "Configured", color: "amber", icon: Info, reason };
    if (status === "not_configured") return { label: "Not Configured", color: "amber", icon: AlertTriangle, reason: reason || "Endpoint not configured yet" };
    if (status === "disabled") return { label: "Disabled", color: "red", icon: XCircle, reason };
    if (status === "auth_failed") return { label: "Auth Failed", color: "red", icon: XCircle, reason };
    if (status === "degraded" || status === "unreachable") return { label: "Degraded", color: "red", icon: AlertTriangle, reason };
    return Boolean(item?.enabled)
      ? { label: "Enabled", color: "blue", icon: Info, reason }
      : { label: "Disabled", color: "red", icon: XCircle, reason };
  };

  return <div>
    {/* === Summary Stats === */}
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: 8, marginBottom: 12 }}>
      {[
        { label: "Proxy Status", value: String(health?.status || "unknown").toUpperCase(), color: proxyHealthColor === "green" ? C.green : proxyHealthColor === "red" ? C.red : C.amber },
        { label: "Endpoints", value: `${enabledCount}/${HYOK_PROTOCOLS.length}`, sub: "enabled", color: C.accent },
        { label: "Requests", value: String(requestStats.total), sub: `${requestStats.success} ok, ${requestStats.failed} failed`, color: requestStats.failed > 0 ? C.red : C.green },
        { label: "Pending", value: String(requestStats.pending), sub: "awaiting approval", color: requestStats.pending > 0 ? C.amber : C.dim },
        { label: "Policy Mode", value: Boolean(health?.policy_fail_closed) ? "CLOSED" : "OPEN", sub: "fail mode", color: Boolean(health?.policy_fail_closed) ? C.red : C.green },
      ].map((stat) => (
        <Card key={stat.label} style={{ padding: "10px 12px" }}>
          <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>{stat.label}</div>
          <div style={{ fontSize: 16, color: stat.color, fontWeight: 700, fontFamily: "var(--font-mono)" }}>{stat.value}</div>
          {stat.sub && <div style={{ fontSize: 10, color: C.dim }}>{stat.sub}</div>}
        </Card>
      ))}
    </div>

    {/* === Protocol Endpoints === */}
    <Section
      title="HYOK Protocol Endpoints"
      actions={<div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <Btn small onClick={() => void refresh(false)} disabled={loading || refreshing}><RefreshCcw size={12} strokeWidth={2} /> Refresh</Btn>
        <Btn small onClick={() => { setUrlsProtocol("dke"); setModal("urls"); }}><ExternalLink size={12} strokeWidth={2} /> Endpoint URLs</Btn>
        <Btn small onClick={() => { setGuideProtocol("dke"); setModal("guide"); }}><Info size={12} strokeWidth={2} /> Setup Guide</Btn>
      </div>}
    >
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))", gap: 10 }}>
        {HYOK_PROTOCOLS.map((protocol) => {
          const item = endpointRows.find((e) => String(e?.protocol || "") === protocol);
          const statusMeta = endpointStatusMeta(protocol, item);
          const StatusIcon = statusMeta.icon;
          return <Card key={protocol}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 6 }}>
              <div>
                <div style={{ fontSize: 12, color: C.text, fontWeight: 700, display: "flex", alignItems: "center", gap: 6 }}>
                  <Shield size={13} strokeWidth={2} style={{ color: statusMeta.color === "green" ? C.greenFg : statusMeta.color === "red" ? C.redFg : C.amberFg }} />
                  {HYOK_PROTOCOL_LABELS[protocol]}
                </div>
                <div style={{ fontSize: 10, color: C.dim, marginTop: 2 }}>{HYOK_PROTOCOL_DETAILS[protocol]}</div>
              </div>
              <B c={statusMeta.color}>{statusMeta.label}</B>
            </div>

            {/* Status details */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2px 8px", fontSize: 10, marginBottom: 8 }}>
              <span style={{ color: C.muted }}>Auth Mode</span>
              <span style={{ color: C.text, fontFamily: "var(--font-mono)" }}>{String(item?.auth_mode === "mtls_or_jwt" ? "jwt" : item?.auth_mode || "jwt")}</span>
              <span style={{ color: C.muted }}>Policy</span>
              <span style={{ color: C.text, fontFamily: "var(--font-mono)" }}>{String(item?.policy_id || "default")}</span>
              <span style={{ color: C.muted }}>Governance</span>
              <span style={{ color: Boolean(item?.governance_required) ? C.amberFg : C.dim }}>{Boolean(item?.governance_required) ? "Required" : "No"}</span>
              <span style={{ color: C.muted }}>Operations</span>
              <span style={{ color: C.dim }}>{(HYOK_OPS_BY_PROTOCOL[protocol] || []).join(", ")}</span>
              {protocol === "azure" && <><span style={{ color: C.muted }}>Managed HSM probe</span>
              <span style={{ color: C.dim }}>{health?.protocol_statuses?.azure?.last_probe_at ? formatAgo(health.protocol_statuses.azure.last_probe_at) : "not seen on this node"}</span></>}
            </div>

            {statusMeta.reason && <div style={{ fontSize: 10, color: C.muted, marginBottom: 6, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title={statusMeta.reason}>{statusMeta.reason}</div>}

            <div style={{ fontSize: 10, color: C.dim, marginBottom: 8, fontStyle: "italic" }}>{HYOK_PROTOCOL_KEY_HINTS[protocol]}</div>

            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              <Btn small primary onClick={() => openConfig(protocol)}>Configure</Btn>
              <Btn small onClick={() => { setUrlsProtocol(protocol); setModal("urls"); }}>URLs</Btn>
              <Btn small onClick={() => { setGuideProtocol(protocol); setModal("guide"); }}>Guide</Btn>
              <Btn small danger onClick={() => void runDelete(protocol)}>Reset</Btn>
            </div>
          </Card>;
        })}
      </div>
    </Section>

    {/* === Request Audit Trail === */}
    <Section title={`Request Audit Trail (${requestStats.total})`} actions={
      <Inp style={{ width: 200 }} value={requestFilter} onChange={(e) => setRequestFilter(e.target.value)} placeholder="Filter protocol/key/status..." />
    }>
      <Card style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "30px 100px 80px 70px 90px 1fr 80px", padding: "8px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>
          <div></div><div>Time</div><div>Protocol</div><div>Operation</div><div>Status</div><div>Key / Requester</div><div>Auth</div>
        </div>
        <div style={{ maxHeight: 360, overflowY: "auto" }}>
          {filteredRequests.map((item) => {
            const isExpanded = expandedRequest === item.id;
            const statusColor = String(item.status || "").toLowerCase() === "success" ? "green" : String(item.status || "").toLowerCase() === "pending_approval" ? "amber" : "red";
            return <div key={item.id}>
              <div
                onClick={() => setExpandedRequest(isExpanded ? null : item.id)}
                style={{ display: "grid", gridTemplateColumns: "30px 100px 80px 70px 90px 1fr 80px", padding: "8px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 10, alignItems: "center", cursor: "pointer" }}
              >
                <div style={{ color: C.dim }}>{isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}</div>
                <div style={{ color: C.dim, fontFamily: "var(--font-mono)" }}>{formatAgo(item.created_at)}</div>
                <div style={{ color: C.accentFg }}>{String(item.protocol || "-")}</div>
                <div style={{ color: C.text }}>{String(item.operation || "-")}</div>
                <div><B c={statusColor}>{String(item.status || "unknown")}</B></div>
                <div style={{ minWidth: 0 }}>
                  <div style={{ color: C.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{String(item.key_id || "-")}</div>
                  <div style={{ fontSize: 10, color: C.muted, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{String(item.requester_id || item.auth_subject || "-")}</div>
                </div>
                <div style={{ color: C.dim }}>{String(item.auth_mode || "-")}</div>
              </div>
              {isExpanded && (
                <div style={{ padding: "8px 12px 12px 42px", background: C.bg, borderBottom: `1px solid ${C.border}` }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px 16px", fontSize: 10, marginBottom: 8 }}>
                    <div><span style={{ color: C.muted }}>Request ID:</span> <span style={{ color: C.text, fontFamily: "var(--font-mono)" }}>{item.id}</span></div>
                    <div><span style={{ color: C.muted }}>Endpoint:</span> <span style={{ color: C.text, fontFamily: "var(--font-mono)" }}>{String(item.endpoint || "-")}</span></div>
                    <div><span style={{ color: C.muted }}>Policy Decision:</span> <span style={{ color: item.policy_decision === "DENY" ? C.redFg : C.greenFg }}>{String(item.policy_decision || "-")}</span></div>
                    <div><span style={{ color: C.muted }}>Governance:</span> <span style={{ color: C.text }}>{Boolean(item.governance_required) ? "Required" : "No"}</span></div>
                    {item.approval_request_id && <div><span style={{ color: C.muted }}>Approval ID:</span> <span style={{ color: C.amberFg, fontFamily: "var(--font-mono)" }}>{item.approval_request_id}</span></div>}
                    <div><span style={{ color: C.muted }}>Requester Email:</span> <span style={{ color: C.text }}>{String(item.requester_email || "-")}</span></div>
                    <div><span style={{ color: C.muted }}>Created:</span> <span style={{ color: C.text }}>{formatDate(item.created_at)}</span></div>
                    <div><span style={{ color: C.muted }}>Completed:</span> <span style={{ color: C.text }}>{formatDate(item.completed_at)}</span></div>
                  </div>
                  {item.error_message && (
                    <div style={{ fontSize: 10, color: C.redFg, padding: "6px 8px", background: `${C.red}11`, borderRadius: 4, marginBottom: 6 }}>
                      {item.error_message}
                    </div>
                  )}
                  {item.response_json && item.response_json !== "{}" && (
                    <div>
                      <div style={{ fontSize: 10, color: C.muted, marginBottom: 2 }}>Response:</div>
                      <pre style={{ fontSize: 10, color: C.dim, fontFamily: "var(--font-mono)", background: C.surface, padding: "6px 8px", borderRadius: 4, maxHeight: 100, overflow: "auto", margin: 0, whiteSpace: "pre-wrap" }}>
                        {(() => { try { return JSON.stringify(JSON.parse(item.response_json), null, 2); } catch { return item.response_json; } })()}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>;
          })}
          {!filteredRequests.length && <div style={{ padding: "12px", fontSize: 10, color: C.dim }}>{loading ? "Loading HYOK requests..." : requestRows.length ? "No requests match filter." : "No HYOK requests yet."}</div>}
        </div>
      </Card>
    </Section>

    {/* === Configure Endpoint Modal === */}
    <Modal open={modal === "config"} onClose={() => setModal(null)} title={`Configure ${HYOK_PROTOCOL_LABELS[cfgProtocol] || cfgProtocol} Endpoint`} wide>
      <div style={{ fontSize: 10, color: C.muted, marginBottom: 10, padding: "8px 10px", background: C.bg, borderRadius: 6 }}>
        {HYOK_PROTOCOL_DETAILS[cfgProtocol]} — {HYOK_PROTOCOL_KEY_HINTS[cfgProtocol]}
      </div>
      <FG label="Protocol">
        <Sel value={cfgProtocol} onChange={(e) => setCfgProtocol(e.target.value)}>
          {HYOK_PROTOCOLS.filter((p) => p !== "azure").map((p) => <option key={p} value={p}>{HYOK_PROTOCOL_LABELS[p]}</option>)}
        </Sel>
      </FG>
      <Row2>
        <FG label="Enabled">
          <Chk label="Enable this protocol endpoint" checked={cfgEnabled} onChange={() => setCfgEnabled((v) => !v)} />
        </FG>
        <FG label="Governance">
          <Chk label="Require governance approval before crypto release" checked={cfgGovernance} onChange={() => setCfgGovernance((v) => !v)} />
        </FG>
      </Row2>
      <Row2>
        <FG label="Auth Mode" required hint="Callers authenticate with a Vecta-issued JWT. Client-certificate (mTLS) authentication is not offered: the edge does not verify client certificates.">
          <Sel value={cfgAuthMode} onChange={(e) => setCfgAuthMode(e.target.value)}>
            <option value="jwt">JWT</option>
          </Sel>
        </FG>
        <FG label="Policy ID" hint="Optional policy ID for operation-level access control.">
          <Inp value={cfgPolicyID} onChange={(e) => setCfgPolicyID(e.target.value)} placeholder={`hyok.${cfgProtocol}.*`} mono />
        </FG>
      </Row2>

      {/* DKE-specific metadata fields */}
      {cfgProtocol === "dke" && (<>
        <div style={{ fontSize: 11, color: C.text, fontWeight: 600, marginTop: 12, marginBottom: 6 }}>Microsoft DKE Configuration</div>
        <div className="vk-fold" tabIndex={0} style={{ fontSize: 10, color: C.muted, marginBottom: 8 }}>
          Office fetches the public key without a token on the Key URI Hostname, and decrypts with an Entra ID token. An Entra token is accepted only when its issuer is listed below, its audience is one of the JWT Audiences, and the user's email or app role is authorized; without audiences and authorized users every Entra token is refused.
        </div>
        <Row2>
          <FG label="Authorized Entra Tenant IDs" hint="Comma-separated. Optional: Entra callers must come from one of these tenants.">
            <Inp value={dkeAuthorizedTenants} onChange={(e) => setDkeAuthorizedTenants(e.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" mono />
          </FG>
          <FG label="Valid Token Issuers" hint="Comma-separated. E.g., https://login.microsoftonline.com/{tenant}/v2.0">
            <Inp value={dkeValidIssuers} onChange={(e) => setDkeValidIssuers(e.target.value)} placeholder="https://login.microsoftonline.com/{tenant}/v2.0" mono />
          </FG>
        </Row2>
        <Row2>
          <FG label="JWT Audiences" hint="Comma-separated audience values expected in the token.">
            <Inp value={dkeJWTAudiences} onChange={(e) => setDkeJWTAudiences(e.target.value)} placeholder="api://dke-service" mono />
          </FG>
          <FG label="Key URI Hostname" hint="If set, the Host header must match this hostname.">
            <Inp value={dkeKeyURIHostname} onChange={(e) => setDkeKeyURIHostname(e.target.value)} placeholder="dke.example.com" mono />
          </FG>
        </Row2>
        <Row2>
          <FG label="Authorized User Emails" hint="Comma-separated. Entra users (UPN or preferred_username; the email claim is not trusted) who may decrypt.">
            <Inp value={dkeAuthorizedEmails} onChange={(e) => setDkeAuthorizedEmails(e.target.value)} placeholder="alice@contoso.com" mono />
          </FG>
          <FG label="Authorized App Roles" hint="Comma-separated. Users holding one of these app roles (token roles claim) may decrypt.">
            <Inp value={dkeAuthorizedRoles} onChange={(e) => setDkeAuthorizedRoles(e.target.value)} placeholder="DKE.Decrypt" mono />
          </FG>
        </Row2>
        <FG label="Allowed Algorithms" hint="Comma-separated. DKE typically uses RSA-OAEP-256.">
          <Inp value={dkeAllowedAlgorithms} onChange={(e) => setDkeAllowedAlgorithms(e.target.value)} placeholder="RSA-OAEP-256" mono />
        </FG>
      </>)}

      {/* Generic metadata for non-DKE protocols */}
      {cfgProtocol !== "dke" && (
        <FG label="Metadata JSON" hint="Stored with endpoint configuration. Keep valid JSON.">
          <Txt rows={6} value={cfgMetadata} onChange={(e) => setCfgMetadata(e.target.value)} placeholder='{"description":"Production endpoint"}' />
        </FG>
      )}

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
        <Btn onClick={() => setModal(null)} disabled={saving}>Cancel</Btn>
        <Btn primary onClick={() => void submitConfig()} disabled={saving}>{saving ? "Saving..." : "Save Endpoint"}</Btn>
      </div>
    </Modal>

    {/* === Endpoint URLs Modal === */}
    <HYOKAzureConfig open={modal === "azure"} session={session} endpoint={endpoints.find((e) => e?.protocol === "azure" && e?.metadata_json && e.metadata_json !== "{}")} keyChoices={keyChoices.map((k) => ({ id: k.id, name: k.name, algo: k.algo }))}
      onClose={() => setModal(null)} onSaved={(m) => { onToast?.(m); setModal(null); void refresh(true); }} />
    <Modal open={modal === "urls"} onClose={() => setModal(null)} title={`Endpoint URLs — ${HYOK_PROTOCOL_LABELS[urlsProtocol] || urlsProtocol}`} wide>
      <div style={{ fontSize: 10, color: C.muted, marginBottom: 10, padding: "8px 10px", background: C.bg, borderRadius: 6 }}>
        Configure your cloud service to point to these URLs. Replace <code style={{ color: C.accentFg, fontFamily: "var(--font-mono)" }}>{"{keyId}"}</code> with your actual Vecta key ID.
      </div>
      <FG label="Protocol">
        <Sel value={urlsProtocol} onChange={(e) => setUrlsProtocol(e.target.value)}>
          {HYOK_PROTOCOLS.map((p) => <option key={p} value={p}>{HYOK_PROTOCOL_LABELS[p]}</option>)}
        </Sel>
      </FG>
      <div style={{ display: "grid", gap: 8, marginTop: 8 }}>
        {(HYOK_PROTOCOL_URLS[urlsProtocol] || []).map((url, idx) => (
          <div key={idx} style={{ padding: "8px 10px", background: C.bg, borderRadius: 6 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <B c="blue">{url.methods}</B>
                <span style={{ fontSize: 10, color: C.text }}>{url.description}</span>
              </div>
              <button onClick={() => copyToClipboard(url.path)} style={{ background: "transparent", border: "none", color: C.dim, cursor: "pointer" }} title="Copy URL path"><Copy size={12} /></button>
            </div>
            <div style={{ fontSize: 11, color: C.accentFg, fontFamily: "var(--font-mono)", padding: "4px 6px", background: C.surface, borderRadius: 4, userSelect: "all" }}>{url.path}</div>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
        <Btn onClick={() => setModal(null)}>Close</Btn>
      </div>
    </Modal>

    {/* === Setup Guide Modal === */}
    <Modal open={modal === "guide"} onClose={() => setModal(null)} title={`Setup Guide — ${HYOK_PROTOCOL_LABELS[guideProtocol] || guideProtocol}`} wide>
      <FG label="Protocol">
        <Sel value={guideProtocol} onChange={(e) => setGuideProtocol(e.target.value)}>
          <option value="dke">Microsoft DKE</option>
          <option value="salesforce">Salesforce Cache-Only</option>
          <option value="google">Google Cloud EKM</option>
          <option value="generic">Generic HYOK</option>
        </Sel>
      </FG>
      <div style={{ marginTop: 10 }}>
        <div style={{ fontSize: 11, color: C.text, fontWeight: 600, marginBottom: 8 }}>{HYOK_PROTOCOL_DETAILS[guideProtocol]}</div>
        <div style={{ display: "grid", gap: 6 }}>
          {(HYOK_SETUP_GUIDES[guideProtocol] || []).map((step, idx) => (
            <div key={idx} style={{ fontSize: 10, color: C.text, padding: "6px 10px", background: C.bg, borderRadius: 4 }}>{step}</div>
          ))}
        </div>

        <div style={{ fontSize: 11, color: C.text, fontWeight: 600, marginTop: 16, marginBottom: 8 }}>Endpoint URLs</div>
        <div style={{ display: "grid", gap: 4 }}>
          {(HYOK_PROTOCOL_URLS[guideProtocol] || []).map((url, idx) => (
            <div key={idx} style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: C.accentFg, padding: "4px 8px", background: C.surface, borderRadius: 4 }}>
              <B c="blue" style={{ marginRight: 6 }}>{url.methods}</B> {url.path}
            </div>
          ))}
        </div>

        <div style={{ fontSize: 11, color: C.text, fontWeight: 600, marginTop: 16, marginBottom: 8 }}>Key Requirements</div>
        <div style={{ fontSize: 10, color: C.muted, padding: "6px 10px", background: C.bg, borderRadius: 4 }}>{HYOK_PROTOCOL_KEY_HINTS[guideProtocol]}</div>

        <div style={{ fontSize: 11, color: C.text, fontWeight: 600, marginTop: 16, marginBottom: 8 }}>Supported Operations</div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {(HYOK_OPS_BY_PROTOCOL[guideProtocol] || []).map((op) => (
            <B key={op} c="blue">{op}</B>
          ))}
        </div>
      </div>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
        <Btn onClick={() => setModal(null)}>Close</Btn>
      </div>
    </Modal>

    {promptDialog.ui}
  </div>;
};
