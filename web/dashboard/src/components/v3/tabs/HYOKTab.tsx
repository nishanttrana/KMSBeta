// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { RefreshCcw, Copy, ChevronDown, ChevronRight, Shield, ExternalLink, AlertTriangle, CheckCircle2, XCircle, Info } from "lucide-react";
import {
  configureHYOKEndpoint,
  deleteHYOKEndpoint,
  getHYOKDKEPublicKey,
  getHYOKHealth,
  hyokCrypto,
  listHYOKEndpoints,
  listHYOKRequests
} from "../../../lib/hyok";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Chk, FG, Inp, Modal, Row2, Section, Sel, Txt, usePromptDialog } from "../legacyPrimitives";

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

const HYOK_PROTOCOL_LABELS: Record<string, string> = {
  dke: "Microsoft DKE",
  salesforce: "Salesforce Cache-Only",
  google: "Google Cloud EKM",
  generic: "Generic HYOK"
};

const HYOK_PROTOCOL_DETAILS: Record<string, string> = {
  dke: "Double Key Encryption for Microsoft 365 / Purview Information Protection",
  salesforce: "Shield Platform Encryption with Cache-Only Key Service",
  google: "External Key Manager for Google Cloud CMEK",
  generic: "Generic encrypt / decrypt / wrap / unwrap proxy"
};

const HYOK_PROTOCOL_KEY_HINTS: Record<string, string> = {
  dke: "Requires RSA key (2048+ bits). Public key is served via DKE endpoint for Microsoft clients.",
  salesforce: "Supports AES-256 or RSA keys for wrap/unwrap operations.",
  google: "Supports AES-256 or RSA keys for wrap/unwrap operations with Google Cloud CMEK.",
  generic: "Any symmetric or asymmetric key supported by your Vecta KMS instance."
};

const HYOK_OPS_BY_PROTOCOL: Record<string, string[]> = {
  dke: ["decrypt", "publickey"],
  salesforce: ["wrap", "unwrap"],
  google: ["wrap", "unwrap"],
  generic: ["encrypt", "decrypt", "wrap", "unwrap"]
};

const HYOK_PROTOCOL_URLS: Record<string, { path: string; methods: string; description: string }[]> = {
  dke: [
    { path: "/api/v1/keys/{keyId}", methods: "GET", description: "Microsoft-compatible public key endpoint (JWK format)" },
    { path: "/api/v1/keys/{keyId}/decrypt", methods: "POST", description: "Microsoft-compatible DKE decrypt endpoint" },
    { path: "/hyok/dke/v1/keys/{keyId}/publickey", methods: "GET", description: "Standard DKE public key endpoint" },
    { path: "/hyok/dke/v1/keys/{keyId}/decrypt", methods: "POST", description: "Standard DKE decrypt endpoint" },
  ],
  salesforce: [
    { path: "/hyok/salesforce/v1/keys/{keyId}/wrap", methods: "POST", description: "Salesforce key wrap endpoint" },
    { path: "/hyok/salesforce/v1/keys/{keyId}/unwrap", methods: "POST", description: "Salesforce key unwrap endpoint" },
  ],
  google: [
    { path: "/hyok/google/v1/keys/{keyId}/wrap", methods: "POST", description: "Google EKM key wrap endpoint" },
    { path: "/hyok/google/v1/keys/{keyId}/unwrap", methods: "POST", description: "Google EKM key unwrap endpoint" },
  ],
  generic: [
    { path: "/hyok/generic/v1/keys/{keyId}/encrypt", methods: "POST", description: "Generic encrypt endpoint" },
    { path: "/hyok/generic/v1/keys/{keyId}/decrypt", methods: "POST", description: "Generic decrypt endpoint" },
    { path: "/hyok/generic/v1/keys/{keyId}/wrap", methods: "POST", description: "Generic key wrap endpoint" },
    { path: "/hyok/generic/v1/keys/{keyId}/unwrap", methods: "POST", description: "Generic key unwrap endpoint" },
  ],
};

const HYOK_SETUP_GUIDES: Record<string, string[]> = {
  dke: [
    "1. Create an RSA key (2048+ bits) in Vecta KMS",
    "2. Enable the DKE protocol endpoint below",
    "3. Configure auth mode (mTLS recommended for production)",
    "4. Set authorized tenants, valid issuers, and JWT audiences in metadata",
    "5. In Microsoft Purview, configure the DKE service URL to point to your Vecta HYOK endpoint",
    "6. Test the public key endpoint: GET /api/v1/keys/{keyId}",
  ],
  salesforce: [
    "1. Create an AES-256 or RSA key in Vecta KMS",
    "2. Enable the Salesforce Cache-Only protocol endpoint below",
    "3. Configure auth mode (mTLS or JWT per Salesforce requirements)",
    "4. In Salesforce Setup, configure Shield Platform Encryption to use Cache-Only Key Service",
    "5. Point the Cache-Only Key Service URL to your Vecta HYOK endpoint",
    "6. Test with the wrap/unwrap operations below",
  ],
  google: [
    "1. Create an AES-256 or RSA key in Vecta KMS",
    "2. Enable the Google EKM protocol endpoint below",
    "3. Configure auth mode and optional policy ID",
    "4. In Google Cloud Console, create an EKM connection pointing to your Vecta HYOK endpoint",
    "5. Create a Cloud KMS key ring using the external key manager",
    "6. Test with the wrap/unwrap operations below",
  ],
  generic: [
    "1. Create a key in Vecta KMS (any supported algorithm)",
    "2. Enable the Generic HYOK protocol endpoint below",
    "3. Configure auth mode and optional policy/governance requirements",
    "4. Use the endpoint URLs below to integrate with your application",
    "5. Test all operations using the Live Test Console",
  ],
};

export const HYOKTab = ({ session, keyCatalog, onToast }) => {
  const [modal, setModal] = useState<null | "config" | "urls" | "guide">(null);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [endpoints, setEndpoints] = useState<any[]>([]);
  const [requests, setRequests] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);
  const [cfgProtocol, setCfgProtocol] = useState("generic");
  const [cfgEnabled, setCfgEnabled] = useState(true);
  const [cfgAuthMode, setCfgAuthMode] = useState("mtls_or_jwt");
  const [cfgPolicyID, setCfgPolicyID] = useState("");
  const [cfgGovernance, setCfgGovernance] = useState(false);
  const [cfgMetadata, setCfgMetadata] = useState("{\n  \"description\": \"\"\n}");
  // DKE-specific metadata fields
  const [dkeAuthorizedTenants, setDkeAuthorizedTenants] = useState("");
  const [dkeValidIssuers, setDkeValidIssuers] = useState("");
  const [dkeJWTAudiences, setDkeJWTAudiences] = useState("");
  const [dkeKeyURIHostname, setDkeKeyURIHostname] = useState("");
  const [dkeAllowedAlgorithms, setDkeAllowedAlgorithms] = useState("RSA-OAEP-256");

  const [testProtocol, setTestProtocol] = useState("generic");
  const [testOperation, setTestOperation] = useState("encrypt");
  const [testKeyID, setTestKeyID] = useState("");
  const [testPlaintext, setTestPlaintext] = useState("");
  const [testCiphertext, setTestCiphertext] = useState("");
  const [testIV, setTestIV] = useState("");
  const [testRefID, setTestRefID] = useState("");
  const [testRequester, setTestRequester] = useState("");
  const [testRequesterEmail, setTestRequesterEmail] = useState("");
  const [testOutput, setTestOutput] = useState("// HYOK result will appear here...");
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
  }, [session?.token, session?.tenantId]);

  useEffect(() => {
    if (testKeyID) return;
    const first = Array.isArray(keyChoices) ? keyChoices[0] : null;
    if (first?.id) setTestKeyID(String(first.id));
  }, [keyChoices, testKeyID]);

  useEffect(() => {
    const allowed = HYOK_OPS_BY_PROTOCOL[testProtocol] || [];
    if (!allowed.includes(testOperation)) setTestOperation(String(allowed[0] || "encrypt"));
  }, [testProtocol, testOperation]);

  const openConfig = (protocol: string) => {
    const existing = (Array.isArray(endpoints) ? endpoints : []).find((item) => String(item?.protocol || "") === protocol);
    setCfgProtocol(protocol);
    setCfgEnabled(existing ? Boolean(existing.enabled) : true);
    setCfgAuthMode(String(existing?.auth_mode || "mtls_or_jwt"));
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
      } catch {
        setDkeAuthorizedTenants("");
        setDkeValidIssuers("");
        setDkeJWTAudiences("");
        setDkeKeyURIHostname("");
        setDkeAllowedAlgorithms("RSA-OAEP-256");
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

  const executeTest = async () => {
    if (!session?.token) return;
    const keyID = String(testKeyID || "").trim();
    if (!keyID) { onToast?.("Select a key."); return; }
    const protocol = String(testProtocol || "generic");
    const operation = String(testOperation || "encrypt");
    setExecuting(true);
    setTestOutput("// Executing...");
    try {
      if (protocol === "dke" && operation === "publickey") {
        const out = await getHYOKDKEPublicKey(session, keyID);
        setTestOutput(JSON.stringify(out, null, 2));
      } else {
        const out = await hyokCrypto(session, protocol, operation, keyID, {
          plaintext: testPlaintext,
          ciphertext: testCiphertext,
          iv: testIV,
          reference_id: testRefID,
          requester_id: testRequester,
          requester_email: testRequesterEmail
        });
        setTestOutput(JSON.stringify(out, null, 2));
      }
      onToast?.(`HYOK ${operation} completed.`);
      await refresh(true);
    } catch (error) {
      setTestOutput(`// Error: ${errMsg(error)}`);
      onToast?.(`HYOK ${operation} failed: ${errMsg(error)}`);
    } finally {
      setExecuting(false);
    }
  };

  const endpointRows = Array.isArray(endpoints) ? endpoints : [];
  const requestRows = Array.isArray(requests) ? requests : [];
  const allowedOps = HYOK_OPS_BY_PROTOCOL[testProtocol] || [];
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
        { label: "Endpoints", value: `${enabledCount}/${endpointRows.length || 4}`, sub: "enabled", color: C.accent },
        { label: "Requests", value: String(requestStats.total), sub: `${requestStats.success} ok, ${requestStats.failed} failed`, color: requestStats.failed > 0 ? C.red : C.green },
        { label: "Pending", value: String(requestStats.pending), sub: "awaiting approval", color: requestStats.pending > 0 ? C.amber : C.dim },
        { label: "Policy Mode", value: Boolean(health?.policy_fail_closed) ? "CLOSED" : "OPEN", sub: "fail mode", color: Boolean(health?.policy_fail_closed) ? C.red : C.green },
      ].map((stat) => (
        <Card key={stat.label} style={{ padding: "10px 12px" }}>
          <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>{stat.label}</div>
          <div style={{ fontSize: 16, color: stat.color, fontWeight: 700, fontFamily: "'JetBrains Mono',monospace" }}>{stat.value}</div>
          {stat.sub && <div style={{ fontSize: 9, color: C.dim }}>{stat.sub}</div>}
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
        {["dke", "salesforce", "google", "generic"].map((protocol) => {
          const item = endpointRows.find((e) => String(e?.protocol || "") === protocol);
          const statusMeta = endpointStatusMeta(protocol, item);
          const StatusIcon = statusMeta.icon;
          return <Card key={protocol}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 6 }}>
              <div>
                <div style={{ fontSize: 12, color: C.text, fontWeight: 700, display: "flex", alignItems: "center", gap: 6 }}>
                  <Shield size={13} strokeWidth={2} style={{ color: statusMeta.color === "green" ? C.green : statusMeta.color === "red" ? C.red : C.amber }} />
                  {HYOK_PROTOCOL_LABELS[protocol]}
                </div>
                <div style={{ fontSize: 9, color: C.dim, marginTop: 2 }}>{HYOK_PROTOCOL_DETAILS[protocol]}</div>
              </div>
              <B c={statusMeta.color}>{statusMeta.label}</B>
            </div>

            {/* Status details */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2px 8px", fontSize: 10, marginBottom: 8 }}>
              <span style={{ color: C.muted }}>Auth Mode</span>
              <span style={{ color: C.text, fontFamily: "'JetBrains Mono',monospace" }}>{String(item?.auth_mode || "mtls_or_jwt")}</span>
              <span style={{ color: C.muted }}>Policy</span>
              <span style={{ color: C.text, fontFamily: "'JetBrains Mono',monospace" }}>{String(item?.policy_id || "default")}</span>
              <span style={{ color: C.muted }}>Governance</span>
              <span style={{ color: Boolean(item?.governance_required) ? C.amber : C.dim }}>{Boolean(item?.governance_required) ? "Required" : "No"}</span>
              <span style={{ color: C.muted }}>Operations</span>
              <span style={{ color: C.dim }}>{(HYOK_OPS_BY_PROTOCOL[protocol] || []).join(", ")}</span>
            </div>

            {statusMeta.reason && <div style={{ fontSize: 9, color: C.muted, marginBottom: 6, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title={statusMeta.reason}>{statusMeta.reason}</div>}

            <div style={{ fontSize: 9, color: C.dim, marginBottom: 8, fontStyle: "italic" }}>{HYOK_PROTOCOL_KEY_HINTS[protocol]}</div>

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

    {/* === Live Test Console === */}
    <Section title="Live Test Console">
      <Row2>
        <Card>
          <div style={{ fontSize: 10, color: C.muted, marginBottom: 8, padding: "6px 8px", background: C.bg, borderRadius: 4 }}>
            Test HYOK crypto operations against your configured endpoints. All requests go through the full policy + governance pipeline.
          </div>
          <Row2>
            <FG label="Protocol" required>
              <Sel value={testProtocol} onChange={(e) => setTestProtocol(e.target.value)}>
                <option value="dke">Microsoft DKE</option>
                <option value="salesforce">Salesforce Cache-Only</option>
                <option value="google">Google Cloud EKM</option>
                <option value="generic">Generic HYOK</option>
              </Sel>
            </FG>
            <FG label="Operation" required>
              <Sel value={testOperation} onChange={(e) => setTestOperation(e.target.value)}>
                {allowedOps.map((op) => <option key={op} value={op}>{op}</option>)}
              </Sel>
            </FG>
          </Row2>
          <FG label="Vecta Key" required hint={HYOK_PROTOCOL_KEY_HINTS[testProtocol]}>
            <Sel value={testKeyID} onChange={(e) => setTestKeyID(e.target.value)}>
              {renderKeyOptions(keyChoices)}
            </Sel>
          </FG>
          {testOperation === "encrypt" || testOperation === "wrap" ? <FG label="Plaintext (base64)" required>
            <Txt rows={3} value={testPlaintext} onChange={(e) => setTestPlaintext(e.target.value)} placeholder="SGVsbG8gd29ybGQ=" />
          </FG> : null}
          {testOperation === "decrypt" || testOperation === "unwrap" ? <FG label="Ciphertext (base64)" required>
            <Txt rows={3} value={testCiphertext} onChange={(e) => setTestCiphertext(e.target.value)} placeholder="Paste ciphertext base64" />
          </FG> : null}
          {testOperation !== "publickey" ? <Row2>
            <FG label="IV (base64)">
              <Inp value={testIV} onChange={(e) => setTestIV(e.target.value)} placeholder="Optional" mono />
            </FG>
            <FG label="Reference ID">
              <Inp value={testRefID} onChange={(e) => setTestRefID(e.target.value)} placeholder="txn-..." mono />
            </FG>
          </Row2> : null}
          <Row2>
            <FG label="Requester ID">
              <Inp value={testRequester} onChange={(e) => setTestRequester(e.target.value)} placeholder="svc-app-01" mono />
            </FG>
            <FG label="Requester Email">
              <Inp value={testRequesterEmail} onChange={(e) => setTestRequesterEmail(e.target.value)} placeholder="security@example.com" mono />
            </FG>
          </Row2>
          <Btn primary onClick={() => void executeTest()} disabled={executing} style={{ width: "100%" }}>{executing ? "Executing..." : `Execute ${testOperation.toUpperCase()}`}</Btn>
        </Card>
        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
            <div style={{ fontSize: 11, color: C.muted, fontWeight: 700 }}>OUTPUT</div>
            <button onClick={() => copyToClipboard(testOutput)} style={{ background: "transparent", border: "none", color: C.dim, cursor: "pointer" }} title="Copy output"><Copy size={12} /></button>
          </div>
          <Txt rows={22} value={testOutput} readOnly />
        </Card>
      </Row2>
    </Section>

    {/* === Request Audit Trail === */}
    <Section title={`Request Audit Trail (${requestStats.total})`} actions={
      <Inp style={{ width: 200 }} value={requestFilter} onChange={(e) => setRequestFilter(e.target.value)} placeholder="Filter protocol/key/status..." />
    }>
      <Card style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "30px 100px 80px 70px 90px 1fr 80px", padding: "8px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>
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
                <div style={{ color: C.dim, fontFamily: "'JetBrains Mono',monospace" }}>{formatAgo(item.created_at)}</div>
                <div style={{ color: C.accent }}>{String(item.protocol || "-")}</div>
                <div style={{ color: C.text }}>{String(item.operation || "-")}</div>
                <div><B c={statusColor}>{String(item.status || "unknown")}</B></div>
                <div style={{ minWidth: 0 }}>
                  <div style={{ color: C.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{String(item.key_id || "-")}</div>
                  <div style={{ fontSize: 9, color: C.muted, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{String(item.requester_id || item.auth_subject || "-")}</div>
                </div>
                <div style={{ color: C.dim }}>{String(item.auth_mode || "-")}</div>
              </div>
              {isExpanded && (
                <div style={{ padding: "8px 12px 12px 42px", background: C.bg, borderBottom: `1px solid ${C.border}` }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px 16px", fontSize: 10, marginBottom: 8 }}>
                    <div><span style={{ color: C.muted }}>Request ID:</span> <span style={{ color: C.text, fontFamily: "'JetBrains Mono',monospace" }}>{item.id}</span></div>
                    <div><span style={{ color: C.muted }}>Endpoint:</span> <span style={{ color: C.text, fontFamily: "'JetBrains Mono',monospace" }}>{String(item.endpoint || "-")}</span></div>
                    <div><span style={{ color: C.muted }}>Policy Decision:</span> <span style={{ color: item.policy_decision === "DENY" ? C.red : C.green }}>{String(item.policy_decision || "-")}</span></div>
                    <div><span style={{ color: C.muted }}>Governance:</span> <span style={{ color: C.text }}>{Boolean(item.governance_required) ? "Required" : "No"}</span></div>
                    {item.approval_request_id && <div><span style={{ color: C.muted }}>Approval ID:</span> <span style={{ color: C.amber, fontFamily: "'JetBrains Mono',monospace" }}>{item.approval_request_id}</span></div>}
                    <div><span style={{ color: C.muted }}>Requester Email:</span> <span style={{ color: C.text }}>{String(item.requester_email || "-")}</span></div>
                    <div><span style={{ color: C.muted }}>Created:</span> <span style={{ color: C.text }}>{formatDate(item.created_at)}</span></div>
                    <div><span style={{ color: C.muted }}>Completed:</span> <span style={{ color: C.text }}>{formatDate(item.completed_at)}</span></div>
                  </div>
                  {item.error_message && (
                    <div style={{ fontSize: 10, color: C.red, padding: "6px 8px", background: `${C.red}11`, borderRadius: 4, marginBottom: 6 }}>
                      {item.error_message}
                    </div>
                  )}
                  {item.response_json && item.response_json !== "{}" && (
                    <div>
                      <div style={{ fontSize: 9, color: C.muted, marginBottom: 2 }}>Response:</div>
                      <pre style={{ fontSize: 9, color: C.dim, fontFamily: "'JetBrains Mono',monospace", background: C.surface, padding: "6px 8px", borderRadius: 4, maxHeight: 100, overflow: "auto", margin: 0, whiteSpace: "pre-wrap" }}>
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
          <option value="dke">Microsoft DKE</option>
          <option value="salesforce">Salesforce Cache-Only</option>
          <option value="google">Google Cloud EKM</option>
          <option value="generic">Generic HYOK</option>
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
        <FG label="Auth Mode" required hint="mTLS recommended for production deployments.">
          <Sel value={cfgAuthMode} onChange={(e) => setCfgAuthMode(e.target.value)}>
            <option value="mtls_or_jwt">mTLS or JWT</option>
            <option value="mtls">mTLS only</option>
            <option value="jwt">JWT only</option>
          </Sel>
        </FG>
        <FG label="Policy ID" hint="Optional policy ID for operation-level access control.">
          <Inp value={cfgPolicyID} onChange={(e) => setCfgPolicyID(e.target.value)} placeholder={`hyok.${cfgProtocol}.*`} mono />
        </FG>
      </Row2>

      {/* DKE-specific metadata fields */}
      {cfgProtocol === "dke" && (<>
        <div style={{ fontSize: 11, color: C.text, fontWeight: 600, marginTop: 12, marginBottom: 6 }}>Microsoft DKE Configuration</div>
        <div style={{ fontSize: 9, color: C.muted, marginBottom: 8 }}>
          These fields control which Microsoft tenants and token issuers are authorized to use this DKE endpoint. Leave empty to allow all.
        </div>
        <Row2>
          <FG label="Authorized Azure AD Tenant IDs" hint="Comma-separated. Only these tenants can use this endpoint.">
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
    <Modal open={modal === "urls"} onClose={() => setModal(null)} title={`Endpoint URLs — ${HYOK_PROTOCOL_LABELS[urlsProtocol] || urlsProtocol}`} wide>
      <div style={{ fontSize: 10, color: C.muted, marginBottom: 10, padding: "8px 10px", background: C.bg, borderRadius: 6 }}>
        Configure your cloud service to point to these URLs. Replace <code style={{ color: C.accent, fontFamily: "'JetBrains Mono',monospace" }}>{"{keyId}"}</code> with your actual Vecta key ID.
      </div>
      <FG label="Protocol">
        <Sel value={urlsProtocol} onChange={(e) => setUrlsProtocol(e.target.value)}>
          <option value="dke">Microsoft DKE</option>
          <option value="salesforce">Salesforce Cache-Only</option>
          <option value="google">Google Cloud EKM</option>
          <option value="generic">Generic HYOK</option>
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
            <div style={{ fontSize: 11, color: C.accent, fontFamily: "'JetBrains Mono',monospace", padding: "4px 6px", background: C.surface, borderRadius: 4, userSelect: "all" }}>{url.path}</div>
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
            <div key={idx} style={{ fontSize: 10, fontFamily: "'JetBrains Mono',monospace", color: C.accent, padding: "4px 8px", background: C.surface, borderRadius: 4 }}>
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
