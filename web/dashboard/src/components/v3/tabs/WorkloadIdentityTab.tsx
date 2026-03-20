// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { B, Btn, Card, Chk, FG, Inp, Row2, Section, Sel, Stat, Tabs, Txt } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  deleteWorkloadFederationBundle,
  deleteWorkloadRegistration,
  exchangeWorkloadToken,
  getWorkloadAuthorizationGraph,
  getWorkloadIdentitySettings,
  getWorkloadIdentitySummary,
  issueWorkloadSVID,
  listWorkloadFederationBundles,
  listWorkloadIssuances,
  listWorkloadRegistrations,
  listWorkloadUsage,
  updateWorkloadIdentitySettings,
  upsertWorkloadFederationBundle,
  upsertWorkloadRegistration
} from "../../../lib/workloadIdentity";

function fmtTS(value: any) {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return dt.toLocaleString();
}

function csvToList(raw: any) {
  return String(raw || "").split(",").map((v) => String(v || "").trim()).filter(Boolean);
}

function listToCSV(values: any) {
  return Array.isArray(values) ? values.map((v) => String(v || "").trim()).filter(Boolean).join(", ") : "";
}

function healthTone(ok: boolean) {
  return ok ? "green" : "amber";
}

export const WorkloadIdentityTab = ({ session, onToast }: any) => {
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState("Overview");
  const [settings, setSettings] = useState<any>({});
  const [summary, setSummary] = useState<any>({});
  const [registrations, setRegistrations] = useState<any[]>([]);
  const [bundles, setBundles] = useState<any[]>([]);
  const [issuances, setIssuances] = useState<any[]>([]);
  const [usage, setUsage] = useState<any[]>([]);
  const [graph, setGraph] = useState<any>({ nodes: [], edges: [] });

  const [settingsDraft, setSettingsDraft] = useState<any>({});
  const [registrationDraft, setRegistrationDraft] = useState<any>({
    name: "",
    spiffe_id: "",
    selectors: "",
    allowed_interfaces: "rest",
    allowed_key_ids: "",
    permissions: "key.encrypt, key.decrypt",
    issue_x509_svid: false,
    issue_jwt_svid: true,
    enabled: true,
    default_ttl_seconds: 1800
  });
  const [federationDraft, setFederationDraft] = useState<any>({
    trust_domain: "",
    bundle_endpoint: "",
    jwks_json: "",
    ca_bundle_pem: "",
    enabled: true
  });
  const [issueDraft, setIssueDraft] = useState<any>({
    registration_id: "",
    svid_type: "jwt",
    audiences: "kms",
    ttl_seconds: 1800
  });
  const [exchangeDraft, setExchangeDraft] = useState<any>({
    registration_id: "",
    interface_name: "rest",
    audience: "kms",
    requested_permissions: "key.encrypt, key.decrypt",
    requested_key_ids: "",
    jwt_svid: "",
    x509_svid_chain_pem: ""
  });
  const [lastIssued, setLastIssued] = useState<any>(null);
  const [lastExchange, setLastExchange] = useState<any>(null);

  const load = async (silent = false) => {
    if (!session?.token) {
      setSettings({});
      setSummary({});
      setRegistrations([]);
      setBundles([]);
      setIssuances([]);
      setUsage([]);
      setGraph({ nodes: [], edges: [] });
      return;
    }
    if (!silent) setLoading(true);
    try {
      const [settingsOut, summaryOut, regsOut, bundlesOut, issuancesOut, usageOut, graphOut] = await Promise.all([
        getWorkloadIdentitySettings(session),
        getWorkloadIdentitySummary(session),
        listWorkloadRegistrations(session),
        listWorkloadFederationBundles(session),
        listWorkloadIssuances(session, 100),
        listWorkloadUsage(session, 100),
        getWorkloadAuthorizationGraph(session)
      ]);
      setSettings(settingsOut || {});
      setSummary(summaryOut || {});
      setRegistrations(Array.isArray(regsOut) ? regsOut : []);
      setBundles(Array.isArray(bundlesOut) ? bundlesOut : []);
      setIssuances(Array.isArray(issuancesOut) ? issuancesOut : []);
      setUsage(Array.isArray(usageOut) ? usageOut : []);
      setGraph(graphOut || { nodes: [], edges: [] });
      setSettingsDraft({
        enabled: Boolean(settingsOut?.enabled),
        trust_domain: String(settingsOut?.trust_domain || ""),
        federation_enabled: Boolean(settingsOut?.federation_enabled),
        token_exchange_enabled: Boolean(settingsOut?.token_exchange_enabled),
        disable_static_api_keys: Boolean(settingsOut?.disable_static_api_keys),
        default_x509_ttl_seconds: Number(settingsOut?.default_x509_ttl_seconds || 43200),
        default_jwt_ttl_seconds: Number(settingsOut?.default_jwt_ttl_seconds || 1800),
        rotation_window_seconds: Number(settingsOut?.rotation_window_seconds || 1800),
        allowed_audiences: listToCSV(settingsOut?.allowed_audiences)
      });
    } catch (error) {
      onToast?.(`Workload Identity load failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    void load(true);
  }, [session?.token, session?.tenantId]);

  const saveSettings = async () => {
    if (!session?.token) return;
    setBusy(true);
    try {
      await updateWorkloadIdentitySettings(session, {
        ...settingsDraft,
        allowed_audiences: csvToList(settingsDraft?.allowed_audiences)
      });
      onToast?.("Workload Identity settings saved");
      await load(true);
    } catch (error) {
      onToast?.(`Settings save failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const saveRegistration = async () => {
    if (!session?.token) return;
    setBusy(true);
    try {
      await upsertWorkloadRegistration(session, {
        ...registrationDraft,
        selectors: csvToList(registrationDraft?.selectors),
        allowed_interfaces: csvToList(registrationDraft?.allowed_interfaces),
        allowed_key_ids: csvToList(registrationDraft?.allowed_key_ids),
        permissions: csvToList(registrationDraft?.permissions),
        default_ttl_seconds: Number(registrationDraft?.default_ttl_seconds || 1800)
      });
      onToast?.("Registration saved");
      setRegistrationDraft({
        name: "",
        spiffe_id: "",
        selectors: "",
        allowed_interfaces: "rest",
        allowed_key_ids: "",
        permissions: "key.encrypt, key.decrypt",
        issue_x509_svid: false,
        issue_jwt_svid: true,
        enabled: true,
        default_ttl_seconds: 1800
      });
      await load(true);
    } catch (error) {
      onToast?.(`Registration save failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const saveFederation = async () => {
    if (!session?.token) return;
    setBusy(true);
    try {
      await upsertWorkloadFederationBundle(session, federationDraft);
      onToast?.("Federation bundle saved");
      setFederationDraft({ trust_domain: "", bundle_endpoint: "", jwks_json: "", ca_bundle_pem: "", enabled: true });
      await load(true);
    } catch (error) {
      onToast?.(`Federation save failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const runIssue = async () => {
    if (!session?.token) return;
    setBusy(true);
    try {
      const out = await issueWorkloadSVID(session, {
        registration_id: issueDraft?.registration_id,
        svid_type: issueDraft?.svid_type,
        audiences: csvToList(issueDraft?.audiences),
        ttl_seconds: Number(issueDraft?.ttl_seconds || 1800),
        requested_by: String(session?.username || "dashboard")
      });
      setLastIssued(out || null);
      if (String(out?.svid_type || "").trim() === "jwt") {
        setExchangeDraft((prev: any) => ({ ...prev, registration_id: String(out?.registration_id || prev?.registration_id || ""), jwt_svid: String(out?.jwt_svid || "") }));
      } else {
        setExchangeDraft((prev: any) => ({ ...prev, registration_id: String(out?.registration_id || prev?.registration_id || ""), x509_svid_chain_pem: `${String(out?.certificate_pem || "")}\n${String(out?.bundle_pem || "")}`.trim() }));
      }
      onToast?.("SVID issued");
      await load(true);
    } catch (error) {
      onToast?.(`SVID issuance failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const runExchange = async () => {
    if (!session?.token) return;
    setBusy(true);
    try {
      const out = await exchangeWorkloadToken(session, {
        registration_id: exchangeDraft?.registration_id,
        interface_name: exchangeDraft?.interface_name,
        audience: exchangeDraft?.audience,
        requested_permissions: csvToList(exchangeDraft?.requested_permissions),
        requested_key_ids: csvToList(exchangeDraft?.requested_key_ids),
        jwt_svid: String(exchangeDraft?.jwt_svid || "").trim(),
        x509_svid_chain_pem: String(exchangeDraft?.x509_svid_chain_pem || "").trim()
      });
      setLastExchange(out || null);
      onToast?.("Workload token exchanged");
      await load(true);
    } catch (error) {
      onToast?.(`Token exchange failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const graphPreview = useMemo(() => {
    const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
    const edges = Array.isArray(graph?.edges) ? graph.edges : [];
    return { nodes: nodes.slice(0, 8), edges: edges.slice(0, 10), nodeCount: nodes.length, edgeCount: edges.length };
  }, [graph]);

  return (
    <div>
      <Section
        title="Workload Identity"
        desc="Tenant-scoped SPIFFE trust domains, SVID issuance, federation, and workload-to-key authorization."
        right={<Btn onClick={() => load(false)}>{loading ? "Refreshing..." : "Refresh"}</Btn>}
      />

      <Row2>
        <Card><Stat l="Trust Domain" v={String(summary?.trust_domain || settings?.trust_domain || "-")} c="accent" s={String(summary?.enabled ? "enabled" : "disabled")} /></Card>
        <Card><Stat l="Registrations" v={String(Number(summary?.registration_count || 0))} c="blue" s={`${Number(summary?.enabled_registration_count || 0)} active`} /></Card>
        <Card><Stat l="Federated Domains" v={String(Number(summary?.federated_trust_domain_count || 0))} c="accent" s={String(summary?.federation_enabled ? "enabled" : "local only")} /></Card>
        <Card><Stat l="SVID Rotation" v={summary?.rotation_healthy ? "Healthy" : "Attention"} c={healthTone(Boolean(summary?.rotation_healthy))} s={`${Number(summary?.expiring_svid_count || 0)} expiring / ${Number(summary?.expired_svid_count || 0)} expired`} /></Card>
        <Card><Stat l="Key Usage 24h" v={String(Number(summary?.key_usage_count_24h || 0))} c="green" s={`${Number(summary?.unique_keys_used_24h || 0)} keys`} /></Card>
        <Card><Stat l="Over-Privileged" v={String(Number(summary?.over_privileged_count || 0))} c={Number(summary?.over_privileged_count || 0) > 0 ? "amber" : "green"} s="registrations needing review" /></Card>
      </Row2>

      <Tabs tabs={["Overview", "Registrations", "Federation", "Issuance", "Usage"]} active={tab} onChange={setTab} />

      {tab === "Overview" && (
        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 14 }}>
          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 12 }}>SPIFFE Trust Domain & Token Exchange</div>
            <FG label="Trust Domain" hint="Local SPIFFE trust domain used for issued SVIDs.">
              <Inp value={String(settingsDraft?.trust_domain || "")} onChange={(e) => setSettingsDraft((prev: any) => ({ ...prev, trust_domain: e.target.value }))} />
            </FG>
            <Row2>
              <FG label="Default X.509 TTL (sec)"><Inp value={String(settingsDraft?.default_x509_ttl_seconds || 43200)} onChange={(e) => setSettingsDraft((prev: any) => ({ ...prev, default_x509_ttl_seconds: e.target.value }))} /></FG>
              <FG label="Default JWT TTL (sec)"><Inp value={String(settingsDraft?.default_jwt_ttl_seconds || 1800)} onChange={(e) => setSettingsDraft((prev: any) => ({ ...prev, default_jwt_ttl_seconds: e.target.value }))} /></FG>
            </Row2>
            <Row2>
              <FG label="Rotation Window (sec)"><Inp value={String(settingsDraft?.rotation_window_seconds || 1800)} onChange={(e) => setSettingsDraft((prev: any) => ({ ...prev, rotation_window_seconds: e.target.value }))} /></FG>
              <FG label="Allowed Audiences" hint="Comma-separated JWT-SVID audiences accepted for exchange.">
                <Inp value={String(settingsDraft?.allowed_audiences || "")} onChange={(e) => setSettingsDraft((prev: any) => ({ ...prev, allowed_audiences: e.target.value }))} />
              </FG>
            </Row2>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginBottom: 12 }}>
              <Chk label="Enable Workload Identity" checked={Boolean(settingsDraft?.enabled)} onChange={() => setSettingsDraft((prev: any) => ({ ...prev, enabled: !prev?.enabled }))} />
              <Chk label="Enable Federation" checked={Boolean(settingsDraft?.federation_enabled)} onChange={() => setSettingsDraft((prev: any) => ({ ...prev, federation_enabled: !prev?.federation_enabled }))} />
              <Chk label="Enable Token Exchange" checked={Boolean(settingsDraft?.token_exchange_enabled)} onChange={() => setSettingsDraft((prev: any) => ({ ...prev, token_exchange_enabled: !prev?.token_exchange_enabled }))} />
              <Chk label="Disable Static API Keys" checked={Boolean(settingsDraft?.disable_static_api_keys)} onChange={() => setSettingsDraft((prev: any) => ({ ...prev, disable_static_api_keys: !prev?.disable_static_api_keys }))} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
              <B c="blue">{String(settings?.jwt_signer_key_id || "local signer")}</B>
              <Btn primary onClick={saveSettings} disabled={busy}>{busy ? "Saving..." : "Save Settings"}</Btn>
            </div>
            <div style={{ marginTop: 12 }}>
              <FG label="Local Federation JWKS" hint="Copy this bundle to another trust domain when federating JWT-SVID verification.">
                <Txt rows={7} value={String(settings?.local_bundle_jwks || "")} readOnly />
              </FG>
            </div>
          </Card>

          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 12 }}>Workload-to-Key Authorization Graph</div>
            <Row2>
              <Stat l="Nodes" v={String(graphPreview.nodeCount)} c="accent" />
              <Stat l="Edges" v={String(graphPreview.edgeCount)} c="blue" />
            </Row2>
            <div style={{ fontSize: 10, color: C.muted, marginBottom: 8 }}>Policy edges come from workload registrations. Usage edges come from live audit-backed key operations performed with workload identity.</div>
            <div style={{ display: "grid", gap: 8 }}>
              {graphPreview.edges.map((edge: any) => (
                <div key={`${edge.source}-${edge.target}-${edge.kind}`} style={{ border: `1px solid ${C.border}`, borderRadius: 8, padding: 10, background: C.card }}>
                  <div style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{String(edge.source).replace(/^workload:/, "")}{" -> "}{String(edge.target).replace(/^key:/, "")}</div>
                  <div style={{ fontSize: 10, color: C.dim }}>{edge.kind === "usage" ? `Observed ${edge.label}` : `Policy ${edge.label}`}{edge.weight ? ` x${edge.weight}` : ""}</div>
                </div>
              ))}
              {!graphPreview.edges.length && <div style={{ fontSize: 10, color: C.muted }}>No workload-to-key relationships yet.</div>}
            </div>
          </Card>
        </div>
      )}

      {tab === "Registrations" && (
        <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr", gap: 14 }}>
          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 12 }}>Workload Registration</div>
            <FG label="Name"><Inp value={String(registrationDraft?.name || "")} onChange={(e) => setRegistrationDraft((prev: any) => ({ ...prev, name: e.target.value }))} /></FG>
            <FG label="SPIFFE ID" hint="Leave blank to derive from trust domain and name."><Inp value={String(registrationDraft?.spiffe_id || "")} onChange={(e) => setRegistrationDraft((prev: any) => ({ ...prev, spiffe_id: e.target.value }))} /></FG>
            <FG label="Selectors" hint="Comma-separated selectors such as k8s:ns:payments, docker:image:payments-api."><Inp value={String(registrationDraft?.selectors || "")} onChange={(e) => setRegistrationDraft((prev: any) => ({ ...prev, selectors: e.target.value }))} /></FG>
            <Row2>
              <FG label="Allowed Interfaces"><Inp value={String(registrationDraft?.allowed_interfaces || "")} onChange={(e) => setRegistrationDraft((prev: any) => ({ ...prev, allowed_interfaces: e.target.value }))} /></FG>
              <FG label="Allowed Key IDs"><Inp value={String(registrationDraft?.allowed_key_ids || "")} onChange={(e) => setRegistrationDraft((prev: any) => ({ ...prev, allowed_key_ids: e.target.value }))} /></FG>
            </Row2>
            <FG label="Permissions"><Inp value={String(registrationDraft?.permissions || "")} onChange={(e) => setRegistrationDraft((prev: any) => ({ ...prev, permissions: e.target.value }))} /></FG>
            <Row2>
              <FG label="Default TTL (sec)"><Inp value={String(registrationDraft?.default_ttl_seconds || 1800)} onChange={(e) => setRegistrationDraft((prev: any) => ({ ...prev, default_ttl_seconds: e.target.value }))} /></FG>
              <div style={{ display: "grid", alignContent: "center", gap: 8, paddingTop: 14 }}>
                <Chk label="Issue JWT-SVID" checked={Boolean(registrationDraft?.issue_jwt_svid)} onChange={() => setRegistrationDraft((prev: any) => ({ ...prev, issue_jwt_svid: !prev?.issue_jwt_svid }))} />
                <Chk label="Issue X.509-SVID" checked={Boolean(registrationDraft?.issue_x509_svid)} onChange={() => setRegistrationDraft((prev: any) => ({ ...prev, issue_x509_svid: !prev?.issue_x509_svid }))} />
                <Chk label="Enabled" checked={Boolean(registrationDraft?.enabled)} onChange={() => setRegistrationDraft((prev: any) => ({ ...prev, enabled: !prev?.enabled }))} />
              </div>
            </Row2>
            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <Btn primary onClick={saveRegistration} disabled={busy}>{busy ? "Saving..." : registrationDraft?.id ? "Update Registration" : "Add Registration"}</Btn>
            </div>
          </Card>

          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 12 }}>Registered Workloads</div>
            <div style={{ display: "grid", gap: 8 }}>
              {registrations.map((item: any) => (
                <div key={item.id} style={{ border: `1px solid ${C.border}`, borderRadius: 10, padding: 12, background: C.card }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 4 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>{String(item?.name || item?.spiffe_id || item?.id)}</div>
                    <B c={item?.enabled ? "green" : "amber"}>{item?.enabled ? "Enabled" : "Disabled"}</B>
                  </div>
                  <div style={{ fontSize: 10, color: C.dim, marginBottom: 8 }}>{String(item?.spiffe_id || "-")}</div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
                    <Stat l="Interfaces" v={String((item?.allowed_interfaces || []).length)} c="accent" />
                    <Stat l="Keys" v={String((item?.allowed_key_ids || []).length)} c={Number(item?.allowed_key_ids?.length || 0) === 0 ? "amber" : "green"} />
                    <Stat l="Permissions" v={String((item?.permissions || []).length)} c={String(item?.permissions || []).includes("key.*") ? "amber" : "blue"} />
                  </div>
                  <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                    <Btn onClick={() => setRegistrationDraft({ ...item, selectors: listToCSV(item?.selectors), allowed_interfaces: listToCSV(item?.allowed_interfaces), allowed_key_ids: listToCSV(item?.allowed_key_ids), permissions: listToCSV(item?.permissions) })}>Edit</Btn>
                    <Btn danger onClick={async () => { try { await deleteWorkloadRegistration(session, item.id); onToast?.("Registration deleted"); await load(true); } catch (error) { onToast?.(`Delete failed: ${errMsg(error)}`); } }}>Delete</Btn>
                  </div>
                </div>
              ))}
              {!registrations.length && <div style={{ fontSize: 10, color: C.muted }}>No workload registrations yet.</div>}
            </div>
          </Card>
        </div>
      )}

      {tab === "Federation" && (
        <div style={{ display: "grid", gridTemplateColumns: "1.05fr 1fr", gap: 14 }}>
          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 12 }}>Federated Trust Domains</div>
            <FG label="Trust Domain"><Inp value={String(federationDraft?.trust_domain || "")} onChange={(e) => setFederationDraft((prev: any) => ({ ...prev, trust_domain: e.target.value }))} /></FG>
            <FG label="Bundle Endpoint"><Inp value={String(federationDraft?.bundle_endpoint || "")} onChange={(e) => setFederationDraft((prev: any) => ({ ...prev, bundle_endpoint: e.target.value }))} /></FG>
            <FG label="JWKS JSON" hint="Use for federated JWT-SVID verification."><Txt rows={8} value={String(federationDraft?.jwks_json || "")} onChange={(e) => setFederationDraft((prev: any) => ({ ...prev, jwks_json: e.target.value }))} /></FG>
            <FG label="CA Bundle PEM" hint="Use for federated X.509-SVID verification."><Txt rows={8} value={String(federationDraft?.ca_bundle_pem || "")} onChange={(e) => setFederationDraft((prev: any) => ({ ...prev, ca_bundle_pem: e.target.value }))} /></FG>
            <Chk label="Enabled" checked={Boolean(federationDraft?.enabled)} onChange={() => setFederationDraft((prev: any) => ({ ...prev, enabled: !prev?.enabled }))} />
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 12 }}>
              <Btn primary onClick={saveFederation} disabled={busy}>{busy ? "Saving..." : federationDraft?.id ? "Update Federation" : "Add Federation"}</Btn>
            </div>
          </Card>

          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 12 }}>Configured Federation</div>
            <div style={{ display: "grid", gap: 8 }}>
              {bundles.map((item: any) => (
                <div key={item.id} style={{ border: `1px solid ${C.border}`, borderRadius: 10, padding: 12, background: C.card }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 4 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>{String(item?.trust_domain || item?.id)}</div>
                    <B c={item?.enabled ? "green" : "amber"}>{item?.enabled ? "Enabled" : "Disabled"}</B>
                  </div>
                  <div style={{ fontSize: 10, color: C.dim, marginBottom: 8 }}>{String(item?.bundle_endpoint || "manual bundle")}</div>
                  <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                    <Btn onClick={() => setFederationDraft({ ...item })}>Edit</Btn>
                    <Btn danger onClick={async () => { try { await deleteWorkloadFederationBundle(session, item.id); onToast?.("Federation bundle deleted"); await load(true); } catch (error) { onToast?.(`Delete failed: ${errMsg(error)}`); } }}>Delete</Btn>
                  </div>
                </div>
              ))}
              {!bundles.length && <div style={{ fontSize: 10, color: C.muted }}>No federated trust domains configured.</div>}
            </div>
          </Card>
        </div>
      )}

      {tab === "Issuance" && (
        <div style={{ display: "grid", gridTemplateColumns: "1.05fr 1fr", gap: 14 }}>
          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 12 }}>SVID Issuance & Token Exchange</div>
            <Row2>
              <FG label="Registration">
                <Sel value={String(issueDraft?.registration_id || "")} onChange={(e) => setIssueDraft((prev: any) => ({ ...prev, registration_id: e.target.value }))}>
                  <option value="">Select registration...</option>
                  {registrations.map((item: any) => <option key={item.id} value={item.id}>{item.name || item.spiffe_id}</option>)}
                </Sel>
              </FG>
              <FG label="SVID Type">
                <Sel value={String(issueDraft?.svid_type || "jwt")} onChange={(e) => setIssueDraft((prev: any) => ({ ...prev, svid_type: e.target.value }))}>
                  <option value="jwt">JWT-SVID</option>
                  <option value="x509">X.509-SVID</option>
                </Sel>
              </FG>
            </Row2>
            <Row2>
              <FG label="Audiences"><Inp value={String(issueDraft?.audiences || "kms")} onChange={(e) => setIssueDraft((prev: any) => ({ ...prev, audiences: e.target.value }))} /></FG>
              <FG label="TTL (sec)"><Inp value={String(issueDraft?.ttl_seconds || 1800)} onChange={(e) => setIssueDraft((prev: any) => ({ ...prev, ttl_seconds: e.target.value }))} /></FG>
            </Row2>
            <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 14 }}>
              <Btn primary onClick={runIssue} disabled={busy}>{busy ? "Issuing..." : "Issue SVID"}</Btn>
            </div>

            <div style={{ height: 1, background: C.border, margin: "14px 0" }} />

            <Row2>
              <FG label="Exchange Registration">
                <Sel value={String(exchangeDraft?.registration_id || "")} onChange={(e) => setExchangeDraft((prev: any) => ({ ...prev, registration_id: e.target.value }))}>
                  <option value="">Select registration...</option>
                  {registrations.map((item: any) => <option key={item.id} value={item.id}>{item.name || item.spiffe_id}</option>)}
                </Sel>
              </FG>
              <FG label="Interface">
                <Sel value={String(exchangeDraft?.interface_name || "rest")} onChange={(e) => setExchangeDraft((prev: any) => ({ ...prev, interface_name: e.target.value }))}>
                  <option value="rest">REST</option>
                  <option value="kmip">KMIP</option>
                  <option value="payment-tcp">Payment TCP</option>
                  <option value="ekm">EKM</option>
                  <option value="hyok">HYOK</option>
                </Sel>
              </FG>
            </Row2>
            <Row2>
              <FG label="Audience"><Inp value={String(exchangeDraft?.audience || "kms")} onChange={(e) => setExchangeDraft((prev: any) => ({ ...prev, audience: e.target.value }))} /></FG>
              <FG label="Requested Key IDs"><Inp value={String(exchangeDraft?.requested_key_ids || "")} onChange={(e) => setExchangeDraft((prev: any) => ({ ...prev, requested_key_ids: e.target.value }))} /></FG>
            </Row2>
            <FG label="Requested Permissions"><Inp value={String(exchangeDraft?.requested_permissions || "")} onChange={(e) => setExchangeDraft((prev: any) => ({ ...prev, requested_permissions: e.target.value }))} /></FG>
            <FG label="JWT-SVID"><Txt rows={6} value={String(exchangeDraft?.jwt_svid || "")} onChange={(e) => setExchangeDraft((prev: any) => ({ ...prev, jwt_svid: e.target.value }))} /></FG>
            <FG label="X.509-SVID Chain PEM"><Txt rows={8} value={String(exchangeDraft?.x509_svid_chain_pem || "")} onChange={(e) => setExchangeDraft((prev: any) => ({ ...prev, x509_svid_chain_pem: e.target.value }))} /></FG>
            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <Btn primary onClick={runExchange} disabled={busy}>{busy ? "Exchanging..." : "Exchange for KMS Token"}</Btn>
            </div>
          </Card>

          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 12 }}>Issuance / Exchange Output</div>
            {lastIssued && (
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: C.accent, marginBottom: 8 }}>Last Issued SVID</div>
                <div style={{ fontSize: 10, color: C.dim, marginBottom: 8 }}>{lastIssued.spiffe_id} • {String(lastIssued.svid_type || "").toUpperCase()} • Expires {fmtTS(lastIssued.expires_at)}</div>
                <Txt rows={lastIssued?.jwt_svid ? 8 : 10} value={String(lastIssued?.jwt_svid || lastIssued?.certificate_pem || "")} readOnly />
              </div>
            )}
            {lastExchange && (
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: C.green, marginBottom: 8 }}>Last Exchanged KMS Token</div>
                <div style={{ fontSize: 10, color: C.dim, marginBottom: 8 }}>{lastExchange.spiffe_id} • {lastExchange.interface_name} • Expires {fmtTS(lastExchange.kms_access_token_expiry)}</div>
                <Txt rows={8} value={String(lastExchange?.kms_access_token || "")} readOnly />
              </div>
            )}
            <div style={{ display: "grid", gap: 8 }}>
              {issuances.slice(0, 8).map((item: any) => (
                <div key={item.id} style={{ border: `1px solid ${C.border}`, borderRadius: 10, padding: 10, background: C.card }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 4 }}>
                    <div style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{item.spiffe_id}</div>
                    <B c={String(item?.status || "").toLowerCase() === "expired" ? "amber" : "green"}>{item.svid_type}</B>
                  </div>
                  <div style={{ fontSize: 10, color: C.dim }}>Issued {fmtTS(item.issued_at)} • Expires {fmtTS(item.expires_at)}</div>
                </div>
              ))}
              {!issuances.length && <div style={{ fontSize: 10, color: C.muted }}>No SVIDs issued yet.</div>}
            </div>
          </Card>
        </div>
      )}

      {tab === "Usage" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 12 }}>Recent Workload Key Usage</div>
            <div style={{ display: "grid", gap: 8 }}>
              {usage.map((item: any) => (
                <div key={`${item.event_id}-${item.key_id}-${item.operation}`} style={{ border: `1px solid ${C.border}`, borderRadius: 10, padding: 10, background: C.card }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                    <div style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{item.workload_identity}</div>
                    <B c={String(item?.result || "").toLowerCase() === "success" ? "green" : "amber"}>{item.operation}</B>
                  </div>
                  <div style={{ fontSize: 10, color: C.dim }}>{item.key_id || "no key id"} • {item.interface_name || "interface unknown"} • {fmtTS(item.created_at)}</div>
                </div>
              ))}
              {!usage.length && <div style={{ fontSize: 10, color: C.muted }}>No workload-backed key usage observed yet.</div>}
            </div>
          </Card>

          <Card>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 12 }}>Operational Signals</div>
            <Row2>
              <Stat l="Token Exchanges 24h" v={String(Number(summary?.token_exchange_count_24h || 0))} c="blue" />
              <Stat l="Workloads Using Keys" v={String(Number(summary?.unique_workloads_using_keys_24h || 0))} c="accent" />
            </Row2>
            <Row2>
              <Stat l="Last Exchange" v={summary?.last_exchange_at ? fmtTS(summary?.last_exchange_at) : "-"} c="green" />
              <Stat l="Last Key Use" v={summary?.last_key_use_at ? fmtTS(summary?.last_key_use_at) : "-"} c="green" />
            </Row2>
            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 8 }}>Local CA Bundle</div>
              <Txt rows={8} value={String(settings?.local_ca_certificate_pem || "")} readOnly />
            </div>
          </Card>
        </div>
      )}
    </div>
  );
};
