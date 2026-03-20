// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import {
  createAutokeyRequest,
  deleteAutokeyServicePolicy,
  deleteAutokeyTemplate,
  getAutokeySettings,
  getAutokeySummary,
  listAutokeyHandles,
  listAutokeyRequests,
  listAutokeyServicePolicies,
  listAutokeyTemplates,
  updateAutokeySettings,
  upsertAutokeyServicePolicy,
  upsertAutokeyTemplate
} from "../../../lib/autokey";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Chk, FG, Inp, Row2, Section, Sel, Stat, Tabs, Txt, usePromptDialog } from "../legacyPrimitives";

function csvToList(value: any): string[] {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

function listToCsv(value: any): string {
  return Array.isArray(value) ? value.map((item) => String(item || "").trim()).filter(Boolean).join(", ") : "";
}

function jsonToPretty(value: any): string {
  if (!value || typeof value !== "object") return "{}";
  return JSON.stringify(value, null, 2);
}

function parseJsonMap(raw: string, label: string): Record<string, string> {
  const trimmed = String(raw || "").trim();
  if (!trimmed) return {};
  let parsed: any = {};
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error(`${label} must be valid JSON`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return Object.entries(parsed).reduce((acc: Record<string, string>, [key, value]) => {
    const nextKey = String(key || "").trim();
    if (!nextKey) return acc;
    acc[nextKey] = typeof value === "string" ? value : JSON.stringify(value);
    return acc;
  }, {});
}

function fmtTS(value: any): string {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return dt.toLocaleString();
}

function requestTone(status: string) {
  const v = String(status || "").trim().toLowerCase();
  if (v === "provisioned") return "green";
  if (v === "denied" || v === "failed") return "red";
  if (v === "pending_approval" || v === "pending") return "amber";
  return "blue";
}

const DEFAULT_SETTINGS = {
  enabled: false,
  mode: "enforce",
  require_approval: true,
  require_justification: true,
  allow_template_override: true,
  default_policy_id: "",
  default_rotation_days: 90
};

const DEFAULT_TEMPLATE = {
  id: "",
  name: "",
  service_name: "payment",
  resource_type: "application",
  handle_name_pattern: "{{service}}/{{resource_type}}/{{resource_slug}}",
  key_name_pattern: "ak-{{service}}-{{resource_slug}}",
  algorithm: "aes256-gcm",
  key_type: "symmetric",
  purpose: "encrypt_decrypt",
  export_allowed: false,
  iv_mode: "generated",
  tags_csv: "autokey, managed",
  labels_json: "{\n  \"service_tier\": \"prod\"\n}",
  ops_limit: 0,
  ops_limit_window: "24h",
  approval_required: true,
  approval_policy_id: "",
  description: "",
  enabled: true
};

const DEFAULT_POLICY = {
  service_name: "payment",
  display_name: "Payment Service",
  default_template_id: "",
  algorithm: "aes256-gcm",
  key_type: "symmetric",
  purpose: "encrypt_decrypt",
  export_allowed: false,
  iv_mode: "generated",
  tags_csv: "production",
  labels_json: "{\n  \"policy_owner\": \"security\"\n}",
  ops_limit: 0,
  ops_limit_window: "24h",
  approval_required: true,
  approval_policy_id: "",
  enforce_policy: true,
  description: "",
  enabled: true
};

const DEFAULT_REQUEST = {
  service_name: "payment",
  resource_type: "application",
  resource_ref: "",
  template_id: "",
  handle_name: "",
  key_name: "",
  requested_algorithm: "",
  requested_key_type: "",
  requested_purpose: "",
  tags_csv: "",
  labels_json: "{}",
  justification: ""
};

export const AutokeyTab = ({ session, onToast }: any) => {
  const promptDialog = usePromptDialog();
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState("Overview");
  const [summary, setSummary] = useState<any>(null);
  const [settings, setSettings] = useState<any>(DEFAULT_SETTINGS);
  const [templates, setTemplates] = useState<any[]>([]);
  const [policies, setPolicies] = useState<any[]>([]);
  const [requests, setRequests] = useState<any[]>([]);
  const [handles, setHandles] = useState<any[]>([]);
  const [settingsDraft, setSettingsDraft] = useState<any>(DEFAULT_SETTINGS);
  const [templateDraft, setTemplateDraft] = useState<any>(DEFAULT_TEMPLATE);
  const [policyDraft, setPolicyDraft] = useState<any>(DEFAULT_POLICY);
  const [requestDraft, setRequestDraft] = useState<any>(DEFAULT_REQUEST);

  const refresh = async (silent = false) => {
    if (!session?.token) {
      setSummary(null);
      setSettings(DEFAULT_SETTINGS);
      setSettingsDraft(DEFAULT_SETTINGS);
      setTemplates([]);
      setPolicies([]);
      setRequests([]);
      setHandles([]);
      return;
    }
    if (!silent) setLoading(true);
    try {
      const [summaryOut, settingsOut, templatesOut, policiesOut, requestsOut, handlesOut] = await Promise.all([
        getAutokeySummary(session),
        getAutokeySettings(session),
        listAutokeyTemplates(session),
        listAutokeyServicePolicies(session),
        listAutokeyRequests(session, { limit: 100 }),
        listAutokeyHandles(session, { limit: 100 })
      ]);
      const nextSettings = { ...DEFAULT_SETTINGS, ...(settingsOut || {}) };
      setSummary(summaryOut || null);
      setSettings(nextSettings);
      setSettingsDraft(nextSettings);
      setTemplates(Array.isArray(templatesOut) ? templatesOut : []);
      setPolicies(Array.isArray(policiesOut) ? policiesOut : []);
      setRequests(Array.isArray(requestsOut) ? requestsOut : []);
      setHandles(Array.isArray(handlesOut) ? handlesOut : []);
    } catch (error) {
      onToast?.(`Autokey load failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    void refresh(false);
  }, [session?.token, session?.tenantId]);

  const saveSettings = async () => {
    if (!session?.token) return;
    setBusy(true);
    try {
      await updateAutokeySettings(session, {
        ...settingsDraft,
        tenant_id: session.tenantId,
        default_rotation_days: Number(settingsDraft?.default_rotation_days || 90),
        updated_by: session.username
      });
      onToast?.("Autokey settings saved");
      await refresh(true);
    } catch (error) {
      onToast?.(`Autokey settings save failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const saveTemplate = async () => {
    if (!session?.token) return;
    setBusy(true);
    try {
      await upsertAutokeyTemplate(session, {
        id: templateDraft?.id || undefined,
        tenant_id: session.tenantId,
        name: templateDraft?.name,
        service_name: templateDraft?.service_name,
        resource_type: templateDraft?.resource_type,
        handle_name_pattern: templateDraft?.handle_name_pattern,
        key_name_pattern: templateDraft?.key_name_pattern,
        algorithm: templateDraft?.algorithm,
        key_type: templateDraft?.key_type,
        purpose: templateDraft?.purpose,
        export_allowed: Boolean(templateDraft?.export_allowed),
        iv_mode: templateDraft?.iv_mode,
        tags: csvToList(templateDraft?.tags_csv),
        labels: parseJsonMap(templateDraft?.labels_json, "Template labels"),
        ops_limit: Number(templateDraft?.ops_limit || 0),
        ops_limit_window: templateDraft?.ops_limit_window,
        approval_required: Boolean(templateDraft?.approval_required),
        approval_policy_id: templateDraft?.approval_policy_id,
        description: templateDraft?.description,
        enabled: Boolean(templateDraft?.enabled),
        updated_by: session.username
      });
      onToast?.("Autokey template saved");
      setTemplateDraft(DEFAULT_TEMPLATE);
      await refresh(true);
    } catch (error) {
      onToast?.(`Autokey template save failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const removeTemplate = async (id: string) => {
    const ok = await promptDialog.confirm({
      title: "Delete Template",
      message: "Delete this Autokey template?",
      danger: true,
      confirmLabel: "Delete"
    });
    if (!ok || !session?.token) return;
    setBusy(true);
    try {
      await deleteAutokeyTemplate(session, id);
      onToast?.("Autokey template deleted");
      await refresh(true);
    } catch (error) {
      onToast?.(`Template delete failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const savePolicy = async () => {
    if (!session?.token) return;
    setBusy(true);
    try {
      await upsertAutokeyServicePolicy(session, {
        tenant_id: session.tenantId,
        service_name: policyDraft?.service_name,
        display_name: policyDraft?.display_name,
        default_template_id: policyDraft?.default_template_id,
        algorithm: policyDraft?.algorithm,
        key_type: policyDraft?.key_type,
        purpose: policyDraft?.purpose,
        export_allowed: Boolean(policyDraft?.export_allowed),
        iv_mode: policyDraft?.iv_mode,
        tags: csvToList(policyDraft?.tags_csv),
        labels: parseJsonMap(policyDraft?.labels_json, "Service policy labels"),
        ops_limit: Number(policyDraft?.ops_limit || 0),
        ops_limit_window: policyDraft?.ops_limit_window,
        approval_required: Boolean(policyDraft?.approval_required),
        approval_policy_id: policyDraft?.approval_policy_id,
        enforce_policy: Boolean(policyDraft?.enforce_policy),
        description: policyDraft?.description,
        enabled: Boolean(policyDraft?.enabled),
        updated_by: session.username
      });
      onToast?.("Service default policy saved");
      setPolicyDraft(DEFAULT_POLICY);
      await refresh(true);
    } catch (error) {
      onToast?.(`Service policy save failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const removePolicy = async (serviceName: string) => {
    const ok = await promptDialog.confirm({
      title: "Delete Service Policy",
      message: `Delete the Autokey default policy for ${serviceName}?`,
      danger: true,
      confirmLabel: "Delete"
    });
    if (!ok || !session?.token) return;
    setBusy(true);
    try {
      await deleteAutokeyServicePolicy(session, serviceName);
      onToast?.("Service default policy deleted");
      await refresh(true);
    } catch (error) {
      onToast?.(`Service policy delete failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const submitRequest = async () => {
    if (!session?.token) return;
    setBusy(true);
    try {
      await createAutokeyRequest(session, {
        tenant_id: session.tenantId,
        service_name: requestDraft?.service_name,
        resource_type: requestDraft?.resource_type,
        resource_ref: requestDraft?.resource_ref,
        template_id: requestDraft?.template_id || undefined,
        handle_name: requestDraft?.handle_name || undefined,
        key_name: requestDraft?.key_name || undefined,
        requested_algorithm: requestDraft?.requested_algorithm || undefined,
        requested_key_type: requestDraft?.requested_key_type || undefined,
        requested_purpose: requestDraft?.requested_purpose || undefined,
        tags: csvToList(requestDraft?.tags_csv),
        labels: parseJsonMap(requestDraft?.labels_json, "Request labels"),
        justification: requestDraft?.justification,
        requester_id: session.username,
        requester_email: session.email
      });
      onToast?.("Autokey request submitted");
      setRequestDraft(DEFAULT_REQUEST);
      await refresh(true);
    } catch (error) {
      onToast?.(`Autokey request failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const summaryTone = !summary?.enabled
    ? "amber"
    : Number(summary?.pending_approvals || 0) > 0 || Number(summary?.policy_mismatch_count || 0) > 0
      ? "amber"
      : Number(summary?.failed_count || 0) > 0
        ? "red"
        : "green";

  const sortedServices = useMemo(() => Array.isArray(summary?.services) ? summary.services : [], [summary]);

  return (
    <Section
      title="Autokey"
      desc="Policy-driven key handle provisioning so teams request keys on demand under central tenant policy."
      right={<div style={{ display: "flex", gap: 8 }}>
        <Btn small onClick={() => refresh(false)} disabled={loading}>{loading ? "Refreshing..." : "Refresh"}</Btn>
        <Btn small primary onClick={saveSettings} disabled={busy || loading}>Save Settings</Btn>
      </div>}
    >
      {promptDialog.ui}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(6,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
        <Stat l="Mode" v={String(summary?.mode || settings?.mode || "enforce")} c="accent" />
        <Stat l="Templates" v={String(Number(summary?.template_count || 0))} c="blue" />
        <Stat l="Service Defaults" v={String(Number(summary?.service_policy_count || 0))} c="blue" />
        <Stat l="Handles" v={String(Number(summary?.handle_count || 0))} c="green" />
        <Stat l="Pending Approvals" v={String(Number(summary?.pending_approvals || 0))} c={Number(summary?.pending_approvals || 0) > 0 ? "amber" : "green"} />
        <Stat l="Policy Mismatches" v={String(Number(summary?.policy_mismatch_count || 0))} c={Number(summary?.policy_mismatch_count || 0) > 0 ? "amber" : "green"} />
      </div>

      <Card style={{ padding: "12px 14px", marginBottom: 10 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Tenant Autokey Status</div>
            <div style={{ fontSize: 10, color: C.dim, marginTop: 3 }}>
              Resource templates and per-service defaults are tenant-scoped. Approval-required requests wait in Governance until approved, then the Autokey service provisions the real key in KeyCore and binds a managed handle.
            </div>
          </div>
          <B c={summaryTone}>
            {!summary?.enabled ? "Disabled" : Number(summary?.failed_count || 0) > 0 ? "Attention" : Number(summary?.pending_approvals || 0) > 0 || Number(summary?.policy_mismatch_count || 0) > 0 ? "Review" : "Healthy"}
          </B>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8 }}>
          <Stat l="Provisioned 24h" v={String(Number(summary?.provisioned_24h || 0))} c="green" />
          <Stat l="Denied" v={String(Number(summary?.denied_count || 0))} c={Number(summary?.denied_count || 0) > 0 ? "amber" : "green"} />
          <Stat l="Failed" v={String(Number(summary?.failed_count || 0))} c={Number(summary?.failed_count || 0) > 0 ? "red" : "green"} />
          <Stat l="Policy Matched" v={String(Number(summary?.policy_matched_count || 0))} c="accent" />
        </div>
      </Card>

      <Tabs tabs={["Overview", "Settings", "Templates", "Service Defaults", "Requests & Handles"]} active={tab} onChange={setTab} />

      {tab === "Overview" && (
        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 10, marginTop: 10 }}>
          <Card style={{ padding: "14px 16px" }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 8 }}>Per-Service Autokey Coverage</div>
            <div style={{ display: "grid", gap: 8 }}>
              {sortedServices.map((item: any) => (
                <div key={String(item?.service_name || "service")} style={{ padding: "10px 12px", borderRadius: 10, border: `1px solid ${C.border}`, background: C.surface }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 6 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>{String(item?.service_name || "-")}</div>
                    <B c={Number(item?.policy_mismatch_count || 0) > 0 ? "amber" : Number(item?.pending_approvals || 0) > 0 ? "blue" : "green"}>
                      {Number(item?.handle_count || 0)} handles
                    </B>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
                    <Stat l="Pending" v={String(Number(item?.pending_approvals || 0))} c={Number(item?.pending_approvals || 0) > 0 ? "amber" : "green"} />
                    <Stat l="Provisioned 24h" v={String(Number(item?.provisioned_24h || 0))} c="green" />
                    <Stat l="Mismatch" v={String(Number(item?.policy_mismatch_count || 0))} c={Number(item?.policy_mismatch_count || 0) > 0 ? "amber" : "green"} />
                  </div>
                </div>
              ))}
              {!sortedServices.length && <div style={{ fontSize: 10, color: C.muted }}>No service activity yet. Save a template and default policy, then request a handle.</div>}
            </div>
          </Card>

          <Card style={{ padding: "14px 16px" }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 8 }}>Approval Flow</div>
            <div style={{ display: "grid", gap: 8 }}>
              {[
                ["1", "Template match", "Autokey resolves the resource template and per-service default policy."],
                ["2", "Policy check", "Requested algorithm, purpose, and key type are checked against central policy."],
                ["3", "Approval gate", "If approval is required, the request enters Governance and waits for approval."],
                ["4", "Provision & bind", "After approval, KeyCore creates the key and Autokey records a managed handle binding."]
              ].map(([step, title, text]) => (
                <div key={String(step)} style={{ display: "grid", gridTemplateColumns: "28px 1fr", gap: 10, alignItems: "start" }}>
                  <div style={{ width: 24, height: 24, borderRadius: 12, background: C.accentDim, color: C.accent, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 800 }}>{step}</div>
                  <div>
                    <div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{title}</div>
                    <div style={{ fontSize: 9, color: C.dim, marginTop: 3 }}>{text}</div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {tab === "Settings" && (
        <div style={{ marginTop: 10 }}>
          <Card style={{ padding: "14px 16px" }}>
            <Row2>
              <FG label="Autokey Enabled"><Chk label="Enable policy-driven provisioning" checked={Boolean(settingsDraft?.enabled)} onChange={() => setSettingsDraft((p: any) => ({ ...p, enabled: !p.enabled }))} /></FG>
              <FG label="Mode">
                <Sel value={String(settingsDraft?.mode || "enforce")} onChange={(e) => setSettingsDraft((p: any) => ({ ...p, mode: e.target.value }))}>
                  <option value="enforce">Enforce</option>
                  <option value="audit">Audit</option>
                </Sel>
              </FG>
            </Row2>
            <Row2>
              <FG label="Approval Gate"><Chk label="Require approval for create" checked={Boolean(settingsDraft?.require_approval)} onChange={() => setSettingsDraft((p: any) => ({ ...p, require_approval: !p.require_approval }))} /></FG>
              <FG label="Justification"><Chk label="Require justification text" checked={Boolean(settingsDraft?.require_justification)} onChange={() => setSettingsDraft((p: any) => ({ ...p, require_justification: !p.require_justification }))} /></FG>
            </Row2>
            <Row2>
              <FG label="Template Override"><Chk label="Allow caller template override" checked={Boolean(settingsDraft?.allow_template_override)} onChange={() => setSettingsDraft((p: any) => ({ ...p, allow_template_override: !p.allow_template_override }))} /></FG>
              <FG label="Default Rotation Days"><Inp type="number" value={Number(settingsDraft?.default_rotation_days || 90)} onChange={(e) => setSettingsDraft((p: any) => ({ ...p, default_rotation_days: e.target.value }))} /></FG>
            </Row2>
            <FG label="Default Approval Policy ID"><Inp value={String(settingsDraft?.default_policy_id || "")} onChange={(e) => setSettingsDraft((p: any) => ({ ...p, default_policy_id: e.target.value }))} placeholder="policy-approval-root" /></FG>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, marginTop: 4 }}>
              <div style={{ fontSize: 9, color: C.dim }}>Updated: {fmtTS(settings?.updated_at)}</div>
              <Btn primary onClick={saveSettings} disabled={busy}>Save Settings</Btn>
            </div>
          </Card>
        </div>
      )}

      {tab === "Templates" && (
        <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr", gap: 10, marginTop: 10 }}>
          <Card style={{ padding: "14px 16px" }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 8 }}>{templateDraft?.id ? "Edit Template" : "New Template"}</div>
            <Row2>
              <FG label="Template Name"><Inp value={templateDraft?.name} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, name: e.target.value }))} placeholder="Payment application handle" /></FG>
              <FG label="Service Name"><Inp value={templateDraft?.service_name} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, service_name: e.target.value }))} placeholder="payment" /></FG>
            </Row2>
            <Row2>
              <FG label="Resource Type"><Inp value={templateDraft?.resource_type} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, resource_type: e.target.value }))} placeholder="application" /></FG>
              <FG label="Algorithm"><Inp value={templateDraft?.algorithm} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, algorithm: e.target.value }))} placeholder="aes256-gcm" /></FG>
            </Row2>
            <Row2>
              <FG label="Key Type"><Inp value={templateDraft?.key_type} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, key_type: e.target.value }))} placeholder="symmetric" /></FG>
              <FG label="Purpose"><Inp value={templateDraft?.purpose} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, purpose: e.target.value }))} placeholder="encrypt_decrypt" /></FG>
            </Row2>
            <FG label="Handle Name Pattern"><Inp value={templateDraft?.handle_name_pattern} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, handle_name_pattern: e.target.value }))} mono /></FG>
            <FG label="Key Name Pattern"><Inp value={templateDraft?.key_name_pattern} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, key_name_pattern: e.target.value }))} mono /></FG>
            <Row2>
              <FG label="IV Mode"><Inp value={templateDraft?.iv_mode} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, iv_mode: e.target.value }))} placeholder="generated" /></FG>
              <FG label="Ops Limit"><Inp type="number" value={Number(templateDraft?.ops_limit || 0)} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, ops_limit: e.target.value }))} /></FG>
            </Row2>
            <Row2>
              <FG label="Ops Limit Window"><Inp value={templateDraft?.ops_limit_window} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, ops_limit_window: e.target.value }))} placeholder="24h" /></FG>
              <FG label="Approval Policy ID"><Inp value={templateDraft?.approval_policy_id} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, approval_policy_id: e.target.value }))} placeholder="policy-approval-root" /></FG>
            </Row2>
            <FG label="Tags (comma-separated)"><Inp value={templateDraft?.tags_csv} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, tags_csv: e.target.value }))} /></FG>
            <FG label="Labels JSON"><Txt rows={5} value={templateDraft?.labels_json} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, labels_json: e.target.value }))} /></FG>
            <FG label="Description"><Txt rows={3} mono={false} value={templateDraft?.description} onChange={(e) => setTemplateDraft((p: any) => ({ ...p, description: e.target.value }))} /></FG>
            <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 10 }}>
              <Chk label="Export allowed" checked={Boolean(templateDraft?.export_allowed)} onChange={() => setTemplateDraft((p: any) => ({ ...p, export_allowed: !p.export_allowed }))} />
              <Chk label="Approval required" checked={Boolean(templateDraft?.approval_required)} onChange={() => setTemplateDraft((p: any) => ({ ...p, approval_required: !p.approval_required }))} />
              <Chk label="Enabled" checked={Boolean(templateDraft?.enabled)} onChange={() => setTemplateDraft((p: any) => ({ ...p, enabled: !p.enabled }))} />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <Btn onClick={() => setTemplateDraft(DEFAULT_TEMPLATE)}>Reset</Btn>
              <Btn primary onClick={saveTemplate} disabled={busy}>Save Template</Btn>
            </div>
          </Card>

          <Card style={{ padding: "14px 16px" }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 8 }}>Saved Templates</div>
            <div style={{ display: "grid", gap: 8 }}>
              {templates.map((item: any) => (
                <div key={String(item?.id || "")} style={{ padding: "10px 12px", borderRadius: 10, border: `1px solid ${C.border}`, background: C.surface }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                    <div>
                      <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>{String(item?.name || item?.id || "-")}</div>
                      <div style={{ fontSize: 9, color: C.dim }}>{String(item?.service_name || "-")} • {String(item?.resource_type || "-")} • {String(item?.algorithm || "-")}</div>
                    </div>
                    <B c={item?.enabled ? "green" : "amber"}>{item?.enabled ? "Enabled" : "Disabled"}</B>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginTop: 8 }}>
                    <div style={{ fontSize: 9, color: C.dim }}>Handle: {String(item?.handle_name_pattern || "-")}</div>
                    <div style={{ fontSize: 9, color: C.dim }}>Key: {String(item?.key_name_pattern || "-")}</div>
                  </div>
                  <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 8 }}>
                    <Btn small onClick={() => setTemplateDraft({
                      ...DEFAULT_TEMPLATE,
                      ...item,
                      tags_csv: listToCsv(item?.tags),
                      labels_json: jsonToPretty(item?.labels)
                    })}>Edit</Btn>
                    <Btn small danger onClick={() => removeTemplate(String(item?.id || ""))}>Delete</Btn>
                  </div>
                </div>
              ))}
              {!templates.length && <div style={{ fontSize: 10, color: C.muted }}>No templates yet.</div>}
            </div>
          </Card>
        </div>
      )}

      {tab === "Service Defaults" && (
        <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr", gap: 10, marginTop: 10 }}>
          <Card style={{ padding: "14px 16px" }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 8 }}>Per-Service Default Policy</div>
            <Row2>
              <FG label="Service Name"><Inp value={policyDraft?.service_name} onChange={(e) => setPolicyDraft((p: any) => ({ ...p, service_name: e.target.value }))} placeholder="payment" /></FG>
              <FG label="Display Name"><Inp value={policyDraft?.display_name} onChange={(e) => setPolicyDraft((p: any) => ({ ...p, display_name: e.target.value }))} placeholder="Payment Service" /></FG>
            </Row2>
            <FG label="Default Template">
              <Sel value={String(policyDraft?.default_template_id || "")} onChange={(e) => setPolicyDraft((p: any) => ({ ...p, default_template_id: e.target.value }))}>
                <option value="">Auto-select</option>
                {templates.map((item: any) => <option key={String(item?.id || "")} value={String(item?.id || "")}>{String(item?.name || item?.id || "")}</option>)}
              </Sel>
            </FG>
            <Row2>
              <FG label="Algorithm"><Inp value={policyDraft?.algorithm} onChange={(e) => setPolicyDraft((p: any) => ({ ...p, algorithm: e.target.value }))} placeholder="aes256-gcm" /></FG>
              <FG label="Key Type"><Inp value={policyDraft?.key_type} onChange={(e) => setPolicyDraft((p: any) => ({ ...p, key_type: e.target.value }))} placeholder="symmetric" /></FG>
            </Row2>
            <Row2>
              <FG label="Purpose"><Inp value={policyDraft?.purpose} onChange={(e) => setPolicyDraft((p: any) => ({ ...p, purpose: e.target.value }))} placeholder="encrypt_decrypt" /></FG>
              <FG label="IV Mode"><Inp value={policyDraft?.iv_mode} onChange={(e) => setPolicyDraft((p: any) => ({ ...p, iv_mode: e.target.value }))} placeholder="generated" /></FG>
            </Row2>
            <Row2>
              <FG label="Ops Limit"><Inp type="number" value={Number(policyDraft?.ops_limit || 0)} onChange={(e) => setPolicyDraft((p: any) => ({ ...p, ops_limit: e.target.value }))} /></FG>
              <FG label="Ops Limit Window"><Inp value={policyDraft?.ops_limit_window} onChange={(e) => setPolicyDraft((p: any) => ({ ...p, ops_limit_window: e.target.value }))} placeholder="24h" /></FG>
            </Row2>
            <FG label="Approval Policy ID"><Inp value={policyDraft?.approval_policy_id} onChange={(e) => setPolicyDraft((p: any) => ({ ...p, approval_policy_id: e.target.value }))} placeholder="policy-approval-root" /></FG>
            <FG label="Tags (comma-separated)"><Inp value={policyDraft?.tags_csv} onChange={(e) => setPolicyDraft((p: any) => ({ ...p, tags_csv: e.target.value }))} /></FG>
            <FG label="Labels JSON"><Txt rows={5} value={policyDraft?.labels_json} onChange={(e) => setPolicyDraft((p: any) => ({ ...p, labels_json: e.target.value }))} /></FG>
            <FG label="Description"><Txt rows={3} mono={false} value={policyDraft?.description} onChange={(e) => setPolicyDraft((p: any) => ({ ...p, description: e.target.value }))} /></FG>
            <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 10, flexWrap: "wrap" }}>
              <Chk label="Enforce requested spec against policy" checked={Boolean(policyDraft?.enforce_policy)} onChange={() => setPolicyDraft((p: any) => ({ ...p, enforce_policy: !p.enforce_policy }))} />
              <Chk label="Approval required" checked={Boolean(policyDraft?.approval_required)} onChange={() => setPolicyDraft((p: any) => ({ ...p, approval_required: !p.approval_required }))} />
              <Chk label="Export allowed" checked={Boolean(policyDraft?.export_allowed)} onChange={() => setPolicyDraft((p: any) => ({ ...p, export_allowed: !p.export_allowed }))} />
              <Chk label="Enabled" checked={Boolean(policyDraft?.enabled)} onChange={() => setPolicyDraft((p: any) => ({ ...p, enabled: !p.enabled }))} />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <Btn onClick={() => setPolicyDraft(DEFAULT_POLICY)}>Reset</Btn>
              <Btn primary onClick={savePolicy} disabled={busy}>Save Service Default</Btn>
            </div>
          </Card>

          <Card style={{ padding: "14px 16px" }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 8 }}>Saved Service Defaults</div>
            <div style={{ display: "grid", gap: 8 }}>
              {policies.map((item: any) => (
                <div key={String(item?.service_name || "")} style={{ padding: "10px 12px", borderRadius: 10, border: `1px solid ${C.border}`, background: C.surface }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                    <div>
                      <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>{String(item?.display_name || item?.service_name || "-")}</div>
                      <div style={{ fontSize: 9, color: C.dim }}>{String(item?.service_name || "-")} • {String(item?.algorithm || "inherit")} • {String(item?.purpose || "inherit")}</div>
                    </div>
                    <B c={item?.enabled ? "green" : "amber"}>{item?.enabled ? "Enabled" : "Disabled"}</B>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8, marginTop: 8 }}>
                    <Stat l="Template" v={String(item?.default_template_id || "Auto")} c="accent" />
                    <Stat l="Approval" v={Boolean(item?.approval_required) ? "Required" : "Direct"} c={Boolean(item?.approval_required) ? "amber" : "green"} />
                    <Stat l="Policy" v={Boolean(item?.enforce_policy) ? "Enforced" : "Audit"} c={Boolean(item?.enforce_policy) ? "blue" : "amber"} />
                  </div>
                  <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 8 }}>
                    <Btn small onClick={() => setPolicyDraft({
                      ...DEFAULT_POLICY,
                      ...item,
                      tags_csv: listToCsv(item?.tags),
                      labels_json: jsonToPretty(item?.labels)
                    })}>Edit</Btn>
                    <Btn small danger onClick={() => removePolicy(String(item?.service_name || ""))}>Delete</Btn>
                  </div>
                </div>
              ))}
              {!policies.length && <div style={{ fontSize: 10, color: C.muted }}>No service default policies yet.</div>}
            </div>
          </Card>
        </div>
      )}

      {tab === "Requests & Handles" && (
        <div style={{ display: "grid", gridTemplateColumns: "1.05fr 1fr", gap: 10, marginTop: 10 }}>
          <Card style={{ padding: "14px 16px" }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 8 }}>Request Managed Key Handle</div>
            <Row2>
              <FG label="Service Name"><Inp value={requestDraft?.service_name} onChange={(e) => setRequestDraft((p: any) => ({ ...p, service_name: e.target.value }))} placeholder="payment" /></FG>
              <FG label="Resource Type"><Inp value={requestDraft?.resource_type} onChange={(e) => setRequestDraft((p: any) => ({ ...p, resource_type: e.target.value }))} placeholder="application" /></FG>
            </Row2>
            <FG label="Resource Reference"><Inp value={requestDraft?.resource_ref} onChange={(e) => setRequestDraft((p: any) => ({ ...p, resource_ref: e.target.value }))} placeholder="payments-api-prod" /></FG>
            <Row2>
              <FG label="Template Override">
                <Sel value={String(requestDraft?.template_id || "")} onChange={(e) => setRequestDraft((p: any) => ({ ...p, template_id: e.target.value }))}>
                  <option value="">Auto-select template</option>
                  {templates.map((item: any) => <option key={String(item?.id || "")} value={String(item?.id || "")}>{String(item?.name || item?.id || "")}</option>)}
                </Sel>
              </FG>
              <FG label="Requested Algorithm"><Inp value={requestDraft?.requested_algorithm} onChange={(e) => setRequestDraft((p: any) => ({ ...p, requested_algorithm: e.target.value }))} placeholder="aes256-gcm" /></FG>
            </Row2>
            <Row2>
              <FG label="Requested Key Type"><Inp value={requestDraft?.requested_key_type} onChange={(e) => setRequestDraft((p: any) => ({ ...p, requested_key_type: e.target.value }))} placeholder="symmetric" /></FG>
              <FG label="Requested Purpose"><Inp value={requestDraft?.requested_purpose} onChange={(e) => setRequestDraft((p: any) => ({ ...p, requested_purpose: e.target.value }))} placeholder="encrypt_decrypt" /></FG>
            </Row2>
            <Row2>
              <FG label="Custom Handle Name"><Inp value={requestDraft?.handle_name} onChange={(e) => setRequestDraft((p: any) => ({ ...p, handle_name: e.target.value }))} placeholder="optional" /></FG>
              <FG label="Custom Key Name"><Inp value={requestDraft?.key_name} onChange={(e) => setRequestDraft((p: any) => ({ ...p, key_name: e.target.value }))} placeholder="optional" /></FG>
            </Row2>
            <FG label="Tags (comma-separated)"><Inp value={requestDraft?.tags_csv} onChange={(e) => setRequestDraft((p: any) => ({ ...p, tags_csv: e.target.value }))} /></FG>
            <FG label="Labels JSON"><Txt rows={4} value={requestDraft?.labels_json} onChange={(e) => setRequestDraft((p: any) => ({ ...p, labels_json: e.target.value }))} /></FG>
            <FG label="Justification"><Txt rows={4} mono={false} value={requestDraft?.justification} onChange={(e) => setRequestDraft((p: any) => ({ ...p, justification: e.target.value }))} placeholder="Why does this service/resource need a managed handle?" /></FG>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
              <div style={{ fontSize: 9, color: C.dim }}>Approval-required requests continue in the Governance tab. Autokey will provision the key after approval.</div>
              <Btn primary onClick={submitRequest} disabled={busy}>Submit Request</Btn>
            </div>
          </Card>

          <div style={{ display: "grid", gap: 10 }}>
            <Card style={{ padding: "14px 16px" }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 8 }}>Recent Requests</div>
              <div style={{ display: "grid", gap: 8, maxHeight: 380, overflow: "auto" }}>
                {requests.map((item: any) => (
                  <div key={String(item?.id || "")} style={{ padding: "10px 12px", borderRadius: 10, border: `1px solid ${C.border}`, background: C.surface }}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                      <div>
                        <div style={{ fontSize: 10, fontWeight: 700, color: C.text }}>{String(item?.service_name || "-")} • {String(item?.resource_ref || "-")}</div>
                        <div style={{ fontSize: 9, color: C.dim }}>{String(item?.resource_type || "-")} • {String(item?.handle_name || "-")}</div>
                      </div>
                      <B c={requestTone(String(item?.status || ""))}>{String(item?.status || "unknown")}</B>
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8, marginTop: 8 }}>
                      <Stat l="Policy" v={Boolean(item?.policy_matched) ? "Matched" : "Mismatch"} c={Boolean(item?.policy_matched) ? "green" : "amber"} />
                      <Stat l="Approval" v={Boolean(item?.approval_required) ? "Required" : "Direct"} c={Boolean(item?.approval_required) ? "amber" : "green"} />
                      <Stat l="Created" v={fmtTS(item?.created_at)} c="blue" />
                    </div>
                    {item?.policy_mismatch_reason ? <div style={{ fontSize: 9, color: C.amber, marginTop: 6 }}>{String(item.policy_mismatch_reason)}</div> : null}
                    {item?.failure_reason ? <div style={{ fontSize: 9, color: C.red, marginTop: 6 }}>{String(item.failure_reason)}</div> : null}
                  </div>
                ))}
                {!requests.length && <div style={{ fontSize: 10, color: C.muted }}>No Autokey requests yet.</div>}
              </div>
            </Card>

            <Card style={{ padding: "14px 16px" }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 8 }}>Managed Handles</div>
              <div style={{ display: "grid", gap: 8, maxHeight: 300, overflow: "auto" }}>
                {handles.map((item: any) => (
                  <div key={String(item?.id || "")} style={{ padding: "10px 12px", borderRadius: 10, border: `1px solid ${C.border}`, background: C.surface }}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                      <div>
                        <div style={{ fontSize: 10, fontWeight: 700, color: C.text }}>{String(item?.handle_name || "-")}</div>
                        <div style={{ fontSize: 9, color: C.dim }}>{String(item?.service_name || "-")} • {String(item?.resource_ref || "-")}</div>
                      </div>
                      <B c={Boolean(item?.policy_matched) ? "green" : "amber"}>{Boolean(item?.policy_matched) ? "Policy matched" : "Review"}</B>
                    </div>
                    <div style={{ fontSize: 9, color: C.dim, marginTop: 6 }}>Key ID: {String(item?.key_id || "-")}</div>
                  </div>
                ))}
                {!handles.length && <div style={{ fontSize: 10, color: C.muted }}>No managed handles yet.</div>}
              </div>
            </Card>
          </div>
        </div>
      )}
    </Section>
  );
};
